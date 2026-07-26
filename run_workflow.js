const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

/**
 * Reachable Critical Audit - CLI Workflow Orchestrator (Node.js)
 *
 * 多平台兼容版本：自动检测并适配 claude / agy / codex CLI 环境。
 *
 * 支持的 CLI 运行环境：
 *   - Claude Code:       claude -p <prompt> --dangerously-skip-permissions
 *   - Antigravity CLI:   agy --dangerously-skip-permissions --prompt <prompt>
 *   - OpenAI Codex CLI:  codex --quiet --full-auto <prompt>
 *   - 环境变量覆盖:      AGENT_CLI=<binary> AGENT_CLI_ARGS=<json_array>
 *
 * 核心保证：
 *   1. 每个候选 spawn 独立子进程 → 物理隔离 context，解决注意力下降
 *   2. 每批次落盘 → 断点续传，中断后重启自动跳过已完成项
 *   3. 完整性 Assert → 所有候选必须被验证，一个不跳过
 *   4. 结构化 Verdict 提取 → 精准正则，防止模糊判定
 *   5. JSON Schema 2.0 兼容 → 支持 {candidates:[]} 和 [] 两种格式
 */

const colors = {
    reset: "\x1b[0m",
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    blue: "\x1b[34m",
    cyan: "\x1b[36m"
};

// ==================== 平台自适应层 ====================

/**
 * 检测当前环境可用的 AI CLI 工具。
 * 优先级: 环境变量 > claude > agy > codex
 */
function detectAgentCli() {
    // 1. 环境变量覆盖
    if (process.env.AGENT_CLI) {
        return process.env.AGENT_CLI;
    }
    // 2. 按优先级探测
    const candidates = ['claude', 'agy', 'codex'];
    for (const cli of candidates) {
        try {
            execSync(`which ${cli}`, { stdio: 'ignore' });
            return cli;
        } catch (e) { /* not found, try next */ }
    }
    // 3. 无可用 CLI
    console.error(`${colors.red}[FATAL] 未检测到任何 AI CLI 工具 (claude/agy/codex)。`);
    console.error(`请安装 Claude Code (npm i -g @anthropic-ai/claude-code) 或设置 AGENT_CLI 环境变量。${colors.reset}`);
    process.exit(1);
}

/**
 * 根据 CLI 类型构建参数数组。
 * Claude Code: claude -p <prompt> --dangerously-skip-permissions
 * Antigravity: agy --dangerously-skip-permissions --prompt <prompt>
 * Codex:       codex --quiet --full-auto <prompt>
 */
function buildCliArgs(cliName, prompt) {
    // 环境变量自定义参数模板
    if (process.env.AGENT_CLI_ARGS) {
        try {
            const template = JSON.parse(process.env.AGENT_CLI_ARGS);
            return template.map(arg => arg === '$PROMPT' ? prompt : arg);
        } catch (e) {
            console.error(`${colors.yellow}[WARN] AGENT_CLI_ARGS 解析失败，使用默认参数模板。${colors.reset}`);
        }
    }

    switch (cliName) {
        case 'claude':
            return ['-p', prompt, '--dangerously-skip-permissions'];
        case 'codex':
            return ['--quiet', '--full-auto', prompt];
        case 'agy':
        default:
            return ['--dangerously-skip-permissions', '--prompt', prompt];
    }
}

// 并发批大小（每批 spawn 的子进程数）
const BATCH_SIZE = parseInt(process.env.BATCH_SIZE || '4', 10);

// CLI 单次执行超时（毫秒，默认 5 分钟）
const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS || '300000', 10);

// ==================== 子进程执行引擎 ====================

/**
 * spawn 独立子进程执行 AI CLI。
 * - 物理隔离 context: 每个候选独立进程，注意力不衰减
 * - spawn 直接传参: 规避 shell 字符注入
 * - 超时保护: 防止单个候选阻塞整个流程
 */
function runAgentCmd(prompt) {
    return new Promise((resolve, reject) => {
        const cliName = detectAgentCli();
        const args = buildCliArgs(cliName, prompt);

        console.log(`${colors.cyan}    [CLI] ${cliName} ${args[0]} ...${colors.reset}`);

        const child = spawn(cliName, args, {
            stdio: ['ignore', 'pipe', 'pipe'],
            timeout: TIMEOUT_MS
        });

        let stdout = '';
        let stderr = '';

        child.stdout.on('data', (data) => { stdout += data; });
        child.stderr.on('data', (data) => { stderr += data; });

        child.on('error', (err) => {
            if (err.code === 'ENOENT') {
                reject(new Error(`CLI "${cliName}" not found in PATH. Install it or set AGENT_CLI env var.`));
            } else {
                reject(err);
            }
        });

        child.on('close', (code, signal) => {
            if (signal === 'SIGTERM') {
                reject(new Error(`CLI timeout after ${TIMEOUT_MS}ms`));
            } else if (code !== 0) {
                reject(new Error(stderr.trim() || `CLI (${cliName}) exited with code ${code}`));
            } else {
                resolve(stdout);
            }
        });
    });
}

// ==================== verify_queue.json 读写层 ====================

/**
 * 兼容两种 JSON Schema:
 *   - Schema 2.0: {"schema_version":"2.0","candidates":[...]}
 *   - Legacy:     [...]
 */
function loadQueue(queuePath) {
    if (!fs.existsSync(queuePath)) return { raw: null, candidates: [] };
    const raw = JSON.parse(fs.readFileSync(queuePath, 'utf8'));
    if (Array.isArray(raw)) {
        return { raw: null, candidates: raw };
    }
    return { raw, candidates: raw.candidates || [] };
}

function saveQueue(queuePath, rawWrapper, candidates) {
    if (rawWrapper === null) {
        // Legacy array format
        fs.writeFileSync(queuePath, JSON.stringify(candidates, null, 2), 'utf8');
    } else {
        // Schema 2.0 object format
        rawWrapper.candidates = candidates;
        fs.writeFileSync(queuePath, JSON.stringify(rawWrapper, null, 2), 'utf8');
    }
}

// ==================== Verdict 结构化提取 ====================

/**
 * 从 AI CLI stdout 中精准提取判定结论。
 * 三层降级策略:
 *   1. 结构化 JSON verdict 字段
 *   2. VERDICT: REACHABLE/UNREACHABLE 标记
 *   3. 末行 YES/NO 关键词 (最弱降级)
 */
function extractVerdict(stdout) {
    if (typeof stdout !== 'string') return 'NEEDS_REVIEW';

    // Layer 1: 尝试解析结构化 JSON 输出
    try {
        const jsonMatch = stdout.match(/\{[\s\S]*"verdict"\s*:\s*"(REACHABLE|UNREACHABLE|NEEDS_REVIEW)"[\s\S]*\}/);
        if (jsonMatch) return jsonMatch[1].toUpperCase();
    } catch (e) { /* not JSON, try next */ }

    // Layer 2: 精准结构化标记 (Prompt 要求输出此格式)
    const verdictMatch = stdout.match(/VERDICT:\s*(REACHABLE|UNREACHABLE|NEEDS_REVIEW)/i);
    if (verdictMatch) return verdictMatch[1].toUpperCase();

    // Layer 3: 降级 — 只看最后 500 字符中的关键词，避免分析过程中的词汇干扰
    const tail = stdout.slice(-500);
    const hasReachable = /\bREACHABLE\b/i.test(tail);
    const hasUnreachable = /\bUNREACHABLE\b/i.test(tail);
    if (hasReachable && !hasUnreachable) return 'REACHABLE';
    if (hasUnreachable && !hasReachable) return 'UNREACHABLE';

    return 'NEEDS_REVIEW';
}

/**
 * 从 R4 Subagent stdout 中提取假说判定。
 */
function extractHypothesisVerdict(stdout) {
    if (typeof stdout !== 'string') return { status: 'NEEDS_REVIEW', summary: 'Non-string output' };

    const confirmedMatch = stdout.match(/HYPOTHESIS_CONFIRMED:\s*([^\r\n]+)/);
    if (confirmedMatch) {
        return { status: 'REACHABLE', verdict: 'confirmed', summary: confirmedMatch[1].trim() };
    }

    const cleanMatch = stdout.match(/HYPOTHESIS_CLEAN:\s*([^\r\n]+)/);
    if (cleanMatch) {
        return { status: 'UNREACHABLE', verdict: 'reviewed_clean', summary: cleanMatch[1].trim() };
    }

    return { status: 'NEEDS_REVIEW', verdict: 'needs_review', summary: '未明确输出假说结论，需要人工复核。' };
}

// ==================== Prompt 模板（结构化输出要求）====================

function buildVerifyPrompt(cand) {
    if (cand.type === "PROPERTY_CHECK") {
        return `你是一个 vulnerability-verifier 子智能体。请对以下代码候选点进行【业务逻辑越权审计】。

任务上下文:
- 语言: ${cand.language}
- CWE类别: ${cand.cwe_id} (${cand.category})
- 敏感API文件: ${cand.file_path}
- 行号: ${cand.line_number}
- 代码内容: ${cand.sink_content}
- 验证逻辑指导: ${cand.verification_logic || '检查指针解引用前是否有 NULL 检查'}

请执行以下校验步骤：
1. 深入阅读该敏感写操作方法体，并回溯其上游控制器方法（至少 3 层调用链）。
2. 重点审查代码中是否缺失了属主关系比对。
3. 检查是否有权限拦截装饰器。

【强制输出格式】在回复的最后一行，输出以下标记之一（不要遗漏）：
VERDICT: REACHABLE
或
VERDICT: UNREACHABLE
并提供分析证据。`;
    }

    const sources = (cand.sources_regex && cand.sources_regex.length > 0)
        ? cand.sources_regex.join(', ')
        : 'argv, getenv, read, recv';

    return `你是一个 vulnerability-verifier 子智能体。请对以下代码的目标调用进行【数据流参数控制关系分析】。

任务上下文:
- 语言: ${cand.language}
- 分析类别: ${cand.category}
- 目标调用文件: ${cand.file_path}
- 目标调用行号: ${cand.line_number}
- 目标代码内容: ${cand.sink_content}
- 校验要求: ${cand.reachability_constraints || "分析入参是否经过严格的安全过滤或强类型转换"}

验证步骤：
1. 追溯调用该目标函数代码的上游函数和控制器入口（至少 3 层调用链）。
2. 检查这些上游调用链中的参数，是否直接或间接地被外部可控输入（例如 ${sources} 等）所控制。
3. 校验路径上是否有健全的类型转换、白名单过滤或编码转义处理将外部控制关系隔断。

【强制输出格式】在回复的最后一行，输出以下标记之一（不要遗漏）：
VERDICT: REACHABLE
或
VERDICT: UNREACHABLE
并给出完整的分析证据链。`;
}

function buildR4Prompt(domainProfile, filePath) {
    return `你是一个 business-logic-verifier 子智能体。请对项目 [${domainProfile.domainName}] 中的高危业务模块进行【6类固化业务逻辑假说深钻】。

目标文件路径：${filePath}
项目领域背景：${domainProfile.summary}

请结合代码结构、控制流与状态机设计，回应以下 6 类固定假说：
1. CWE-789 远端控制 allocation size
2. CWE-125/787 远端控制解引用长度/索引
3. CWE-416 异步对象生命周期竞态
4. 跨进程信任边界破坏
5. Exported component 鉴权缺失
6. 多租户/owner 比对缺失

必须为每个适用的假说给出明确结论：confirmed | reviewed_clean | not_applicable。

【强制输出格式】
如果确认存在漏洞: HYPOTHESIS_CONFIRMED: [假说名称] - [简短说明]
如果审查无问题:   HYPOTHESIS_CLEAN: [假说名称] - [简短说明]`;
}

// ==================== --check-availability 子命令 ====================

function checkAvailability() {
    const cliName = detectAgentCli();
    const versionCmd = cliName === 'claude' ? '--version' : '--version';
    let reported = false;

    const child = spawn(cliName, [versionCmd]);

    child.on('error', (err) => {
        console.log(JSON.stringify({
            mode: 'AGENT_NATIVE_FALLBACK',
            reason: `${cliName} CLI error: ${err.message}`,
            instruction: '主 Agent 接管'
        }));
        process.exit(0);
    });

    child.stdout.on('data', (data) => {
        if (reported) return;
        reported = true;
        console.log(JSON.stringify({
            mode: `CLI_${cliName.toUpperCase()}`,
            cli: cliName,
            version: data.toString().trim(),
            instruction: `可进入 CLI 编排模式, 由 run_workflow.js + ${cliName} 编排 R1/R3/R4`
        }));
        process.exit(0);
    });

    child.on('close', (code) => {
        if (reported) return;
        console.log(JSON.stringify({
            mode: `CLI_${cliName.toUpperCase()}`,
            cli: cliName,
            exit_code: code,
            instruction: `可进入 CLI 编排模式`
        }));
        process.exit(0);
    });
}

// 入口短路: --check-availability
if (process.argv.includes('--check-availability')) {
    checkAvailability();
}

// ==================== 主工作流 ====================

async function executeWorkflow(workspacePath) {
    const cliName = detectAgentCli();
    console.log(`${colors.cyan}[*] Reachable Critical Audit 工作流启动${colors.reset}`);
    console.log(`${colors.cyan}[*] 检测到 CLI 环境: ${cliName} | 并发批大小: ${BATCH_SIZE} | 超时: ${TIMEOUT_MS}ms${colors.reset}`);

    const scannerPath = path.join(__dirname, 'tools', 'ast_scanner.py');
    const outputDir = path.join(workspacePath, '.audit_results');
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    const queuePath = path.join(outputDir, 'verify_queue.json');
    const reportPath = path.join(outputDir, 'reachable_vulnerabilities_report.json');

    // 写入执行模式记录
    fs.writeFileSync(path.join(outputDir, 'execution_mode.json'), JSON.stringify({
        mode: `CLI_${cliName.toUpperCase()}`,
        cli: cliName,
        batch_size: BATCH_SIZE,
        timeout_ms: TIMEOUT_MS,
        detected_at: new Date().toISOString()
    }, null, 2), 'utf8');

    // --- 阶段 1: 扫描/加载候选队列 ---
    let queueObj;
    if (fs.existsSync(queuePath)) {
        console.log(`${colors.yellow}[*] 发现已存在的队列文件，载入断点续传...${colors.reset}`);
        queueObj = loadQueue(queuePath);
    } else {
        console.log(`${colors.blue}[*] 未发现历史队列，启动 AST 扫描...${colors.reset}`);
        try {
            execSync(`python3 "${scannerPath}" "${workspacePath}" "${outputDir}"`, { stdio: 'inherit' });
            queueObj = loadQueue(queuePath);
        } catch (error) {
            console.error(`${colors.red}[Error] AST 扫描器执行失败. 流程终止。${colors.reset}`);
            process.exit(1);
        }
    }

    let queue = queueObj.candidates;
    const pendingCandidates = queue.filter(c => c.status === "PENDING");
    console.log(`${colors.green}[+] 队列: 总计 ${queue.length} 项, PENDING ${pendingCandidates.length} 项, 已完成 ${queue.length - pendingCandidates.length} 项${colors.reset}`);

    if (pendingCandidates.length === 0) {
        console.log(`${colors.green}[+] 所有候选点均已验证，直接进行报告汇总。${colors.reset}`);
        compileReport(queue, reportPath, [], workspacePath);
        return;
    }

    // --- 阶段 2: 批处理并发审计循环 ---
    console.log(`${colors.blue}[*] 阶段 2: 启动 ${cliName} 子进程批处理并发研判...${colors.reset}`);

    const pendingIndices = queue
        .map((cand, index) => ({ cand, index }))
        .filter(item => item.cand.status === "PENDING");

    let totalVerified = 0;

    for (let i = 0; i < pendingIndices.length; i += BATCH_SIZE) {
        const batch = pendingIndices.slice(i, i + BATCH_SIZE);
        const batchNum = Math.floor(i / BATCH_SIZE) + 1;
        const totalBatches = Math.ceil(pendingIndices.length / BATCH_SIZE);

        console.log(`\n${'='.repeat(60)}`);
        console.log(`${colors.yellow}[Batch ${batchNum}/${totalBatches}] 并发 ${batch.length} 个子进程 | 进度 ${totalVerified}/${pendingIndices.length}${colors.reset}`);
        console.log(`${'='.repeat(60)}`);

        // 并发执行当前批次
        await Promise.all(batch.map(async ({ cand, index }) => {
            console.log(`${colors.blue}  [${cand.id}] ${cand.cwe_id} ${path.basename(cand.file_path)}:${cand.line_number}${colors.reset}`);

            const prompt = buildVerifyPrompt(cand);

            try {
                const stdout = await runAgentCmd(prompt);
                const status = extractVerdict(stdout);

                // 写回结果
                queue[index].status = status;
                queue[index].verdict = typeof stdout === 'string' ? stdout.slice(-2000) : String(stdout);
                queue[index].verified_at = new Date().toISOString();

                // 传播相同位置+CWE 的判定结果
                let propagated = 0;
                queue.forEach(item => {
                    if (item.file_path === cand.file_path &&
                        item.line_number === cand.line_number &&
                        item.cwe_id === cand.cwe_id &&
                        item.status === "PENDING") {
                        item.status = status;
                        item.verdict = `[Propagated from ${cand.id}]`;
                        item.verified_at = new Date().toISOString();
                        propagated++;
                    }
                });

                const statusIcon = status === 'REACHABLE' ? `${colors.red}🔴` :
                                   status === 'UNREACHABLE' ? `${colors.green}✅` :
                                   `${colors.yellow}⚠️`;
                const propMsg = propagated > 0 ? ` (+${propagated} propagated)` : '';
                console.log(`  ${statusIcon} [${cand.id}] → ${status}${propMsg}${colors.reset}`);

            } catch (err) {
                console.error(`${colors.red}  ❌ [${cand.id}] 异常: ${err.message.slice(0, 120)}${colors.reset}`);
                queue[index].status = 'NEEDS_REVIEW';
                queue[index].verdict = `ERROR: ${err.message.slice(0, 500)}`;
                queue[index].verified_at = new Date().toISOString();
            }

            totalVerified++;
        }));

        // 每批次立即落盘
        saveQueue(queuePath, queueObj.raw, queue);
        console.log(`${colors.cyan}  [落盘] Batch ${batchNum} 完成，已安全写入磁盘。${colors.reset}`);
    }

    // --- 阶段 3: 完整性 Assert ---
    console.log(`\n${'='.repeat(60)}`);
    console.log(`${colors.cyan}[Assert] 执行完整性校验...${colors.reset}`);

    const { candidates: finalQueue } = loadQueue(queuePath);
    const unverified = finalQueue.filter(c => c.status === "PENDING");

    if (unverified.length > 0) {
        console.error(`${colors.red}[CRITICAL] 完整性校验失败！仍有 ${unverified.length} 个 PENDING 节点！${colors.reset}`);
        unverified.slice(0, 20).forEach(item => {
            console.error(`  - ${item.id} | ${item.file_path}:${item.line_number}`);
        });
        if (unverified.length > 20) console.error(`  ... 及另外 ${unverified.length - 20} 项`);
        process.exit(2);
    }

    const stats = {
        total: finalQueue.length,
        reachable: finalQueue.filter(c => c.status === 'REACHABLE').length,
        unreachable: finalQueue.filter(c => c.status === 'UNREACHABLE').length,
        needs_review: finalQueue.filter(c => c.status === 'NEEDS_REVIEW').length,
    };
    console.log(`${colors.green}[✓] Assert 通过: 全部 ${stats.total} 项已验证 (REACHABLE=${stats.reachable}, UNREACHABLE=${stats.unreachable}, NEEDS_REVIEW=${stats.needs_review})${colors.reset}`);

    // --- 阶段 4: 业务逻辑深钻 (REQ-14 ~ REQ-16) ---
    console.log(`\n${'='.repeat(60)}`);
    console.log(`${colors.yellow}[R4] 启发式业务逻辑深钻...${colors.reset}`);

    const domainProfile = inferProjectDomain(workspacePath);
    const archViewPath = path.join(outputDir, 'architecture_view.json');
    fs.writeFileSync(archViewPath, JSON.stringify(domainProfile, null, 2), 'utf8');
    console.log(`${colors.cyan}[R4] 项目域: ${domainProfile.domainName}${colors.reset}`);

    const highRiskFiles = findHighRiskModules(workspacePath);
    const autonomousFindings = [];

    if (highRiskFiles.length === 0) {
        console.log(`${colors.green}[R4] 未发现典型高危业务逻辑模块，跳过。${colors.reset}`);
    } else {
        console.log(`${colors.blue}[R4] 发现 ${highRiskFiles.length} 个高危锚点:${colors.reset}`);
        highRiskFiles.forEach(f => console.log(`  - ${f}`));

        const autonomousBatchSize = 3;
        for (let j = 0; j < highRiskFiles.length; j += autonomousBatchSize) {
            const batchFiles = highRiskFiles.slice(j, j + autonomousBatchSize);
            await Promise.all(batchFiles.map(async (filePath) => {
                console.log(`${colors.blue}  [R4 Subagent] 深钻: ${filePath}...${colors.reset}`);

                const prompt = buildR4Prompt(domainProfile, filePath);

                try {
                    const stdout = await runAgentCmd(prompt);
                    const result = extractHypothesisVerdict(stdout);

                    const icon = result.status === 'REACHABLE' ? `${colors.red}🔴` : `${colors.green}✅`;
                    console.log(`  ${icon} [R4] ${filePath} → ${result.status}: ${result.summary}${colors.reset}`);

                    autonomousFindings.push({
                        file_path: filePath,
                        origin: "R4",
                        status: result.status,
                        verdict: result.verdict || result.status.toLowerCase(),
                        summary: result.summary,
                        evidence: typeof stdout === 'string' ? stdout.slice(-2000) : String(stdout)
                    });
                } catch (err) {
                    console.error(`${colors.red}  ❌ [R4] ${filePath} 异常: ${err.message.slice(0, 120)}${colors.reset}`);
                    autonomousFindings.push({
                        file_path: filePath,
                        origin: "R4",
                        status: 'NEEDS_REVIEW',
                        verdict: 'execution_failed',
                        summary: `ERROR: ${err.message.slice(0, 200)}`,
                        evidence: `ERROR: ${err.message}`
                    });
                }
            }));
        }

        const autonomousPath = path.join(outputDir, 'autonomous_logical_findings.json');
        fs.writeFileSync(autonomousPath, JSON.stringify(autonomousFindings, null, 2), 'utf8');
    }

    compileReport(finalQueue, reportPath, autonomousFindings, workspacePath);
}

// ==================== 项目域感知 ====================

function inferProjectDomain(workspacePath) {
    let domainName = "通用开源应用/服务";
    let summary = "常规代码库，包含标准模块交互。";

    const hasAndroid = fs.existsSync(path.join(workspacePath, 'AndroidManifest.xml'));
    const hasBluetooth = fs.existsSync(path.join(workspacePath, 'system', 'btif')) ||
                         fs.existsSync(path.join(workspacePath, 'android', 'app', 'src', 'com', 'android', 'bluetooth'));
    const hasKernel = fs.existsSync(path.join(workspacePath, 'Kconfig')) &&
                      fs.existsSync(path.join(workspacePath, 'kernel'));
    const hasMakefile = fs.existsSync(path.join(workspacePath, 'Makefile'));

    if (hasKernel) {
        domainName = "Linux Kernel / 系统级 C 代码库";
        summary = "包含内核子系统（net/drivers/fs/mm 等），C 语言为主，强依赖内核内存管理与锁机制。";
    } else if (hasBluetooth || (hasAndroid && workspacePath.toLowerCase().includes('bluetooth'))) {
        domainName = "Android 原生蓝牙协议栈与系统服务 (Bluetooth Module)";
        summary = "包含 HCI、L2CAP、SDP、GATT、HFP、OPP、MAP 等底层 C++ 协议栈与 Android 上层 Java IPC 服务。";
    } else if (hasAndroid) {
        domainName = "Android 系统服务 / 应用 (Android App/Service)";
        summary = "包含 Activity/Service/Provider 组件交互、Binder IPC 及权限拦截。";
    } else if (fs.existsSync(path.join(workspacePath, 'package.json'))) {
        domainName = "Node.js / Web 应用服务";
        summary = "基于 JavaScript/TypeScript 的 Web 后端或 CLI 工具。";
    } else if (fs.existsSync(path.join(workspacePath, 'Cargo.toml'))) {
        domainName = "Rust 系统级模块/应用";
        summary = "基于 Rust 语言的底层高性能服务与内存安全管控。";
    } else if (fs.existsSync(path.join(workspacePath, 'go.mod'))) {
        domainName = "Go 语言服务/应用";
        summary = "基于 Go 语言的网络服务或系统工具。";
    } else if (fs.existsSync(path.join(workspacePath, 'pom.xml')) || fs.existsSync(path.join(workspacePath, 'build.gradle'))) {
        domainName = "Java/Spring 企业应用";
        summary = "基于 Java/Spring 的企业级 Web 应用或微服务。";
    } else if (fs.existsSync(path.join(workspacePath, 'requirements.txt')) || fs.existsSync(path.join(workspacePath, 'setup.py'))) {
        domainName = "Python 应用/服务";
        summary = "基于 Python 的 Web 框架(Django/Flask)或数据处理工具。";
    }

    return { domainName, summary };
}

function findHighRiskModules(workspacePath) {
    const highRiskFiles = [];
    const keywords = [
        'auth', 'login', 'session', 'jwt', 'token',
        'payment', 'pay', 'order', 'cart', 'billing', 'checkout',
        'admin', 'manage', 'role', 'permission',
        'user', 'profile', 'account', 'service', 'provider', 'manager'
    ];
    const ignoreDirs = ['node_modules', '.git', '.audit_results', 'scratch', 'target', 'build', 'dist', 'vendor', 'third_party'];

    function walk(dir, depth) {
        if (depth > 5) return; // 限制递归深度
        let list;
        try { list = fs.readdirSync(dir); } catch (e) { return; }

        list.forEach(file => {
            const fullPath = path.join(dir, file);
            let stat;
            try { stat = fs.statSync(fullPath); } catch (e) { return; }

            if (stat && stat.isDirectory()) {
                if (!ignoreDirs.some(ignored => file.includes(ignored))) {
                    walk(fullPath, depth + 1);
                }
            } else {
                const ext = path.extname(file).toLowerCase();
                const validExts = ['.java', '.cpp', '.cc', '.c', '.h', '.py', '.go', '.rs', '.js', '.ts', '.cs', '.php', '.rb', '.swift', '.kt'];
                if (validExts.includes(ext)) {
                    const nameLower = file.toLowerCase();
                    if (keywords.some(kw => nameLower.includes(kw))) {
                        highRiskFiles.push(path.relative(workspacePath, fullPath));
                    }
                }
            }
        });
    }

    walk(workspacePath, 0);
    return highRiskFiles.slice(0, 6);
}

// ==================== 报告生成 ====================

function compileReport(queue, reportJsonPath, autonomousFindings = [], workspacePath = '.') {
    const reachable = queue.filter(c => c.status === 'REACHABLE');
    const unreachable = queue.filter(c => c.status === 'UNREACHABLE');
    const needsReview = queue.filter(c => c.status === 'NEEDS_REVIEW');

    const total = queue.length;
    const verifiedTotal = reachable.length + unreachable.length;

    const l0Count = queue.filter(c => (c.origin || 'L0') === 'L0').length;
    const l1Count = queue.filter(c => c.origin === 'L1').length;
    const l2Count = queue.filter(c => c.origin === 'L2').length;
    const r4Count = queue.filter(c => c.origin === 'R4').length + autonomousFindings.length;
    const r4Reachable = autonomousFindings.filter(f => f.status === 'REACHABLE').length;

    const pct = (n, d) => d > 0 ? ((n / d) * 100).toFixed(2) : "0.00";

    const reportContent = {
        report_meta: {
            generated_at: new Date().toISOString(),
            schema_version: "2.0",
            cli_used: detectAgentCli()
        },
        quantified_metrics: {
            total_candidates: total,
            verified: verifiedTotal,
            reachable: reachable.length,
            unreachable: unreachable.length,
            needs_review: needsReview.length,
            rule_coverage_rate_pct: `${pct(verifiedTotal, total)}%`,
            reachability_rate_pct: `${pct(reachable.length, verifiedTotal)}%`,
            noise_reduction_rate_pct: `${pct(unreachable.length, verifiedTotal)}%`,
            sink_discovery_rate_pct: `${pct(l0Count, total)}%`,
            false_negative_risk_pct: `${pct(l1Count + r4Reachable, total)}%`,
            origin_breakdown: { L0: l0Count, L1: l1Count, L2: l2Count, R4: r4Count }
        },
        reachable_vulnerabilities: reachable.map(c => ({
            id: c.id, origin: c.origin || 'L0', language: c.language,
            cwe_id: c.cwe_id || c.sink_type, category: c.category, type: c.type,
            source_file: c.source_file || c.file_path,
            source_line: c.source_line || c.line_number,
            reachability_type: c.reachability_type || 'DIRECT',
            sink_content: c.sink_content, evidence: c.verdict
        })),
        needs_review: needsReview.map(c => ({
            id: c.id, origin: c.origin || 'L0',
            source_file: c.source_file || c.file_path,
            source_line: c.source_line || c.line_number,
            sink_type: c.sink_type || c.cwe_id,
            blocking_point: c.blocking_point || null,
            reason: c.verdict || "研判拒绝或返回模糊"
        })),
        autonomous_findings: autonomousFindings.map(f => ({
            file_path: f.file_path, origin: "R4", status: f.status,
            summary: f.summary, evidence: f.evidence
        }))
    };

    fs.writeFileSync(reportJsonPath, JSON.stringify(reportContent, null, 2), 'utf8');

    // Markdown 报告
    const reportMdPath = path.join(path.dirname(reportJsonPath), 'reachable_vulnerabilities_report.md');
    let md = `# Reachable Critical Audit Report\n\n`;
    md += `Generated: ${reportContent.report_meta.generated_at} | CLI: ${reportContent.report_meta.cli_used}\n\n`;
    md += `## Metrics\n\n`;
    md += `| Metric | Value |\n|---|---|\n`;
    md += `| Total Candidates | ${total} |\n`;
    md += `| Verified | ${verifiedTotal} |\n`;
    md += `| **REACHABLE** | **${reachable.length}** |\n`;
    md += `| UNREACHABLE | ${unreachable.length} |\n`;
    md += `| NEEDS_REVIEW | ${needsReview.length} |\n`;
    md += `| Coverage Rate | ${pct(verifiedTotal, total)}% |\n`;
    md += `| Noise Reduction | ${pct(unreachable.length, verifiedTotal)}% |\n\n`;

    if (reachable.length > 0) {
        md += `## 🚨 Reachable Vulnerabilities\n\n`;
        reachable.forEach(c => {
            md += `### [${c.id}] ${c.cwe_id || c.sink_type}\n`;
            md += `- **File**: \`${c.source_file || c.file_path}:${c.source_line || c.line_number}\`\n`;
            md += `- **Sink**: \`${c.sink_content}\`\n`;
            md += `- **Evidence**: ${(c.verdict || '').slice(0, 500)}\n\n`;
        });
    }

    if (needsReview.length > 0) {
        md += `## ⚠️ Needs Review\n\n`;
        needsReview.slice(0, 50).forEach(c => {
            md += `- **[${c.id}]** \`${c.source_file || c.file_path}:${c.source_line || c.line_number}\` (${c.sink_type || c.cwe_id})\n`;
        });
        if (needsReview.length > 50) md += `\n... and ${needsReview.length - 50} more\n`;
    }

    fs.writeFileSync(reportMdPath, md, 'utf8');
    console.log(`${colors.green}[+] 报告已生成:\n  - JSON: ${reportJsonPath}\n  - Markdown: ${reportMdPath}${colors.reset}`);
}

// ==================== 入口 ====================

const targetDir = process.argv[2] || '.';
if (!process.argv.includes('--check-availability')) {
    executeWorkflow(targetDir);
}
