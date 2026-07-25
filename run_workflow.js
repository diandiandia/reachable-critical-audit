const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

/**
 * Reachable Critical Audit - CLI Workflow Orchestrator (Node.js) -- Mode B (可选)
 *
 * v2 角色: 本脚本是 SKILL.md REQ-01/REQ-17 平台兼容层中的 **可选执行路径**。
 *   - Mode A (Antigravity Native): define_subagent/invoke_subagent, 不调用本脚本
 *   - Mode A' (opencode 等):       task 工具, 不调用本脚本 ← **opencode 见到这个应立即退出，改用 task 模式**
 *   - Mode B (Antigravity CLI):    本脚本 + agy spawn 编排
 *
 * ┌──────────────────────────────────────────────────────────────────────────┐
 * │ opencode / Claude Code 用户在 Mode A' 下不要运行此脚本。请改用以下方式: │
 * │                                                                          │
 * │   R1 阶段: python3 tools/ast_scanner.py <workspace> .audit_results/     │
 * │            → 产出 verify_queue.json (全量候选队列)                      │
 * │                                                                          │
 * │   R3 阶段: for batch [0..candidates.length] @ step 4:                   │
 * │              task(subagent_type="general",                               │
 * │                   description="vulnerability-verifier: CAND-xxx",        │
 * │                   prompt=<按照附录 A.1 生成的任务书>)                    │
 * │            每批完成后: fs.writeFileSync("verify_queue.json", ...)        │
 * │            Assert: candidates.every(c => c.status !== "PENDING")         │
 * │                                                                          │
 * │   R4 阶段: task(...) 并发深钻 6 类假说                                    │
 * │   最终: 汇总 verify_queue.json + r4_findings → 生成报告                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Skill 在 R0 平台探测阶段会运行 `node run_workflow.js --check-availability`:
 *   - agy 可用 → 进入 Mode B, 本脚本接管 R1/R3/R4 编排
 *   - agy 不可用 (ENOENT) → 返回结构化 {mode:"AGENT_NATIVE_FALLBACK",...},
 *     主 Agent 接管所有后续子智能体调用 (Mode A 或 A')
 *
 * 具备【并发批处理 / 物理隔离 / 实时落盘断点保护】的安全审计工作流：
 * 1. 执行本地 AST 物理扫描，加载/生成 verify_queue.json 持久化队列。
 * 2. 按照每次启动 3-5 个（默认 4 个）子智能体的并发方式，进行批处理循环研判。
 * 3. 使用 child_process.spawn 异步调度 CLI 会话，彻底避免 Shell 字符注入漏洞。
 * 4. 每批次运行结束后【实时落盘】，断点续传，最终进行 Assert 完整性拦截校验。
 * 5. 完成后 compileReport 生成 JSON + Markdown 报告。
 *
 * v2 修订要点:
 * - runAgentCmd 的 child.on('error') 增加 ENOENT 结构化降级返回
 * - 新增 --check-availability 子命令,供 R0 平台探测调用
 * - 顶部说明文档化为"可选执行路径",避免与 Agent-Native 模式混用
 * - 新增 opencode Mode A' 工作流注释（此脚本不执行,仅供文档参考）
 */

const colors = {
    reset: "\x1b[0m",
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    blue: "\x1b[34m",
    cyan: "\x1b[36m"
};

// 并发批大小定义 (用户要求 3-5 个)
const BATCH_SIZE = 4;

// 使用 spawn 独立进程执行，规避 Shell 字符注入与转义解析异常
// v2: 增加 ENOENT 结构化降级 (REQ-01/REQ-17)
function runAgentCmd(args) {
    return new Promise((resolve, reject) => {
        const child = spawn('agy', args);
        let stdout = '';
        let stderr = '';
        
        // v2: ENOENT 时返回结构化 fallback 对象, 由主 Agent 接管 (Mode A/A')
        // 这保证 R0 平台探测能拿到结构化结果而非异常崩溃
        child.on('error', (err) => {
            if (err.code === 'ENOENT') {
                resolve({
                    mode: 'AGENT_NATIVE_FALLBACK',
                    reason: 'agy CLI not found in PATH',
                    instruction: '主 Agent 接管, 所有后续 subagent 调用走 define_subagent/task 工具 (Mode A/A\')'
                });
            } else {
                reject(err);
            }
        });
        
        child.stdout.on('data', (data) => {
            stdout += data;
        });
        
        child.stderr.on('data', (data) => {
            stderr += data;
        });
        
        child.on('close', (code) => {
            if (code !== 0) {
                reject(new Error(stderr.trim() || `Process exited with code ${code}`));
            } else {
                resolve(stdout);
            }
        });
    });
}

/**
 * --check-availability 子命令: 供 SKILL.md R0 平台兼容层调用。
 * 探测 agy 是否可用, 输出结构化 JSON 供主 Agent 决策模式:
 *   {"mode": "B_ANTIGRAVITY_CLI", "agy_path": "..."}      → 进入 Mode B
 *   {"mode": "AGENT_NATIVE_FALLBACK", "reason": "ENOENT"}  → 切回 Mode A/A'
 *
 * Usage: node run_workflow.js --check-availability
 */
function checkAvailability() {
    // 通过 spawning `agy --version` 探测
    let reported = false;
    const child = spawn('agy', ['--version']);
    child.on('error', (err) => {
        if (err.code === 'ENOENT') {
            console.log(JSON.stringify({
                mode: 'AGENT_NATIVE_FALLBACK',
                reason: 'agy CLI not found in PATH (ENOENT)',
                instruction: '主 Agent 接管, 走 define_subagent (Antigravity) 或 task 工具 (opencode)'
            }));
            process.exit(0);
        } else {
            console.error(`[!] check-availability error: ${err.message}`);
            process.exit(2);
        }
    });
    child.stdout.on('data', (data) => {
        if (reported) return;
        reported = true;
        const version = data.toString().trim();
        console.log(JSON.stringify({
            mode: 'B_ANTIGRAVITY_CLI',
            agy_version: version,
            instruction: '可进入 Mode B, 由 run_workflow.js 编排 R1/R3/R4'
        }));
        process.exit(0);
    });
    child.on('close', (code) => {
        if (reported) return;  // stdout 已输出,无需重复
        console.log(JSON.stringify({
            mode: 'B_ANTIGRAVITY_CLI',
            agy_exit_code: code,
            note: code === 0 ? 'agy --version exit 0 (no stdout)' : `agy --version exit ${code},仍视为可用`,
            instruction: '可进入 Mode B, 由 run_workflow.js 编排 R1/R3/R4'
        }));
        process.exit(0);
    });
}

// 入口: --check-availability 短路(必须阻止 executeWorkflow 入口)
if (process.argv.includes('--check-availability')) {
    checkAvailability();
    // checkAvailability 内部进程退出;此处设置守卫标志,文件末尾入口检查后跳过 executeWorkflow
}

async function executeWorkflow(workspacePath) {
    console.log(`${colors.cyan}[*] 初始化 Reachable Critical Audit 工作流...${colors.reset}`);
    const scannerPath = path.join(__dirname, 'tools', 'ast_scanner.py');
    
    // 创建特殊文件夹以防污染源码
    const outputDir = path.join(workspacePath, '.audit_results');
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    
    const queuePath = path.join(outputDir, 'verify_queue.json');
    const reportPath = path.join(outputDir, 'reachable_vulnerabilities_report.json');

    // --- 阶段 1: 扫描/加载候选队列 ---
    let queue = [];
    if (fs.existsSync(queuePath)) {
        console.log(`${colors.yellow}[*] 发现已存在的队列文件 verify_queue.json，载入以支持断点续传模式...${colors.reset}`);
        queue = JSON.parse(fs.readFileSync(queuePath, 'utf8'));
    } else {
        console.log(`${colors.blue}[*] 未发现历史队列，启动本地 AST 扫描生成新队列...${colors.reset}`);
        try {
            // 同步执行初筛作为第一步，秒级速度
            const { execSync } = require('child_process');
            execSync(`python3 "${scannerPath}" "${workspacePath}" "${outputDir}"`, { stdio: 'inherit' });
            queue = JSON.parse(fs.readFileSync(queuePath, 'utf8'));
        } catch (error) {
            console.error(`${colors.red}[Error] AST 扫描器执行失败. 流程终止。${colors.reset}`);
            process.exit(1);
        }
    }

    const pendingCandidates = queue.filter(c => c.status === "PENDING");
    console.log(`${colors.green}[+] 队列载入成功: 总候选点数 ${queue.length}，剩余待分析点数 ${pendingCandidates.length}。${colors.reset}`);

    if (pendingCandidates.length === 0) {
        console.log(`${colors.green}[+] 所有候选点均已分析完毕，直接进行报告汇总。${colors.reset}`);
        compileReport(queue, reportPath);
        return;
    }

    // --- 阶段 2: 批处理异步并发审计循环 (REQ-01) ---
    console.log(`${colors.blue}[*] 阶段 2: 启动子智能体批处理并发研判 (每批大小: ${BATCH_SIZE})...${colors.reset}`);
    
    // 仅提取待处理的候选点索引
    const pendingIndices = queue
        .map((cand, index) => ({ cand, index }))
        .filter(item => item.cand.status === "PENDING");

    for (let i = 0; i < pendingIndices.length; i += BATCH_SIZE) {
        const batch = pendingIndices.slice(i, i + BATCH_SIZE);
        const batchNum = Math.floor(i / BATCH_SIZE) + 1;
        const totalBatches = Math.ceil(pendingIndices.length / BATCH_SIZE);

        console.log(`\n==================================================`);
        console.log(`${colors.yellow}[*] 执行审计批次 [Batch: ${batchNum}/${totalBatches}] (并发数: ${batch.length})${colors.reset}`);
        console.log(`==================================================`);

        // 并发执行当前批次
        await Promise.all(batch.map(async ({ cand, index }) => {
            console.log(`${colors.blue}[*] [ID: ${cand.id}] 开始验证... (CWE: ${cand.cwe_id} | File: ${path.basename(cand.file_path)}:${cand.line_number})${colors.reset}`);

            // 组装专属审计 Prompt
            let prompt = "";
            if (cand.type === "PROPERTY_CHECK") {
                prompt = `
请对以下代码候选点进行【业务逻辑越权审计】。你可以调用 read_file_segment, find_callers 等工具：
- 语言: ${cand.language}
- CWE类别: ${cand.cwe_id} (${cand.category})
- 敏感API文件: ${cand.file_path}
- 行号: ${cand.line_number}
- 代码内容: ${cand.sink_content}
- 验证逻辑指导: ${cand.verification_logic}

请执行以下校验步骤：
1. 深入阅读该敏感写操作方法体，并回溯其上游控制器方法。
2. 重点审查代码中是否缺失了属主关系比对（例如，是否验证了当前会话登录的用户ID等于被修改数据的所有者ID，如 session.userId == data.userId）。
3. 检查是否有权限拦截装饰器。若缺乏任何归属比对，判定为越权逻辑漏洞。

请输出最终结论：YES (确认存在越权越权逻辑漏洞) 或 NO (安全/已做属主校验)。并提供分析证据。
`;
            } else {
                prompt = `
请对以下代码的目标调用进行【数据流参数控制关系分析】。你可以使用 find_callers, read_file_segment 等代码定位工具：
- 语言: ${cand.language}
- 分析类别: ${cand.category}
- 目标调用文件: ${cand.file_path}
- 目标调用行号: ${cand.line_number}
- 目标代码内容: ${cand.sink_content}
- 校验要求: ${cand.reachability_constraints || "分析入参是否经过严格的安全过滤或强类型转换"}

验证步骤：
1. 追溯调用该目标函数代码的上游函数和控制器入口。
2. 检查这些上游调用链中的参数，是否直接或间接地被外部可控输入（例如 ${cand.sources_regex.join(', ')} 等）所控制。
3. 校验路径上是否有健全的类型转换、白名单过滤或编码转义处理将外部控制关系隔断。

请输出最终结论：YES (确认外部输入可控制该目标调用且没有被妥善处理) 或 NO (不可控/或已被安全隔离)。并给出完整的分析证据链。
`;
            }

            // 直接通过数组传参给 spawn，操作系统层级传递，免去 shell 特殊字符转义
            const args = ['--dangerously-skip-permissions', '--prompt', prompt];

            try {
                // 异步拉起子会话执行
                const stdout = await runAgentCmd(args);

                // REQ-01 / REQ-17 降级保护: 若返回结构化 fallback 对象, 引导主 Agent 接管并安全退出
                if (typeof stdout === 'object' && stdout.mode === 'AGENT_NATIVE_FALLBACK') {
                    console.log(`${colors.yellow}[!] 检测到处于 Agent-Native 平台模式 (agy 不可用: ${stdout.reason})。${colors.reset}`);
                    console.log(`${colors.cyan}[*] 按照 REQ-01 规范，流程由主 Agent 直接接管 (Mode A/A')。关闭当前 CLI 编排器。${colors.reset}`);
                    process.exit(0);
                }

                const hasYes = typeof stdout === 'string' && stdout.includes('YES');
                const hasNo = typeof stdout === 'string' && stdout.includes('NO');
                
                let status = 'NEEDS_REVIEW';
                if (hasYes && !hasNo) {
                    status = 'REACHABLE';
                } else if (hasNo && !hasYes) {
                    status = 'UNREACHABLE';
                }
                
                // 将结果写回内存 queue 中对应的索引起点
                queue[index].status = status;
                queue[index].verdict = stdout;

                // Propagate verdict to identical candidates in the queue (Optimization 2)
                const identicals = queue.filter(item => 
                    item.file_path === cand.file_path && 
                    item.line_number === cand.line_number && 
                    item.cwe_id === cand.cwe_id && 
                    item.status === "PENDING"
                );
                identicals.forEach(item => {
                    item.status = status;
                    item.verdict = `[Propagated from ID: ${cand.id}] ${stdout}`;
                });
                if (identicals.length > 0) {
                    console.log(`${colors.green}[+] [ID: ${cand.id}] 判定结果自动传播至 ${identicals.length} 个相同的候选点。${colors.reset}`);
                }

                if (status === 'REACHABLE') {
                    console.log(`${colors.red}[!] [ID: ${cand.id}] 判定结果: REACHABLE (确认真实漏洞)${colors.reset}`);
                } else if (status === 'UNREACHABLE') {
                    console.log(`${colors.green}[✓] [ID: ${cand.id}] 判定结果: UNREACHABLE (安全阻断)${colors.reset}`);
                } else {
                    console.log(`${colors.yellow}[?] [ID: ${cand.id}] 判定结果: NEEDS_REVIEW (研判不确定/拒绝)${colors.reset}`);
                }
            } catch (err) {
                console.error(`${colors.red}[!] [ID: ${cand.id}] 研判异常: ${err.message}${colors.reset}`);
                queue[index].status = 'NEEDS_REVIEW';
                queue[index].verdict = `ERROR: Execution failed: ${err.message}`;
            }
        }));

        // 【安全落盘机制】：当前批次并发运行完，立即写盘，支持断点重启
        fs.writeFileSync(queuePath, JSON.stringify(queue, null, 2), 'utf8');
        console.log(`\n${colors.cyan}[*] 批次 [Batch: ${batchNum}] 审计完毕，进度状态已落盘保存。${colors.reset}`);
    }

    // --- 阶段 3: 强制完整性断言校验 (Assert) ---
    console.log(`\n==================================================`);
    console.log(`${colors.cyan}[*] 阶段 3: 执行队列完整性审计断言校验...${colors.reset}`);
    
    // 重新从硬盘读取核对
    const finalQueue = JSON.parse(fs.readFileSync(queuePath, 'utf8'));
    const unverifiedItems = finalQueue.filter(c => c.status === "PENDING");

    if (unverifiedItems.length > 0) {
        console.error(`${colors.red}[CRITICAL ERROR] 完整性校验失败！仍有 ${unverifiedItems.length} 个节点未被分析！${colors.reset}`);
        unverifiedItems.forEach(item => {
            console.error(`  - 未处理节点 ID: ${item.id} | File: ${item.file_path}:${item.line_number}`);
        });
        process.exit(2);
    }

    console.log(`${colors.green}[✓] 完整性校验通过：所有 ${finalQueue.length} 个安全问题已100%分析归档，无任何跳过。${colors.reset}`);

    // --- 阶段 4: 启发式架构感知与业务逻辑 Subagent 深度深钻 (REQ-14 ~ REQ-16) ---
    console.log(`\n==================================================`);
    console.log(`${colors.yellow}[*] 阶段 4: 启动启发式项目感知与业务逻辑 Subagent 深度深钻 (REQ-14 ~ REQ-16)...${colors.reset}`);
    
    // REQ-14: 启发式项目架构与业务域自动感知并落盘
    const domainProfile = inferProjectDomain(workspacePath);
    const archViewPath = path.join(outputDir, 'architecture_view.json');
    fs.writeFileSync(archViewPath, JSON.stringify(domainProfile, null, 2), 'utf8');
    console.log(`${colors.cyan}[+] [REQ-14] 项目架构与业务域推断写入 ${archViewPath}: ${domainProfile.domainName}${colors.reset}`);

    // REQ-15: 固化 6 类业务威胁假说推演与锚点构建
    const highRiskFiles = findHighRiskModules(workspacePath);
    const autonomousFindings = [];

    if (highRiskFiles.length === 0) {
        console.log(`${colors.green}[✓] 未发现典型高危业务逻辑模块，跳过自主逻辑探索。${colors.reset}`);
    } else {
        console.log(`${colors.blue}[*] [REQ-15] 假说推演匹配到以下 ${highRiskFiles.length} 个高危业务控制锚点，开始调度 Subagent 并行深钻：${colors.reset}`);
        highRiskFiles.forEach(f => console.log(`  - ${f}`));

        // REQ-16: 业务逻辑专项 Subagent 并行深钻 (6类固化假说)
        const autonomousBatchSize = 3;
        for (let j = 0; j < highRiskFiles.length; j += autonomousBatchSize) {
            const batchFiles = highRiskFiles.slice(j, j + autonomousBatchSize);
            await Promise.all(batchFiles.map(async (filePath) => {
                console.log(`${colors.blue}[*] [REQ-16 Subagent] 开始深钻模块: ${filePath}...${colors.reset}`);
                
                const prompt = `
你是一个资深安全审计专家。我们现在要对项目 [${domainProfile.domainName}] 中的高危业务模块进行【6类固化业务逻辑假说深钻 (REQ-15 ~ REQ-16)】。
目标文件路径：${filePath}
项目领域背景：${domainProfile.summary}

请你结合代码结构、控制流与状态机设计，回应以下 6 类固定假说：
1. CWE-789 远端控制 allocation size: 远端字段 * sizeof 进 *alloc/new[]/osi_*alloc 无上限
2. CWE-125/787 远端控制解引用长度/索引: 远端字段进数组下标/memcpy 长度/STREAM_TO_* 无边界检查
3. CWE-416 异步对象生命周期竞态: 异步回调/队列/alarm 持 Unretained(this)/raw ptr, 对象先释放
4. 跨进程信任边界破坏: 远端输入拼字符串进 ContentResolver.query/Binder/Intent 且参数化字段 null
5. Exported component 鉴权缺失: manifest exported=true 且无 permission
6. 多租户/owner 比对缺失: 写/删/查资源方法体无 session vs owner 相等性比对

必须为每个适用的假说给出明确结论：confirmed (已坐实) | reviewed_clean (已审查无问题) | not_applicable (不适用)。

如果确认存在漏洞，请在回复中包含: HYPOTHESIS_CONFIRMED: [假说名称] - [简短说明]
如果审查无问题，包含: HYPOTHESIS_CLEAN: [假说名称] - [简短说明]
`;

                const args = ['--dangerously-skip-permissions', '--prompt', prompt];
                try {
                    const stdout = await runAgentCmd(args);
                    if (typeof stdout === 'object' && stdout.mode === 'AGENT_NATIVE_FALLBACK') {
                        return;
                    }
                    const confirmedMatch = stdout.match(/HYPOTHESIS_CONFIRMED:\s*([^\r\n]+)/);
                    const cleanMatch = stdout.match(/HYPOTHESIS_CLEAN:\s*([^\r\n]+)/);

                    if (confirmedMatch) {
                        console.log(`${colors.red}[!] [Subagent 深钻] 模块 ${filePath} 判定存在漏洞: ${confirmedMatch[1].trim()}${colors.reset}`);
                        autonomousFindings.push({
                            file_path: filePath,
                            origin: "R4",
                            status: 'REACHABLE',
                            verdict: 'confirmed',
                            summary: confirmedMatch[1].trim(),
                            evidence: stdout
                        });
                    } else if (cleanMatch) {
                        console.log(`${colors.green}[✓] [Subagent 深钻] 模块 ${filePath} 判定安全: ${cleanMatch[1].trim()}${colors.reset}`);
                        autonomousFindings.push({
                            file_path: filePath,
                            origin: "R4",
                            status: 'UNREACHABLE',
                            verdict: 'reviewed_clean',
                            summary: cleanMatch[1].trim(),
                            evidence: stdout
                        });
                    } else {
                        console.log(`${colors.yellow}[?] [Subagent 深钻] 模块 ${filePath} 判定未决${colors.reset}`);
                        autonomousFindings.push({
                            file_path: filePath,
                            origin: "R4",
                            status: 'NEEDS_REVIEW',
                            verdict: 'needs_review',
                            summary: '未明确输出假说结论，需要人工复核。',
                            evidence: stdout
                        });
                    }
                } catch (err) {
                    console.error(`${colors.red}[!] [Subagent 深钻] 模块 ${filePath} 审计异常: ${err.message}${colors.reset}`);
                    autonomousFindings.push({
                        file_path: filePath,
                        origin: "R4",
                        status: 'NEEDS_REVIEW',
                        verdict: 'execution_failed',
                        summary: `ERROR: Execution failed: ${err.message}`,
                        evidence: `ERROR: ${err.message}`
                    });
                }
            }));
        }

        // 保存自主探索的中间结果
        const autonomousPath = path.join(outputDir, 'autonomous_logical_findings.json');
        fs.writeFileSync(autonomousPath, JSON.stringify(autonomousFindings, null, 2), 'utf8');
        console.log(`${colors.green}[+] 启发式业务逻辑深钻结束，中间结果已落盘：${autonomousPath}${colors.reset}`);
    }

    compileReport(finalQueue, reportPath, autonomousFindings, workspacePath);
}

// REQ-14 启发式项目架构与业务域感知函数
function inferProjectDomain(workspacePath) {
    let domainName = "通用开源应用/服务";
    let summary = "常规代码库，包含标准模块交互。";

    // 检查元数据文件
    const hasAndroid = fs.existsSync(path.join(workspacePath, 'AndroidManifest.xml'));
    const hasBluetooth = fs.existsSync(path.join(workspacePath, 'system', 'btif')) || fs.existsSync(path.join(workspacePath, 'android', 'app', 'src', 'com', 'android', 'bluetooth'));
    const hasProto = fs.existsSync(path.join(workspacePath, 'proto')) || fs.existsSync(path.join(workspacePath, 'system', 'gd'));

    if (hasBluetooth || (hasAndroid && workspacePath.toLowerCase().includes('bluetooth'))) {
        domainName = "Android 原生蓝牙协议栈与系统服务 (Bluetooth Module)";
        summary = "包含 HCI、L2CAP、SDP、GATT、HFP、OPP、MAP 等底层 C++ 协议栈与 Android 上层 Java IPC 服务，强依赖状态机与 Binder 访问控制。";
    } else if (hasAndroid) {
        domainName = "Android 系统服务 / 应用 (Android App/Service)";
        summary = "包含 Activity/Service/Provider 组件交互、Binder IPC 及权限拦截。";
    } else if (fs.existsSync(path.join(workspacePath, 'package.json'))) {
        domainName = "Node.js / Web 应用服务";
        summary = "基于 JavaScript/TypeScript 的 Web 后端或 CLI 工具。";
    } else if (fs.existsSync(path.join(workspacePath, 'Cargo.toml'))) {
        domainName = "Rust 系统级模块/应用";
        summary = "基于 Rust 语言的底层高性能服务与内存安全管控。";
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
    const ignoreDirs = ['node_modules', '.git', '.audit_results', 'scratch', 'target', 'build', 'dist'];

    function walk(dir) {
        let list;
        try {
            list = fs.readdirSync(dir);
        } catch (e) {
            return;
        }
        list.forEach(file => {
            const fullPath = path.join(dir, file);
            let stat;
            try {
                stat = fs.statSync(fullPath);
            } catch (e) {
                return;
            }
            if (stat && stat.isDirectory()) {
                if (!ignoreDirs.some(ignored => file.includes(ignored))) {
                    walk(fullPath);
                }
            } else {
                const ext = path.extname(file).toLowerCase();
                const validExts = ['.java', '.cpp', '.cc', '.c', '.h', '.py', '.go', '.rs', '.js', '.ts', '.cs', '.php', '.rb', '.swift', '.kt', '.scala', '.sh', '.pl', '.pm', '.ps1'];
                if (validExts.includes(ext)) {
                    const relativePath = path.relative(workspacePath, fullPath);
                    const nameLower = file.toLowerCase();
                    if (keywords.some(kw => nameLower.includes(kw))) {
                        highRiskFiles.push(relativePath);
                    }
                }
            }
        });
    }

    walk(workspacePath);
    return highRiskFiles.slice(0, 6); // 最多选择前 6 个文件
}

// REQ-10 完整的量化度量报告生成 (含 Sink Discovery Rate, False Negative Risk, origin_breakdown)
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

    const coverageRate = total > 0 ? ((verifiedTotal / total) * 100).toFixed(2) : "0.00";
    const reachabilityRate = verifiedTotal > 0 ? ((reachable.length / verifiedTotal) * 100).toFixed(2) : "0.00";
    const noiseReductionRate = verifiedTotal > 0 ? ((unreachable.length / verifiedTotal) * 100).toFixed(2) : "0.00";
    const sinkDiscoveryRate = total > 0 ? ((l0Count / total) * 100).toFixed(2) : "0.00";
    const falseNegativeRisk = total > 0 ? (((l1Count + r4Reachable) / total) * 100).toFixed(2) : "0.00";

    const reportContent = {
        report_meta: {
            generated_at: new Date().toISOString(),
            schema_version: "2.0"
        },
        quantified_metrics: {
            total_candidates: total,
            verified: verifiedTotal,
            reachable: reachable.length,
            unreachable: unreachable.length,
            needs_review: needsReview.length,
            rule_coverage_rate_pct: `${coverageRate}%`,
            reachability_rate_pct: `${reachabilityRate}%`,
            noise_reduction_rate_pct: `${noiseReductionRate}%`,
            sink_discovery_rate_pct: `${sinkDiscoveryRate}%`,
            false_negative_risk_pct: `${falseNegativeRisk}%`,
            origin_breakdown: {
                L0: l0Count,
                L1: l1Count,
                L2: l2Count,
                R4: r4Count
            }
        },
        reachable_vulnerabilities: reachable.map(c => ({
            id: c.id,
            origin: c.origin || 'L0',
            language: c.language,
            cwe_id: c.cwe_id || c.sink_type,
            category: c.category,
            type: c.type,
            source_file: c.source_file || c.file_path,
            source_line: c.source_line || c.line_number,
            reachability_type: c.reachability_type || 'DIRECT',
            sink_content: c.sink_content,
            evidence: c.verdict
        })),
        needs_review: needsReview.map(c => ({
            id: c.id,
            origin: c.origin || 'L0',
            source_file: c.source_file || c.file_path,
            source_line: c.source_line || c.line_number,
            sink_type: c.sink_type || c.cwe_id,
            blocking_point: c.blocking_point || null,
            reason: c.verdict || "研判拒绝或返回模糊"
        })),
        autonomous_findings: autonomousFindings.map(f => ({
            file_path: f.file_path,
            origin: "R4",
            status: f.status,
            summary: f.summary,
            evidence: f.evidence
        }))
    };

    // 写出 JSON 报告
    fs.writeFileSync(reportJsonPath, JSON.stringify(reportContent, null, 2), 'utf8');

    // 写出 Markdown 报告 (REQ-10)
    const reportMdPath = path.join(path.dirname(reportJsonPath), 'reachable_vulnerabilities_report.md');
    let mdText = `# Reachable Critical Audit 安全审计报告\n\n`;
    mdText += `生成时间: ${reportContent.report_meta.generated_at}\n\n`;
    mdText += `## 📊 量化审计指标\n\n`;
    mdText += `| 指标名称 | 数值 | 说明 |\n`;
    mdText += `|---|---|---|\n`;
    mdText += `| 候选点总数 (Total) | ${total} | 覆盖 L0/L1/L2/R4 所有来源 |\n`;
    mdText += `| 已验证候选数 (Verified) | ${verifiedTotal} | 推进至 REACHABLE / UNREACHABLE 状态点数 |\n`;
    mdText += `| 确认可达漏洞数 (Reachable) | ${reachable.length} | 存在真实可利用威胁的漏洞点 |\n`;
    mdText += `| 安全阻断噪音数 (Unreachable) | ${unreachable.length} | 被白名单/类型转换隔断的噪音 |\n`;
    mdText += `| 待人工复核数 (Needs Review) | ${needsReview.length} | 研判未决或被阻断的节点 |\n`;
    mdText += `| **Rule Coverage Rate** | **${coverageRate}%** | 已验证候选 / 总候选 |\n`;
    mdText += `| **Reachability Rate** | **${reachabilityRate}%** | 可达漏洞占比 |\n`;
    mdText += `| **Noise Reduction Rate** | **${noiseReductionRate}%** | 噪音降噪率 |\n`;
    mdText += `| **Sink Discovery Rate** | **${sinkDiscoveryRate}%** | L0 规则召回能力（越接近 100% 规则越完备） |\n`;
    mdText += `| **False Negative Risk** | **${falseNegativeRisk}%** | 规则盲区指标（高占比需补齐 L0 规则） |\n\n`;
    mdText += `### 候选来源分布 (Origin Breakdown)\n\n`;
    mdText += `- **L0 (预设 CodeQL 清洗规则)**: ${l0Count}\n`;
    mdText += `- **L1 (项目 Wrapper 框架扩展)**: ${l1Count}\n`;
    mdText += `- **L2 (非预设语言 fallback)**: ${l2Count}\n`;
    mdText += `- **R4 (启发式业务逻辑深钻)**: ${r4Count}\n\n`;

    if (reachable.length > 0) {
        mdText += `## 🚨 确认真实漏洞 (Reachable Vulnerabilities)\n\n`;
        reachable.forEach(c => {
            mdText += `### [${c.id}] ${c.cwe_id || c.sink_type} - ${c.category}\n`;
            mdText += `- **位置**: \`${c.source_file || c.file_path}:${c.source_line || c.line_number}\`\n`;
            mdText += `- **来源**: ${c.origin || 'L0'}\n`;
            mdText += `- **可达类型**: ${c.reachability_type || 'DIRECT'}\n`;
            mdText += `- **Sink 代码**: \`${c.sink_content}\`\n`;
            mdText += `- **归因分析**: ${c.verdict}\n\n`;
        });
    }

    if (needsReview.length > 0) {
        mdText += `## ⚠️ 待复核节点 (Needs Review)\n\n`;
        needsReview.forEach(c => {
            mdText += `- **[${c.id}]** \`${c.source_file || c.file_path}:${c.source_line || c.line_number}\` (${c.sink_type || c.cwe_id}) — 原因: ${c.verdict || "研判拒绝"}\n`;
        });
    }

    fs.writeFileSync(reportMdPath, mdText, 'utf8');
    console.log(`${colors.green}[+] 审计报告已生成:\n  - JSON: ${reportJsonPath}\n  - Markdown: ${reportMdPath}${colors.reset}`);
}

const targetDir = process.argv[2] || '.';
// 入口守卫: --check-availability 时由 checkAvailability 处理,不进入 executeWorkflow
if (!process.argv.includes('--check-availability')) {
    executeWorkflow(targetDir);
}

