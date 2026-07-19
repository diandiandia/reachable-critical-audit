const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

/**
 * Reachable Critical Audit - CLI Workflow Orchestrator (Node.js)
 * 
 * 具备【并发批处理 / 物理隔离 / 实时落盘断点保护】的安全审计工作流：
 * 1. 执行本地 AST 物理扫描，加载/生成 verify_queue.json 持久化队列。
 * 2. 按照每次启动 3-5 个（默认 4 个）子智能体的并发方式，进行批处理循环研判。
 * 3. 异步调度 CLI 会话，子智能体上下文物理隔离。
 * 4. 每批次运行结束后【实时落盘】，断点续传，最终进行 Assert 完整性拦截校验。
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

// 封装异步子进程调用，支持并发运行
function runAgentCmd(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                reject(error);
            } else {
                resolve(stdout);
            }
        });
    });
}

async function executeWorkflow(workspacePath) {
    console.log(`${colors.cyan}[*] 初始化 Reachable Critical Audit 工作流...${colors.reset}`);
    const scannerPath = path.join(workspacePath, 'tools', 'ast_scanner.py');
    const queuePath = path.join(workspacePath, 'verify_queue.json');
    const reportPath = path.join(workspacePath, 'reachable_vulnerabilities_report.json');

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
            execSync(`python "${scannerPath}" "${workspacePath}"`, { stdio: 'inherit' });
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
请对以下代码候选点进行【污点可达性分析】。你可以调用 find_callers, read_file_segment 等本地工具：
- 语言: ${cand.language}
- CWE类别: ${cand.cwe_id} (${cand.category})
- 敏感 Sink 点文件: ${cand.file_path}
- 敏感 Sink 行号: ${cand.line_number}
- 敏感 Sink 内容: ${cand.sink_content}
- 验证约束指导: ${cand.reachability_constraints}

验证步骤：
1. 查找调用该敏感 Sink 方法的上游函数。
2. 检查这些上游调用链路中的参数传递，是否能被外部输入源(${cand.sources_regex.join(', ')})控制。
3. 校验路径上是否有类型转换或 Sanitizer 将数据流阻断。

请输出最终结论：YES (确认真实污染可达) 或 NO (不可达)。并给出完整的分析证据链。
`;
            }

            const safePrompt = prompt.replace(/"/g, '\\"').replace(/\n/g, ' ');
            const command = `agy agent run --prompt "${safePrompt}"`;

            try {
                // 异步拉起子会话执行
                const stdout = await runAgentCmd(command);
                const isReachable = stdout.includes('YES');
                
                // 将结果写回内存 queue 中对应的索引起点
                queue[index].status = isReachable ? 'REACHABLE' : 'UNREACHABLE';
                queue[index].verdict = stdout;

                if (isReachable) {
                    console.log(`${colors.red}[!] [ID: ${cand.id}] 判定结果: REACHABLE (确认真实漏洞)${colors.reset}`);
                } else {
                    console.log(`${colors.green}[✓] [ID: ${cand.id}] 判定结果: UNREACHABLE (安全阻断)${colors.reset}`);
                }
            } catch (err) {
                console.error(`${colors.red}[!] [ID: ${cand.id}] 异常崩溃: ${err.message}${colors.reset}`);
                queue[index].status = 'NEEDS_REVIEW';
                queue[index].verdict = `ERROR: Execution failed: ${err.message}`;
            }
        }));

        // 【安全落盘机制】：当前批次并发运行完，立即写盘，支持断点重启，并保证即使某批次故障，状态依然不被遗漏
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
    compileReport(finalQueue, reportPath);
}

function compileReport(queue, reportPath) {
    const reachable = queue.filter(c => c.status === 'REACHABLE');
    const unreachable = queue.filter(c => c.status === 'UNREACHABLE');
    const failed = queue.filter(c => c.status === 'NEEDS_REVIEW');

    const total = queue.length;
    const verifiedTotal = reachable.length + unreachable.length;
    const coverageRate = ((verifiedTotal / total) * 100).toFixed(2);
    const reachabilityRate = ((reachable.length / total) * 100).toFixed(2);
    const noiseReductionRate = ((unreachable.length / total) * 100).toFixed(2);

    const reportContent = {
        metrics: {
            total_candidates: total,
            verified: verifiedTotal,
            reachable_vulnerabilities: reachable.length,
            unreachable_noise: unreachable.length,
            failed_execution: failed.length,
            coverage_rate: `${coverageRate}%`,
            reachability_rate: `${reachabilityRate}%`,
            noise_reduction_rate: `${noiseReductionRate}%`
        },
        findings: queue.map(c => ({
            id: c.id,
            language: c.language,
            cwe_id: c.cwe_id,
            category: c.category,
            type: c.type,
            location: `${c.file_path}:${c.line_number}`,
            sink_content: c.sink_content,
            status: c.status,
            evidence: c.verdict
        }))
    };

    fs.writeFileSync(reportPath, JSON.stringify(reportContent, null, 2), 'utf8');
    console.log(`${colors.green}[+] 审计报告已安全输出至: ${reportPath}${colors.reset}`);
}

const targetDir = process.argv[2] || '.';
executeWorkflow(targetDir);
