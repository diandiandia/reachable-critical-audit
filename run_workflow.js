const fs = require('fs');
const path = require('path');
const { spawn, execSync, execFileSync } = require('child_process');

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

const REQUIRED_VERDICT_KEYS = ['verdict', 'reachability_type', 'call_chain', 'call_chain_depth', 'evidence'];
const VALID_VERDICTS = ['REACHABLE', 'UNREACHABLE', 'NEEDS_REVIEW'];
const VALID_REACHABILITY_TYPES = ['DIRECT', 'ACROSS_BOUNDARY', 'INDIRECT', null];
const MIN_CALL_CHAIN_DEPTH = 3;

// ==================== 平台自适应层 ====================

/**
 * 检测当前环境可用的 AI CLI 工具。
 * 优先级: 环境变量 > claude > agy > codex
 */
function findAgentCli() {
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
    return null;
}

function detectAgentCli() {
    const cli = findAgentCli();
    if (cli) return cli;
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

const TREE_SITTER_DEPS = [
    'tree-sitter',
    'tree-sitter-java',
    'tree-sitter-cpp',
    'tree-sitter-python',
    'tree-sitter-javascript',
    'tree-sitter-go',
    'tree-sitter-rust',
    'tree-sitter-c-sharp',
    'tree-sitter-php',
    'tree-sitter-ruby',
    'tree-sitter-swift',
    'tree-sitter-kotlin',
    'tree-sitter-scala'
];

let PYTHON_BIN_CACHE = null;

function skillVenvDir() {
    return process.env.REACHABLE_AUDIT_VENV || path.join(__dirname, '.venv');
}

function venvPythonPath() {
    return path.join(skillVenvDir(), 'bin', 'python3');
}

function pythonBin() {
    if (PYTHON_BIN_CACHE) return PYTHON_BIN_CACHE;
    if (process.env.PYTHON_BIN) return process.env.PYTHON_BIN;
    const venvPython = venvPythonPath();
    return fs.existsSync(venvPython) ? venvPython : 'python3';
}

function ensureWorkflowPython() {
    if (process.env.PYTHON_BIN) {
        PYTHON_BIN_CACHE = process.env.PYTHON_BIN;
        return PYTHON_BIN_CACHE;
    }

    const venvPython = venvPythonPath();
    if (!fs.existsSync(venvPython)) {
        const venvDir = skillVenvDir();
        console.log(`${colors.blue}[*] 未发现 skill-local .venv，创建 Python 虚拟环境: ${venvDir}${colors.reset}`);
        execFileSync('python3', ['-m', 'venv', venvDir], { stdio: 'inherit' });
    }
    PYTHON_BIN_CACHE = venvPython;
    return PYTHON_BIN_CACHE;
}

function installTreeSitterDeps(pyBin) {
    console.log(`${colors.blue}[*] 安装 tree-sitter grammar 依赖到 skill-local .venv...${colors.reset}`);
    execFileSync(pyBin, ['-m', 'pip', 'install', ...TREE_SITTER_DEPS], { stdio: 'inherit' });
}

function runAstSelfCheck(scannerPath) {
    const pyBin = ensureWorkflowPython();
    try {
        execFileSync(pyBin, [scannerPath, '--self-check'], { stdio: 'inherit' });
    } catch (error) {
        if (process.env.PYTHON_BIN) {
            throw error;
        }
        installTreeSitterDeps(pyBin);
        execFileSync(pyBin, [scannerPath, '--self-check'], { stdio: 'inherit' });
    }
}

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
    if (path.basename(path.dirname(path.resolve(queuePath))) !== '.audit_results') {
        throw new Error(`Refusing to write queue outside .audit_results: ${queuePath}`);
    }
    if (rawWrapper === null) {
        // Legacy array format
        fs.writeFileSync(queuePath, JSON.stringify(candidates, null, 2), 'utf8');
    } else {
        // Schema 2.0 object format
        rawWrapper.candidates = candidates;
        fs.writeFileSync(queuePath, JSON.stringify(rawWrapper, null, 2), 'utf8');
    }
}

function assertAuditResultPath(outputDir, targetPath) {
    const base = path.resolve(outputDir);
    const target = path.resolve(targetPath);
    if (path.basename(base) !== '.audit_results') {
        throw new Error(`Audit output directory must be .audit_results: ${base}`);
    }
    if (target !== base && !target.startsWith(base + path.sep)) {
        throw new Error(`Refusing to write outside .audit_results: ${target}`);
    }
    return target;
}

function writeAuditJson(outputDir, filename, value) {
    const target = assertAuditResultPath(outputDir, path.join(outputDir, filename));
    fs.writeFileSync(target, JSON.stringify(value, null, 2), 'utf8');
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

function extractJsonObjectWithKey(stdout, key) {
    if (typeof stdout !== 'string') return null;
    const keyIndex = stdout.indexOf(`"${key}"`);
    if (keyIndex < 0) return null;

    const start = stdout.lastIndexOf('{', keyIndex);
    const end = stdout.lastIndexOf('}');
    if (start < 0 || end <= start) return null;

    try {
        return JSON.parse(stdout.slice(start, end + 1));
    } catch (e) {
        return null;
    }
}

function normalizeVerdictValue(value) {
    if (typeof value !== 'string') return null;
    const upper = value.toUpperCase();
    return VALID_VERDICTS.includes(upper) ? upper : null;
}

function extractVerdictResult(stdout) {
    const parsed = extractJsonObjectWithKey(stdout, 'verdict');
    const verdict = normalizeVerdictValue(parsed && parsed.verdict) || extractVerdict(stdout);
    const callChain = Array.isArray(parsed && parsed.call_chain) ? parsed.call_chain : [];

    return {
        structured: !!parsed,
        raw_keys: parsed ? Object.keys(parsed) : [],
        verdict,
        reachability_type: parsed && parsed.reachability_type ? parsed.reachability_type : null,
        call_chain: callChain,
        call_chain_depth: Number.isInteger(parsed && parsed.call_chain_depth) ? parsed.call_chain_depth : callChain.length,
        blocking_point: parsed && parsed.blocking_point ? parsed.blocking_point : null,
        path_count: Number.isInteger(parsed && parsed.path_count) ? parsed.path_count : 0,
        paths_analyzed: Array.isArray(parsed && parsed.paths_analyzed) ? parsed.paths_analyzed : [],
        evidence: parsed && parsed.evidence ? String(parsed.evidence) : String(stdout || '').slice(-2000),
        cwe: parsed && parsed.cwe ? parsed.cwe : null
    };
}

function normalizeVerifierResult(result) {
    const issues = [];
    if (!result.structured) {
        issues.push('verifier did not return the required JSON object');
    }

    const missing = REQUIRED_VERDICT_KEYS.filter(k => !result.raw_keys.includes(k));
    if (missing.length) {
        issues.push(`missing required keys: ${missing.join(', ')}`);
    }

    if (!VALID_VERDICTS.includes(result.verdict)) {
        issues.push(`invalid verdict: ${result.verdict}`);
    }

    if (!VALID_REACHABILITY_TYPES.includes(result.reachability_type)) {
        issues.push(`invalid reachability_type: ${result.reachability_type}`);
    }

    if (!Array.isArray(result.call_chain)) {
        issues.push('call_chain must be an array');
        result.call_chain = [];
    }

    if (!Number.isInteger(result.call_chain_depth)) {
        issues.push('call_chain_depth must be an integer');
        result.call_chain_depth = result.call_chain.length;
    }

    if (result.verdict !== 'NEEDS_REVIEW' && result.call_chain_depth < MIN_CALL_CHAIN_DEPTH) {
        issues.push(`call_chain_depth=${result.call_chain_depth} < ${MIN_CALL_CHAIN_DEPTH}`);
    }

    if (issues.length) {
        result.verdict = 'NEEDS_REVIEW';
        result.reachability_type = result.reachability_type || null;
        result.evidence = `${result.evidence || ''}\n[AUTO NEEDS_REVIEW] ${issues.join('; ')}`.trim();
    }
    return result;
}

function normalizeQueueState(candidates) {
    candidates.forEach(c => {
        const legacyVerdict = normalizeVerdictValue(c.status);
        if (!legacyVerdict) return;
        if (!normalizeVerdictValue(c.verdict)) {
            c.evidence = c.verdict || c.evidence || '';
            c.verdict = legacyVerdict;
        }
        c.status = 'VERIFIED';
    });
}

/**
 * 从 R4 Subagent stdout 中提取假说判定。
 */
function extractHypothesisVerdict(stdout, hypothesis) {
    const parsed = extractJsonObjectWithKey(stdout, 'hypothesis_id');
    if (!parsed || parsed.hypothesis_id !== hypothesis.id ||
        !['confirmed', 'reviewed_clean', 'not_applicable'].includes(parsed.verdict)) {
        return {
            hypothesis_id: hypothesis.id,
            hypothesis: hypothesis.title,
            origin: 'R4',
            status: 'VERIFIED',
            verdict: 'NEEDS_REVIEW',
            hypothesis_verdict: 'needs_review',
            cwe: hypothesis.cwe,
            findings: [],
            coverage_note: 'R4 子任务未返回符合 schema 的三选一 JSON 结论。',
            evidence: typeof stdout === 'string' ? stdout.slice(-2000) : String(stdout || '')
        };
    }

    return {
        hypothesis_id: hypothesis.id,
        hypothesis: hypothesis.title,
        origin: 'R4',
        status: 'VERIFIED',
        verdict: parsed.verdict === 'confirmed' ? 'REACHABLE' : 'UNREACHABLE',
        hypothesis_verdict: parsed.verdict,
        cwe: Array.isArray(parsed.cwe) ? parsed.cwe : hypothesis.cwe,
        findings: Array.isArray(parsed.findings) ? parsed.findings : [],
        coverage_note: parsed.coverage_note || '',
        evidence: typeof stdout === 'string' ? stdout.slice(-2000) : String(stdout || '')
    };
}

// ==================== Prompt 模板（结构化输出要求）====================

function buildVerifyPrompt(cand) {
    const outputFormat = `## 输出格式（强制 JSON，不要其他文字）
{
  "verdict": "REACHABLE | UNREACHABLE | NEEDS_REVIEW",
  "reachability_type": "DIRECT | ACROSS_BOUNDARY | INDIRECT",
  "call_chain": ["file:line:function", "file:line:function", "file:line:function"],
  "call_chain_depth": 3,
  "blocking_point": "file:line / null",
  "path_count": 1,
  "paths_analyzed": ["path description"],
  "evidence": "包含调用链和每层数据流路径分析的说明",
  "cwe": ["CWE-xxx"]
}`;

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
4. 无法明确判定时输出 verdict=NEEDS_REVIEW。

${outputFormat}`;
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
4. 无法明确判定时输出 verdict=NEEDS_REVIEW。

${outputFormat}`;
}

function buildR4Prompt(domainProfile, hypothesis, anchors, workspacePath) {
    const anchorText = anchors.length ? anchors.join('\n- ') : '全项目（未发现文件名锚点，仍需按假说搜索）';
    return `你是一个 business-logic-verifier 子智能体。请对项目 [${domainProfile.domainName}] 做固化业务逻辑假说深钻。

项目路径：${workspacePath}
项目领域背景：${domainProfile.summary}
假说 ID：${hypothesis.id}
假说名称：${hypothesis.title}
相关 CWE：${hypothesis.cwe.join(', ')}
建议优先检查锚点：
- ${anchorText}

请不限于锚点，在全项目搜索该假说的相关模式。若坐实漏洞，给出完整证据；若审查无问题，说明覆盖范围；若该项目不适用，说明理由。

输出格式（强制 JSON，不要其他文字）：
{
  "hypothesis_id": "${hypothesis.id}",
  "verdict": "confirmed | reviewed_clean | not_applicable",
  "cwe": ${JSON.stringify(hypothesis.cwe)},
  "findings": [
    {
      "title": "...",
      "severity": "Critical | High | Medium | Low",
      "call_chain": ["file:line", "..."],
      "evidence": "...",
      "fix": "..."
    }
  ],
  "coverage_note": "若 reviewed_clean，说明审查范围；若 not_applicable，说明理由"
}`;
}

// ==================== R1.5 框架感知扩展 (REQ-18, 始终执行) ====================

// 扩展名 → 语言 (与 ast_scanner / batch_verify 保持一致的子集)
const R15_EXT_LANG = {
    '.java': 'java', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.c': 'cpp',
    '.h': 'cpp', '.hpp': 'cpp', '.py': 'python', '.go': 'go', '.rs': 'rust',
    '.js': 'javascript', '.ts': 'javascript', '.jsx': 'javascript', '.tsx': 'javascript',
    '.cs': 'csharp', '.php': 'php', '.rb': 'ruby', '.swift': 'swift',
    '.kt': 'kotlin', '.kts': 'kotlin', '.scala': 'scala', '.sh': 'shell',
    '.pl': 'perl', '.pm': 'perl', '.ps1': 'powershell'
};
const R15_IGNORE_DIRS = ['node_modules', '.git', '.audit_results', '.agents', '.codex',
    '.venv', '__pycache__', 'reachable-critical-audit', 'build', 'target', 'dist',
    'vendor', 'third_party', 'libs', 'test', 'tests', 'tool', 'tools', 'script',
    'scripts', 'mock', 'mocks', 'unittest', 'scratch', 'demo'];
const L2_NON_SOURCE_EXTS = new Set([
    '', '.md', '.txt', '.json', '.lock', '.yaml', '.yml', '.toml', '.xml',
    '.html', '.css', '.csv', '.tsv', '.svg', '.png', '.jpg', '.jpeg', '.gif',
    '.pdf', '.zip', '.gz', '.tar', '.ico', '.map'
]);

function isIgnoredDirName(name) {
    return R15_IGNORE_DIRS.includes(name);
}

/** 统计项目各语言源文件数，返回按文件数降序的语言列表。 */
function detectLanguages(workspacePath) {
    const counts = {};
    function walk(dir, depth) {
        if (depth > 6) return;
        let list;
        try { list = fs.readdirSync(dir); } catch (e) { return; }
        for (const file of list) {
            const full = path.join(dir, file);
            let stat;
            try { stat = fs.statSync(full); } catch (e) { continue; }
            if (stat.isDirectory()) {
                if (!isIgnoredDirName(file)) walk(full, depth + 1);
            } else if (!file.includes('.min.')) {
                const lang = R15_EXT_LANG[path.extname(file).toLowerCase()];
                if (lang) counts[lang] = (counts[lang] || 0) + 1;
            }
        }
    }
    walk(workspacePath, 0);
    const langs = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
    return { langs, counts };
}

function loadL2FallbackRules() {
    const profilePath = path.join(__dirname, 'resources', 'security_profiles.json');
    const profile = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
    const rawRules = profile.l2_fallback_rules;
    if (!Array.isArray(rawRules) || rawRules.length < 10) {
        throw new Error('security_profiles.json l2_fallback_rules must contain at least 10 rules');
    }
    return rawRules.map((rule, idx) => {
        if (!rule.cwe_id || !rule.category || typeof rule.regex !== 'string') {
            throw new Error(`Invalid l2_fallback_rules[${idx}]`);
        }
        return {
            cwe_id: rule.cwe_id,
            category: rule.category,
            priority: Number.isInteger(rule.priority) ? rule.priority : 1,
            regex: new RegExp(rule.regex),
            regex_source: rule.regex,
        };
    });
}

const R4_HYPOTHESES = [
    { id: 'H-1', title: '远端控制 allocation size', cwe: ['CWE-789'] },
    { id: 'H-2', title: '远端控制解引用长度/索引', cwe: ['CWE-125', 'CWE-787'] },
    { id: 'H-3', title: '异步对象生命周期竞态', cwe: ['CWE-416'] },
    { id: 'H-4', title: '跨进程信任边界破坏', cwe: ['CWE-20', 'CWE-89', 'CWE-78'] },
    { id: 'H-5', title: 'Exported component 鉴权缺失', cwe: ['CWE-862', 'CWE-926'] },
    { id: 'H-6', title: '多租户/owner 比对缺失', cwe: ['CWE-639', 'CWE-285'] },
];

function collectUnknownSourceFiles(workspacePath) {
    const files = [];
    const extCounts = {};
    function walk(dir, depth) {
        if (depth > 8) return;
        let list;
        try { list = fs.readdirSync(dir); } catch (e) { return; }
        for (const file of list) {
            const full = path.join(dir, file);
            let stat;
            try { stat = fs.statSync(full); } catch (e) { continue; }
            if (stat.isDirectory()) {
                if (!isIgnoredDirName(file)) walk(full, depth + 1);
                continue;
            }
            if (file.includes('.min.')) continue;
            const ext = path.extname(file).toLowerCase();
            if (R15_EXT_LANG[ext] || L2_NON_SOURCE_EXTS.has(ext)) continue;
            files.push(full);
            extCounts[ext] = (extCounts[ext] || 0) + 1;
        }
    }
    walk(workspacePath, 0);
    return { files, extCounts };
}

function runL2Fallback(workspacePath, queue, outputDir) {
    const { files, extCounts } = collectUnknownSourceFiles(workspacePath);
    if (files.length === 0) return 0;
    const l2Rules = loadL2FallbackRules();

    const profile = {
        schema_version: '2.0',
        origin: 'L2',
        reviewed_by: 'main-agent',
        generated_at: new Date().toISOString(),
        unknown_extensions: Object.entries(extCounts)
            .map(([ext, count]) => ({ ext, count }))
            .sort((a, b) => b.count - a.count),
        rules: l2Rules.map(r => ({
            cwe_id: r.cwe_id,
            category: r.category,
            priority: r.priority,
            pattern: r.regex_source
        }))
    };
    writeAuditJson(outputDir, 'extended_profile.json', profile);

    let maxN = 0;
    const existingKeys = new Set();
    queue.forEach(c => {
        const cid = c.id || '';
        if (cid.startsWith('CAND-')) {
            const n = parseInt(cid.split('-')[1], 10);
            if (!isNaN(n)) maxN = Math.max(maxN, n);
        }
        existingKeys.add(`${c.file_path}|${c.line_number || c.source_line}|${c.cwe_id || c.sink_type}|${c.source_pattern || ''}`);
    });

    let added = 0;
    for (const filePath of files) {
        let content;
        try {
            content = fs.readFileSync(filePath, 'utf8');
        } catch (e) {
            continue;
        }
        const rel = path.relative(workspacePath, filePath);
        const lines = content.split(/\r?\n/);
        lines.forEach((line, idx) => {
            for (const rule of l2Rules) {
                if (!rule.regex.test(line)) continue;
                const key = `${rel}|${idx + 1}|${rule.cwe_id}|${rule.category}`;
                if (existingKeys.has(key)) break;
                existingKeys.add(key);
                maxN += 1;
                const sinkContent = line.trim().slice(0, 1000);
                queue.push({
                    id: `CAND-${String(maxN).padStart(3, '0')}`,
                    origin: 'L2',
                    language: path.extname(filePath).slice(1) || 'unknown',
                    file_path: rel,
                    source_file: rel,
                    line_number: idx + 1,
                    source_line: idx + 1,
                    cwe_id: rule.cwe_id,
                    sink_type: rule.cwe_id,
                    category: rule.category,
                    source_pattern: rule.regex_source,
                    type: 'TAINT_ANALYSIS',
                    sink_content: sinkContent,
                    priority: rule.priority,
                    status: 'PENDING',
                    verdict: null,
                    reachability_type: null,
                    blocking_point: null
                });
                added += 1;
                break;
            }
        });
    }
    console.log(`${colors.green}[L2] 非预设语言 fallback 已生成 extended_profile.json，并入 ${added} 个候选${colors.reset}`);
    return added;
}

/** 构建 framework-sink-extractor 任务书 (与 batch_verify._build_r15_prompt 对齐)。 */
function buildR15Prompt(lang, patterns, workspacePath) {
    const patLines = [];
    for (const [group, globs] of Object.entries(patterns)) {
        if (group.startsWith('_')) continue;
        patLines.push(`  - **${group}**: ${globs.join(', ')}`);
    }
    const patBlock = patLines.length ? patLines.join('\n') : '  (该语言无预置 wrapper 模式)';
    return `你是一个 framework-sink-extractor 子智能体 (R1.5 阶段)。你有完整的 grep/read 工具。

## 任务上下文
- **项目路径**: ${workspacePath}
- **目标语言**: ${lang}
- **wrapper_detection 模式** (名字匹配以下 glob 的、本项目自定义的函数/宏/方法):
${patBlock}

## 任务
1. 用 grep 在全项目 ${lang} 源码中，找出**名字匹配上述模式**、且是**本项目自定义**（非第三方库）的函数/宏/方法。
2. 判断它是否 wrapping 了 sink 性质：分配内存 / 执行命令 / 拼接 SQL / 跨进程调用 / 释放对象。
3. 判断远端/外部数据是否可能流入该 wrapper。

## 输出格式（强制 JSON，不要其他文字）
{"extended_sinks":[{"file":"相对路径","line":123,"wrapper_name":"osi_calloc","matched_pattern":"allocator_pattern:osi_*","inferred_sink_type":"CWE-789 UncontrolledMemoryAllocation","remote_data_reachable":true,"evidence":"一句话说明"}]}
若未发现，返回 {"extended_sinks":[]}。`;
}

/** 从子进程 stdout 提取 extended_sinks 数组。 */
function extractExtendedSinks(stdout) {
    if (typeof stdout !== 'string') return [];
    const m = stdout.match(/\{[\s\S]*"extended_sinks"[\s\S]*\}/);
    if (!m) return [];
    try {
        const obj = JSON.parse(m[0]);
        return Array.isArray(obj.extended_sinks) ? obj.extended_sinks : [];
    } catch (e) {
        // 宽松兜底: 尝试截取到最后一个 ]
        try {
            const start = stdout.indexOf('"extended_sinks"');
            const arrStart = stdout.indexOf('[', start);
            const arrEnd = stdout.lastIndexOf(']');
            if (arrStart >= 0 && arrEnd > arrStart) {
                return JSON.parse(stdout.slice(arrStart, arrEnd + 1));
            }
        } catch (e2) { /* give up */ }
        return [];
    }
}

/**
 * R1.5 框架感知扩展 (REQ-18, 无条件执行)。
 * 读 wrapper_detection → 每主要语言 spawn framework-sink-extractor 子进程
 * → 产出 extended_sinks.json → 以 origin=L1 并入 queue（原地修改并返回并入数）。
 */
async function runR15FrameworkExtraction(workspacePath, queue, outputDir) {
    const profilePath = path.join(__dirname, 'resources', 'security_profiles.json');
    let wrapperDetection = {};
    try {
        wrapperDetection = JSON.parse(fs.readFileSync(profilePath, 'utf8')).wrapper_detection || {};
    } catch (e) {
        console.error(`${colors.yellow}[R1.5] 无法读取 wrapper_detection，跳过扩展。${colors.reset}`);
        return 0;
    }

    const { langs, counts } = detectLanguages(workspacePath);
    const applicable = langs.filter(l => wrapperDetection[l]);
    console.log(`${colors.blue}[R1.5] 框架感知扩展 | 语言: ${langs.join(', ') || '无'} | 适用 wrapper 检测: ${applicable.join(', ') || '无'}${colors.reset}`);

    if (applicable.length === 0) {
        console.log(`${colors.yellow}[R1.5] 无适用语言的 wrapper_detection 配置，扩展阶段无产出（但已执行）。${colors.reset}`);
        writeAuditJson(outputDir, 'extended_sinks.json', { extended_sinks: [] });
        return 0;
    }

    const allSinks = [];
    // 逐语言 spawn（数量少，串行即可，避免与 R3 抢并发额度）
    for (const lang of applicable) {
        console.log(`${colors.cyan}  [R1.5] 扫描 ${lang} wrapper (${counts[lang]} 文件)...${colors.reset}`);
        const prompt = buildR15Prompt(lang, wrapperDetection[lang], workspacePath);
        try {
            const stdout = await runAgentCmd(prompt);
            const sinks = extractExtendedSinks(stdout);
            sinks.forEach(s => { s._lang = lang; });
            allSinks.push(...sinks);
            console.log(`${colors.green}  [R1.5] ${lang}: 发现 ${sinks.length} 个 wrapper sink${colors.reset}`);
        } catch (err) {
            console.error(`${colors.red}  [R1.5] ${lang} 扫描异常: ${err.message.slice(0, 100)}${colors.reset}`);
            throw new Error(`R1.5 ${lang} framework-sink-extractor failed: ${err.message}`);
        }
    }

    writeAuditJson(outputDir, 'extended_sinks.json', { extended_sinks: allSinks });

    // 以 origin=L1 并入 queue，去重键 file+line+wrapper_name
    let maxN = 0;
    const existingKeys = new Set();
    queue.forEach(c => {
        const cid = c.id || '';
        if (cid.startsWith('CAND-')) {
            const n = parseInt(cid.split('-')[1], 10);
            if (!isNaN(n)) maxN = Math.max(maxN, n);
        }
        existingKeys.add(`${c.file_path}|${c.source_line || c.line_number}|${c.source_pattern}`);
    });

    let added = 0;
    for (const s of allSinks) {
        const key = `${s.file}|${s.line}|${s.wrapper_name}`;
        if (existingKeys.has(key)) continue;
        existingKeys.add(key);
        maxN += 1;
        const cwe = (s.inferred_sink_type || 'Unknown').split(' ')[0];
        queue.push({
            id: `CAND-${String(maxN).padStart(3, '0')}`,
            origin: 'L1',
            language: s._lang || '?',
            file_path: s.file || '',
            source_file: s.file || '',
            source_line: s.line || 0,
            line_number: s.line || 0,
            cwe_id: cwe,
            sink_type: cwe,
            category: s.inferred_sink_type || 'FrameworkWrapper',
            source_pattern: s.wrapper_name || '',
            matched_pattern: s.matched_pattern || '',
            type: 'TAINT_ANALYSIS',
            sink_content: (s.evidence || '').slice(0, 1000),
            priority: 1,
            status: 'PENDING',
            verdict: null,
            reachability_type: null,
            blocking_point: null
        });
        added += 1;
    }
    console.log(`${colors.green}[R1.5] 并入 ${added} 个 L1 候选 (extended_sinks.json 已落盘)${colors.reset}`);
    return added;
}

// ==================== --check-availability 子命令 ====================

function checkAvailability() {
    if (process.env.REACHABLE_AUDIT_MODE === 'native') {
        console.log(JSON.stringify({
            mode: 'A_NATIVE_ANTIGRAVITY',
            reason: 'REACHABLE_AUDIT_MODE=native',
            instruction: '使用 define_subagent/invoke_subagent 编排'
        }));
        process.exit(0);
    }
    if (process.env.OPENCODE === '1') {
        console.log(JSON.stringify({
            mode: 'A_NATIVE_OPENCODE',
            reason: 'OPENCODE=1',
            instruction: '使用 task 工具 + tools/batch_verify.py 编排'
        }));
        process.exit(0);
    }
    const cliName = findAgentCli();
    if (!cliName) {
        console.log(JSON.stringify({
            mode: 'AGENT_NATIVE_FALLBACK',
            reason: 'No AI CLI found in PATH (claude/agy/codex)',
            instruction: '主 Agent 接管'
        }));
        process.exit(0);
    }
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

    console.log(`${colors.blue}[*] R0: AST 工具自检...${colors.reset}`);
    try {
        runAstSelfCheck(scannerPath);
    } catch (error) {
        console.error(`${colors.red}[FATAL] R0 self-check 失败，流程终止。请先安装 tree-sitter 依赖并确认规则库可加载。${colors.reset}`);
        process.exit(1);
    }

    // 写入执行模式记录
    writeAuditJson(outputDir, 'execution_mode.json', {
        mode: `CLI_${cliName.toUpperCase()}`,
        cli: cliName,
        batch_size: BATCH_SIZE,
        timeout_ms: TIMEOUT_MS,
        detected_at: new Date().toISOString()
    });

    // --- 阶段 1: 扫描/加载候选队列 ---
    let queueObj;
    if (fs.existsSync(queuePath)) {
        console.log(`${colors.yellow}[*] 发现已存在的队列文件，载入断点续传...${colors.reset}`);
        queueObj = loadQueue(queuePath);
        normalizeQueueState(queueObj.candidates);
        saveQueue(queuePath, queueObj.raw, queueObj.candidates);
    } else {
        console.log(`${colors.blue}[*] 未发现历史队列，启动 AST 扫描...${colors.reset}`);
        try {
            execFileSync(pythonBin(), [scannerPath, workspacePath, outputDir], { stdio: 'inherit' });
            queueObj = loadQueue(queuePath);
            normalizeQueueState(queueObj.candidates);
            saveQueue(queuePath, queueObj.raw, queueObj.candidates);
        } catch (error) {
            console.error(`${colors.red}[Error] AST 扫描器执行失败. 流程终止。${colors.reset}`);
            process.exit(1);
        }
    }

    let queue = queueObj.candidates;

    // --- 阶段 1.5: 框架感知扩展 (REQ-18, 无条件执行, 与 R1 互补) ---
    // 幂等: extended_sinks.json 已存在说明本轮已跑过 R1.5(断点续传时不重复 spawn)。
    const extendedSinksPath = path.join(outputDir, 'extended_sinks.json');
    if (!fs.existsSync(extendedSinksPath)) {
        console.log(`\n${'='.repeat(60)}`);
        console.log(`${colors.yellow}[R1.5] 框架感知扩展 (始终执行, 捕获 L0 规则未覆盖的项目自有 wrapper)${colors.reset}`);
        console.log(`${'='.repeat(60)}`);
        try {
            const added = await runR15FrameworkExtraction(workspacePath, queue, outputDir);
            if (added > 0) {
                // 立即落盘, 保证断点续传能看到新并入的 L1 候选
                saveQueue(queuePath, queueObj.raw, queue);
            }
        } catch (err) {
            saveQueue(queuePath, queueObj.raw, queue);
            console.error(`${colors.red}[FATAL] R1.5 扩展阶段失败，流程终止: ${err.message.slice(0, 160)}${colors.reset}`);
            process.exit(1);
        }
    } else {
        console.log(`${colors.yellow}[R1.5] extended_sinks.json 已存在, 跳过重复扫描(断点续传)。${colors.reset}`);
    }

    const extendedProfilePath = path.join(outputDir, 'extended_profile.json');
    if (!fs.existsSync(extendedProfilePath)) {
        const l2Added = runL2Fallback(workspacePath, queue, outputDir);
        if (l2Added > 0) {
            saveQueue(queuePath, queueObj.raw, queue);
        }
    } else {
        console.log(`${colors.yellow}[L2] extended_profile.json 已存在, 跳过重复扫描(断点续传)。${colors.reset}`);
    }

    const pendingCandidates = queue.filter(c => c.status === "PENDING");
    console.log(`${colors.green}[+] 队列: 总计 ${queue.length} 项, PENDING ${pendingCandidates.length} 项, 已完成 ${queue.length - pendingCandidates.length} 项${colors.reset}`);

    if (pendingCandidates.length === 0) {
        console.log(`${colors.green}[+] 所有 R1/R1.5/L2 候选点均已验证，继续执行 R4。${colors.reset}`);
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
                const result = normalizeVerifierResult(extractVerdictResult(stdout));
                const verdict = result.verdict;

                // 写回结果
                queue[index].status = 'VERIFIED';
                queue[index].verdict = verdict;
                queue[index].reachability_type = result.reachability_type;
                queue[index].call_chain = result.call_chain;
                queue[index].call_chain_depth = result.call_chain_depth;
                queue[index].blocking_point = result.blocking_point;
                queue[index].path_count = result.path_count;
                queue[index].paths_analyzed = result.paths_analyzed;
                queue[index].evidence = result.evidence;
                if (result.cwe) queue[index].cwe = result.cwe;
                queue[index].verified_at = new Date().toISOString();

                // 传播相同位置+CWE 的判定结果
                let propagated = 0;
                queue.forEach(item => {
                    if (item.file_path === cand.file_path &&
                        item.line_number === cand.line_number &&
                        item.cwe_id === cand.cwe_id &&
                        item.status === "PENDING") {
                        item.status = 'VERIFIED';
                        item.verdict = verdict;
                        item.reachability_type = result.reachability_type;
                        item.call_chain = result.call_chain;
                        item.call_chain_depth = result.call_chain_depth;
                        item.blocking_point = result.blocking_point;
                        item.path_count = result.path_count;
                        item.paths_analyzed = result.paths_analyzed;
                        item.evidence = `[Propagated from ${cand.id}] ${result.evidence || ''}`;
                        item.verified_at = new Date().toISOString();
                        propagated++;
                    }
                });

                const statusIcon = verdict === 'REACHABLE' ? `${colors.red}🔴` :
                                   verdict === 'UNREACHABLE' ? `${colors.green}✅` :
                                   `${colors.yellow}⚠️`;
                const propMsg = propagated > 0 ? ` (+${propagated} propagated)` : '';
                console.log(`  ${statusIcon} [${cand.id}] → ${verdict}${propMsg}${colors.reset}`);

            } catch (err) {
                console.error(`${colors.red}  ❌ [${cand.id}] 异常: ${err.message.slice(0, 120)}${colors.reset}`);
                saveQueue(queuePath, queueObj.raw, queue);
                throw new Error(`R3 verifier failed for ${cand.id}: ${err.message}`);
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
    const invalidVerified = [];
    for (const c of finalQueue) {
        if (c.status !== 'VERIFIED') continue;
        if (!VALID_VERDICTS.includes(c.verdict)) {
            invalidVerified.push({ id: c.id, reason: 'invalid verdict' });
            continue;
        }
        if (c.verdict === 'REACHABLE' || c.verdict === 'UNREACHABLE') {
            if (!Array.isArray(c.call_chain) || c.call_chain_depth < MIN_CALL_CHAIN_DEPTH) {
                invalidVerified.push({ id: c.id, reason: 'insufficient call_chain_depth' });
            }
            if (!c.evidence) {
                invalidVerified.push({ id: c.id, reason: 'missing evidence' });
            }
        }
        if (c.verdict === 'REACHABLE' && !c.reachability_type) {
            invalidVerified.push({ id: c.id, reason: 'missing reachability_type' });
        }
        if (c.verdict === 'UNREACHABLE' && !c.blocking_point) {
            invalidVerified.push({ id: c.id, reason: 'missing blocking_point' });
        }
    }

    if (unverified.length > 0) {
        console.error(`${colors.red}[CRITICAL] 完整性校验失败！仍有 ${unverified.length} 个 PENDING 节点！${colors.reset}`);
        unverified.slice(0, 20).forEach(item => {
            console.error(`  - ${item.id} | ${item.file_path}:${item.line_number}`);
        });
        if (unverified.length > 20) console.error(`  ... 及另外 ${unverified.length - 20} 项`);
        process.exit(2);
    }
    if (invalidVerified.length > 0) {
        console.error(`${colors.red}[CRITICAL] 完整性校验失败！存在 ${invalidVerified.length} 个非法 VERIFIED 节点！${colors.reset}`);
        invalidVerified.slice(0, 20).forEach(item => {
            console.error(`  - ${item.id}: ${item.reason}`);
        });
        process.exit(3);
    }

    const stats = {
        total: finalQueue.length,
        reachable: finalQueue.filter(c => c.verdict === 'REACHABLE').length,
        unreachable: finalQueue.filter(c => c.verdict === 'UNREACHABLE').length,
        needs_review: finalQueue.filter(c => c.verdict === 'NEEDS_REVIEW').length,
    };
    console.log(`${colors.green}[✓] Assert 通过: 全部 ${stats.total} 项已验证 (REACHABLE=${stats.reachable}, UNREACHABLE=${stats.unreachable}, NEEDS_REVIEW=${stats.needs_review})${colors.reset}`);

    // --- 阶段 4: 业务逻辑深钻 (REQ-14 ~ REQ-16) ---
    console.log(`\n${'='.repeat(60)}`);
    console.log(`${colors.yellow}[R4] 启发式业务逻辑深钻...${colors.reset}`);

    const domainProfile = inferProjectDomain(workspacePath);
    const archViewPath = path.join(outputDir, 'architecture_view.json');
    writeAuditJson(outputDir, 'architecture_view.json', domainProfile);
    console.log(`${colors.cyan}[R4] 项目域: ${domainProfile.domainName}${colors.reset}`);

    const highRiskFiles = findHighRiskModules(workspacePath);
    const anchors = highRiskFiles.length ? highRiskFiles : [];
    if (anchors.length) {
        console.log(`${colors.blue}[R4] 发现 ${anchors.length} 个高危锚点:${colors.reset}`);
        anchors.forEach(f => console.log(`  - ${f}`));
    } else {
        console.log(`${colors.yellow}[R4] 未发现文件名锚点，仍按 6 类固化假说做全项目审查。${colors.reset}`);
    }

    const queueForR4 = loadQueue(queuePath);
    const queueWrapper = queueForR4.raw || { schema_version: "2.0", candidates: queueForR4.candidates };
    let autonomousFindings = Array.isArray(queueWrapper.r4_findings) ? queueWrapper.r4_findings : [];
    const doneHypotheses = new Set(autonomousFindings.map(f => f.hypothesis_id));

    if (R4_HYPOTHESES.every(h => doneHypotheses.has(h.id))) {
        console.log(`${colors.yellow}[R4] r4_findings 已存在且覆盖 H1-H6，跳过重复深钻。${colors.reset}`);
    } else {
        const r4BatchSize = 3;
        const pendingHypotheses = R4_HYPOTHESES.filter(h => !doneHypotheses.has(h.id));
        for (let j = 0; j < pendingHypotheses.length; j += r4BatchSize) {
            const batchHypotheses = pendingHypotheses.slice(j, j + r4BatchSize);
            await Promise.all(batchHypotheses.map(async (hypothesis) => {
                console.log(`${colors.blue}  [R4 Subagent] ${hypothesis.id}: ${hypothesis.title}...${colors.reset}`);
                const prompt = buildR4Prompt(domainProfile, hypothesis, anchors, workspacePath);

                try {
                    const stdout = await runAgentCmd(prompt);
                    const result = extractHypothesisVerdict(stdout, hypothesis);
                    const icon = result.verdict === 'REACHABLE' ? `${colors.red}🔴` :
                                 result.verdict === 'NEEDS_REVIEW' ? `${colors.yellow}⚠️` :
                                 `${colors.green}✅`;
                    console.log(`  ${icon} [R4] ${hypothesis.id} → ${result.hypothesis_verdict}${colors.reset}`);
                    autonomousFindings.push(result);
                } catch (err) {
                    console.error(`${colors.red}  ❌ [R4] ${hypothesis.id} 异常: ${err.message.slice(0, 120)}${colors.reset}`);
                    throw new Error(`R4 verifier failed for ${hypothesis.id}: ${err.message}`);
                }
            }));
            queueWrapper.r4_findings = autonomousFindings;
            fs.writeFileSync(queuePath, JSON.stringify(queueWrapper, null, 2), 'utf8');
        }
    }

    queueWrapper.r4_findings = autonomousFindings;
    fs.writeFileSync(queuePath, JSON.stringify(queueWrapper, null, 2), 'utf8');
    const autonomousPath = path.join(outputDir, 'autonomous_logical_findings.json');
    writeAuditJson(outputDir, 'autonomous_logical_findings.json', autonomousFindings);

    const completedR4 = new Set(autonomousFindings.map(f => f.hypothesis_id));
    const missingR4 = R4_HYPOTHESES.filter(h => !completedR4.has(h.id));
    const invalidR4 = autonomousFindings.filter(f =>
        f.status !== 'VERIFIED' ||
        !['confirmed', 'reviewed_clean', 'not_applicable', 'needs_review'].includes(f.hypothesis_verdict)
    );
    if (missingR4.length > 0 || invalidR4.length > 0) {
        console.error(`${colors.red}[CRITICAL] R4 完整性校验失败，缺少假说: ${missingR4.map(h => h.id).join(', ')}${colors.reset}`);
        if (invalidR4.length > 0) {
            console.error(`${colors.red}[CRITICAL] R4 存在非法结果: ${invalidR4.map(f => f.hypothesis_id || '?').join(', ')}${colors.reset}`);
        }
        process.exit(2);
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
    const ignoreDirs = ['node_modules', '.git', '.audit_results', '.agents', '.codex',
        '.venv', '__pycache__', 'reachable-critical-audit', 'scratch', 'target',
        'build', 'dist', 'vendor', 'third_party'];

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
    const reachable = queue.filter(c => c.verdict === 'REACHABLE');
    const unreachable = queue.filter(c => c.verdict === 'UNREACHABLE');
    const needsReview = queue.filter(c => c.verdict === 'NEEDS_REVIEW');
    const r4Reachable = autonomousFindings.filter(f => f.verdict === 'REACHABLE');
    const r4Unreachable = autonomousFindings.filter(f => f.verdict === 'UNREACHABLE');
    const r4NeedsReview = autonomousFindings.filter(f => f.verdict === 'NEEDS_REVIEW');

    const total = queue.length + autonomousFindings.length;
    const verifiedTotal = queue.filter(c => c.status === 'VERIFIED').length +
        autonomousFindings.filter(f => f.status === 'VERIFIED').length;

    const l0Count = queue.filter(c => (c.origin || 'L0') === 'L0').length;
    const l1Count = queue.filter(c => c.origin === 'L1').length;
    const l2Count = queue.filter(c => c.origin === 'L2').length;
    const r4Count = autonomousFindings.length;

    const pct = (n, d) => d > 0 ? ((n / d) * 100).toFixed(2) : "0.00";
    const l1RatioPct = pct(l1Count, total);
    const r4ReachableRatioPct = pct(r4Reachable.length, total);

    const reportContent = {
        report_meta: {
            generated_at: new Date().toISOString(),
            schema_version: "2.0",
            cli_used: detectAgentCli(),
            sampling_strategy: "full_queue_no_sampling"
        },
        quantified_metrics: {
            total_candidates: total,
            verified: verifiedTotal,
            reachable: reachable.length + r4Reachable.length,
            unreachable: unreachable.length + r4Unreachable.length,
            needs_review: needsReview.length + r4NeedsReview.length,
            rule_coverage_rate_pct: `${pct(verifiedTotal, total)}%`,
            reachability_rate_pct: `${pct(reachable.length + r4Reachable.length, verifiedTotal)}%`,
            noise_reduction_rate_pct: `${pct(unreachable.length + r4Unreachable.length, verifiedTotal)}%`,
            sink_discovery_rate_pct: `${pct(l0Count, total)}%`,
            l1_ratio_pct: `${l1RatioPct}%`,
            r4_reachable_ratio_pct: `${r4ReachableRatioPct}%`,
            false_negative_risk_pct: `${pct(l1Count + r4Reachable.length, total)}%`,
            origin_breakdown: { L0: l0Count, L1: l1Count, L2: l2Count, R4: r4Count }
        },
        reachable_vulnerabilities: reachable.map(c => ({
            id: c.id, origin: c.origin || 'L0', language: c.language,
            cwe_id: c.cwe_id || c.sink_type, category: c.category, type: c.type,
            source_file: c.source_file || c.file_path,
            source_line: c.source_line || c.line_number,
            reachability_type: c.reachability_type || 'DIRECT',
            sink_content: c.sink_content, evidence: c.evidence || c.verdict
        })),
        needs_review: needsReview.map(c => ({
            id: c.id, origin: c.origin || 'L0',
            source_file: c.source_file || c.file_path,
            source_line: c.source_line || c.line_number,
            sink_type: c.sink_type || c.cwe_id,
            blocking_point: c.blocking_point || null,
            reason: c.evidence || "研判拒绝或返回模糊"
        })).concat(r4NeedsReview.map(f => ({
            id: f.hypothesis_id,
            origin: 'R4',
            source_file: null,
            source_line: null,
            sink_type: Array.isArray(f.cwe) ? f.cwe.join(',') : null,
            blocking_point: null,
            reason: f.coverage_note || f.evidence || 'R4 hypothesis requires review'
        }))),
        unreachable_verified: {
            count: unreachable.length + r4Unreachable.length,
            candidates: unreachable.map(c => ({
                id: c.id,
                origin: c.origin || 'L0',
                source_file: c.source_file || c.file_path,
                source_line: c.source_line || c.line_number,
                sink_type: c.sink_type || c.cwe_id,
                blocking_point: c.blocking_point || null,
                evidence: c.evidence || ''
            })),
            r4_findings: r4Unreachable.map(f => ({
                hypothesis_id: f.hypothesis_id,
                hypothesis: f.hypothesis,
                hypothesis_verdict: f.hypothesis_verdict,
                evidence: f.evidence || f.coverage_note || ''
            }))
        },
        autonomous_findings: autonomousFindings.map(f => ({
            hypothesis_id: f.hypothesis_id,
            hypothesis: f.hypothesis,
            origin: "R4",
            status: f.status,
            verdict: f.verdict,
            hypothesis_verdict: f.hypothesis_verdict,
            cwe: f.cwe,
            findings: f.findings,
            coverage_note: f.coverage_note,
            evidence: f.evidence
        }))
    };

    assertAuditResultPath(path.dirname(reportJsonPath), reportJsonPath);
    fs.writeFileSync(reportJsonPath, JSON.stringify(reportContent, null, 2), 'utf8');

    // Markdown 报告
    const reportMdPath = path.join(path.dirname(reportJsonPath), 'reachable_vulnerabilities_report.md');
    let md = `# Reachable Critical Audit Report\n\n`;
    md += `Generated: ${reportContent.report_meta.generated_at} | CLI: ${reportContent.report_meta.cli_used}\n\n`;
    md += `Sampling: ${reportContent.report_meta.sampling_strategy} (NEEDS_REVIEW is included in all denominators)\n\n`;
    md += `## Metrics\n\n`;
    md += `| Metric | Value |\n|---|---|\n`;
    md += `| Total Candidates | ${total} |\n`;
    md += `| Verified | ${verifiedTotal} |\n`;
    md += `| **REACHABLE** | **${reachable.length + r4Reachable.length}** |\n`;
    md += `| UNREACHABLE | ${unreachable.length + r4Unreachable.length} |\n`;
    md += `| NEEDS_REVIEW | ${needsReview.length + r4NeedsReview.length} |\n`;
    md += `| Rule Coverage Rate | ${pct(verifiedTotal, total)}% |\n`;
    md += `| Reachability Rate | ${pct(reachable.length + r4Reachable.length, verifiedTotal)}% |\n`;
    md += `| Noise Reduction Rate | ${pct(unreachable.length + r4Unreachable.length, verifiedTotal)}% |\n`;
    md += `| Sink Discovery Rate | ${pct(l0Count, total)}% |\n`;
    md += `| False Negative Risk | ${pct(l1Count + r4Reachable.length, total)}% |\n`;
    md += `| Origin Breakdown | L0=${l0Count}, L1=${l1Count}, L2=${l2Count}, R4=${r4Count} |\n\n`;

    if (reachable.length > 0) {
        md += `## 🚨 Reachable Vulnerabilities\n\n`;
        reachable.forEach(c => {
            md += `### [${c.id}] ${c.cwe_id || c.sink_type}\n`;
            md += `- **File**: \`${c.source_file || c.file_path}:${c.source_line || c.line_number}\`\n`;
            md += `- **Sink**: \`${c.sink_content}\`\n`;
            md += `- **Evidence**: ${(c.evidence || c.verdict || '').slice(0, 500)}\n\n`;
        });
    }

    if (needsReview.length + r4NeedsReview.length > 0) {
        md += `## ⚠️ Needs Review\n\n`;
        needsReview.slice(0, 50).forEach(c => {
            md += `- **[${c.id}]** \`${c.source_file || c.file_path}:${c.source_line || c.line_number}\` (${c.sink_type || c.cwe_id})\n`;
        });
        r4NeedsReview.forEach(f => {
            md += `- **[${f.hypothesis_id}]** R4 ${f.hypothesis}: ${f.coverage_note || 'needs review'}\n`;
        });
        if (needsReview.length > 50) md += `\n... and ${needsReview.length - 50} more queue items\n`;
    }

    if (autonomousFindings.length > 0) {
        md += `\n## R4 Hypotheses\n\n`;
        autonomousFindings.forEach(f => {
            md += `- **${f.hypothesis_id}** ${f.hypothesis}: ${f.hypothesis_verdict}\n`;
        });
    }

    assertAuditResultPath(path.dirname(reportJsonPath), reportMdPath);
    fs.writeFileSync(reportMdPath, md, 'utf8');
    console.log(`${colors.green}[+] 报告已生成:\n  - JSON: ${reportJsonPath}\n  - Markdown: ${reportMdPath}${colors.reset}`);
}

// ==================== 入口 ====================

if (require.main === module) {
    const targetDir = process.argv[2] || '.';
    if (!process.argv.includes('--check-availability')) {
        executeWorkflow(targetDir).catch(err => {
            console.error(`${colors.red}[FATAL] ${err.message}${colors.reset}`);
            process.exit(1);
        });
    }
}

module.exports = {
    assertAuditResultPath,
    compileReport,
    loadL2FallbackRules,
    normalizeVerifierResult,
    skillVenvDir,
    venvPythonPath,
};
