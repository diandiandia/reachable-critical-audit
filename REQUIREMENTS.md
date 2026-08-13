# Reachable Critical Audit Skill -- 详细需求文档 (Requirements Specification)

本文档系统整理了 `reachable-critical-audit` 技能的全部核心功能与非功能性需求，并对所有需求进行了规范编号（REQ-01 至 REQ-20）。本版本相对 pre-v2 的关键修订：

- **REQ-01** 双平台兼容（Antigravity `define_subagent` / opencode `task` / Antigravity `agy` CLI 可选），不再绑定单一平台。
- **REQ-02** 由"严格白名单拒绝审计"改为"层级 fallback L0/L1/L2"，确保非预设语言也能审计。
- **REQ-06 / REQ-19** 新增"跨进程/跨 DSO 边界 sink 终结"规则，解决 framework 项目跨进程透传必漏报的问题。
- **REQ-09** `verify_queue.json` 强制落盘 + `NEEDS_REVIEW` 兜底状态，杜绝漏报黑洞。
- **REQ-10** 量化公式重做，区分 L0/L1/L2 候选来源，新增 Sink Discovery Rate 与 False Negative Risk。
- **REQ-11** 规则库来源改为"CodeQL 官方 qll 模型清洗 + 项目 wrapper 自识别"双源。
- **REQ-15** 业务假说清单固化为 6 类必选，不再自由推演。
- **REQ-17 ~ REQ-20** 新增平台兼容层、框架感知扩展、跨边界 sink 终结、CodeQL 清洗工具四项需求。

---

## 📌 需求分类表 (Overview)

| 需求编号 (ID) | 需求名称 (Name) | 优先级 (Priority) | 描述概要 (Summary) |
| :--- | :--- | :--- | :--- |
| **REQ-01** | 双平台原生 Subagent 拓扑编排 | P0 (Must Have) | 优先使用 `define_subagent`/`invoke_subagent`，opencode 平台降级为 `task`，`agy` CLI 为可选执行路径。 |
| **REQ-02** | 语言层级 fallback (L0/L1/L2) | P0 (Must Have) | 15 种预设语言直接用 L0；含项目 wrapper 走 L1；非预设语言走 L2 自动生成 extended_profile。 |
| **REQ-03** | AST 依赖 bootstrap + 物理工具 R0 self-check | P0 (Must Have) | 启动首步必须使用 skill 安装目录下的 `.venv` 补齐 tree-sitter grammar 依赖，再运行 `ast_scanner.py --self-check`；失败即 fail-fast，拒绝 LLM 脑补 AST。 |
| **REQ-04** | 物理过滤低危/规范与三方库噪音 | P0 (Must Have) | 必须在初筛阶段彻底忽略代码风格、命名规范、第三方 `.min.` 压缩库以及超长行代码。 |
| **REQ-05** | 数据流污点与业务逻辑双轨审计 | P0 (Must Have) | TAINT_ANALYSIS 追 Source→Sink 污染链；PROPERTY_CHECK 识别属主校验缺失/跨边界透传/导出无权等模式。 |
| **REQ-06** | 双向调用链数据流追踪 | P0 (Must Have) | 自 Sink 向 Source 自底向上回溯，**强制最小深度 3 层**；遇跨进程/跨 DSO/跨 IPC 边界时按 REQ-19 终结判定。 |
| **REQ-07** | 可达性条件过滤约束校验 | P1 (Should Have) | 调用链中遇到强类型转换、白名单、参数化绑定等无法穿透的 Sanitizer，判定 UNREACHABLE 并丢弃。 |
| **REQ-08** | 特权提升可利用性分析 | P0 (Must Have) | 针对特权切换 Sink，判定提权后动作参数是否仍混入低特权用户可控变量。 |
| **REQ-09** | verify_queue 状态机与断点硬校验 | P0 (Must Have) | 候选入队 → 分批并发 → 每批强制落盘 → 状态机 PENDING/VERIFIED/REACHABLE/UNREACHABLE/NEEDS_REVIEW → Assert 兜底。 |
| **REQ-10** | 审计漏斗量化度量 (L0/L1/L2 区分) | P1 (Should Have) | Coverage/Reachability/Noise Reduction 三率 + Sink Discovery Rate + False Negative Risk，分母按 L0+L1+L2 合计。 |
| **REQ-11** | 声明式静态配置 + CodeQL 双源 | P0 (Must Have) | `security_profiles.json` 必须源自 CodeQL 模型清洗（L0），并支持 `wrapper_detection` 配置驱动的 L1 扩展。 |
| **REQ-12** | 物理文件隔离前置守卫 | P0 (Must Have) | R0 阶段 `mkdir .audit_results/`，任何报告/中间产物路径必须以此为前缀；违反即流程失败。 |
| **REQ-13** | 有向自主逻辑漏洞探索 | P1 (Should Have) | 静态规则审计后扫描高危业务模块，模糊提示词并发自主威胁建模。 |
| **REQ-14** | 启发式项目架构与业务域自动感知 | P0 (Must Have) | 解析 README/Manifest/Proto/AIDL 自动判别业务领域。 |
| **REQ-15** | 固化 6 类业务威胁假说 | P0 (Must Have) | 必须推演并回应 6 类固定假说：CWE-789/125-787/416-UAF/跨进程/导出无权/越权-多租户。 |
| **REQ-16** | 业务逻辑专项 Subagent 并行深钻 | P0 (Must Have) | 通过平台任务编排拉起 `business-logic-verifier` 并发深钻锚点。 |
| **REQ-17** | 平台兼容层与执行模式自检 | P0 (Must Have) | 启动时探测平台能力（`define_subagent` / `task` / `agy`），选择执行模式写入 `.audit_results/execution_mode.json`。 |
| **REQ-18** | 框架感知扩展 (R1.5 阶段，**始终执行**) | P0 (Must Have) | 按 `wrapper_detection` 扫描项目自有 wrapper（如 `osi_*`、`STREAM_TO_*`、Android SQL），产出 `extended_sinks.json` 并入队。与 R1 互补，不可替代。 |
| **REQ-19** | 跨进程/跨 DSO 边界 sink 终结 | P0 (Must Have) | 调用链终止于 IPC/DSO/Provider 边界且对方参数为自由文本时，边界即 sink，标记 `REACHABLE_ACROSS_BOUNDARY`。 |
| **REQ-20** | CodeQL 模型清洗工具与可重现更新 | P0 (Must Have) | 提供 `tools/codeql_sink_extractor.py`，从 CodeQL qll 文件提取 sink/source 写入 JSON，支持版本可重现。 |
| **REQ-21** | Mode A' batch 调度器（新增） | P0 (Must Have) | 提供 `tools/batch_verify.py`，纯 Python 实现，不走 CLI 进程，支持 --stage next/collect/assert 循环，每批 3~4 个 task 并发验证。 |
| **REQ-22** | Rust unsafe 安全注释豁免（新增） | P1 (Should Have) | `ast_scanner.py` 检查 Rust unsafe 调用相邻行是否有 `// SAFETY:` 注释，有则自动降级为 NEEDS_REVIEW。 |
| **REQ-23** | Go 框架规则库（新增） | P1 (Should Have) | 向 `wrapper_detection.go` 和 `manual_additions.go` 注入 CodeQL/CVE/OWASP 衍生的 Go 框架特定 sink。 |
| **REQ-24** | 锚点召回验证（AnchorRecall，v2.1 新增） | P0 (Must Have) | 每语言绑定 8~15 个真实 CVE sink 作为 ground-truth 锚点；R0 self-check 必须全部命中，未命中该语言规则库判 FAIL。报告必须输出 AnchorRecall 指标。 |
| **REQ-25** | 安全修复差异考古（R0.5 阶段，v2.1 新增） | P0 (Must Have) | 对目标 repo 扫描安全相关 commit 并 diff parent..commit，提取"新增校验/被删危险路径"特征，检查目标版本是否含该漏洞特征，产出疑似未修复清单入 R3。 |
| **REQ-26** | LOGIC_PATTERN 危险谓词规则（v2.1 新增） | P1 (Should Have) | 新增第三类规则类型，匹配"授权/白名单校验被弱化"模式（hash-only 匹配、远端计数无上限循环、前缀校验代替全名校验、null 分支跳过黑名单）。 |
| **REQ-27** | 提取器完整性修复（v2.1 新增） | P0 (Must Have) | `semgrep_extractor.py` 必须支持 `mode: taint` + `metavariable-regex` 规则；合并改为增量式（保留 `manual_additions`）；新增 `--reconcile` 输出"官方有、skill 无"差异清单。 |
| **REQ-28** | 语言适配 sink 词表与上下文排除（v2.1 新增） | P1 (Should Have) | sink 匹配必须按语言限定接收者/上下文，排除框架内部同名方法（ASM `Frame.execute`、javac `JCTree.exec`、Go 裸 `.Exec`/`.Add` 等）导致的跨语言伪通用噪音。 |

---

## 🎯 详细需求规约说明

### REQ-01: 多平台原生 Subagent 拓扑编排与降级路径
*   **详细描述**：安全审计依托平台原生的智能体拓扑编排，且必须支持跨平台。优先使用 Antigravity 原生 `define_subagent` 创建 `vulnerability-verifier` / `business-logic-verifier` / `framework-sink-extractor` 子智能体并通过 `invoke_subagent` 隔离执行；在仅提供通用 task 工具的 Agent 平台（如 opencode）上，自动降级为 **Mode A'**（`task(subagent_type="general", description="<role>", prompt=<同一任务书>)`）；在无子智能体工具的环境（如 Claude Code 或通用命令行）上，自动降级为 **Mode A'' (Single-Agent In-Process Fallback)**，由主 Agent 在本地会话中按队列串行研判。Antigravity CLI（`agy` + `run_workflow.js`）作为可选执行路径 **Mode B** 保留，由 REQ-17 的模式自检决定是否启用。
*   **强制约束**：无论哪种执行模式，均不允许在网络中传输、存储或暴露任何第三方大模型 API Key。流程层面（R0 工具自检、verify_queue 落盘、R4 假说 6 类必选、量化公式）必须一致，不因模式而异。

### REQ-02: 语言层级 fallback (L0/L1/L2)
*   **详细描述**：系统按三层级处理语言覆盖，**删除 pre-v2 中"白名单外语言直接拒绝审计"的约束**：
    *   **L0**：项目主语言属于 15 种预设语言（Python、C/C++、Java、JS/TS、C#、Go、Rust、PHP、Ruby、Swift、Kotlin、Scala、Shell、Perl、PowerShell）时，直接加载 `security_profiles.json` 中固化的 Top-N 规则。每个候选节点必须标注 `origin: "L0"`。
    *   **L1**：项目主语言在 L0 之内，但使用了项目自有的 sink/source wrapper（如 Android Bluetooth 的 `osi_*alloc`、`STREAM_TO_UINT*` 宏，PHP 框架的 `DB\SQL::exec` 等）。由 REQ-18 的 R1.5 阶段识别产出 `extended_sinks.json`，并入候选队列，标注 `origin: "L1"`。
    *   **L2**：项目包含非预设语言（如 Erlang、Haskell、Cobol）。Agent **必须**基于 `security_profiles.json.l2_fallback_rules` 动态生成该语言的 Top 10 高危漏洞映射（覆盖 RCE、SQLi、SSRF、越权、反序列化等类别），落盘为 `.audit_results/extended_profile.json`，由主 Agent 复核后才并入候选队列，标注 `origin: "L2"`。Mode B 中由 `run_workflow.js` 对非预设源码扩展执行保守通用高危模式扫描，并写入 `reviewed_by: "main-agent"`。
*   **强制约束**：L2 fallback 产物必须经主 Agent 显式复核签名（在 `extended_profile.json` 中写 `reviewed_by: "main-agent"` 字段）后才能进入 R3 验证队列。

### REQ-03: AST 依赖 bootstrap + 物理工具 R0 self-check 与全语言 AST 对齐
*   **详细描述**：Skill 启动后第一步（R0 阶段）必须先完成本地依赖 bootstrap：优先使用 **skill 安装目录** 下的 `.venv/bin/python3`；若该 `.venv` 不存在则创建；若 self-check 报告 `tree-sitter` 或有规则语言 grammar 缺失，则在 skill-local `.venv` 中安装 `tree-sitter` 及 Java/C++/Python/JavaScript/Go/Rust/C#/PHP/Ruby/Swift/Kotlin/Scala grammar 包后重试一次。不得在被审计项目根目录创建 `.venv`，不得把依赖安装到系统 Python；遇到 PEP 668 / externally-managed-environment 时必须改用 skill-local `.venv`。Mode B 的 `run_workflow.js` 必须执行同等 bootstrap；`REACHABLE_AUDIT_VENV` 可显式覆盖 skill-local venv 目录，`PYTHON_BIN` 可显式覆盖 Python 解释器，但覆盖后失败应 fail-fast，不得擅自污染系统环境。
*   **self-check 要求**：bootstrap 完成后必须运行 `<skill_dir>/.venv/bin/python3 tools/ast_scanner.py --self-check`（或 `PYTHON_BIN` 指定的 Python），确认 `tree-sitter`、对应语言 grammar 以及 `security_profiles.json` 规则库装载状态。脚本输出结构化 JSON（包含 `status`, `has_tree_sitter`, `configured_languages` (全部 15 种), `wrapper_detection_languages` (全部 15 种), `required_grammar_languages`, `grammar_missing`, `grammar_coverage_ok`, `total_rules`, `coverage_rule_count`, `manual_review_regex_rules`, `ast_patterns_coverage_pct`, `ast_coverage_threshold_pct`, `ast_coverage_ok`, `ast_gap_by_language`），self-check 校验规则库加载失败、tree-sitter 不可用、任一有规则语言 grammar 缺失、机器覆盖率低于阈值（返回 exit 1）即 fail-fast 终止审计流程，**绝不允许**降级为"由大模型脑补 AST"的模糊模式。CodeQL L0 规则须达到 **≥ 95%**（`AST_COVERAGE_THRESHOLD`）的机器可校验支撑：Tree-Sitter AST S-expression 或 Go/Swift 结构化模型（`go_models` / `swift_models`）。`manual_additions` 中带 `source_reason` 且无 `codeql_model` 的人工补丁不计入覆盖率分母，单独计入 `manual_review_regex_rules`；这类 regex-only 命中必须在 R1/R3 降级复核，不能直接计入 REACHABLE 候选。
*   **锚点召回自检（REQ-24）**：self-check 必须加载 `resources/anchor_registry.json`，对每个有锚点的语言运行 `_smoke_check_language` 级别的锚点命中测试。**锚点命中率 < 100% 时该语言规则库判 FAIL**（`anchor_recall_pct` 字段报告），阻止审计启动。锚点是真实 CVE sink（如 PHP `include $_GET['x']` → CVE-2018-12613；Java `checkAutoType` hash-only 白名单 → fastjson2），防止"覆盖率 100% 但核心攻击面零命中"的指标失真。

### REQ-04: 物理过滤低危/规范与三方库噪音
*   **详细描述**：初筛与审计阶段必须物理忽略：未采用驼峰命名、缺失文件注释、非安全场景弱随机数、代码风格违规等规范类问题。同时必须自动识别并过滤第三方压缩/混淆库（文件名含 `.min.`、路径组件为 `vendor/`、`node_modules/`、`third_party/`、`libs`、`.agents`、`.codex`、`.venv`、`reachable-critical-audit` 等典型路径），匹配行长度超过 1000 字符强制截断并标注 `... [TRUNCATED]` 以防空提示词触发模型安全策略或导致子会话挂起。路径过滤必须按相对路径组件判断，禁止用绝对路径子串匹配，以免工作区名包含 `build` 等词时整库误跳过。

### REQ-05: 数据流污点与业务逻辑双轨审计
*   **详细描述**：双轨制审计分流，PROPERTY_CHECK 从 pre-v2 的粗关键字识别升级为模式识别：
    *   **TAINT_ANALYSIS (污点分析)**：追踪外部 Source 到 Sink 的变量污染链，适用于 SQLi、RCE、SSRF、内存越界、UAF、未控内存分配等。
    *   **PROPERTY_CHECK (属性与模式校验)**：从粗关键字改为结构化模式识别，覆盖 4 类模式：
        1.  **missing_owner_check**：写/删/查资源方法体内未出现 session 用户 ID 与资源 owner 的相等性比对。
        2.  **cross_boundary_trust_violation**：外部输入拼字符串后作为 `selection`/`command` 等 自由文本参数传入跨进程/跨 DSO API，且对应 API 缺省参数化字段为 null。
        3.  **exported_no_permission**：AndroidManifest 等 manifest 文件中 `exported=true` 且无 `android:permission`。
        4.  **privilege_boundary_skip**：提权前数据流入提权后执行的指令/文件路径。
*   **强制约束**：PROPERTY_CHECK 模式定义必须固化在 `security_profiles.json` 的 `property_check_patterns` 字段，不允许散落在代码逻辑里；`ast_scanner.py` 扫描阶段需联动抽取生成 Candidate。

### REQ-06: 双向调用链数据流追踪 + 跨边界终结（语言无关）
*   **详细描述**：子智能体以匹配到的 sink 函数为回溯终点，利用本地代码检索（`grep` / `Grep` 工具）反向查找所有调用者，逐层向上构建 `Sink ← Caller_L1 ← Caller_L2 ← ... ← Source` 拓扑。**强制输出调用链最小深度 3 层**（Sink ← L1 ← L2），不足 3 层必须继续向上搜索。遇接口/抽象类必须穿透到所有具体实现类继续回溯。
*   **跨边界终结**：当调用链到达以下边界时，按 REQ-19 终结判定，不再要求在当前仓库内闭环（语言无关）：
    *   跨进程 IPC：ContentResolver.query / Binder.transact / Intent extras / sendBroadcast（Java）；send/write 到 IPC socket（C/Python）
    *   跨 DSO/FFI：调用外部动态库导出函数且无源码（C/C++）；extern "C" FFI（Rust）
    *   跨 Provider authority：content:// 切换到第三方实现的 ContentProvider
    *   子进程执行：subprocess.Popen / os.system（Python）；child_process.exec（JS）；system / popen（C）
    *   动态代码执行：eval / exec（Python/JS）；MethodHandle.invoke（Java）

### REQ-07: 可达性条件过滤约束校验
*   **详细描述**：调用链中校验变量传递的控制流约束。若变量在传递途中经过无法绕过的：强类型转换（int/UUID）、严格白名单过滤器、参数化绑定（prepared statement + bindValue）、`if (offset+N>p_pkt_end)` 显式边界检查，则判定 `UNREACHABLE` 并立即从报告丢弃。判定 UNREACHABLE 必须记录阻断点 `file:line` 入 `verify_queue.json` 的 `blocking_point` 字段。

### REQ-08: 特权提升可利用性分析
*   **详细描述**：针对 C/C++/Go/Python/Node.js 的特权切换 Sink（`setuid`/`seteuid`/`setgid`/`setegid`/`setresuid`/`setresgid`/`capng_*`/`prctl(PR_SET_UID)`等），必须验证：提权后的指令参数或文件路径是否仍混入提权前低特权用户可控的变量。若提权后动作完全由硬编码参数控制，判定 `UNREACHABLE`；若提权后动作参数可被低特权用户影响，判定 `REACHABLE`。Android Bluetooth 等系统服务同样适用：蓝牙守护进程运行于 `android.uid.bluetooth` (1002)，任何能让该 UID 执行特权动作的远端输入都按提权对待。

### REQ-09: verify_queue 状态机与断点硬校验 + batch 调度器
*   **详细描述**：候选清单必须以状态机形式落盘到 `.audit_results/verify_queue.json`，**绝不允许只在内存中维护**：
    1.  **入队 Schema**：每个候选节点包含规范字段：`{id, origin("L0"/"L1"/"L2"/"R4"), source_file, source_line, sink_type, status("PENDING"/"VERIFIED"), verdict, reachability_type, blocking_point}`。
     2.  **分批并发/串行研判**：按 REQ-01 选定的执行模式分批研判。Mode A' 使用 `tools/batch_verify.py` 调度：`--stage next` 输出下一批任务书 → task 并发验证 → `--stage collect` 写回队列 → 循环直至 `--stage assert` 通过。单批完成后**立即落盘**。
     2a. **调用链深度门禁**：`--stage collect` 自动验证每个 verdict 的必需字段（`verdict`、`reachability_type`、`call_chain`、`call_chain_depth`、`evidence`）和 `call_chain_depth`。缺字段或类型错误的结果保持 `PENDING` 以便重试；若 `REACHABLE/UNREACHABLE` 的深度 `< 3`，自动升级为 `NEEDS_REVIEW` 并追加原因。`--stage assert` 输出平均/最小/最大调用链深度指标，并对非法 VERIFIED 节点返回非 0。
    3.  **状态机**：`PENDING → VERIFIED → {REACHABLE | UNREACHABLE | NEEDS_REVIEW}`；子智能体返回模糊或拒绝回答时强制 `NEEDS_REVIEW`，不允许默认判定。
    4.  **断点续传**：二次启动读取 `verify_queue.json`，跳过已 `VERIFIED` 的节点，只处理 `PENDING`。
    5.  **Assert 兜底**：报告生成前 `batch_verify.py --stage assert` 必须通过（exit 0），存在 `PENDING` 节点则 `exit(2)` 强制中断。`NEEDS_REVIEW` 节点必须在报告中显式列出。

### REQ-10: 审计漏斗量化度量 (L0/L1/L2 区分)
*   **详细描述**：量化公式分母必须为 `(R1 + R1.5 + L2 + R4)` 候选总数，分子按来源标记 `origin` 字段：
    *   **Rule Coverage Rate** = `(R1 + R1.5 + L2 + R4) 已验证候选` / `(R1 + R1.5 + L2 + R4) 总候选`
    *   **Reachability Rate** = `REACHABLE` / 已验证候选
    *   **Noise Reduction Rate** = `UNREACHABLE` / 已验证候选
    *   **Sink Discovery Rate** *(新增)* = `R1(L0) 命中` / `(R1 + R1.5 + L2 + R4)` 总候选 — 反映 L0 规则库的召回能力。
    *   **False Negative Risk** *(新增)* = `(L1 占比 + R4 REACHABLE 占比)` — 反映规则盲区。
    *   **Anchor Recall** *(v2.1 新增)* = 锚点命中数 / `resources/anchor_registry.json` 中该语言锚点总数 — 规则库对真实 CVE 攻击面的召回，**不达 100% 禁止声称 Coverage/Reachability 有效**，与 Reachability Rate 并列输出。
    *   **Origin Breakdown** *(新增)* = 输出 `L0`, `L1`, `L2`, `R4` 的各分类候选统计数。
*   **强制约束**：明确分母为"已入队候选数"（即进入 verify_queue 的总数），`NEEDS_REVIEW` 计入分母，采样策略与全量指标必须在 JSON 和 Markdown 报告中双输出。

### REQ-11: 声明式静态配置 + CodeQL 双源
*   **详细描述**：规则库 `security_profiles.json` 必须满足双源约束：
    *   **L0 源 = CodeQL 官方模型清洗**：清洗过程由 REQ-20 的 `codeql_sink_extractor.py` 完成，可重现；来源包括旧式 `.qll`、现代 `.model.yml` Models-as-Data、Swift `SinkModelCsv`。
    *   **L1 源 = 项目 wrapper_detection**：`security_profiles.json` 内必须包含 `wrapper_detection` 段，描述如何让 R1.5 阶段识别项目自有 sink wrapper。
    *   **PROPERTY_CHECK 模式段**：包含 4 类逻辑/属性校验模式的结构化定义。
    *   **手工补丁段**：CodeQL 不覆盖但必须纳入的 sink，单独列在 `manual_additions` 段。
    *   **L2 fallback 规则段**：非预设语言兜底扫描的 Top 10 高危模式必须位于 `l2_fallback_rules` 段。
*   **强制约束**：禁止在程序逻辑中散落或硬编码任何 sink/source 规则；所有规则必须在 JSON 中可审计。

### REQ-12: 物理文件隔离前置守卫
*   **详细描述**：R0 阶段必须 `mkdir -p .audit_results/`，后续所有产物（`verify_queue.json` / `extended_sinks.json` / `extended_profile.json` / `execution_mode.json` / `architecture_view.json` / `reachable_vulnerabilities_report.{md,json}`）路径必须以 `.audit_results/` 为前缀。写文件前必须自检路径，**任何对项目源码根目录的直接报告写入都视为流程违规**，立即终止。

### REQ-13: 有向自主逻辑漏洞探索
*   **详细描述**：静态规则审计（R1 + R1.5 + R3）完成后，工作流扫描高危业务领域模块（如 `auth`/`payment`/`order`/`admin`/`map`/`pbap`/`avrc` 等关联文件），结合模糊提示词进行发散威胁建模。模块覆盖上限 6 个文件。

### REQ-14: 启发式项目架构与业务域自动感知
*   **详细描述**：通过解析项目顶层结构文件（`README.md` / `AndroidManifest.xml` / `pom.xml` / `Cargo.toml` / `.proto` 等）自动判别业务领域，生成《业务域架构视图》写入 `.audit_results/architecture_view.json`，供 R4 阶段假说推演使用。

### REQ-15: 固化 6 类业务威胁假说
*   **详细描述**：R4 阶段必须推演并回应以下 6 类固定假说，**禁止自由发散**，每类必须给出三选一明确结论：`confirmed (已坐实)` / `reviewed_clean (已审查无问题)` / `not_applicable (不适用)`。
    1.  **CWE-789 远端控制 allocation size**
    2.  **CWE-125/787 远端控制解引用长度/索引**
    3.  **CWE-416 异步对象生命周期竞态（UAF）**
    4.  **跨进程信任边界破坏（CWE-20+89/78）**
    5.  **Exported component 鉴权缺失（CWE-862/926）**
    6.  **多租户/owner 比对缺失（CWE-639/285）**

### REQ-16: 业务逻辑专项 Subagent 并行深钻
*   **详细描述**：针对 R4 推演锚点，Agent 通过编排机制拉起 `business-logic-verifier` 子智能体并发深钻。结果落盘至 `verify_queue.json` 的 `r4_findings` 段（标注 `origin: "R4"`）并写入最终报告。

### REQ-17: 平台兼容层与执行模式自检
*   **详细描述**：Skill 启动时按以下顺序探测执行模式，并将探测结果落盘写入 `.audit_results/execution_mode.json`：
    1.  工具列表含 `define_subagent` 或环境变量 `REACHABLE_AUDIT_MODE=native` → **Mode A (Antigravity Native)**。
    2.  工具列表含 `task` 或环境变量 `OPENCODE=1` → **Mode A' (OpenCode Native)**。
    3.  尝试 `node run_workflow.js --check-availability`，返回 Mode B → **Mode B (Antigravity CLI)**。
    4.  既无 `define_subagent` 也无 `task` 工具且 CLI 不可用 → **Mode A'' (Single-Agent In-Process Fallback)**，主 Agent 在本地主会话中串行研判。
*   **强制约束**：`run_workflow.js` 在 CLI 探测时遇到 ENOENT 必须返回结构化 `{mode: "AGENT_NATIVE_FALLBACK", reason}` 对象且不触发崩溃，引导主 Agent 切换模式接管。

### REQ-18: 框架感知扩展 (R1.5 阶段全语言对齐，**始终执行**)
*   **详细描述**：R1 静态扫描完成后**必须无条件执行** R1.5。R1.5 与 R1 互补：R1 聚焦预设 L0 规则（CodeQL 清洗的函数签名），R1.5 通过 `wrapper_detection` 配置扫描项目自定义 wrapper（覆盖全部 15 种预设语言的 allocator / parser macros / lifecycle / sql & db wrappers / process & cmd wrappers / ipc sinks / async ownership 等）。两者覆盖不同的攻击面，不可互相替代。即使 R1 在目标语言上命中率很高，R1.5 仍会捕获 L0 规则未覆盖的项目特有 wrapper（如 Android Bluetooth 的 `osi_*alloc`、`STREAM_TO_UINT*`、`ContentResolver.query` 自定义封装等）。
*   **产出**：`.audit_results/extended_sinks.json`，并入 `verify_queue.json`，标记 `origin: "L1"`。

### REQ-19: 跨进程/跨 DSO 边界 sink 终结
*   **详细描述**：调用链回溯到达以下边界时，按规则判定为 sink 达成，标记 `verdict=REACHABLE_ACROSS_BOUNDARY`，不要求在当前仓库内闭环追溯外部实现：
    *   **跨进程 IPC**：`ContentResolver.query(uri, ..., selection, selectionArgs, ...)` 当 `selection` 含字符串拼接且 `selectionArgs` 为 null；`Binder.transact`；`Intent` extras 携带自由文本；`broadcast` 发送。
    *   **跨 DSO**：调用外部动态库导出函数且无源码，参数为远端可控自由文本。
    *   **跨 Provider authority**：URI authority 切换到第三方 ContentProvider 实现。
*   **判定规则**：边界 API 的自由文本参数（如 `selection`）若含外部输入拼接 OR 参数化字段（如 `selectionArgs`）缺省为 null，即判定 sink 达成；若边界 API 强制参数化（如 `ContentValues` + `update(uri, values, where, args)` 且 `where` 经 `?` 占位 + `args` 绑定），则判定阻断。
*   **强制约束**：pre-v2 要求"本仓库内闭环"导致 framework 项目（如 Android Bluetooth MAP）必漏报，本规则正式放松该约束。

### REQ-20: CodeQL 模型清洗工具与可重现更新
*   **详细描述**：提供 `tools/codeql_sink_extractor.py`，从 CodeQL 模型提取 sink/source 写入 `security_profiles.json`。清洗流程必须可重现：
    1.  `git clone https://github.com/github/codeql --depth 1 --branch <tag>` 固定版本
    2.  扫描每个语言的 security QLL 与 `.model.yml` Models-as-Data；Swift 必须额外解析 `SinkModelCsv` 以及 SQL QLL 中的 `hasQualifiedName(...)` 模型。
    3.  按 CodeQL sink kind / CWE 归类（如 `command-injection`→CWE-78、`path-injection`→CWE-22、`sql-injection`→CWE-89）。
    4.  Go/Swift 规则必须保留结构化上下文：Go 写入 `sinks.go_models[]`（`package/type/method/access_path/sink_kind`），Swift 写入 `sinks.swift_models[]`（`type/signature/method/access_path/sink_kind`）。
    5.  输出到 `security_profiles.json` 对应语言段，并写入 `codeql_revision` 字段记录所用 CodeQL 版本。
*   **强制约束**：每次更新 `security_profiles.json` 必须更新 `codeql_revision` 字段；手工补丁（`manual_additions` 段）必须标注来源理由与不在 CodeQL 中的原因。Go/Swift 禁止把 `Exec` / `Query` / `init` / `write` 等裸方法名作为高置信初筛依据；`ast_scanner.py` 必须优先使用结构化模型上下文，regex-only 命中只能降级为 `NEEDS_REVIEW` 或被上下文过滤。

### REQ-24: 锚点召回验证（AnchorRecall）
*   **详细描述**：规则库有效性必须用真实 CVE 攻击面度量，而不是字符串存在性：
    *   `resources/anchor_registry.json` 固化每语言的 ground-truth 锚点：`{cwe_id, category, sample_code, cve}`，覆盖该语言最常见的高危 sink（如 PHP `include $_GET['x']` / Java `checkAutoType` hash 白名单 / Go `exec.Command(shell, userInput)`）。
    *   `ast_scanner.py --self-check` 对每个锚点跑 `_smoke_check_language` 级别的命中测试；**Anchor Recall = 命中锚点数 / 锚点总数，< 100% 该语言判 FAIL**（exit 1），阻止审计启动。
    *   报告 `quantified_metrics` 必须输出 `anchor_recall_pct`（按语言 + 全局）。
*   **背景**：v2.1 基于两次实测（phpMyAdmin 4.8.5 漏 CVE-2018-12613 LFI、fastjson2 2.0.62 漏 checkAutoType hash 绕过）引入。fastjson2 报告曾声称 Coverage 100% / Sink Discovery 99.66%，但 CWE-502 核心逻辑零命中——**无锚点召回的覆盖率是自欺欺人**。

### REQ-25: 安全修复差异考古（R0.5 阶段）
*   **详细描述**：在 R1 静态扫描之前（或并行）执行"修复 commit 考古"，利用 git 历史中的安全修复作为漏洞特征来源：
    1.  输入目标 repo 与指定 tag/commit。
    2.  `git log --grep="security|autotype|rce|bypass|cve|deny|fix|safe|exploit"` 收集候选修复 commit。
    3.  对每个候选 commit 执行 `git diff <parent>..<commit>`，提取"新增的校验"与"被删除/弱化的危险路径"作为漏洞特征。
    4.  检查**目标版本**是否含该特征（如 hash-only 白名单 `binarySearch(hash)>=0` + `loadClass`）。
    5.  产出 `.audit_results/r05_diff_archaeology.json`，标注 `[疑似未修复 / 已修复]`，疑似项直接入 R3 验证队列。
*   **背景**：fastjson2 AutoType hash 伪造绕过（2.0.63 修复 commit `ec47e24c4`）与 phpMyAdmin LFI 均未被静态规则捕获，唯一可靠定位手段是版本差异考古。对"迭代修 N 轮"的库（AutoType/RCE 类），该阶段产出价值高于其余阶段之和。

### REQ-26: LOGIC_PATTERN 危险谓词规则（第三类规则类型）
*   **详细描述**：规则类型从 `TAINT_ANALYSIS` / `PROPERTY_CHECK` 扩展出 **`LOGIC_PATTERN`**，匹配"授权/白名单/边界校验被弱化"的语义缺陷，不依赖污点链：
    *   hash-only 白名单：`Arrays.binarySearch(hashCodes, hash) >= 0` 后直接 `loadClass(typeName)`（未校验完整类名）→ fastjson2 类。
    *   远端计数无上限循环：远端 uint32 驱动 `for(i=0;i<count;i++)` 写入固定大小数组且无 `count<=MAX` 比对 → tengine `parse_rc_info` 类。
    *   前缀校验代替全名校验 / `expectClass==null` 分支跳过黑名单。
*   **强制约束**：LOGIC_PATTERN 定义固化在 `security_profiles.json` 的 `rules.<lang>[]`（`type: "LOGIC_PATTERN"`），`ast_scanner.py` 以 AST 模式匹配，产出候选并入 R3。

### REQ-27: 提取器完整性修复与对账
*   **详细描述**：修复 `semgrep_extractor.py` / `codeql_sink_extractor.py` 三个缺陷：
    1.  **taint-mode 支持**：必须能提取 `mode: taint` + `pattern-sinks` + `metavariable-regex` 规则（如 semgrep `php/lang/security/file-inclusion.yaml` 的 `\b(include|include_once|require|require_once)\b`），当前仅提取 `pattern: $FUNC(...)` 标识符。
    2.  **增量合并**：提取结果与 `manual_additions` / 既有规则取**并集**，禁止覆盖式替换；`manual_additions` 段永远保留。
    3.  **对账输出**：新增 `--reconcile` 模式，输出 `[官方有, skill 无]` / `[skill 有, 官方无]` 差异清单，作为规则库治理输入。
*   **背景**：实测对账证明——即使重跑 extractor，官方 `file-inclusion.yaml`（CWE-98）也进不了 skill，因为提取逻辑跳过了 taint-mode 规则；且合并是覆盖式，会抹掉手工清洗结果。

### REQ-28: 语言适配 sink 词表与上下文排除
*   **详细描述**：sink 匹配必须带语言感知的上下文约束，消除跨语言伪通用噪音：
    *   Java `exec`/`execute` 必须限定接收者（`Runtime.exec` / `ProcessBuilder`），排除 ASM `Frame.execute`、javac `JCTree.exec`。
    *   Go `Exec`/`Add`/`Query` 裸方法名不作为高置信 sink（方法调用上下文）。
    *   PHP 规则不得命中非 PHP 源（`.js`/`.py` 文件）；CWE-22 类 sink 限定 `include/require/file_get_contents/fopen/readfile/unlink` 等 PHP 文件操作，排除 `window.open`/`indexedDB.open`。
*   **强制约束**：语言适配规则（接收者排除表 / 语言文件类型白名单）固化在 `security_profiles.json` 的 `language_adaptation` 段。

---

## 📋 修订前后对照表 (Change Log)

| 需求 | pre-v2 | v2 | 修订理由 |
| :--- | :--- | :--- | :--- |
| REQ-01 | 单一 `define_subagent`/`agy` | 双平台兼容 + `agy` 可选 | opencode 平台无 `define_subagent`，需降级；保留 Antigravity 兼容 |
| REQ-02 | 严格白名单，拒绝审计 | L0/L1/L2 层级 fallback | pre-v2 与 SKILL.md Fallback 段自相矛盾 |
| REQ-03 | 提及但未强制 | R0 依赖 bootstrap + 强制 self-check，失败 fail-fast | ast_scanner.py 从未被调用，REQ-03 形同虚设；系统 Python 受 PEP 668 管理时必须自动改用 `.venv` |
| REQ-05 | PROPERTY_CHECK 粗关键字 | 4 类模式识别 | `admin/manage/delete` 关键字毫无意义 |
| REQ-06 | 要求本仓库闭环 | 跨边界按 REQ-19 终结 | MAP SQL 注入 sink 在外部 Provider，pre-v2 必漏报 |
| REQ-09 | 提及但未落盘 | verify_queue 状态机强制落盘 | pre-v2 两次审计均未生成 verify_queue.json |
| REQ-10 | Coverage = 验证/匹配 | 区分 L0/L1/L2 分母 | pre-v2 Bluetooth 报告 Coverage 造假(11% 写成 100%) |
| REQ-11 | 手写 JSON | CodeQL 清洗 + 手工补丁双源 | pre-v2 缺失 CWE-789/787/125, 无 osi_*/STREAM_TO_* |
| REQ-12 | 事后要求自觉 | 前置守卫 + 路径前缀强制 | pre-v2 Bluetooth 根目录残留报告文件 |
| REQ-15 | 自由 3~5 个假说 | 固化 6 类必选 | pre-v2 漏推演 CWE-789/UAF 跨进程等假说 |
| REQ-17~20 | 不存在 | 新增 | 补平台兼容层 / R1.5 / 跨边界 / CodeQL 工具 |
| REQ-18 | 条件触发(R1命中0且文件>500) | **始终执行** | 框架感知扩展与R1互补，不可互相替代；pre-v2漏报根因补救需全覆盖 |
| REQ-06 | 无深度约束 | **强制最小深度3层** | 防止子智能体按上下文归类而非追踪数据流导致遗漏 |
| REQ-09 | 仅状态机 | **增加调用链深度门禁** | batch_verify.py自动验证depth<3→NEEDS_REVIEW |
| REQ-19 | 仅Java ContentResolver/Binder | **语言无关化** | 新增Python/JS/C/C++/Rust跨边界示例 |
| REQ-24~28 | 不存在 | **v2.1 新增** | 锚点召回验证 / R0.5 修复差异考古 / LOGIC_PATTERN 危险谓词 / 提取器完整性修复 / 语言适配 sink 词表 —— 由 phpMyAdmin LFI 漏检 + fastjson2 AutoType hash 绕过两次实测驱动 |
