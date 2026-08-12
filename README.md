# Reachable Critical Audit System v2 (可达性严重漏洞审计系统)

这是一个面向 **opencode** 与 **Antigravity** 双平台的 Skill。它旨在解决传统静态代码分析工具（SAST）中**噪音大、误报高、需要繁琐配置 API Key** 的痛点。

v2 相对 pre-v2 修订:五阶段漏斗(R0+R1+R1.5+R3+R4) + 双平台兼容层 + CodeQL 双源规则库 + 跨进程 sink 终结 + verify_queue 状态机。修订动机详见 [REQUIREMENTS.md](REQUIREMENTS.md) 末尾的修订对照表。

---

## 📂 项目结构 (Project Layout)

```
reachable-critical-audit/
├── README.md               # 项目自述文件
├── REQUIREMENTS.md         # 详细需求规格书 (REQ-01 至 REQ-20)
├── SYSTEM_DESIGN.md        # 系统架构与实现映射设计文档
├── SKILL.md                # 技能主入口(Agent 行为规范指南)
├── run_workflow.js         # Mode B 可选执行路径(Antigravity CLI agy 编排)
├── resources/
│   └── security_profiles.json  # 规则库:CodeQL L0 + manual_additions + wrapper_detection + property_check_patterns
└── tools/
    ├── ast_scanner.py          # R0 强制工具:tree-sitter AST 校验
    └── codeql_sink_extractor.py  # REQ-20:CodeQL qll → security_profiles.json 清洗脚本
```

---

## 🌟 核心特色 (Core Features)

1. **双平台原生兼容 (Zero-Key Autonomy)**：
   - **Mode A (Antigravity)**:`define_subagent`/`invoke_subagent` 编排
   - **Mode A' (opencode 等)**:`task` 工具降级
   - **Mode B (Antigravity CLI)**:`run_workflow.js` + `agy` 可选
   - 三模式自动探测,行为一致。完全使用 Agent 自身的 LLM 能力与本地工具，无需配置任何第三方大模型 API Key。
2. **五阶段漏斗模型 (Five-Stage Funnel)**：
   - R0 工具自检 + 平台探测 + 目录守卫
   - R1 静态规则扫描(L0,CodeQL 清洗)
   - **R1.5 框架感知扩展(L1,项目 wrapper 自识别)** ← 修复 pre-v2 漏报根因
   - R3 双向回溯验证 + verify_queue 状态机
   - R4 业务逻辑深钻(固化 6 类假说)
3. **Top 15 语言原生覆盖 + L2 fallback**：
   Python、C/C++、Java、JS/TS、C#、Go、Rust、PHP、Ruby、Swift、Kotlin、Scala、Shell、Perl、PowerShell。超出 15 种语言的源码扩展会走 L2 fallback，生成带 `reviewed_by: "main-agent"` 的 `.audit_results/extended_profile.json` 并以 `origin=L2` 入队。
4. **CodeQL 双源规则库**：
   - L0 sink 来自 [github/codeql](https://github.com/github/codeql) 官方 qll 模型自动清洗(由 `tools/codeql_sink_extractor.py` 完成,可重现)
   - L1 wrapper 由 R1.5 阶段动态识别项目自有 sink wrapper(如 Android Bluetooth 的 `osi_*alloc`、`STREAM_TO_UINT16` 宏、Android `ContentResolver.query`)
   - 手工补丁段(`manual_additions`)覆盖 CodeQL 不识别的 Android/框架特定 sink
5. **跨进程 sink 终结 (REQ-19)**：
   调用链到达 IPC/DSO/Provider 边界时,边界即 sink,不要求在当前仓库内闭环追溯外部实现。修复 pre-v2 中 Android Bluetooth MAP SQL 注入因 sink 在外部 Provider 而漏报的问题。
6. **verify_queue 状态机 (REQ-09)**：
   候选清单必须落盘 `.audit_results/verify_queue.json`,状态机 `PENDING→VERIFIED→{REACHABLE|UNREACHABLE|NEEDS_REVIEW}`,断点续传 + Assert 兜底。`NEEDS_REVIEW` 不允许静默丢弃。
7. **科学的可量化指标 (L0/L1/L2 区分)**：
   Rule Coverage Rate / Reachability Rate / Noise Reduction Rate 三率 + **Sink Discovery Rate**(L0 召回能力)+ **False Negative Risk**(L1+R4 REACHABLE 占比,量化盲区)。
8. **Top 10 严重漏洞聚焦 (Zero Noise)**：
   坚决剔除代码规范、命名、弱随机数等垃圾报警。只关注 RCE、SQLi、SSRF、逻辑越权、内存越界(OOB read/write)、UAF、未控内存分配(CWE-789)、特权提升等直接对系统产生实质危害的缺陷。
9. **固化 6 类业务逻辑假说 (REQ-15)**：
   R4 阶段必选 6 类假说:CWE-789 / CWE-125-787 / CWE-416-UAF / 跨进程信任边界破坏 / 导出无权 / 越权-多租户。每类三选一结论(`confirmed` / `reviewed_clean` / `not_applicable`),禁止默默跳过；结果写入 `verify_queue.json` 的 `r4_findings` 段并参与最终指标。

---

## 🚀 如何安装本技能

### 方式 1:工作区加载（本地项目）
将本目录移动或创建到您开发项目的 `.agents/skills/` 下：
```bash
cp -r /root/reachable-critical-audit <您的开发项目目录>/.agents/skills/reachable-critical-audit
```

### 方式 2:opencode 全局加载（所有项目）
opencode 外部 skill 自动加载路径(无需额外配置):
```bash
# 任一即可,~/.agents/skills/ 是 opencode 默认扫描路径之一
cp -r /root/reachable-critical-audit ~/.agents/skills/reachable-critical-audit
# 或显式配置
mkdir -p ~/.config/opencode/skills/
cp -r /root/reachable-critical-audit ~/.config/opencode/skills/reachable-critical-audit
```

### 方式 3:Antigravity 全局加载（所有项目）
```bash
mkdir -p ~/.gemini/config/skills/
cp -r /root/reachable-critical-audit ~/.gemini/config/skills/reachable-critical-audit
```

加载后,在聊天框中输入:
> *“请使用 `reachable-critical-audit` 技能，帮我审计这个项目，只报告能从外部输入触发的可达严重漏洞。”*

Agent 会自动执行 R0 平台探测选择执行模式(opencode 上自动走 `task` 工具,Antigravity 上优先 `define_subagent`,`agy` 可用时可选 Mode B)。

---

## 🧰 本地依赖

R0 自检依赖 `tree-sitter` 及 12 个有规则语言的 grammar 包。依赖应安装到 **skill 安装目录** 下的 `.venv`，不要在被审计项目根目录创建虚拟环境，也不要安装到系统 Python：

```bash
cd /path/to/reachable-critical-audit
python3 -m venv .venv
.venv/bin/python3 -m pip install \
  tree-sitter tree-sitter-java tree-sitter-cpp tree-sitter-python \
  tree-sitter-javascript tree-sitter-go tree-sitter-rust tree-sitter-c-sharp \
  tree-sitter-php tree-sitter-ruby tree-sitter-swift tree-sitter-kotlin \
  tree-sitter-scala
.venv/bin/python3 tools/ast_scanner.py --self-check
```

`run_workflow.js` 会优先使用 skill 安装目录内的 `.venv/bin/python3`；也可用 `REACHABLE_AUDIT_VENV=/path/to/venv` 覆盖 venv 目录，或用 `PYTHON_BIN=/path/to/python3` 显式覆盖解释器。

---

## 🔧 规则库维护（开发者）

`resources/security_profiles.json` 的 L0 段由 CodeQL 自动清洗产出。每次 CodeQL 主分支更新后,运行:

```bash
# 重新清洗最新 CodeQL main HEAD (不可重现,仅一次性刷新)
python3 tools/codeql_sink_extractor.py --output resources/security_profiles.json

# 推荐:固定 CodeQL tag 以保证可重现
python3 tools/codeql_sink_extractor.py --codeql-tag codeql-bundle-v2.18.0 \
    --output resources/security_profiles.json

# 重用本地已克隆的 CodeQL 副本
python3 tools/codeql_sink_extractor.py --codeql-path /path/to/codeql \
    --output resources/security_profiles.json

# Dry-run: 仅打印提取结果到 stdout,不写 JSON
python3 tools/codeql_sink_extractor.py --dry-run
```

清洗流程:
1. 克隆固定 tag 的 CodeQL 仓库
2. 自动扫描各语言 `ql/lib/semmle/<lang>/security/` 目录及 `dataflow/` 子目录
3. 按 CWE 关键字匹配文件名(`*sql*injection*` / `*uncontrolled*allocation*` / `*flow*after*free*` 等)
4. 用 `hasGlobalName("xxx")` / `hasName([...])` / `getMethod("xxx")` 等正则提取 sink 函数名
5. 写入 `rules.<lang>` 段,记录 `codeql_revision` 字段
6. 保留 `manual_additions` / `wrapper_detection` / `property_check_patterns` 段不动(手工维护)

手工补丁段(`manual_additions`)用于覆盖 CodeQL 不识别的项目特定 sink,每条必须标注 `source_reason`。

---

## 📋 需求与设计文档

- [REQUIREMENTS.md](REQUIREMENTS.md):REQ-01 至 REQ-20 详细需求规约,含修订前后对照表
- [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md):五阶段漏斗模型 + 平台兼容层 + CodeQL 双源规则库 + REQ-01~20 完整映射
- [SKILL.md](SKILL.md):Agent 行为规范主入口,含任务书模板附录

---

## 🧪 设计动机

v2 的核心改动（R1.5 框架感知扩展、`manual_additions` 手工补丁、跨边界 sink 终结、固化 6 类业务假说）针对的是 pre-v2 在 framework 类项目上暴露的两类系统性盲区：

- **项目自有 wrapper 不可见**：规则库只列原生 sink（如 `query`/`strcpy`），漏掉项目自定义封装（如 Android Bluetooth 的 `osi_*alloc` allocator、`STREAM_TO_UINT*` 解析宏）。→ R1.5 wrapper_detection 修复。
- **跨进程 sink 不可见**：要求调用链在本仓库内闭环，导致恶意输入透传给外部 ContentProvider / DSO 后无法判定。→ REQ-19 跨边界终结修复。

> 上述改动的有效性以设计推演与单元验证为准。仓库未随附具体项目的审计报告产物；若需复现审计结论，请对目标项目实际运行本 Skill 并核对 `.audit_results/` 下的落盘结果。

---

## About

reachable-critical-audit 是面向 Agent 的可达性严重漏洞审计 Skill。基于 CodeQL 官方规则库 + 项目 wrapper 自识别 + 跨进程边界感知,实现"外部可控输入 → 高危 Sink(含跨进程边界)"的真实可达性验证。

License: 同宿主项目。
