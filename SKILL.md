---
name: reachable-critical-audit
description: 专门针对项目进行严重漏洞（RCE, SQLi, SSRF, Bypasses）的可达性分析审计，忽略代码规范、弱随机数等低风险噪音。仅依赖 Agent 本地工具和内置大模型，不需要配置任何外部 LLM API Key。
---

# Reachable Critical Audit Skill (可达性严重漏洞审计)

> [!IMPORTANT]
> **本 Skill 旨在代替传统漏报/误报极高的静态扫描工具。Agent 必须严格遵守以下规则，忽略一切代码规范与合规性噪音，只聚焦于验证“外部可控输入是否能真实到达高危敏感 Sink 点”的真实严重漏洞。**

---

## 🎯 核心使命：无 Key 自治与 100% 可达性验证

本 Skill 运行在 Antigravity 平台的原生 Agent 之上，**完全使用 Agent 自身的 LLM 能力与本地工具，无需配置任何第三方大模型 API Key**。

为了确保在不同项目、不同运行周期中审计基准的**强一致性与可量化性**，Agent 在执行此 Skill 时，必须加载并严格遵守固化的规则配置文件：`resources/security_profiles.json`。

---

## 🛠️ 阶段 1：规则固化与未知语言的 Top 10 降级生成 (Profiling & Fallback)

在进入任何审计流程前，Agent 必须确定要扫描的语言，并获取相应的规则对齐：
1. **基准规则对齐**：Agent 首先读取并解析项目根目录的 `resources/security_profiles.json`。如果项目语言属于已定义的语言（Java、C++、Go、Python、JavaScript 等），直接加载其固化的 Top 10 规则。
2. **非预设语言的 Top 10 降级生成 (Universal Fallback)**：如果项目中包含配置文件未显式定义规则的语言（如 Erlang、Haskell、Cobol 等）：
   * Agent **必须利用其内置的安全大模型知识，动态生成该语言的 Top 10 核心高危漏洞映射（仅限 RCE、SQLi、SSRF、越权、反序列化等严重漏洞类别）**。
   * 提取该语言对应的最危险的 Sink 函数签名。
   * 仅针对这 10 个高危类别的 Sink 点在项目中进行搜索，**严禁发散到代码风格、规范噪音**。
3. **过滤低风险噪音**：不在 Top 10 规则内的 CWE 类别，一律**物理忽略**。

---

## 🔍 阶段 2：双向数据流追踪与可达约束验证 (Reachability Constraint Auditing)

一旦定位到敏感 Sink 点，Agent 必须通过**“回溯法”**验证其可达性。

### 第一步：自底向上（Bottom-Up）追踪调用链
对于发现的每一个敏感 Sink 函数，使用 `grep_search` 或者代码搜索定位其上游调用函数（Callers）：
1. 找出谁调用了当前函数，以及传入的参数是如何赋值的。
2. 逐层逆向往上找：`Sink` <- `Caller_Level_1` <- `Caller_Level_2` <- ... <- `Controller_Entry`。
3. **多态穿透**：如果遇到接口（Interface）定义，必须使用搜索手段找到所有具体的实现类（Implementations），并在实现类的方法体内继续逆向追踪。

### 第二步：可达性约束验证 (Reachability Constraints)
在调用链回溯的过程中，分析入参是否在传递途中被“截断”或“净化”：
*   **安全阻断**：参数是否经过了强类型转换、是否经过了严格的白名单校验，或者使用了安全的参数化查询。
    *   *判定结果*：如果调用链中途有**无法绕过的安全净化或格式校验**，判定为 **`UNREACHABLE` (不可达/误报)**，立即丢弃，**不要**写入漏洞报告。
*   **特权与越权约束**：针对特权提升（如 C/C++ 的 `setuid(0)`、`seteuid` 等），必须验证是否存在**普通用户/外部不可信实体所控制的数据**，能直接影响切换到 UID=0 (root) 后的后续操作或文件名/系统命令。若可以任意操纵提权后的指令参数，则判定为真实漏洞。
*   **参数可控**：参数是否能毫无阻拦地一直溯源到**外部流量入口点（Source）**的入参（如 `HTTP Request Parameter`、`HTTP Headers` 等）。
    *   *判定结果*：如果参数可以直接由外部用户控制，且中途没有被妥善处理，且符合该 CWE 对应的 `reachability_constraints`，判定为 **`REACHABLE` (真实漏洞)**。

---

## 📊 阶段 3：量化指标与结构化报告

分析结束后，Agent 必须输出可量化的度量数据，并在 `reachable_vulnerabilities_report.md` 报告中体现：

### 1. 量化审计度量 (Quantified Metrics)
*   **配置规则匹配率 (Rule Coverage Rate)**:
    $$\text{Coverage} = \frac{\text{已执行回溯验证的 Sink 点数}}{\text{静态代码中匹配到的 Sink 总数}}$$
*   **真实可达转化率 (Reachability Success Rate)**:
    $$\text{Reachability Rate} = \frac{\text{判定为 REACHABLE 的漏洞数}}{\text{静态匹配到的 Candidate 总数}}$$
*   **静态误报降噪率 (Noise Reduction Rate)**:
    $$\text{Noise Reduction} = \frac{\text{判定为 UNREACHABLE/误报的 Candidate 数}}{\text{静态匹配到的 Candidate 总数}}$$
