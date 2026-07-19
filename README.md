# Reachable Critical Audit System (可达性严重漏洞审计系统)

这是一个专为 Google Antigravity 设计的自定义 Skill 项目。它旨在解决传统静态代码分析工具（SAST）中**噪音大、误报高、需要繁琐配置 API Key** 的痛点。

---

## 📂 项目结构 (Project Layout)

```
reachable-critical-audit/
├── README.md               # 项目自述文件
├── REQUIREMENTS.md         # 详细需求规格书 (REQ-01 至 REQ-10)
├── SYSTEM_DESIGN.md       # 系统架构与实现映射设计文档
├── SKILL.md                # 技能主入口（Agent 行为规范指南）
└── resources/
    └── security_profiles.json  # 固化的 Top 15 语言 Top 10 漏洞规则库
```

---

## 🌟 核心特色 (Core Features)

1. **原生零 Key 自治 (Zero-Key Autonomy)**：
   直接依托于 Antigravity 平台的原生 Agent 运行，利用系统内置的大模型能力，无需开发人员申请和配置任何第三方 `API_KEY`。
2. **Top 15 语言原生覆盖**：
   通过 `security_profiles.json` 固化了 Python、C++、Java、JS/TS、C#、Go、Rust、PHP、Ruby、Swift、Kotlin、Scala、Shell、Perl、PowerShell 共 15 种开发语言的匹配正则。
3. **Top 10 严重漏洞聚焦 (Zero Noise)**：
   坚决剔除任何格式规范、变量命名、非安全场景弱随机数等垃圾报警。只关注 RCE、SQLi、SSRF、逻辑越权、内存越界、UAF 和特权提升等直接对系统产生实质危害的缺陷。
4. **自底向上可达性验证**：
   追踪数据流向，检测调用链上传递的参数是否被强类型转换或过滤拦截。只有 100% 能被外部入口控制的 Sink 才会报告为漏洞。
5. **未预设语言的 Fallback 机制**：
   若项目包含非 15 种预设语言（如 Erlang），Agent 自动通过内置知识库动态合成该语言的 Top 10 规则库并无缝执行数据流追踪，确保 100% 语言覆盖率。
6. **科学的可量化指标**：
   审计结束后，自动计算并输出规则匹配率、可达率、以及静态降噪率。

---

## 🚀 如何在 Antigravity 中运行本技能

### 方式 1：工作区加载（本地项目）
将本目录移动或创建到您开发项目的 `.agents/skills/` 下：
```bash
cp -r /root/reachable-critical-audit <您的开发项目目录>/.agents/skills/
```
在 Antigravity 聊天框中输入：
> *“请使用 `reachable-critical-audit` 技能，帮我审计这个项目，只报告能从外部输入触发的可达严重漏洞。”*

### 方式 2：全局加载（所有项目）
将本目录放置于您的全局配置路径：
```bash
mkdir -p ~/.gemini/config/skills/
cp -r /root/reachable-critical-audit ~/.gemini/config/skills/
```
Agent 在所有关联工作区都可以随时加载并调用该技能。
