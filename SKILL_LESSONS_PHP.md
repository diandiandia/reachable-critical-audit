# Reachable Critical Audit Skill — PHP 审计暴露的缺陷与改进建议

> **文档性质**：基于 phpMyAdmin 4.8.5 (RELEASE_4_8_5 tag, 739 PHP 文件) 实测审计对
> `reachable-critical-audit` skill 的回顾性缺陷分析。驱动 skill 规则库改进，非项目审计报告。
>
> **审计日期**：2026-08-13
> **测试目标**：phpMyAdmin 4.8.5 — ground truth = CVE-2018-12613（`index.php` LFI→RCE）
> **环境**：skill venv 安装 `tree_sitter_php` 后 PHP AST 扫描可用（self-check php 冒烟 4/4 命中）
> **扫描结果**：4981 候选（php 3558, javascript 1420, python 3）

---

## 0. 摘要

PHP 是 skill 规则库的**低覆盖语言**：7 条规则（CWE-502/78/79/89/918/94/95），全部来自
semgrep-registry 移植。实测暴露 3 类缺陷：

1. **无 CWE-22/98（路径遍历/LFI）PHP 规则，且 PHP 全部规则无 `include`/`require` sink**
   → 最高频的 PHP 漏洞类（LFI→RCE，CVE-2018-12613 即此类）**系统性漏检**
2. CWE-22 候选来自跨语言 fallback，命中 JS `window.open`/doc 配置行，**纯噪音**
3. R3 可达性回溯对 PHP 有效（`$_GET/$_POST/$_SERVER` source 可正确判定 UNREACHABLE），
   但候选质量被规则缺失拖累

---

## 1. 关键缺陷

### 1.1 CVE-2018-12613 LFI sink 完全漏检（最高优先级）

**现象**：phpMyAdmin 4.8.5 `index.php:62` 存在标准 LFI sink：
```php
if (! empty($_REQUEST['target'])
    && is_string($_REQUEST['target'])
    && ! preg_match('/^index/', $_REQUEST['target'])
    && ! in_array($_REQUEST['target'], $target_blacklist)
    && Core::checkPageValidity($_REQUEST['target'], [], true)   // 4.8.5 可用 %253f 双编码绕过
) {
    include $_REQUEST['target'];                                 // ← CVE-2018-12613 sink
}
```
扫描器对全库 739 个 PHP 文件产出 4981 候选，但**对该 sink 零命中**。

**根因**：PHP 规则集 sink 列表只覆盖 `exec/system/eval/assert/curl_exec/mysqli_query/unserialize`
等，**无 `include/include_once/require/require_once`**。CodeQL/semgrep 的 PHP LFI 规则
（`php.lang.security.tainted-path-concat` 等）未被收录。PHP 的 CWE-22 攻击面与 C 不同：
不是 `open()`，而是 `include`/`file_get_contents`/`fopen`。

### 1.2 PHP 无 CWE-22 规则，跨语言 fallback 产出纯噪音

**现象**：扫描产生 5 条 `CWE-22` 候选，全部为 JS `window.open`（`js/functions.js:4423`）、
`indexedDB.open`（designer）与 doc/conf.py 注释行——与 PHP 路径操作无关。

**根因**：PHP 规则表无 CWE-22；候选来自规则库对全语言的通用 CWE-22 兜底正则。PHP 应建立
**语言专属 CWE-22/98 规则**，sink 限定 `include/require/file_get_contents/fopen/readfile/
copy/unlink/rename/move_uploaded_file`。

### 1.3 R3 可达性回溯对 PHP 有效（正面结论）

**现象**：`CAND-975`（`libraries/classes/SysInfoSunOS.php:30` `shell_exec('kstat -p d ' . $key)`）
被 L0 命中为 CWE-78。R3 回溯发现 `_kstat()` 全部 9 个调用点的 `$key` 均为**硬编码字符串**
（`unix:0:system_misc:avenrun_1min` 等），无任何用户输入路径 → **UNREACHABLE**。

**结论**：PHP source 模型（`$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER`）配合跨函数回溯可
正确过滤常量拼接的伪候选，这是 skill 在 PHP 上可复用的能力。

---

## 2. 建议改进

### P0：新增 PHP CWE-22/98（LFI）规则

```json
{
  "cwe_id": "CWE-98",
  "category": "LocalFileInclusion",
  "sinks": {
    "ast_patterns": [
      "(include_expression) @sink",
      "(require_expression) @sink",
      "(function_call_expression function: (name) @fn (#match? @fn \"^(include|include_once|require|require_once|file_get_contents|fopen|readfile)$\"))"
    ],
    "regex": ["(^|[^a-zA-Z_])(include|include_once|require|require_once)\\s*\\(?\\s*\\$"]
  },
  "sources": {
    "regex": ["\\$_?(GET|POST|REQUEST|COOKIE|SERVER|FILES)\\s*\\["]
  }
}
```

### P1：PHP source 模型结构化

- 内置 `$_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER['HTTP_*']/$_FILES/$argv` 为 taint source，
  供 R3 回溯统一使用（当前依赖正则零散命中）。

### P1：PHP sink 去噪

- CWE-78/94 的 `ast_patterns` 用 `function_call_expression` 已正确；regex 兜底需排除
  `shell_exec('硬编码')` 常量场景（与 1.3 结论一致）。

---

## 3. 建议后续验证目标

| 项目 | 版本 | Ground truth CVE | 规则面 |
|---|---|---|---|
| phpMyAdmin | 4.8.5 | CVE-2018-12613 (LFI→RCE) | CWE-98/22, 94 |
| Drupal 8.3.x | <8.3.9 | CVE-2018-7600 Drupalgeddon2 (unserialize RCE) | CWE-502 |
| PrestaShop 1.7.7.x | <1.7.7.7 | CVE-2021-4048 (SQLi) | CWE-89 |
| SuiteCRM 7.11.x | <7.11.20 | CVE-2020-28020 (include RCE) | CWE-94/98 |
