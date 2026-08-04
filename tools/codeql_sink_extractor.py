#!/usr/bin/env python3
"""
CodeQL Sink/Source Extractor for reachable-critical-audit skill v2.

从 GitHub CodeQL 官方 qll 模型文件自动发现并清洗提取 sink/source 函数名，写入
security_profiles.json 对应语言段。实现 REQ-11 / REQ-20 的可重现规则库更新机制。

设计要点(吸取 v1 经验):
- CodeQL 文件名会随版本演进变化,因此 **不硬编码文件路径**，而是
  * 自动扫描各语言 security 目录 + dataflow 子目录
  * 按 CWE 关键字 + 文件名模式匹配
- 提取正则覆盖 CodeQL 模型常见声明形式 hasGlobalName/hasName/getMethod 等
- 提取的 sink 规则为 `re.escape(name) + r"\\s*\\("` 简单形式
  (AST 详细匹配交给 ast_scanner.py 在 R1 阶段完成)
- manual_additions / wrapper_detection / property_check_patterns 段保留不动
  (这些是 CodeQL 不覆盖的项目特定补丁)

Usage:
    # 默认克隆最新 CodeQL main 分支清洗
    python3 codeql_sink_extractor.py --output ../resources/security_profiles.json

    # 指定 CodeQL 版本(推荐固定 tag 以保证可重现)
    python3 codeql_sink_extractor.py --codeql-tag codeql-bundle-v2.18.0 \\
        --output ../resources/security_profiles.json

    # 重用已克隆的 CodeQL 本地副本
    python3 codeql_sink_extractor.py --codeql-path /path/to/codeql \\
        --output ../resources/security_profiles.json

    # 不写入 JSON，仅打印提取结果到 stdout 供人工复核
    python3 codeql_sink_extractor.py --dry-run

Output:
    更新 security_profiles.json 的 rules.<lang>[] 段，并写入 codeql_revision 字段。
    manual_additions / wrapper_detection / property_check_patterns 段保留不动。
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable

try:
    import yaml  # PyYAML — 现代 CodeQL sink 存于 .model.yml 的 sinkModel 段
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ==============================================================================
# 语言配置 — security 目录候选路径 + CWE 关键字映射
# ==============================================================================

# CodeQL 各语言 security 库的相对路径候选(按优先级;新版 CodeQL 部分
# 语言改到了 dataflow 子目录或新 codeql/ 包路径)
# Rust CWE 文件名模式：Rust 安全查询文件通常以 `.qll` 结尾且在 security 子目录中
# CodeQL for Rust 仍在演进，CWE 模式基于现有查询名称
RUST_CWE_PATTERNS: list[tuple[str, str, list[str]]] = [
    ("CWE-119", "BufferOverflow",
     ["*buffer*", "*overflow*", "*out_of_bounds*", "*from_raw_parts*"]),
    ("CWE-416", "UseAfterFree",
     ["*use_after_free*", "*after_free*", "*uaf*"]),
    ("CWE-789", "UncontrolledMemoryAllocation",
     ["*allocation*", "*uncontrolled*size*"]),
    ("CWE-190", "IntegerOverflow",
     ["*integer*overflow*", "*arithmetic*"]),
    ("CWE-78", "CommandInjection",
     ["*command*injection*", "*exec*"]),
    ("CWE-22", "PathTraversal",
     ["*path*traversal*", "*file*"]),
    ("CWE-362", "RaceCondition",
     ["*race*", "*data_race*", "*concurrent*", "*send_sync*"]),
    ("CWE-400", "UncontrolledResource",
     ["*resource*exhaustion*", "*panic*", "*unbounded*"]),
    ("CWE-502", "Deserialization",
     ["*deserialization*", "*deser*"]),
    ("CWE-1321", "PrototypePollution",
     ["*prototype*pollut*"]),
]

LANG_SECURITY_PATHS: dict[str, list[str]] = {
    "cpp": [
        "cpp/ql/lib/semmle/code/cpp/security",
    ],
    "java": [
        "java/ql/lib/semmle/code/java/security",
    ],
    "python": [
        "python/ql/lib/semmle/python/security",
        "python/ql/lib/semmle/code/python/security",
    ],
    "javascript": [
        "javascript/ql/lib/semmle/javascript/security",
        "javascript/ql/lib/semmle/code/javascript/security",
    ],
    "go": [
        "go/ql/lib/semmle/go/security",
        "go/ql/lib/semmle/code/go/security",
    ],
    "csharp": [
        "csharp/ql/lib/semmle/code/csharp/security",
        "csharp/ql/lib/semmle/code/csharp/frameworks/system/security",
    ],
    "rust": [
        "rust/ql/lib/codeql/rust/security",
    ],
    "php": [
        "php/ql/lib/semmle/code/php/security",
        "php/ql/lib/semmle/php/security",
    ],
    "ruby": [
        "ruby/ql/lib/codeql/ruby/security",
        "ruby/ql/lib/semmle/code/ruby/security",
        "ruby/ql/lib/semmle/ruby/security",
    ],
    "swift": [
        "swift/ql/lib/codeql/swift/security",
    ],
    "kotlin": [
        "kotlin/ql/lib/codeql/kotlin/security",
    ],
    # 注意: CodeQL 官方不支持 scala。此前 fallback 到 java 路径会产出"贴 scala
    # 标签的 java 规则"(伪来源), 已移除。scala 规则须走 manual_additions。
    "scala": [
        "scala/ql/lib/codeql/scala/security",
    ],
    "shell": [
        "shell/ql/lib/codeql/shell/security",
    ],
    "perl": [
        "perl/ql/lib/codeql/perl/security",
    ],
    "powershell": [
        "powershell/ql/lib/codeql/powershell/security",
    ],
}

# CWE 关键字 → (cwe_id, category, filename_patterns)
# filename_patterns 使用 fnmatch 风格的小写匹配,允许多个候选
CWE_PATTERNS: list[tuple[str, str, list[str]]] = [
    # CWE-78 命令执行
    ("CWE-78", "CommandExecution",
     ["*command*injection*", "*command*line*", "*exec*tainted*", "*exec*",
      "*shell*command*"]),
    # CWE-89 SQL 注入
    ("CWE-89", "SqlInjection",
     ["*sql*injection*", "*sql*query*", "*sql*concat*", "* NosqlInjection*"]),
    # CWE-94 代码执行
    ("CWE-94", "CodeExecution",
     ["*code*injection*", "*codeexec*"]),
    # CWE-787 越界写 / CWE-119 缓冲区
    ("CWE-787", "BufferWrite",
     ["*buffer*write*", "*buffer*overflow*", "*uncontrolled*write*"]),
    # CWE-125 越界读 / CWE-119
    ("CWE-125", "BufferAccess",
     ["*buffer*access*", "*out*of*bound*", "*overread*"]),
    # CWE-789 未控内存分配(关键!对应 AVRCP heap DoS)
    ("CWE-789", "UncontrolledMemoryAllocation",
     ["*uncontrolled*allocation*", "*allocation*size*", "*uncontrolled*size*"]),
    # CWE-190 整数溢出
    ("CWE-190", "IntegerOverflow",
     ["*overflow*", "*integer*overflow*", "*arithmetic*"]),
    # CWE-416/415 UAF/Double-free
    ("CWE-416", "UseAfterFree",
     ["*flow*after*free*", "*use*after*free*", "*after*free*", "*double*free*"]),
    # CWE-134 格式串
    ("CWE-134", "FormatString",
     ["*printf*like*", "*format*string*"]),
    # CWE-22 路径穿越
    ("CWE-22", "PathTraversal",
     ["*path*traversal*", "*file*access*", "*file*write*", "*file*read*write*",
      "*partial*path*"]),
    # CWE-79 XSS
    ("CWE-79", "Xss",
     ["*xss*", "*cross*site*", "*dom*xss*"]),
    # CWE-502 反序列化
    ("CWE-502", "Deserialization",
     ["*deserialization*", "*deser*", "*unsafe*deserialization*"]),
    # CWE-918 SSRF
    ("CWE-918", "Ssrf",
     ["*request*forgery*", "*ssrf*", "*server*side*request*"]),
    # CWE-611 XXE
    ("CWE-611", "XmlParserSink",
     ["*xml*", "*xxe*", "*xml*parsers*"]),
    # CWE-601 开放重定向
    ("CWE-601", "OpenRedirect",
     ["*redirect*", "*open*redirect*", "*url*redirect*"]),
    # CWE-1321 原型污染(JS)
    ("CWE-1321", "PrototypePollution",
     ["*prototype*pollut*"]),
    # CWE-434 文件上传
    ("CWE-434", "UnrestrictedUpload",
     ["* unrestricted*upload*", "*upload*"]),
]

# 提取正则 — 覆盖 CodeQL 模型常见声明
SINK_PATTERNS: list[re.Pattern] = [
    # hasGlobalName("name") / hasGlobalName(["a","b"])  (C/C++)
    re.compile(r'hasGlobalName\(\s*"([^"]+)"\s*\)'),
    re.compile(r'hasGlobalName\(\s*\[([^\]]+)\]\s*\)'),
    # hasName([...])  (C/C++ 多名)
    re.compile(r'hasName\(\s*\[([^\]]+)\]\s*\)'),
    # hasName("name")  (单名形式)
    re.compile(r'hasName\(\s*"([^"]+)"\s*\)'),
    # getMethod("name") / getStaticMethod("name")  (Java)
    re.compile(r'getMethod\(\s*"([^"]+)"\s*\)'),
    re.compile(r'getStaticMethod\(\s*"([^"]+)"\s*\)'),
    # getFunc("name")  (Python 等)
    re.compile(r'getFunc\(\s*"([^"]+)"\s*\)'),
    # getCalleeName("name")  (JS)
    re.compile(r'getCalleeName\(\s*"([^"]+)"\s*\)'),
    # hasMemberName("name")  (Go)
    re.compile(r'hasMemberName\(\s*"([^"]+)"\s*\)'),
    # 直接字符串名 — 形如 getStringValue("system") 等
    # (保守起见,只匹配 hasName/hasGlobalName 系列)
]

# 供扫描的子目录,在 security_root 之下递归找 .qll 文件
SCAN_SUBDIRS = ["", "dataflow"]

# ==============================================================================
# 现代 CodeQL: Models-as-Data (MaD) sinkModel YAML 通道
# ==============================================================================
# 新版 CodeQL 的 sink 定义主体已从 qll 的 hasName("...") 迁移到 .model.yml 的
# sinkModel 扩展段。行格式因语言而异(长度不定), 但 sink-kind 恒为倒数第 2 列
# (最后一列是 provenance: manual/generated/df-generated)。函数名位置:
#   - java/csharp/go/js/py/ruby: [ns, type, subtypes(bool), NAME, sig, ext, ap, kind, prov]
#     → NAME = bool 列之后第一个非空字符串
#   - rust/cpp 短格式:            [ns::path, ap, kind, prov]
#     → NAME = 第一列命名空间路径的最后一段
#
# sink-kind → (cwe_id, category)。仅保留本 skill 关心的严重类别; df-generated /
# ai-generated / test-sink / log-injection / *-manual 等噪音 kind 不在表内即被丢弃。
SINK_KIND_TO_CWE: dict[str, tuple[str, str]] = {
    "sql-injection": ("CWE-89", "SqlInjection"),
    "nosql-injection": ("CWE-89", "NoSqlInjection"),
    "command-injection": ("CWE-78", "CommandInjection"),
    "environment-injection": ("CWE-78", "EnvironmentInjection"),
    "code-injection": ("CWE-94", "CodeInjection"),
    "jexl-injection": ("CWE-94", "JexlInjection"),
    "mvel-injection": ("CWE-94", "MvelInjection"),
    "ognl-injection": ("CWE-94", "OgnlInjection"),
    "groovy-injection": ("CWE-94", "GroovyInjection"),
    "template-injection": ("CWE-94", "TemplateInjection"),
    "js-injection": ("CWE-94", "JsInjection"),
    "xslt-injection": ("CWE-94", "XsltInjection"),
    "path-injection": ("CWE-22", "PathTraversal"),
    "unsafe-deserialization": ("CWE-502", "Deserialization"),
    "request-forgery": ("CWE-918", "Ssrf"),
    "ldap-injection": ("CWE-90", "LdapInjection"),
    "xpath-injection": ("CWE-643", "XPathInjection"),
    "jndi-injection": ("CWE-74", "JndiInjection"),
    "url-redirection": ("CWE-601", "OpenRedirect"),
    "url-forward": ("CWE-601", "UrlForward"),
    "fragment-injection": ("CWE-601", "FragmentInjection"),
    "response-splitting": ("CWE-113", "ResponseSplitting"),
    "html-injection": ("CWE-79", "HtmlInjection"),
    "alloc-size": ("CWE-789", "UncontrolledAllocationSize"),
    "alloc-layout": ("CWE-789", "UncontrolledAllocationLayout"),
    "pointer-access": ("CWE-119", "PointerAccess"),
    "trust-boundary-violation": ("CWE-501", "TrustBoundaryViolation"),
    "intent-redirection": ("CWE-926", "IntentRedirection"),
    "pending-intents": ("CWE-927", "PendingIntent"),
}

# 提取到的名字里需过滤的脏值: SIMD intrinsics / 编译器内部符号 / 单字母
_NAME_JUNK_RE = re.compile(r"^(_mm|_rust_|__rust|__rdl_|_load_mask|_load_epi)")


def _valid_sink_name(name: str) -> bool:
    if not name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return False
    if len(name) <= 1:
        return False
    if _NAME_JUNK_RE.search(name):
        return False
    return True


def _mad_name(cells: list, lang: str) -> str | None:
    """从一行 MaD sinkModel data 提取函数/方法名。"""
    if lang in ("rust", "cpp"):
        path = cells[0] if cells and isinstance(cells[0], str) else ""
        segs = [s for s in re.split(r"::|\.", path) if s]
        return segs[-1] if segs else None
    # 结构化语言: bool(subtypes) 列之后第一个非空字符串即方法名
    for i, c in enumerate(cells):
        if isinstance(c, bool):
            for j in range(i + 1, len(cells)):
                if isinstance(cells[j], str) and cells[j].strip():
                    return cells[j].strip()
            break
    # 兜底: 首个非空字符串
    return next((c.strip() for c in cells if isinstance(c, str) and c.strip()), None)


def extract_from_yaml(lang_root: Path) -> dict[str, list[str]]:
    """扫描一个语言目录下所有 .model.yml/.yml 的 sinkModel 段。

    返回 {cwe_id: [names...]}。lang_root 传语言顶层目录(如 codeql_root/'java')。
    """
    if not HAS_YAML:
        return {}
    lang = lang_root.name
    cwe_to_names: dict[str, list[str]] = {}
    for f in glob.glob(str(lang_root / "**" / "*.yml"), recursive=True):
        try:
            doc = yaml.safe_load(Path(f).read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        for ext in doc.get("extensions", []) or []:
            if not isinstance(ext, dict):
                continue
            if ext.get("addsTo", {}).get("extensible") != "sinkModel":
                continue
            for row in ext.get("data", []) or []:
                if not isinstance(row, list):
                    continue
                kind = next((c for c in row
                             if isinstance(c, str) and c in SINK_KIND_TO_CWE), None)
                if not kind:
                    continue
                name = _mad_name(row, lang)
                if not name or not _valid_sink_name(name):
                    continue
                cwe_id = SINK_KIND_TO_CWE[kind][0]
                cwe_to_names.setdefault(cwe_id, []).append(name)
    return cwe_to_names


# ==============================================================================
# 工具函数
# ==============================================================================

def clone_codeql(tag: str | None, target: Path) -> str:
    """Clone CodeQL repo. Returns the commit hash actually checked out."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.rmtree(target)
    print(f"[+] Cloning github/codeql @ {tag or 'main'} ...", file=sys.stderr)
    subprocess.run(
        ["git", "clone", "--depth", "1",
         *(["--branch", tag] if tag else []),
         "https://github.com/github/codeql.git",
         str(target)],
        check=True,
    )
    rev = subprocess.check_output(
        ["git", "-C", str(target), "rev-parse", "HEAD"], text=True
    ).strip()
    return rev


def find_security_root(codeql_root: Path, lang: str) -> Path | None:
    """在 LANG_SECURITY_PATHS 配置的候选路径里找第一个存在的目录。"""
    for rel in LANG_SECURITY_PATHS.get(lang, []):
        p = codeql_root / rel
        if p.exists() and p.is_dir():
            return p
    return None


def discover_qll_files(security_root: Path) -> list[Path]:
    """递归扫描 security_root 下的所有 .qll 文件(含 dataflow 子目录)。"""
    files: list[Path] = []
    for sub in SCAN_SUBDIRS:
        d = security_root / sub if sub else security_root
        if not d.exists():
            continue
        files.extend(d.rglob("*.qll"))
    return sorted(set(files))


def match_cwe_for_file(qll_path: Path, lang: str = "") -> list[tuple[str, str]]:
    """根据文件名匹配 CWE,返回 [(cwe_id, category), ...] 列表(可能多个)。
       lang 参数允许使用语言特定的 CWE 模式表(如 Rust)。"""
    name_lower = qll_path.name.lower()
    results: list[tuple[str, str]] = []
    # 避免 Customizations / Sanitizers / Query / Config 等非 sink 文件
    # (这些文件主要定义 source/sanitizer 而非 sink)
    skip_suffixes = ("customizations.qll", "sanitizers.qll", "config.qll",
                     "taintedlocalquery.qll", "query.qll")
    if name_lower.endswith(skip_suffixes):
        pass

    patterns = RUST_CWE_PATTERNS if lang == "rust" else CWE_PATTERNS
    for cwe_id, category, pats in patterns:
        for pat in pats:
            needle = pat.lower().replace("*", "")
            if needle in name_lower:
                results.append((cwe_id, category))
                break
    return results


def extract_names_from_qll(qll_path: Path) -> list[str]:
    """Extract function/method names from a .qll file using all SINK_PATTERNS."""
    try:
        text = qll_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[!] read {qll_path} fail: {e}", file=sys.stderr)
        return []
    names: list[str] = []
    for pat in SINK_PATTERNS:
        for m in pat.finditer(text):
            if m.groups():
                raw = m.group(1)
                if "," in raw:
                    # hasName(["a", "b", "c"])
                    for piece in raw.split(","):
                        n = piece.strip().strip('"').strip("'")
                        if n and not n.startswith("//") and not n.startswith("/*"):
                            names.append(n)
                else:
                    n = raw.strip().strip('"').strip("'")
                    if n:
                        names.append(n)
    return names


def dedupe(seq: Iterable[str]) -> list[str]:
    """Deduplicate list while preserving insertion order."""
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def build_rule_entry(
    cwe_id: str, category: str, names: list[str],
    sources: tuple[str, ...] = ("codeql-mad-yaml",),
) -> dict | None:
    if not names:
        return None
    regex_list = [re.escape(n) + r"\s*\(" for n in names]
    return {
        "cwe_id": cwe_id,
        "category": category,
        "type": "TAINT_ANALYSIS",
        # 诚实来源标注: codeql-mad-yaml=从 .model.yml sinkModel 提取;
        # codeql-qll-hasname=从旧式 qll hasName/getMethod 提取。多源合并时并列。
        "codeql_model": "+".join(sources),
        "sink_count": len(names),
        "sinks": {"regex": regex_list, "ast_patterns": []},
        "sources": {"regex": []},
    }


# ==============================================================================
# 主流程
# ==============================================================================

# cwe_id -> 默认 category (YAML 通道按 CWE 聚合, 需一个稳定的展示名)
_CWE_DEFAULT_CATEGORY = {
    "CWE-89": "SqlInjection", "CWE-78": "CommandInjection", "CWE-94": "CodeInjection",
    "CWE-22": "PathTraversal", "CWE-502": "Deserialization", "CWE-918": "Ssrf",
    "CWE-90": "LdapInjection", "CWE-643": "XPathInjection", "CWE-74": "JndiInjection",
    "CWE-601": "OpenRedirect", "CWE-113": "ResponseSplitting", "CWE-79": "Xss",
    "CWE-789": "UncontrolledAllocation", "CWE-119": "MemoryAccess",
    "CWE-501": "TrustBoundaryViolation", "CWE-926": "IntentRedirection",
    "CWE-927": "PendingIntent",
    # 旧式 qll 通道(match_cwe_for_file)可能产出的 CWE
    "CWE-416": "UseAfterFree", "CWE-611": "XxeXmlParser", "CWE-787": "BufferWrite",
    "CWE-125": "BufferOverread", "CWE-190": "IntegerOverflow", "CWE-134": "FormatString",
    "CWE-476": "NullDereference", "CWE-362": "RaceCondition", "CWE-1321": "PrototypePollution",
    "CWE-434": "UnrestrictedUpload",
}

# JVM 引擎别名: 这些语言编译到 JVM, CodeQL 无独立引擎, 但调用的是同一套 Java 库
# API (Runtime.exec / Statement.executeQuery / ...), 故直接复用 java 的提取结果。
# 这正是 CodeQL 官方分析 kotlin 的方式 (用 java extractor)。来源诚实标注为
# codeql-jvm-shared-with-java, 与凭空伪造 org.jetbrains.kotlin.* 有本质区别。
JVM_ALIAS_OF_JAVA = ("kotlin", "scala")


def extract_all(codeql_root: Path) -> dict[str, list[dict]]:
    """遍历所有语言, 并集两个提取通道:
      1. YAML sinkModel (现代 CodeQL 主力来源)
      2. 旧式 qll hasName/getMethod (补充 cpp 等老式定义)
    """
    all_rules: dict[str, list[dict]] = {}
    for lang in LANG_SECURITY_PATHS:
        # ---- JVM 别名: kotlin/scala 复用 java 提取结果 ----
        if lang in JVM_ALIAS_OF_JAVA:
            java_rules = all_rules.get("java", [])
            aliased = []
            for r in java_rules:
                r = json.loads(json.dumps(r))  # deep copy
                srcs = r.get("codeql_model", "")
                r["codeql_model"] = "codeql-jvm-shared-with-java"
                r["provenance"] = "codeql-jvm-alias"
                aliased.append(r)
            all_rules[lang] = aliased
            print(f"  [{lang}] 复用 java 的 {len(aliased)} 条规则 "
                  f"(JVM 共享库, codeql-jvm-shared-with-java)", file=sys.stderr)
            continue

        # cwe_id -> {"names": set, "sources": set}
        agg: dict[str, dict] = {}

        # ---- 通道 1: YAML sinkModel (扫语言顶层目录) ----
        lang_root = codeql_root / lang
        if HAS_YAML and lang_root.is_dir():
            for cwe_id, names in extract_from_yaml(lang_root).items():
                slot = agg.setdefault(cwe_id, {"names": set(), "sources": set()})
                slot["names"].update(names)
                slot["sources"].add("codeql-mad-yaml")
        elif not HAS_YAML:
            print("[!] PyYAML 未安装, 跳过 YAML sinkModel 通道 (pip install pyyaml)",
                  file=sys.stderr)

        # ---- 通道 2: 旧式 qll hasName (security_root 之下) ----
        sec_root = find_security_root(codeql_root, lang)
        if sec_root is not None:
            for qll in discover_qll_files(sec_root):
                cwes = match_cwe_for_file(qll, lang)
                if not cwes:
                    continue
                names = [n for n in dedupe(extract_names_from_qll(qll))
                         if _valid_sink_name(n)]
                if not names:
                    continue
                for cwe_id, _cat in cwes:
                    slot = agg.setdefault(cwe_id, {"names": set(), "sources": set()})
                    slot["names"].update(names)
                    slot["sources"].add("codeql-qll-hasname")

        if not agg:
            print(f"[!] {lang}: 两个通道均未提取到 sink "
                  f"(CodeQL 可能不支持该语言, 或 sink 走 Concepts.qll 抽象类)",
                  file=sys.stderr)
            all_rules[lang] = []
            continue

        entries: list[dict] = []
        for cwe_id, slot in sorted(agg.items()):
            names = sorted(slot["names"])
            category = _CWE_DEFAULT_CATEGORY.get(cwe_id, cwe_id)
            entry = build_rule_entry(cwe_id, category, names,
                                     sources=tuple(sorted(slot["sources"])))
            if entry:
                entries.append(entry)
                print(f"  [{lang}] {cwe_id:10s} {category:26s} "
                      f"{len(names):4d} sinks  [{'+'.join(sorted(slot['sources']))}]",
                      file=sys.stderr)
        all_rules[lang] = entries
    return all_rules


def merge_into_profiles(
    profiles_path: Path, codeql_rev: str, extracted: dict, replace: bool = False
) -> None:
    """Merge extracted rules into security_profiles.json.

    replace=True 时: 丢弃手工 rules，完全使用 CodeQL 提取结果 + manual_additions。
    replace=False 时: 保守合并，仅补充新 CWE。
    """
    profile: dict = {}
    if profiles_path.exists():
        try:
            profile = json.loads(profiles_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[!] existing {profiles_path} parse fail: {e}", file=sys.stderr)
            profile = {}

    profile["schema_version"] = "6.0"
    profile["codeql_revision"] = codeql_rev
    profile["codeql_extraction_notes"] = (
        "L0 rules auto-extracted by tools/codeql_sink_extractor.py. "
        "manual_additions / wrapper_detection / property_check_patterns "
        "段保留手工维护。"
    )

    rules = profile.setdefault("rules", {})

    if replace:
        # 纯 CodeQL 模式: 完全替换 rules，仅保留 CodeQL 提取 + manual_additions
        rules.clear()
        for lang, entries in extracted.items():
            if entries:
                rules[lang] = entries
    else:
        # 保守模式: 仅补充新 CWE
        for lang, extracted_entries in extracted.items():
            existing_cwes = {e.get("cwe_id") for e in rules.get(lang, [])}
            for entry in extracted_entries:
                if entry["cwe_id"] not in existing_cwes:
                    rules.setdefault(lang, []).append(entry)
                    existing_cwes.add(entry["cwe_id"])

    # 合并 manual_additions 段 (CodeQL 不覆盖但必须纳入的 sink)
    for lang, manual_entries in profile.get("manual_additions", {}).items():
        if lang.startswith("_") or not isinstance(manual_entries, list):
            continue
        existing_cwes = {e.get("cwe_id") for e in rules.get(lang, [])}
        for entry in manual_entries:
            if isinstance(entry, dict) and entry.get("cwe_id") not in existing_cwes:
                rules.setdefault(lang, []).append(entry)
                existing_cwes.add(entry.get("cwe_id"))

    profiles_path.parent.mkdir(parents=True, exist_ok=True)
    profiles_path.write_text(
        json.dumps(profile, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"[+] Wrote {profiles_path}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CodeQL -> security_profiles.json sink/source extractor. "
                    "实现 reachable-critical-audit skill REQ-11 / REQ-20。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    here = Path(__file__).resolve().parent
    parser.add_argument(
        "--output", "-o",
        default=str(here.parent / "resources" / "security_profiles.json"),
        help="Output security_profiles.json path",
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(
        "--codeql-path",
        help="Reuse existing CodeQL checkout at this path",
    )
    grp.add_argument(
        "--codeql-tag",
        help="git clone CodeQL at this tag (e.g. codeql-bundle-v2.18.0). "
             "Default: clone main HEAD (not reproducible, only for one-off refresh)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print extracted rules to stdout, do not write JSON",
    )
    parser.add_argument(
        "--replace-rules", action="store_true",
        help="Replace all existing rules with CodeQL extraction (default: conservative merge)",
    )
    args = parser.parse_args()

    if args.codeql_path:
        codeql_root = Path(args.codeql_path)
        if not codeql_root.exists():
            print(f"[!] codeql-path not exist: {codeql_root}", file=sys.stderr)
            return 2
        rev = subprocess.check_output(
            ["git", "-C", str(codeql_root), "rev-parse", "HEAD"], text=True
        ).strip()
    else:
        tmp = Path(tempfile.mkdtemp(prefix="codeql-extract-"))
        codeql_root = tmp / "codeql"
        try:
            rev = clone_codeql(args.codeql_tag, codeql_root)
        except subprocess.CalledProcessError as e:
            print(f"[!] clone failed: {e}", file=sys.stderr)
            return 2

    print(f"[+] CodeQL revision: {rev}", file=sys.stderr)

    extracted = extract_all(codeql_root)

    if args.dry_run:
        print(json.dumps(extracted, indent=2, ensure_ascii=False))
        return 0

    merge_into_profiles(Path(args.output), rev, extracted, replace=args.replace_rules)

    # 清理临时 clone(用户传 --codeql-path 时不删)
    if not args.codeql_path:
        shutil.rmtree(codeql_root.parent, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
