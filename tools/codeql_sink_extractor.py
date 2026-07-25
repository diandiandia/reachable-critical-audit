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
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable

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
    # shell/perl/powershell 暂无独立 security 目录，用通用 fallback
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
    cwe_id: str, category: str, names: list[str]
) -> dict | None:
    if not names:
        return None
    regex_list = [re.escape(n) + r"\s*\(" for n in names]
    return {
        "cwe_id": cwe_id,
        "category": category,
        "type": "TAINT_ANALYSIS",
        "codeql_model": f"extracted via codeql_sink_extractor.py",
        "sinks": {"regex": regex_list, "ast_patterns": []},
        "sources": {"regex": []},
    }


# ==============================================================================
# 主流程
# ==============================================================================

def extract_all(codeql_root: Path) -> dict[str, list[dict]]:
    """Walk all configured languages and extract rule entries."""
    all_rules: dict[str, list[dict]] = {}
    for lang in LANG_SECURITY_PATHS:
        sec_root = find_security_root(codeql_root, lang)
        if sec_root is None:
            print(f"[!] {lang} security_root not found in any candidate path",
                  file=sys.stderr)
            continue
        print(f"[+] {lang} security_root: {sec_root.relative_to(codeql_root)}",
              file=sys.stderr)

        # 按 CWE 聚合 names
        cwe_to_names: dict[str, dict] = {}  # cwe_id -> {"category", "names": [...]}
        for qll in discover_qll_files(sec_root):
                cwes = match_cwe_for_file(qll, lang)
            if not cwes:
                continue
            names = dedupe(extract_names_from_qll(qll))
            if not names:
                continue
            for cwe_id, category in cwes:
                slot = cwe_to_names.setdefault(
                    cwe_id, {"category": category, "names": []}
                )
                slot["names"].extend(names)

        # 构建 entries — 合并重名并排序
        entries: list[dict] = []
        for cwe_id, slot in cwe_to_names.items():
            names = dedupe(slot["names"])
            entry = build_rule_entry(cwe_id, slot["category"], names)
            if entry:
                entries.append(entry)
                print(f"  [{lang}] {cwe_id:10s} {slot['category']:30s} "
                      f"{len(names):3d} sinks", file=sys.stderr)
        all_rules[lang] = entries
    return all_rules


def merge_into_profiles(
    profiles_path: Path, codeql_rev: str, extracted: dict
) -> None:
    """Merge extracted rules into security_profiles.json.

    Note: 参数顺序按调用点习惯 (path, rev, extracted) 排列,便于 main() 直接传。
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
    for lang, extracted_entries in extracted.items():
        # 策略:保留原 rules.<lang> 段已有的所有 CWE,只补充 CodeQL 提取到的
        # 新 CWE(原段没有的)。原段每个 CWE 的 sinks 不被覆盖,因为手写规则
        # 通常比 CodeQL 提取的正则更精炼(含 ast_patterns)。
        # CodeQL 提取到的 CWE 若原段已有,跳过;若原段没有,追加。
        existing_cwes = {e.get("cwe_id") for e in rules.get(lang, [])}
        for entry in extracted_entries:
            if entry["cwe_id"] not in existing_cwes:
                rules.setdefault(lang, []).append(entry)
                existing_cwes.add(entry["cwe_id"])

    # 同时合并 manual_additions 段(若用户已手工填的 CWE 也不在 CodeQL 提取中)
    for lang, manual_entries in profile.get("manual_additions", {}).items():
        existing_cwes = {e.get("cwe_id") for e in rules.get(lang, [])}
        for entry in manual_entries:
            if entry.get("cwe_id") not in existing_cwes:
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

    merge_into_profiles(Path(args.output), rev, extracted)

    # 清理临时 clone(用户传 --codeql-path 时不删)
    if not args.codeql_path:
        shutil.rmtree(codeql_root.parent, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
