#!/usr/bin/env python3
"""
Semgrep Sink Extractor for reachable-critical-audit skill.

从 Semgrep registry (github.com/semgrep/semgrep-rules, LGPL 开源) 清洗提取
sink 函数名, 补齐 CodeQL 官方不支持的语言 (php / ruby / swift / bash 等)。

与 codeql_sink_extractor.py 对称: 输出同样的规则条目结构, provenance 标注为
semgrep, 可重现 (记录 semgrep_revision)。

来源分层 (方案 A 第 2 层):
  - CodeQL 支持的语言由 codeql_sink_extractor.py 处理, 本工具不覆盖。
  - 本工具专门补 php / ruby / swift 等 CodeQL 无引擎、但 Semgrep 有规则的语言。

设计要点:
  - Semgrep 规则的 metadata.cwe 直接给出 CWE 编号, 无需按文件名猜测 (比 CodeQL 更准)。
  - sink 函数名藏在 pattern-sinks 下的 `pattern: name(...)` 里, 用正则抽取标识符。
  - 复杂结构模式 (字符串插值 / 反引号 / metavariable) 无法机械抽名, 跳过。

Usage:
    python3 semgrep_extractor.py --semgrep-path /home/zjamg/semgrep-rules --dry-run
    python3 semgrep_extractor.py --semgrep-path /path --langs php,ruby,swift \\
        --output ../resources/security_profiles.json
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# 本 skill 关心的严重 CWE 白名单 (与 codeql_sink_extractor 的类别对齐)。
# 不在表内的 CWE (如弱随机 CWE-330、硬编码 CWE-798) 视为低危噪音丢弃。
CWE_WHITELIST = {
    "CWE-78": "CommandInjection", "CWE-89": "SqlInjection", "CWE-94": "CodeInjection",
    "CWE-22": "PathTraversal", "CWE-502": "Deserialization", "CWE-918": "Ssrf",
    "CWE-90": "LdapInjection", "CWE-643": "XPathInjection", "CWE-74": "Injection",
    "CWE-601": "OpenRedirect", "CWE-79": "Xss", "CWE-611": "Xxe",
    "CWE-434": "UnrestrictedUpload", "CWE-98": "PhpFileInclusion",
    "CWE-95": "EvalInjection", "CWE-77": "CommandInjection", "CWE-116": "ImproperEncoding",
}

# Semgrep 语言目录 → 我们的语言 key
DEFAULT_LANGS = ["php", "ruby", "swift", "bash"]
SEMGREP_LANG_DIR = {"php": "php", "ruby": "ruby", "swift": "swift",
                    "bash": "bash", "shell": "bash"}

# 从 `pattern: name(...)` / `name.method(...)` 抽函数/方法名
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# 明显非 sink 的元变量/占位符
_JUNK = re.compile(r"^\$|^\.\.\.$|^_+$")


def _cwe_of(meta: dict) -> str | None:
    """从 metadata.cwe 取首个白名单内的 CWE 编号。"""
    cwes = meta.get("cwe")
    if isinstance(cwes, str):
        cwes = [cwes]
    if not isinstance(cwes, list):
        return None
    for c in cwes:
        m = re.search(r"CWE-\d+", str(c))
        if m and m.group(0) in CWE_WHITELIST:
            return m.group(0)
    return None


def _walk_patterns(node, out: list[str]):
    """递归遍历 pattern-sinks 子树, 收集所有 pattern / metavariable-regex / pattern-inside 字符串。

    v2.1 (REQ-27): 支持 taint-mode 规则 —— 官方 LFI 类规则 (如 php lang/security/file-inclusion.yaml)
    的 sink 形如:
        pattern-inside: $FUNC(...);
        pattern: $VAR
        metavariable-regex:
          metavariable: $FUNC
          regex: \b(include|include_once|require|require_once)\b
    旧实现只收集 `pattern:` 且仅取首行调用名, 无法提取这类 sink。此处统一收集
    pattern / pattern-inside 的调用表达式 与 metavariable-regex 的 regex 值。"""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                out.append(v)
            elif k == "pattern-inside" and isinstance(v, str):
                out.append(v)
            elif k == "metavariable-regex" and isinstance(v, dict):
                rx = v.get("regex")
                if isinstance(rx, str):
                    out.append("METAVARREGEX:" + rx)
            elif k in ("pattern-either", "patterns", "pattern-sinks", "pattern-where-python"):
                _walk_patterns(v, out)
            elif isinstance(v, (dict, list)):
                _walk_patterns(v, out)
    elif isinstance(node, list):
        for x in node:
            _walk_patterns(x, out)


# metavariable-regex 值中的函数名分组, 如 \b(include|include_once|require|require_once)\b
_METAVAR_GROUP_RE = re.compile(r"\((?:[^()|]+\|)*([A-Za-z_][A-Za-z0-9_]*(?:\|[A-Za-z_][A-Za-z0-9_]*)+)\)")


def _names_from_patterns(patterns: list[str]) -> list[str]:
    names = []
    for p in patterns:
        if p.startswith("METAVARREGEX:"):
            # 提取 \b(include|include_once|require|require_once)\b 中的函数名列表
            rx = p[len("METAVARREGEX:"):]
            for m in _METAVAR_GROUP_RE.finditer(rx):
                group = m.group(1)
                for name in group.split("|"):
                    name = name.strip()
                    if name and not _JUNK.search(name) and not name.isupper():
                        names.append(name)
            continue
        # 只取第一行的调用 (多行结构模式如字符串插值不可靠)
        first = p.strip().splitlines()[0] if p.strip() else ""
        for m in _CALL_RE.finditer(first):
            name = m.group(1)
            if _JUNK.search(name) or len(name) <= 1:
                continue
            # 过滤 semgrep 关键字与常见控制流
            if name in ("if", "for", "while", "return", "and", "or", "not"):
                continue
            # 过滤 semgrep 元变量占位符 (全大写, 如 METHOD/EXPR/FUNC/SQLSTR)
            if name.isupper():
                continue
            names.append(name)
    return names


def extract_lang(semgrep_root: Path, lang: str) -> dict[str, set]:
    """返回 {cwe_id: set(names)}。"""
    subdir = SEMGREP_LANG_DIR.get(lang, lang)
    root = semgrep_root / subdir
    result: dict[str, set] = {}
    if not root.is_dir():
        print(f"[!] {lang}: semgrep 目录 {subdir}/ 不存在", file=sys.stderr)
        return result
    for f in glob.glob(str(root / "**" / "*.yaml"), recursive=True) + \
             glob.glob(str(root / "**" / "*.yml"), recursive=True):
        try:
            doc = yaml.safe_load(Path(f).read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        for rule in doc.get("rules", []) or []:
            if not isinstance(rule, dict):
                continue
            meta = rule.get("metadata", {}) or {}
            if meta.get("category") not in ("security", None):
                continue
            cwe = _cwe_of(meta)
            if not cwe:
                continue
            sinks_node = rule.get("pattern-sinks")
            if not sinks_node:
                continue
            pats: list[str] = []
            _walk_patterns(sinks_node, pats)
            names = _names_from_patterns(pats)
            if names:
                result.setdefault(cwe, set()).update(names)
    return result


def build_entry(cwe_id: str, names: list[str]) -> dict:
    regex_list = [re.escape(n) + r"\s*\(" for n in names]
    # v2.1: ast_patterns 也生成, 供 tree-sitter 扫描 (PHP include_expression 等特殊处理由规则库治理)
    return {
        "cwe_id": cwe_id,
        "category": CWE_WHITELIST.get(cwe_id, cwe_id),
        "type": "TAINT_ANALYSIS",
        "codeql_model": "semgrep-registry",
        "provenance": "semgrep",
        "sink_count": len(names),
        "sinks": {"regex": regex_list, "ast_patterns": []},
        "sources": {"regex": []},
    }


def _merge_entries(existing: list[dict], extracted: dict[str, list[str]]) -> list[dict]:
    """增量合并 (REQ-27): 以 cwe_id 为单位取并集, 保留既有规则(含人工清洗的
    regex / ast_patterns / manual 字段)。禁止覆盖式替换。"""
    by_cwe: dict[str, dict] = {}
    for e in existing:
        by_cwe[e.get("cwe_id")] = dict(e)
    for cwe_id, names in extracted.items():
        new_names = sorted(set(names))
        if not new_names:
            continue
        if cwe_id in by_cwe:
            base = by_cwe[cwe_id]
            old_regex = base.get("sinks", {}).get("regex", [])
            old_ast = base.get("sinks", {}).get("ast_patterns", [])
            # 从新 regex 中剔除已存在的, 仅追加增量
            old_escaped = set(old_regex)
            added = [re.escape(n) + r"\s*\(" for n in new_names]
            extra = [r for r in added if r not in old_escaped]
            base.setdefault("sinks", {})["regex"] = old_regex + extra
            base["sink_count"] = len(base["sinks"]["regex"]) + len(base["sinks"].get("ast_patterns", []))
        else:
            by_cwe[cwe_id] = build_entry(cwe_id, new_names)
    # 保持稳定顺序: 既有条目在前, 新增在后
    ordered = [e for c, e in by_cwe.items() if e.get("provenance") != "semgrep-new" or True]
    return list(by_cwe.values())


def extract_all(semgrep_root: Path, langs: list[str]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for lang in langs:
        by_cwe = extract_lang(semgrep_root, lang)
        entries = []
        for cwe_id, names in sorted(by_cwe.items()):
            e = build_entry(cwe_id, sorted(names))
            entries.append(e)
            print(f"  [{lang}] {cwe_id:8s} {CWE_WHITELIST.get(cwe_id, ''):20s} "
                  f"{len(names):3d} sinks", file=sys.stderr)
        out[lang] = entries
    return out


def reconcile(prof_rules: dict, extracted: dict[str, list[str]]) -> dict:
    """对账 (REQ-27): 输出 [官方有, skill 无] / [skill 有, 官方无] 差异清单。"""
    diff = {"official_only": {}, "skill_only": {}}
    for lang, by_cwe in extracted.items():
        skill_cwes = {e.get("cwe_id") for e in prof_rules.get(lang, [])}
        official_cwes = set(by_cwe)  # by_cwe 已是 cwe set
        miss = official_cwes - skill_cwes
        extra = skill_cwes - official_cwes
        if miss:
            diff["official_only"][lang] = sorted(miss)
        if extra:
            diff["skill_only"][lang] = sorted(extra)
    return diff


def main() -> int:
    ap = argparse.ArgumentParser(description="Semgrep -> security_profiles.json sink extractor")
    here = Path(__file__).resolve().parent
    ap.add_argument("--semgrep-path", required=True, help="本地 semgrep-rules 仓库路径")
    ap.add_argument("--output", "-o",
                    default=str(here.parent / "resources" / "security_profiles.json"))
    ap.add_argument("--langs", default=",".join(DEFAULT_LANGS),
                    help="逗号分隔的语言列表, 默认 php,ruby,swift,bash")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--reconcile", action="store_true",
                    help="只输出 [官方有, skill 无] / [skill 有, 官方无] 对账差异, 不写回 profile")
    args = ap.parse_args()

    if not HAS_YAML:
        print("[!] 需要 PyYAML: pip install pyyaml", file=sys.stderr)
        return 2

    root = Path(args.semgrep_path)
    if not root.is_dir():
        print(f"[!] semgrep-path 不存在: {root}", file=sys.stderr)
        return 2

    try:
        rev = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"],
                                      text=True).strip()
    except Exception:
        rev = "unknown"
    print(f"[+] semgrep-rules revision: {rev}", file=sys.stderr)

    langs = [l.strip() for l in args.langs.split(",") if l.strip()]
    extracted = extract_all(root, langs)

    if args.dry_run:
        print(json.dumps(extracted, indent=2, ensure_ascii=False))
        return 0

    prof = json.loads(Path(args.output).read_text(encoding="utf-8"))
    prof.setdefault("rules", {})

    if args.reconcile:
        diff = reconcile(prof["rules"], {l: {e["cwe_id"] for e in es} for l, es in extracted.items()})
        print("[RECONCILE] 官方有、skill 无 (规则盲区, 需补):")
        for lang, cwes in diff["official_only"].items():
            print(f"  {lang}: {cwes}")
        print("[RECONCILE] skill 有、官方无 (可能为手工补丁/误标, 需核):")
        for lang, cwes in diff["skill_only"].items():
            print(f"  {lang}: {cwes}")
        return 0

    # v2.1 (REQ-27): 增量合并 — 以 cwe_id 为并集保留既有规则与 manual_additions,
    # 不再覆盖式替换
    prof["semgrep_revision"] = rev
    for lang, entries in extracted.items():
        if not entries:
            continue
        existing = prof["rules"].get(lang, [])
        prof["rules"][lang] = _merge_entries_by_names(existing, entries)
    Path(args.output).write_text(
        json.dumps(prof, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[+] Wrote {args.output} (增量合并)", file=sys.stderr)
    return 0


def _merge_entries_by_names(existing: list[dict], new_entries: list[dict]) -> list[dict]:
    """按 cwe_id 并集合并 sink names, 保留既有条目全部字段 (增量合并, REQ-27)。"""
    _SUFFIX = r"\s*\("  # 与 build_entry 的 re.escape(n) + r"\s*\(" 对应
    def _names_of(rx_list):
        out = set()
        for rx in rx_list:
            if rx.endswith(_SUFFIX):
                out.add(rx[:-len(_SUFFIX)])
        return out

    by_cwe: dict[str, dict] = {}
    for e in existing:
        by_cwe[e.get("cwe_id")] = dict(e)
    for ne in new_entries:
        cwe = ne.get("cwe_id")
        if not cwe:
            continue
        names = _names_of(ne.get("sinks", {}).get("regex", []))
        if not names:
            continue
        if cwe in by_cwe:
            base = by_cwe[cwe]
            old_names = _names_of(base.get("sinks", {}).get("regex", []))
            added = sorted(names - old_names)
            if added:
                base.setdefault("sinks", {}).setdefault("regex", []).extend(
                    re.escape(n) + r"\s*\(" for n in added)
                base["sink_count"] = len(base["sinks"].get("regex", [])) + len(base["sinks"].get("ast_patterns", []))
        else:
            by_cwe[cwe] = ne
    return list(by_cwe.values())


if __name__ == "__main__":
    sys.exit(main())
