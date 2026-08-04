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
    """递归遍历 pattern-sinks 子树, 收集所有 pattern 字符串。"""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                out.append(v)
            elif k in ("pattern-either", "patterns", "pattern-sinks"):
                _walk_patterns(v, out)
            elif isinstance(v, (dict, list)):
                _walk_patterns(v, out)
    elif isinstance(node, list):
        for x in node:
            _walk_patterns(x, out)


def _names_from_patterns(patterns: list[str]) -> list[str]:
    names = []
    for p in patterns:
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


def main() -> int:
    ap = argparse.ArgumentParser(description="Semgrep -> security_profiles.json sink extractor")
    here = Path(__file__).resolve().parent
    ap.add_argument("--semgrep-path", required=True, help="本地 semgrep-rules 仓库路径")
    ap.add_argument("--output", "-o",
                    default=str(here.parent / "resources" / "security_profiles.json"))
    ap.add_argument("--langs", default=",".join(DEFAULT_LANGS),
                    help="逗号分隔的语言列表, 默认 php,ruby,swift,bash")
    ap.add_argument("--dry-run", action="store_true")
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

    # 写回: 只更新指定语言的 rules 段, 标注 semgrep_revision
    prof = json.loads(Path(args.output).read_text(encoding="utf-8"))
    prof.setdefault("rules", {})
    prof["semgrep_revision"] = rev
    for lang, entries in extracted.items():
        if entries:
            prof["rules"][lang] = entries
            # 从 manual_additions 移除已被 semgrep 覆盖的条目(避免重复)
    Path(args.output).write_text(
        json.dumps(prof, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[+] Wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
