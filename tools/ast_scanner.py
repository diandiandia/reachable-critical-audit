import os
import re
import json
import sys
import warnings

# Tree-sitter 兼容层: 同时支持旧版 tree_sitter_languages 和新版独立语言包 (v0.26+)
HAS_TREE_SITTER = False
TS_QUERY_OLD_API = False  # True=tree_sitter_languages, False=独立包 v0.26+
TS_GET_LANG = None
TS_GET_PARSER = None
TS_QUERY_CLS = None
TS_CURSOR_CLS = None

# 语言 → tree-sitter 独立包名称映射
_TS_PACKAGES = {
    "java": "tree_sitter_java",
    "cpp": "tree_sitter_cpp",
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "go": "tree_sitter_go",
    "rust": "tree_sitter_rust",
    "csharp": "tree_sitter_c_sharp",
    "php": "tree_sitter_php",
    "ruby": "tree_sitter_ruby",
    "swift": "tree_sitter_swift",
    "kotlin": "tree_sitter_kotlin",
    "scala": "tree_sitter_scala",
    "shell": "tree_sitter_bash",
    "perl": "tree_sitter_perl",
    "powershell": None,
}

try:
    import tree_sitter_languages
    HAS_TREE_SITTER = True
    TS_QUERY_OLD_API = True
    TS_GET_LANG = tree_sitter_languages.get_language
    TS_GET_PARSER = tree_sitter_languages.get_parser
except ImportError:
    try:
        import tree_sitter
        HAS_TREE_SITTER = True
        TS_QUERY_OLD_API = False
        from tree_sitter import Language, Parser, Query, QueryCursor as QC
        # tree-sitter 0.26 的 Language(PyCapsule) 会触发 DeprecationWarning，无害，抑制之
        warnings.filterwarnings("ignore", message="int argument support is deprecated", category=DeprecationWarning)
        TS_QUERY_CLS = Query
        TS_CURSOR_CLS = QC

        _TS_LANG_CACHE = {}
        for _ts_lang, _ts_mod_name in _TS_PACKAGES.items():
            if _ts_mod_name is None:
                continue
            try:
                _ts_mod = __import__(_ts_mod_name, fromlist=["language"])
                _ts_lang_func = None
                for _attr in ("language", f"language_{_ts_lang}", "lang"):
                    if hasattr(_ts_mod, _attr):
                        _ts_lang_func = getattr(_ts_mod, _attr)
                        break
                if _ts_lang_func is None:
                    continue
                _TS_LANG_CACHE[_ts_lang] = Language(_ts_lang_func())
            except ImportError:
                pass

        def TS_GET_LANG(lang):
            lang_obj = _TS_LANG_CACHE.get(lang)
            if lang_obj is None:
                raise ImportError(f"No tree-sitter grammar for '{lang}'")
            return lang_obj

        def TS_GET_PARSER(lang):
            p = Parser()
            p.language = TS_GET_LANG(lang)
            return p
    except ImportError:
        pass

# 统一执行 tree-sitter 查询: 返回 [(node, tag_name), ...]
def _ts_run_query(lang_obj, query_str, root_node):
    if TS_QUERY_OLD_API:
        query = lang_obj.query(query_str)
        return list(query.captures(root_node))
    # New API (v0.26+)
    query = TS_QUERY_CLS(lang_obj, query_str)
    cursor = TS_CURSOR_CLS(query)
    results = []
    for pattern_idx, capture_dict in cursor.matches(root_node):
        for tag, nodes in capture_dict.items():
            for node in nodes:
                results.append((node, tag))
    return results

class ASTCoarseScanner:
    EXTENSION_MAP = {
        ".java": "java",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".c": "cpp",
        ".h": "cpp",
        ".hpp": "cpp",
        ".hxx": "cpp",
        ".c++": "cpp",
        ".h++": "cpp",
        ".py": "python",
        ".pyw": "python",
        ".go": "go",
        ".rs": "rust",
        ".js": "javascript",
        ".ts": "javascript",
        ".jsx": "javascript",
        ".tsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".cs": "csharp",
        ".csx": "csharp",
        ".php": "php",
        ".phtml": "php",
        ".php3": "php",
        ".php4": "php",
        ".php5": "php",
        ".phps": "php",
        ".rb": "ruby",
        ".rbw": "ruby",
        ".rake": "ruby",
        ".swift": "swift",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".scala": "scala",
        ".sh": "shell",
        ".bash": "shell",
        ".zsh": "shell",
        ".pl": "perl",
        ".pm": "perl",
        ".t": "perl",
        ".ps1": "powershell"
    }

    def __init__(self, profile_path):
        with open(profile_path, 'r', encoding='utf-8') as f:
            self.profile = json.load(f)

    def scan(self, workspace_path):
        candidates = []
        rules = self.profile.get("rules", {})
        lang_hits = {}
        total_source_files = 0
        unknown_extensions = {}

        # PROPERTY_CHECK 模式 (REQ-05) — 独立于语言识别, 对所有文件运行
        # (exported_no_permission 的锚点是 AndroidManifest.xml, 不在 EXTENSION_MAP 内)
        prop_patterns_raw = self.profile.get("property_check_patterns", [])
        prop_patterns = prop_patterns_raw.get("patterns", []) if isinstance(prop_patterns_raw, dict) else prop_patterns_raw

        for root, _, files in os.walk(workspace_path):
            if any(ignored in root for ignored in ["node_modules", ".git", "scratch", "target", "build"]):
                continue

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                lang = self.EXTENSION_MAP.get(ext)
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, workspace_path)

                # R1.5 强制触发条件: 统计源文件数（所有非 .min. 文件）
                if ".min." not in file:
                    total_source_files += 1

                # L2 fallback 检测: 记录未能映射到预设语言的扩展名
                if not lang:
                    unknown_extensions[ext] = unknown_extensions.get(ext, 0) + 1

                # 读取文件内容 (源码规则 + property-check 共用)
                content = None
                if (lang and lang in rules) or prop_patterns:
                    try:
                        with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f_code:
                            content = f_code.read()
                    except Exception:
                        content = None

                # ---- 源码语言规则扫描 (仅预设语言) ----
                if content is not None and lang and lang in rules:
                    if lang not in lang_hits:
                        lang_hits[lang] = 0
                    lang_rules = rules[lang]

                    # 收集 sinks 下的规则
                    ast_queries = []
                    regex_patterns = []
                    for item in lang_rules:
                        sinks = item.get("sinks", {})
                        if "ast_patterns" in sinks:
                            ast_queries.extend(sinks["ast_patterns"])
                        if "regex" in sinks:
                            regex_patterns.extend(sinks["regex"])

                    ast_success = False
                    # 1. 尝试使用 Tree-Sitter 语法解析
                    if HAS_TREE_SITTER and ast_queries:
                        try:
                            ast_candidates = self._scan_via_tree_sitter(content, lang, ast_queries, rel_path, rules[lang])
                            candidates.extend(ast_candidates)
                            ast_success = True
                        except Exception as e:
                            # 语法解析报错，打印日志并降级到正则
                            sys.stderr.write(f"[Warning] AST scan failed for {rel_path}: {str(e)}. Falling back to regex...\n")

                    # 2. 降级逻辑：如缺少环境或解析失败，退化为正则检索
                    if not ast_success and regex_patterns:
                        line_candidates = self._scan_via_regex(content, regex_patterns, rel_path, lang, rules[lang])
                        candidates.extend(line_candidates)

                # ---- PROPERTY_CHECK 扫描 (所有文件, 语言无关) ----
                if content is not None and prop_patterns:
                    prop_candidates = self._scan_property_checks(content, prop_patterns, rel_path, lang)
                    candidates.extend(prop_candidates)

        # 编号并规范化 Schema 输出 (REQ-02, REQ-09)
        for idx, cand in enumerate(candidates, 1):
            cand["id"] = f"CAND-{idx:03d}"
            cand["origin"] = cand.get("origin", "L0")
            cand["source_file"] = cand.get("file_path", "")
            cand["source_line"] = cand.get("line_number", 0)
            cand["sink_type"] = cand.get("cwe_id", "Unknown")
            if "status" not in cand or not cand["status"]:
                cand["status"] = "PENDING"
            cand["verdict"] = None
            cand["reachability_type"] = None
            cand["blocking_point"] = None
            # 统计语言命中数
            lang = cand.get("language", "")
            if lang:
                lang_hits[lang] = lang_hits.get(lang, 0) + 1

        # 过滤 test/build/third-party 候选 + 按 CWE 标记优先级 (语言无关)
        filtered, discarded = self._filter_and_prioritize(candidates)

        # 按优先级统计
        priority_dist = {}
        for c in filtered:
            p = c.get("priority", 2)
            priority_dist[p] = priority_dist.get(p, 0) + 1

        # L2 fallback: 非预设语言扩展
        l2_exts = [
            {"ext": ext, "count": cnt}
            for ext, cnt in sorted(unknown_extensions.items(), key=lambda x: -x[1])
        ]
        l2_required = (
            len(filtered) == 0 and len(l2_exts) > 0 and total_source_files > 0
        )

        # 主体语言统计
        lang_file_counts = {}
        for root, _, files in os.walk(workspace_path):
            if any(ignored in root for ignored in ["node_modules", ".git", "scratch", "target", "build"]):
                continue
            for file in files:
                if ".min." in file:
                    continue
                ext = os.path.splitext(file)[1].lower()
                lang = self.EXTENSION_MAP.get(ext)
                if lang:
                    lang_file_counts[lang] = lang_file_counts.get(lang, 0) + 1

        scan_meta = {
            "total_source_files": total_source_files,
            "raw_candidates": len(candidates),
            "discarded_test_build": discarded,
            "candidates_after_filter": len(filtered),
            "priority_distribution": priority_dist,
            "r1_5_required": True,  # R1.5 始终执行
            "l2_required": l2_required,
            "l2_exts": l2_exts,
            "l2_note": (
                f"项目含 {len(l2_exts)} 种非预设语言扩展名 "
                f"({', '.join(e['ext'] for e in l2_exts[:5])})"
                if l2_required else None
            )
        }
        return filtered, scan_meta

    def _scan_property_checks(self, content, prop_patterns, file_path, lang):
        """PROPERTY_CHECK 锚点扫描 (REQ-05)。

        property_check_patterns 的 `detect` 字段是**自然语言语义描述**(如
        "方法体内未出现 owner 比对")，无法作为逐行正则匹配——缺失型判定必须
        交给 R3 子智能体研判。scanner 在此只负责用各 pattern 的**可机器匹配
        字段**定位可疑锚点行，并把语义描述带入 `verification_logic`：
          - anchor_regex: 直接作为正则匹配 (如 exported=true)
          - anchor_hints.<lang>: 语言相关关键字, 转义后子串匹配
          - sinks: 函数/前缀名列表, 转义后作为调用点匹配 (如 setuid()
                   privilege_boundary_skip); 以 `_` 结尾视为前缀 (capng_*)
          - files: 仅当当前文件名匹配时才生效 (如 AndroidManifest.xml)
        """
        candidates = []
        lines = content.splitlines()
        base_name = os.path.basename(file_path)

        for prop in prop_patterns:
            pid = prop.get("id", "PROPERTY_CHECK")
            cwe_id = prop.get("cwe_id", "CWE-862")

            # files 约束: pattern 限定文件名时, 不匹配则整体跳过
            file_globs = prop.get("files", [])
            if file_globs:
                import fnmatch
                if not any(fnmatch.fnmatch(base_name, g) for g in file_globs):
                    continue

            # 组装该 pattern 在当前语言下的匹配器: (compiled_regex, raw)
            matchers = []
            for rx_pat in prop.get("anchor_regex", []):
                try:
                    matchers.append((re.compile(rx_pat), rx_pat))
                except re.error:
                    pass
            hints = prop.get("anchor_hints", {}).get(lang, [])
            for h in hints:
                matchers.append((re.compile(re.escape(h)), h))
            for s in prop.get("sinks", []):
                # `capng_` 这类前缀 → 匹配 前缀+标识符+( ; 普通名 → 名+(
                if s.endswith("_"):
                    matchers.append((re.compile(re.escape(s) + r"\w*\s*\("), s))
                else:
                    matchers.append((re.compile(r"\b" + re.escape(s) + r"\s*\("), s))

            if not matchers:
                continue

            verification_logic = prop.get("verification_logic", prop.get("detect", ""))

            for idx, line in enumerate(lines):
                for rx, raw in matchers:
                    try:
                        if rx.search(line):
                            sink_content = line.strip()
                            if len(sink_content) > 1000:
                                sink_content = sink_content[:1000] + "... [TRUNCATED]"
                            candidates.append({
                                "language": lang,
                                "cwe_id": cwe_id,
                                "category": pid,
                                "type": "PROPERTY_CHECK",
                                "file_path": file_path,
                                "line_number": idx + 1,
                                "sink_content": sink_content,
                                "matched_hint": raw,
                                "origin": "L0",
                                "status": "PENDING",
                                "sources_regex": [],
                                "reachability_constraints": prop.get("detect", ""),
                                "verification_logic": verification_logic
                            })
                            break
                    except Exception:
                        pass
        return candidates

    def _scan_via_tree_sitter(self, content, lang, ast_queries, file_path, lang_rules):
        lang_obj = TS_GET_LANG(lang)
        parser = TS_GET_PARSER(lang)
        
        tree = parser.parse(bytes(content, "utf8"))
        root_node = tree.root_node
        candidates = []
        lines = content.splitlines()

        for query_str in ast_queries:
            captures = _ts_run_query(lang_obj, query_str, root_node)
            for node, tag in captures:
                line_no = node.start_point[0] + 1
                line_content = lines[line_no - 1] if line_no <= len(lines) else ""
                
                # 匹配该 S-expression 属于哪一个 CWE
                matched_rule = self._find_rule_by_ast(lang_rules, query_str)
                cwe_id = matched_rule.get("cwe_id")

                # Rust unsafe 安全注释豁免 (REQ-22)
                is_rust_unsafe = (lang == "rust" and cwe_id in ("CWE-119", "CWE-416", "CWE-787"))
                if is_rust_unsafe:
                    start = max(0, line_no - 9)
                    end = min(len(lines), line_no + 2)
                    rust_exempted = False
                    for ctx_line in lines[start:end]:
                        stripped = ctx_line.strip()
                        if stripped.startswith("// Safety:") or stripped.startswith("# Safety:") or \
                           stripped.startswith("// SAFETY:") or stripped.startswith("// safety:") or \
                           stripped.startswith("/* Safety:") or stripped.startswith("/* SAFETY:"):
                            rust_exempted = True
                            break
                    if rust_exempted:
                        continue

                # Optimization 1: 初筛漏斗过滤优化
                if cwe_id == "CWE-476" and lang == "cpp":
                    try:
                        ptr_name = node.text.decode('utf-8', errors='ignore').lstrip('*').strip()
                        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_\->\.]*$', ptr_name):
                            checked = False
                            for pre_line in lines[max(0, line_no - 6):line_no - 1]:
                                if re.search(r'\b' + re.escape(ptr_name) + r'\b', pre_line):
                                    if 'NULL' in pre_line or '== 0' in pre_line or '!= 0' in pre_line or '!' in pre_line or 'if' in pre_line:
                                        checked = True
                                        break
                            if checked:
                                continue
                    except Exception:
                        pass
                
                sink_content = line_content.strip()
                if len(sink_content) > 1000:
                    sink_content = sink_content[:1000] + "... [TRUNCATED]"

                candidates.append({
                    "language": lang,
                    "cwe_id": matched_rule["cwe_id"],
                    "category": matched_rule["category"],
                    "type": matched_rule.get("type", "TAINT_ANALYSIS"),
                    "file_path": file_path,
                    "line_number": line_no,
                    "sink_content": sink_content,
                    "origin": "L0",
                    "status": "PENDING",
                    "sources_regex": matched_rule.get("sources", {}).get("regex", []),
                    "reachability_constraints": matched_rule.get("reachability_constraints", ""),
                    "verification_logic": matched_rule.get("verification_logic", "")
                })
        return candidates

    def _scan_via_regex(self, content, regex_patterns, file_path, lang, lang_rules):
        candidates = []
        lines = content.splitlines()
        compiled = [(re.compile(pat), pat) for pat in regex_patterns]

        for line_idx, line in enumerate(lines):
            for rx, raw_pat in compiled:
                if rx.search(line):
                    matched_rule = self._find_rule_by_regex(lang_rules, raw_pat)
                    cwe_id = matched_rule.get("cwe_id")

                    # Optimization 1: Rust unsafe 安全注释豁免
                    # 如果 unsafe 调用行附近有 Safety 注释，标记为 NEEDS_REVIEW 而非 PENDING
                    is_rust_unsafe = (lang == "rust" and cwe_id in ("CWE-119", "CWE-416", "CWE-787"))
                    rust_exempted = False
                    if is_rust_unsafe:
                        start = max(0, line_idx - 8)
                        end = min(len(lines), line_idx + 3)
                        for ctx_line in lines[start:end]:
                            stripped = ctx_line.strip()
                            if stripped.startswith("// Safety:") or stripped.startswith("# Safety:") or \
                               stripped.startswith("// SAFETY:") or stripped.startswith("// safety:") or \
                               stripped.startswith("/* Safety:") or stripped.startswith("/* SAFETY:"):
                                rust_exempted = True
                                break
                    
                    # Optimization 2: 初筛漏斗过滤优化
                    if cwe_id == "CWE-476" and lang == "cpp":
                        try:
                            match_ptr = re.search(r'\*([a-zA-Z_][a-zA-Z0-9_\->\.]*)', line)
                            if match_ptr:
                                ptr_name = match_ptr.group(1).strip()
                                checked = False
                                for pre_line in lines[max(0, line_idx - 5):line_idx]:
                                    if re.search(r'\b' + re.escape(ptr_name) + r'\b', pre_line):
                                        if 'NULL' in pre_line or '== 0' in pre_line or '!= 0' in pre_line or '!' in pre_line or 'if' in pre_line:
                                            checked = True
                                            break
                                if checked:
                                    continue
                        except Exception:
                            pass

                    sink_content = line.strip()
                    if len(sink_content) > 1000:
                        sink_content = sink_content[:1000] + "... [TRUNCATED]"

                    # REQ-03: 正则降级扫描产生的候选点标记 ast_verified=False，若无 AST 精确校验支撑则降级为 NEEDS_REVIEW 初始候选
                    status = "NEEDS_REVIEW" if (HAS_TREE_SITTER and matched_rule.get("sinks", {}).get("ast_patterns")) else "PENDING"
                    # Rust unsafe 调用有 safety 注释时降级为 NEEDS_REVIEW（需人工复核）
                    if rust_exempted and status == "PENDING":
                        status = "NEEDS_REVIEW"

                    candidates.append({
                        "language": lang,
                        "cwe_id": matched_rule["cwe_id"],
                        "category": matched_rule["category"],
                        "type": matched_rule.get("type", "TAINT_ANALYSIS"),
                        "file_path": file_path,
                        "line_number": line_idx + 1,
                        "sink_content": sink_content,
                        "origin": "L0",
                        "status": status,
                        "sources_regex": matched_rule.get("sources", {}).get("regex", []),
                        "reachability_constraints": matched_rule.get("reachability_constraints", ""),
                        "verification_logic": matched_rule.get("verification_logic", "")
                    })
                    break
        return candidates

    # ---- 语言无关优先级与过滤 ----

    _CWE_PRIORITY = {
        "CWE-78": 0, "CWE-89": 0, "CWE-94": 0, "CWE-119": 0, "CWE-416": 0,
        "CWE-502": 0, "CWE-787": 0, "CWE-918": 0, "CWE-789": 0,
        "CWE-20": 1, "CWE-22": 1, "CWE-125": 1, "CWE-190": 1, "CWE-269": 1,
        "CWE-285": 1, "CWE-287": 1, "CWE-611": 1, "CWE-862": 1,
        "CWE-79": 2, "CWE-134": 2, "CWE-200": 2, "CWE-250": 2, "CWE-352": 2,
        "CWE-362": 2, "CWE-400": 2, "CWE-434": 2, "CWE-476": 2, "CWE-601": 2, "CWE-908": 2,
    }
    _IGNORE_PATH_PARTS = {
        "test", "tests", "mock", "mocks", "unittest", "mockcify",
        "tools", "tool", "build", "scripts",
        "node_modules", "vendor", "third_party", "libs",
    }

    @classmethod
    def _is_ignored_path(cls, rel_path):
        parts = rel_path.replace("\\", "/").split("/")
        for part in parts:
            if part in cls._IGNORE_PATH_PARTS:
                return True
            if part.endswith("Test") or part.startswith("Test"):
                return True
        return False

    @classmethod
    def _priority_for_cwe(cls, cwe_id):
        return cls._CWE_PRIORITY.get(cwe_id, 2)

    def _filter_and_prioritize(self, candidates):
        filtered = []
        discarded = 0
        for cand in candidates:
            fp = cand.get("file_path", "")
            if self._is_ignored_path(fp):
                discarded += 1
                continue
            cand["priority"] = self._priority_for_cwe(cand.get("cwe_id", ""))
            filtered.append(cand)
        return filtered, discarded

    def _find_rule_by_ast(self, lang_rules, ast_pattern):
        for rule in lang_rules:
            if ast_pattern in rule.get("sinks", {}).get("ast_patterns", []):
                return rule
        return {"cwe_id": "Unknown", "category": "General Sink"}

    def _find_rule_by_regex(self, lang_rules, regex_pattern):
        for rule in lang_rules:
            if regex_pattern in rule.get("sinks", {}).get("regex", []):
                return rule
        return {"cwe_id": "Unknown", "category": "General Sink"}

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    profile_path = os.path.join(script_dir, "../resources/security_profiles.json")

    # REQ-03: R0 AST 物理工具强制 self-check 支持
    if len(sys.argv) > 1 and sys.argv[1] == "--self-check":
        profile_ok = os.path.exists(profile_path)
        profile_langs = []
        wrapper_langs = []
        total_rules_count = 0
        empty_ast_count = 0
        langs_with_gaps = {}
        if profile_ok:
            try:
                with open(profile_path, 'r', encoding='utf-8') as pf:
                    pdata = json.load(pf)
                profile_langs = list(pdata.get("rules", {}).keys())
                wrapper_langs = list(pdata.get("wrapper_detection", {}).keys())
                for lang_name, r_list in pdata.get("rules", {}).items():
                    total_rules_count += len(r_list)
                    for r in r_list:
                        if not r.get("sinks", {}).get("ast_patterns"):
                            empty_ast_count += 1
                            langs_with_gaps[lang_name] = langs_with_gaps.get(lang_name, 0) + 1
            except Exception:
                profile_ok = False

        grammars_available = []
        if HAS_TREE_SITTER:
            if TS_QUERY_OLD_API:
                for lang in profile_langs:
                    try:
                        TS_GET_LANG(lang)
                        grammars_available.append(lang)
                    except Exception:
                        pass
            else:
                grammars_available = list(_TS_LANG_CACHE.keys())

        # REQ-03: AST 覆盖率门槛 (真实值; 覆盖率不足不阻断启动, 但如实告警)
        AST_COVERAGE_THRESHOLD = 95.0
        coverage_pct = round((1 - empty_ast_count / total_rules_count) * 100, 1) if total_rules_count else 0
        res = {
            "status": "ok" if HAS_TREE_SITTER else "FAIL: tree-sitter not available",
            "has_tree_sitter": HAS_TREE_SITTER,
            "tree_sitter_api": "tree_sitter_languages" if TS_QUERY_OLD_API else "individual_packages_v0.26",
            "grammars_available": grammars_available,
            "profile_loaded": profile_ok,
            "configured_languages": profile_langs,
            "wrapper_detection_languages": [l for l in wrapper_langs if not l.startswith("_")],
            "total_rules": total_rules_count,
            "ast_patterns_coverage_pct": coverage_pct,
            "ast_coverage_threshold_pct": AST_COVERAGE_THRESHOLD,
            "ast_coverage_ok": coverage_pct >= AST_COVERAGE_THRESHOLD,
            "rules_missing_ast_patterns": empty_ast_count,
            "ast_gap_by_language": langs_with_gaps
        }
        if not res["ast_coverage_ok"]:
            res["warning"] = (
                f"AST S-expression 覆盖率 {coverage_pct}% 低于阈值 {AST_COVERAGE_THRESHOLD}%; "
                f"{empty_ast_count} 条规则仅有正则 (命中将降级为 NEEDS_REVIEW): {langs_with_gaps}"
            )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        sys.exit(0 if (profile_ok and HAS_TREE_SITTER) else 1)

    workspace = sys.argv[1] if len(sys.argv) > 1 else "."
    # REQ-12 目录守卫: 缺省输出到 <workspace>/.audit_results/ (batch_verify.py 硬编码
    # 从该路径读取)。绝不落盘到项目源码根目录。允许 argv[2] 覆盖, 但会规范到
    # .audit_results/ 子目录以保持契约一致。
    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
        if os.path.basename(os.path.normpath(output_dir)) != ".audit_results":
            output_dir = os.path.join(output_dir, ".audit_results")
    else:
        output_dir = os.path.join(workspace, ".audit_results")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    profile = os.path.join(script_dir, "../resources/security_profiles.json")
    
    scanner = ASTCoarseScanner(profile)
    results, scan_meta = scanner.scan(workspace)
    
    # 写入待验证队列
    os.makedirs(output_dir, exist_ok=True)
    queue_path = os.path.join(output_dir, "verify_queue.json")
    with open(queue_path, 'w', encoding='utf-8') as f:
        json.dump({"schema_version": "2.0", "candidates": results}, f, indent=2, ensure_ascii=False)
    
    print(f"SUCCESS: AST/Regex Scan complete. Found {len(results)} Candidates. Written to {queue_path}")
    print(json.dumps({"SCAN_META": scan_meta}, indent=2, ensure_ascii=False))
