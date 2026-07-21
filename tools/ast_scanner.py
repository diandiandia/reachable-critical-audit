import os
import re
import json
import sys

# 尝试导入 tree_sitter 及其依赖
HAS_TREE_SITTER = False
try:
    import tree_sitter
    import tree_sitter_languages
    HAS_TREE_SITTER = True
except ImportError:
    pass

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

        for root, _, files in os.walk(workspace_path):
            if any(ignored in root for ignored in ["node_modules", ".git", "scratch", "target", "build"]):
                continue
            
            for file in files:
                if ".min." in file:
                    continue
                ext = os.path.splitext(file)[1].lower()
                lang = self.EXTENSION_MAP.get(ext)
                if not lang or lang not in rules:
                    continue

                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, workspace_path)

                try:
                    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f_code:
                        content = f_code.read()
                except Exception:
                    continue

                # 提取配置中该语言的规则
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

        # 编号并输出
        for idx, cand in enumerate(candidates, 1):
            cand["id"] = idx
            cand["status"] = "PENDING"
            cand["verdict"] = None
        return candidates

    def _scan_via_tree_sitter(self, content, lang, ast_queries, file_path, lang_rules):
        parser_lang = tree_sitter_languages.get_language(lang)
        parser = tree_sitter_languages.get_parser(lang)
        
        tree = parser.parse(bytes(content, "utf8"))
        root_node = tree.root_node
        candidates = []
        lines = content.splitlines()

        for query_str in ast_queries:
            query = parser_lang.query(query_str)
            captures = query.captures(root_node)
            for node, tag in captures:
                line_no = node.start_point[0] + 1
                line_content = lines[line_no - 1] if line_no <= len(lines) else ""
                
                # 匹配该 S-expression 属于哪一个 CWE
                matched_rule = self._find_rule_by_ast(lang_rules, query_str)
                cwe_id = matched_rule.get("cwe_id")

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

                    # Optimization 1: 初筛漏斗过滤优化
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

                    candidates.append({
                        "language": lang,
                        "cwe_id": matched_rule["cwe_id"],
                        "category": matched_rule["category"],
                        "type": matched_rule.get("type", "TAINT_ANALYSIS"),
                        "file_path": file_path,
                        "line_number": line_idx + 1,
                        "sink_content": sink_content,
                        "sources_regex": matched_rule.get("sources", {}).get("regex", []),
                        "reachability_constraints": matched_rule.get("reachability_constraints", ""),
                        "verification_logic": matched_rule.get("verification_logic", "")
                    })
                    break
        return candidates

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
    workspace = sys.argv[1] if len(sys.argv) > 1 else "."
    output_dir = sys.argv[2] if len(sys.argv) > 2 else workspace
    script_dir = os.path.dirname(os.path.abspath(__file__))
    profile = os.path.join(script_dir, "../resources/security_profiles.json")
    
    scanner = ASTCoarseScanner(profile)
    results = scanner.scan(workspace)
    
    # 写入待验证队列
    queue_path = os.path.join(output_dir, "verify_queue.json")
    with open(queue_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"SUCCESS: AST/Regex Scan complete. Found {len(results)} Candidates. Written to {queue_path}")
