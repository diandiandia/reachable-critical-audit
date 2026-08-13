import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class WorkflowContractTests(unittest.TestCase):
    def _load_ast_scanner_module(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "ast_scanner", REPO_ROOT / "tools" / "ast_scanner.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_l2_fallback_rules_are_configured_top10(self):
        profile = json.loads((REPO_ROOT / "resources" / "security_profiles.json").read_text())
        rules = profile.get("l2_fallback_rules", [])
        self.assertGreaterEqual(len(rules), 10)
        for rule in rules:
            self.assertIn("cwe_id", rule)
            self.assertIn("category", rule)
            self.assertIn("regex", rule)

    def test_batch_collect_keeps_invalid_payload_pending(self):
        with tempfile.TemporaryDirectory() as td:
            audit_dir = Path(td) / ".audit_results"
            audit_dir.mkdir()
            queue_path = audit_dir / "verify_queue.json"
            queue_path.write_text(json.dumps({
                "schema_version": "2.0",
                "candidates": [{
                    "id": "CAND-001",
                    "status": "PENDING",
                    "verdict": None,
                    "file_path": "app.py",
                    "line_number": 1,
                    "cwe_id": "CWE-78",
                }],
            }))

            bad_verdict = json.dumps({
                "verdict": "REACHABLE",
                "reachability_type": "DIRECT",
                "call_chain": ["a", "b", "c"],
                "call_chain_depth": 3,
            })
            result = subprocess.run(
                [
                    "python3", str(REPO_ROOT / "tools" / "batch_verify.py"),
                    td, "--stage", "collect", f"--cand-001={bad_verdict}",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn("BATCH_COLLECTED_WITH_ERRORS", result.stdout)
            queue = json.loads(queue_path.read_text())
            self.assertEqual(queue["candidates"][0]["status"], "PENDING")

    def test_batch_collect_downgrades_shallow_verified_to_needs_review(self):
        with tempfile.TemporaryDirectory() as td:
            audit_dir = Path(td) / ".audit_results"
            audit_dir.mkdir()
            queue_path = audit_dir / "verify_queue.json"
            queue_path.write_text(json.dumps({
                "schema_version": "2.0",
                "candidates": [{
                    "id": "CAND-001",
                    "status": "PENDING",
                    "verdict": None,
                    "file_path": "app.py",
                    "line_number": 1,
                    "cwe_id": "CWE-78",
                }],
            }))

            shallow_verdict = json.dumps({
                "verdict": "REACHABLE",
                "reachability_type": "DIRECT",
                "call_chain": ["sink", "caller"],
                "call_chain_depth": 2,
                "evidence": "too shallow",
            })
            subprocess.run(
                [
                    "python3", str(REPO_ROOT / "tools" / "batch_verify.py"),
                    td, "--stage", "collect", f"--cand-001={shallow_verdict}",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            queue = json.loads(queue_path.read_text())
            cand = queue["candidates"][0]
            self.assertEqual(cand["status"], "VERIFIED")
            self.assertEqual(cand["verdict"], "NEEDS_REVIEW")
            self.assertIn("call_chain_depth=2", cand["evidence"])

    def test_batch_assert_rejects_unreachable_without_blocking_point(self):
        with tempfile.TemporaryDirectory() as td:
            audit_dir = Path(td) / ".audit_results"
            audit_dir.mkdir()
            (audit_dir / "verify_queue.json").write_text(json.dumps({
                "schema_version": "2.0",
                "candidates": [{
                    "id": "CAND-001",
                    "status": "VERIFIED",
                    "verdict": "UNREACHABLE",
                    "reachability_type": "DIRECT",
                    "call_chain": ["sink", "caller1", "caller2"],
                    "call_chain_depth": 3,
                    "evidence": "blocked",
                    "blocking_point": None,
                }],
            }))

            result = subprocess.run(
                ["python3", str(REPO_ROOT / "tools" / "batch_verify.py"), td, "--stage", "assert"],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 3)
            self.assertIn("missing blocking_point", result.stdout)

    def test_compile_report_writes_required_fields_and_markdown_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            audit_dir = Path(td) / ".audit_results"
            audit_dir.mkdir()
            report_path = audit_dir / "reachable_vulnerabilities_report.json"
            script = """
const wf = require(process.argv[1]);
const reportPath = process.argv[2];
wf.compileReport([
  {
    id: 'CAND-001', origin: 'L0', status: 'VERIFIED', verdict: 'UNREACHABLE',
    reachability_type: 'DIRECT', call_chain: ['a','b','c'], call_chain_depth: 3,
    evidence: 'blocked', blocking_point: 'app.py:2', file_path: 'app.py',
    line_number: 1, cwe_id: 'CWE-78'
  },
  {
    id: 'CAND-002', origin: 'L1', status: 'VERIFIED', verdict: 'NEEDS_REVIEW',
    evidence: 'manual review', file_path: 'app.py', line_number: 2, cwe_id: 'CWE-89'
  }
], reportPath, [
  {
    hypothesis_id: 'H-1', hypothesis: 'remote alloc', origin: 'R4', status: 'VERIFIED',
    verdict: 'NEEDS_REVIEW', hypothesis_verdict: 'needs_review', cwe: ['CWE-789'],
    findings: [], coverage_note: 'schema issue', evidence: 'needs review'
  }
]);
"""
            env = os.environ.copy()
            env["AGENT_CLI"] = "test-cli"
            subprocess.run(
                ["node", "-e", script, str(REPO_ROOT / "run_workflow.js"), str(report_path)],
                text=True,
                capture_output=True,
                check=True,
                env=env,
            )
            report = json.loads(report_path.read_text())
            self.assertIn("unreachable_verified", report)
            self.assertIn("sampling_strategy", report["report_meta"])
            self.assertEqual(report["quantified_metrics"]["origin_breakdown"]["R4"], 1)
            self.assertEqual(len(report["needs_review"]), 2)
            md = (audit_dir / "reachable_vulnerabilities_report.md").read_text()
            self.assertIn("Sink Discovery Rate", md)
            self.assertIn("False Negative Risk", md)

    def test_check_availability_prefers_native_mode_env(self):
        env = os.environ.copy()
        env["REACHABLE_AUDIT_MODE"] = "native"
        result = subprocess.run(
            ["node", str(REPO_ROOT / "run_workflow.js"), "--check-availability"],
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["mode"], "A_NATIVE_ANTIGRAVITY")

    def test_workflow_venv_can_be_overridden_without_project_venv(self):
        script = """
const wf = require(process.argv[1]);
console.log(JSON.stringify({
  venvDir: wf.skillVenvDir(),
  python: wf.venvPythonPath()
}));
"""
        env = os.environ.copy()
        env["REACHABLE_AUDIT_VENV"] = "/tmp/reachable-audit-test-venv"
        result = subprocess.run(
            ["node", "-e", script, str(REPO_ROOT / "run_workflow.js")],
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["venvDir"], "/tmp/reachable-audit-test-venv")
        self.assertEqual(payload["python"], "/tmp/reachable-audit-test-venv/bin/python3")

    def test_scanner_ignores_skill_and_venv_paths(self):
        module = self._load_ast_scanner_module()

        ignored = module.ASTCoarseScanner._is_ignored_path
        self.assertTrue(ignored(".agents/skills/reachable-critical-audit/tools/ast_scanner.py"))
        self.assertTrue(ignored(".venv/lib/python/site-packages/pkg.py"))
        self.assertTrue(ignored(".codex/skills/reachable-critical-audit/SKILL.md"))
        self.assertFalse(ignored("src/service/auth.py"))

    def test_codeql_profile_preserves_go_swift_structured_models(self):
        profile = json.loads((REPO_ROOT / "resources" / "security_profiles.json").read_text())

        go_sql = next(r for r in profile["rules"]["go"] if r.get("cwe_id") == "CWE-89")
        self.assertGreater(len(go_sql["sinks"].get("go_models", [])), 0)
        self.assertTrue(any(
            m.get("package") == "database/sql" and m.get("method") in {"Exec", "Query"}
            for m in go_sql["sinks"]["go_models"]
        ))

        swift_cwes = {r.get("cwe_id"): r for r in profile["rules"]["swift"]}
        self.assertIn("CWE-22", swift_cwes)
        self.assertIn("CWE-78", swift_cwes)
        self.assertIn("CWE-89", swift_cwes)
        self.assertGreater(len(swift_cwes["CWE-22"]["sinks"].get("swift_models", [])), 1)
        self.assertTrue(any(
            m.get("type") == "FileManager" and m.get("method") == "removeItem"
            for m in swift_cwes["CWE-22"]["sinks"]["swift_models"]
        ))

    def test_self_check_counts_structured_models_separately_from_manual_regex(self):
        result = subprocess.run(
            ["python3", str(REPO_ROOT / "tools" / "ast_scanner.py"), "--self-check"],
            text=True,
            capture_output=True,
        )
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ast_coverage_ok"], payload)
        self.assertEqual(payload["ast_patterns_coverage_pct"], 100.0)
        self.assertGreater(payload["coverage_rule_count"], 0)
        self.assertGreater(payload["manual_review_regex_rules"], 0)
        self.assertIn("go_models/swift_models", payload["coverage_note"])

    def test_swift_sinkmodel_csv_parser_keeps_type_and_access_path(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "codeql_sink_extractor", REPO_ROOT / "tools" / "codeql_sink_extractor.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        row = ";FileManager;true;removeItem(at:);;;Argument[0];path-injection"
        model = module._parse_swift_sinkmodel_row(row)
        self.assertEqual(model["type"], "FileManager")
        self.assertEqual(model["method"], "removeItem")
        self.assertEqual(model["access_path"], "Argument[0]")
        self.assertEqual(model["sink_kind"], "path-injection")

    def test_go_structured_model_requires_package_context(self):
        module = self._load_ast_scanner_module()
        profile = {
            "rules": {
                "go": [{
                    "cwe_id": "CWE-89",
                    "category": "SqlInjection",
                    "type": "TAINT_ANALYSIS",
                    "sinks": {
                        "regex": ["Exec\\s*\\("],
                        "go_models": [{
                            "package": "database/sql",
                            "type": "DB",
                            "method": "Exec",
                            "access_path": "Argument[0]",
                            "sink_kind": "sql-injection",
                        }],
                    },
                    "sources": {"regex": []},
                }]
            }
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile))
            (root / "main.go").write_text(
                "package main\n"
                "type Worker struct{}\n"
                "func (w Worker) Exec(q string) {}\n"
                "func main(){ var w Worker; w.Exec(\"select 1\") }\n"
            )
            scanner = module.ASTCoarseScanner(str(profile_path))
            candidates, _meta = scanner.scan(td)
            self.assertEqual(candidates, [])

            (root / "main.go").write_text(
                "package main\n"
                "import \"database/sql\"\n"
                "func run(db *sql.DB, q string){ db.Exec(q) }\n"
            )
            candidates, _meta = scanner.scan(td)
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["cwe_id"], "CWE-89")
            self.assertEqual(candidates[0]["matched_model"]["package"], "database/sql")

    def test_swift_structured_model_matches_type_and_label(self):
        module = self._load_ast_scanner_module()
        profile = {
            "rules": {
                "swift": [{
                    "cwe_id": "CWE-22",
                    "category": "PathTraversal",
                    "type": "TAINT_ANALYSIS",
                    "sinks": {
                        "regex": ["contentsOf\\s*\\("],
                        "swift_models": [{
                            "type": "Data",
                            "signature": "init(contentsOf:options:)",
                            "method": "contentsOf",
                            "access_path": "Argument[0]",
                            "sink_kind": "path-injection",
                        }],
                    },
                    "sources": {"regex": []},
                }]
            }
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(profile))
            (root / "main.swift").write_text(
                "import Foundation\n"
                "func load(url: URL) throws { _ = try Data(contentsOf: url) }\n"
            )
            scanner = module.ASTCoarseScanner(str(profile_path))
            candidates, _meta = scanner.scan(td)
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["cwe_id"], "CWE-22")
            self.assertEqual(candidates[0]["matched_model"]["type"], "Data")


if __name__ == "__main__":
    unittest.main()
