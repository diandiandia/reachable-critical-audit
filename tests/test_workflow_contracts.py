import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class WorkflowContractTests(unittest.TestCase):
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
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "ast_scanner", REPO_ROOT / "tools" / "ast_scanner.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        ignored = module.ASTCoarseScanner._is_ignored_path
        self.assertTrue(ignored(".agents/skills/reachable-critical-audit/tools/ast_scanner.py"))
        self.assertTrue(ignored(".venv/lib/python/site-packages/pkg.py"))
        self.assertTrue(ignored(".codex/skills/reachable-critical-audit/SKILL.md"))
        self.assertFalse(ignored("src/service/auth.py"))


if __name__ == "__main__":
    unittest.main()
