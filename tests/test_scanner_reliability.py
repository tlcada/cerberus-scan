import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_server import report, scan
from mcp_server.scanner_image import run_scanners as runner


def sast(
    path: str = "routes/a.ts",
    line: int = 12,
    rule: str = "unsafe-query",
    severity: str = "ERROR",
) -> dict:
    return {
        "check_id": rule,
        "path": path,
        "start": {"line": line},
        "extra": {"severity": severity, "message": "Untrusted SQL input"},
    }


class TemporaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name: str, value: object) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path


class RunnerTests(TemporaryTest):
    def run_fake(
        self, code: str, filename: str = "opengrep.json", timeout: float = 5, **kwargs
    ) -> tuple[str, str]:
        with patch.object(runner, "OUT", self.root):
            return runner.run([sys.executable, "-c", code], filename, timeout, **kwargs)

    def test_process_failure_does_not_become_clean_json(self) -> None:
        _, status = self.run_fake("import sys; print('bad arguments'); sys.exit(2)")
        self.assertIn("exit code 2", status)
        self.assertEqual(
            (self.root / "opengrep.json").read_text().strip(), "bad arguments"
        )

    def test_invalid_json_with_success_exit_is_failure(self) -> None:
        _, status = self.run_fake("print('not JSON')")
        self.assertIn("invalid JSON", status)

    def test_valid_partial_result_is_not_complete(self) -> None:
        _, status = self.run_fake(
            'print(\'{"results": [], "errors": [{"type": "Timeout"}]}\')'
        )
        self.assertTrue(status.startswith("partial:"))

    def test_routine_parse_warnings_do_not_mark_scan_partial(self) -> None:
        # opengrep emits a warn-level entry for every partially parsed file on a
        # real repo; with results present and exit 0 that is a healthy scan, not
        # a failure. The unparsed files are recorded as analysis gaps elsewhere.
        _, status = self.run_fake(
            'print(\'{"results": [{"check_id": "x"}], "errors": ['
            '{"level": "warn", "type": ["PartialParsing", []], "message": "syntax"},'
            '{"level": "warn", "type": "Syntax error", "message": "unexpected"}'
            ']}\')'
        )
        self.assertEqual(status, "done")

    def test_error_level_entry_still_marks_scan_partial(self) -> None:
        _, status = self.run_fake(
            'print(\'{"results": [], "errors": [{"level": "error", "type": "RuleError"}]}\')'
        )
        self.assertTrue(status.startswith("partial:"))

    def test_finding_exit_codes_are_not_tool_failure(self) -> None:
        _, status = self.run_fake(
            "import sys; print('{\"vulnerabilities\": {}}'); sys.exit(1)",
            "npm-audit.json",
        )
        self.assertEqual(status, "done")

    def test_npm_error_json_is_failure_even_with_exit_one(self) -> None:
        _, status = self.run_fake(
            'import sys; print(\'{"error": {"code": "ENOLOCK"}}\'); sys.exit(1)',
            "npm-audit.json",
        )
        self.assertTrue(status.startswith("partial:"))

    def test_osv_no_packages_is_explicit(self) -> None:
        _, status = self.run_fake("import sys; sys.exit(128)", "osv.json")
        self.assertIn("no supported packages", status)

    def test_timeout_retains_stdout_stderr_and_metadata(self) -> None:
        _, status = self.run_fake(
            "import sys,time; print('partial', flush=True); print('downloading DB',file=sys.stderr,flush=True); time.sleep(5)",
            timeout=0.1,
        )
        self.assertIn("timed out", status)
        self.assertIn("partial", (self.root / "opengrep.json").read_text())
        self.assertIn("downloading DB", (self.root / "opengrep.err").read_text())
        meta = json.loads((self.root / "opengrep.status.json").read_text())
        self.assertEqual(meta["timeout_seconds"], 0.1)
        self.assertIsNone(meta["exit_code"])

    def test_own_report_is_not_overwritten(self) -> None:
        target = self.root / "gitleaks-tree.json"
        code = f"from pathlib import Path; Path({str(target)!r}).write_text('[]'); print('log output')"
        _, status = self.run_fake(code, "gitleaks-tree.json", writes_own_file=True)
        self.assertEqual(status, "done")
        self.assertEqual(target.read_text(), "[]")

    def test_own_missing_report_is_failure(self) -> None:
        _, status = self.run_fake(
            "print('log only')", "gitleaks-tree.json", writes_own_file=True
        )
        self.assertIn("missing or invalid JSON", status)

    def test_typescript_includes_javascript_security_rules(self) -> None:
        rules = self.root / "rules"
        for lang in ("typescript", "javascript", "generic"):
            (rules / lang / "security").mkdir(parents=True)
        (self.root / "app.ts").write_text("const app = 1")
        with (
            patch.object(runner, "TGT", self.root),
            patch.object(runner, "BUNDLED_RULES", rules),
        ):
            configs = runner._bundled_configs()
        self.assertIn(str(rules / "javascript" / "security"), configs)

    def test_discovery_prunes_angular_cache_and_deduplicates(self) -> None:
        (self.root / ".angular" / "cache").mkdir(parents=True)
        (self.root / ".angular" / "cache" / "Dockerfile").touch()
        (self.root / "Dockerfile").touch()
        self.assertEqual(
            runner.discover(["Dockerfile*", "Dockerfile"], self.root),
            [self.root / "Dockerfile"],
        )

    def test_low_cpu_budget(self) -> None:
        with patch.object(runner, "_cpu_count", return_value=1):
            self.assertEqual(runner._worker_count(), 1)
            self.assertEqual(runner._opengrep_jobs(), ["-j", "1"])

    def test_tasks_use_internal_and_outer_trivy_deadlines(self) -> None:
        with (
            patch.object(runner, "TGT", self.root),
            patch.object(runner, "WORKSPACE", self.root),
            patch.dict(runner.os.environ, {"CERBERUS_TIMEOUT_TRIVY": "42"}),
        ):
            tasks = runner.build_tasks()
        trivy = next(t for t in tasks if t[1] == "trivy.json")
        self.assertIn("42s", trivy[0])
        self.assertEqual(trivy[2], 72)
        self.assertNotIn("--severity", trivy[0])
        osv = next(t for t in tasks if t[1] == "osv.json")
        self.assertEqual(osv[0][:3], ["osv-scanner", "scan", "source"])


class ReportTests(TemporaryTest):
    def test_severity_pagination_preserves_sast_priority_and_context(self) -> None:
        self.write(
            "out/opengrep.json",
            {"results": [sast(severity="WARNING"), sast("routes/b.ts")]},
        )
        result = report.build_report(str(self.root / "out"), severity="HIGH")
        self.assertEqual(Path(result["report_file"]), self.root / "out" / "security-scan-report.json")
        self.assertTrue(Path(result["report_file"]).is_file())
        self.assertFalse((self.root / ".security-scan-report.json").exists())
        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["findings"][0]["rule"], "unsafe-query")
        self.assertEqual(result["findings"][0]["title"], "Untrusted SQL input")

    def test_npm_audit_normalized(self) -> None:
        values = report.parse_npm_audit(
            {
                "vulnerabilities": {
                    "demo": {
                        "severity": "critical",
                        "via": [
                            {
                                "source": 123,
                                "title": "Bad query",
                                "severity": "critical",
                            }
                        ],
                    }
                }
            }
        )
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["severity"], "CRITICAL")
        self.assertEqual(values[0]["package"], "demo")

    def test_dedup_and_comparison_do_not_claim_fixed(self) -> None:
        out = self.root / "out"
        self.write("out/opengrep.json", {"results": [sast()]})
        self.write(
            "out/opengrep-rules.json", {"results": [sast("/workspace/routes/a.ts")]}
        )
        self.write("out/previous-report.json", {"findings": [{"id": "old-hit"}]})
        self.write(
            "out/scanner-status.json", {"opengrep": "done", "trivy": "timed out (300s)"}
        )
        result = report.build_report(str(out))
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["coverage_status"], "incomplete")
        self.assertEqual(result["comparison"]["not_observed_ids"], ["old-hit"])

    def test_same_cve_in_different_packages_has_distinct_ids(self) -> None:
        values = report.parse_trivy(
            {
                "Results": [
                    {
                        "Target": "lock.json",
                        "Vulnerabilities": [
                            {"VulnerabilityID": "CVE-X", "PkgName": "a"},
                            {"VulnerabilityID": "CVE-X", "PkgName": "b"},
                        ],
                    }
                ]
            }
        )
        self.assertNotEqual(values[0]["id"], values[1]["id"])


class ScanLifecycleTests(TemporaryTest):
    def test_previous_report_survives_output_preparation(self) -> None:
        previous = self.write(
            f"{scan.OUTPUT_DIR_NAME}/security-scan-report.json", {"findings": [{"id": "previous"}]}
        )
        previous_text = previous.read_text()
        output = scan._prepare_out(self.root)
        self.assertEqual(
            (output / "previous-report.json").read_text(), previous_text
        )

    def test_legacy_root_report_is_used_for_previous_comparison(self) -> None:
        legacy = self.write(
            ".security-scan-report.json", {"findings": [{"id": "legacy"}]}
        )
        output = scan._prepare_out(self.root)
        self.assertEqual((output / "previous-report.json").read_text(), legacy.read_text())

    def test_new_report_takes_precedence_over_legacy_report(self) -> None:
        self.write(".security-scan-report.json", {"findings": [{"id": "legacy"}]})
        current = self.write(
            f"{scan.OUTPUT_DIR_NAME}/security-scan-report.json",
            {"findings": [{"id": "current"}]},
        )
        current_text = current.read_text()
        output = scan._prepare_out(self.root)
        self.assertEqual((output / "previous-report.json").read_text(), current_text)

    def test_repeated_run_does_not_delete_active_outputs(self) -> None:
        with (
            patch.object(
                scan, "ensure_scanner_image", return_value=("docker", "image")
            ),
            patch.object(scan, "_scan_state", return_value={"running": True}),
            patch.object(scan, "collect_results", return_value={"status": "running"}),
            patch.object(scan, "_prepare_out") as prepare,
        ):
            result = scan.run_scanners(str(self.root))
        self.assertEqual(result["status"], "running")
        prepare.assert_not_called()

    def test_running_container_with_missing_output_is_failed(self) -> None:
        with (
            patch.object(scan, "docker_bin", return_value="docker"),
            patch.object(
                scan, "_scan_state", return_value={"exists": True, "running": True}
            ),
        ):
            result = scan.collect_results(str(self.root))
        self.assertEqual(result["status"], "failed")
        self.assertIn("output directory", result["message"])
        self.assertTrue(result["container_running"])

    def test_failed_container_is_preserved_across_polls(self) -> None:
        output = self.root / scan.OUTPUT_DIR_NAME
        output.mkdir()
        (output / "SUMMARY.md").write_text("Partial summary")
        with (
            patch.object(scan, "docker_bin", return_value="docker"),
            patch.object(
                scan,
                "_scan_state",
                return_value={"exists": True, "running": False, "exit_code": 1},
            ),
            patch.object(scan.subprocess, "run") as run,
            patch.object(scan, "_rm_container") as remove,
        ):
            run.return_value.stdout = "scanner crashed"
            run.return_value.stderr = ""
            for _ in range(2):
                result = scan.collect_results(str(self.root))
                self.assertEqual(result["status"], "failed")
                self.assertIn("scanner crashed", result["container_log"])
        remove.assert_not_called()

    def test_subproject_cannot_escape(self) -> None:
        with self.assertRaises(scan.ScanError):
            scan.run_scanners(str(self.root), "..")


if __name__ == "__main__":
    unittest.main()
