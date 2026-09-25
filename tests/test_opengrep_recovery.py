import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_server.scanner_image import run_scanners as runner


class RecoveryTests(unittest.TestCase):
    def test_timeout_retry_retains_findings_and_parser_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.ts"
            source.write_text("eval(input)")
            parser_error = {
                "type": "PartialParsing",
                "path": str(source),
                "message": "bad syntax",
            }
            timeout = {"type": "Timeout", "path": str(source), "rule_id": "slow"}
            calls = []

            def fake_run(command, output_name, *args):
                calls.append(command)
                name = output_name.removesuffix(".json")
                if len(calls) == 1:
                    data = {
                        "results": [{"check_id": "original"}],
                        "errors": [timeout, parser_error],
                    }
                    status = "partial: scanner reported errors"
                else:
                    data = {
                        "results": [{"check_id": "recovered"}],
                        "errors": [parser_error],
                    }
                    status = "partial: scanner reported errors"
                (root / output_name).write_text(json.dumps(data))
                (root / f"{name}.status.json").write_text(
                    json.dumps({"status": status})
                )
                return name, status

            with (
                patch.object(runner, "OUT", root),
                patch.object(runner, "run", side_effect=fake_run),
            ):
                name, status = runner.run_task(
                    ["opengrep", "scan", str(source), "--config", "/rules", "--json"],
                    "opengrep.json",
                    10,
                    False,
                    None,
                )
                runner.write_analysis_gaps({name: status})
            data = json.loads((root / "opengrep.json").read_text())
            self.assertEqual(
                [hit["check_id"] for hit in data["results"]], ["original", "recovered"]
            )
            self.assertIn("--timeout", calls[1])
            self.assertTrue(status.startswith("partial:"))
            gaps = json.loads((root / "analysis-gaps.json").read_text())
            self.assertTrue(any(gap["type"] == "PartialParsing" for gap in gaps))
            self.assertTrue((root / "opengrep.original.json").exists())

    def test_successful_retry_clears_only_resolved_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.touch()
            calls = []
            scanned_paths = [str(source)]

            def fake_run(command, output_name, *args):
                calls.append(command)
                errors = (
                    [{"type": "Timeout", "path": str(source)}]
                    if len(calls) == 1
                    else []
                )
                status = "partial: scanner reported errors" if errors else "done"
                (root / output_name).write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": errors,
                            "paths": {"scanned": scanned_paths},
                        }
                    )
                )
                name = output_name.removesuffix(".json")
                (root / f"{name}.status.json").write_text(
                    json.dumps({"status": status})
                )
                return name, status

            with (
                patch.object(runner, "OUT", root),
                patch.object(runner, "run", side_effect=fake_run),
            ):
                _, status = runner.run_task(
                    ["opengrep", "scan", str(source), "--json"], "opengrep.json", 10
                )
            self.assertEqual(status, "done")
            calls.clear()
            scanned_paths.clear()
            with (
                patch.object(runner, "OUT", root),
                patch.object(runner, "run", side_effect=fake_run),
            ):
                _, status = runner.run_task(
                    ["opengrep", "scan", str(source), "--json"], "opengrep.json", 10
                )
            self.assertTrue(status.startswith("partial:"))

    def test_retry_clears_timeout_and_warn_parse_leftovers_become_done(self) -> None:
        # After retries resolve the real timeout, only routine warn-level parse
        # warnings on other files remain. Those are recorded as analysis gaps,
        # not a scan failure, so the recovered status must upgrade to "done"
        # rather than staying "partial" forever.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            slow = root / "slow.py"
            slow.touch()
            other = str(root / "other.ts")
            warn = {"level": "warn", "type": "Syntax error", "path": other}
            calls = []

            def fake_run(command, output_name, *args):
                calls.append(command)
                errors = (
                    [{"type": "Timeout", "path": str(slow)}, warn]
                    if len(calls) == 1
                    else []
                )
                status = "partial: scanner reported errors" if errors else "done"
                (root / output_name).write_text(
                    json.dumps(
                        {
                            "results": [],
                            "errors": errors,
                            "paths": {"scanned": [str(slow)]},
                        }
                    )
                )
                name = output_name.removesuffix(".json")
                (root / f"{name}.status.json").write_text(
                    json.dumps({"status": status})
                )
                return name, status

            with (
                patch.object(runner, "OUT", root),
                patch.object(runner, "run", side_effect=fake_run),
            ):
                _, status = runner.run_task(
                    ["opengrep", "scan", str(root), "--json"], "opengrep.json", 10
                )
            self.assertEqual(status, "done")
            # The warn-level parse gap is still retained for analysis-gaps.
            data = json.loads((root / "opengrep.json").read_text())
            self.assertEqual(data["errors"], [warn])


if __name__ == "__main__":
    unittest.main()
