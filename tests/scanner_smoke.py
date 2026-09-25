"""Run with the scanner image; all targets are disposable synthetic fixtures.

Pass --online to also test Trivy against its real vulnerability database.
The network-free checks never contact secret providers or a live application.
"""

import json
import sys
import tempfile
from pathlib import Path

from mcp_server.scanner_image import run_scanners as runner


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        target, output = root / "target", root / "output"
        target.mkdir()
        output.mkdir()
        runner.TGT, runner.OUT = target, output
        runner.write_ignore_files()
        secret = 'api_key = "a9B2c7D4e8F1g6H3i5J0k9L2m7N4o8P1"\n'
        (target / ".env").write_text(secret)
        (target / ".angular" / "cache").mkdir(parents=True)
        (target / ".angular" / "cache" / "noise.env").write_text(secret)
        (target / "app.ts").write_text(
            'import express from "express";\nconst app = express();\napp.post("/user", (req, res) => { User.update(req.body); });\n'
        )
        (target / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "cerberus-synthetic-test",
                    "version": "1.0.0",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {
                            "name": "cerberus-synthetic-test",
                            "version": "1.0.0",
                            "dependencies": {"lodash": "4.17.20"},
                        },
                        "node_modules/lodash": {"version": "4.17.20"},
                    },
                }
            )
        )
        name, status = runner.run(
            [
                "gitleaks",
                "dir",
                str(target),
                "--exit-code",
                "0",
                "--config",
                runner.GITLEAKS_CONFIG,
                "--report-format",
                "json",
                "--report-path",
                str(output / "gitleaks-tree.json"),
            ],
            "gitleaks-tree.json",
            30,
            writes_own_file=True,
        )
        assert status == "done", (
            name,
            status,
            (output / "gitleaks-tree.err").read_text(),
        )
        hits = json.loads((output / "gitleaks-tree.json").read_text())
        assert hits and all(".angular" not in hit["File"] for hit in hits), hits
        print(
            f"PASS: gitleaks detects synthetic source secret, excludes Angular cache ({len(hits)} hit(s))"
        )
        name, status = runner.run(
            [
                "opengrep",
                "scan",
                str(target),
                "--config",
                "/rules",
                "--json",
                "-j",
                "1",
            ],
            "opengrep-rules.json",
            90,
        )
        assert status == "done", (
            name,
            status,
            (output / "opengrep-rules.err").read_text(),
        )
        hits = json.loads((output / "opengrep-rules.json").read_text())["results"]
        assert hits, "synthetic mass assignment should be detected"
        print(
            f"PASS: custom SAST detects synthetic mass assignment ({len(hits)} hit(s))"
        )
        broken_source = target / "parser-gap.ts"
        broken_source.write_text("interface State { new?: any }\neval(userInput)\n")
        name, status = runner.run(
            [
                "opengrep",
                "scan",
                str(broken_source),
                "--config",
                "/fallback-rules",
                "--json",
                "-j",
                "1",
                "--timeout",
                "30",
                "--timeout-threshold",
                "0",
            ],
            "parser-fallback.json",
            60,
        )
        assert status == "done", (name, status)
        fallback = json.loads((output / "parser-fallback.json").read_text())
        assert fallback["results"], "generic fallback must detect eval despite AST gaps"
        print("PASS: parser-independent fallback detects a synthetic eval sink")
        broken_source.write_text(
            "interface State {\n new?: string\n}\neval(userInput)\n"
        )
        parser_rule = root / "parse-rule.yaml"
        parser_rule.write_text(
            "rules:\n  - id: synthetic-eval\n    languages: [typescript]\n"
            "    severity: WARNING\n    message: synthetic fixture\n"
            "    pattern: eval($X)\n"
        )
        name, status = runner.run_task(
            [
                "opengrep",
                "scan",
                str(broken_source),
                "--config",
                str(parser_rule),
                "--json",
                "-j",
                "1",
            ],
            "opengrep.json",
            60,
        )
        partial = json.loads((output / "opengrep.json").read_text())
        assert status.startswith("partial:"), (name, status)
        assert partial["errors"], "fallback must retain AST parser errors"
        assert any("parser-fallback" in hit["check_id"] for hit in partial["results"])
        runner.write_analysis_gaps({name: status})
        assert json.loads((output / "analysis-gaps.json").read_text())
        print(
            "PASS: parser failure triggers fallback and retains actionable coverage gaps"
        )
        empty = root / "empty"
        empty.mkdir()
        name, status = runner.run(
            [
                "osv-scanner",
                "scan",
                "source",
                "--offline",
                "--format",
                "json",
                str(empty),
            ],
            "osv.json",
            30,
        )
        assert status == "not applicable: no supported packages found", (
            name,
            status,
            (output / "osv.err").read_text(),
        )
        print("PASS: OSV v2 command works; no-packages is explicit")
        if "--online" in sys.argv:
            for attempt in range(2):
                name, status = runner.run(
                    [
                        "trivy",
                        "fs",
                        str(target),
                        "--scanners",
                        "vuln",
                        "--cache-dir",
                        "/cache/trivy",
                        "--timeout",
                        "180s",
                        "--format",
                        "json",
                    ],
                    "trivy.json",
                    210,
                )
                assert status == "done", (
                    name,
                    status,
                    (output / "trivy.err").read_text(),
                )
                data = json.loads((output / "trivy.json").read_text())
                assert any(
                    result.get("Vulnerabilities") for result in data.get("Results", [])
                ), data
                timing = json.loads((output / "trivy.status.json").read_text())[
                    "elapsed_seconds"
                ]
                print(
                    f"PASS: Trivy attempt {attempt + 1} detects vulnerable synthetic dependency ({timing}s)",
                    flush=True,
                )


if __name__ == "__main__":
    main()
