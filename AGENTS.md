# Repository guidance

- `mcp_server/` contains the host-side MCP server. `mcp_server/scanner_image/` contains the scanner container, its runner, and custom rules. `methodology/` (including its `stacks/` subfolder of stack-specific playbooks) is bundled into the Python package. `tests/` contains regression and scanner smoke tests.
- `pyproject.toml` is the source of truth for Python dependencies. Keep package data paths working both from the checkout and from an installed wheel.
- After Python changes, run `python -m unittest discover -s tests`. If scanner runner, Dockerfile, or rules change, rebuild with `docker build -t cerberus-scan-scanner:local mcp_server/scanner_image` and run the relevant scanner smoke checks from the README.
- The server does the mechanical work (scanning, normalizing, ZAP orchestration); the agent does the reasoning and writes the report. There is no server-side report generator or report linter — the report is a template the agent fills once (`get_methodology("report-template")`), not a format enforced by a tool. Do not reintroduce a regenerate-until-pass loop.
- Treat scanner timeouts, invalid output, and partial runs as coverage gaps. Do not describe a failed scanner as finding zero issues.
- Keep static evidence, observed runtime behavior, and inferred impact distinct in security reports.
- Run active validation only against an explicitly identified, authorized target. Keep manual proof requests minimal and non-destructive; never change target data or credentials.
- The local-host-only target check in `mcp_server/zap.py` (bypassed only by `SEC_ALLOW_REMOTE=1`) is a safety guardrail. Do not weaken or remove it.
