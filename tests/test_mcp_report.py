import asyncio
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

try:
    from mcp_server import server
except ModuleNotFoundError:
    server = None


# Tools the refactor removed — the report-enforcement and review-accounting
# machinery, plus get_playbook (folded into get_methodology). None of these may
# reappear in the server's tool catalog.
REMOVED_TOOLS = (
    "generate_final_report",
    "check_report",
    "record_runtime_proofs",
    "get_review_queue",
    "read_review_source",
    "record_reviews",
    "get_review_evidence",
    "get_playbook",
)

CURRENT_TOOLS = (
    "run_scan",
    "scan_status",
    "get_report",
    "get_methodology",
    "validate_target",
    "validation_status",
    "stop_validation",
)


@unittest.skipIf(server is None, "MCP dependency is only installed on the host")
class McpReportTests(unittest.TestCase):
    def test_running_scan_directs_agent_to_hunt_and_blocks_zap(self) -> None:
        running = {"status": "running", "output_dir": "/repo/out"}
        with (
            patch.object(server.scan_mod, "run_scanners", return_value=running),
            patch.object(server.scan_mod, "collect_results", return_value=running),
            patch.object(server.scan_mod, "any_scan_running", return_value=True),
        ):
            run_response = server.run_scan("/repo")
            report_response = json.loads(server.get_report("/repo"))["message"]
            validate_response = server.validate_target("http://localhost:3000")

        # run_scan hands the agent straight into an autonomous hunt.
        self.assertIn("hunting", run_response.lower())
        self.assertIn("do not re-run run_scan", run_response.lower())
        # get_report keeps the agent reviewing while the scan runs.
        self.assertIn("still running", report_response.lower())
        # validate_target refuses while a scan is in flight.
        self.assertIn("VALIDATION BLOCKED", validate_response)

    def test_workflow_and_tool_surface_delivered_over_mcp(self) -> None:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        async def connect(project: str) -> None:
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "mcp_server.server"],
                cwd=project,
                env={
                    "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(
                    read, write, read_timeout_seconds=timedelta(seconds=20)
                ) as session:
                    initialized = await session.initialize()
                    self.assertEqual(initialized.serverInfo.name, "cerberus-scan")
                    instructions = initialized.instructions or ""
                    for step in (
                        "run_scan",
                        "get_report",
                        "validate_target",
                        "validation_status",
                        "stop_validation",
                        "get_methodology",
                        "report-template",
                        "workflow",
                    ):
                        self.assertIn(step, instructions)
                    for removed in REMOVED_TOOLS:
                        self.assertNotIn(removed, instructions)

                    names = [tool.name for tool in (await session.list_tools()).tools]
                    for name in CURRENT_TOOLS:
                        self.assertIn(name, names)
                    for removed in REMOVED_TOOLS:
                        self.assertNotIn(removed, names)

                    entry = next(
                        tool
                        for tool in (await session.list_tools()).tools
                        if tool.name == "run_scan"
                    )
                    self.assertIn("Cerberus", entry.description)
                    self.assertIn("workflow", entry.description)
                    self.assertIn("repo_path", entry.inputSchema["required"])

                    guide = await session.call_tool(
                        "get_methodology", {"name": "workflow"}
                    )
                    self.assertFalse(guide.isError)
                    text = "\n".join(
                        block.text for block in guide.content if block.type == "text"
                    )
                    self.assertIn("The shape of a scan (five moves)", text)
                    self.assertIn("The report rule", text)

                    # Stack playbooks resolve through the same tool (no
                    # separate get_playbook), so a stack name returns its guide.
                    stack = await session.call_tool(
                        "get_methodology", {"name": "aws"}
                    )
                    self.assertFalse(stack.isError)
                    stack_text = "\n".join(
                        block.text for block in stack.content if block.type == "text"
                    )
                    self.assertIn("AWS", stack_text)

                    # A dropped guide name reports an error, not a stale file.
                    missing = await session.call_tool(
                        "get_methodology", {"name": "security-scan"}
                    )
                    missing_text = "\n".join(
                        block.text for block in missing.content if block.type == "text"
                    )
                    self.assertIn("unknown methodology", missing_text)

        # The client starts the server from an unrelated project without an
        # AGENTS.md. Only MCP metadata and packaged guide lookup supply context.
        with tempfile.TemporaryDirectory() as project:
            asyncio.run(connect(project))


if __name__ == "__main__":
    unittest.main()
