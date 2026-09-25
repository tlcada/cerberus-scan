#!/usr/bin/env python3
"""Cerberus-Scan MCP server.

Exposes a security-scanning pipeline as MCP tools that any MCP-compatible
agent (Claude Code, Copilot CLI, Cursor, Kiro, ...) can call. The server runs
on the host, orchestrates Docker (scanner container + ZAP sibling), and hands
raw + normalised results back to the agent. The agent supplies the reasoning
(data-flow traces, IDOR sibling diffs) guided by the methodology tools.

The server never runs an AI model itself and needs no API key. It needs only
Docker on the host.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import report as report_mod
from . import scan as scan_mod
from . import validation as validation_mod
from . import zap as zap_mod

logger = logging.getLogger(__name__)


def _data_dir(name: str) -> Path:
    """Locate a bundled data directory in both source and installed layouts.

    In the source tree the dir is a sibling of mcp_server/ (repo root); once
    installed via uvx/pip the packaging places it inside mcp_server/. Try the
    in-package location first, then the repo-root fallback.
    """
    here = Path(__file__).resolve().parent
    for cand in (here / name, here.parent / name):
        if cand.is_dir():
            return cand
    # Default to in-package path; glob on a missing dir just yields nothing.
    return here / name


METHODOLOGY = _data_dir("methodology")
STACKS = METHODOLOGY / "stacks"

# Sent in MCP initialize, so this guidance follows the server into every
# connected project. Keep the opening self-contained for clients that truncate
# server instructions; repeat the entry point in run_scan's tool description.
WORKFLOW_INSTRUCTIONS = """Load get_methodology(name="workflow") first — it is the whole plan. Then: call run_scan(repo_path) to start the scanners in a detached background container, and immediately begin hunting for vulnerabilities yourself with your own file/grep/read tools. Do not sit and poll; a "running" response is normal, never a timeout, and you never re-run a running scan.

Use the absolute path of the user's current project as repo_path, not the Cerberus installation directory. For a named subfolder, pass its repository root plus subproject.

While the scan runs, load get_methodology(name="recon") and get_methodology(name="code-review") and read the dangerous code (auth, payments, admin, file parsers, DB access, URL fetchers, eval/template sinks) end to end, tracing untrusted input to its sink. The scanners only catch pattern matches; the highest-impact bugs (RCE, SSRF, XXE, auth bypass, IDOR, business logic) are found only by your own reading. Poll get_report between review tasks to fold in scanner findings, then push past them to the second-order leads they imply.

A scan request without runtime validation means static scanning plus your code review. When the user requests validation against an authorized URL, preserve that URL; after the scan completes and you have triaged it, call validate_target with the attack vectors you flagged (method + path + body, not just paths) as endpoints, the tech fingerprint from recon, and auth_headers for a test account so authenticated routes are reachable. It starts a background ZAP job: poll validation_status(job_id) until complete, partial or failed, then call stop_validation. validate_target refuses while a scan is still running, by design. Then add the read-only manual probes ZAP is weak at (access control, IDOR, logic).

Write the report last, once, using get_methodology(name="report-template") as the shape. It is a template you fill in a single time — do NOT regenerate it repeatedly or run any validate-and-fix loop; a clear, honest report that mostly follows the template is the goal. There is no report-checking or review-accounting tool to satisfy. Keep every finding backed by a real source-to-sink trace or a read-only runtime proof; drop or clearly label anything unverified. Keep manual proof requests minimal and non-destructive.
"""

mcp = FastMCP("cerberus-scan", instructions=WORKFLOW_INSTRUCTIONS)


@mcp.tool()
def run_scan(
    repo_path: str,
    subproject: str = ".",
    diff_base: str = "",
    diff_target: str = "HEAD",
) -> str:
    """Start a Cerberus-Scan security scan of the user's project.

    Use this tool for requests such as "scan this project with Cerberus" or
    "security scan this project and validate against <URL>". Resolve repo_path
    from the user's project. The workflow is supplied by this server: load
    get_methodology("workflow"), start hunting while the scan runs, poll
    get_report to fold in findings, run validate_target if requested, and write
    the report last from get_methodology("report-template"). The user does not
    need to paste these steps into chat.

    Runs opengrep (SAST), trivy + osv-scanner (CVEs), gitleaks + trufflehog
    (secrets), checkov/hadolint (IaC), actionlint/zizmor (CI). Returns the
    SUMMARY with per-scanner counts.

    Immediately begin your own source review with your file/grep tools while the
    scanners run. Poll get_report between review tasks, then trace its findings
    as well. Review auth, ownership, business logic, and dangerous sinks even
    when scanners flag nothing there. Do NOT re-run these scanners yourself.

    Args:
        repo_path: absolute path to the repository to scan.
        subproject: path within the repo to focus on (default "." = whole repo).
        diff_base: if set (e.g. "main"), scan only files changed between this
            ref and diff_target — useful for reviewing a single PR/branch.
            Leave empty to scan the whole tree. Repo-wide scanners (dependency
            CVEs, git-history secrets) always run against the full tree.
        diff_target: the ref to diff against diff_base (default "HEAD").
    """
    try:
        result = scan_mod.run_scanners(
            repo_path,
            subproject,
            diff_base=diff_base or None,
            diff_target=diff_target,
        )
    except scan_mod.ScanError as e:
        return (
            f"SCAN FAILED — do not substitute a manual review.\n\n"
            f"Reason: {e}\n\n"
            "This tool's value is the scanner baseline (SAST, CVEs across two "
            "databases, secret detection with live verification). A hand review "
            "without it has no CVE data, no secret scan, and no full SAST pass, "
            "so a 'clean' result would be misleading — worse than no answer.\n\n"
            "Docker is required. STOP here and tell the user exactly how to fix "
            "it, then have them re-run the scan:\n"
            "  1. Make sure Docker Desktop is installed and running "
            "(check with `docker ps`).\n"
            "  2. Launch your agent after Docker is up, so the server inherits "
            "a PATH that can see Docker.\n"
            "Do NOT fall back to reviewing the code by hand — that is not this "
            "tool's job and gives the user false assurance."
        )

    if result.get("status") not in ("running", "complete"):
        return json.dumps(result, indent=2)

    # The scan runs in a detached container, so on a large repo it is still
    # going when this returns. That is expected — NOT a failure or a timeout.
    if result.get("status") == "running":
        return (
            f"Scan STARTED and running in the background. Outputs will appear in "
            f"{result['output_dir']}.\n\n"
            "This is normal for a large repo — the scan runs in a detached "
            "container so this call returns immediately instead of timing out. "
            "Do NOT re-run run_scan. Start hunting for vulnerabilities now with "
            "your own file/grep/read tools while the scanners work; both are "
            "required.\n\n"
            "Load get_methodology(name='workflow'), then get_methodology(name='recon') "
            "and get_methodology(name='code-review'), and read the dangerous code "
            "(auth, payments, admin, file parsers, DB access, eval/template sinks) "
            "end to end, tracing untrusted input to its sink.\n\n"
            "Poll get_report between review tasks (about every 20-30s). Once it is "
            "done it returns the normalised findings to investigate alongside your "
            "own; do not stop your review just because results arrive. Preserve any "
            "runtime URL the user supplied for validate_target after triage."
        )

    scope = f"\nDiff scope: {result['diff_scope']}" if result.get("diff_scope") else ""
    return (
        f"Scan complete. Outputs in {result['output_dir']}{scope}\n\n"
        f"{result.get('summary', '')}\n\n"
        "Next: load get_methodology(name='workflow') and its class guides, review "
        "the dangerous code with your own tools, and call get_report to normalize "
        "the scanner observations. Trace the findings through source, push past "
        "them to the leads they imply, perform any requested runtime validation, "
        "and write the report last from get_methodology(name='report-template')."
    )


@mcp.tool()
def scan_status(repo_path: str) -> str:
    """Check whether the background scan for a repo has finished.

    run_scan starts the scanners in a detached container and returns right away,
    so a large repo keeps scanning after that call. Poll this (or just call
    get_report, which reports the same state) to know when results are ready.

    Returns one of: "scanning" (still running — wait ~20-30s and check again),
    "complete" (results ready — call get_report), "failed" (container errored),
    or "missing" (no scan started — call run_scan first).

    Args:
        repo_path: the same repo path passed to run_scan.
    """
    status = scan_mod.collect_results(repo_path)
    state = status.get("status")
    mapping = {
        "running": "scanning",
        "complete": "complete",
        "failed": "failed",
        "missing": "missing",
    }
    return json.dumps(
        {**status, "status": mapping.get(state, state)},
        indent=2,
    )


@mcp.tool()
def get_report(
    repo_path: str,
    verbosity: str = "compact",
    severity: str = "",
    limit: int = 25,
    offset: int = 0,
) -> str:
    """Return normalised findings (stable ids, cross-checked CVEs) as JSON.

    Reads the raw scanner outputs produced by run_scan and returns a compact,
    de-duplicated report. Findings from trivy and osv-scanner that flag the
    same CVE are marked "corroborated". Each finding has an "endpoint" and
    "traced" field for you to fill in during code review.

    The result is ALWAYS bounded and paginated so it fits in one tool result,
    even for a huge repo with hundreds of findings: it returns the counts plus a
    page of findings, most-severe first. The complete, untrimmed report is
    always written to .security-scan-output/security-scan-report.json (path in `report_file`) — read
    it from disk, or page with `offset`, for anything beyond the returned window.
    When the result has "truncated": true, more findings exist — do not treat
    the unreturned ones as absent.

    Args:
        repo_path: the same repo path passed to run_scan.
        verbosity: "compact" (default — the fields needed to triage),
            "minimal" (counts only, no findings list), or "full" (every field
            per finding; still paginated).
        severity: optional filter — "CRITICAL"/"HIGH"/"MEDIUM"/"LOW". Empty =
            all severities. Use it to page through one severity at a time.
        limit: max findings to return in this call (default 25, hard cap 100).
        offset: skip this many (within the severity-sorted list) for paging.
    """
    # The scan runs in a detached container. Check its state first: if it's
    # still going, say so (the agent polls); only build the report once done.
    status = scan_mod.collect_results(repo_path)
    state = status.get("status")
    if state == "running":
        return json.dumps(
            {
                "status": "scanning",
                "message": "Scan still running in the background. Continue independent "
                "source review, including code without scanner hits. Poll get_report "
                "between review tasks (about every 20-30s); do not re-run run_scan.",
            },
            indent=2,
        )
    if state == "failed":
        return json.dumps(
            {
                **status,
                "status": "failed",
                "message": status.get("message")
                or f"Scanner container exited {status.get('exit_code')}. Audit incomplete.",
                "container_log": status.get("container_log", ""),
            },
            indent=2,
        )
    if state == "missing":
        return f"ERROR: no scan found for {repo_path}. Run run_scan first."

    out_dir = Path(status["output_dir"])
    if not out_dir.is_dir():
        return f"ERROR: no scan output at {out_dir}. Run run_scan first."
    if verbosity not in ("compact", "minimal", "full"):
        verbosity = "compact"
    report = report_mod.build_report(
        str(out_dir), verbosity=verbosity, severity=severity, limit=limit, offset=offset
    )
    return json.dumps(report, indent=2)


@mcp.tool()
def get_methodology(name: str) -> str:
    """Return a methodology guide. Load one only when the step needs it.

    Core guides (apply to every scan):
      - workflow           the whole plan (load this first)
      - recon              fingerprint the app + map the attack surface
      - code-review        the manual hunt: injection, auth, IDOR, logic
      - secrets-deps-iac   secrets / CVE / IaC / CI triage
      - runtime-zap        drive ZAP + manual probes + payload cheatsheet
      - report-template    the report shape (filled in once, no rework loop)

    Stack playbooks (load ONLY when the target's stack matches):
      - aws                AWS SDK call scoping (DynamoDB/S3/STS/Lambda/...)
      - azure-entra        Azure AD / Entra ID token validation (tid/aud/scp)
      - mobile             iOS/Android app testing (static + on-device; no ZAP)

    Args:
        name: one of the guide names above.
    """
    # Core guides live in methodology/; the conditional stack playbooks live in
    # methodology/stacks/. One tool resolves both so the agent has a single
    # entry point; the docstring marks which are load-on-match.
    for base in (METHODOLOGY, STACKS):
        path = base / f"{name}.md"
        if path.is_file():
            return path.read_text(encoding="utf-8")
    available = sorted(
        p.stem for p in (*METHODOLOGY.glob("*.md"), *STACKS.glob("*.md"))
    )
    return f"ERROR: unknown methodology '{name}'. Available: {', '.join(available)}"


@mcp.tool()
def validate_target(
    target_url: str,
    endpoints: list | None = None,
    tech: list[str] | None = None,
    auth_headers: dict | None = None,
) -> str:
    """Start a background ZAP validation job and return its job_id immediately.

    Brings up the ZAP container, replays the attack vectors you flagged during
    code review as real requests, spiders the app, then runs a full active scan
    with injection scanners at high strength. Poll validation_status(job_id) for
    progress and paginated alerts. Do not stop the job merely because this call
    returns running.

    Only run this against a target the user explicitly named. Local hosts only
    unless SEC_ALLOW_REMOTE=1 is set. Active scanning sends many requests — use
    only on systems the user owns.

    Args:
        target_url: e.g. http://localhost:3000 (must include scheme + host).
        endpoints: the attack vectors you flagged. Each item is either a string
            ("/api/users/:id" or "POST /api/orders") or a dict for anything with
            a body or query, e.g.
            {"method": "POST", "path": "/api/orders",
             "body": {"total": 1, "items": []}, "content_type": "json"}.
            content_type is "json" (default) or "form"; route params like ":id"
            or "{id}" are auto-filled so ZAP fuzzes a concrete resource. Pass the
            endpoint rows from your recon output block here.
        tech: stack fingerprint, e.g. ["Db.PostgreSQL","Language.JavaScript"].
        auth_headers: headers added to every ZAP request so authenticated routes
            are tested, e.g. {"Authorization": "Bearer <token>"} or
            {"Cookie": "session=<id>"}. Use a token for a throwaway/test account.
            Values are used in-process only and are never saved or echoed back.
    """
    # ZAP runs LAST. If a static scan is still going in the background, refuse:
    # runtime validation is aimed by the endpoints code review flagged, so
    # starting it before the scan finishes and is triaged would scan blind.
    if scan_mod.any_scan_running():
        return (
            "VALIDATION BLOCKED — a static scan is still running.\n\n"
            "ZAP runs LAST: after the static scan completes AND you have triaged "
            "the findings in code, because it is aimed by the endpoints code "
            "review flagged. Starting it now would scan blind and waste the run.\n\n"
            "Wait until get_report reports the scan is complete, finish your code "
            "review, then call validate_target again with the endpoints and tech "
            "you gathered. Continue independent source review in the meantime; "
            "only live validation is blocked."
        )
    try:
        zap_mod.guard_target(target_url)
        result = validation_mod.start(
            target_url, endpoints or [], tech or [], auth_headers or {}
        )
    except zap_mod.ZapError as e:
        # Do NOT let a failed validation be silently dropped. The user asked to
        # validate against a live target, so an incomplete run must be surfaced
        # in the report, not abandoned.
        return (
            "RUNTIME VALIDATION DID NOT RUN.\n\n"
            f"Reason: {e}\n\n"
            "This is NOT optional to hide. The user asked to validate against a "
            "live target, so you MUST:\n"
            "  1. Relay the reason/fix above to the user (e.g. pull the ZAP image, "
            "start the app, correct the URL), and\n"
            "  2. In your report, add a prominent line 'Runtime validation: NOT "
            "PERFORMED (<reason>)' and label every finding by what actually "
            "backs it — 'Static + traced' or 'Confirmed by manual probe', never "
            "'runtime confirmed' for anything ZAP did not test.\n"
            "Do not present the report as if runtime validation happened. If you "
            "confirmed findings with your own curl/manual probes, keep those and "
            "say so; just don't claim ZAP coverage you don't have."
        )
    return json.dumps(result, indent=2)


@mcp.tool()
def validation_status(job_id: str = "", offset: int = 0, limit: int = 20) -> str:
    """Read background ZAP progress and alerts. Poll while running or stopping.

    Read every alert page before correlating results. A partial, failed,
    cancelled or interrupted job means incomplete runtime coverage.
    """
    try:
        return json.dumps(validation_mod.status(job_id, offset, limit), indent=2)
    except (ValueError, OSError) as error:
        return json.dumps({"status": "error", "error": str(error)})


@mcp.tool()
def stop_validation() -> str:
    """Stop the ZAP container after validation is complete."""
    try:
        return json.dumps(validation_mod.stop(), indent=2)
    except Exception as e:  # noqa: BLE001 - report to user rather than crash the tool
        logger.warning(f"stop_validation failed: {e}")
        return f"ERROR: {e}"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
