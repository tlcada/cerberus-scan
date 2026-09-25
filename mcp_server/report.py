"""Normalise raw scanner outputs into one stable-id report JSON.

Mechanical work only — parsing, counting, de-duplicating, stable ids — so the
agent spends its budget on data-flow traces, not counting. Stable id =
sha1(scanner + rule + file + line)[:12].
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


def _load(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8").strip()
        return json.loads(text) if text else None
    except (OSError, json.JSONDecodeError) as e:
        logger.debug(f"Failed to load JSON from {path}: {e}")
        return None


def _as_list(val: Any) -> List[Any]:
    """Ensure the value is a list, returning empty list otherwise."""
    return val if isinstance(val, list) else []


def _as_dict(val: Any) -> Dict[str, Any]:
    """Ensure the value is a dictionary, returning empty dict otherwise."""
    return val if isinstance(val, dict) else {}


def _sid(scanner: str, rule: str, file: str, line: int) -> str:
    payload = f"{scanner}|{rule}|{file}|{line}".encode()
    return hashlib.sha1(payload).hexdigest()[:12]


def _f(
    scanner: str,
    rule: str,
    file: str,
    line: int,
    severity: str,
    title: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    file = str(file).replace("\\", "/")
    if file.startswith("/workspace/"):
        file = file[len("/workspace/") :]
    file = file.removeprefix("./")
    severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFORMATIONAL": "INFO"}.get(
        (severity or "").upper(), (severity or "").upper()
    )
    identity_rule = rule
    if extra and extra.get("package"):
        identity_rule += "|" + str(extra["package"])
    finding = {
        "id": _sid(scanner, identity_rule, file, line),
        "scanner": scanner,
        "rule": rule,
        "file": file,
        "line": line,
        "severity": (severity or "").upper(),
        "title": title,
        "endpoint": "",
        "confidence": "",
        "traced": False,
    }
    if extra:
        finding.update(extra)
    return finding


def parse_opengrep(data: Any) -> List[Dict[str, Any]]:
    findings = []
    for result in _as_list(_as_dict(data).get("results")):
        result_data = _as_dict(result)
        start = _as_dict(result_data.get("start"))
        extra = _as_dict(result_data.get("extra"))

        findings.append(
            _f(
                scanner="opengrep",
                rule=result_data.get("check_id", ""),
                file=result_data.get("path", ""),
                line=start.get("line", 0),
                severity=extra.get("severity", ""),
                title=extra.get("message", result_data.get("check_id", "")),
            )
        )
    return findings


def parse_npm_audit(data: Any) -> List[Dict[str, Any]]:
    """Normalize npm audit v2, including direct and transitive package records."""
    findings = []
    for name, value in _as_dict(_as_dict(data).get("vulnerabilities")).items():
        item = _as_dict(value)
        via = _as_list(item.get("via"))
        advisories = [entry for entry in via if isinstance(entry, dict)]
        for advisory in advisories or [{}]:
            rule = str(advisory.get("source") or name)
            findings.append(
                _f(
                    "npm-audit",
                    rule,
                    "package-lock.json",
                    0,
                    advisory.get("severity") or item.get("severity", ""),
                    advisory.get("title") or f"Vulnerable dependency: {name}",
                    {
                        "package": name,
                        "via": via,
                        "range": item.get("range"),
                        "fix_available": item.get("fixAvailable"),
                    },
                )
            )
    return findings


def parse_trivy(data: Any) -> List[Dict[str, Any]]:
    findings = []
    for result in _as_list(_as_dict(data).get("Results")):
        result_data = _as_dict(result)
        target = result_data.get("Target", "")
        for vulnerability in _as_list(result_data.get("Vulnerabilities")):
            vulnerability_data = _as_dict(vulnerability)
            cve = vulnerability_data.get("VulnerabilityID", "")
            package = vulnerability_data.get("PkgName", "")
            version = vulnerability_data.get("InstalledVersion", "")

            findings.append(
                _f(
                    scanner="trivy",
                    rule=cve,
                    file=target,
                    line=0,
                    severity=vulnerability_data.get("Severity", ""),
                    title=f"{cve} in {package}@{version}",
                    extra={"package": package, "cve": cve},
                )
            )
    return findings


def parse_osv(data: Any) -> List[Dict[str, Any]]:
    findings = []
    for result in _as_list(_as_dict(data).get("results")):
        result_data = _as_dict(result)
        source_path = _as_dict(result_data.get("source")).get("path", "")

        for package_entry in _as_list(result_data.get("packages")):
            package_data = _as_dict(package_entry)
            package_info = _as_dict(package_data.get("package"))
            name = package_info.get("name", "")
            version = package_info.get("version", "")

            for vulnerability in _as_list(package_data.get("vulnerabilities")):
                vulnerability_data = _as_dict(vulnerability)
                vulnerability_id = vulnerability_data.get("id", "")

                findings.append(
                    _f(
                        scanner="osv",
                        rule=vulnerability_id,
                        file=source_path,
                        line=0,
                        severity="",
                        title=f"{vulnerability_id} in {name}@{version}",
                        extra={"package": name, "cve": vulnerability_id},
                    )
                )
    return findings


def parse_gitleaks(data: Any, scanner: str) -> List[Dict[str, Any]]:
    findings = []
    for result in _as_list(data):
        result_data = _as_dict(result)
        rule_id = result_data.get("RuleID", "")
        description = result_data.get("Description", rule_id)

        findings.append(
            _f(
                scanner=scanner,
                rule=rule_id,
                file=result_data.get("File", ""),
                line=result_data.get("StartLine", 0),
                severity="HIGH",
                title=f"secret: {description}",
            )
        )
    return findings


def parse_trufflehog(path: Path) -> List[Dict[str, Any]]:
    findings = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        logger.debug(f"Failed to read trufflehog log {path}: {e}")
        return findings

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue

        result_data = _as_dict(result)
        detector = result_data.get("DetectorName", "")
        verified = bool(result_data.get("Verified", False))
        filesystem = _as_dict(
            _as_dict(result_data.get("SourceMetadata")).get("Data")
        ).get("Filesystem", {})
        filesystem_data = _as_dict(filesystem)

        findings.append(
            _f(
                scanner="trufflehog",
                rule=detector,
                file=filesystem_data.get("file", ""),
                line=filesystem_data.get("line", 0),
                severity="HIGH",
                title=f"{'VERIFIED ' if verified else ''}secret: {detector}",
                extra={"verified": verified},
            )
        )
    return findings


def parse_checkov(data: Any, scanner: str) -> List[Dict[str, Any]]:
    findings = []
    if isinstance(data, list):
        for entry in data:
            findings.extend(parse_checkov(entry, scanner))
        return findings
    results = _as_dict(_as_dict(data).get("results"))

    for check in _as_list(results.get("failed_checks")):
        check_data = _as_dict(check)
        check_id = check_data.get("check_id", "")
        line_range = _as_list(check_data.get("file_line_range"))
        line = line_range[0] if line_range else 0

        findings.append(
            _f(
                scanner=scanner,
                rule=check_id,
                file=check_data.get("file_path", ""),
                line=line,
                severity="MEDIUM",
                title=check_data.get("check_name", check_id),
            )
        )
    return findings


def parse_zizmor(data: Any) -> List[Dict[str, Any]]:
    findings = []
    for result in _as_list(data):
        result_data = _as_dict(result)
        locations = _as_list(result_data.get("locations"))
        file = ""
        if locations:
            symbolic_location = _as_dict(_as_dict(locations[0]).get("symbolic"))
            file = _as_dict(symbolic_location.get("key")).get("filename", "")

        description = result_data.get("desc", "")
        identifier = result_data.get("ident", "") or description
        determinations = _as_dict(result_data.get("determinations"))

        findings.append(
            _f(
                scanner="zizmor",
                rule=identifier,
                file=file,
                line=0,
                severity=determinations.get("severity", ""),
                title=description,
            )
        )
    return findings


def cross_check(findings: List[Dict[str, Any]]) -> None:
    by_cve: Dict[str, set[str]] = {}

    # First pass: map scanners to CVEs
    for finding in findings:
        cve = finding.get("cve")
        if finding["scanner"] in ("trivy", "osv") and cve:
            by_cve.setdefault(cve, set()).add(finding["scanner"])

    # Second pass: mark as corroborated
    for finding in findings:
        cve = finding.get("cve")
        if finding["scanner"] in ("trivy", "osv") and cve:
            if len(by_cve.get(cve, set())) > 1:
                finding["corroborated"] = True


def _counts(findings: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        value = str(finding.get(key) or "UNKNOWN")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _safe(parser: Callable[..., Any], *args: Any) -> List[Dict[str, Any]]:
    """Run a parser defensively: a single malformed scanner file must never
    crash the whole report. On any error that scanner contributes nothing —
    but the error is logged so a real bug is diagnosable rather than silent."""
    try:
        out = parser(*args)
        return out if isinstance(out, list) else []
    except Exception as e:  # noqa: BLE001 - deliberately broad; must not crash the report
        logger.warning(f"Parser {parser.__name__} failed: {e}")
        return []


# Severity ordering so the first page returned is always the most important
# findings, whatever order the scanners produced them in.
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
# Hard cap on findings returned inline, so a huge repo can never produce a
# tool result bigger than an MCP client can ingest. The full set is on disk.
_MAX_LIMIT = 100
_DEFAULT_LIMIT = 25


def _compare_findings(
    findings: List[Dict[str, Any]], previous: Any
) -> Optional[Dict[str, Any]]:
    """Compare stable IDs without treating absent findings as fixed bugs."""
    comparison = None
    if isinstance(previous, dict):
        previous_ids = {
            f["id"]
            for f in previous.get("findings", [])
            if isinstance(f, dict) and "id" in f
        }
        current_ids = {f["id"] for f in findings}
        comparison = {
            "new_ids": sorted(current_ids - previous_ids),
            "not_observed_ids": sorted(previous_ids - current_ids),
            "unchanged_count": len(previous_ids & current_ids),
            "note": "Not observed does not mean fixed: check scope, scanner failures, line changes, image and advisory DB updates.",
        }

    return comparison


def build_report(
    output_dir: str,
    verbosity: str = "compact",
    severity: str = "",
    limit: int = _DEFAULT_LIMIT,
    offset: int = 0,
) -> Dict[str, Any]:
    output_path = Path(output_dir)
    findings: List[Dict[str, Any]] = []

    findings += _safe(parse_opengrep, _load(output_path / "opengrep.json"))
    # Cerberus custom rules run as a separate opengrep pass (opengrep-rules.json)
    # so they land even when the heavy "auto" pass times out. Same JSON shape.
    findings += _safe(parse_opengrep, _load(output_path / "opengrep-rules.json"))
    findings += _safe(parse_trivy, _load(output_path / "trivy.json"))
    findings += _safe(parse_osv, _load(output_path / "osv.json"))
    findings += _safe(parse_npm_audit, _load(output_path / "npm-audit.json"))
    findings += _safe(
        parse_gitleaks, _load(output_path / "gitleaks-tree.json"), "gitleaks-tree"
    )
    findings += _safe(
        parse_gitleaks, _load(output_path / "gitleaks-history.json"), "gitleaks-history"
    )
    findings += _safe(parse_trufflehog, output_path / "trufflehog.json")
    findings += _safe(
        parse_checkov, _load(output_path / "checkov-tf.json"), "checkov-tf"
    )
    findings += _safe(
        parse_checkov, _load(output_path / "checkov-df.json"), "checkov-df"
    )
    findings += _safe(parse_zizmor, _load(output_path / "zizmor.json"))

    findings = list({f["id"]: f for f in findings}.values())
    findings.sort(
        key=lambda f: (_SEV_RANK.get(f["severity"], 5), f["file"], f["line"], f["id"])
    )
    cross_check(findings)
    statuses = _load(output_path / "scanner-status.json")
    gaps = {
        name: status
        for name, status in _as_dict(statuses).items()
        if status != "done" and not str(status).startswith("not applicable:")
    }
    previous = _load(output_path / "previous-report.json")
    comparison = _compare_findings(findings, previous)
    if not isinstance(statuses, dict):
        coverage_status = "unknown"
    elif gaps:
        coverage_status = "incomplete"
    else:
        coverage_status = "complete"

    full = {
        "findings": findings,
        "count": len(findings),
        "by_severity": _counts(findings, "severity"),
        "by_scanner": _counts(findings, "scanner"),
        "scanner_status": statuses,
        "coverage_gaps": gaps,
        "coverage_status": coverage_status,
        "comparison": comparison,
        "tool_versions": _load(output_path / "tool-versions.json"),
        "analysis_gaps": _as_list(_load(output_path / "analysis-gaps.json")),
        "analysis_gaps_file": str(output_path / "analysis-gaps.json"),
    }

    # The full report is always written to disk so the agent can read it in
    # detail if it wants; what we RETURN is always trimmed and paginated so it
    # can never exceed what an MCP client can read in one tool result.
    report_path = output_path / "security-scan-report.json"
    try:
        report_path.write_text(json.dumps(full, indent=2), encoding="utf-8")
    except OSError as e:
        logger.error(f"Failed to write full report to {report_path}: {e}")

    shaped = _shape(full, verbosity, str(report_path), severity, limit, offset)

    # Keep the model-facing response compact: the complete inventory is on disk,
    # and the scanner summary is sent only with the first page so paging through
    # findings does not repeat it.
    if offset == 0:
        summary_md = ""
        summary_path = output_path / "SUMMARY.md"
        if summary_path.exists():
            try:
                summary_md = summary_path.read_text(encoding="utf-8")
            except OSError:
                summary_md = ""
        shaped["scanner_summary"] = summary_md[:8000]  # counts + coverage
    execution_lines = []
    for name, status in sorted(_as_dict(statuses).items()):
        if status == "done":
            label = "ok"
        elif str(status).startswith("not applicable:"):
            label = "skipped"
        else:
            label = "failed"
        execution_lines.append(f"{label} {name} — {status}")
    shaped["tool_execution_summary"] = "\n".join(execution_lines)
    shaped["next_step"] = (
        "Trace the high-risk findings through source with your own tools. If "
        "runtime was requested, run and poll validate_target after the scan is "
        "complete and triaged. Write the report last from "
        "get_methodology('report-template')."
    )
    shaped["assurance_rule"] = (
        "Scanner observations are unverified until you trace them. Coverage gaps "
        "and untriaged inventory are not a clean result; say so in Coverage."
    )
    return shaped


def _shape(
    full: Dict[str, Any],
    verbosity: str,
    report_path: str,
    severity: str = "",
    limit: int = _DEFAULT_LIMIT,
    offset: int = 0,
) -> Dict[str, Any]:
    """Trim the returned report: filter by severity, sort by severity, and
    paginate. The complete, untrimmed report is always on disk at report_path;
    read it (or page with offset) for anything beyond the returned window."""
    counts = {
        "count": full["count"],
        "by_severity": full["by_severity"],
        "by_scanner": full["by_scanner"],
        "report_file": report_path,
        "scanner_status": full.get("scanner_status"),
        "coverage_status": full.get("coverage_status", "unknown"),
        "coverage_gaps": full.get("coverage_gaps", {}),
        "comparison": full.get("comparison"),
        "tool_versions": full.get("tool_versions"),
        "analysis_gaps": full.get("analysis_gaps", [])[:50],
        "analysis_gaps_count": len(full.get("analysis_gaps", [])),
        "analysis_gaps_file": full.get("analysis_gaps_file"),
    }
    if verbosity == "minimal":
        return counts

    # Filter by severity if asked, then order most-severe first so page 1 is
    # always the findings that matter most.
    severity_filter = (severity or "").upper()
    items = full["findings"]
    if severity_filter:
        items = [
            f for f in items if str(f.get("severity", "")).upper() == severity_filter
        ]
    items = sorted(
        items, key=lambda f: _SEV_RANK.get(str(f.get("severity", "")).upper(), 5)
    )

    matched = len(items)
    page_offset = max(0, int(offset))
    page_limit = int(limit) if int(limit) > 0 else _DEFAULT_LIMIT
    page_limit = min(page_limit, _MAX_LIMIT)
    window = items[page_offset : page_offset + page_limit]

    def shape_one(f: Dict[str, Any]) -> Dict[str, Any]:
        if verbosity == "full":
            return f
        finding = {
            k: f[k]
            for k in (
                "id",
                "scanner",
                "rule",
                "title",
                "severity",
                "file",
                "line",
                "endpoint",
                "traced",
                "confidence",
            )
            if k in f
        }
        for extra in ("cve", "verified", "corroborated"):
            if f.get(extra):
                finding[extra] = f[extra]
        return finding

    result: Dict[str, Any] = dict(counts)
    result["findings"] = [shape_one(f) for f in window]
    result["returned"] = len(window)
    result["matched"] = matched  # total after the severity filter
    result["offset"] = page_offset
    truncated = page_offset + len(window) < matched
    result["truncated"] = truncated
    if truncated:
        result["more"] = (
            f"Showing {page_offset + 1}-{page_offset + len(window)} of {matched}"
            + (f" {severity_filter}" if severity_filter else "")
            + " findings, most-severe first. For the rest, call get_report again "
            f"with offset={page_offset + len(window)} (and a severity filter to focus), "
            "or read the full report_file from disk. Do not assume the "
            "unreturned findings are absent."
        )
    return result
