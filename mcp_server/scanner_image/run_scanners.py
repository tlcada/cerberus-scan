#!/usr/bin/env python3
"""In-container scanner orchestrator.

Runs every deterministic scanner in parallel with per-scanner timeouts,
writes raw outputs to /out, then builds SUMMARY.md. No AI, no model — this
container only produces raw scanner outputs and a human-readable summary.

Environment:
    SCAN_SUB    subproject path relative to /workspace (default ".")

Mounts (set by the MCP server):
    /workspace  the repo, read-only
    /out        output directory, read-write
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

WORKSPACE = Path("/workspace")
OUT = Path("/out")
SUB = os.environ.get("SCAN_SUB", ".")
TGT = (WORKSPACE / SUB).resolve() if SUB != "." else WORKSPACE

# Optional diff scope: a file (mounted at /out) listing changed paths, one per
# line, repo-relative. When set, per-file SAST scans only these; repo-wide
# scanners (CVEs, git history) still run against the whole tree. Read from a
# file rather than an env var because multiline env values are unreliable via
# `docker run -e`, especially on Windows.
_changed_file = os.environ.get("SCAN_CHANGED_FILE", "").strip()
CHANGED_FILES = []
if _changed_file:
    try:
        _raw = Path(_changed_file).read_text(encoding="utf-8")
        CHANGED_FILES = [ln.strip() for ln in _raw.splitlines() if ln.strip()]
    except OSError:
        CHANGED_FILES = []

T_DEFAULT = 180
T_FAST = 60
T_HISTORY = 240

SKIP_DIRS = [
    "node_modules",
    "dist",
    "build",
    ".next",
    "out",
    "coverage",
    ".cache",
    ".angular",
    ".nuxt",
    ".venv",
    "venv",
    ".git",
    "vendor",
    "__pycache__",
    ".security-scan-output",
]


def _timeout(name: str, default: int) -> int:
    value = os.environ.get(
        "CERBERUS_TIMEOUT_" + name.upper().replace("-", "_"), str(default)
    )
    seconds = int(value)
    if seconds <= 0:
        raise ValueError(f"Timeout for {name} must be a positive number of seconds")
    return seconds


# Generated / third-party dirs (node_modules above all) are pointless to
# SAST-scan or secret-scan: they're vendored code, they dominate a real repo's
# file count, and walking them is what pushes a large project
# past the client's tool-call timeout. Dependency CVEs still come from the
# lockfile/manifest scanners (trivy, osv, npm audit), so excluding the vendored
# *source* from opengrep/gitleaks/trufflehog loses no real coverage.
#
# Each scanner takes exclusions differently, so we hand each the shape it wants:
#   - opengrep : repeated --exclude <dir> (basename glob)
#   - trivy    : repeated --skip-dirs **/<dir> (path glob)
#   - gitleaks : a --config TOML whose allowlist has path regexes
#   - trufflehog: an --exclude-paths file of path regexes
GITLEAKS_CONFIG = "/tmp/gitleaks-scan.toml"
TRUFFLEHOG_EXCLUDE = "/tmp/trufflehog-exclude.txt"


def _path_regexes() -> list[str]:
    """Regex per skip-dir, matching it as a path segment anywhere in the tree."""
    return [rf"(^|/){re.escape(d)}(/|$)" for d in SKIP_DIRS] + [
        r"(^|/)\.security-scan-report\.json$",
    ]


def _opengrep_excludes() -> list[str]:
    arguments = []
    for directory in SKIP_DIRS:
        arguments += ["--exclude", directory]
    return arguments


def _trivy_skip_dirs() -> list[str]:
    arguments = []
    for directory in SKIP_DIRS:
        arguments += ["--skip-dirs", f"**/{directory}"]
    return arguments


def _cpu_count() -> int:
    """The container's real CPU allowance, honouring the cgroup quota.

    os.cpu_count() reports the HOST's cores, but Docker Desktop typically caps a
    container at 1-2 CPUs. Running 8 scanners in parallel on 2 cores is what
    starved the heavy passes (opengrep broad, trivy, gitleaks-tree) until they
    timed out. Read the quota so the worker pool matches what's actually there.
    """
    # cgroup v2
    try:
        parts = Path("/sys/fs/cgroup/cpu.max").read_text().split()
        if parts and parts[0] != "max":
            quota, period = int(parts[0]), int(parts[1])
            if period > 0:
                return max(1, round(quota / period))
    except (OSError, ValueError, IndexError):
        pass
    # cgroup v1
    try:
        quota = int(Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read_text().strip())
        period = int(Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us").read_text().strip())
        if quota > 0 and period > 0:
            return max(1, round(quota / period))
    except (OSError, ValueError):
        pass
    return os.cpu_count() or 2


def _worker_count() -> int:
    """Bound concurrent scanners to available cores, at most four."""
    return max(1, min(4, _cpu_count()))


def _opengrep_jobs() -> list[str]:
    """Share CPU capacity across scanners instead of giving each all cores."""
    return ["-j", str(max(1, _cpu_count() // _worker_count()))]


# A real SAST ruleset baked into the image (see Dockerfile). Using it instead of
# opengrep's `--config auto` removes the dependency on the semgrep.dev registry
# (network), which is why the broad pass was silently skipping in some
# environments. We scope it to the languages actually present so the scan stays
# fast (loading every language's rules is slow) and general (works beyond JS/TS).
BUNDLED_RULES = Path("/opt/semgrep-rules")
_EXT_RULEDIR = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".scala": "scala",
    ".rs": "rust",
    ".swift": "swift",
    ".sh": "bash",
    ".tf": "terraform",
}


def _security_dirs(lang_dir: Path) -> list[Path]:
    """The `security` rule subdirs under a language dir, or the whole dir if it
    has none. semgrep-rules groups rules by intent (security / best-practice /
    correctness / performance / ...); we want ONLY the security ones. Loading the
    entire corpus is what made the broad pass slow enough to time out under CPU
    contention — best-practice/correctness/perf rules are lint, not findings a
    security report should carry. Every language we target (js/ts/py/go/java/php/
    ruby) ships a `security` subtree; the whole-dir fallback only triggers for a
    language that structures rules differently, so we still get coverage."""
    sec = sorted(d for d in lang_dir.rglob("security") if d.is_dir())
    return sec if sec else [lang_dir]


def _bundled_configs() -> list[str]:
    """opengrep --config args for the bundled ruleset, scoped to (a) the
    languages present in the target and (b) the SECURITY rules within them.
    Offline + deterministic. Empty if the bundle isn't in the image (older
    build); the caller reports a configuration failure instead of using auto."""
    if not BUNDLED_RULES.is_dir():
        return []
    languages = set()
    for dirpath, dirnames, filenames in os.walk(TGT):
        dirnames[:] = [
            directory for directory in dirnames if directory not in SKIP_DIRS
        ]
        for filename in filenames:
            language = _EXT_RULEDIR.get(Path(filename).suffix.lower())
            if language:
                languages.add(language)
                # JavaScript rules also match TypeScript, and contain most of
                # the shared Node/Express rules. TS-only projects need both.
                if language == "typescript":
                    languages.add("javascript")
    languages.add("generic")  # secrets / crypto / cross-language patterns
    configs = []
    for language_name in sorted(languages):
        language_path = BUNDLED_RULES / language_name
        if language_path.is_dir():
            for security_directory in _security_dirs(language_path):
                configs += ["--config", str(security_directory)]
    return configs


def write_ignore_files() -> None:
    """Write the runtime ignore configs for gitleaks and trufflehog to /tmp.

    Kept out of the image (written at run time) so tuning the skip list means
    editing this one file, not rebuilding — the dir list above is the single
    source of truth for every scanner.
    """
    regexes = _path_regexes()
    paths_toml = ",\n  ".join(f"'''{r}'''" for r in regexes)
    Path(GITLEAKS_CONFIG).write_text(
        "[extend]\n"
        "useDefault = true\n\n"
        "[allowlist]\n"
        'description = "skip generated / third-party dirs"\n'
        f"paths = [\n  {paths_toml}\n]\n",
        encoding="utf-8",
    )
    Path(TRUFFLEHOG_EXCLUDE).write_text("\n".join(regexes) + "\n", encoding="utf-8")


def _error_is_blocking(entry: object) -> bool:
    """Whether a scanner JSON `errors` entry means degraded coverage.

    opengrep (semgrep JSON) emits a `warn`-level entry for every file it can only
    partially parse — unusual syntax, a newer language feature, a generated file.
    On any real repo that is a handful to dozens of files, while the scan still
    exits 0 and returns full results, and those files are recorded separately as
    analysis gaps. Treating that as a failed scan mislabels a healthy run. So a
    routine parse/syntax warning is NOT blocking; a timeout or an error/fatal-
    level entry (or one with no level, kept conservative for other scanners) is.
    """
    if not isinstance(entry, dict):
        return bool(entry)
    if "timeout" in str(entry.get("type", "")).lower():
        return True
    level = str(entry.get("level", "error")).lower()
    return level not in ("warn", "warning", "info", "note", "debug")


def _completed_status(
    name: str, exit_code: int, out_file: str, report_path: Path, ndjson: bool
) -> str:
    """Interpret exit codes and validate output without discarding partial data."""
    finding_exit_scanners = {
        "osv",
        "npm-audit",
        "checkov-tf",
        "checkov-df",
        "hadolint",
        "actionlint",
    }
    accepted_codes = {0}
    if name in finding_exit_scanners:
        accepted_codes.add(1)
    if name == "osv" and exit_code == 128:
        return "not applicable: no supported packages found"
    if exit_code not in accepted_codes:
        return f"error: exit code {exit_code}; see {name}.err"
    if not out_file.endswith(".json"):
        return "done"

    try:
        raw = report_path.read_text(encoding="utf-8")
        if ndjson:
            data = []
            for line in raw.splitlines():
                if line.strip():
                    data.append(json.loads(line))
        else:
            data = json.loads(raw)
        if not isinstance(data, (dict, list)):
            raise ValueError("expected a JSON object or array")
        if isinstance(data, dict):
            errs = data.get("errors")
            blocking = data.get("error") or (
                isinstance(errs, list) and any(_error_is_blocking(e) for e in errs)
            ) or (bool(errs) and not isinstance(errs, list))
            if blocking:
                return f"partial: scanner reported errors; see {out_file} and {name}.err"
    except (OSError, ValueError):
        return f"error: missing or invalid JSON output; see {name}.err"
    return "done"


def run(
    cmd: list[str],
    out_file: str,
    timeout: float,
    ndjson: bool = False,
    cwd: str | Path | None = None,
    writes_own_file: bool = False,
) -> tuple[str, str]:
    name = out_file.rsplit(".", 1)[0] if out_file else cmd[0]
    # Announce start immediately so the container never looks dead: the
    # completion line below only prints when a scanner *finishes*, which on a
    # large repo can be a minute+ away. Without this a grinding container shows
    # no output and reads as "not running".
    print(f"  {name}: started (timeout {timeout}s)", flush=True)
    started = time.monotonic()
    status, exit_code = "error: not started", None
    report_path = OUT / out_file
    stdout_path = OUT / (f"{name}.stdout" if writes_own_file else out_file)
    try:
        # Stream directly to disk: retain diagnostics and partial results even
        # on timeout, without buffering an entire scan's output in memory.
        with (
            stdout_path.open("w", encoding="utf-8") as stdout,
            (OUT / f"{name}.err").open("w", encoding="utf-8") as stderr,
        ):
            proc = subprocess.Popen(
                cmd,
                stdout=stdout,
                stderr=stderr,
                cwd=cwd,
                start_new_session=(os.name == "posix"),
            )
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
                proc.wait()
                status = f"timed out ({timeout}s); see {name}.err"
        if exit_code is not None:
            status = _completed_status(name, exit_code, out_file, report_path, ndjson)
    except FileNotFoundError:
        status = "tool not found"
    except Exception as e:  # noqa: BLE001
        status = f"error: {e}"
    (OUT / f"{name}.status.json").write_text(
        json.dumps(
            {
                "status": status,
                "exit_code": exit_code,
                "elapsed_seconds": round(time.monotonic() - started, 2),
                "timeout_seconds": timeout,
                "command": cmd,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return name, status


def ensure_json_array(path: Path) -> None:
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        path.write_text("[]", encoding="utf-8")


def _opengrep_data(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            return data
    except (OSError, ValueError):
        pass
    return {}


def run_task(*task: Any) -> tuple[str, str]:
    """Retry SAST timeouts on isolated files, retaining unresolved coverage gaps."""
    name, status = run(*task)
    if name not in {"opengrep", "opengrep-rules"} or status == "done":
        return name, status
    recovery_started = time.monotonic()
    initial_status = status
    command, output_name = task[:2]
    report_path = OUT / output_name
    data = _opengrep_data(report_path)
    original_path = OUT / f"{name}.original.json"
    if report_path.exists():
        original_path.write_bytes(report_path.read_bytes())

    # Preserve all options; replace only the positional scan targets.
    option_start = next(
        (i for i in range(2, len(command)) if command[i].startswith("-")), len(command)
    )
    targets = [Path(value).resolve() for value in command[2:option_start]]
    options = command[option_start:]
    errors = list(data.get("errors") or [])
    retry_paths = set()
    for error in errors:
        if "timeout" in str(error.get("type", "")).lower() and error.get("path"):
            retry_paths.add(Path(error["path"]).resolve())
    if not data and status.startswith("timed out"):
        # A killed process may produce no JSON. Recover supported source files
        # individually; never silently call the original run complete.
        for target in targets:
            if target.is_file():
                retry_paths.add(target)
            elif target.is_dir():
                retry_paths.update(
                    discover(["*" + ext for ext in _EXT_RULEDIR], target)
                )
        data = {"results": [], "errors": []}
        errors.append({"type": "ProcessTimeout", "message": status})
    deadline = time.monotonic() + _timeout("opengrep_retry", 180)
    attempts = []
    for index, path in enumerate(sorted(retry_paths)):
        if not path.is_file() or not any(
            path == target or path.is_relative_to(target) for target in targets
        ):
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        retry_name = f"{name}-retry-{index}.json"
        retry_command = [
            *command[:2],
            str(path),
            *options,
            "--timeout",
            "30",
            "--timeout-threshold",
            "0",
        ]
        _, retry_status = run(retry_command, retry_name, min(60, remaining))
        retry = _opengrep_data(OUT / retry_name)
        attempts.append(
            {"path": str(path), "status": retry_status, "output": retry_name}
        )
        data.setdefault("results", []).extend(retry.get("results", []))
        scanned_paths = {
            Path(value).resolve() for value in retry.get("paths", {}).get("scanned", [])
        }
        if retry_status == "done" and path in scanned_paths:
            errors = [
                error
                for error in errors
                if not error.get("path") or Path(error["path"]).resolve() != path
            ]
        else:
            errors.extend(retry.get("errors") or [])
    if data:
        # A generic-language pass can surface sinks despite AST parser failure.
        # It supplements the partial output; it never clears parser errors.
        parser_paths = sorted(
            {
                str(Path(error["path"]).resolve())
                for error in errors
                if error.get("path")
                and "pars" in str(error.get("type", "")).lower()
                and Path(error["path"]).is_file()
                and any(
                    Path(error["path"]).resolve() == target
                    or Path(error["path"]).resolve().is_relative_to(target)
                    for target in targets
                )
            }
        )
        if parser_paths and Path("/fallback-rules").is_dir():
            fallback_name = f"{name}-fallback.json"
            _, fallback_status = run(
                [
                    "opengrep",
                    "scan",
                    *parser_paths,
                    "--config",
                    "/fallback-rules",
                    "--json",
                    "-j",
                    "1",
                ],
                fallback_name,
                60,
            )
            fallback = _opengrep_data(OUT / fallback_name)
            data.setdefault("results", []).extend(fallback.get("results", []))
            attempts.append(
                {
                    "kind": "parser-independent fallback",
                    "status": fallback_status,
                    "output": fallback_name,
                    "paths": parser_paths,
                }
            )
        data["errors"] = errors
        data["recovery_attempts"] = attempts
        report_path.write_text(json.dumps(data), encoding="utf-8")
        # Once retries clear the timeouts, only routine per-file parse warnings
        # may remain; those are recorded as analysis gaps and do not mean the
        # scan failed. Upgrade to "done" when no BLOCKING error is left (mirrors
        # _completed_status), not only when the list is empty — otherwise every
        # real repo's opengrep run stays mislabelled "partial". This changes the
        # status label only; results and recorded gaps are unaffected.
        if status.startswith("partial:") and not any(
            _error_is_blocking(error) for error in errors
        ):
            status = "done"
    metadata_path = OUT / f"{name}.status.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update(
        status=status,
        initial_status=initial_status,
        recovery_attempts=attempts,
        recovery_elapsed_seconds=round(time.monotonic() - recovery_started, 2),
    )
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return name, status


def write_analysis_gaps(statuses: dict[str, str]) -> None:
    """Make parser failures and unrecovered timeouts actionable for code review."""
    gaps = []
    for name in ("opengrep", "opengrep-rules"):
        data = _opengrep_data(OUT / f"{name}.json")
        for error in data.get("errors") or []:
            gaps.append(
                {
                    "scanner": name,
                    "file": error.get("path", ""),
                    "rule": error.get("rule_id", ""),
                    "type": error.get("type"),
                    "message": str(error.get("message", ""))[:2000],
                    "required_action": "Independent source review; do not infer zero findings.",
                }
            )
        if statuses.get(name) not in (None, "done") and not data.get("errors"):
            gaps.append(
                {
                    "scanner": name,
                    "file": "",
                    "message": statuses[name],
                    "required_action": "Scan output is incomplete; review scope independently.",
                }
            )
    (OUT / "analysis-gaps.json").write_text(
        json.dumps(gaps, indent=2), encoding="utf-8"
    )


def discover(globs: list[str], root: Path) -> list[Path]:
    found = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in filenames:
            if any(Path(name).match(g) for g in globs):
                found.add(Path(dirpath) / name)
    return sorted(found)


def build_tasks() -> list[tuple]:
    tasks = []
    target_path = str(TGT)

    # SAST target: in diff mode, pass the changed files that exist under the
    # scan target; otherwise scan the whole target dir.
    if _changed_file:
        scoped = []
        for relative_path in CHANGED_FILES:
            path = WORKSPACE / relative_path
            if path.is_file() and path.resolve().is_relative_to(TGT.resolve()):
                scoped.append(str(path))
        # If nothing changed under this subproject, fall back to a no-op path
        # that opengrep will simply find nothing in.
        opengrep_targets = scoped if scoped else []
    else:
        opengrep_targets = [target_path]

    if opengrep_targets:
        # Two SEPARATE opengrep runs, on purpose. opengrep applies all --config
        # sources in one process and writes output only when it finishes, so on
        # a large repo the heavy registry "auto" set can hit the timeout and
        # take everything — including our custom rules — down with it. Splitting
        # them means the small local /rules pack (Express mass assignment, JWT
        # alg confusion, Angular DOM XSS, IDOR owner-id, forged trust fields)
        # ALWAYS completes and lands, even when auto times out or the registry
        # is unreachable. auto is then pure best-effort on top.
        # Timeouts: both passes are offline (local rules). The worker pool is now
        # capped to the container's CPU count (see _worker_count), and the broad
        # pass loads only the SECURITY rules (see _security_dirs), so it no longer
        # fights the whole lint corpus for a fraction of a core. The custom-rules
        # floor gets 180s; the broad security pass keeps 300s as generous headroom.
        if Path("/rules").is_dir():
            tasks.append(
                (
                    [
                        "opengrep",
                        "scan",
                        *opengrep_targets,
                        *_opengrep_excludes(),
                        *_opengrep_jobs(),
                        "--config",
                        "/rules",
                        "--json",
                    ],
                    "opengrep-rules.json",
                    240,
                    False,
                    None,
                )
            )
        # Broad pass uses only bundled rules, including generic rules when no
        # supported language is detected. Missing bundle = visible failure.
        # 600s: the aggregate of ~300 security rules over a large tree (Juice
        # Shop: 1009 files) on a CPU-capped Docker Desktop can genuinely need
        # several minutes even with a full core. The container is detached and
        # nothing kills it on a wall-clock, so a generous per-scanner cap costs
        # nothing — get_report just polls until the container exits.
        broad_configs = _bundled_configs() or ["--config", str(BUNDLED_RULES)]
        tasks.append(
            (
                [
                    "opengrep",
                    "scan",
                    *opengrep_targets,
                    *_opengrep_excludes(),
                    *_opengrep_jobs(),
                    *broad_configs,
                    "--json",
                ],
                "opengrep.json",
                600,
                False,
                None,
            )
        )
    trivy_timeout = _timeout("trivy", 900)
    tasks.append(
        (
            [
                "trivy",
                "fs",
                target_path,
                "--scanners",
                "vuln",
                "--cache-dir",
                "/cache/trivy",
                "--timeout",
                f"{trivy_timeout}s",
                *_trivy_skip_dirs(),
                "--format",
                "json",
            ],
            "trivy.json",
            trivy_timeout + 30,
            False,
            None,
        )
    )
    tasks.append(
        (
            ["osv-scanner", "scan", "source", "--format", "json", "-r", target_path],
            "osv.json",
            T_DEFAULT,
            False,
            None,
        )
    )
    # The supported directory command prunes globally allowlisted paths during
    # traversal. Include Angular build caches, which produced noise in Juice
    # Shop. History stays unfiltered: generated files may have been committed.
    tasks.append(
        (
            [
                "gitleaks",
                "dir",
                target_path,
                "--exit-code",
                "0",
                "--config",
                GITLEAKS_CONFIG,
                "--report-format",
                "json",
                "--report-path",
                "/out/gitleaks-tree.json",
            ],
            "gitleaks-tree.json",
            _timeout("gitleaks_tree", 600),
            False,
            None,
            True,
        )
    )
    tasks.append(
        (
            [
                "gitleaks",
                "detect",
                "--source",
                "/workspace",
                "--exit-code",
                "0",
                "--report-format",
                "json",
                "--report-path",
                "/out/gitleaks-history.json",
            ],
            "gitleaks-history.json",
            T_HISTORY,
            False,
            None,
            True,
        )
    )
    tasks.append(
        (
            [
                "trufflehog",
                "filesystem",
                target_path,
                "--json",
                "--only-verified",
                "--exclude-paths",
                TRUFFLEHOG_EXCLUDE,
            ],
            "trufflehog.json",
            T_DEFAULT,
            True,
            None,
        )
    )

    if (TGT / "package.json").is_file():
        tasks.append(
            (
                ["npm", "audit", "--omit=dev", "--json"],
                "npm-audit.json",
                T_FAST,
                False,
                target_path,
            )
        )
    if discover(["*.tf"], TGT):
        tasks.append(
            (
                [
                    "checkov",
                    "-d",
                    target_path,
                    "--framework",
                    "terraform",
                    "--output",
                    "json",
                ],
                "checkov-tf.json",
                T_DEFAULT,
                False,
                None,
            )
        )
    dockerfiles = discover(["Dockerfile*", "*.Dockerfile"], TGT)
    if dockerfiles:
        tasks.append(
            (
                [
                    "checkov",
                    "-d",
                    target_path,
                    "--framework",
                    "dockerfile",
                    "--output",
                    "json",
                ],
                "checkov-df.json",
                T_DEFAULT,
                False,
                None,
            )
        )
        tasks.append(
            (
                ["hadolint", *[str(path) for path in dockerfiles]],
                "hadolint.txt",
                T_FAST,
                False,
                None,
            )
        )
    workflow_directory = WORKSPACE / ".github" / "workflows"
    workflows = (
        sorted(workflow_directory.glob("*.y*ml")) if workflow_directory.is_dir() else []
    )
    if workflows:
        tasks.append(
            (
                ["actionlint", "-no-color", *[str(path) for path in workflows]],
                "actionlint.txt",
                T_FAST,
                False,
                None,
            )
        )
        tasks.append(
            (
                [
                    "zizmor",
                    "--no-exit-codes",
                    "--format",
                    "json",
                    str(workflow_directory),
                ],
                "zizmor.json",
                T_DEFAULT,
                False,
                None,
            )
        )
    return tasks


def count_json(name: str, path: Path) -> int | str:
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "null")
    except (OSError, json.JSONDecodeError):
        return "(parse error)"
    try:
        if name.startswith("opengrep"):
            return len(data.get("results", []))
        if name == "trivy":
            return sum(
                len(r.get("Vulnerabilities", []) or [])
                for r in data.get("Results", []) or []
            )
        if name == "osv":
            return sum(
                len(p.get("vulnerabilities", []) or [])
                for res in data.get("results", []) or []
                for p in res.get("packages", []) or []
            )
        if name.startswith("gitleaks"):
            return len(data or [])
        if name == "npm-audit":
            v = data.get("metadata", {}).get("vulnerabilities", {})
            return f"high={v.get('high', 0)} critical={v.get('critical', 0)}"
        if name.startswith("checkov"):
            return len(data.get("results", {}).get("failed_checks", []) or [])
        if name == "zizmor":
            return len(data or [])
    except Exception:  # noqa: BLE001
        return "(parse error)"
    return "?"


def count_ndjson(path: Path) -> int | str:
    try:
        lines = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except OSError:
        return 0
    verified = 0
    for line in lines:
        try:
            if json.loads(line).get("Verified") is True:
                verified += 1
        except json.JSONDecodeError:
            continue
    return f"{len(lines)} ({verified} verified)"


def count_coverage() -> dict[str, Any]:
    """Count source files in scope vs generated files skipped.

    Deterministic file accounting so the report can state honestly what the
    scanners covered. Counts real source files under the scan target, and how
    many were skipped as generated/third-party. In diff mode, reports the
    changed-file scope instead.
    """
    # Extensions worth counting as "source" — the code a review cares about.
    source_extensions = {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".py",
        ".rb",
        ".go",
        ".java",
        ".php",
        ".cs",
        ".rs",
        ".kt",
        ".swift",
        ".scala",
        ".vue",
        ".svelte",
        ".sql",
        ".sh",
        ".tf",
        ".yml",
        ".yaml",
        ".json",
        ".hbs",
        ".ejs",
        ".html",
    }
    skip = set(SKIP_DIRS)
    scanned = 0
    skipped_dirs = set()
    for dirpath, dirnames, filenames in os.walk(TGT):
        skipped_dirs.update(d for d in dirnames if d in skip)
        dirnames[:] = [d for d in dirnames if d not in skip]  # prune, don't descend
        for filename in filenames:
            if Path(filename).suffix.lower() in source_extensions:
                scanned += 1
    return {"scanned": scanned, "skipped_dirs": sorted(skipped_dirs)}


def build_summary(statuses: dict[str, str]) -> None:
    lines = [
        "# Pre-computed scanner outputs",
        "",
        f"Target: {SUB} (mounted at {TGT})",
        "",
    ]

    # Coverage — what the scanners actually looked at (deterministic).
    coverage = count_coverage()
    lines += ["## Coverage", ""]
    if _changed_file:
        lines.append(
            f"- Diff scope: {len(CHANGED_FILES)} changed paths supplied "
            f"(SAST limited to the diff; CVE + git-history scanners "
            f"still cover the whole tree)"
        )
    else:
        lines.append(
            f"- Source files in scope: {coverage['scanned']} (inventory, not proof every scanner analyzed every file)"
        )
    if coverage["skipped_dirs"]:
        lines.append(
            f"- Generated/third-party dirs skipped: "
            f"{', '.join(coverage['skipped_dirs'])}"
        )
    lines += [""]

    # Each scanner's REAL status from run() (done / timed out / tool not found /
    # error), not just "does a file exist". This is what lets the report say
    # exactly why a scanner has no findings — "ran, 0 findings" vs "timed out
    # (60s)" vs "tool not found" are very different, and conflating them as
    # "(skipped)" led to opengrep being reported as unavailable when it had
    # actually run or timed out.
    def _scanner_line(name: str, count_str: str) -> str:
        st = statuses.get(name)
        if st is None:
            return f"- {name}: not run (not applicable to this repo)"
        if st == "done":
            return f"- {name}: ok -- {count_str}"
        return f"- {name}: {st}"  # e.g. "timed out (60s)" / "tool not found"

    lines += ["## Counts (status -- findings)", ""]
    for name in [
        "opengrep",
        "opengrep-rules",
        "trivy",
        "osv",
        "gitleaks-tree",
        "gitleaks-history",
        "npm-audit",
        "checkov-tf",
        "checkov-df",
        "zizmor",
    ]:
        p = OUT / f"{name}.json"
        count = count_json(name, p) if p.exists() else "(no output file)"
        lines.append(_scanner_line(name, f"{count} findings"))
    trufflehog_path = OUT / "trufflehog.json"
    lines.append(
        _scanner_line(
            "trufflehog",
            f"{count_ndjson(trufflehog_path)} findings"
            if trufflehog_path.exists()
            else "(no output file)",
        )
    )
    for name in ["hadolint", "actionlint"]:
        p = OUT / f"{name}.txt"
        if p.exists():
            n = len(
                [x for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
            )
            count = f"{n} lines"
        else:
            count = "(no output file)"
        lines.append(_scanner_line(name, count))
    opengrep_path = OUT / "opengrep.json"
    if opengrep_path.exists():
        try:
            data = json.loads(opengrep_path.read_text(encoding="utf-8") or "{}")
            severity_counts = {}
            for result in data.get("results") or []:
                severity = result.get("extra", {}).get("severity", "UNKNOWN")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            if severity_counts:
                lines += ["", "## Severity breakdown (opengrep)", ""]
                lines += [f"- {k}: {v}" for k, v in sorted(severity_counts.items())]
        except (json.JSONDecodeError, OSError):
            pass
    (OUT / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    write_ignore_files()
    tasks = build_tasks()
    workers = _worker_count()
    # Startup banner — visible the instant the container runs, so `docker logs`
    # (or Docker Desktop) shows life before any scanner has finished.
    print(f"Cerberus-Scan: scanning {TGT}", flush=True)
    print(f"  excluding generated/vendored dirs: {', '.join(SKIP_DIRS)}", flush=True)
    print(
        f"  detected {_cpu_count()} CPU(s); running {len(tasks)} scanners "
        f"with {workers} parallel workers...",
        flush=True,
    )
    statuses = {}
    versions = {}
    for binary in sorted({task[0][0] for task in tasks}):
        try:
            version = subprocess.run(
                [binary, "--version"], capture_output=True, text=True, timeout=10
            )
            versions[binary] = (
                (version.stdout or "") + (version.stderr or "")
            ).strip()[:1000]
        except (OSError, subprocess.TimeoutExpired) as e:
            versions[binary] = str(e)
    revision_file = Path("/opt/semgrep-rules-sha256")
    versions["bundled_rules_sha256"] = (
        revision_file.read_text().split()[0]
        if revision_file.exists()
        else "unknown (legacy image)"
    )
    (OUT / "tool-versions.json").write_text(
        json.dumps(versions, indent=2, sort_keys=True), encoding="utf-8"
    )
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run_task, *task): task for task in tasks}
        for future in as_completed(futures):
            name, status = future.result()
            statuses[name] = status
            print(f"  {name}: {status}", flush=True)
    (OUT / "scanner-status.json").write_text(
        json.dumps(statuses, indent=2, sort_keys=True), encoding="utf-8"
    )
    write_analysis_gaps(statuses)
    build_summary(statuses)
    print("  SUMMARY.md ready", flush=True)


if __name__ == "__main__":
    main()
