"""Run the scanner container against a repo. Called by the MCP server.

The scan runs as a DETACHED container (`docker run -d`) and the tool call
returns as soon as it has started — it never blocks for the whole scan. This
is what keeps `run_scan` safely under any MCP client's tool-call timeout, no
matter how large the repository: a big monorepo is collected by polling
`get_report`, not by holding one long call open. A small repo can still come
back in a single call: `run_scan` waits a short, bounded budget
(CERBERUS_INLINE_WAIT seconds, default 0) for a fast scan to finish before
handing back a "still running, poll get_report" result.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SCANNER_IMAGE = "cerberus-scan-scanner:local"
OUTPUT_DIR_NAME = ".security-scan-output"

# How long run_scan waits inline for a fast scan to finish before returning a
# "still running" result the agent polls. Kept well under a conservative client
# timeout so the call itself never times out. Set to 0 to always return
# immediately (fully async); raise it if your client's timeout is generous and
# you prefer one-shot calls on medium repos.
INLINE_WAIT_SECONDS = int(os.environ.get("CERBERUS_INLINE_WAIT", "0"))

# The scanner build context ships inside the package (mcp_server/scanner_image),
# so it is always next to this file whether run from source or installed via
# uvx/pip — no dependency on repo layout or packaging data-file placement.
_SCANNER_DIR = Path(__file__).resolve().parent / "scanner_image"

# Common Docker install locations to fall back on when it isn't on PATH — a
# frequent case when the server is launched by a GUI app (Claude Desktop) whose
# child processes inherit a minimal PATH.
_DOCKER_FALLBACKS = [
    r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
    r"C:\ProgramData\DockerDesktop\version-bin\docker.exe",
    "/usr/local/bin/docker",
    "/usr/bin/docker",
    "/opt/homebrew/bin/docker",
]


class ScanError(RuntimeError):
    pass


def docker_bin() -> Optional[str]:
    """Locate a working docker executable.

    Tries PATH first, then well-known install locations, and confirms the
    binary actually runs. Returns the path/name to use, or None if Docker is
    genuinely unavailable. This avoids the common failure where a GUI-launched
    server has Docker installed but not on its PATH.
    """
    candidates: List[str] = []
    on_path = shutil.which("docker")
    if on_path:
        candidates.append(on_path)
    candidates.extend(p for p in _DOCKER_FALLBACKS if Path(p).exists())

    for candidate in candidates:
        try:
            proc = subprocess.run(
                [candidate, "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode == 0:
                return candidate
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.debug(f"docker candidate {candidate} not usable: {e}")
            continue
    return None


def _image_exists(docker: str, image: str) -> bool:
    try:
        proc = subprocess.run(
            [docker, "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.debug(f"image inspect for {image} failed: {e}")
        return False


def ensure_scanner_image() -> tuple[str, str]:
    """Resolve docker and verify the scanner image is present.

    The image is built once by hand (see README), not automatically — a build
    inside a tool call overruns the MCP client's timeout. If it's missing, we
    say exactly how to build it rather than trying to build it here. Returns
    (docker_bin, image_ref) so the caller uses the same docker executable for
    the run command.
    """
    docker = docker_bin()
    if docker is None:
        raise ScanError(
            "Docker is installed nowhere this server can see it. Docker must be "
            "running and reachable. If it works in your terminal but not here, "
            "the app that launched this server has a different PATH — start "
            "Docker Desktop before launching your agent, or ensure docker is on "
            "the system PATH."
        )

    image = SCANNER_IMAGE
    if _image_exists(docker, image):
        return docker, image

    raise ScanError(
        f"the scanner image ({image}) isn't built yet. Build it once by hand:\n"
        f"    docker build -t {image} {_SCANNER_DIR}\n"
        "then run the scan again. (This is a one-time step — after the image is "
        "built, every scan reuses it. See the README.)"
    )


def _git_changed_files(repo: Path, base: str, target: str) -> List[str]:
    """Return files changed between base and target, relative to repo root.

    Runs git on the host (the container has the repo read-only and no full
    history mounted). Returns paths relative to the repo root.
    """
    if shutil.which("git") is None:
        raise ScanError("git not found on PATH; needed for diff-scoped scans")
    try:
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "diff",
                "--name-only",
                "--diff-filter=d",
                f"{base}...{target}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError("git diff timed out") from e
    if proc.returncode != 0:
        raise ScanError(
            f"git diff failed ({base}...{target}): {proc.stderr.strip()[:300]}"
        )
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


# ── Background-container lifecycle ───────────────────────────────────────────
#
# One scan == one detached container, named deterministically from the repo
# path so run_scan (start) and get_report (collect) agree on which container is
# "this repo's scan" without the agent having to pass an id around.


def _container_name(target: Path) -> str:
    path_hash = hashlib.sha1(str(target).encode("utf-8")).hexdigest()[:10]
    return f"cerberus-scan-run-{path_hash}"


def _rm_container(docker: str, name: str) -> None:
    """Remove a container by name, ignoring "no such container"."""
    try:
        subprocess.run(
            [docker, "rm", "-f", name], capture_output=True, text=True, timeout=30
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.debug(f"rm container {name} failed: {e}")


def _scan_state(docker: str, name: str) -> Dict[str, object]:
    """Inspect the scan container. Returns exists/running/exit_code."""
    try:
        proc = subprocess.run(
            [docker, "inspect", "-f", "{{.State.Status}}|{{.State.ExitCode}}", name],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.debug(f"inspect {name} failed: {e}")
        return {"exists": False, "running": False, "exit_code": None}
    if proc.returncode != 0:
        return {"exists": False, "running": False, "exit_code": None}
    status, _, code = proc.stdout.strip().partition("|")
    code = code.strip()
    return {
        "exists": True,
        "running": status == "running",
        "status": status,
        "exit_code": int(code) if code.lstrip("-").isdigit() else None,
    }


def any_scan_running() -> bool:
    """True if any Cerberus-Scan scanner container is still running.

    Used to stop runtime validation (ZAP) from starting before the static scan
    has finished. ZAP must run last, aimed by the endpoints code review flagged;
    launching it mid-scan would scan blind.
    """
    docker = docker_bin()
    if docker is None:
        return False
    try:
        proc = subprocess.run(
            [
                docker,
                "ps",
                "--filter",
                "name=cerberus-scan-run-",
                "--filter",
                "status=running",
                "-q",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return proc.returncode == 0 and bool(proc.stdout.strip())


def _prepare_out(target: Path) -> Path:
    out_dir = target / OUTPUT_DIR_NAME
    if out_dir.is_symlink() or out_dir.resolve().parent != target.resolve():
        raise ScanError("scan output directory must be directly inside the repository")
    previous = out_dir / "security-scan-report.json"
    legacy_previous = target / ".security-scan-report.json"
    if not previous.is_file():
        previous = legacy_previous
    previous_text = previous.read_text(encoding="utf-8") if previous.is_file() else None
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    if previous_text:
        (out_dir / "previous-report.json").write_text(previous_text, encoding="utf-8")
    return out_dir


def _start_container(
    docker: str,
    image: str,
    target: Path,
    out_dir: Path,
    subproject: str,
    changed: Optional[List[str]],
) -> str:
    """Start the scanner container detached. Returns the container name."""
    name = _container_name(target)
    # Clear any previous run for this repo so a stale container/name can't block
    # the new one or leak its old output.
    _rm_container(docker, name)

    env_args = ["-e", f"SCAN_SUB={subproject}"]
    for key in ("CERBERUS_TIMEOUT_TRIVY", "CERBERUS_TIMEOUT_GITLEAKS_TREE"):
        value = os.environ.get(key)
        if value is not None:
            try:
                if int(value) <= 0:
                    raise ValueError()
            except ValueError as e:
                raise ScanError(f"{key} must be a positive number of seconds") from e
            env_args += ["-e", f"{key}={value}"]
    if changed is not None:
        (out_dir / "changed-files.txt").write_text("\n".join(changed), encoding="utf-8")
        env_args += ["-e", "SCAN_CHANGED_FILE=/out/changed-files.txt"]

    # NB: no --rm. We need the exited container to survive so get_report can
    # read its exit code and logs; get_report removes it once collected.
    command = [
        docker,
        "run",
        "-d",
        "--name",
        name,
        *env_args,
        "-v",
        f"{target}:/workspace:ro",
        "-v",
        f"{out_dir}:/out",
        # Per-repository persistent DB cache: warm across runs, isolated from
        # other repos so concurrent scans don't contend over a database lock.
        "-v",
        f"{name}-trivy-cache:/cache/trivy",
        image,
    ]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired as e:
        raise ScanError("docker run -d did not return within 120s") from e
    if proc.returncode != 0:
        raise ScanError(
            f"failed to start scanner container.\n{proc.stderr.strip()[-500:]}"
        )
    return name


def _empty_diff_result(
    out_dir: Path, diff_base: str, diff_target: str
) -> Dict[str, object]:
    (out_dir / "SUMMARY.md").write_text(
        f"# Pre-computed scanner outputs\n\n"
        f"Diff scope: {diff_base}...{diff_target} — no files changed.\n",
        encoding="utf-8",
    )
    return {
        "status": "complete",
        "output_dir": str(out_dir),
        "summary": (out_dir / "SUMMARY.md").read_text(encoding="utf-8"),
        "container_log": "",
        "diff_scope": f"{diff_base}...{diff_target}",
        "changed_files": [],
    }


def run_scanners(
    repo_path: str,
    subproject: str = ".",
    diff_base: Optional[str] = None,
    diff_target: str = "HEAD",
) -> Dict[str, object]:
    """Start the scan (detached) and wait a short bounded budget for it to end.

    Returns a result dict with a "status":
      - "complete" : the scan finished within INLINE_WAIT_SECONDS; the dict
                     carries the SUMMARY and container log, same as before.
      - "running"  : still scanning in the background — the agent should poll
                     collect_results()/get_report until it reports complete.

    A detached container means the call never blocks for the whole scan, so a
    large repo can't push run_scan past the client's tool-call timeout.
    """
    target = Path(repo_path).resolve()
    if not target.is_dir():
        raise ScanError(f"repo path is not a directory: {target}")
    scoped = (target / subproject).resolve()
    if not scoped.is_relative_to(target) or not scoped.is_dir():
        raise ScanError(
            "subproject must be an existing directory inside the repository"
        )

    docker, image = ensure_scanner_image()
    if _scan_state(docker, _container_name(target))["running"]:
        return collect_results(repo_path)

    changed: Optional[List[str]] = None
    if diff_base:
        changed = _git_changed_files(target, diff_base, diff_target)
        if not changed:
            # Nothing changed — no container needed; return an empty-but-valid
            # completed result rather than scanning the whole repo unexpectedly.
            out_dir = _prepare_out(target)
            return _empty_diff_result(out_dir, diff_base, diff_target)

    out_dir = _prepare_out(target)
    name = _start_container(docker, image, target, out_dir, subproject, changed)

    # Bounded inline wait: fast scans finish here and return complete in one
    # call; anything slower is handed back as "running" for the agent to poll.
    deadline = time.time() + max(0, INLINE_WAIT_SECONDS)
    while time.time() < deadline:
        if not _scan_state(docker, name)["running"]:
            break
        time.sleep(2)

    result = collect_results(repo_path)
    if diff_base and result.get("status") == "complete":
        result["diff_scope"] = f"{diff_base}...{diff_target}"
    return result


def collect_results(repo_path: str) -> Dict[str, object]:
    """Report the background scan's status; on completion, gather its outputs.

    Called by get_report (and by run_scanners' inline wait). Returns a dict
    whose "status" is one of:
      - "running"  : the container is still scanning; poll again shortly.
      - "complete" : finished; dict carries output_dir, summary, container_log.
      - "failed"   : the container exited non-zero without producing a summary.
      - "missing"  : no scan container and no output on disk — run_scan first.
    """
    target = Path(repo_path).resolve()
    out_dir = target / OUTPUT_DIR_NAME
    summary_path = out_dir / "SUMMARY.md"

    docker = docker_bin()
    name = _container_name(target)
    state = (
        _scan_state(docker, name)
        if docker
        else {"exists": False, "running": False, "exit_code": None}
    )

    if state["exists"] and not out_dir.is_dir():
        return {
            "status": "failed",
            "output_dir": str(out_dir),
            "container_name": name,
            "container_running": state["running"],
            "message": "Missing scan output directory. "
            "The scan cannot provide a complete audit. Preserve container logs "
            "and investigate deleted output or a stale server before restarting.",
        }

    if state["running"]:
        return {"status": "running", "output_dir": str(out_dir)}

    if state["exists"]:
        # Container has exited — read its exit code + log, then remove it.
        container_log = ""
        if docker:
            try:
                logs = subprocess.run(
                    [docker, "logs", name], capture_output=True, text=True, timeout=60
                )
                container_log = (logs.stdout or "") + (logs.stderr or "")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        exit_code = state.get("exit_code")
        if exit_code not in (0, None) or not summary_path.exists():
            return {
                "status": "failed",
                "output_dir": str(out_dir),
                "exit_code": exit_code,
                "container_log": container_log[-600:],
                "message": "Scanner failed or exited without SUMMARY.md. "
                "Container and partial outputs retained for diagnosis.",
            }
        if docker:
            _rm_container(docker, name)
        return {
            "status": "complete",
            "output_dir": str(out_dir),
            "summary": summary_path.read_text(encoding="utf-8")
            if summary_path.exists()
            else "",
            "container_log": container_log,
        }

    # No container. If a prior run left output, treat it as complete; else the
    # scan was never started (or was cleaned up without finishing).
    if summary_path.exists():
        return {
            "status": "complete",
            "output_dir": str(out_dir),
            "summary": summary_path.read_text(encoding="utf-8"),
            "container_log": "",
        }
    return {"status": "missing", "output_dir": str(out_dir)}
