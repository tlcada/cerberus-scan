"""Non-blocking ZAP jobs with saved results and cooperative cancellation."""

from __future__ import annotations

import copy
import json
import tempfile
import threading
import uuid
from pathlib import Path

from . import zap

_lock = threading.RLock()
_job: dict = {}
_worker: threading.Thread | None = None
_cancel = threading.Event()
STATE_DIR = Path(tempfile.gettempdir()) / "cerberus-validation"


def _save() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = STATE_DIR / (_job["job_id"] + ".json")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(_job), encoding="utf-8")
    temporary.replace(path)


def _update(**values: object) -> None:
    with _lock:
        _job.update(values)
        _save()


def _run(
    target: str,
    endpoints: list,
    tech: list[str],
    auth_headers: dict | None = None,
) -> None:
    try:
        zap.start_zap(cancel=_cancel)
        result = zap.full_active_scan(
            target,
            endpoints,
            tech,
            auth_headers=auth_headers,
            cancel=_cancel,
            progress=lambda phase: _update(phase=phase),
        )
        _update(status="partial" if result["partial"] else "complete", result=result)
    except Exception as error:
        result = {"target": target, "partial": True, "alerts": []}
        try:
            result["alerts"] = zap._collect_alerts(zap._container_url(target))
        except zap.ZapError:
            pass
        result["alert_count"] = len(result["alerts"])
        _update(
            status="cancelled" if _cancel.is_set() else "failed",
            error=str(error),
            result=result,
        )
    finally:
        if _cancel.is_set() or _job.get("status") == "failed":
            try:
                zap.stop_zap()
            except Exception as error:
                _update(cleanup_error=str(error))
            finally:
                if _cancel.is_set():
                    _update(status="cancelled")


def start(
    target: str,
    endpoints: list,
    tech: list[str],
    auth_headers: dict | None = None,
) -> dict:
    """Start once; repeated calls for an active target return the same job.

    auth_headers are handed straight to the worker thread and never stored in
    the saved job state, so bearer tokens do not land on disk.
    """
    global _job, _worker
    target = zap.guard_target(target)
    with _lock:
        if _worker is not None and _worker.is_alive():
            if _job.get("target") != target:
                raise zap.ZapError("Another validation job is active; stop it first.")
            if _job.get("endpoints", []) != endpoints or _job.get("tech", []) != tech:
                raise zap.ZapError(
                    "Validation is already active with different endpoints or technologies. "
                    "Poll validation_status, or stop it before changing scope."
                )
            return status()
        _cancel.clear()
        _job = {
            "job_id": uuid.uuid4().hex,
            "target": target,
            "endpoints": list(endpoints),
            "tech": list(tech),
            "authenticated": bool(auth_headers),
            "status": "running",
            "phase": "starting ZAP",
        }
        _save()
        _worker = threading.Thread(
            target=_run,
            args=(target, list(endpoints), list(tech), dict(auth_headers or {})),
            daemon=True,
            name="cerberus-zap",
        )
        _worker.start()
        return status()


def status(job_id: str = "", offset: int = 0, limit: int = 20) -> dict:
    """Return saved progress and a bounded page of alerts without calling ZAP."""
    with _lock:
        if not job_id or job_id == _job.get("job_id"):
            result = copy.deepcopy(_job) or {"status": "missing"}
        else:
            identifier = uuid.UUID(job_id).hex
            path = STATE_DIR / (identifier + ".json")
            if not path.is_file():
                return {"status": "missing", "job_id": identifier}
            result = json.loads(path.read_text(encoding="utf-8"))
            if result["status"] in {"running", "stopping"}:
                result.update(
                    status="interrupted",
                    error="Server restarted; saved progress is incomplete. Stop ZAP before restarting validation.",
                )
        if "result" in result:
            alerts = result["result"].get("alerts", [])
            offset = max(0, offset)
            limit = max(1, min(limit, 100))
            result["result"]["alerts"] = alerts[offset : offset + limit]
            result["offset"] = offset
            result["truncated"] = offset + limit < len(alerts)
        result["instruction"] = (
            "Poll validation_status with job_id until terminal; read all alert pages. Failed, partial or interrupted validation is a coverage gap."
        )
        return result


def snapshot(job_id: str = "") -> dict:
    """Return the complete saved result for server-side report generation.

    Unlike the MCP-facing status function, this is intentionally unpaginated:
    its result is consumed locally and summarized without entering model context.
    """
    with _lock:
        if not job_id or job_id == _job.get("job_id"):
            result = copy.deepcopy(_job) or {"status": "missing"}
        else:
            identifier = uuid.UUID(job_id).hex
            path = STATE_DIR / (identifier + ".json")
            if not path.is_file():
                return {"status": "missing", "job_id": identifier}
            result = json.loads(path.read_text(encoding="utf-8"))
            if result.get("status") in {"running", "stopping"}:
                result.update(
                    status="interrupted",
                    error="Server restarted; saved progress is incomplete.",
                )
        return result


def stop() -> dict:
    """Request cleanup without blocking an MCP call on Docker or ZAP."""
    global _worker
    with _lock:
        _cancel.set()
        if _worker is not None and _worker.is_alive():
            if _job.get("status") in {"running", "stopping"}:
                _update(status="stopping")
        else:

            def cleanup() -> None:
                try:
                    zap.stop_zap()
                except Exception as error:
                    if _job:
                        _update(cleanup_status="failed", cleanup_error=str(error))
                else:
                    if _job:
                        _update(container_stopped=True, cleanup_status="complete")

            if _job:
                _update(cleanup_status="stopping")
            _worker = threading.Thread(target=cleanup, daemon=True)
            _worker.start()
        return {
            "status": "stopping",
            "job_id": _job.get("job_id"),
            "instruction": "Cleanup requested; saved results remain available through validation_status.",
        }
