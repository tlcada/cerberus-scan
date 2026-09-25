"""ZAP full active-scan orchestration for runtime validation.

The MCP server brings up the ZAP sibling container (compose profile
"validate"), then drives a full active scan against a user-supplied target,
scoped by the endpoints the agent flagged during code review. ZAP runs in a
container and reaches the target on the host via host.docker.internal.

Safety: the target must be local unless SEC_ALLOW_REMOTE=1 is set. Active
scanning sends many requests to the target — only run against systems you own.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import threading
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from .scan import docker_bin

ZAP_PORT = 8282
ZAP_BASE = f"http://localhost:{ZAP_PORT}"
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
LOCAL_SUFFIXES = (".local", ".test", ".localhost")

# ZAP scanner ids to run at high strength (injection classes).
STRONG_SCANNERS: Dict[str, str] = {
    "40018": "SQL Injection",
    "90020": "Command Injection",
    "90019": "Code Injection",
    "40019": "SQLi-MySQL",
    "40020": "SQLi-Hypersonic",
    "40021": "SQLi-Oracle",
    "40022": "SQLi-PostgreSQL",
    "6": "Path Traversal",
    "7": "Remote File Inclusion",
    "90023": "XXE",
    "90035": "SSTI",
    "90036": "SSTI-Blind",
    "40046": "SSRF",
    "20019": "External Redirect",
    "40015": "LDAP Injection",
    "90021": "XPath Injection",
    "40033": "NoSQL-Mongo",
    "90029": "Insecure Deserialization",
}


class ZapError(RuntimeError):
    pass


_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
# Path templates the agent may pass verbatim from a route table.
_PATH_PARAM = re.compile(r":[A-Za-z_]\w*|\{[^}/]+\}|<[^>/]+>")
# Namespace for the replacer rules that carry the caller's auth header, so a
# later job can find and clear them without knowing the header names.
_AUTH_RULE_PREFIX = "CerberusAuth:"


def normalize_vectors(endpoints: Optional[List[Any]]) -> List[Dict[str, Any]]:
    """Normalise the agent's flagged endpoints into uniform request specs.

    Accepts, per entry, a plain "/path", a "POST /path" string, or a dict with
    `path` plus optional `method`, `query`, `body`, `content_type`
    ("json"|"form") and `headers`. Route-template params (":id", "{id}", "<id>")
    collapse to "1" so ZAP fetches a concrete resource, not the literal template.
    Bodies here are ordinary request data; ZAP's active scanner supplies the
    payloads it fuzzes them with.
    """
    specs: List[Dict[str, Any]] = []
    for entry in endpoints or []:
        if isinstance(entry, str):
            parts = entry.strip().split(None, 1)
            if len(parts) == 2 and parts[0].upper() in _HTTP_METHODS:
                entry = {"method": parts[0], "path": parts[1]}
            else:
                entry = {"path": entry.strip()}
        if not isinstance(entry, dict) or not str(entry.get("path", "")).strip():
            raise ZapError(f"invalid endpoint (needs a path): {entry!r}")
        method = str(entry.get("method", "GET")).upper()
        if method not in _HTTP_METHODS:
            raise ZapError(f"unsupported HTTP method: {method}")
        content_type = str(entry.get("content_type", "json")).lower()
        if content_type not in ("json", "form"):
            raise ZapError(f"content_type must be 'json' or 'form', got {content_type!r}")
        path = "/" + _PATH_PARAM.sub("1", str(entry["path"]).strip()).lstrip("/")
        specs.append(
            {
                "method": method,
                "path": path,
                "query": entry.get("query") or {},
                "body": entry.get("body"),
                "content_type": content_type,
                "headers": entry.get("headers") or {},
            }
        )
    return specs


def _raw_http(base: str, spec: Dict[str, Any], host: str) -> str:
    """Build the raw HTTP message ZAP's sendRequest expects for one spec."""
    url = base + spec["path"]
    if spec["query"]:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(
            spec["query"], doseq=True
        )
    body = spec["body"]
    if body is None:
        payload = ""
    elif isinstance(body, str):
        payload = body
    elif spec["content_type"] == "form":
        payload = urllib.parse.urlencode(body, doseq=True)
    else:
        payload = json.dumps(body)
    headers = {"Host": host, **spec["headers"]}
    if payload or spec["method"] in ("POST", "PUT", "PATCH"):
        headers.setdefault(
            "Content-Type",
            "application/x-www-form-urlencoded"
            if spec["content_type"] == "form"
            else "application/json",
        )
        headers["Content-Length"] = str(len(payload.encode("utf-8")))
    lines = [f"{spec['method']} {url} HTTP/1.1"]
    lines += [f"{name}: {value}" for name, value in headers.items()]
    return "\r\n".join(lines) + "\r\n\r\n" + payload


def _is_local(host: str) -> bool:
    normalized_host = (host or "").lower()
    return normalized_host in LOCAL_HOSTS or any(
        normalized_host.endswith(s) for s in LOCAL_SUFFIXES
    )


def guard_target(url: str) -> str:
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
        raise ZapError(
            "target URL must include scheme and host, e.g. http://localhost:3000"
        )
    if not _is_local(parsed_url.hostname) and os.environ.get("SEC_ALLOW_REMOTE") != "1":
        raise ZapError(
            f"refusing non-local target: {parsed_url.hostname}. Active scanning is only "
            "allowed against local hosts by default. Set SEC_ALLOW_REMOTE=1 only "
            "for a host you own and are authorised to test."
        )
    return url.rstrip("/")


def _api(path: str, **params: Any) -> Dict[str, Any]:
    url = f"{ZAP_BASE}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
            response_text = response.read().decode("utf-8")
            result = json.loads(response_text)
            if isinstance(result, dict) and "code" in result and "message" in result:
                raise ZapError(f"{result['code']}: {result['message']}")
            return result
    except Exception as e:  # noqa: BLE001 - many failure modes, all wrapped as ZapError
        raise ZapError(f"ZAP API call failed ({path}): {e}") from e


def _reachable() -> bool:
    try:
        _api("/JSON/core/view/version/")
        return True
    except ZapError:
        return False


def _clear_auth_rules(runner: Callable[..., None]) -> None:
    """Remove every Cerberus auth replacer rule ZAP currently holds.

    Rules are namespaced with _AUTH_RULE_PREFIX, so a job can drop the auth
    headers a previous one installed without knowing their header names.
    """
    try:
        rules = _api("/JSON/replacer/view/rules/").get("rules", [])
    except ZapError:
        return
    for rule in rules:
        description = rule.get("description", "") if isinstance(rule, dict) else ""
        if description.startswith(_AUTH_RULE_PREFIX):
            runner("/JSON/replacer/action/removeRule/", description=description)


def compose_file() -> str:
    return str(Path(__file__).resolve().parent / "docker-compose.yml")


def _zap_image_present(docker: str) -> bool:
    try:
        proc = subprocess.run(
            [docker, "image", "inspect", ZAP_IMAGE],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _port_in_use() -> bool:
    """True if something already answers on the ZAP port that isn't our ZAP."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        return connection.connect_ex(("127.0.0.1", ZAP_PORT)) == 0


def start_zap(cancel: threading.Event | None = None) -> None:
    """Bring up the ZAP sibling container and wait for it to answer.

    The ZAP image is large (~3.7GB) and is NOT downloaded automatically — a
    download inside a tool call overruns the MCP client's timeout. It's a
    one-time prerequisite the user pulls by hand (see README). If it's missing,
    we say exactly how to get it rather than trying to fetch it here.
    """
    _check_cancel(cancel)
    if _reachable():
        return
    docker = docker_bin()
    if docker is None:
        raise ZapError(
            "Docker is not reachable from this server, so ZAP can't be started. "
            "Start Docker Desktop before launching your agent."
        )

    if _port_in_use() and not _reachable():
        raise ZapError(
            f"port {ZAP_PORT} is in use by something that isn't Cerberus-Scan's ZAP. "
            "Free the port (or stop the other process) and retry."
        )

    if not _zap_image_present(docker):
        raise ZapError(
            "the ZAP image isn't on this machine. Runtime validation needs it as "
            f"a one-time download (~3.7GB). Pull it once:\n"
            f"    docker pull {ZAP_IMAGE}\n"
            "then run the validation again. (Static scanning needs nothing extra "
            "— this is only for ZAP runtime validation.)"
        )

    _check_cancel(cancel)
    up = subprocess.run(
        [
            docker,
            "compose",
            "-f",
            compose_file(),
            "--profile",
            "validate",
            "up",
            "-d",
            "zap",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if up.returncode != 0:
        raise ZapError(f"failed to start ZAP container:\n{up.stderr[-400:]}")

    for _ in range(90):
        _check_cancel(cancel)
        if _reachable():
            return
        time.sleep(2)
    raise ZapError(
        "ZAP started but its API did not respond within 3 minutes. It may still "
        "be booting on a slow machine — retry the validation, or check "
        "`docker logs` for the ZAP container."
    )


def stop_zap() -> None:
    docker = docker_bin()
    if docker is None:
        return
    subprocess.run(
        [
            docker,
            "compose",
            "-f",
            compose_file(),
            "--profile",
            "validate",
            "stop",
            "zap",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise ZapError("Validation cancelled; coverage is incomplete.")


def _container_url(target: str) -> str:
    """Rewrite a host localhost URL to host.docker.internal for ZAP-in-container."""
    parsed_url = urlparse(target)
    if parsed_url.hostname in LOCAL_HOSTS:
        return target.replace(parsed_url.hostname, "host.docker.internal", 1)
    return target


def _wait(
    view_path: str,
    done_value: str = "100",
    cap_seconds: int = 900,
    cancel: threading.Event | None = None,
    **params: Any,
) -> bool:
    """Poll until the scan reports done_value, or the cap elapses.

    Returns True if it completed, False if it hit the time cap (partial scan).
    """
    deadline = time.time() + cap_seconds
    while time.time() < deadline:
        _check_cancel(cancel)
        status = _api(view_path, **params).get("status", "")
        if str(status) == str(done_value):
            return True
        time.sleep(3)
    return False


def _collect_alerts(target: str) -> List[Dict[str, Any]]:
    """Read every alert page and retain the fields used in the report."""
    alerts: List[Dict[str, Any]] = []
    start = 0
    while True:
        batch = _api(
            "/JSON/core/view/alerts/", baseurl=target, start=start, count=500
        ).get("alerts", [])
        if not batch:
            break
        alerts.extend(batch)
        start += 500
        if len(batch) < 500:
            break

    compact = []
    for alert in alerts:
        compact.append(
            {
                "alert": alert.get("alert", ""),
                "risk": alert.get("risk", ""),
                "confidence": alert.get("confidence", ""),
                "url": alert.get("url", ""),
                "param": alert.get("param", ""),
                "evidence": (alert.get("evidence", "") or "")[:200],
                "cweid": alert.get("cweid", ""),
            }
        )

    return compact


def full_active_scan(
    target: str,
    endpoints: Optional[List[Any]] = None,
    tech: Optional[List[str]] = None,
    *,
    auth_headers: Optional[Dict[str, str]] = None,
    cancel: threading.Event | None = None,
    progress: Callable[[str], None] | None = None,
) -> Dict[str, Any]:
    """Run a full ZAP active scan against target, seeded with flagged requests.

    Each entry in `endpoints` is normalised to a real request (method, query,
    body) and replayed through ZAP so the active scanner fuzzes the parameters
    the agent found in code, not just bare GETs. `auth_headers` are attached to
    every ZAP request so authenticated routes are reachable; their values are
    used only in-process and are never returned or written to the saved result.
    """
    target_clean = guard_target(target)
    if not _reachable():
        raise ZapError("ZAP is not running; call start_zap() first")
    specs = normalize_vectors(endpoints)

    container_target = _container_url(target_clean)
    parsed_target = urlparse(target_clean)

    def _try(path: str, **params: Any) -> None:
        _check_cancel(cancel)
        try:
            _api(path, **params)
        except ZapError:
            pass  # already exists / not applicable — fine on re-run

    def _set_header_rule(description: str, header: str, value: str) -> None:
        # Remove first so a re-run never keeps a stale value from a prior job.
        _try("/JSON/replacer/action/removeRule/", description=description)
        _try(
            "/JSON/replacer/action/addRule/",
            description=description,
            enabled="true",
            matchType="REQ_HEADER",
            matchRegex="false",
            matchString=header,
            replacement=value,
            initiators="",
            url="",
        )

    # Fix host header issues for local servers.
    host_header = (
        f"{parsed_target.hostname}:{parsed_target.port}"
        if parsed_target.port
        else str(parsed_target.hostname)
    )
    _set_header_rule("FixHost", "Host", host_header)

    # Clear any auth headers a previous job left behind, then apply this job's so
    # every spider/active-scan request is authenticated. Values are not persisted.
    _clear_auth_rules(_try)
    for header, value in (auth_headers or {}).items():
        _set_header_rule(f"{_AUTH_RULE_PREFIX}{header}", header, str(value))

    # Context scoped to the target. NB: pass the include regex RAW — _api
    # url-encodes every param once, so pre-encoding it here (urllib.parse.quote)
    # double-encodes it, the context ends up empty, and ascan's inScopeOnly then
    # scans nothing. The regex matches the container-side host+port.
    _try("/JSON/context/action/newContext/", contextName="t")
    _try(
        "/JSON/context/action/includeInContext/",
        contextName="t",
        regex=re.escape(container_target) + r"(?:/.*)?$",
    )
    if tech:
        _try("/JSON/context/action/excludeAllContextTechnologies/", contextName="t")
        _try(
            "/JSON/context/action/includeContextTechnologies/",
            contextName="t",
            technologyNames=",".join(tech),
        )

    # Reachability check + seed the site tree. ZAP runs in a container, so it
    # reaches a host target as host.docker.internal. If that fails, say exactly
    # why rather than letting the spider fail later with an opaque HTTP 400.
    try:
        _api(
            "/JSON/core/action/accessUrl/", url=container_target, followRedirects="true"
        )
    except ZapError as e:
        raise ZapError(
            f"ZAP could not reach the target from inside its container "
            f"(tried {container_target} for your {target_clean}). Runtime validation needs the "
            "app reachable from Docker. Check that:\n"
            "  - the app is actually running at that URL;\n"
            "  - it listens on all interfaces (0.0.0.0), not only 127.0.0.1 — a "
            "server bound to localhost only is often unreachable from a "
            "container;\n"
            "  - the port is correct.\n"
            "On Docker Desktop the container reaches the host as "
            "host.docker.internal (already mapped in docker-compose)."
        ) from e

    # Seed flagged endpoints as real requests. A GET with no body still goes
    # through accessUrl (cheaper); anything with a body or a non-GET method is
    # replayed via sendRequest so the active scanner has parameters to fuzz.
    for spec in specs:
        if spec["method"] == "GET" and spec["body"] is None and not spec["query"]:
            _try(
                "/JSON/core/action/accessUrl/",
                url=f"{container_target}{spec['path']}",
                followRedirects="true",
            )
        else:
            _try(
                "/JSON/core/action/sendRequest/",
                request=_raw_http(container_target, spec, host_header),
                followRedirects="true",
            )

    # Spider crawl. No contextName here: spidering the URL directly avoids the
    # "url not in context" HTTP 400, and the context still scopes the active
    # scan below (inScopeOnly). The site was just reached via accessUrl above.
    if progress:
        progress("spider")
    spider = _api("/JSON/spider/action/scan/", url=container_target, recurse="true")
    if "scan" not in spider:
        raise ZapError("ZAP did not return a spider scan ID")
    spider_params = {"scanId": spider["scan"]}
    spider_done = _wait(
        "/JSON/spider/view/status/", cap_seconds=300, cancel=cancel, **spider_params
    )
    if not spider_done:
        _api("/JSON/spider/action/stop/", **spider_params)

    # Aggressive policy settings
    _try("/JSON/ascan/action/addScanPolicy/", scanPolicyName="agg")
    for scanner_id in STRONG_SCANNERS:
        _try(
            "/JSON/ascan/action/setScannerAttackStrength/",
            id=scanner_id,
            attackStrength="HIGH",
            scanPolicyName="agg",
        )
        _try(
            "/JSON/ascan/action/setScannerAlertThreshold/",
            id=scanner_id,
            alertThreshold="LOW",
            scanPolicyName="agg",
        )

    # Active scan execution
    if progress:
        progress("active scan")
    active_scan = _api(
        "/JSON/ascan/action/scan/",
        url=container_target,
        recurse="true",
        inScopeOnly="true",
        scanPolicyName="agg",
    )
    if "scan" not in active_scan:
        raise ZapError("ZAP did not return an active scan ID")
    active_params = {"scanId": active_scan["scan"]}
    ascan_done = _wait(
        "/JSON/ascan/view/status/", cap_seconds=900, cancel=cancel, **active_params
    )
    if not ascan_done:
        _api("/JSON/ascan/action/stop/", **active_params)

    # Wait for passive scan queue to clear
    for _ in range(60):
        _check_cancel(cancel)
        pending_records = _api("/JSON/pscan/view/recordsToScan/").get(
            "recordsToScan", "0"
        )
        if str(pending_records) == "0":
            break
        time.sleep(2)

    if progress:
        progress("collecting alerts")
    compact = _collect_alerts(container_target)
    # Drop the auth headers from ZAP so they do not linger for an unrelated
    # later target; the saved result never carried them in the first place.
    _clear_auth_rules(_try)

    return {
        "target": target_clean,
        "endpoints_seeded": [f"{s['method']} {s['path']}" for s in specs],
        "authenticated": bool(auth_headers),
        "spider_completed": spider_done,
        "active_scan_completed": ascan_done,
        "partial": not (spider_done and ascan_done),
        "alert_count": len(compact),
        "alerts": compact,
    }
