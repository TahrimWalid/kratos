"""
Read-only local telemetry collection for the Kratos sub-agent (capability 1
-- docs/subagent_architecture.md). Runs ON the monitored target as the
sub-agent's own process.

Every external command below is a FIXED argv list -- no shell=True, no
caller-supplied or model-supplied argv, matching the same no-injection bar
every other target-facing Kratos tool holds (see agent/tools.py). Nothing
here writes, mutates, or executes anything the operator didn't already fix at
write time; this module can only ever produce a read-only snapshot.

Every collect_* function fails soft: a missing binary, a permission error, or
a timeout is recorded as an "error"/"ok": False field in that section instead
of raising, so one unavailable data source (e.g. no permission to read
journal entries) never takes down the rest of the snapshot. This follows the
same partial-failure rule the rest of Kratos holds: an item that can't be
resolved is reported as unknown/errored, never silently dropped -- a missing
data point is itself information.

Stdlib-only, no kratos-internal imports -- see protocol.py's module
docstring for why (this file ships as a sibling of agent.py/protocol.py
directly onto the target).
"""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import socket
import subprocess
import time
from typing import Any

DEFAULT_WATCH_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
]
DEFAULT_SERVICE_WATCHLIST = ["ssh", "sshd", "fail2ban", "cron"]
_CMD_TIMEOUT_SECONDS = 8


def _run(argv: list[str]) -> dict[str, Any]:
    """Run one fixed, read-only command. Never raises, never uses a shell."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=_CMD_TIMEOUT_SECONDS)
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip()[:2000],
        }
    except FileNotFoundError:
        return {"ok": False, "error": f"{argv[0]} not installed"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"{argv[0]} timed out after {_CMD_TIMEOUT_SECONDS}s"}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def _uptime_seconds() -> float | None:
    try:
        with open("/proc/uptime") as f:
            return float(f.readline().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def collect_host_info() -> dict[str, Any]:
    try:
        load1, load5, load15 = os.getloadavg()
    except (OSError, AttributeError):
        load1 = load5 = load15 = None
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "uptime_seconds": _uptime_seconds(),
        "load_avg": {"1m": load1, "5m": load5, "15m": load15},
    }


def collect_disk_usage(path: str = "/") -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
        used_pct = round(usage.used / usage.total * 100, 1) if usage.total else None
        return {
            "ok": True,
            "path": path,
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "used_pct": used_pct,
        }
    except OSError as e:
        return {"ok": False, "path": path, "error": str(e)}


def collect_listening_ports() -> dict[str, Any]:
    result = _run(["ss", "-tlnH"])
    if not result.get("ok"):
        return result
    ports: set[str] = set()
    for line in result["stdout"].splitlines():
        parts = line.split()
        if len(parts) >= 4 and ":" in parts[3]:
            ports.add(parts[3].rsplit(":", 1)[-1])
    return {"ok": True, "listening_ports": sorted(ports)}


def collect_process_count() -> dict[str, Any]:
    result = _run(["ps", "-e", "--no-headers"])
    if not result.get("ok"):
        return result
    lines = [line for line in result["stdout"].splitlines() if line.strip()]
    return {"ok": True, "process_count": len(lines)}


def collect_service_states(services: list[str] | None = None) -> dict[str, Any]:
    services = DEFAULT_SERVICE_WATCHLIST if services is None else services
    states: dict[str, str] = {}
    for name in services:
        r = _run(["systemctl", "is-active", name])
        states[name] = (r.get("stdout") or r.get("error") or "unknown").strip()
    return {"services": states}


def collect_file_hashes(paths: list[str] | None = None) -> dict[str, Any]:
    paths = DEFAULT_WATCH_FILES if paths is None else paths
    hashes: dict[str, Any] = {}
    for path in paths:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            hashes[path] = h.hexdigest()
        except FileNotFoundError:
            hashes[path] = None  # absent is informative on its own, not an error.
        except PermissionError:
            hashes[path] = "permission_denied"
        except OSError as e:
            hashes[path] = f"error: {e}"
    return {"file_hashes": hashes}


def collect_auth_summary(since_minutes: int = 60) -> dict[str, Any]:
    r = _run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", f"-{since_minutes}min", "--no-pager", "-o", "cat"])
    if not r.get("ok"):
        return {"ok": False, "since_minutes": since_minutes, "error": r.get("error") or r.get("stderr") or "journalctl unavailable"}
    failed = accepted = 0
    for line in r["stdout"].splitlines():
        if "Failed password" in line or "Invalid user" in line:
            failed += 1
        elif "Accepted password" in line or "Accepted publickey" in line:
            accepted += 1
    return {"ok": True, "since_minutes": since_minutes, "failed_logins": failed, "accepted_logins": accepted}


def collect_snapshot(
    *,
    watch_files: list[str] | None = None,
    services: list[str] | None = None,
    auth_since_minutes: int = 60,
) -> dict[str, Any]:
    """One full read-only telemetry snapshot. Every section is best-effort
    independently (see module docstring) -- a failure in one never blocks
    the others."""
    return {
        "collected_at_epoch": time.time(),
        "host": collect_host_info(),
        "disk": collect_disk_usage(),
        "listening_ports": collect_listening_ports(),
        "processes": collect_process_count(),
        "services": collect_service_states(services),
        "file_hashes": collect_file_hashes(watch_files),
        "auth": collect_auth_summary(auth_since_minutes),
    }
