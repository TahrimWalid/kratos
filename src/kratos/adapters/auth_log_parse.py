from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


# --- Event model (normalized) ---
@dataclass
class AuthEvent:
    timestamp: str               # ISO timestamp string
    host: str | None             # hostname in the log line (if present)
    program: str | None          # sshd / sudo / etc.
    event_type: str              # ssh_failed_login, ssh_success_login, sudo_command, etc.
    user: str | None             # target user (e.g., root) or invoking user (sudo)
    source_ip: str | None        # where it came from, if available
    raw: str                     # original log line (useful for debugging & traceability)


# --- Prefix formats ---
# Example ISO:
# 2026-02-01T18:56:57.976846+02:00 OPTIMUS sudo: ...
_ISO_PREFIX = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)

# Classic syslog:
# Feb  2 00:18:01 OPTIMUS sudo: ...
_SYSLOG_PREFIX = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)

_PROGRAM_PREFIX = re.compile(
    r"^(?P<program>[A-Za-z0-9_\-/.()]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

# --- SSH patterns (common on Ubuntu/Debian) ---
_RE_SSH_FAIL = re.compile(
    r"Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_RE_SSH_PUBLICKEY_FAIL = re.compile(
    r"Failed publickey for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_RE_SSH_AUTH_FAILURE = re.compile(
    r"authentication failure.*?user=(?P<user>\S+).*?rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_RE_SSH_ACCEPT = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_RE_SSH_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_RE_SSH_DISCONNECT = re.compile(
    r"Disconnected from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# --- sudo patterns ---
# Normal sudo command line:
# walid000 : TTY=pts/0 ; PWD=/home/... ; USER=root ; COMMAND=/usr/bin/apt update
_RE_SUDO_CMD = re.compile(
    r"(?P<invoker>\S+)\s*:\s*TTY=.*;\s*PWD=.*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)

# Bonus: incorrect password attempts:
# walid000 : 3 incorrect password attempts ; TTY=... ; PWD=... ; USER=root ; COMMAND=...
_RE_SUDO_BADPW = re.compile(
    r"(?P<invoker>\S+)\s*:\s*(?P<count>\d+)\s+incorrect password attempts\s*;\s*(?P<rest>.+)$"
)

# sudo session open/close lines:
# pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)
_RE_SUDO_SESSION_OPEN = re.compile(
    r"pam_unix\(sudo:session\): session opened for user (?P<target>\S+)\(uid=\d+\) by \((?:uid=)?(?P<by_uid>\d+)\)"
)

_RE_SUDO_SESSION_CLOSE = re.compile(
    r"pam_unix\(sudo:session\): session closed for user (?P<target>\S+)"
)

# sudo pam auth failure line:
# pam_unix(sudo:auth): authentication failure; ... user=walid000
_RE_SUDO_PAM_AUTH_FAIL = re.compile(
    r"pam_unix\(sudo:auth\): authentication failure;.*\buser=(?P<user>\S+)"
)


def _parse_syslog_timestamp(mon: str, day: str, timestr: str, year: int | None = None) -> str:
    """Convert syslog timestamp (no year) into ISO."""
    if year is None:
        year = datetime.now().year
    dt = datetime.strptime(f"{year} {mon} {day} {timestr}", "%Y %b %d %H:%M:%S")
    return dt.isoformat(timespec="seconds")


def _extract_prefix(line: str) -> tuple[str, str | None, str, bool]:
    """
    Returns (timestamp_iso, host, rest, parsed_ok).
    Supports ISO prefix and classic syslog prefix.
    """
    m = _ISO_PREFIX.match(line)
    if m:
        return m["iso"], m["host"], m["rest"], True

    m = _SYSLOG_PREFIX.match(line)
    if m:
        ts = _parse_syslog_timestamp(m["mon"], m["day"], m["time"])
        return ts, m["host"], m["rest"], True

    return datetime.now().isoformat(timespec="seconds"), None, line, False


def iter_auth_events(lines: Iterable[str]) -> list[AuthEvent]:
    events: list[AuthEvent] = []

    for line in lines:
        line = line.rstrip("\n")
        if not line:
            continue

        ts, host, rest, ok = _extract_prefix(line)
        if not ok:
            events.append(
                AuthEvent(
                    timestamp=ts,
                    host=None,
                    program=None,
                    event_type="unparsed_auth_line",
                    user=None,
                    source_ip=None,
                    raw=line,
                )
            )
            continue

        pm = _PROGRAM_PREFIX.match(rest)
        program = pm["program"] if pm else None
        msg = pm["msg"] if pm else rest

        # --- SSH related ---
        if program and "sshd" in program:
            # Check for failed password
            mm = _RE_SSH_FAIL.search(msg)
            if mm:
                events.append(AuthEvent(ts, host, program, "ssh_failed_login", mm["user"], mm["ip"], line))
                continue

            # Check for failed publickey
            mm = _RE_SSH_PUBLICKEY_FAIL.search(msg)
            if mm:
                events.append(AuthEvent(ts, host, program, "ssh_failed_login", mm["user"], mm["ip"], line))
                continue
            
            # Check for generic authentication failure
            mm = _RE_SSH_AUTH_FAILURE.search(msg)
            if mm:
                events.append(AuthEvent(ts, host, program, "ssh_failed_login", mm["user"], mm["ip"], line))
                continue

            # Check for accepted login
            mm = _RE_SSH_ACCEPT.search(msg)
            if mm:
                events.append(AuthEvent(ts, host, program, "ssh_success_login", mm["user"], mm["ip"], line))
                continue

            # Check for invalid user (treat as failed login for correlation)
            mm = _RE_SSH_INVALID_USER.search(msg)
            if mm:
                events.append(AuthEvent(ts, host, program, "ssh_failed_login", mm["user"], mm["ip"], line))
                continue

            # Check for disconnect
            mm = _RE_SSH_DISCONNECT.search(msg)
            if mm:
                events.append(AuthEvent(ts, host, program, "ssh_disconnect", None, mm["ip"], line))
                continue

            events.append(AuthEvent(ts, host, program, "ssh_other", None, None, line))
            continue

        # --- sudo related ---
        if program == "sudo":
            # 1) PAM auth failure (often appears before "incorrect password attempts" or standalone)
            pf = _RE_SUDO_PAM_AUTH_FAIL.search(msg)
            if pf:
                user = pf["user"]
                events.append(
                    AuthEvent(
                        ts, host, program,
                        "sudo_pam_auth_failure",
                        user,
                        None,
                        line,
                    )
                )
                continue

            # 2) incorrect password attempts (your bonus improvement)
            bm = _RE_SUDO_BADPW.search(msg)
            if bm:
                invoker = bm["invoker"]
                count = bm["count"]
                events.append(
                    AuthEvent(
                        ts, host, program,
                        "sudo_auth_failure",
                        invoker,
                        None,
                        f"{line} | INCORRECT_PASSWORD_ATTEMPTS={count}",
                    )
                )
                continue

            # 3) session opened
            so = _RE_SUDO_SESSION_OPEN.search(msg)
            if so:
                target = so["target"]
                by_uid = so["by_uid"]
                events.append(
                    AuthEvent(
                        ts, host, program,
                        "sudo_session_open",
                        None,
                        None,
                        f"{line} | TARGET_USER={target} | BY_UID={by_uid}",
                    )
                )
                continue

            # 4) session closed
            sc = _RE_SUDO_SESSION_CLOSE.search(msg)
            if sc:
                target = sc["target"]
                events.append(
                    AuthEvent(
                        ts, host, program,
                        "sudo_session_close",
                        None,
                        None,
                        f"{line} | TARGET_USER={target}",
                    )
                )
                continue

            # 5) normal sudo command
            sm = _RE_SUDO_CMD.search(msg)
            if sm:
                invoker = sm["invoker"]
                target = sm["target"]
                cmd = sm["cmd"].strip()
                events.append(
                    AuthEvent(
                        ts, host, program,
                        "sudo_command",
                        invoker,
                        None,
                        f"{line} | TARGET_USER={target} | COMMAND={cmd}",
                    )
                )
                continue

            events.append(AuthEvent(ts, host, program, "sudo_other", None, None, line))
            continue

        # Anything else in auth.log (still valuable)
        events.append(AuthEvent(ts, host, program, "auth_other", None, None, line))

    return events


def compute_basic_stats(events: list[AuthEvent]) -> dict[str, Any]:
    by_type = Counter(e.event_type for e in events)

    by_ip_fail = Counter(e.source_ip for e in events if e.event_type == "ssh_failed_login" and e.source_ip)
    by_user_fail = Counter(e.user for e in events if e.event_type == "ssh_failed_login" and e.user)

    by_user_sudo = Counter(e.user for e in events if e.event_type == "sudo_command" and e.user)
    by_user_sudo_fail = Counter(e.user for e in events if e.event_type == "sudo_auth_failure" and e.user)
    by_user_sudo_pam_fail = Counter(e.user for e in events if e.event_type == "sudo_pam_auth_failure" and e.user)

    return {
        "total_events": len(events),
        "events_by_type": dict(by_type),
        "top_failed_login_ips": [{"ip": ip, "count": c} for ip, c in by_ip_fail.most_common(5)],
        "top_failed_login_users": [{"user": u, "count": c} for u, c in by_user_fail.most_common(5)],
        "top_sudo_users": [{"user": u, "count": c} for u, c in by_user_sudo.most_common(5)],
        "top_sudo_auth_fail_users": [{"user": u, "count": c} for u, c in by_user_sudo_fail.most_common(5)],
        "top_sudo_pam_auth_fail_users": [{"user": u, "count": c} for u, c in by_user_sudo_pam_fail.most_common(5)],
    }


def detect_auth_log_source(explicit_log_file: Path | None = None) -> tuple[str, Path | None, bool]:
    """
    Auto-detect which auth log source to use.
    
    Returns: (source_type, path_or_none, explicit_file_not_found)
    - source_type: "file", "journald", or "none"
    - path_or_none: Path if file, None otherwise
    - explicit_file_not_found: True if user provided a file that doesn't exist
    """
    # If user explicitly provided a log file
    if explicit_log_file:
        if explicit_log_file.exists():
            return ("file", explicit_log_file, False)
        else:
            # User provided a file but it doesn't exist - we'll fall back but flag it
            explicit_not_found = True
    else:
        explicit_not_found = False
    
    # Try common log file locations
    for candidate in [Path("/var/log/auth.log"), Path("/var/log/secure")]:
        if candidate.exists():
            return ("file", candidate, explicit_not_found)
    
    # Check if journalctl is available
    if shutil.which("journalctl"):
        return ("journald", None, explicit_not_found)
    
    # No source found
    return ("none", None, explicit_not_found)


def collect_journald_lines() -> tuple[list[str], list[str]]:
    """
    Collect auth-related logs from journald (sudo + sshd).
    Uses short-iso format for better timestamp consistency.
    
    Returns: (lines, units_collected)
    """
    lines = []
    units = []
    
    # Collect sudo logs
    try:
        result = subprocess.run(
            ["journalctl", "--no-pager", "-o", "short-iso", "_COMM=sudo"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            lines.extend(result.stdout.splitlines())
            units.append("sudo")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    # Collect sshd logs
    try:
        result = subprocess.run(
            ["journalctl", "--no-pager", "-o", "short-iso", "_COMM=sshd"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            lines.extend(result.stdout.splitlines())
            units.append("sshd")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    return lines, units


def parse_auth_log_file(
    data_dir: Path,
    log_path: Path | None = None,
    source: str = "auto"
) -> tuple[Path, Path, dict[str, Any]]:
    """
    Parse authentication logs from various sources.
    
    Args:
        data_dir: Where to write output files
        log_path: Explicit log file path (optional)
        source: "auto", "file", "journald", or "none"
    
    Returns: (events_file, stats_file, stats_dict)
    """
    logs_dir = data_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    source_info = ""
    source_details: dict[str, Any] = {}
    warn_explicit_not_found = False
    explicit_file_path = None
    
    # Determine source
    if source == "auto":
        detected_source, detected_path, explicit_not_found = detect_auth_log_source(log_path)
        if explicit_not_found:
            warn_explicit_not_found = True
            explicit_file_path = log_path
        source = detected_source
        if detected_path:
            log_path = detected_path
    
    # Collect lines based on source
    if source == "file":
        if not log_path or not log_path.exists():
            source = "none"  # Fallback if file doesn't exist
        else:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            source_info = f"file:{log_path}"
            source_details["file_path"] = str(log_path)
    
    elif source == "journald":
        lines, units = collect_journald_lines()
        source_info = "journald"
        if units:
            source_details["journald_units"] = units
    
    # If no source found, create empty outputs
    if source == "none" or not lines:
        events = []
        stats = {
            "source": "none",
            "total_events": 0,
            "events_by_type": {},
            "top_failed_login_ips": [],
            "top_failed_login_users": [],
            "top_sudo_users": [],
            "top_sudo_auth_fail_users": [],
            "top_sudo_pam_auth_fail_users": [],
        }
        source_info = "none"
    else:
        events = iter_auth_events(lines)
        stats = compute_basic_stats(events)
        stats["source"] = source_info
        if source_details:
            stats["source_details"] = source_details

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    events_out = logs_dir / f"auth_events_{ts}.json"
    stats_out = logs_dir / f"auth_stats_{ts}.json"

    events_out.write_text(json.dumps([asdict(e) for e in events], indent=2), encoding="utf-8")
    stats_out.write_text(json.dumps(stats, indent=2), encoding="utf-8")

    # Return warning flag for CLI to display
    if warn_explicit_not_found:
        stats["_warn_explicit_file_not_found"] = str(explicit_file_path)

    return events_out, stats_out, stats
