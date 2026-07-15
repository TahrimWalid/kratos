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


def classify_auth_message(
    ts: str,
    host: str | None,
    program: str | None,
    msg: str,
    raw: str,
) -> AuthEvent:
    """
    Core auth-event classification (SSH/sudo regex rules), factored out of
    iter_auth_events so it can be reused for input shapes that don't need
    (or don't have) the raw-syslog-line prefix parsing this module also
    does -- e.g. structured journalctl entries fetched over SSH from the
    monitored target already have timestamp/program/message split out, and
    re-serializing them into fake syslog text just to re-parse them would
    be pointless round-tripping. See iter_auth_events (local raw log
    lines) and adapters/ssh_remote.py's journalctl fetchers (structured
    entries from the remote target) for the two callers.
    """
    # --- SSH related ---
    if program and "sshd" in program:
        mm = _RE_SSH_FAIL.search(msg)
        if mm:
            return AuthEvent(ts, host, program, "ssh_failed_login", mm["user"], mm["ip"], raw)

        mm = _RE_SSH_PUBLICKEY_FAIL.search(msg)
        if mm:
            return AuthEvent(ts, host, program, "ssh_failed_login", mm["user"], mm["ip"], raw)

        mm = _RE_SSH_AUTH_FAILURE.search(msg)
        if mm:
            return AuthEvent(ts, host, program, "ssh_failed_login", mm["user"], mm["ip"], raw)

        mm = _RE_SSH_ACCEPT.search(msg)
        if mm:
            return AuthEvent(ts, host, program, "ssh_success_login", mm["user"], mm["ip"], raw)

        # Invalid user is treated as a failed login for correlation purposes.
        mm = _RE_SSH_INVALID_USER.search(msg)
        if mm:
            return AuthEvent(ts, host, program, "ssh_failed_login", mm["user"], mm["ip"], raw)

        mm = _RE_SSH_DISCONNECT.search(msg)
        if mm:
            return AuthEvent(ts, host, program, "ssh_disconnect", None, mm["ip"], raw)

        return AuthEvent(ts, host, program, "ssh_other", None, None, raw)

    # --- sudo related ---
    if program == "sudo":
        # 1) PAM auth failure (often appears before "incorrect password attempts" or standalone)
        pf = _RE_SUDO_PAM_AUTH_FAIL.search(msg)
        if pf:
            return AuthEvent(ts, host, program, "sudo_pam_auth_failure", pf["user"], None, raw)

        # 2) incorrect password attempts
        bm = _RE_SUDO_BADPW.search(msg)
        if bm:
            return AuthEvent(
                ts, host, program, "sudo_auth_failure", bm["invoker"], None,
                f"{raw} | INCORRECT_PASSWORD_ATTEMPTS={bm['count']}",
            )

        # 3) session opened
        so = _RE_SUDO_SESSION_OPEN.search(msg)
        if so:
            return AuthEvent(
                ts, host, program, "sudo_session_open", None, None,
                f"{raw} | TARGET_USER={so['target']} | BY_UID={so['by_uid']}",
            )

        # 4) session closed
        sc = _RE_SUDO_SESSION_CLOSE.search(msg)
        if sc:
            return AuthEvent(ts, host, program, "sudo_session_close", None, None, f"{raw} | TARGET_USER={sc['target']}")

        # 5) normal sudo command
        sm = _RE_SUDO_CMD.search(msg)
        if sm:
            return AuthEvent(
                ts, host, program, "sudo_command", sm["invoker"], None,
                f"{raw} | TARGET_USER={sm['target']} | COMMAND={sm['cmd'].strip()}",
            )

        return AuthEvent(ts, host, program, "sudo_other", None, None, raw)

    # Anything else in auth.log (still valuable)
    return AuthEvent(ts, host, program, "auth_other", None, None, raw)


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

        events.append(classify_auth_message(ts, host, program, msg, line))

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


def _reject_if_structured_json(path: Path, text: str) -> None:
    """
    Guard against feeding parse_auth_log its own (or anyone else's)
    normalized JSON output as if it were a raw auth log. Without this,
    iter_auth_events happily runs its syslog/ISO prefix regexes over JSON
    lines, matches nothing, and silently emits a pile of
    unparsed_auth_line garbage events instead of failing loudly. Mirrors
    the explicit-path validation findings_engine.py's correlate_findings
    already does for a similar "wrong kind of file" class of mistake.

    Cheap structural check only (first-char peek + one json.loads), not a
    log-format validator -- a real auth log's first non-whitespace
    character is never '{' or '[', so this can't false-positive on
    legitimate log content.
    """
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return

    hint = ""
    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict) and "event_type" in parsed[0]:
        hint = " (this looks like parse_auth_log's own auth_events_*.json output)"
    elif isinstance(parsed, dict) and "events_by_type" in parsed:
        hint = " (this looks like parse_auth_log's own auth_stats_*.json output)"

    raise RuntimeError(
        f"'{path}' looks like structured/normalized JSON, not a raw auth log file{hint}. "
        "parse_auth_log expects a raw log file (e.g. /var/log/auth.log or journalctl text), "
        "not JSON that parse_auth_log or another tool already produced. Do not feed a "
        "previous tool's output file back in as log_path."
    )


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
            text = log_path.read_text(encoding="utf-8", errors="replace")
            _reject_if_structured_json(log_path, text)
            lines = text.splitlines()
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
