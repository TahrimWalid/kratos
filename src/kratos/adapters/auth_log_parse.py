from __future__ import annotations

import json
import re
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
            mm = _RE_SSH_FAIL.search(msg)
            if mm:
                events.append(AuthEvent(ts, host, program, "ssh_failed_login", mm["user"], mm["ip"], line))
                continue

            mm = _RE_SSH_ACCEPT.search(msg)
            if mm:
                events.append(AuthEvent(ts, host, program, "ssh_success_login", mm["user"], mm["ip"], line))
                continue

            mm = _RE_SSH_INVALID_USER.search(msg)
            if mm:
                events.append(AuthEvent(ts, host, program, "ssh_invalid_user", mm["user"], mm["ip"], line))
                continue

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


def parse_auth_log_file(data_dir: Path, log_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    logs_dir = data_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    if not log_path.exists():
        raise RuntimeError(f"Log file not found: {log_path}")

    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    events = iter_auth_events(lines)
    stats = compute_basic_stats(events)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    events_out = logs_dir / f"auth_events_{ts}.json"
    stats_out = logs_dir / f"auth_stats_{ts}.json"

    events_out.write_text(json.dumps([asdict(e) for e in events], indent=2), encoding="utf-8")
    stats_out.write_text(json.dumps(stats, indent=2), encoding="utf-8")

    return events_out, stats_out, stats
