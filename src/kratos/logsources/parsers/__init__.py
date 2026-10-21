"""Parsers for the 0.3 log sources: extractor records -> `Parsed` facts.

Pure functions, one module per source, no I/O. Each turns a
logread.Record (a file line or a journal entry) into a `Parsed` -- the facts
an event needs -- or None for a line that isn't one of its events (a kernel
line that isn't a firewall line, a malformed line). events.converters
.from_parsed then makes the Event, masking credentials on the way.

`parse_read(read)` dispatches by source. The sudo source reuses the existing
auth classifier (adapters/auth_log_parse), so its events are the same kind as
the target sshd/sudo journal read's (`kratos.auth`).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# The Event attributes a parser may fill (events/model.Event). Anything else is a bug.
FIELDS: frozenset[str] = frozenset({
    "user_name", "user_id", "user_effective_name", "user_target_name", "group_name", "source_ip", "source_port",
    "process_name", "process_pid", "process_parent_pid", "process_executable", "process_command_line",
    "process_working_directory", "file_path", "service_name", "destination_ip", "destination_port",
    "network_transport", "package_name", "package_version", "url_original", "http_request_method",
    "http_response_status_code", "user_agent_original", "sequence", "log_syslog_priority",
    # C.1: what Sigma's auditd and process rules look at
    "process_args", "user_effective_id", "audit_types", "audit_key", "audit_syscall", "audit_paths",
    "audit_created_paths", "audit_session",
})
# The fields above that hold a list (in order) rather than one value.
LIST_FIELDS: frozenset[str] = frozenset({"process_args", "audit_types", "audit_paths", "audit_created_paths"})


@dataclass
class Parsed:
    ts: float
    action: str
    provider: str | None = None
    outcome: str | None = None            # None: the action table's default
    message: str | None = None
    original: str | None = None           # the raw line(s), if read from a file
    fields: dict[str, Any] = field(default_factory=dict)
    log_file_path: str | None = None
    cursor: str | None = None             # journal __CURSOR -> a stable event id
    zone_assumed: bool = False
    redacted: bool = False                # the parser masked something (e.g. a URL query value)

    def __post_init__(self) -> None:
        bad = set(self.fields) - FIELDS
        if bad:
            raise ValueError(f"not an event field: {sorted(bad)}")


# "Oct 11 17:18:01 host prog[pid]: msg", BusyBox "... host fac.lvl prog[pid]: msg",
# RFC3339 "2026-10-11T17:18:01.123+00:00 host prog[pid]: msg"
_SYSLOG = re.compile(
    r"^(?:[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) (?P<host>\S+) "
    r"(?:[a-z0-9]+\.[a-z]+ )?(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$", re.DOTALL)


def split_syslog(text: str) -> tuple[str | None, int | None, str]:
    """(program, pid, message) of a classic syslog line; (None, None, text) if
    it isn't one."""
    m = _SYSLOG.match(text or "")
    if not m:
        return None, None, text
    return m.group("prog"), int(m.group("pid")) if m.group("pid") else None, m.group("msg")


def journal_text(entry: dict[str, Any] | None) -> str:
    msg = (entry or {}).get("MESSAGE")
    if isinstance(msg, list):  # journald sends non-UTF-8 messages as a byte array
        try:
            return bytes(msg).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return ""
    return msg if isinstance(msg, str) else ""


def journal_int(entry: dict[str, Any] | None, key: str) -> int | None:
    try:
        return int((entry or {}).get(key))
    except (TypeError, ValueError):
        return None


def record_parts(rec: Any) -> tuple[str | None, int | None, str, str | None, str | None]:
    """(program, pid, message, original line, cursor) for a file line or journal entry."""
    if rec.kind == "journal":
        e = rec.entry or {}
        prog = e.get("SYSLOG_IDENTIFIER") or e.get("_COMM")
        pid = journal_int(e, "SYSLOG_PID") or journal_int(e, "_PID")
        cursor = e.get("__CURSOR") if isinstance(e.get("__CURSOR"), str) else None
        return (prog if isinstance(prog, str) else None), pid, journal_text(e), None, cursor
    prog, pid, msg = split_syslog(rec.text)
    return prog, pid, msg, rec.text, None


def parse_read(read: Any, target: str = "") -> list[Any]:
    """Parsed facts (or AuthEvents, for the sudo source) for every record of a
    logread.LogRead, newest first. Lines that aren't events are skipped."""
    from kratos.logsources.parsers import auditd, auth, cron, firewall, packages, sudo, systemd, web

    if read.source == "sudo":
        return sudo.parse(read, target)
    if read.source == "auth":
        return auth.parse(read, target)
    module = {"auditd": auditd, "cron": cron, "systemd": systemd, "firewall": firewall, "packages": packages,
              "web": web}[read.source]
    return module.parse(read)
