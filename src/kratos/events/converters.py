"""Existing parser outputs -> Events. Pure functions, table-driven, no I/O.

The parsers are not rewritten (detection keeps working exactly as before);
these map what they already produce:

  * `from_auth_event`       -- adapters/auth_log_parse.AuthEvent (local auth.log
                               lines and the target's sshd/sudo journal)
  * `from_journal_entry`    -- ssh_remote._parse_journal_entry dicts (any unit)
  * `from_privileged_event` -- privileged_accounts.parse_event dicts

Times: journald and privileged-account times are absolute already. A classic
syslog line (`Oct  9 13:01:02`) has no zone and no year; it is read in the
machine's zone when known, else as UTC with `kratos.time_zone_assumed`, and a
line dated more than a day in the future belongs to the previous year (reading
December's log in January).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, tzinfo
from typing import Any

from kratos import run_context
from kratos.adapters.auth_log_parse import AuthEvent, _ISO_PREFIX, _PROGRAM_PREFIX, _SYSLOG_PREFIX
from kratos.events import fields as F
from kratos.events.model import UTC, Event, event_id
from kratos.events.redact import clean
from kratos.target_key import target_key

PARSER_AUTH = "auth_log/1"
PARSER_JOURNAL = "journal/1"
PARSER_PRIVILEGED = "privileged_accounts/1"

# The named reads (kratos.read).
READ_AUTH_LOG = "auth_log"                     # a local auth.log / secure file, or local journald text
READ_JOURNAL_AUTH = "journal_auth"             # the target's sshd/sudo journal
READ_JOURNAL_FETCH = "journal_fetch"           # the target's journal, any unit
READ_PRIVILEGED = "privileged_accounts"

DATASET_AUTH = "kratos.auth"
DATASET_JOURNAL = "kratos.journal"
DATASET_PRIVILEGED = "kratos.privileged_accounts"

# AuthEvent.event_type -> (event.category, event.type, event.outcome). Every type
# classify_auth_message / iter_auth_events can return must be here (a test scans
# their source).
AUTH_EVENT_TYPES: dict[str, tuple[tuple[str, ...], tuple[str, ...], str]] = {
    "ssh_failed_login": (("authentication",), ("start",), "failure"),
    "ssh_success_login": (("authentication",), ("start",), "success"),
    "ssh_disconnect": (("session",), ("end",), "unknown"),
    "sudo_command": (("process",), ("start",), "success"),
    "sudo_auth_failure": (("authentication",), ("start",), "failure"),
    "sudo_pam_auth_failure": (("authentication",), ("start",), "failure"),
    "sudo_session_open": (("session",), ("start",), "success"),
    "sudo_session_close": (("session",), ("end",), "success"),
    "ssh_other": ((), ("info",), "unknown"),
    "sudo_other": ((), ("info",), "unknown"),
    "auth_other": ((), ("info",), "unknown"),
    "unparsed_auth_line": ((), ("info",), "unknown"),
}

# privileged_accounts action -> (event.category, event.type). Every action in its
# _EVENT_PATTERNS must be here (a test scans them).
PRIVILEGED_ACTIONS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "added_to_group": (("iam",), ("group", "change")),
    "removed_from_group": (("iam",), ("group", "change")),
    "user_created": (("iam",), ("user", "creation")),
    "user_deleted": (("iam",), ("user", "deletion")),
    "uid_changed": (("iam",), ("user", "change")),
}

_UNIT_SUFFIXES = (".service", ".scope", ".socket", ".timer", ".mount", ".target", ".slice", ".path",
                  ".device", ".swap", ".automount")
# What classify_auth_message appends to AuthEvent.raw (not part of the real line).
_CLASSIFIER_SUFFIX = re.compile(r" \| (?:TARGET_USER|INCORRECT_PASSWORD_ATTEMPTS)=.*$", re.DOTALL)
_SUFFIX_FIELD = re.compile(r" \| (?P<key>[A-Z_]+)=(?P<val>.*?)(?= \| [A-Z_]+=|$)", re.DOTALL)
_SSH_PORT = re.compile(r"\bport (?P<port>\d{1,5})\b")
_SUDO_TARGET = re.compile(r";\s*USER=(?P<target>\S+)\s*;")
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
                                       "Oct", "Nov", "Dec"), start=1)}


@dataclass(frozen=True)
class ReadContext:
    """What the converters need to know about the read a line came from."""
    target: str                                   # the machine (any spelling; stored as target_key)
    transport: str                                # ssh / agent / local
    read: str                                     # the named read, e.g. journal_auth
    window: tuple[float | None, float | None] | None = None
    coverage: str | None = None                   # complete / truncated / sampled
    time_zone: tzinfo | None = None               # the machine's zone, for zone-less times
    log_file_path: str | None = None
    run_id: str | None = field(default_factory=run_context.current_run_id)
    created: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def host(self) -> str:
        return target_key(self.target)


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------
def syslog_time(mon: str, day: int, hms: str, *, zone: tzinfo | None, now: datetime) -> tuple[datetime, bool]:
    """A classic syslog time as an absolute UTC instant, and whether the zone was
    assumed (UTC). The year is the machine's current one, minus one if that puts
    the line more than a day in the future; Feb 29 goes back to the last leap year."""
    tz = zone or UTC
    local_now = now.astimezone(tz)
    hour, minute, second = (int(x) for x in hms.split(":"))
    month = _MONTHS[mon]
    for year in range(local_now.year, local_now.year - 9, -1):
        try:
            dt = datetime(year, month, int(day), hour, minute, second, tzinfo=tz)
        except ValueError:  # Feb 29 outside a leap year
            continue
        if dt <= local_now + timedelta(days=1):
            return dt.astimezone(UTC), zone is None
    raise ValueError(f"no plausible year for {mon} {day} {hms}")


def _parse_any_time(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(UTC) if dt.tzinfo else None


# ---------------------------------------------------------------------------
# Shared assembly
# ---------------------------------------------------------------------------
def _text_fields(original: str | None, message: str | None, command_line: str | None) -> dict[str, Any]:
    original, r1, t1 = clean(original, F.ORIGINAL_MAX_BYTES)
    message, r2, t2 = clean(message, F.MESSAGE_MAX_BYTES)
    command_line, r3, t3 = clean(command_line, F.COMMAND_LINE_MAX_BYTES)
    return {"original": original or None, "message": message or None, "process_command_line": command_line or None,
            "redacted": r1 or r2 or r3, "truncated": t1 or t2 or t3}


def _short(value: Any, limit: int = 256) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    raw = text.encode("utf-8", "surrogatepass")
    return raw[:limit].decode("utf-8", "ignore") if len(raw) > limit else text


def _uniq(*values: str | None) -> tuple[str, ...]:
    seen: list[str] = []
    for v in values:
        if v and v not in seen:
            seen.append(v)
    return tuple(seen)


def _build(ctx: ReadContext, *, dataset: str, parser: str, timestamp: datetime, provider: str | None,
           text: dict[str, Any], time_zone_assumed: bool = False, **values: Any) -> Event:
    host = ctx.host
    ident_text = text["original"] or text["message"]
    return Event(
        timestamp=timestamp,
        created=ctx.created,
        event_id=event_id(host, dataset, timestamp, provider, ident_text),
        kind="event",
        dataset=dataset,
        provider=provider,
        host_name=host,
        transport=ctx.transport,
        read=ctx.read,
        run_id=ctx.run_id,
        window=ctx.window,
        coverage=ctx.coverage,
        log_file_path=ctx.log_file_path,
        parser=parser,
        time_zone_assumed=time_zone_assumed,
        **text,
        **values,
    )


def _ip(value: str | None) -> str | None:
    import ipaddress

    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# AuthEvent
# ---------------------------------------------------------------------------
def from_auth_event(ev: AuthEvent, *, ctx: ReadContext) -> Event:
    category, etype, outcome = AUTH_EVENT_TYPES.get(ev.event_type, ((), ("info",), "unknown"))
    suffix = {m["key"]: m["val"].strip() for m in _SUFFIX_FIELD.finditer(ev.raw)}
    raw_line = _CLASSIFIER_SUFFIX.sub("", ev.raw)

    # The message part (after "host program[pid]:") and the pid, when the raw
    # line carries the syslog prefix; journal lines arrive as the message itself.
    message, pid, assumed = raw_line, None, False
    timestamp = None
    # Only whole log lines carry a prefix; a journal read hands over the message alone.
    prefix = (_ISO_PREFIX.match(raw_line) or _SYSLOG_PREFIX.match(raw_line)) if ctx.read == READ_AUTH_LOG else None
    if prefix:
        pm = _PROGRAM_PREFIX.match(prefix["rest"])
        if pm:
            message = pm["msg"]
            pid = int(pm["pid"]) if pm["pid"] else None
        else:
            message = prefix["rest"]
        if "mon" in prefix.groupdict():
            timestamp, assumed = syslog_time(prefix["mon"], int(prefix["day"]), prefix["time"],
                                             zone=ctx.time_zone, now=ctx.created)
    if timestamp is None and ev.event_type != "unparsed_auth_line":
        timestamp = _parse_any_time(ev.timestamp)
    if timestamp is None:
        # No time in the source (an unparsed line): ECS's rule -- when it was received.
        timestamp = ctx.created

    user_name = _short(ev.user)
    user_id = effective = command = None
    if ev.event_type == "sudo_command":
        effective = _short(suffix.get("TARGET_USER"))
        command = suffix.get("COMMAND")
    elif ev.event_type == "sudo_session_open":
        effective = _short(suffix.get("TARGET_USER"))
        by_uid = suffix.get("BY_UID")
        user_id = by_uid if by_uid and by_uid.isdigit() else None
    elif ev.event_type == "sudo_session_close":
        effective = _short(suffix.get("TARGET_USER"))
    elif ev.event_type == "sudo_auth_failure":
        target = _SUDO_TARGET.search(raw_line)
        effective = _short(target["target"]) if target else None

    # A sudo-run command is a process event about the COMMAND (ECS): its process.*
    # fields describe what was started; sudo is the provider and the parent.
    executable, process_name, parent_pid = None, _short(ev.program), None
    if ev.event_type == "sudo_command" and command:
        first = command.split(None, 1)[0]
        executable = first if first.startswith("/") else None
        process_name = _short(first.rsplit("/", 1)[-1])
        parent_pid, pid = pid, None

    source_ip = _ip(ev.source_ip)
    port = None
    if source_ip and ev.program and "ssh" in ev.program:
        pm = _SSH_PORT.search(message)
        port = int(pm["port"]) if pm and int(pm["port"]) <= 65535 else None
    program = _short(ev.program)
    return _build(
        ctx, dataset=DATASET_AUTH, parser=PARSER_AUTH, timestamp=timestamp, provider=program,
        text=_text_fields(raw_line if prefix else None, message, command),
        time_zone_assumed=assumed,
        category=category, type=etype, outcome=outcome, action=ev.event_type,
        user_name=user_name, user_id=user_id, user_effective_name=effective,
        source_ip=source_ip, source_port=port,
        process_name=process_name, process_pid=pid, process_parent_pid=parent_pid,
        process_executable=_short(executable, 1024),
        related_ip=_uniq(source_ip), related_user=_uniq(user_name, effective),
    )


# ---------------------------------------------------------------------------
# Journal entries (any unit)
# ---------------------------------------------------------------------------
def from_journal_entry(entry: dict[str, Any], *, ctx: ReadContext) -> Event:
    unit = _short(entry.get("unit"))
    is_unit = bool(unit) and unit.endswith(_UNIT_SUFFIXES)
    priority = entry.get("priority")
    try:
        priority = int(priority) if priority is not None and str(priority).strip() != "" else None
    except (TypeError, ValueError):
        priority = None
    if priority is not None and not 0 <= priority <= 7:
        priority = None
    message = entry.get("message")
    if isinstance(message, list):  # journald sends non-UTF-8 messages as a byte array
        try:
            message = bytes(message).decode("utf-8", "replace")
        except (TypeError, ValueError):
            message = None
    timestamp = _parse_any_time(entry.get("timestamp")) or ctx.created
    return _build(
        ctx, dataset=DATASET_JOURNAL, parser=PARSER_JOURNAL, timestamp=timestamp,
        provider=None if is_unit else unit,
        text=_text_fields(None, str(message) if message is not None else None, None),
        type=("info",), service_name=unit if is_unit else None,
        process_name=None if is_unit else unit, log_syslog_priority=priority,
    )


# ---------------------------------------------------------------------------
# Privileged-account changes
# ---------------------------------------------------------------------------
def from_privileged_event(ev: dict[str, Any], *, ctx: ReadContext) -> Event:
    action = str(ev.get("action") or "")
    category, etype = PRIVILEGED_ACTIONS.get(action, ((), ("info",)))
    timestamp = datetime.fromtimestamp(float(ev["ts"]), UTC)
    provider = _short(ev.get("source"))
    account = _short(ev.get("user"))
    group = _short(ev.get("group"))
    return _build(
        ctx, dataset=DATASET_PRIVILEGED, parser=PARSER_PRIVILEGED, timestamp=timestamp, provider=provider,
        text=_text_fields(None, ev.get("message"), None),
        category=category, type=etype, outcome="success", action=action or None,
        user_target_name=account, group_name=group, process_name=provider,
        related_user=_uniq(account),
    )
