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
from kratos.events.model import UTC, Event, cursor_event_id, event_id
from kratos.events.redact import MASK, cap, clean, mask
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
           text: dict[str, Any], time_zone_assumed: bool = False, cursor: str | None = None, **values: Any) -> Event:
    host = ctx.host
    ident_text = text["original"] or text["message"]
    return Event(
        timestamp=timestamp,
        created=ctx.created,
        event_id=cursor_event_id(host, cursor) if cursor else event_id(host, dataset, timestamp, provider, ident_text),
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
        cursor=entry.get("cursor") if isinstance(entry.get("cursor"), str) else None,
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


# ---------------------------------------------------------------------------
# The 0.3 log sources (kratos.logsources.parsers)
# ---------------------------------------------------------------------------
PARSER_LOGSOURCE = "logsource/1"

# Parsed.action -> (event.category, event.type, default event.outcome). Every
# action a parser in kratos/logsources/parsers can return must be here (a test
# scans their source).
LOG_ACTIONS: dict[str, tuple[tuple[str, ...], tuple[str, ...], str | None]] = {
    # auditd
    "process_started": (("process",), ("start",), None),
    "user_login": (("authentication",), ("start",), None),
    "user_auth": (("authentication",), ("info",), None),
    "session_started": (("session",), ("start",), None),
    "session_ended": (("session",), ("end",), None),
    "user_added": (("iam",), ("user", "creation"), None),
    "user_deleted": (("iam",), ("user", "deletion"), None),
    "user_changed": (("iam",), ("user", "change"), None),
    "group_added": (("iam",), ("group", "creation"), None),
    "group_deleted": (("iam",), ("group", "deletion"), None),
    "group_changed": (("iam",), ("group", "change"), None),
    "password_changed": (("iam",), ("user", "change"), None),
    "audit_disabled": (("configuration",), ("change",), None),
    "audit_rule_removed": (("configuration",), ("change", "deletion"), None),
    "audit_rule_added": (("configuration",), ("change", "creation"), None),
    "audit_config_change": (("configuration",), ("change",), None),
    "auditd_started": (("configuration",), ("start",), None),
    "auditd_stopped": (("configuration",), ("end",), None),
    "auditd_aborted": (("configuration",), ("end", "error"), "failure"),
    "auditd_reconfigured": (("configuration",), ("change",), None),
    "service_started": (("process",), ("start",), None),
    "service_stopped": (("process",), ("end",), None),
    "sudo_command": (("process",), ("start",), None),
    "audit_other": ((), ("info",), "unknown"),
    # cron
    "cron_command": (("process",), ("start",), "success"),
    "cron_command_ended": (("process",), ("end",), "success"),
    "cron_session_opened": (("session",), ("start",), "success"),
    "cron_session_closed": (("session",), ("end",), "success"),
    "cron_other": ((), ("info",), "unknown"),
    # systemd
    "unit_started": (("process",), ("start",), "success"),
    "unit_starting": (("process",), ("info",), "unknown"),
    "unit_stopped": (("process",), ("end",), "success"),
    "unit_stopping": (("process",), ("info",), "unknown"),
    "unit_failed": (("process",), ("end", "error"), "failure"),
    "unit_reloaded": (("configuration",), ("change",), "success"),
    "unit_reloading": (("configuration",), ("info",), "unknown"),
    "unit_finished": (("process",), ("end",), "success"),
    "systemd_other": ((), ("info",), "unknown"),
    # firewall
    "blocked": (("network",), ("connection", "denied"), "failure"),
    "allowed": (("network",), ("connection", "allowed"), "success"),
    "audit": (("network",), ("connection", "info"), "unknown"),
    "logged": (("network",), ("connection", "info"), "unknown"),
    # packages
    "package_installed": (("package",), ("installation",), "success"),
    "package_upgraded": (("package",), ("change",), "success"),
    "package_downgraded": (("package",), ("change",), "success"),
    "package_reinstalled": (("package",), ("change",), "success"),
    "package_removed": (("package",), ("deletion",), "success"),
    "package_transaction": (("package",), ("change",), "success"),
    "package_command": (("package", "process"), ("start",), "success"),
    # web
    "http_request": (("web", "network"), ("access",), None),
    "web_error": (("web",), ("error",), "unknown"),
}
_FIELD_CAPS = {"url_original": 2048, "user_agent_original": 1024, "process_working_directory": 1024,
               "process_executable": 1024, "file_path": 4096, "network_transport": 32, "http_request_method": 32,
               "package_name": 256, "package_version": 128}


_LIST_CAPS = {"process_args": (64, 1024), "audit_types": (32, 32), "audit_paths": (32, 4096),
              "audit_created_paths": (32, 4096)}


def _scrub(original: str | None, secrets: list[str]) -> str | None:
    """The raw line(s) with each masked argument removed, as written and as auditd's
    hex encoding (EXECVE aN=..., PROCTITLE), before the usual masking and cap."""
    if not original or not secrets:
        return original
    for secret in sorted(set(secrets), key=len, reverse=True):
        if len(secret) < 2:
            continue
        original = original.replace(secret, MASK)
        hexed = secret.encode("utf-8", "surrogatepass").hex().upper()
        original = original.replace(hexed, MASK.encode().hex().upper())
    return original


def mask_args(args: list[str]) -> tuple[list[str], bool]:
    """argv with credentials masked, argument by argument. An argument is masked as
    masking it alone does, or -- when its secret only shows in context (`--password x`,
    `sshpass -p x`, `mysql -px`) -- replaced whole when masking the command line up to
    and including it changes it. Returns (args, whether anything was masked)."""
    out: list[str] = []
    changed = False
    for i, arg in enumerate(args):
        masked, red = mask(arg)
        if not red and i:
            prefix, _ = mask(" ".join(args[:i + 1]))
            if not prefix.endswith(" " + arg):
                masked, red = MASK, True
        out.append(masked)
        changed = changed or red
    return out, changed


def from_parsed(p: Any, *, ctx: ReadContext, dataset: str) -> Event:
    """A logsources.parsers.Parsed -> Event. Masks command lines, messages and the
    raw line (events.redact) and the URL's query (already masked by the web
    parser, masked again here as a backstop); caps every text field."""
    category, etype, default_outcome = LOG_ACTIONS.get(p.action, ((), ("info",), "unknown"))
    f = dict(p.fields)
    command = f.pop("process_command_line", None)
    values: dict[str, Any] = {}
    flags = {"redacted": False, "truncated": False}
    secrets: list[str] = []
    for key in _LIST_CAPS:
        items = f.pop(key, None)
        if not items:
            continue
        max_items, max_bytes = _LIST_CAPS[key]
        items = [str(v) for v in items]
        if key == "process_args":
            masked, red = mask_args(items)
            secrets = [old for old, new in zip(items, masked) if old != new]
            items, flags["redacted"] = masked, red
        if len(items) > max_items:
            items, flags["truncated"] = items[:max_items], True
        capped = []
        for v in items:
            c, cut = cap(v, max_bytes)
            flags["truncated"] = flags["truncated"] or cut
            capped.append(c)
        if key != "process_args" and key != "audit_paths":       # unordered: unique values only
            capped = list(dict.fromkeys(capped))
        values[key] = tuple(capped)
    text = _text_fields(_scrub(p.original, secrets), p.message, command)
    text["redacted"] = text["redacted"] or flags["redacted"] or bool(getattr(p, "redacted", False))
    text["truncated"] = text["truncated"] or flags["truncated"]
    for key, value in f.items():
        if key in ("source_ip", "destination_ip"):
            value = _ip(str(value))
        elif key in ("source_port", "destination_port", "process_pid", "process_parent_pid", "sequence",
                     "http_response_status_code", "log_syslog_priority"):
            try:
                value = int(value)
            except (TypeError, ValueError):
                value = None
            if key.endswith("_port") and value is not None and not 0 <= value <= 65535:
                value = None
        elif value is not None:
            value = str(value)
            if key in ("url_original", "user_agent_original"):
                value, red, cut = clean(value, _FIELD_CAPS[key])
                text["redacted"] = text["redacted"] or red
                text["truncated"] = text["truncated"] or cut
            else:
                value = _short(value, _FIELD_CAPS.get(key, 256))
        if value is not None and value != "":
            values[key] = value
    if "url_original" in values:
        from kratos.logsources.parsers.web import mask_url

        values["url_original"], red = mask_url(values["url_original"])
        text["redacted"] = text["redacted"] or red
    timestamp = datetime.fromtimestamp(float(p.ts), UTC)
    related_ip = _uniq(values.get("source_ip"), values.get("destination_ip"))
    related_user = _uniq(values.get("user_name"), values.get("user_effective_name"), values.get("user_target_name"))
    log_path = _short(p.log_file_path, 4096) or ctx.log_file_path
    use = ReadContext(target=ctx.target, transport=ctx.transport, read=ctx.read, window=ctx.window,
                      coverage=ctx.coverage, time_zone=ctx.time_zone, log_file_path=log_path, run_id=ctx.run_id,
                      created=ctx.created)
    return _build(
        use, dataset=dataset, parser=PARSER_LOGSOURCE, timestamp=timestamp, provider=_short(p.provider),
        text=text, time_zone_assumed=bool(p.zone_assumed),
        cursor=p.cursor, category=category, type=etype, outcome=p.outcome or default_outcome, action=p.action,
        related_ip=related_ip, related_user=related_user, **values,
    )
