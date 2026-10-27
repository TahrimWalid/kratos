"""Parser output -> event values, the part shared by Kratos and its agents (C.2).

`events.converters` builds an Event from these values on Kratos; the agent's
watcher (kratos.subagent.watch) builds the flat {ECS field: value} dict the
detection evaluator reads from the SAME values, so a log line is judged the same
way whether a rule looked at it on the agent or over the stored events. A parity
test feeds the same lines to both sides.

Standard-library Python 3.8, no kratos imports: this file ships in the agent
bundle as `event_assemble.py` beside `event_fields.py` (events/fields.py),
`event_redact.py` (events/redact.py) and `auth_log_parse.py`.

Event IDs live here too (events.model re-exports them): an agent computes the
same ID Kratos stores for a line, so a detection the agent raises names the event
log sync stores later.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # in the agent bundle: sibling modules
    from . import auth_log_parse, event_fields as F, event_redact as R  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:  # Kratos (the same files under their package names)
        from kratos.adapters import auth_log_parse
        from kratos.events import fields as F
        from kratos.events import redact as R
    except ImportError:  # run directly
        import auth_log_parse  # type: ignore[no-redef]
        import event_fields as F  # type: ignore[no-redef]
        import event_redact as R  # type: ignore[no-redef]

UTC = timezone.utc

PARSER_AUTH = "auth_log/1"
PARSER_LOGSOURCE = "logsource/1"
DATASET_AUTH = "kratos.auth"

# AuthEvent.event_type -> (event.category, event.type, event.outcome). Every type
# classify_auth_message / iter_auth_events can return must be here (a test scans
# their source).
AUTH_EVENT_TYPES: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...], str]] = {
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
    # account management (shadow-utils), Phase C audit
    "account_created": (("iam",), ("user", "creation"), "success"),
    "account_added_to_group": (("iam",), ("group", "change"), "success"),
    "account_changed": (("iam",), ("user", "change"), "success"),
    "account_deleted": (("iam",), ("user", "deletion"), "success"),
    "account_password_changed": (("iam",), ("user", "change"), "success"),
    "account_group_created": (("iam",), ("group", "creation"), "success"),
    "account_other": (("iam",), ("info",), "unknown"),
}

# Parsed.action -> (event.category, event.type, default event.outcome). Every
# action a parser in kratos/logsources/parsers can return must be here (a test
# scans their source).
LOG_ACTIONS: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...], Optional[str]]] = {
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
    "crontab_replaced": (("configuration",), ("change",), "success"),
    "crontab_deleted": (("configuration",), ("change", "deletion"), "success"),
    "crontab_edit_started": (("configuration",), ("info",), "success"),
    "crontab_edited": (("configuration",), ("change",), "success"),
    "crontab_listed": (("configuration",), ("access",), "success"),
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
    # a program crashed (the kernel's segfault / protection-fault line, Apache's "exit signal")
    "process_crashed": (("process",), ("end", "error"), "failure"),
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
FIELD_CAPS = {"url_original": 2048, "user_agent_original": 1024, "process_working_directory": 1024,
              "process_executable": 1024, "file_path": 4096, "network_transport": 32, "http_request_method": 32,
              "package_name": 256, "package_version": 128}
LIST_CAPS = {"process_args": (64, 1024), "audit_types": (32, 32), "audit_paths": (32, 4096),
             "audit_created_paths": (32, 4096)}
_INT_FIELDS = ("source_port", "destination_port", "process_pid", "process_parent_pid", "sequence",
               "http_response_status_code", "log_syslog_priority")

# What classify_auth_message appends to AuthEvent.raw (not part of the real line).
_CLASSIFIER_SUFFIX = re.compile(r" \| (?:TARGET_USER|INCORRECT_PASSWORD_ATTEMPTS)=.*$", re.DOTALL)
_SUFFIX_FIELD = re.compile(r" \| (?P<key>[A-Z_]+)=(?P<val>.*?)(?= \| [A-Z_]+=|$)", re.DOTALL)
_SSH_PORT = re.compile(r"\bport (?P<port>\d{1,5})\b")
_SUDO_TARGET = re.compile(r";\s*USER=(?P<target>\S+)\s*;")
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
                                       "Oct", "Nov", "Dec"), start=1)}
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


# ---------------------------------------------------------------------------
# IDs and times
# ---------------------------------------------------------------------------
def format_timestamp(dt: datetime) -> str:
    """ISO 8601 UTC with microseconds and a Z, e.g. 2026-10-11T09:01:02.000123Z."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def event_id(host: str, dataset: str, timestamp: datetime, provider: Optional[str], text: Optional[str]) -> str:
    """Deterministic ID: the first 32 hex chars of
    sha256(host ␟ dataset ␟ @timestamp in µs ␟ provider ␟ original-or-message),
    with U+001F (unit separator) between the parts. The same line read twice
    (overlapping windows) gets the same ID, so it is stored once.

    Known limit: two genuinely identical lines from the same program in the same
    microsecond collapse into one event. Journal entries that carry their
    __CURSOR use cursor_event_id instead (0.3) -- except the sudo/sshd auth
    events (kratos.auth), which keep this ID so the same line read by the auth
    read and by the sudo source is still stored once."""
    micros = int(round(timestamp.astimezone(UTC).timestamp() * 1_000_000))
    raw = "\x1f".join((host, dataset, str(micros), provider or "", text or ""))
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def cursor_event_id(host: str, cursor: str) -> str:
    """A journal entry's ID from its own __CURSOR: the first 32 hex chars of
    sha256(host ␟ cursor). Unique per entry even for identical lines in the same
    microsecond, and the same however often the entry is read."""
    raw = "\x1f".join((host, cursor))
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def syslog_time(mon: str, day: int, hms: str, *, zone: Optional[tzinfo], now: datetime) -> Tuple[datetime, bool]:
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
    raise ValueError("no plausible year for %s %s %s" % (mon, day, hms))


def parse_any_time(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(UTC) if dt.tzinfo else None


# ---------------------------------------------------------------------------
# Text and values
# ---------------------------------------------------------------------------
def text_fields(original: Optional[str], message: Optional[str], command_line: Optional[str]) -> Dict[str, Any]:
    original, r1, t1 = R.clean(original, F.ORIGINAL_MAX_BYTES)
    message, r2, t2 = R.clean(message, F.MESSAGE_MAX_BYTES)
    command_line, r3, t3 = R.clean(command_line, F.COMMAND_LINE_MAX_BYTES)
    return {"original": original or None, "message": message or None, "process_command_line": command_line or None,
            "redacted": r1 or r2 or r3, "truncated": t1 or t2 or t3}


def short(value: Any, limit: int = 256) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    raw = text.encode("utf-8", "surrogatepass")
    return raw[:limit].decode("utf-8", "ignore") if len(raw) > limit else text


def uniq(*values: Optional[str]) -> Tuple[str, ...]:
    seen: List[str] = []
    for v in values:
        if v and v not in seen:
            seen.append(v)
    return tuple(seen)


def ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def build_values(*, host: str, dataset: str, parser: str, timestamp: datetime, provider: Optional[str],
                 text: Dict[str, Any], time_zone_assumed: bool = False, cursor: Optional[str] = None,
                 **values: Any) -> Dict[str, Any]:
    """The Event's attributes that come from the line (not from the read that found it:
    created, transport, read, run id, window and coverage are the caller's)."""
    ident_text = text["original"] or text["message"]
    return dict(
        timestamp=timestamp,
        event_id=cursor_event_id(host, cursor) if cursor else event_id(host, dataset, timestamp, provider, ident_text),
        kind="event",
        dataset=dataset,
        provider=provider,
        host_name=host,
        parser=parser,
        time_zone_assumed=time_zone_assumed,
        **text,
        **values,
    )


# ---------------------------------------------------------------------------
# An AuthEvent (adapters/auth_log_parse) -> values
# ---------------------------------------------------------------------------
def auth_values(ev: Any, *, host: str, line_prefix: bool, time_zone: Optional[tzinfo],
                created: datetime) -> Dict[str, Any]:
    """`line_prefix`: the raw line may carry a syslog/ISO prefix (a whole log line read
    from a file); journal reads hand over the message alone."""
    category, etype, outcome = AUTH_EVENT_TYPES.get(ev.event_type, ((), ("info",), "unknown"))
    suffix = {m["key"]: m["val"].strip() for m in _SUFFIX_FIELD.finditer(ev.raw)}
    raw_line = _CLASSIFIER_SUFFIX.sub("", ev.raw)

    # The message part (after "host program[pid]:") and the pid, when the raw
    # line carries the syslog prefix; journal lines arrive as the message itself.
    message, pid, assumed = raw_line, None, False
    timestamp = None
    prefix = ((auth_log_parse._ISO_PREFIX.match(raw_line) or auth_log_parse._SYSLOG_PREFIX.match(raw_line))
              if line_prefix else None)
    if prefix:
        pm = auth_log_parse._PROGRAM_PREFIX.match(prefix["rest"])
        if pm:
            message = pm["msg"]
            pid = int(pm["pid"]) if pm["pid"] else None
        else:
            message = prefix["rest"]
        if "mon" in prefix.groupdict():
            timestamp, assumed = syslog_time(prefix["mon"], int(prefix["day"]), prefix["time"],
                                             zone=time_zone, now=created)
    if pid is None and isinstance(getattr(ev, "pid", None), int):
        pid = ev.pid
    if timestamp is None and ev.event_type != "unparsed_auth_line":
        timestamp = parse_any_time(ev.timestamp)
    if timestamp is None:
        # No time in the source (an unparsed line): ECS's rule -- when it was received.
        timestamp = created

    user_name = short(ev.user)
    user_id = effective = command = None
    if ev.event_type == "sudo_command":
        effective = short(suffix.get("TARGET_USER"))
        command = suffix.get("COMMAND")
    elif ev.event_type == "sudo_session_open":
        effective = short(suffix.get("TARGET_USER"))
        by_uid = suffix.get("BY_UID")
        user_id = by_uid if by_uid and by_uid.isdigit() else None
    elif ev.event_type == "sudo_session_close":
        effective = short(suffix.get("TARGET_USER"))
    elif ev.event_type == "sudo_auth_failure":
        target = _SUDO_TARGET.search(raw_line)
        effective = short(target["target"]) if target else None
    group_name = None
    if ev.event_type.startswith("account_"):
        uid = suffix.get("UID")
        user_id = uid if uid and uid.isdigit() else None
        group_name = short(suffix.get("GROUP"))

    # A sudo-run command is a process event about the COMMAND (ECS): its process.*
    # fields describe what was started; sudo is the provider and the parent.
    executable, process_name, parent_pid = None, short(ev.program), None
    if ev.event_type == "sudo_command" and command:
        first = command.split(None, 1)[0]
        executable = first if first.startswith("/") else None
        process_name = short(first.rsplit("/", 1)[-1])
        parent_pid, pid = pid, None

    source_ip = ip(ev.source_ip)
    port = None
    if source_ip and ev.program and "ssh" in ev.program:
        pm = _SSH_PORT.search(message)
        port = int(pm["port"]) if pm and int(pm["port"]) <= 65535 else None
    program = short(ev.program)
    return build_values(
        host=host, dataset=DATASET_AUTH, parser=PARSER_AUTH, timestamp=timestamp, provider=program,
        text=text_fields(raw_line if prefix else None, message, command),
        time_zone_assumed=assumed,
        category=category, type=etype, outcome=outcome, action=ev.event_type,
        user_name=user_name, user_id=user_id, user_effective_name=effective,
        source_ip=source_ip, source_port=port,
        process_name=process_name, process_pid=pid, process_parent_pid=parent_pid,
        process_executable=short(executable, 1024),
        related_ip=uniq(source_ip), related_user=uniq(user_name, effective),
        **({"group_name": group_name} if group_name else {}),
    )


# ---------------------------------------------------------------------------
# A logsources.parsers.Parsed -> values
# ---------------------------------------------------------------------------
def scrub(original: Optional[str], secrets: List[str]) -> Optional[str]:
    """The raw line(s) with each masked argument removed, as written and as auditd's
    hex encoding (EXECVE aN=..., PROCTITLE), before the usual masking and cap."""
    if not original or not secrets:
        return original
    for secret in sorted(set(secrets), key=len, reverse=True):
        if len(secret) < 2:
            continue
        original = original.replace(secret, R.MASK)
        hexed = secret.encode("utf-8", "surrogatepass").hex().upper()
        original = original.replace(hexed, R.MASK.encode().hex().upper())
    return original


def mask_args(args: List[str]) -> Tuple[List[str], bool]:
    """argv with credentials masked, argument by argument. An argument is masked as
    masking it alone does, or -- when its secret only shows in context (`--password x`,
    `sshpass -p x`, `mysql -px`) -- replaced whole when masking the command line up to
    and including it changes it. Returns (args, whether anything was masked)."""
    out: List[str] = []
    changed = False
    for i, arg in enumerate(args):
        masked, red = R.mask(arg)
        if not red and i:
            prefix, _ = R.mask(" ".join(args[:i + 1]))
            if not prefix.endswith(" " + arg):
                masked, red = R.MASK, True
        out.append(masked)
        changed = changed or red
    return out, changed


def parsed_values(p: Any, *, host: str, dataset: str,
                  mask_url: Optional[Callable[[str], Tuple[str, bool]]] = None) -> Dict[str, Any]:
    """Masks command lines, messages and the raw line (events.redact) and caps every
    text field. `mask_url`: the web parser's query masking, a backstop for URLs."""
    category, etype, default_outcome = LOG_ACTIONS.get(p.action, ((), ("info",), "unknown"))
    dataset = getattr(p, "dataset", None) or dataset
    f = dict(p.fields)
    command = f.pop("process_command_line", None)
    values: Dict[str, Any] = {}
    flags = {"redacted": False, "truncated": False}
    secrets: List[str] = []
    for key in LIST_CAPS:
        items = f.pop(key, None)
        if not items:
            continue
        max_items, max_bytes = LIST_CAPS[key]
        items = [str(v) for v in items]
        if key == "process_args":
            masked, red = mask_args(items)
            secrets = [old for old, new in zip(items, masked) if old != new]
            items, flags["redacted"] = masked, red
        if len(items) > max_items:
            items, flags["truncated"] = items[:max_items], True
        capped = []
        for v in items:
            c, cut = R.cap(v, max_bytes)
            flags["truncated"] = flags["truncated"] or cut
            capped.append(c)
        if key != "process_args" and key != "audit_paths":       # unordered: unique values only
            capped = list(dict.fromkeys(capped))
        values[key] = tuple(capped)
    text = text_fields(scrub(p.original, secrets), p.message, command)
    text["redacted"] = text["redacted"] or flags["redacted"] or bool(getattr(p, "redacted", False))
    text["truncated"] = text["truncated"] or flags["truncated"]
    for key, value in f.items():
        if key in ("source_ip", "destination_ip"):
            value = ip(str(value))
        elif key in _INT_FIELDS:
            try:
                value = int(value)
            except (TypeError, ValueError):
                value = None
            if key.endswith("_port") and value is not None and not 0 <= value <= 65535:
                value = None
        elif value is not None:
            value = str(value)
            if key in ("url_original", "user_agent_original"):
                value, red, cut = R.clean(value, FIELD_CAPS[key])
                text["redacted"] = text["redacted"] or red
                text["truncated"] = text["truncated"] or cut
            else:
                value = short(value, FIELD_CAPS.get(key, 256))
        if value is not None and value != "":
            values[key] = value
    if "url_original" in values and mask_url is not None:
        values["url_original"], red = mask_url(values["url_original"])
        text["redacted"] = text["redacted"] or red
    timestamp = datetime.fromtimestamp(float(p.ts), UTC)
    related_ip = uniq(values.get("source_ip"), values.get("destination_ip"))
    related_user = uniq(values.get("user_name"), values.get("user_effective_name"), values.get("user_target_name"))
    return build_values(
        host=host, dataset=dataset, parser=PARSER_LOGSOURCE, timestamp=timestamp, provider=short(p.provider),
        text=text, time_zone_assumed=bool(p.zone_assumed),
        cursor=p.cursor, category=category, type=etype, outcome=p.outcome or default_outcome, action=p.action,
        related_ip=related_ip, related_user=related_user, **values,
    )


# ---------------------------------------------------------------------------
# Values -> the flat dict the evaluator reads
# ---------------------------------------------------------------------------
def _no_surrogates(value: Any) -> Any:
    """What events.model does to a lone surrogate (U+FFFD), so both sides see the same text."""
    if isinstance(value, str) and _LONE_SURROGATE.search(value):
        return _LONE_SURROGATE.sub("�", value)
    if isinstance(value, tuple) and any(isinstance(v, str) and _LONE_SURROGATE.search(v) for v in value):
        return tuple(_LONE_SURROGATE.sub("�", v) if isinstance(v, str) else v for v in value)
    return value


def flat(values: Dict[str, Any]) -> Dict[str, Any]:
    """Every set value by its ECS name; arrays as lists, times as ISO text -- the same
    dict kratos.detect.flat.flat gives for the Event built from `values`."""
    out: Dict[str, Any] = {}
    for f in F.FIELDS:
        value = values.get(f.py_attr)
        if value is None or value == () or value is False or value == "":
            continue
        base = f.base_type
        if base == "datetime":
            value = format_timestamp(value)
        elif base == "window":
            continue
        elif f.is_array:
            value = list(_no_surrogates(tuple(value)))
        else:
            value = _no_surrogates(value)
        out[f.name] = value
    if "ecs.version" not in out:
        out["ecs.version"] = F.ECS_VERSION
    if "kratos.schema_version" not in out:
        out["kratos.schema_version"] = F.SCHEMA_VERSION
    return out
