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

from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from typing import Any

from kratos import run_context
from kratos.adapters.auth_log_parse import AuthEvent
from kratos.events import assemble as A
from kratos.events.model import UTC, Event
from kratos.target_key import target_key

PARSER_AUTH = A.PARSER_AUTH
PARSER_JOURNAL = "journal/1"
PARSER_PRIVILEGED = "privileged_accounts/1"

# The named reads (kratos.read).
READ_AUTH_LOG = "auth_log"                     # a local auth.log / secure file, or local journald text
READ_JOURNAL_AUTH = "journal_auth"             # the target's sshd/sudo journal
READ_JOURNAL_FETCH = "journal_fetch"           # the target's journal, any unit
READ_PRIVILEGED = "privileged_accounts"
READ_WATCH = "watch"                           # an agent's continuous watch (C.2)

DATASET_AUTH = A.DATASET_AUTH
DATASET_JOURNAL = "kratos.journal"
DATASET_PRIVILEGED = "kratos.privileged_accounts"

# The tables live in events/assemble.py (shared with the agent's watcher); these
# names stay for the tests and callers that read them here.
AUTH_EVENT_TYPES = A.AUTH_EVENT_TYPES

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
syslog_time = A.syslog_time
_parse_any_time = A.parse_any_time


# ---------------------------------------------------------------------------
# Shared assembly
# ---------------------------------------------------------------------------
_text_fields = A.text_fields
_short = A.short
_uniq = A.uniq
_ip = A.ip


def _event(ctx: ReadContext, values: dict[str, Any]) -> Event:
    """An Event from the line's values (events/assemble.py) and the read that found it."""
    return Event(created=ctx.created, transport=ctx.transport, read=ctx.read, run_id=ctx.run_id,
                 window=ctx.window, coverage=ctx.coverage,
                 **{"log_file_path": ctx.log_file_path, **values})


def _build(ctx: ReadContext, *, dataset: str, parser: str, timestamp: datetime, provider: str | None,
           text: dict[str, Any], time_zone_assumed: bool = False, cursor: str | None = None, **values: Any) -> Event:
    return _event(ctx, A.build_values(host=ctx.host, dataset=dataset, parser=parser, timestamp=timestamp,
                                      provider=provider, text=text, time_zone_assumed=time_zone_assumed,
                                      cursor=cursor, **values))


# ---------------------------------------------------------------------------
# AuthEvent
# ---------------------------------------------------------------------------
def from_auth_event(ev: AuthEvent, *, ctx: ReadContext) -> Event:
    return _event(ctx, A.auth_values(ev, host=ctx.host, line_prefix=ctx.read == READ_AUTH_LOG,
                                     time_zone=ctx.time_zone, created=ctx.created))


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
PARSER_LOGSOURCE = A.PARSER_LOGSOURCE
LOG_ACTIONS = A.LOG_ACTIONS
_FIELD_CAPS = A.FIELD_CAPS
_LIST_CAPS = A.LIST_CAPS
_scrub = A.scrub
mask_args = A.mask_args


def from_parsed(p: Any, *, ctx: ReadContext, dataset: str) -> Event:
    """A logsources.parsers.Parsed -> Event. Masks command lines, messages and the
    raw line (events.redact) and the URL's query (already masked by the web
    parser, masked again here as a backstop); caps every text field."""
    from kratos.logsources.parsers.web import mask_url

    values = A.parsed_values(p, host=ctx.host, dataset=dataset, mask_url=mask_url)
    log_path = _short(p.log_file_path, 4096) or ctx.log_file_path
    return _event(ctx, {**values, "log_file_path": log_path})
