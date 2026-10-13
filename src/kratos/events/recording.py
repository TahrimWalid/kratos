"""Where the reads hand their lines to the event store.

One function per read (spec §5.8), each called by its tool right after the
tool's own work, with what the tool already has in hand. All best-effort:
nothing here raises, slows a tool noticeably, or changes what the tool returns
-- a line that won't convert is skipped, a store problem is logged once
(events/store.record_events).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable, Iterable, TypeVar

from kratos.events import converters as C
from kratos.events.model import Event
from kratos.events.store import record_events

logger = logging.getLogger(__name__)

# The host's own auth logs: their zone-less times are in this machine's zone.
_HOST_AUTH_LOGS = ("/var/log/auth.log", "/var/log/secure")
_warned: set[str] = set()

T = TypeVar("T")


def _transport(via: str | None) -> str:
    return "agent" if via == "subagent" else "ssh"


def _convert(items: Iterable[T], convert: Callable[[T], Event]) -> list[Event]:
    out = []
    for item in items:
        try:
            out.append(convert(item))
        except Exception as e:  # noqa: BLE001 -- one odd line must not lose the rest
            kind = f"{getattr(convert, '__name__', 'convert')}:{type(e).__name__}"
            if kind not in _warned:
                _warned.add(kind)
                logger.warning("skipped a log line that could not become an event (%s: %s)", type(e).__name__, e)
    return out


def _guard(fn: Callable[..., Any]) -> Callable[..., int | None]:
    def wrapper(*args: Any, **kwargs: Any) -> int | None:
        try:
            return fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 -- recording is additive, never a tool failure
            if fn.__name__ not in _warned:
                _warned.add(fn.__name__)
                logger.warning("could not record events for %s (%s: %s)", fn.__name__, type(e).__name__, e)
            return None
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


@_guard
def record_local_auth_log(data_dir: Path, events_file: Path, stats: dict[str, Any]) -> int | None:
    """parse_auth_log (Kratos's own host): the AuthEvents it just wrote."""
    from kratos.adapters.auth_log_parse import AuthEvent
    from kratos.utils.timeutil import detect_local_tz

    source = str(stats.get("source") or "")
    if source == "none":
        return 0
    path = source[len("file:"):] if source.startswith("file:") else None
    # A file at some other path may have been copied from another machine: its
    # zone is unknown, so its times are read as UTC and flagged.
    own_log = path is None or path in _HOST_AUTH_LOGS
    ctx = C.ReadContext(target="127.0.0.1", transport="local", read=C.READ_AUTH_LOG, coverage="complete",
                        time_zone=detect_local_tz() if own_log else None, log_file_path=path)
    raw = json.loads(Path(events_file).read_text(encoding="utf-8"))
    events = _convert(raw, lambda d: C.from_auth_event(AuthEvent(**d), ctx=ctx))
    return record_events(events, data_dir=data_dir)


@_guard
def record_target_auth(data_dir: Path, target: str, entries: list[tuple[str, str | None, str]],
                       windows: dict[str, Any], *, since_epoch: float | None,
                       until_epoch: float | None) -> int | None:
    """The target's sshd/sudo journal (read_journalctl's background auth fetch).
    `entries` is the fetcher's list, identifier by identifier in the order of
    `windows` (each window says how many entries it returned and how it was read)."""
    from kratos.adapters.auth_log_parse import classify_auth_message

    events: list[Event] = []
    pos = 0
    for window in windows.values():
        chunk = entries[pos:pos + window.returned]
        pos += window.returned
        ctx = C.ReadContext(target=target, transport=_transport(window.via), read=C.READ_JOURNAL_AUTH,
                            window=(since_epoch, until_epoch),
                            coverage="truncated" if window.truncated else "complete")
        events += _convert(
            (e for e in chunk if e[2]),
            lambda e, ctx=ctx: C.from_auth_event(classify_auth_message(e[0], target, e[1], e[2], e[2]), ctx=ctx))
    return record_events(events, data_dir=data_dir)


@_guard
def record_journal(data_dir: Path, target: str, entries: list[dict[str, Any]], window: Any) -> int | None:
    """read_journalctl's own query: the target's journal, any unit."""
    ctx = C.ReadContext(target=target, transport=_transport(window.via), read=C.READ_JOURNAL_FETCH,
                        window=(window.since_epoch, window.until_epoch),
                        coverage="truncated" if window.truncated else "complete")
    return record_events(_convert(entries, lambda e: C.from_journal_entry(e, ctx=ctx)), data_dir=data_dir)


@_guard
def record_privileged_changes(data_dir: Path, target: str, change_events: list[dict[str, Any]],
                              since_epoch: float, via: str, capped: bool) -> int | None:
    """list_privileged_accounts: the account/group change lines from the target's journal."""
    ctx = C.ReadContext(target=target, transport=_transport(via), read=C.READ_PRIVILEGED,
                        window=(float(since_epoch), None), coverage="truncated" if capped else "complete")
    return record_events(_convert(change_events, lambda e: C.from_privileged_event(e, ctx=ctx)),
                         data_dir=data_dir)


def events_for_log_read(target: str, read: Any) -> list[Event]:
    """read_host_logs: one source's records (kratos.logsources) as events of the
    source's dataset -- sudo lines as kratos.auth, like the auth read's. Masking
    and caps happen here, so the tool's summary only ever shows masked text.
    Never raises: a line that won't convert is skipped."""
    from kratos.logsources import catalog
    from kratos.logsources.parsers import parse_read

    ctx = C.ReadContext(target=target, transport=_transport(read.via),
                        read=f"{getattr(read, 'read_label', None) or 'log_read'}.{read.source}",
                        window=(read.since, read.until), coverage="truncated" if read.truncated else "complete")
    try:
        items = parse_read(read, target)
    except Exception as e:  # noqa: BLE001 -- a parser bug must not fail the read
        logger.warning("could not parse the %s read (%s: %s)", read.source, type(e).__name__, e)
        return []
    if read.source in ("sudo", "auth"):
        return _convert(items, lambda ev: C.from_auth_event(ev, ctx=ctx))
    dataset = catalog.SOURCES[read.source].dataset
    return _convert(items, lambda p: C.from_parsed(p, ctx=ctx, dataset=dataset))


@_guard
def record_log_read(data_dir: Path, events: list[Event]) -> int | None:
    """Store read_host_logs' events (best-effort)."""
    return record_events(events, data_dir=data_dir)
