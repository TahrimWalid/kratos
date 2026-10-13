"""Incremental log sync: pull only the log lines that are new since last time.

Kratos remembers its position in each security-relevant source -- the journal cursor,
or (inode, byte offset) of a classic file -- and reads FORWARD from there, so the event
store fills steadily instead of only when the model asks for lines. It also records which
time spans it holds COMPLETELY (`cursors.covered`), and records a gap, never a false
"complete", when the position can't be trusted (a vacuumed journal, a truncated or
vanished file).

Transport-neutral: the reads come from `Fetchers` (SSH scripts or sub-agent probes, see
adapters/ssh_remote.fetch_journal_sync / fetch_file_sync), the lines become events through
the same parsers and converters as `read_host_logs`, and positions are kept in `kratos.db`
on THIS host -- nothing is ever written on the monitored machine.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kratos.collect.sync import cursors
from kratos.logsources import catalog, logread
from kratos.logsources.logread import LogRead, Record
from kratos.target_key import target_key

logger = logging.getLogger(__name__)

OLDEST_SLACK_SECONDS = 2.0        # the journal's oldest entry may trail the sync time by this much without a hole
RESTART_GAP_SECONDS = 2.0         # a restart by time can never be merged with the span before it
MAX_ROUNDS = 4                    # follow-up reads per source and sync while it is still catching up
_CURSOR_ERROR_RE = re.compile(r"cursor|seek|invalid argument", re.IGNORECASE)


@dataclass
class Fetchers:
    """The two reads a sync needs. Each returns the parsed result, or a failed
    ssh_remote.SSHResult (anything with `ok` False)."""
    journal: Callable[[str, str | None, float | None, int], Any]
    file: Callable[[str, int, int | None, int, float | None], Any]

    @classmethod
    def default(cls) -> "Fetchers":
        from kratos.adapters import ssh_remote

        return cls(journal=ssh_remote.fetch_journal_sync, file=ssh_remote.fetch_file_sync)


@dataclass
class SourceReport:
    source: str
    mode: str = "none"                # journal | files | none
    status: str = "ok"                # ok | partial | failed | not_supported | skipped
    message: str = ""                 # one plain line
    new_events: int = 0
    lines_read: int = 0
    behind: bool = False
    gaps: list[str] = field(default_factory=list)
    synced_through: float | None = None
    via: str | None = None
    old_agent: bool = False


@dataclass
class SyncReport:
    target: str
    target_key: str
    sources: list[SourceReport] = field(default_factory=list)
    started: float = 0.0
    finished: float = 0.0

    @property
    def new_events(self) -> int:
        return sum(s.new_events for s in self.sources)

    @property
    def behind(self) -> list[str]:
        return [s.source for s in self.sources if s.behind]


def _failed(res: Any) -> bool:
    return getattr(res, "ok", True) is False


def _failure_text(res: Any, what: str) -> tuple[str, bool]:
    """(plain words, is-it-an-old-agent) for a failed read."""
    text = (getattr(res, "stderr", "") or "").strip()
    old = "update the agent" in text or "needs 0.5" in text or "sub-agent" in text and "older" in text
    if old:
        return f"{what}: this machine's sub-agent is too old for log sync -- update it (`g` in /subagent)", True
    return f"{what}: could not be read", False


def _store(data_dir: Path, target: str, read: LogRead) -> int | None:
    """Events for `read` into the event store. None = the store failed (the caller must
    NOT advance its position then, or lines would be lost while coverage says complete)."""
    from kratos.events import recording

    read.read_label = "log_sync"
    events = recording.events_for_log_read(target, read)
    if not events:
        return 0
    return recording.record_log_read(data_dir, events)


def _entry_ts(entry: dict[str, Any]) -> float | None:
    try:
        return int(entry.get("__REALTIME_TIMESTAMP")) / 1_000_000
    except (TypeError, ValueError):
        return None


def _seqnum_id(cursor: str) -> str | None:
    m = re.match(r"s=([0-9a-f]{32});", cursor or "")
    return m.group(1) if m else None


# ----------------------------------------------------------------------------- journal
def _journal_rounds(data_dir: Path, target: str, source: str, fetch: Fetchers, rep: SourceReport, *,
                    now: float, initial_hours: float, max_lines: int, deadline: float) -> str:
    """Returns "done", "no_journal" (fall back to files) or "failed"."""
    spec = catalog.SYNC_SOURCES[source]
    tkey = target_key(target)
    rep.mode = "journal"
    for _round in range(MAX_ROUNDS):
        cur = cursors.get_cursor(data_dir, tkey, source, "journal")
        after = cur.position if cur and logread.valid_cursor(cur.position) else None
        since = None
        restart_note = ""
        if after is None:
            since = (cur.last_ts - 1) if cur is not None and cur.last_ts else now - initial_hours * 3600
            if cur is not None and cur.position is not None:      # a saved position that is not a cursor
                restart_note = "the saved journal position was not valid"
        res = fetch.journal(spec.journal, after, since, max_lines)
        if _failed(res):
            rep.status = "failed"
            rep.message, rep.old_agent = _failure_text(res, source)
            rep.gaps.append(rep.message)
            return "failed"
        rep.via = getattr(res, "via", None)
        if not res.have_journal:
            return "no_journal"
        if after is not None and res.errors and not res.entries and any(_CURSOR_ERROR_RE.search(e) for e in res.errors):
            # The cursor was refused: restart by time from where we had got to, and say so.
            restart_note = "the journal no longer accepted the saved position"
            since = (cur.last_ts - 1) if cur is not None and cur.last_ts else now - initial_hours * 3600
            after = None
            res = fetch.journal(spec.journal, None, since, max_lines)
            if _failed(res):
                rep.status = "failed"
                rep.message, rep.old_agent = _failure_text(res, source)
                rep.gaps.append(rep.message)
                return "failed"
        if res.errors and not res.entries:
            rep.status = "failed"
            rep.message = f"{source}: the journal reported an error"
            rep.gaps.append(rep.message)
            return "failed"
        entries = [e for e in res.entries if logread.valid_cursor(e.get("__CURSOR")) and _entry_ts(e) is not None]
        more = len(res.entries) > max_lines or res.byte_capped
        entries = entries[:max_lines]
        sync_now = res.now if res.now is not None else now
        # --- where does the span we can vouch for start? ---
        prev_end = cur.last_ts if cur is not None else None
        start: float
        if prev_end is None:
            start = max(since if since is not None else sync_now, res.oldest_ts or 0.0)
        else:
            start = prev_end
            if res.oldest_ts is not None and res.oldest_ts > prev_end + OLDEST_SLACK_SECONDS:
                cursors.add_span(data_dir, tkey, source, prev_end, res.oldest_ts, complete=False,
                                 note="journal entries in between were removed (vacuum or rotation)")
                rep.gaps.append(f"{source}: the journal no longer holds entries between "
                                f"{_utc(prev_end)} and {_utc(res.oldest_ts)}")
                start = res.oldest_ts
            if restart_note:
                first_ts = _entry_ts(entries[0]) if entries else sync_now
                new_start = max(first_ts or sync_now, prev_end + RESTART_GAP_SECONDS, start)
                cursors.add_span(data_dir, tkey, source, prev_end, new_start, complete=False, note=restart_note)
                rep.gaps.append(f"{source}: {restart_note}; restarted by time")
                start = new_start
        # --- store, then (only then) move the position ---
        last_ts = _entry_ts(entries[-1]) if entries else None
        if entries:
            read = LogRead(source=source, since=start, until=last_ts, via=getattr(res, "via", "ssh"),
                           has_journal=True, now=sync_now, truncated=more)
            read.records = [Record(kind="journal", ts=_entry_ts(e) or 0.0, entry=e, match=spec.journal) for e in entries]
            stored = _store(data_dir, target, read)
            if stored is None:
                rep.status = "failed"
                rep.message = f"{source}: could not be saved to the event store"
                rep.gaps.append(rep.message)
                return "failed"
            rep.new_events += stored
            rep.lines_read += len(entries)
        position = entries[-1]["__CURSOR"] if entries else (cur.position if cur else None)
        through = (last_ts if more else max(sync_now, last_ts or 0.0)) if (entries or more) else sync_now
        if position is not None and (entries or restart_note):
            cursors.put_cursor(data_dir, tkey, source, "journal", position=position, seqnum_id=_seqnum_id(position),
                               last_ts=through, behind=more)
        elif cur is None:
            cursors.put_cursor(data_dir, tkey, source, "journal", position=None, last_ts=through, behind=more)
        else:
            cursors.put_cursor(data_dir, tkey, source, "journal", position=cur.position,
                               seqnum_id=cur.seqnum_id, last_ts=through, behind=more)
        if through > start:
            cursors.add_span(data_dir, tkey, source, start, through, complete=True)
        rep.synced_through = through
        rep.behind = more
        if not more or time.monotonic() > deadline:
            return "done"
    return "done"


# ----------------------------------------------------------------------------- files
def _file_rounds(data_dir: Path, target: str, source: str, fetch: Fetchers, rep: SourceReport, *,
                 now: float, initial_hours: float, deadline: float) -> str:
    rep.mode = "files"
    tkey = target_key(target)
    spec = catalog.SYNC_SOURCES[source]
    n_files: int | None = None
    ends: list[float] = []
    starts: list[float] = []
    index = 0
    while n_files is None or index < n_files:
        i = index
        index += 1
        kind = f"file:{i}"
        file_behind = True
        for _round in range(MAX_ROUNDS):
            if not file_behind:
                break
            cur = cursors.get_cursor(data_dir, tkey, source, kind)
            inode = cur.inode if cur is not None else None
            offset = cur.offset if cur is not None else 0
            floor = now - initial_hours * 3600 if cur is None else None
            read = fetch.file(source, i, inode, offset, floor)
            if _failed(read):
                rep.status = "failed"
                rep.message, rep.old_agent = _failure_text(read, source)
                rep.gaps.append(rep.message)
                return "failed"
            rep.via = getattr(read, "via", None)
            if n_files is None:
                if read.family is None:
                    rep.status = "not_supported"
                    rep.message = f"{source}: unknown Linux distribution -- no log paths are known"
                    return "done"
                n_files = len(catalog.sync_files(source, read.family))
                if n_files == 0:
                    rep.status = "not_supported"
                    rep.message = f"{source}: no log is kept for this on this kind of machine"
                    return "done"
                if i >= n_files:
                    break
            sync_now = read.now if read.now is not None else now
            f0 = next((f for f in read.files if f.slot == 0), None)
            f1 = next((f for f in read.files if f.slot == 1), None)
            if f0 is None:
                file_behind = False
                break
            if f0.status in ("missing", "skipped_journal"):
                file_behind = False
                break
            if f0.status in ("unreadable", "symlink", "hardlink", "not_regular", "refused"):
                rep.status = "partial"
                access = spec_access(source, read.family)
                rep.gaps.append(f"{source}: {f0.path.rsplit('/', 1)[-1]} {_file_problem(f0.status)}"
                                + (f" ({access})" if access else ""))
                file_behind = False
                break
            if f0.status == "changed" or (f1 is not None and f1.status == "changed"):
                rep.status = "partial"
                file_behind = False
                break
            prev_end = cur.last_ts if cur is not None else None
            if f0.status == "truncated":
                start = prev_end if prev_end is not None else sync_now
                cursors.add_span(data_dir, tkey, source, start, sync_now, complete=False,
                                 note=f"{f0.path} is smaller than where the last sync stopped (cut short or replaced)")
                rep.gaps.append(f"{source}: {f0.path.rsplit('/', 1)[-1]} was cut short; what was in it is not synced")
                cursors.put_cursor(data_dir, tkey, source, kind, position="0", inode=f0.inode, last_ts=sync_now,
                                   behind=True)
                file_behind = True
                continue
            slice_file = f0
            if f0.status == "current":                     # the file we followed was rotated
                if f1 is not None and f1.status == "read":
                    slice_file = f1
                else:
                    start = prev_end if prev_end is not None else sync_now
                    cursors.add_span(data_dir, tkey, source, start, sync_now, complete=False,
                                     note="the log was rotated and the previous file could not be found")
                    rep.gaps.append(f"{source}: the log was rotated and the previous file is gone; lines in "
                                    "between are not synced")
                    cursors.put_cursor(data_dir, tkey, source, kind, position="0", inode=f0.inode, last_ts=sync_now,
                                       behind=True)
                    file_behind = True
                    continue
            if slice_file.status != "read" or slice_file.consumed is None:
                rep.status = "partial"
                file_behind = False
                break
            consumed = slice_file.consumed
            lstart = slice_file.start or 0
            new_off = lstart + consumed
            size = slice_file.size or 0
            records = [r for r in read.records if r.path == slice_file.path]
            eof = lstart + logread.SYNC_CHUNK_BYTES >= size
            if slice_file is f1:
                finished_old = eof                      # a rotated file gets no more lines
                next_inode, next_off = (f0.inode, 0) if finished_old else (cur.inode if cur else None, new_off)
                behind_now = True
            else:
                finished_old = False
                next_inode, next_off = slice_file.inode, new_off
                behind_now = not eof
            if records:
                part = LogRead(source=source, family=read.family, tz_name=read.tz_name, tz_offset=read.tz_offset,
                               now=sync_now, via=getattr(read, "via", "ssh"), truncated=False,
                               since=slice_file.first, until=slice_file.last)
                part.records = records
                stored = _store(data_dir, target, part)
                if stored is None:
                    rep.status = "failed"
                    rep.message = f"{source}: could not be saved to the event store"
                    rep.gaps.append(rep.message)
                    return "failed"
                rep.new_events += stored
                rep.lines_read += len(records)
            if slice_file.truncated:                      # more lines matched than came back
                rep.status = "partial"
                rep.gaps.append(f"{source}: some lines of {slice_file.path.rsplit('/', 1)[-1]} were too many to keep")
            through = sync_now if (not behind_now and slice_file is f0) else (slice_file.last or prev_end or sync_now)
            cursors.put_cursor(data_dir, tkey, source, kind, position=str(next_off), inode=next_inode,
                               last_ts=through, behind=behind_now or finished_old)
            if prev_end is None:
                begin = max(floor or 0.0, slice_file.first or sync_now)
            else:
                begin = prev_end
            starts.append(begin)
            ends.append(through)
            file_behind = behind_now or finished_old
            if time.monotonic() > deadline:
                break
        rep.behind = rep.behind or file_behind                     # still behind after the rounds
        if n_files is None:
            break
    # One span per source: from the latest start to the earliest end of its files.
    if starts and ends and not rep.gaps and rep.status == "ok":
        lo, hi = max(starts), min(ends)
        if hi > lo:
            cursors.add_span(data_dir, tkey, source, lo, hi, complete=True)
        rep.synced_through = hi
    elif ends:
        rep.synced_through = min(ends)
    return "done"


def spec_access(source: str, family: str | None) -> str:
    src = catalog.SOURCES.get(source)
    return src.access_for(family) if src is not None else ""


def _file_problem(status: str) -> str:
    return {"unreadable": "can't be read by the SSH user", "symlink": "is a symbolic link (not read)",
            "hardlink": "has several hard links (not read)", "not_regular": "is not a regular file",
            "refused": "was refused"}.get(status, status)


def _utc(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


# ----------------------------------------------------------------------------- entry points
def sync_source(data_dir: Path, target: str, source: str, *, fetchers: Fetchers, now: float,
                initial_hours: float, max_lines: int, deadline: float) -> SourceReport:
    rep = SourceReport(source=source)
    spec = catalog.SYNC_SOURCES.get(source)
    if spec is None:
        rep.status, rep.message = "failed", f"{source}: not a source Kratos syncs"
        return rep
    try:
        if spec.journal is not None:
            outcome = _journal_rounds(data_dir, target, source, fetchers, rep, now=now, initial_hours=initial_hours,
                                      max_lines=max_lines, deadline=deadline)
            if outcome == "no_journal":
                if not spec.files:
                    rep.status = "not_supported"
                    rep.message = f"{source}: this machine has no systemd journal and keeps no other log of it"
                    return rep
                _file_rounds(data_dir, target, source, fetchers, rep, now=now, initial_hours=initial_hours,
                             deadline=deadline)
        else:
            _file_rounds(data_dir, target, source, fetchers, rep, now=now, initial_hours=initial_hours,
                         deadline=deadline)
    except Exception as e:  # noqa: BLE001 -- one source failing must not stop the others
        logger.warning("log sync of %s failed: %s: %s", source, type(e).__name__, e, exc_info=True)
        rep.status = "failed"
        rep.message = f"{source}: sync failed"
        rep.gaps.append(rep.message)
    if not rep.message:
        rep.message = ("catching up" if rep.behind else "up to date") if rep.status == "ok" else rep.status
    return rep


def sync_logs(target: str, data_dir: Path | str, *, sources: tuple[str, ...] | None = None,
              fetchers: Fetchers | None = None, now: float | None = None, deadline: float | None = None,
              initial_hours: float | None = None, max_lines: int | None = None) -> SyncReport:
    """Bring the event store up to date for `target`, source by source. Stops starting new
    work at `deadline` (a time.monotonic() value); what is done stays done."""
    from kratos import settings_store
    from kratos.collect.sync import settings as sync_settings

    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    out = SyncReport(target=target, target_key=target_key(target), started=now)
    sources = sources if sources is not None else tuple(settings_store.get(sync_settings.SOURCES, data_dir=data_dir))
    initial_hours = initial_hours if initial_hours is not None else float(
        settings_store.get(sync_settings.INITIAL_HOURS, data_dir=data_dir))
    max_lines = max_lines if max_lines is not None else int(settings_store.get(sync_settings.MAX_LINES, data_dir=data_dir))
    fetchers = fetchers or Fetchers.default()
    deadline = deadline if deadline is not None else time.monotonic() + 3600
    for source in sources:
        if time.monotonic() > deadline:
            skipped = SourceReport(source=source, status="skipped", message="not synced this time (out of time)")
            skipped.behind = True
            out.sources.append(skipped)
            continue
        out.sources.append(sync_source(data_dir, target, source, fetchers=fetchers, now=now,
                                       initial_hours=initial_hours, max_lines=max_lines, deadline=deadline))
    out.finished = time.time()
    return out
