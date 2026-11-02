"""Container log files as a log source (D.5 §3.8, dataset kratos.container).

The journald log driver's lines arrive through the journal sync of source ``containers``
(kratos.collect.sync.engine). This module syncs each running container's OWN log file --
Docker ``json-file``, Podman ``k8s-file`` -- through the machine's sub-agent (the files are
root-only), with the same bookkeeping as every other log: a position per container
(``sync_cursors``, kind ``ctr:<id>``: inode + byte offset), rotation followed through the
``.1`` file, and the spans held completely (``sync_coverage``, source ``containers``) --
a gap is recorded, never a false "complete".

A container whose file vanished (it was removed) is a stated end, not an error. Excluded
containers (``containers.logs.exclude``) are not read at all. Every line is machine text:
masked and capped as it becomes an event.
"""
from __future__ import annotations

import fnmatch
import logging
import time
from pathlib import Path
from typing import Any, Callable

from kratos import settings_store
from kratos.collect.sync import cursors
from kratos.containers import record
from kratos.containers import settings as S
from kratos.target_key import target_key

logger = logging.getLogger(__name__)

SOURCE = "containers"
DATASET = "kratos.container"
FILE_DRIVERS = ("json-file", "k8s-file")
MAX_ROUNDS = 4

Fetch = Callable[[str, "int | None", int], Any]


def _default_fetch(target: str) -> Fetch:
    def fetch(cid: str, inode: int | None, offset: int) -> Any:
        from kratos import kratos_config
        from kratos.adapters.ssh_remote import fetch_container_log

        with kratos_config.pinned_target(target):
            return fetch_container_log(cid, inode, offset)
    return fetch


def wanted(doc: dict[str, Any] | None, data_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """(running containers whose log files are synced, gaps) from the newest container read."""
    if not doc or not doc.get("engines_found"):
        return [], []
    limit = int(settings_store.get(S.LOGS_MAX_CONTAINERS, data_dir=data_dir))
    exclude = list(settings_store.get(S.LOGS_EXCLUDE, data_dir=data_dir) or [])
    rows = [r for r in doc.get("rows") or [] if r.get("running") and r.get("id")]
    gaps: list[str] = []
    local = [r for r in rows if r.get("log_driver") == "local"]
    if local:
        gaps.append(f"{len(local)} container(s) use the 'local' log driver, whose binary format Kratos doesn't read")
    files = [r for r in rows if r.get("log_driver") in FILE_DRIVERS
             and not any(fnmatch.fnmatchcase(str(r.get("name") or ""), p) for p in exclude)]
    if len(files) > limit:
        gaps.append(f"{len(files)} containers write log files; only the first {limit} are synced "
                    f"({S.LOGS_MAX_CONTAINERS})")
    return files[:limit], gaps


def sync_files(data_dir: Path, target: str, rep: Any, *, now: float, initial_hours: float, deadline: float,
               fetch: Fetch | None = None) -> None:
    """Sync every wanted container's log file into the event store; report into `rep`
    (a collect.sync.engine.SourceReport)."""
    data_dir = Path(data_dir)
    doc = record.load(data_dir, target)
    todo, gaps = wanted(doc, data_dir)
    rep.gaps += [f"containers: {g}" for g in gaps]
    if not todo:
        return
    if doc.get("via") not in ("agent", "subagent") and fetch is None:
        rep.gaps.append("containers: their own log files are root-only -- read this machine through its sub-agent "
                        "(the journald log driver's lines are synced from the journal)")
        if rep.status == "ok":
            rep.status = "partial"
        return
    fetch = fetch or _default_fetch(target)
    max_lines = int(settings_store.get(S.LOGS_MAX_LINES, data_dir=data_dir))
    tkey = target_key(target)
    starts: list[float] = []
    ends: list[float] = []
    complete = True
    for row in todo:
        if time.monotonic() > deadline:
            rep.behind = True
            complete = False
            break
        ok, begin, through = _sync_one(data_dir, target, tkey, row, rep, fetch, now=now,
                                       floor=now - initial_hours * 3600, max_lines=max_lines, deadline=deadline)
        complete = complete and ok
        if begin is not None and through is not None:
            starts.append(begin)
            ends.append(through)
    if starts and ends:
        lo, hi = max(starts), min(ends)
        if hi > lo:
            cursors.add_span(data_dir, tkey, SOURCE, lo, hi, complete=complete,
                             note="" if complete else "a container's log could not be synced completely")
    if not complete and rep.status == "ok":
        rep.status = "partial"


def _sync_one(data_dir: Path, target: str, tkey: str, row: dict[str, Any], rep: Any, fetch: Fetch, *,
              now: float, floor: float, max_lines: int, deadline: float) -> tuple[bool, float | None, float | None]:
    """(complete, begin, synced-through) for one container."""
    cid = str(row["id"])
    kind = f"ctr:{cid}"
    name = str(row.get("name") or cid[:12])
    begin: float | None = None
    through: float | None = None
    for _round in range(MAX_ROUNDS):
        cur = cursors.get_cursor(data_dir, tkey, SOURCE, kind)
        if cur is not None and cur.position == "ended":
            return True, None, None
        inode = cur.inode if cur is not None else None
        offset = int(cur.position) if cur is not None and str(cur.position or "").isdigit() else 0
        res = fetch(cid, inode, offset)
        if isinstance(res, dict) and res.get("unsupported"):
            rep.gaps.append(f"containers: {res['unsupported']}")
            return False, None, None
        if not isinstance(res, dict):
            text = (getattr(res, "stderr", "") or "").strip()
            old = "update the agent" in text or "needs 0.11" in text
            rep.gaps.append(f"containers: {name}'s log: " + ("this machine's sub-agent is too old -- update it (`g` "
                                                                "in /subagent)" if old else "could not be read"))
            rep.old_agent = rep.old_agent or old
            return False, None, None
        files = res.get("files") or []
        f0 = next((f for f in files if f["slot"] == 0), None)
        f1 = next((f for f in files if f["slot"] == 1), None)
        if f0 is None:
            return False, begin, through
        if f0["status"] == "gone":
            cursors.put_cursor(data_dir, tkey, SOURCE, kind, position="ended", inode=inode, last_ts=now)
            return True, begin, through          # removed: a stated end, not an error
        if f0["status"] == "unsupported":
            return True, None, None              # journald etc.: synced from the journal, or stated in `wanted`
        if f0["status"] in ("refused", "missing") and f1 is None:
            rep.gaps.append(f"containers: {name}'s log file {f0['status']} ({f0.get('note') or ''})".rstrip(" ()"))
            return False, begin, through
        prev_end = cur.last_ts if cur is not None else None
        events, newest = _store(data_dir, target, res, cid, floor if cur is None else None, max_lines, rep)
        if events is None:
            rep.gaps.append(f"containers: {name}'s lines could not be saved to the event store")
            return False, begin, through
        rep.new_events += events
        if begin is None:
            begin = prev_end if prev_end is not None else max(floor, _first_ts(res) or now)
        if f1 is not None:                        # the followed file was rotated
            if f1["status"] == "read":
                done = f1["start"] + f1["consumed"] >= f1["size"]
                nxt_inode, nxt_off = (f0["inode"], 0) if done else (f1["inode"], f1["start"] + f1["consumed"])
                cursors.put_cursor(data_dir, tkey, SOURCE, kind, position=str(nxt_off), inode=nxt_inode,
                                   last_ts=newest or prev_end or now, behind=True)
                through = newest or prev_end
                continue
            cursors.add_span(data_dir, tkey, SOURCE, prev_end or now, now, complete=False,
                             note=f"{name}'s log was rotated and the previous file is gone")
            rep.gaps.append(f"containers: {name}'s log was rotated and the previous file is gone; lines in between "
                            "are not synced")
            cursors.put_cursor(data_dir, tkey, SOURCE, kind, position="0", inode=f0["inode"], last_ts=now, behind=True)
            return False, begin, through
        if f0["status"] != "read":
            return False, begin, through
        if inode is not None and f0["inode"] == inode and f0["start"] < offset:
            cursors.add_span(data_dir, tkey, SOURCE, prev_end or now, now, complete=False,
                             note=f"{name}'s log is smaller than where the last sync stopped (cut short)")
            rep.gaps.append(f"containers: {name}'s log was cut short; what was in it is not synced")
            cursors.put_cursor(data_dir, tkey, SOURCE, kind, position="0", inode=f0["inode"], last_ts=now, behind=True)
            continue
        new_off = f0["start"] + f0["consumed"]
        behind = new_off < f0["size"]
        through = now if not behind else (newest or prev_end or now)
        cursors.put_cursor(data_dir, tkey, SOURCE, kind, position=str(new_off), inode=f0["inode"], last_ts=through,
                           behind=behind)
        if not behind:
            return events >= 0, begin, through
        if time.monotonic() > deadline:
            break
    rep.behind = True
    return True, begin, through


def _first_ts(res: dict[str, Any]) -> float | None:
    from kratos.logsources.parsers.containers import file_line

    meta = res.get("meta") or {}
    for fmt, raw in res.get("lines") or []:
        p = file_line(fmt, raw, meta, "0" * 64)
        if p is not None:
            return p.ts
    return None


def _store(data_dir: Path, target: str, res: dict[str, Any], cid: str, floor: float | None, max_lines: int,
           rep: Any) -> tuple[int | None, float | None]:
    """(events stored or None on a store failure, the newest line's time)."""
    from kratos.events import converters as C
    from kratos.events import recording
    from kratos.logsources.parsers.containers import file_line

    meta = res.get("meta") or {}
    ctx = C.ReadContext(target=target, transport="agent", read="log_sync.containers", coverage="complete")
    parsed = []
    for fmt, raw in res.get("lines") or []:
        p = file_line(fmt, raw, meta, cid)
        if p is None or (floor is not None and p.ts < floor):
            continue
        parsed.append(p)
    newest = max((p.ts for p in parsed), default=None)
    if len(parsed) > max_lines:
        rep.gaps.append(f"containers: {meta.get('name') or cid[:12]} wrote {len(parsed)} lines in one chunk; the "
                        f"newest {max_lines} were kept ({S.LOGS_MAX_LINES})")
        parsed = parsed[-max_lines:]
    events = []
    for p in parsed:
        try:
            events.append(C.from_parsed(p, ctx=ctx, dataset=DATASET))
        except Exception as e:  # noqa: BLE001 -- one odd line must not stop the sync
            logger.debug("container line skipped: %s", e)
    if not events:
        return 0, newest
    stored = recording.record_log_read(data_dir, events)
    return stored, newest
