"""Run a hunt: search everything Kratos holds for one or more indicators (C.3).

Code only -- no model call, no network, nothing sent to a machine. For each machine
searched and each indicator:

1. **Events, typed fields** -- the term index (kratos.hunt.terms), over everything
   held: addresses, accounts, hashes, programs, paths, URL domains. Events stored
   before the index existed and not indexed yet are searched by their main columns
   (source address, user, program, hash), and the report says so.
2. **Events, log text** -- a bounded substring scan (escaped LIKE, then a whole-word
   check) over the newest `hunt.scan_days`, newest hour first, stopped after
   `hunt.scan_seconds`: the report says how many of how many events it searched.
3. **Detections** -- the same events, dataset `kratos.detect`, counted separately.
4. **Snapshots** -- persistence and running-process reads, installed-package lists.
5. **Findings** -- the finding records' entities.

Every result carries its machine, its source and its time; machine text in hits is
cleaned for display (A.4). The coverage (kratos.hunt.coverage) is built from records,
so "not found" always means "not found in what Kratos holds for these stretches".
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kratos import settings_store
from kratos.hunt import coverage as C
from kratos.hunt import settings as S
from kratos.hunt import snapshots as SN
from kratos.hunt import terms as T
from kratos.hunt.indicators import Indicator
from kratos.target_key import target_key

DETECT_DATASET = "kratos.detect"
SCAN_SLICE_SECONDS = 3600
EXCERPT_CHARS = 160
# where an indicator kind is found by the main columns of an event not yet in the index
_COLUMN_FOR = {"ip": "source_ip", "account": "user_name", "program": "process_name", "sha256": "file_sha256"}
# shown on a hit: the validated fields (A.4: never free text unless cleaned)
_HIT_FIELDS = ("source.ip", "destination.ip", "user.name", "user.target.name", "process.name",
               "process.executable", "file.path", "file.hash.sha256", "event.action", "event.outcome")


@dataclass
class EventHit:
    machine: str
    row: int
    ts: float
    dataset: str
    event_id: str
    via: str                                   # "field" | "text" | "column"
    fields: dict[str, Any] = field(default_factory=dict)
    excerpt: str = ""
    rule: dict[str, str] | None = None         # a detection: {id, name, author}

    def as_dict(self) -> dict[str, Any]:
        return {"machine": self.machine, "time": C.fmt(self.ts), "ts": self.ts, "source": self.dataset,
                "event_id": self.event_id, "matched": self.via, "fields": self.fields, "excerpt": self.excerpt,
                "detection": self.rule}


@dataclass
class SourceSummary:
    machine: str
    source: str                                # a dataset, "detections", or a snapshot kind
    count: int
    first: float | None
    last: float | None
    per_day: dict[str, int] = field(default_factory=dict)
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"machine": self.machine, "source": self.source, "count": self.count, "first": C.fmt(self.first),
                "last": C.fmt(self.last), "first_ts": self.first, "last_ts": self.last, "per_day": self.per_day,
                "note": self.note}


@dataclass
class TextScan:
    machine: str
    start: float
    end: float
    searched: int = 0
    total: int = 0
    matched: int = 0                            # events whose text holds it (may include typed hits)
    stopped_at: float | None = None             # the scan reached back to here, then ran out of time

    def as_dict(self) -> dict[str, Any]:
        return {"machine": self.machine, "from": C.fmt(self.start), "to": C.fmt(self.end), "searched": self.searched,
                "total": self.total, "matched": self.matched, "complete": self.stopped_at is None,
                "reached_back_to": C.fmt(self.stopped_at) if self.stopped_at else None}


@dataclass
class IndicatorResult:
    indicator: Indicator
    summaries: list[SourceSummary] = field(default_factory=list)
    hits: list[EventHit] = field(default_factory=list)
    snapshot_hits: list[SN.SnapHit] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    text_scans: list[TextScan] = field(default_factory=list)
    total_events: int = 0
    too_many: bool = False

    @property
    def found(self) -> bool:
        return bool(self.total_events or self.snapshot_hits or self.findings)

    def machines_hit(self) -> list[str]:
        return sorted({s.machine for s in self.summaries if s.count} | {h.machine for h in self.snapshot_hits}
                      | {str(f.get("machine")) for f in self.findings})


@dataclass
class HuntResult:
    indicators: list[IndicatorResult]
    machines: list[str]
    coverage: list[C.MachineCoverage]
    window: tuple[float | None, float | None]
    started: float
    finished: float
    index: dict[str, Any]
    snapshot_stats: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    record_id: int | None = None
    run_id: str | None = None

    @property
    def total_hits(self) -> int:
        return sum(r.total_events + len(r.snapshot_hits) + len(r.findings) for r in self.indicators)

    def as_dict(self) -> dict[str, Any]:
        from kratos import untrusted

        return {
            "window": {"from": C.fmt(self.window[0]) if self.window[0] else "everything Kratos holds",
                       "to": C.fmt(self.window[1]) if self.window[1] else "now"},
            "machines": self.machines,
            "index": self.index,
            "duration_seconds": round(self.finished - self.started, 3),
            "results": [{
                "indicator": r.indicator.as_dict(), "found": r.found, "total_events": r.total_events,
                "too_many_to_list": r.too_many, "machines_with_hits": r.machines_hit(),
                "by_source": [s.as_dict() for s in r.summaries],
                "hits": [untrusted.for_model(h.as_dict()) for h in r.hits],
                "snapshot_hits": [{"machine": h.machine, "source": h.label, "time": C.fmt(h.ts), "file": h.file,
                                   "what": untrusted.for_display(h.where), "prefix_only": h.prefix_only}
                                  for h in r.snapshot_hits],
                "findings": r.findings,
                "text_search": [t.as_dict() for t in r.text_scans],
            } for r in self.indicators],
            "coverage": [c.as_dict() for c in self.coverage],
            "record_id": self.record_id, "run_id": self.run_id,
        }


# --------------------------------------------------------------------------- helpers
def _day(ts: float) -> str:
    return C.fmt(ts)[:10]


def _boundary(ind: Indicator) -> re.Pattern[str]:
    v = re.escape(ind.value)
    if ind.kind == "ip":
        return re.compile(r"(?<![0-9A-Fa-f:.])" + v + r"(?![0-9A-Fa-f:]|\.\d)")
    if ind.kind == "path":
        return re.compile(v + r"(?![\w.-])")
    if ind.kind == "domain":
        return re.compile(r"(?<![\w.-])" + v + r"(?![\w-]|\.\w)", re.IGNORECASE)
    return re.compile(r"(?<![\w.@/-])" + v + r"(?![\w@-])")


def _like(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _hit(machine: str, row: int, ts: float, dataset: str, doc_text: str, via: str) -> EventHit:
    from kratos import untrusted

    try:
        doc = json.loads(doc_text)
    except ValueError:
        doc = {}
    fields = {}
    for name in _HIT_FIELDS:
        v = T._get(doc, name)
        if v is not None and v != "":
            fields[name] = untrusted.for_display(str(v))[:300]
    text = T._get(doc, "message") or T._get(doc, "event.original") or T._get(doc, "process.command_line") or ""
    rule = None
    if dataset == DETECT_DATASET:
        r = T._get(doc, "rule") or {}
        rule = {"id": str(r.get("id") or ""), "name": str(r.get("name") or ""),
                "author": ", ".join(r.get("author") or []) if isinstance(r.get("author"), list) else
                str(r.get("author") or "")}
    excerpt = untrusted.for_display(str(text))
    excerpt = " ".join(excerpt.split())
    if len(excerpt) > EXCERPT_CHARS:
        excerpt = excerpt[:EXCERPT_CHARS - 1] + "…"
    return EventHit(machine, int(row), float(ts), dataset, str(T._get(doc, "event.id") or ""), via, fields,
                    excerpt, rule)


def _window_sql(alias: str, start: float | None, end: float | None) -> tuple[str, list[Any]]:
    sql, args = "", []
    if start is not None:
        sql += f" AND {alias}.ts >= ?"
        args.append(start)
    if end is not None:
        sql += f" AND {alias}.ts < ?"
        args.append(end)
    return sql, args


# --------------------------------------------------------------------------- events
def _typed(conn: sqlite3.Connection, machine: str, ind: Indicator, start: float | None, end: float | None,
           max_hits: int) -> tuple[dict[str, SourceSummary], list[EventHit], int]:
    match, margs = T.match_clause(ind.kind, ind.value, ind.network)
    wsql, wargs = _window_sql("t", start, end)
    join = "JOIN host_events e ON e.id = t.row AND e.target = t.target AND e.ts = t.ts"
    base = f"FROM host_event_terms t {join} WHERE t.target = ? AND {match}{wsql}"
    args = [machine, *margs, *wargs]
    summaries: dict[str, SourceSummary] = {}
    for ds, day, n, lo, hi in conn.execute(
            f"SELECT e.dataset, CAST(t.ts / 86400 AS INTEGER), COUNT(DISTINCT t.row), MIN(t.ts), MAX(t.ts) {base} "
            "GROUP BY e.dataset, CAST(t.ts / 86400 AS INTEGER)", args):
        s = summaries.setdefault(ds, SourceSummary(machine, ds, 0, None, None))
        s.count += int(n)
        s.first = lo if s.first is None else min(s.first, lo)
        s.last = hi if s.last is None else max(s.last, hi)
        s.per_day[_day(day * 86400)] = s.per_day.get(_day(day * 86400), 0) + int(n)
    hits = [_hit(machine, r, ts, ds, doc, "field") for r, ts, ds, doc in conn.execute(
        f"SELECT DISTINCT e.id, e.ts, e.dataset, e.doc {base} ORDER BY t.ts DESC, e.id DESC LIMIT ?",
        (*args, max_hits))]
    if ind.kind == "ip":
        # an address the index took from the log text, not from a typed field: say so
        for h in hits:
            if not any(_in_network(ind, h.fields.get(f)) for f in ("source.ip", "destination.ip")) \
                    and not _related_has(conn, h.row, ind):
                h.via = "text"
    return summaries, hits, sum(s.count for s in summaries.values())


def _in_network(ind: Indicator, value: Any) -> bool:
    import ipaddress

    try:
        return value is not None and ipaddress.ip_address(str(value)) in ind.network
    except ValueError:
        return False


def _related_has(conn: sqlite3.Connection, row: int, ind: Indicator) -> bool:
    r = conn.execute("SELECT json_extract(doc, '$.related.ip') FROM host_events WHERE id = ?", (row,)).fetchone()
    try:
        return any(_in_network(ind, v) for v in json.loads(r[0] or "[]")) if r else False
    except (TypeError, ValueError):
        return False


def _unindexed(conn: sqlite3.Connection, machine: str, ind: Indicator, start: float | None, end: float | None,
               index: dict[str, Any], max_hits: int) -> tuple[list[EventHit], int]:
    """Events stored before the index existed and not indexed yet: their main columns."""
    col = _COLUMN_FOR.get(ind.kind)
    if col is None or index.get("done") or ind.is_cidr:
        return [], 0
    wsql, wargs = _window_sql("e", start, end)
    value = ind.value
    rows = conn.execute(f"SELECT e.id, e.ts, e.dataset, e.doc FROM host_events e WHERE e.target = ? AND e.{col} = ? "
                        f"AND e.id > ? AND e.id <= ?{wsql} ORDER BY e.ts DESC LIMIT ?",
                        (machine, value, index["through"], index["upto"], *wargs, max_hits)).fetchall()
    return [_hit(machine, r, ts, ds, doc, "column") for r, ts, ds, doc in rows], len(rows)


def _text_scan(conn: sqlite3.Connection, machine: str, ind: Indicator, start: float, end: float,
               deadline: float, max_hits: int) -> tuple[TextScan, list[EventHit]]:
    """Newest hour first, until the deadline. Counts what it searched."""
    scan = TextScan(machine, start, end)
    scan.total = int(conn.execute("SELECT COUNT(*) FROM host_events WHERE target = ? AND ts >= ? AND ts < ?",
                                  (machine, start, end)).fetchone()[0])
    if scan.total == 0:
        return scan, []
    pattern = _boundary(ind)
    like = _like(ind.value)
    hits: list[EventHit] = []
    hi = end
    interrupted = {"v": False}

    def _progress() -> int:
        if time.monotonic() > deadline:
            interrupted["v"] = True
            return 1
        return 0

    conn.set_progress_handler(_progress, 20000)
    try:
        while hi > start:
            lo = max(start, hi - SCAN_SLICE_SECONDS)
            if time.monotonic() > deadline:
                scan.stopped_at = hi
                break
            try:
                n = int(conn.execute("SELECT COUNT(*) FROM host_events WHERE target = ? AND ts >= ? AND ts < ?",
                                     (machine, lo, hi)).fetchone()[0])
                rows = conn.execute("SELECT id, ts, dataset, doc FROM host_events WHERE target = ? AND ts >= ? "
                                    "AND ts < ? AND doc LIKE ? ESCAPE '\\' ORDER BY ts DESC",
                                    (machine, lo, hi, like)).fetchall()
            except sqlite3.OperationalError:
                if interrupted["v"]:
                    scan.stopped_at = hi
                    break
                raise
            scan.searched += n
            for r, ts, ds, doc in rows:
                if pattern.search(doc):
                    scan.matched += 1
                    if len(hits) < max_hits:
                        hits.append(_hit(machine, r, ts, ds, doc, "text"))
            hi = lo
    finally:
        conn.set_progress_handler(None, 0)
    return scan, hits


# --------------------------------------------------------------------------- findings
def _finding_match(ind: Indicator, values: list[str]) -> bool:
    import ipaddress

    for v in values:
        if not v:
            continue
        if ind.kind == "ip":
            for token in re.findall(r"[0-9A-Fa-f:.]+", v):
                try:
                    if ipaddress.ip_address(token) in ind.network:
                        return True
                except ValueError:
                    continue
        elif ind.kind == "sha256":
            frag = v.partition("#")[2].lower()
            if (frag and len(frag) >= 12 and ind.value.startswith(frag)) or ind.value in v.lower():
                return True
        elif ind.kind == "path":
            p = v.partition("#")[0].split("|")[0]
            if p == ind.value or p.startswith(ind.value.rstrip("/") + "/"):
                return True
        elif _boundary(ind).search(v):
            return True
    return False


def _findings(conn: sqlite3.Connection, machines: list[str], ind: Indicator) -> list[dict[str, Any]]:
    if not conn.execute("SELECT 1 FROM sqlite_schema WHERE name='finding_records'").fetchone():
        return []
    from kratos.lifecycle.keys import short

    out = []
    marks = ",".join("?" * len(machines)) or "NULL"
    for r in conn.execute(f"SELECT finding_key, rule_id, target, subject, state, severity, title, entities, "
                          f"first_seen, last_seen FROM finding_records WHERE target IN ({marks})", machines):
        try:
            ents = [str(e) for e in json.loads(r[7] or "[]")]
        except ValueError:
            ents = []
        if _finding_match(ind, [str(r[3] or ""), *ents]):
            out.append({"machine": r[2], "key": short(r[0]), "rule": r[1], "state": r[4], "severity": r[5],
                        "title": r[6], "first_seen": C.fmt(r[8]), "last_seen": C.fmt(r[9])})
    return out


# --------------------------------------------------------------------------- the hunt
def run_hunt(data_dir: Path | str, indicators: list[Indicator], *, machines: list[str] | None = None,
             start: float | None = None, end: float | None = None, source: str = "cli", actor: str = "?",
             record: bool = True, now: float | None = None, with_text: bool = True,
             with_snapshots: bool = True, progress: Callable[[str], None] | None = None) -> HuntResult:
    """Hunt `indicators` over `machines` (default: every machine Kratos holds anything
    about). `machines` is the caller's scope: a chat token's machines, never more."""
    from kratos import run_context
    from kratos.storage.sqlite_files import connect_store

    data_dir = Path(data_dir)
    started = time.time()
    now = started if now is None else now
    say = progress or (lambda _m: None)
    machines = sorted({target_key(m) for m in machines}) if machines is not None else C.known_machines(data_dir)
    max_hits = int(settings_store.get(S.MAX_HITS, data_dir=data_dir))
    scan_seconds = float(settings_store.get(S.SCAN_SECONDS, data_dir=data_dir))
    scan_days = int(settings_store.get(S.SCAN_DAYS, data_dir=data_dir))
    snap_files = int(settings_store.get(S.SNAPSHOT_FILES, data_dir=data_dir))
    index_seconds = float(settings_store.get(S.INDEX_SECONDS, data_dir=data_dir))

    from kratos.events.store import EventStore

    EventStore(data_dir / "kratos.db")._connect().close()       # tables (and the index) exist, even when empty
    conn = connect_store(data_dir / "kratos.db")
    try:
        say("bringing the search index up to date…")
        index = T.backfill(conn, seconds=index_seconds)
        results = [IndicatorResult(ind) for ind in indicators]
        snapshot_stats: dict[str, dict[str, dict[str, Any]]] = {}
        loaded_snaps: dict[str, SN.Loaded] = {}
        text_end = end if end is not None else now + 1
        text_start = max(start or 0.0, text_end - scan_days * 86400)
        deadline_each = scan_seconds / max(1, len(machines) * len(indicators))
        for res in results:
            ind = res.indicator
            say(f"searching for {ind.label} {ind.value}…")
            for m in machines:
                summaries, hits, total = _typed(conn, m, ind, start, end, max_hits)
                col_hits, col_n = _unindexed(conn, m, ind, start, end, index, max_hits)
                seen = {h.row for h in hits}
                for h in col_hits:
                    if h.row not in seen:
                        hits.append(h)
                        seen.add(h.row)
                        s = summaries.setdefault(h.dataset, SourceSummary(m, h.dataset, 0, None, None,
                                                                          note="not yet in the search index"))
                        s.count += 1
                        s.first = h.ts if s.first is None else min(s.first, h.ts)
                        s.last = h.ts if s.last is None else max(s.last, h.ts)
                        s.per_day[_day(h.ts)] = s.per_day.get(_day(h.ts), 0) + 1
                        total += 1
                if with_text and not (ind.kind == "sha256" or ind.is_cidr):
                    scan, thits = _text_scan(conn, m, ind, text_start, text_end,
                                             time.monotonic() + deadline_each, max_hits)
                    res.text_scans.append(scan)
                    extra = [h for h in thits if h.row not in seen]
                    for h in extra:
                        seen.add(h.row)
                        s = summaries.setdefault(f"{h.dataset} (log text)",
                                                 SourceSummary(m, f"{h.dataset} (log text)", 0, None, None,
                                                               note="found in the log text, not a typed field"))
                        s.count += 1
                        s.first = h.ts if s.first is None else min(s.first, h.ts)
                        s.last = h.ts if s.last is None else max(s.last, h.ts)
                        s.per_day[_day(h.ts)] = s.per_day.get(_day(h.ts), 0) + 1
                        total += 1
                    hits.extend(extra)
                for s in summaries.values():
                    if s.source == DETECT_DATASET:
                        s.source = "detections"
                res.summaries.extend(s for s in summaries.values() if s.count)
                res.total_events += total
                res.hits.extend(hits)
                if m not in loaded_snaps:
                    loaded_snaps[m] = (SN.load(data_dir, m, start=start, end=end, max_files=snap_files)
                                       if with_snapshots else SN.Loaded([], {}))
                shits = SN.match(loaded_snaps[m], data_dir, m, ind, start=start, end=end)
                res.snapshot_hits.extend(shits)
                snapshot_stats[m] = loaded_snaps[m].stats
                if shits:
                    by_kind = defaultdict(list)
                    for h in shits:
                        by_kind[h.label].append(h.ts)
                    for label, tss in by_kind.items():
                        res.summaries.append(SourceSummary(m, label, len(tss), min(tss), max(tss),
                                                           {_day(t): sum(1 for x in tss if _day(x) == _day(t))
                                                            for t in tss}))
            res.findings = _findings(conn, machines, ind)
            res.hits.sort(key=lambda h: (h.ts, h.row), reverse=True)
            res.too_many = res.total_events > max_hits
            res.hits = res.hits[:max_hits]
        say("working out what Kratos holds (coverage)…")
        covs = []
        for m in machines:
            snaps = {st["label"] + "s": st for st in snapshot_stats.get(m, {}).values()}
            covs.append(C.machine_coverage(data_dir, m, start=start, end=end, snapshots=snaps, now=now, conn=conn))
    finally:
        conn.close()
    ctx = run_context.current()
    result = HuntResult(results, machines, covs, (start, end), started, time.time(), index,
                        snapshot_stats, run_id=ctx.run_id if ctx else None)
    if record:
        from kratos.hunt import store

        result.record_id = store.record(
            data_dir, at=started, source=source, actor=actor,
            indicators=[r.indicator.as_dict() for r in results], window=(start, end), machines=machines,
            coverage=C.summary_line(covs), hits=result.total_hits,
            hit_machines=len({m for r in results for m in r.machines_hit()}),
            summary={r.indicator.value: {s.machine + " " + s.source: {"count": s.count, "first": s.first,
                                                                      "last": s.last}
                                         for s in r.summaries} for r in results},
            run_id=result.run_id)
    return result
