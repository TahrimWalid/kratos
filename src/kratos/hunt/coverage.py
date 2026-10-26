"""What a hunt could see: coverage built ONLY from Kratos's own records (C.3 §3.4).

Never from "the query returned nothing". Per machine:

- **synced** -- `sync_coverage` spans per log source: stretches where Kratos holds
  EVERY matching line, recorded gaps (a vacuumed journal, a lost rotation), and the
  holes in between (not synced then);
- **watched** -- C.2's `detect_watch`: watching continuously since when, per log, and
  the stretches the watcher reported it could not watch. Watching stores rule MATCHES
  only, so a watched stretch says the detection rules saw every line -- the full lines
  come from log sync;
- **read** -- what the event store holds per log source outside synced stretches
  (lines Kratos read during investigations): first and last time and how many --
  partial by nature;
- **pruned** -- `data_prunes`: events older than a cutoff that the person removed;
- **snapshots** -- saved persistence / running-process reads in the window, and the
  installed-package lists Kratos kept;
- **nothing** -- a machine with none of these is "not searched: Kratos holds nothing
  from it for this period".
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kratos.target_key import target_key

UTC = timezone.utc
SYNC_STALE_SECONDS = 6 * 3600       # a source not synced for this long is "not synced since"


def fmt(ts: float | None) -> str:
    if ts is None:
        return "?"
    try:
        return datetime.fromtimestamp(float(ts), UTC).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return "?"


def _table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?", (name,)).fetchone() is not None


@dataclass
class SourceSync:
    source: str
    spans: list[tuple[float, float]] = field(default_factory=list)      # complete, clipped to the window
    gaps: list[tuple[float, float, str]] = field(default_factory=list)  # recorded gaps
    holes: list[tuple[float, float]] = field(default_factory=list)      # between spans: not synced then
    since_stale: float | None = None                                      # last synced up to here, long ago


@dataclass
class SourceWatch:
    source: str
    state: str
    watching_since: float | None
    gaps: list[dict[str, Any]] = field(default_factory=list)            # [{from, to, reason}] in the window
    error: str | None = None


@dataclass
class MachineCoverage:
    machine: str
    window: tuple[float | None, float]
    synced: list[SourceSync] = field(default_factory=list)
    watched: list[SourceWatch] = field(default_factory=list)
    watch_enabled: bool = False
    watch_notes: list[str] = field(default_factory=list)                # link down, rules not confirmed, ...
    read: dict[str, dict[str, Any]] = field(default_factory=dict)       # dataset -> {first, last, count}
    events_total: int = 0
    pruned: list[dict[str, Any]] = field(default_factory=list)
    snapshots: dict[str, dict[str, Any]] = field(default_factory=dict)  # kind -> {count, first, last}
    findings: int = 0

    @property
    def holds_anything(self) -> bool:
        return bool(self.events_total or any(s.spans for s in self.synced) or self.watched
                    or any(v.get("count") for v in self.snapshots.values()) or self.findings)

    def lines(self) -> list[str]:
        """The coverage in plain words, one line each."""
        out: list[str] = []
        if not self.holds_anything:
            return [f"not searched: Kratos holds nothing from {self.machine} for this period (never synced, "
                    "never watched, no events or snapshots)"]
        for s in self.synced:
            if s.spans:
                parts = [f"{fmt(a)} to {fmt(b)}" for a, b in s.spans[:4]]
                more = f" (+{len(s.spans) - 4} more)" if len(s.spans) > 4 else ""
                out.append(f"{s.source} log: every line held for {', '.join(parts)}{more}")
            for a, b, note in s.gaps[:5]:
                out.append(f"{s.source} log: GAP {fmt(a)} to {fmt(b)} -- {note or 'lines missing'}")
            for a, b in s.holes[:5]:
                out.append(f"{s.source} log: not synced from {fmt(a)} to {fmt(b)}")
            if s.since_stale is not None:
                out.append(f"{s.source} log: not synced since {fmt(s.since_stale)}")
        if self.watched:
            for w in self.watched:
                if w.state == "watching" and w.watching_since:
                    out.append(f"{w.source}: watched live since {fmt(w.watching_since)} (only rule matches are "
                               "stored from watching)")
                else:
                    out.append(f"{w.source}: NOT being watched now ({w.state}{': ' + w.error if w.error else ''})")
                for g in w.gaps[:5]:
                    out.append(f"{w.source}: not watched from {fmt(g.get('from'))} to {fmt(g.get('to'))} -- "
                               f"{g.get('reason') or 'no reason given'}")
            for note in self.watch_notes[:4]:
                out.append(f"watching: {note}")
        elif self.watch_enabled is False:
            out.append("not watched continuously (no agent watches this machine)")
        synced_ds = {_dataset_of(s.source) for s in self.synced if s.spans}
        for ds, v in sorted(self.read.items()):
            if ds in synced_ds or ds == "kratos.detect":
                continue
            out.append(f"{ds}: {v['count']:,} event(s) Kratos read between {fmt(v['first'])} and {fmt(v['last'])} "
                       "(only what investigations read -- not every line)")
        for p in self.pruned:
            out.append(f"PRUNED: events before {fmt(p['cutoff'])} were removed on {fmt(p['at'])} by {p['actor']} "
                       "-- nothing before then can be found")
        for kind, v in sorted(self.snapshots.items()):
            if v.get("count"):
                out.append(f"{kind}: {v['count']} saved read(s) between {fmt(v['first'])} and {fmt(v['last'])}")
        return out

    def as_dict(self) -> dict[str, Any]:
        return {"machine": self.machine, "window": list(self.window), "holds_anything": self.holds_anything,
                "synced": [{"source": s.source, "spans": s.spans, "gaps": s.gaps, "holes": s.holes,
                            "not_synced_since": s.since_stale} for s in self.synced],
                "watched": [{"source": w.source, "state": w.state, "watching_since": w.watching_since,
                             "gaps": w.gaps, "error": w.error} for w in self.watched],
                "watch_notes": self.watch_notes, "read": self.read, "events": self.events_total, "pruned": self.pruned,
                "snapshots": self.snapshots, "statement": self.lines()}


def _dataset_of(source: str) -> str:
    """The event dataset a log-sync source stores (auth -> kratos.auth, packages -> kratos.package)."""
    try:
        from kratos.logsources.catalog import SYNC_SOURCES

        return SYNC_SOURCES[source].dataset
    except (ImportError, KeyError):
        return f"kratos.{source}"


# --------------------------------------------------------------------------- building
def _clip(a: float, b: float, lo: float | None, hi: float) -> tuple[float, float] | None:
    a2, b2 = max(a, lo) if lo is not None else a, min(b, hi)
    return (a2, b2) if b2 > a2 else None


def _synced(conn: sqlite3.Connection, machine: str, lo: float | None, hi: float, now: float) -> list[SourceSync]:
    if not _table(conn, "sync_coverage"):
        return []
    out: dict[str, SourceSync] = {}
    rows = conn.execute("SELECT source, start_ts, end_ts, complete, note FROM sync_coverage WHERE target = ? "
                        "ORDER BY source, start_ts", (machine,)).fetchall()
    for source, a, b, complete, note in rows:
        s = out.setdefault(source, SourceSync(source))
        c = _clip(float(a), float(b), lo, hi)
        if c is None:
            continue
        if complete:
            s.spans.append(c)
        else:
            s.gaps.append((c[0], c[1], str(note or "")))
    for s in out.values():
        s.spans.sort()
        for (a1, b1), (a2, b2) in zip(s.spans, s.spans[1:]):
            if a2 - b1 > 1.0 and not any(g[0] <= b1 + 1 and g[1] >= a2 - 1 for g in s.gaps):
                s.holes.append((b1, a2))
        if s.spans and now - s.spans[-1][1] > SYNC_STALE_SECONDS and hi >= now - 60:
            s.since_stale = s.spans[-1][1]
    return [out[k] for k in sorted(out)]


def _watched(data_dir: Path, machine: str, lo: float | None,
             hi: float) -> tuple[bool, list[SourceWatch], list[str]]:
    try:
        from kratos.detect import live
    except Exception:  # noqa: BLE001
        return False, [], []
    out: list[SourceWatch] = []
    notes: list[str] = []
    try:
        targets = live.watched_targets(data_dir, machine)
    except Exception:  # noqa: BLE001
        return False, [], []
    for st in targets:
        for r in live.watch_rows(data_dir, st["target_id"]):
            gaps = []
            for g in r.get("gaps") or []:
                try:
                    a, b = float(g.get("from")), float(g.get("to"))
                except (TypeError, ValueError):
                    continue
                if _clip(a, b, lo, hi) is not None:
                    gaps.append({"from": a, "to": b, "reason": str(g.get("reason") or "")})
            out.append(SourceWatch(r["source"], str(r.get("state") or "off"), r.get("watching_since"), gaps,
                                   r.get("error")))
        try:
            h = live.health(data_dir, st["target_id"])
            notes += [text for code, text in h.reasons if not str(code).startswith(("gap:", "stopped:"))]
        except Exception:  # noqa: BLE001 -- health is a note, never a reason the hunt fails
            pass
    return bool(targets), out, notes


def _read(conn: sqlite3.Connection, machine: str, lo: float | None, hi: float) -> tuple[dict[str, dict], int]:
    if not _table(conn, "host_events"):
        return {}, 0
    sql = "SELECT dataset, MIN(ts), MAX(ts), COUNT(*) FROM host_events WHERE target = ? AND ts < ?"
    args: list[Any] = [machine, hi]
    if lo is not None:
        sql += " AND ts >= ?"
        args.append(lo)
    out, total = {}, 0
    for ds, a, b, n in conn.execute(sql + " GROUP BY dataset", args):
        out[ds] = {"first": a, "last": b, "count": int(n)}
        total += int(n)
    return out, total


def _pruned(conn: sqlite3.Connection, lo: float | None) -> list[dict[str, Any]]:
    if not _table(conn, "data_prunes"):
        return []
    rows = conn.execute("SELECT at, actor, cutoff FROM data_prunes WHERE category = 'host_events' "
                        "ORDER BY cutoff DESC").fetchall()
    out = []
    for at, actor, cutoff in rows:
        if lo is None or cutoff > lo:
            out.append({"at": at, "actor": actor, "cutoff": cutoff})
    return out[:1]          # the newest cutoff covers every older one


def _findings(conn: sqlite3.Connection, machine: str) -> int:
    if not _table(conn, "finding_records"):
        return 0
    return int(conn.execute("SELECT COUNT(*) FROM finding_records WHERE target = ?", (machine,)).fetchone()[0])


def machine_coverage(data_dir: Path | str, machine: str, *, start: float | None = None, end: float | None = None,
                     snapshots: dict[str, dict[str, Any]] | None = None, now: float | None = None,
                     conn: sqlite3.Connection | None = None) -> MachineCoverage:
    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    hi = end if end is not None else now + 1
    key = target_key(machine)
    own = conn is None
    if own:
        from kratos.storage.sqlite_files import connect_store

        conn = connect_store(data_dir / "kratos.db")
    try:
        cov = MachineCoverage(key, (start, hi))
        cov.synced = _synced(conn, key, start, hi, now)
        cov.read, cov.events_total = _read(conn, key, start, hi)
        cov.pruned = _pruned(conn, start)
        cov.findings = _findings(conn, key)
    finally:
        if own:
            conn.close()
    cov.watch_enabled, cov.watched, cov.watch_notes = _watched(data_dir, key, start, hi)
    cov.snapshots = snapshots or {}
    return cov


def known_machines(data_dir: Path | str) -> list[str]:
    """Every machine Kratos holds anything about: events, sync records, watching,
    findings, package lists -- plus the configured machine."""
    from kratos.storage.sqlite_files import connect_store

    out: set[str] = set()
    db = Path(data_dir) / "kratos.db"
    if db.exists():
        conn = connect_store(db)
        try:
            for table, col in (("host_events", "target"), ("sync_coverage", "target"),
                               ("finding_records", "target"), ("pkg_inventory", "target"),
                               ("detect_pack_state", "machine")):
                if _table(conn, table):
                    out |= {str(r[0]) for r in conn.execute(f"SELECT DISTINCT {col} FROM {table}") if r[0]}
        finally:
            conn.close()
    try:
        from kratos import kratos_config

        t = kratos_config.get_active_target()
        if t:
            out.add(target_key(t))
    except Exception:  # noqa: BLE001
        pass
    return sorted(out)


def summary_line(covs: list[MachineCoverage]) -> str:
    """One line for the hunt record."""
    parts = []
    for c in covs:
        if not c.holds_anything:
            parts.append(f"{c.machine}: nothing held")
            continue
        bits = []
        synced = [s for s in c.synced if s.spans]
        if synced:
            lo = min(s.spans[0][0] for s in synced)
            bits.append(f"synced {','.join(s.source for s in synced)} from {fmt(lo)}")
        live = [w for w in c.watched if w.state == "watching" and w.watching_since]
        if live:
            bits.append(f"watched since {fmt(min(w.watching_since for w in live))}")
        if c.events_total:
            bits.append(f"{c.events_total:,} events")
        if c.pruned:
            bits.append(f"pruned before {fmt(c.pruned[0]['cutoff'])}")
        gaps = sum(len(s.gaps) + len(s.holes) for s in c.synced) + sum(len(w.gaps) for w in c.watched)
        if gaps:
            bits.append(f"{gaps} gap(s)")
        parts.append(f"{c.machine}: " + "; ".join(bits))
    return " | ".join(parts)

