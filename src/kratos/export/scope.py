"""What an export holds: the person's choice (machines or a group, a period, contents),
turned into a plan of files, events and findings, with a size estimate and the caps.

Everything here only reads. The plan is taken at one instant: the event store's newest
row id and the ledger's head are recorded first, so an export taken while log sync is
writing holds a consistent snapshot (events up to that row, files up to that ledger row).
"""
from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kratos.evidence import ledger as L
from kratos.target_key import target_key

VARIANTS = ("full", "redacted")
FINDINGS_CHOICES = ("window", "open", "all", "none")
# ledger categories that are run records / findings reports (the rest are snapshots)
RUN_CATEGORIES = frozenset({"run_record"})
REPORT_CATEGORIES = frozenset({"findings_report", "findings_report_md"})
_STAMP_RE = re.compile(r"(\d{8})_(\d{6})")


class ExportError(ValueError):
    pass


@dataclass
class ExportRequest:
    machines: list[str]                       # target_key form
    start: float | None                       # epoch seconds UTC; None = from the beginning
    end: float                                # epoch seconds UTC
    variant: str = "full"
    group: str | None = None                  # the group the machines came from, for the record
    include_snapshots: bool = True
    include_runs: bool = True
    include_events: bool = True
    findings: str = "window"
    narrative: bool = False
    archive: bool = True

    def check(self) -> None:
        if not self.machines:
            raise ExportError("no machine chosen")
        if self.variant not in VARIANTS:
            raise ExportError(f"variant must be one of {VARIANTS}")
        if self.findings not in FINDINGS_CHOICES:
            raise ExportError(f"findings must be one of {FINDINGS_CHOICES}")
        if self.start is not None and self.start >= self.end:
            raise ExportError("the period's start must be before its end")

    def as_dict(self) -> dict[str, Any]:
        return {"machines": list(self.machines), "group": self.group, "window": {"start": _iso(self.start),
                                                                                "end": _iso(self.end)},
                "variant": self.variant,
                "include": {"snapshots": self.include_snapshots, "run_records": self.include_runs,
                            "events": self.include_events, "findings": self.findings,
                            "narrative": self.narrative}}


def _iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class PlannedFile:
    source_rel: str                     # path in the data folder
    machine: str
    category: str
    entry: L.LedgerEntry | None         # the newest ledger row of this path (None: predates the ledger)
    size: int
    captured_at: float | None           # when Kratos wrote it (ledger) or a best guess (pre-ledger)
    captured_how: str                   # "ledger" | "content:collected_at" | "filename" | "file mtime"


@dataclass
class PlannedEvents:
    machine: str
    dataset: str
    count: int                          # rows that fall in the window (up to the snapshot row)
    included: int                       # after the cap
    cut_at: float | None = None         # ts of the first event left out by the cap


@dataclass
class Plan:
    export_id: str
    request: ExportRequest
    taken_at: float
    events_upto_row: int
    ledger_head: tuple[int, str]
    files: list[PlannedFile] = field(default_factory=list)
    events: list[PlannedEvents] = field(default_factory=list)
    findings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)   # machine -> records
    unattributed: int = 0               # pre-ledger files in the window whose machine can't be told
    max_events: int = 0

    @property
    def total_events(self) -> int:
        return sum(e.included for e in self.events)

    @property
    def file_bytes(self) -> int:
        return sum(f.size for f in self.files)

    def cuts(self) -> list[dict[str, Any]]:
        return [{"machine": e.machine, "dataset": e.dataset, "in_window": e.count, "included": e.included,
                 "left_out_from": _iso(e.cut_at),
                 "why": f"the export copies at most {self.max_events:,} events (export.max_events)"}
                for e in self.events if e.included < e.count]

    def estimate_bytes(self) -> int:
        # an exported event line is about the size of its stored document (~600 bytes measured on the lab)
        return self.file_bytes + self.total_events * 600 + 200_000

    def summary_lines(self) -> list[str]:
        r = self.request
        win = f"{_iso(r.start) or 'the beginning'} to {_iso(r.end)}"
        out = [f"machines: {', '.join(r.machines)}" + (f" (group @{r.group})" if r.group else ""),
               f"period: {win}",
               f"variant: {r.variant}" + (" (names and addresses replaced, secrets removed)"
                                         if r.variant == "redacted" else ""),
               f"evidence files: {len(self.files)} ({self.file_bytes / 1e6:.1f} MB)"
               + (f", {sum(1 for f in self.files if f.entry is None)} of them from before the evidence "
                  "ledger (hashed when exporting)" if any(f.entry is None for f in self.files) else ""),
               f"events: {self.total_events:,}" if r.include_events else "events: not included",
               f"findings: {sum(len(v) for v in self.findings.values())}",
               f"estimated size: {self.estimate_bytes() / 1e6:.1f} MB"]
        for c in self.cuts():
            out.append(f"CUT: {c['machine']} {c['dataset']}: {c['included']:,} of {c['in_window']:,} events "
                       f"(left out from {c['left_out_from']}) -- {c['why']}")
        if self.unattributed:
            out.append(f"not included: {self.unattributed} older file(s) in the period whose machine can't be told")
        return out


# ---------------------------------------------------------------------------
# pre-ledger files: when and for which machine
# ---------------------------------------------------------------------------
def _captured(path: Path) -> tuple[float, str, str | None]:
    from kratos.timewin import snapshots as S

    try:
        t, how, target = S._captured(path, "")
    except Exception:  # noqa: BLE001
        return path.stat().st_mtime, "file mtime", None
    if path.suffix == ".json" and target is None:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                target = data.get("machine") or data.get("target_key") or S._json_target(data)
        except (OSError, ValueError):
            pass
    return t, how, target


def _in_window(t: float | None, req: ExportRequest) -> bool:
    return t is not None and (req.start is None or t >= req.start) and t <= req.end


# ---------------------------------------------------------------------------
# the plan
# ---------------------------------------------------------------------------
def _events_upto(data_dir: Path) -> int:
    from kratos.storage.sqlite_files import connect_store

    p = data_dir / "kratos.db"
    if not p.exists():
        return 0
    conn = connect_store(p)
    try:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='host_events'").fetchone():
            return 0
        return int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM host_events").fetchone()[0])
    finally:
        conn.close()


def _event_counts(data_dir: Path, req: ExportRequest, upto: int, cap: int) -> list[PlannedEvents]:
    from kratos.storage.sqlite_files import connect_store

    if not req.include_events or upto == 0:
        return []
    conn = connect_store(data_dir / "kratos.db")
    out: list[PlannedEvents] = []
    left = cap
    try:
        for m in req.machines:
            rows = conn.execute(
                "SELECT dataset, COUNT(*) FROM host_events WHERE target = ? AND id <= ? AND ts <= ?"
                + (" AND ts >= ?" if req.start is not None else "") + " GROUP BY dataset ORDER BY dataset",
                (m, upto, req.end) + ((req.start,) if req.start is not None else ())).fetchall()
            for ds, n in rows:
                inc = min(n, max(left, 0))
                pe = PlannedEvents(m, ds, n, inc)
                if inc < n:
                    r = conn.execute(
                        "SELECT ts FROM host_events WHERE target = ? AND dataset = ? AND id <= ? AND ts <= ?"
                        + (" AND ts >= ?" if req.start is not None else "")
                        + " ORDER BY ts, id LIMIT 1 OFFSET ?",
                        (m, ds, upto, req.end) + ((req.start,) if req.start is not None else ()) + (inc,)).fetchone()
                    pe.cut_at = r[0] if r else None
                left -= inc
                out.append(pe)
    finally:
        conn.close()
    return out


def _findings(data_dir: Path, req: ExportRequest) -> dict[str, list[dict[str, Any]]]:
    from kratos.lifecycle import store as LS

    if req.findings == "none" or not (data_dir / "kratos.db").exists():
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    with LS.opened(data_dir) as conn:
        for m in req.machines:
            recs = []
            for r in conn.execute("SELECT * FROM finding_records WHERE target = ? ORDER BY first_seen", (m,)):
                state = r["state"]
                if req.findings == "open" and state not in ("open", "verified"):
                    continue
                if req.findings == "window" and not (
                        r["first_seen"] <= req.end and (req.start is None or r["last_seen"] >= req.start)):
                    continue
                recs.append(dict(r))
            if recs:
                out[m] = recs
    return out


def plan(data_dir: Path | str, req: ExportRequest, *, now: float | None = None) -> Plan:
    """Decide what goes in. Records the snapshot point first (newest event row, ledger head)."""
    from kratos.export import settings as ES

    data_dir = Path(data_dir)
    req.machines = list(dict.fromkeys(target_key(m) for m in req.machines if target_key(m)))
    req.check()
    taken = time.time() if now is None else now
    head = L.head(data_dir)
    upto = _events_upto(data_dir)
    cap = int(ES.get(ES.MAX_EVENTS, data_dir))
    p = Plan(export_id=f"{datetime.fromtimestamp(taken, timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}",
             request=req, taken_at=taken, events_upto_row=upto, ledger_head=head, max_events=cap)
    wanted = set(req.machines)

    # 1. files the ledger recorded: every path with a row for one of the machines in the window
    newest: dict[str, L.LedgerEntry] = {}
    in_window: set[str] = set()
    for e in L.entries(data_dir, upto_seq=head[0]):
        if not e.path or e.path.startswith("exports/"):
            continue
        newest[e.path] = e
        if e.machine in wanted and _in_window(e.written_at, req):
            in_window.add(e.path)
    root = data_dir
    for rel in sorted(in_window):
        e = newest[rel]
        if e.machine not in wanted:
            continue          # a file now recorded for another machine (replaced in place): not this machine's
        if e.category in RUN_CATEGORIES and not req.include_runs:
            continue
        if e.category not in RUN_CATEGORIES | REPORT_CATEGORIES and not req.include_snapshots:
            continue
        p_ = root / rel
        if not p_.is_file():
            continue          # pruned since: the manifest's ledger section still lists it as recorded
        p.files.append(PlannedFile(rel, e.machine or "", e.category or "", e, p_.stat().st_size,
                                   e.written_at, "ledger"))

    # 2. files from before the ledger: no row at all, captured in the window, machine from the content
    if req.include_snapshots:
        for rel, path in L.evidence_files(data_dir):
            if rel in newest or rel.startswith("exports/") or rel.startswith("traces/"):
                continue
            t, how, target = _captured(path)
            if not _in_window(t, req):
                continue
            mk = target_key(target) if target else ""
            if mk not in wanted:
                if not mk:
                    p.unattributed += 1
                continue
            p.files.append(PlannedFile(rel, mk, rel.split("/")[0], None, path.stat().st_size, t, how))

    p.events = _event_counts(data_dir, req, upto, cap)
    p.findings = _findings(data_dir, req)
    return p
