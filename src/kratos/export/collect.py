"""Copy a plan into a bundle folder: evidence files, events, findings and coverage.

Every file written is listed as a :class:`BundleFile` with its SHA-256 and where that hash
comes from:

- ``hashed_at = "collection"`` -- the file's bytes match the evidence-ledger row written
  when Kratos collected it; the hash IS the collection-time hash.
- ``hashed_at = "export"`` -- the file predates the ledger, or (a warning) it no longer
  matches what the ledger recorded: the hash is of the file as exported.
- ``generated`` -- written now from Kratos's database (findings, coverage); the hash is of
  the generated file.

In the redacted variant every file is masked; its ``sha256`` is of the redacted bytes, and
``original_sha256`` keeps the collection-time hash of the original so a holder of the full
data can prove correspondence.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from kratos.evidence import ledger as L
from kratos.export.redact import Redactor
from kratos.export.scope import Plan, _iso

Progress = Callable[[str], None]
INDEX_HEADER = b"# line\tevent_id\tsha256 of the line (without its newline)\n"


@dataclass
class BundleFile:
    path: str                        # inside the bundle, '/'-separated
    sha256: str
    size: int
    kind: str                        # evidence | events | event_index | generated | report
    machine: str | None = None       # as shown in the bundle (a placeholder in the redacted variant)
    category: str | None = None
    hashed_at: str = "export"        # collection | export | generated
    source_path: str | None = None   # path in the data folder (full variant only)
    collected_at: str | None = None
    ledger_seq: int | None = None
    ledger_entry_hash: str | None = None
    read: str | None = None
    transport: str | None = None
    run_id: str | None = None
    kratos_build: str | None = None
    original_sha256: str | None = None
    events: int | None = None
    index: str | None = None         # the per-line index of an events file
    warning: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class Collected:
    files: list[BundleFile] = field(default_factory=list)
    findings: dict[str, list[dict[str, Any]]] = field(default_factory=dict)   # shown machine -> findings
    coverage: dict[str, dict[str, Any]] = field(default_factory=dict)         # shown machine -> coverage
    timeline: list[dict[str, Any]] = field(default_factory=list)
    machine_names: dict[str, str] = field(default_factory=dict)                # real -> shown
    warnings: list[str] = field(default_factory=list)


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _safe_dir(name: str) -> str:
    out = "".join(c if (c.isalnum() or c in "-._") else "_" for c in name) or "_"
    return out.lstrip(".") or "_"


def _copy_hashed(src: Path, dst: Path) -> tuple[str, int]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    n = 0
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            chunk = fi.read(L.CHUNK)
            if not chunk:
                break
            h.update(chunk)
            fo.write(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def _write_text(dst: Path, text: str) -> tuple[str, int]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")
    dst.write_bytes(data)
    return _sha256_bytes(data), len(data)


def _json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n"


def collect(data_dir: Path, plan: Plan, out: Path, red: Redactor, *, progress: Progress | None = None) -> Collected:
    say = progress or (lambda _m: None)
    c = Collected()
    for m in plan.request.machines:
        c.machine_names[m] = red.machine(m)
    shown = c.machine_names

    # 1. evidence files
    counters: dict[tuple[str, str], int] = {}
    for i, f in enumerate(plan.files, 1):
        if i % 50 == 0:
            say(f"copying evidence {i}/{len(plan.files)}")
        src = data_dir / f.source_rel
        mdir = _safe_dir(shown[f.machine])
        folder = f.source_rel.split("/")[0]
        if red.active:
            k = (mdir, folder)
            counters[k] = counters.get(k, 0) + 1
            suffix = PurePosixPath(f.source_rel).suffix or ".txt"
            rel = f"evidence/{mdir}/{folder}/{counters[k]:04d}_{_safe_dir(f.category)}{suffix}"
        else:
            rel = f"evidence/{mdir}/{f.source_rel}"
        dst = out / rel
        try:
            if red.active:
                raw = src.read_bytes()
                orig = _sha256_bytes(raw)
                digest, size = _write_text(dst, red.text(raw.decode("utf-8", errors="replace")))
            else:
                digest, size = _copy_hashed(src, dst)
                orig = digest
        except OSError as e:
            c.warnings.append(f"{rel if red.active else f.source_rel}: couldn't be read ({type(e).__name__}); left out")
            continue
        e = f.entry
        bf = BundleFile(rel, digest, size, "evidence", shown[f.machine], f.category,
                        source_path=None if red.active else f.source_rel,
                        collected_at=_iso(f.captured_at), read=e.read if e else None,
                        transport=e.transport if e else None, run_id=e.run_id if e else None,
                        kratos_build=e.build if e else None)
        if e is not None and e.sha256 == orig:
            bf.hashed_at = "collection"
            bf.ledger_seq, bf.ledger_entry_hash = e.seq, e.entry_hash
        elif e is not None:
            bf.hashed_at = "export"
            bf.ledger_seq, bf.ledger_entry_hash = e.seq, e.entry_hash
            bf.warning = (f"this file no longer matches what Kratos recorded when it collected it (ledger row "
                          f"{e.seq}, {_iso(e.written_at)}, sha256 {e.sha256}); the hash here is of the file as "
                          "exported")
            c.warnings.append(f"{rel}: changed since collection (ledger row {e.seq})")
        else:
            bf.hashed_at = "export"
            bf.warning = "hash taken when exporting (this file predates Kratos's evidence ledger)"
        if red.active:
            bf.original_sha256 = e.sha256 if (e is not None and e.sha256 == orig) else orig
        c.files.append(bf)
        c.timeline.append({"at": f.captured_at, "machine": shown[f.machine], "kind": "read",
                           "what": f"{f.category} saved" + (f" ({e.read} via {e.transport})" if e and e.read and
                                                             e.transport else ""),
                           "ref": rel})

    # 2. events, one NDJSON file per machine and dataset, from the store's canonical documents
    if plan.events:
        _collect_events(data_dir, plan, out, red, c, say)

    # 3. findings and coverage, generated from the database now
    _collect_findings(data_dir, plan, out, red, c)
    _collect_coverage(data_dir, plan, out, red, c)
    _collect_compliance(data_dir, plan, out, red, c)
    return c


def _collect_events(data_dir: Path, plan: Plan, out: Path, red: Redactor, c: Collected, say: Progress) -> None:
    from kratos.storage.sqlite_files import connect_store

    req = plan.request
    conn = connect_store(data_dir / "kratos.db")
    try:
        for pe in plan.events:
            if pe.included <= 0:
                continue
            mdir = _safe_dir(c.machine_names[pe.machine])
            rel = f"evidence/{mdir}/events/{_safe_dir(pe.dataset)}.ndjson"
            idx_rel = rel + ".index"
            say(f"copying {pe.included:,} {pe.dataset} events for {c.machine_names[pe.machine]}")
            dst, idx = out / rel, out / idx_rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            h, hi, size, isize, n = hashlib.sha256(), hashlib.sha256(), 0, 0, 0
            sql = ("SELECT event_id, ts, action, doc FROM host_events WHERE target = ? AND dataset = ? AND id <= ? "
                   "AND ts <= ?" + (" AND ts >= ?" if req.start is not None else "") + " ORDER BY ts, id LIMIT ?")
            args = (pe.machine, pe.dataset, plan.events_upto_row, req.end) + \
                ((req.start,) if req.start is not None else ()) + (pe.included,)
            sample_every = max(1, pe.included // 400)
            with open(dst, "wb") as fo, open(idx, "wb") as fx:
                fx.write(INDEX_HEADER)
                isize += len(INDEX_HEADER)
                hi.update(INDEX_HEADER)
                for row in conn.execute(sql, args):
                    n += 1
                    if red.active:
                        # the document carries its own event.id: replaced with the same opaque value
                        red.known_event_id(row["event_id"])
                        text = red.text(row["doc"]).replace(row["event_id"], red.opaque(row["event_id"]))
                    else:
                        text = row["doc"]
                    line = text.encode("utf-8")
                    fo.write(line + b"\n")
                    h.update(line + b"\n")
                    size += len(line) + 1
                    rec = f"{n}\t{red.opaque(row['event_id'])}\t{_sha256_bytes(line)}\n".encode("ascii")
                    fx.write(rec)
                    hi.update(rec)
                    isize += len(rec)
                    if n % sample_every == 0 or n == 1:
                        c.timeline.append({"at": row["ts"], "machine": c.machine_names[pe.machine], "kind": "event",
                                           "what": f"{pe.dataset}: {row['action'] or 'event'}", "ref": f"{rel}#{n}"})
            c.files.append(BundleFile(rel, h.hexdigest(), size, "events", c.machine_names[pe.machine], pe.dataset,
                                      hashed_at="export", events=n, index=idx_rel,
                                      warning=None if pe.included == pe.count else
                                      f"cut: {pe.included:,} of {pe.count:,} events in the period"))
            c.files.append(BundleFile(idx_rel, hi.hexdigest(), isize, "event_index", c.machine_names[pe.machine],
                                      pe.dataset, hashed_at="generated"))
    finally:
        conn.close()


def _ssvc_cell(latest: dict[str, Any]) -> str:
    from kratos.ssvc import present

    try:
        return present.cell(latest)
    except Exception:  # noqa: BLE001
        return ""


def _ssvc_line(latest: dict[str, Any]) -> str:
    from kratos.ssvc import present

    try:
        s = present.ssvc_of(latest)
        return present.one_line(s) if s else ""
    except Exception:  # noqa: BLE001
        return ""


def _finding_view(rec: dict[str, Any], latest: dict[str, Any], verdict: Any, history: list[dict[str, Any]],
                  red: Redactor) -> dict[str, Any]:
    from kratos import attack

    labels = [{"id": lab.get("id"), "name": lab.get("name"), "tactics": lab.get("tactics")}
              for lab in attack.attack_of(latest)]
    out = {
        "finding_key": red.opaque(rec["finding_key"]), "rule_id": rec["rule_id"], "subject": red.text(rec["subject"]),
        "kind": rec["kind"], "state": rec["state"], "severity": rec["severity"], "title": red.text(rec["title"]),
        "entities": [red.text(str(x)) for x in json.loads(rec["entities"] or "[]")],
        "first_seen": _iso(rec["first_seen"]), "last_seen": _iso(rec["last_seen"]),
        "times_seen": rec["times_seen"],
        "evidence": [red.text(str(x)) for x in (latest.get("evidence") or [])],
        "attack": labels,
        "ssvc": json.loads(red.text(json.dumps(latest["ssvc"]))) if latest.get("ssvc") else None,
        "ssvc_decision": _ssvc_cell(latest),
        "ssvc_line": red.text(_ssvc_line(latest)),
        # E.4: what each file the finding names is known to be (an annotation, never a state)
        "reputation": [{"path": red.text(str(r.get("path") or "")), "sha256": r.get("sha256"),
                        "verdict": r.get("verdict"), "label": r.get("label"),
                        "note": red.text(str(r.get("note") or "")),
                        "sources": [{"source": str(x.get("source") or ""), "detail": red.text(str(x.get("detail") or "")),
                                     "date": str(x.get("date") or "")}
                                    for x in r.get("sources") or [] if isinstance(x, dict)],
                        "checked_at": r.get("checked_at")}
                       for r in latest.get("reputation") or [] if isinstance(r, dict)],
        "verdict": ({"verdict": verdict.verdict.verdict, "basis": verdict.verdict.basis,
                     "at": _iso(verdict.at), "verifier": verdict.verifier,
                     "sentence": red.text(verdict.verdict.sentence or "")} if verdict else None),
        "history": [{"at": _iso(h["at"]), "kind": h["kind"], "from": h["from_state"], "to": h["to_state"],
                     "by": red.text(str(h["actor"])), "interface": h["interface"],
                     "reason": red.text(str(h["reason"] or ""))} for h in history],
    }
    return out


def _collect_findings(data_dir: Path, plan: Plan, out: Path, red: Redactor, c: Collected) -> None:
    from kratos.lifecycle import store as LS

    if not plan.findings:
        return
    try:
        from kratos.triage import store as TS
    except Exception:  # noqa: BLE001
        TS = None  # type: ignore[assignment]
    with LS.opened(data_dir) as conn:
        for m, recs in plan.findings.items():
            keys = [r["finding_key"] for r in recs]
            verdicts = TS.latest_verdicts(data_dir, keys) if TS else {}
            views = []
            for r in recs:
                try:
                    latest = json.loads(r["latest"] or "{}")
                except ValueError:
                    latest = {}
                hist = [dict(h) for h in LS.events_for(conn, r["finding_key"])]
                views.append(_finding_view(r, latest, verdicts.get(r["finding_key"]), hist, red))
                for h in hist:
                    c.timeline.append({"at": h["at"], "machine": c.machine_names[m], "kind": "finding",
                                       "what": f"{r['rule_id']} {h['kind']}" + (f" -> {h['to_state']}"
                                                                                if h['to_state'] else ""),
                                       "ref": red.opaque(r["finding_key"])[:12]})
            shown = c.machine_names[m]
            c.findings[shown] = views
            rel = f"evidence/{_safe_dir(shown)}/findings.json"
            digest, size = _write_text(out / rel, _json({"machine": shown, "findings": views,
                                                          "note": "generated from Kratos's findings database when "
                                                                  "exporting"}))
            c.files.append(BundleFile(rel, digest, size, "generated", shown, "findings", hashed_at="generated"))


def _collect_coverage(data_dir: Path, plan: Plan, out: Path, red: Redactor, c: Collected) -> None:
    from kratos.hunt import coverage as HC

    req = plan.request
    for m in req.machines:
        shown = c.machine_names[m]
        try:
            cov = HC.machine_coverage(data_dir, m, start=req.start, end=req.end, now=plan.taken_at).as_dict()
        except Exception as e:  # noqa: BLE001
            cov = {"machine": m, "statement": [f"coverage couldn't be read ({type(e).__name__})"]}
        cov["fleet_runs"] = _fleet_outcomes(data_dir, m, req.start, req.end)
        cov["gaps"] = _gaps(cov)
        cov = json.loads(red.text(json.dumps(cov, default=str)))
        cov["machine"] = shown
        c.coverage[shown] = cov
        rel = f"evidence/{_safe_dir(shown)}/coverage.json"
        digest, size = _write_text(out / rel, _json(cov))
        c.files.append(BundleFile(rel, digest, size, "generated", shown, "coverage", hashed_at="generated"))


def _collect_compliance(data_dir: Path, plan: Plan, out: Path, red: Redactor, c: Collected) -> None:
    """E.2: each machine's compliance reports (CIS, ISO 27001, NIS2), generated from its saved
    hardening facts when exporting -- the facts files themselves travel as evidence."""
    from kratos.compliance import record as CR
    from kratos.compliance import report as CRP

    for m in plan.request.machines:
        if CR.load_result(data_dir, m) is None:
            continue
        shown = c.machine_names[m]
        for fw in ("cis", "iso27001", "nis2"):
            try:
                doc = CRP.build(data_dir, fw, [m], label=m, now=plan.taken_at)
            except Exception as e:  # noqa: BLE001
                c.warnings.append(f"compliance report {fw} for {shown}: not made ({type(e).__name__})")
                continue
            doc = json.loads(red.text(json.dumps(doc, default=str, ensure_ascii=False)))
            doc["scope"] = shown
            for s in doc.get("machines") or []:
                s["machine"] = shown
                if red.active:      # control owners are people's names: left out, not masked
                    for ctl in s.get("controls") or []:
                        if ctl.get("owner"):
                            ctl["owner"] = "(an owner is set -- names are left out of redacted bundles)"
            for suffix, text in ((".json", CRP.to_json(doc)), (".md", CRP.to_markdown(doc))):
                rel = f"evidence/{_safe_dir(shown)}/compliance_{fw}{suffix}"
                digest, size = _write_text(out / rel, text)
                c.files.append(BundleFile(rel, digest, size, "generated", shown, "compliance", hashed_at="generated"))


def _gaps(cov: dict[str, Any]) -> list[str]:
    """Every gap in plain words: log stretches missing, not synced, not watched, pruned,
    and every fleet run that couldn't read this machine."""
    out = [s for s in cov.get("statement") or [] if any(w in s for w in ("GAP", "not synced", "NOT being watched",
                                                                         "not watched", "PRUNED", "not searched"))]
    for r in cov.get("fleet_runs") or []:
        if r.get("outcome") != "ok":
            out.append(f"fleet run {r.get('started')}: {r.get('outcome')}"
                       + (f" -- {r.get('reason')}" if r.get("reason") else "")
                       + (f"; not read: {', '.join(r.get('not_read') or [])}" if r.get("not_read") else ""))
    return out


def _fleet_outcomes(data_dir: Path, machine: str, start: float | None, end: float) -> list[dict[str, Any]]:
    from kratos.storage.sqlite_files import connect_store

    p = data_dir / "kratos.db"
    if not p.exists():
        return []
    conn = connect_store(p)
    try:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='fleet_run_machines'").fetchone():
            return []
        cols = {r[1] for r in conn.execute("PRAGMA table_info(fleet_runs)")}
        tcol = "started_at" if "started_at" in cols else None
        if tcol is None:
            return []
        rows = conn.execute(
            f"SELECT r.run_id, r.{tcol} AS t, r.group_ref, m.outcome, m.reason, m.transport, m.coverage "
            "FROM fleet_run_machines m JOIN fleet_runs r ON r.run_id = m.run_id WHERE m.machine = ? "
            f"ORDER BY r.{tcol}", (machine,)).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        t = _epoch(r["t"])
        if t is None or t > end or (start is not None and t < start):
            continue
        try:
            not_read = json.loads(r["coverage"] or "[]")
        except ValueError:
            not_read = []
        out.append({"run_id": r["run_id"], "started": _iso(t), "group": r["group_ref"], "outcome": r["outcome"],
                    "reason": r["reason"], "transport": r["transport"], "not_read": not_read})
    return out


def _epoch(v: Any) -> float | None:
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str) and v:
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None

