"""Run the compliance evaluation for one machine and save what the findings engine and the
reports read (E.2 §5.1).

One call: read `hardening_facts` (SSH or the sub-agent), save it per transport
(``data_dir/compliance/facts/hardening_<machine>_<via>.json``), load every reused fact
source, run the closed check table, compute each framework's control statuses, judge
COMP-001, write ``data_dir/compliance/results/comp_<machine>.json`` (one per machine,
replaced in place, evidence-recorded) and store the run in ``compliance_runs`` /
``compliance_results``.

Nothing here calls a model. A read that failed is never "nothing found": every check
that needed it is "not checked" with the reason.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from kratos.compliance import cac
from kratos.compliance import checks as C
from kratos.compliance import facts as FX
from kratos.compliance import judge as J
from kratos.compliance import status as ST
from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso

FOLDER = "compliance/results"
FACTS_FOLDER = "compliance/facts"
PATTERN = "comp_*.json"
VIAS = ("ssh", "subagent")


def _h8(target: str) -> str:
    return hashlib.sha256(target_key(target).encode()).hexdigest()[:8]


def result_path(data_dir: Path, target: str) -> Path:
    return Path(data_dir) / FOLDER / f"comp_{_h8(target)}.json"


def hardening_path(data_dir: Path, target: str, via: str) -> Path:
    return Path(data_dir) / FACTS_FOLDER / f"hardening_{_h8(target)}_{via}.json"


def hardening_paths(data_dir: Path, target: str) -> list[Path]:
    return [p for p in (hardening_path(data_dir, target, v) for v in VIAS) if p.exists()]


def _default_reader() -> Any:
    from kratos.adapters.ssh_remote import fetch_hardening_facts

    return fetch_hardening_facts()


def _write(path: Path, doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=1, default=str, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _norm_via(via: Any) -> str:
    return "subagent" if str(via or "").startswith(("subagent", "agent")) else "ssh"


def _read_failure(result: Any) -> str:
    text = " ".join(str(getattr(result, "stderr", "") or getattr(result, "observation", "") or "").split())
    return text[:300] or "the hardening read failed"


def _open_rules(data_dir: Path, target: str) -> set[str]:
    try:
        from kratos.lifecycle import query

        rows = query.list_findings(data_dir, target=target_key(target), state="open_verified")
    except Exception:  # noqa: BLE001 -- no lifecycle yet = nothing open
        return set()
    return {str(r.get("rule_id") or r.get("rule") or "") for r in rows}


def _exposure(data_dir: Path, target: str, facts: FX.Facts) -> tuple[bool, str]:
    try:
        from kratos.assets import store as assets
        from kratos.ssvc import exposure as X

        asset = assets.get(data_dir, target)
        live = facts.get("live")
        e = X.machine_highest(live.data if live else None, override=asset.exposure_override if asset else None)
        return e.value == X.INTERNET, e.reason
    except Exception:  # noqa: BLE001
        return False, ""


def evaluate(data_dir: Path, target: str, facts: FX.Facts, *, now: float | None = None,
             level: str | None = None) -> dict[str, Any]:
    """Checks, control statuses and COMP-001 from `facts` -- no read, no write."""
    from kratos.compliance import owners as O
    from kratos.compliance import settings as CS

    now = time.time() if now is None else now
    max_age = float(CS.get(CS.MAX_AGE_HOURS, data_dir))
    runs = ST.run_checks(facts, max_age_hours=max_age, now=now, open_rules=_open_rules(data_dir, target))
    hard = facts.get("hardening")
    product = cac.detect(facts.h().get("os") or {}) if hard else cac.Product(None, "not read yet")
    level = level or O.level_for(data_dir, target)
    frameworks: dict[str, list[dict[str, Any]]] = {}
    summaries: dict[str, str] = {}
    for fw in ("cis", "iso27001", "nis2"):
        rows = ST.controls_for(fw, runs, product=product, level=level)
        ST.apply_na(rows, O.na_for(data_dir, fw, target, now))
        frameworks[fw] = [r.to_dict() for r in rows]
        summaries[fw] = ST.summary_line(fw, rows, product, level)
    internet, why = _exposure(data_dir, target, facts)
    key = target_key(target)
    signals = J.judge(runs, target=key, internet=internet, exposure_why=why)
    return {"runs": runs, "product": product, "level": level, "frameworks": frameworks, "summaries": summaries,
            "signals": signals, "internet": internet}


def run(data_dir: Path, target: str, *, fetch: Callable[[], Any] | None = None, now: float | None = None) -> dict:
    data_dir = Path(data_dir)
    when = time.time() if now is None else now
    key = target_key(target)
    got = (fetch or _default_reader)()
    read_gap = ""
    via = "ssh"
    if isinstance(got, dict) and got.get("format"):
        via = _norm_via(got.get("via"))
        hdoc = {"target": key, "read_at": epoch_to_utc_iso(when), "read_at_epoch": when, "via": via, "facts": got}
        path = hardening_path(data_dir, target, via)
        _write(path, hdoc)
        from kratos import evidence as _evidence

        _evidence.record(path, data_dir=data_dir, category="compliance", machine=target, read="hardening_facts",
                         transport=via)
    else:
        read_gap = _read_failure(got)
        if "update the agent" in read_gap or "update it from" in read_gap:
            read_gap = ("this machine's sub-agent is too old for the hardening read -- update it (`g` in /subagent)")
    facts = FX.load(data_dir, target)
    ev = evaluate(data_dir, target, facts, now=when)
    runs: list[ST.CheckRun] = ev["runs"]
    hard = facts.get("hardening")
    gaps: list[str] = []
    if read_gap:
        gaps.append(f"hardening read: {read_gap}" + (" (older saved facts were used where fresh enough)"
                                                     if hard else ""))
    if hard is not None:
        for k, v in sorted((hard.gaps or {}).items()):
            gaps.append(f"hardening read: {k.replace('_', ' ')} {v}")
        if not hard.complete:
            gaps.append("hardening read: incomplete (cut off)")
    complete = bool(hard is not None and hard.complete and not read_gap)
    product: cac.Product = ev["product"]
    doc = {
        "target": key, "checked_at": epoch_to_utc_iso(when), "checked_at_epoch": when,
        "via": hard.via if hard else via, "read_at_epoch": hard.read_at if hard else None,
        "complete": complete, "product": product.id, "product_note": product.note,
        "benchmark_version": product.benchmark_version, "level": ev["level"],
        "mapping_version": cac.mapping_version(), "mapping_commit": cac.source().get("commit"),
        "os": (facts.h().get("os") or {}).get("PRETTY_NAME") or "",
        "virt": facts.h().get("virt") or "", "internet": ev["internet"],
        "checks": [r.to_dict() for r in runs], "frameworks": ev["frameworks"], "summaries": ev["summaries"],
        "signals": ev["signals"], "coverage_gaps": gaps,
        "sources": {n: {"read_at": s.read_at, "via": s.via, "complete": s.complete}
                    for n, s in facts.sources.items()},
        "other_read": ({"via": facts.other_hardening.via, "read_at": facts.other_hardening.read_at}
                       if facts.other_hardening else None),
    }
    out = result_path(data_dir, key)
    _write(out, doc)
    from kratos import evidence as _evidence

    _evidence.record(out, data_dir=data_dir, category="compliance", machine=target, read="hardening_facts",
                     transport=doc["via"])
    try:
        from kratos.compliance import store

        read_times = {n: s.read_at for n, s in facts.sources.items()}
        rows = [{"framework": fw, "control": r["control"], "status": r["status"], "reason": r.get("reason"),
                 "checks": r.get("checks") or [], "read_times": read_times}
                for fw, rs in ev["frameworks"].items() for r in rs]
        store.save_run(data_dir, key, at=when, via=doc["via"], read_at=doc["read_at_epoch"], product=product.id,
                       product_note=product.note, level=ev["level"], mapping_version=doc["mapping_version"],
                       counts={fw: ST.counts([_Row(r) for r in rs]) for fw, rs in ev["frameworks"].items()},
                       complete=complete, rows=rows)
    except Exception:  # noqa: BLE001 -- the result file is the source of truth for findings
        import logging

        logging.getLogger(__name__).warning("compliance: run rows not stored", exc_info=True)
    return {**doc, "status": "ok", "file": str(out)}


class _Row:
    def __init__(self, d: dict[str, Any]):
        self.status = d.get("status")


def load_result(data_dir: Path, target: str) -> dict[str, Any] | None:
    p = result_path(data_dir, target)
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def summary_line(doc: dict[str, Any]) -> str:
    checks = doc.get("checks") or []
    if not any(c.get("status") in ("pass", "fail") for c in checks):
        return "no hardening facts read yet" + (f" ({doc['coverage_gaps'][0]})" if doc.get("coverage_gaps") else "")
    n = {s: sum(1 for c in checks if c.get("status") == s) for s in ("pass", "fail", "unknown", "na")}
    sig = doc.get("signals") or []
    if sig:
        ents = list(sig[0].get("entities") or [])
        more = f" (+{len(ents) - 4} more)" if len(ents) > 4 else ""
        return (f"COMP-001 ({sig[0]['severity']}): {len(ents)} hardening check(s) fail: {', '.join(ents[:4])}{more}; "
                f"{n['pass']} pass, {n['unknown']} not checked")
    return f"{n['pass']} hardening checks pass, {n['fail']} fail (already findings of their own), " \
           f"{n['unknown']} not checked" if n["fail"] else \
        f"{n['pass']} hardening checks pass, {n['unknown']} not checked"


def entity_label(check_id: str) -> str:
    c = C.BY_ID.get(check_id)
    return c.text if c else check_id
