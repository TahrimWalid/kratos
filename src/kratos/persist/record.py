"""Run the persistence read, judge it, and save what the rule engine reads (A.1).

One call: read the inventory (SSH, or the machine's sub-agent when it is linked
to one -- `ssh_remote.fetch_persistence` routes it), judge it against Kratos's
first look (`judge`), write
`data_dir/persistence/persistence_<time>.json`, and keep the baseline's
coverage up to date. `correlate_findings` picks that file up like any other
input (findings_engine.find_latest_inputs, category `persistence`) and turns
its `signals` into PERSIST-* findings.

Nothing is written on the monitored machine, and nothing here calls a model.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from kratos.adapters import persistence as _P
from kratos.persist import baseline as _baseline
from kratos.persist.judge import judge
from kratos.utils.timeutil import epoch_to_utc_iso

PERSISTENCE_DIR = "persistence"
FILE_GLOB = "persistence_*.json"

Reader = Callable[[bool], Any]


def _default_reader(verify: bool) -> Any:
    from kratos.adapters.ssh_remote import fetch_persistence

    return fetch_persistence(verify=verify)


def _failure_text(result: Any) -> str:
    text = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
    return " ".join(text.split())[:300] or "the read failed"


def _counts(inv: dict[str, Any]) -> dict[str, int]:
    items = inv.get("items") or {}
    return {
        "items": len(items),
        "with_lines": sum(1 for it in items.values() if it.get("lines")),
        "package_owned": sum(1 for it in items.values() if it.get("package")),
        "suid": sum(1 for it in items.values() if it.get("suid_bits")),
        "keys": len(inv.get("keys") or []),
        "modules": len(inv.get("modules") or {}),
    }


def run(data_dir: Path, target: str, *, verify: bool = False, reader: Reader | None = None,
        now: float | None = None, run_id: str | None = None) -> dict[str, Any]:
    """Read, judge, save. Returns the saved document plus `file` (its path), or
    `{"status": "error", ...}` when the read itself failed (nothing is saved and
    the baseline is left alone -- a failed read must never become "nothing there")."""
    data_dir = Path(data_dir)
    reader = reader or _default_reader
    when = time.time() if now is None else now
    result = reader(verify)
    if not isinstance(result, dict):
        return {"status": "error", "target": target, "observation": _failure_text(result)}

    inv = result
    base = _baseline.load(data_dir, target)
    judged = judge(inv, base, areas_known=_P.AREAS)
    first_look = base is None
    if first_look:
        base = _baseline.save_first_look(data_dir, target, inv, areas=_P.AREAS, now=when, run_id=run_id)
    else:
        assert base is not None
        base = _baseline.extend_coverage(data_dir, target, base, inv,
                                         new_areas=judged.new_areas,
                                         first_look_paths=tuple(dict.fromkeys(judged.first_look_paths)), now=when)

    doc: dict[str, Any] = {
        "target": target,
        "checked_at": epoch_to_utc_iso(when),
        "checked_at_epoch": when,
        "via": inv.get("via") or "ssh",
        "family": inv.get("family"),
        "container": inv.get("container"),
        "reader_uid": inv.get("reader_uid"),
        "complete": bool(inv.get("complete")) and not inv.get("truncated_output"),
        "verify": {"requested": bool(verify), "done": bool((inv.get("verify") or {}).get("done")),
                   "tool": (inv.get("verify") or {}).get("tool"),
                   "error": (inv.get("verify") or {}).get("error")},
        "ownership": inv.get("ownership") or {},
        "areas_checked": list(_P.AREAS),
        "baseline": {"first_look": first_look,
                     "taken_at": epoch_to_utc_iso(base.taken_at) if base else None,
                     "areas": list(base.areas) if base else [],
                     "new_areas": list(judged.new_areas),
                     "items": base.item_count if base else 0},
        "counts": _counts(inv),
        "coverage_gaps": list(judged.gaps),
        "signals": [s.as_dict() for s in judged.signals],
    }
    out_dir = data_dir / PERSISTENCE_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"persistence_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return {**doc, "status": "ok", "file": str(path)}


def summary_line(doc: dict[str, Any]) -> str:
    """The one plain line the collection digest shows (Kratos's own words)."""
    counts = doc.get("counts") or {}
    signals = [s for s in doc.get("signals") or [] if str(s.get("rule")) != "PERSIST-009"]
    places = int(counts.get("items") or 0)
    if doc.get("baseline", {}).get("first_look"):
        head = f"first look: {places} place(s) that can start programs recorded as the baseline"
    else:
        head = f"{places} place(s) that can start programs checked against the first look"
    if signals:
        worst = ", ".join(sorted({str(s.get("rule")) for s in signals}))
        return f"{head}; something to look at ({worst})"
    return f"{head}; nothing new"
