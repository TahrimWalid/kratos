"""Run the live-response read, judge it, and save what the rule engine reads (A.5).

One call: read ``/proc`` (over SSH as the SSH user, or through the machine's
sub-agent as root -- ``ssh_remote.fetch_live_response`` routes it), judge it
(``judge``), and write ``data_dir/live/live_response_<time>.json``.
``correlate_findings`` picks that file up like any other input
(``findings_engine.find_latest_inputs``, category ``live_response``) and turns its
``signals`` into LIVE-* findings.

Live-response findings are point-in-time, so there is no baseline: the read
describes what is running at the moment it ran. Nothing is written on the
monitored machine, and nothing here calls a model.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from kratos.live.judge import judge
from kratos.utils.timeutil import epoch_to_utc_iso

LIVE_DIR = "live"
FILE_GLOB = "live_response_*.json"

Reader = Callable[[], Any]


def _default_reader() -> Any:
    from kratos.adapters.ssh_remote import fetch_live_response

    return fetch_live_response()


def _failure_text(result: Any) -> str:
    text = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
    return " ".join(text.split())[:300] or "the read failed"


def _counts(inv: dict[str, Any]) -> dict[str, int]:
    procs = inv.get("procs") or {}
    socks = inv.get("sockets") or []
    temp = inv.get("temp_files") or {}
    return {
        "processes": len(procs),
        "listening": sum(1 for s in socks if str(s.get("state") or "").upper() == "0A"),
        "temp_executables": sum(1 for it in temp.values() if str(it.get("header") or "") in ("elf", "script")),
        "deleted": sum(1 for it in procs.values() if str(it.get("exe") or "").endswith(" (deleted)")),
    }


def run(data_dir: Path, target: str, *, reader: Reader | None = None,
        now: float | None = None, run_id: str | None = None) -> dict[str, Any]:
    """Read, judge, save. Returns the saved document plus `file` (its path), or
    `{"status": "error", ...}` when the read itself failed (nothing is saved -- a
    failed read must never become "nothing running")."""
    data_dir = Path(data_dir)
    reader = reader or _default_reader
    when = time.time() if now is None else now
    result = reader()
    if not isinstance(result, dict):
        return {"status": "error", "target": target, "observation": _failure_text(result)}

    inv = result
    judged = judge(inv)
    coverage_gaps: list[str] = []
    for s in judged.signals:
        if s.rule == "LIVE-007":
            coverage_gaps = [ln.strip() for ln in s.evidence]
    doc: dict[str, Any] = {
        "target": target,
        "checked_at": epoch_to_utc_iso(when),
        "checked_at_epoch": when,
        "via": inv.get("via") or "ssh",
        "family": inv.get("family"),
        "reader_uid": inv.get("reader_uid"),
        "complete": bool(inv.get("complete")) and not inv.get("truncated_output"),
        "ownership": inv.get("ownership") or {},
        "counts": _counts(inv),
        "coverage_gaps": coverage_gaps,
        "signals": [s.as_dict() for s in judged.signals],
    }
    out_dir = data_dir / LIVE_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"live_response_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return {**doc, "status": "ok", "file": str(path)}


def summary_line(doc: dict[str, Any]) -> str:
    """The one plain line the collection digest shows (Kratos's own words)."""
    counts = doc.get("counts") or {}
    procs = int(counts.get("processes") or 0)
    signals = [s for s in doc.get("signals") or [] if str(s.get("rule")) != "LIVE-007"]
    head = f"{procs} running process(es) checked"
    if signals:
        worst = ", ".join(sorted({str(s.get("rule")) for s in signals}))
        return f"{head}; something to look at ({worst})"
    return f"{head}; nothing unusual"
