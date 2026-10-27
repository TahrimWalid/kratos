"""Gather what the web-server signals need -- all of it already on this host -- and save
the judged snapshot the findings engine reads (`web_signals/web_signals_<machine>.json`,
one per machine, replaced in place).

Inputs: the crash events log sync stored (`process_crashed`: the kernel's crash lines,
Apache's "exit signal" lines), the machine's newest package list and where each package
came from (kratos.pkgvuln.inventory_store), and its newest running-process read's
listening sockets (kratos.live). Nothing is read from or sent to the machine.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso
from kratos.websig import judge as J

FOLDER = "web_signals"
PATTERN = "web_signals_*.json"
LOOKBACK_SECONDS = 24 * 3600
MAX_CRASHES = 5000
KERNEL_SOURCE = "firewall"           # the sync source that reads the kernel's journal lines


def _crashes(data_dir: Path, key: str, now: float) -> list[J.Crash]:
    from kratos.events.store import EventStore

    db = data_dir / "kratos.db"
    if not db.exists():
        return []
    events = EventStore(db).query(key, action="process_crashed", start=now - LOOKBACK_SECONDS, limit=MAX_CRASHES,
                                  newest_first=False)
    return [J.Crash(ts=e.timestamp.timestamp(), name=str(e.process_name or ""), pid=e.process_pid,
                    provider=str(e.provider or ""), message=str(e.message or "")) for e in events]


def _kernel_lines_synced(data_dir: Path) -> bool:
    from kratos import settings_store
    from kratos.collect.sync import settings as SS

    try:
        return KERNEL_SOURCE in (settings_store.get(SS.SOURCES, data_dir=data_dir) or [])
    except Exception:  # noqa: BLE001
        return True


def _listeners(data_dir: Path, key: str) -> list[dict[str, Any]] | None:
    from kratos.adapters import findings_engine as FE

    path = FE.find_latest_inputs(data_dir, key).get("live_response")
    doc = FE.SNAPSHOT_SOURCES["live_response"].load(path) if path else None
    if not doc or not isinstance(doc.get("listeners"), list):
        return None
    # A read made before listeners carried their address can't say what faces the network.
    if any(isinstance(x, dict) and "address" not in x for x in doc["listeners"]):
        return None
    return doc["listeners"]


def _packages(data_dir: Path, key: str) -> tuple[list[dict[str, Any]] | None, dict[str, dict[str, Any]], bool, str]:
    from kratos.pkgvuln import inventory_store
    from kratos.pkgvuln.origin import DISTRO_NAMES

    row = inventory_store.latest(data_dir, key)
    if row is None or time.time() - row.last_seen_at > 7 * 86400:
        return None, {}, False, ""
    origins = (row.read or {}).get("origins") or {}
    outside = {str(o[0]): {"origin": o[2], "kind": o[3]} for o in origins.get("outside") or []
               if isinstance(o, list) and len(o) == 4}
    distro = DISTRO_NAMES.get(str(row.os_id or "").lower(), str(row.os_id or ""))
    return list(row.packages), outside, bool(origins.get("checked")), distro


def run(data_dir: Path, target: str, *, now: float | None = None) -> dict[str, Any]:
    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    key = target_key(target)
    crashes = _crashes(data_dir, key, now)
    kernel = _kernel_lines_synced(data_dir)
    gaps: list[str] = []
    if not kernel:
        gaps.append("web-server worker crashes are read from the kernel's journal lines, which aren't synced "
                    f"(the '{KERNEL_SOURCE}' log source is off in collect.sync_sources)")
    source_note = ("Read from the crash lines the kernel (and Apache's error log, when web logs are synced) "
                   "wrote, as stored by Kratos's log sync -- nothing new was read from the machine.")
    signals = J.burst_signals(J.bursts(crashes), target=key, source_note=source_note)
    listeners = _listeners(data_dir, key)
    packages, outside, origins_checked, distro = _packages(data_dir, key)
    exposure, line = J.exposure_signal(target=key, listeners=listeners, packages=packages, outside=outside,
                                       origins_checked=origins_checked, distro=distro,
                                       today=datetime.fromtimestamp(now, timezone.utc).date())
    if exposure:
        signals.append(exposure)
    if listeners is None:
        gaps.append("whether PHP is served to the network: no recent read of the listening ports with their "
                    "addresses yet")
    doc = {
        "target": key, "checked_at": epoch_to_utc_iso(now), "checked_at_epoch": now,
        "complete": kernel and listeners is not None and packages is not None,
        "crashes_seen": len(crashes), "exposure_line": line, "coverage_gaps": gaps, "signals": signals,
    }
    out = data_dir / FOLDER
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"web_signals_{hashlib.sha256(key.encode()).hexdigest()[:8]}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)
    return {**doc, "status": "ok", "file": str(path)}


def summary_line(doc: dict[str, Any]) -> str:
    parts = []
    bursts = [s for s in doc.get("signals") or [] if s.get("rule") == "WEB-001"]
    if bursts:
        parts.append("worker crash bursts: " + ", ".join(J.FAMILY_WORDS.get(str(s["subject"]), str(s["subject"]))
                                                        for s in bursts))
    else:
        parts.append(f"no web-server worker crash bursts in the last 24 h ({doc.get('crashes_seen', 0)} crash "
                     "line(s) stored)")
    if doc.get("exposure_line"):
        parts.append(str(doc["exposure_line"]))
    return "; ".join(parts)
