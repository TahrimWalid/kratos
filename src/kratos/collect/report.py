"""What `/doctor`, `/collect` and `kratos collect` say about the collection layer: when each
check last ran for the active machine, which logs are still catching up, how big the event
store is."""
from __future__ import annotations

import time
from pathlib import Path

from kratos.collect.digest import ago


def doctor_row(data_dir: Path) -> tuple[str, str]:
    """(status, one plain line) for /doctor."""
    from kratos import kratos_config
    from kratos.collect import checks as _checks  # noqa: F401
    from kratos.collect import registry, state
    from kratos.collect.sync import cursors
    from kratos.events.store import EventStore
    from kratos.target_key import target_key

    target = kratos_config.get_active_target()
    if not target:
        return "info", "no target is set, so nothing is being checked"
    tkey = target_key(target)
    rows = {r.check_name: r for r in state.all_rows(data_dir, tkey)}
    now = time.time()
    bits = []
    stale = 0
    for c in registry.checks("quick"):
        r = rows.get(c.name)
        if r is None or r.finished_at is None:
            bits.append(f"{c.short or c.label}: never")
            stale += 1
        else:
            bits.append(f"{c.short or c.label}: {ago(r.age(now))}" + ("" if r.status in ("ok", "partial") else f" ({r.status})"))
            if r.status not in ("ok", "partial"):
                stale += 1
    behind = sorted({c.source for c in cursors.cursors(data_dir, tkey) if c.behind})
    try:
        n_events = EventStore(Path(data_dir) / "kratos.db").count(target)
    except Exception:  # noqa: BLE001
        n_events = 0
    size = ""
    db = Path(data_dir) / "kratos.db"
    if db.exists():
        size = f", database {db.stat().st_size / 1_048_576:.0f} MB"
    detail = "; ".join(bits) + f". {n_events:,} log events stored for this machine{size}"
    if behind:
        detail += f". Still catching up: {', '.join(behind)}"
    return ("warn" if stale == len(registry.checks("quick")) and rows else "pass"), detail
