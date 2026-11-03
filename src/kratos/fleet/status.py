"""What /fleet and `kratos fleet status` show per machine, from Kratos's own records only
(no read of any machine): how it is reached, its sub-agent's version, its certificate
state, when it was last collected, its open findings by severity, and how the last
fleet run went for it. A machine listed twice under different names (an address and
an agent link to the same box) is shown once, with the other name noted.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

OPEN_STATES = ("open", "verified")


def _open_counts(data_dir: Path, machine: str) -> dict[str, int]:
    from kratos.lifecycle import store as lstore

    db = Path(data_dir) / "kratos.db"
    if not db.exists():
        return {}
    out: dict[str, int] = {}
    try:
        with lstore.opened(Path(data_dir)) as conn:
            for r in lstore.list_records(conn, target=machine, states=set(OPEN_STATES)):
                sev = str(r["severity"] or "info").lower()
                out[sev] = out.get(sev, 0) + 1
    except sqlite3.Error:
        return {}
    return out


def _last_collected(data_dir: Path, machine: str) -> float | None:
    from kratos.collect import state as collect_state

    try:
        rows = collect_state.all_rows(Path(data_dir), machine)
    except Exception:  # noqa: BLE001 -- no collection yet
        return None
    return max((r.finished_at or 0 for r in rows), default=0) or None


def rows(data_dir: Path | str, group: str = "@all") -> list[dict[str, Any]]:
    from kratos.fleet import groups as G
    from kratos.fleet import record
    from kratos.fleet.collect import machine_info
    from kratos.subagent.status import agent_outdated

    data_dir = Path(data_dir)
    try:
        r = G.resolve(data_dir, group)
        machines, dups = r.machines, r.duplicates
    except G.GroupError:
        machines, dups = [], []
    last = record.last_per_machine(data_dir)
    out: list[dict[str, Any]] = []
    for m in machines:
        info = machine_info(data_dir, m)
        fr = last.get(m) or {}
        out.append({"machine": m, "name": info["label"], "link": info["transport"],
                    "agent_version": info["agent_version"], "agent_outdated": agent_outdated(info["agent_version"]),
                    "certificate": info["cert_state"], "last_collected": _last_collected(data_dir, m),
                    "open_findings": _open_counts(data_dir, m),
                    "last_fleet_outcome": fr.get("outcome"), "last_fleet_reason": fr.get("reason")})
    for a, b in dups:
        if a != b:
            out.append({"machine": a, "duplicate_of": b})
    return out


def agent_update_note(rows_: list[dict[str, Any]]) -> str:
    n = sum(1 for r in rows_ if r.get("agent_outdated"))
    if not n:
        return ""
    return (f"{n} machine{'s' if n != 1 else ''} need{'s' if n == 1 else ''} an agent update: press g on it in "
            "/subagent (the owner does this; Kratos never updates an agent by itself).")
