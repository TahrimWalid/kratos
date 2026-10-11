"""Read-only views of finding records -- for the CLI, the TUI and MCP.

Nothing here changes anything; decisions live in `decide` (people only).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from kratos.lifecycle import store as S
from kratos.lifecycle.keys import short
from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso

# --state values people type -> the states they mean
STATE_FILTERS: dict[str, frozenset[str] | None] = {
    "open": frozenset({"open"}), "verified": frozenset({"verified"}),
    "mitigated": frozenset({"mitigated"}), "inactive": frozenset({"inactive"}),
    "risk_accepted": frozenset({"risk_accepted"}), "false_positive": frozenset({"false_positive"}),
    "out_of_scope": frozenset({"out_of_scope"}),
    "decided": S.DECIDED, "open_verified": S.SHOWN_BY_DEFAULT, "all": None,
}


def _iso(epoch: float | None) -> str | None:
    return epoch_to_utc_iso(epoch) if epoch is not None else None


def _row(conn, rec, now: float) -> dict[str, Any]:
    d = {k: rec[k] for k in rec.keys() if k != "latest"}
    d["entities"] = json.loads(rec["entities"] or "[]")
    d["short_key"] = short(rec["finding_key"])
    for k in ("first_seen", "last_seen", "last_checked"):
        d[k] = _iso(rec[k])
    exc = S.decision_of(conn, rec, now)
    d["decision"] = None if exc is None else {
        "id": exc["id"], "kind": exc["kind"], "scope": exc["scope"], "owner": exc["owner"],
        "reason": exc["reason"], "expires_at": _iso(exc["expires_at"]), "decided_at": _iso(exc["created_at"]),
        "decided_by": exc["created_by"]}
    return d


def list_findings(data_dir: Path, *, target: str | None = None, state: str | None = "open_verified",
                  limit: int | None = None) -> list[dict[str, Any]]:
    """Finding records, newest seen first. `state` is one of STATE_FILTERS."""
    if state not in STATE_FILTERS:
        raise ValueError(f"state must be one of: {', '.join(STATE_FILTERS)}")
    states = STATE_FILTERS[state]
    now = time.time()
    with S.opened(data_dir) as conn:
        rows = S.list_records(conn, target=target_key(target) if target else None,
                              states=set(states) if states is not None else None, limit=limit)
        return [_row(conn, r, now) for r in rows]


def get_finding(data_dir: Path, key: str) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """(record, latest finding dict, events) for a full key or a unique prefix.
    Raises LookupError."""
    with S.opened(data_dir) as conn:
        full = S.resolve_key(conn, key)
        rec = S.get_record(conn, full)
        row = _row(conn, rec, time.time())
        latest = json.loads(rec["latest"] or "{}")
        events = []
        for e in S.events_for(conn, full):
            d = dict(e)
            d["at"] = _iso(e["at"])
            d["details"] = json.loads(e["details"]) if e["details"] else None
            events.append(d)
    return row, latest, events


def hidden_counts(data_dir: Path, target: str | None = None) -> dict[str, int]:
    with S.opened(data_dir) as conn:
        sql = "SELECT state, COUNT(*) FROM finding_records WHERE state IN ('risk_accepted','false_positive'," \
              "'out_of_scope')"
        params: list[Any] = []
        if target:
            sql += " AND target = ?"
            params.append(target_key(target))
        rows = conn.execute(sql + " GROUP BY state", params).fetchall()
    out = {k: 0 for k in S.EXCEPTION_KINDS}
    out.update({r[0]: r[1] for r in rows})
    return out
