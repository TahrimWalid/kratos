"""The one audit trail (docs/phaseD/D.7 §3.10): who did what, through which door, with
which credential, on which machine -- allowed or refused, with a short reason.

Append-only (triggers in kratos.authz.store). `serve_audit` (HTTP detail) and
`finding_events` (lifecycle detail) stay as they are and are linked by run id. The
trail is personal data (B.5's inventory, category `audit`); only a person prunes it,
and the prune is itself recorded.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Iterable

from kratos.authz import store as S

RESULTS = ("allowed", "refused")
_MAX = {"user_name": 80, "credential": 160, "action": 60, "machine": 200, "object": 200, "reason": 300}


def _clip(name: str, value: Any) -> str | None:
    if value is None:
        return None
    text = "".join(ch if ch.isprintable() else " " for ch in str(value)).strip()
    return text[:_MAX.get(name, 200)] or None


def record(data_dir: Path | str, *, interface: str, action: str, result: str, user_id: str | None = None,
           user_name: str | None = None, credential: str | None = None, machine: str | None = None,
           obj: str | None = None, reason: str | None = None, run_id: str | None = None,
           now: float | None = None) -> None:
    """Add one row. Raises on a write failure -- the caller decides (require() fails closed)."""
    if result not in RESULTS:
        raise ValueError(f"unknown audit result {result!r}")
    if run_id is None:
        from kratos import run_context

        run_id = run_context.current_run_id()
    with S.opened(data_dir) as conn:
        conn.execute(
            "INSERT INTO audit_log (at, user_id, user_name, interface, credential, action, machine, object, result, "
            "reason, run_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time() if now is None else float(now), user_id, _clip("user_name", user_name),
             str(interface or "?")[:20], _clip("credential", credential), _clip("action", action),
             _clip("machine", machine), _clip("object", obj), result, _clip("reason", reason), run_id),
        )


def query(data_dir: Path | str, *, user: str | None = None, action: str | None = None, result: str | None = None,
          machine: str | None = None, since: float | None = None, until: float | None = None,
          interface: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    """Newest first. `user` matches the user id or name."""
    where, args = [], []
    if user:
        where.append("(user_id = ? OR lower(user_name) = lower(?))")
        args += [user, user]
    if action:
        where.append("action = ?")
        args.append(action)
    if result:
        if result not in RESULTS:
            raise ValueError(f"result must be one of {', '.join(RESULTS)}")
        where.append("result = ?")
        args.append(result)
    if machine:
        where.append("machine = ?")
        args.append(machine)
    if interface:
        where.append("interface = ?")
        args.append(interface)
    if since is not None:
        where.append("at >= ?")
        args.append(float(since))
    if until is not None:
        where.append("at < ?")
        args.append(float(until))
    sql = "SELECT * FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "") + \
          " ORDER BY at DESC, id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 100_000)))
    with S.opened(data_dir) as conn:
        return [dict(r) for r in conn.execute(sql, args)]


def counts(data_dir: Path | str, *, since: float) -> dict[str, int]:
    with S.opened(data_dir) as conn:
        rows = conn.execute("SELECT result, COUNT(*) AS n FROM audit_log WHERE at >= ? GROUP BY result",
                            (float(since),)).fetchall()
    out = {r: 0 for r in RESULTS}
    out.update({r["result"]: int(r["n"]) for r in rows})
    return out


def oldest(data_dir: Path | str) -> float | None:
    with S.opened(data_dir) as conn:
        r = conn.execute("SELECT MIN(at) AS t FROM audit_log").fetchone()
    return float(r["t"]) if r and r["t"] is not None else None


def prune_preview(data_dir: Path | str, before: float) -> int:
    with S.opened(data_dir) as conn:
        r = conn.execute("SELECT COUNT(*) AS n FROM audit_log WHERE at < ?", (float(before),)).fetchone()
    return int(r["n"])


def prune(data_dir: Path | str, before: float, actor: Any) -> int:
    """Remove rows older than `before` (epoch). People only: needs `audit.prune` (the owner
    at the TUI/CLI) and refuses inside an agent tool. The prune itself is recorded, after
    the removal, so it is never removed by the prune it describes."""
    from kratos.authz import check
    from kratos.authz.permissions import AUDIT_PRUNE

    check.require(actor, AUDIT_PRUNE, data_dir=data_dir, obj=f"before {before:.0f}")
    with S.opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("INSERT INTO audit_log_prune_permit (opened_at) VALUES (?)", (time.time(),))
            n = conn.execute("DELETE FROM audit_log WHERE at < ?", (float(before),)).rowcount
            conn.execute("DELETE FROM audit_log_prune_permit")
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    record(data_dir, interface=actor.interface, action=AUDIT_PRUNE, result="allowed",
           user_id=getattr(actor, "user_id", None) or S.OWNER_ID, user_name=actor.user,
           obj=f"removed {n} rows older than {time.strftime('%Y-%m-%d', time.gmtime(before))}")
    return int(n)


def recent_refusals(data_dir: Path | str, limit: int = 5) -> list[dict[str, Any]]:
    return query(data_dir, result="refused", limit=limit)


def iter_actions(rows: Iterable[dict[str, Any]]) -> list[str]:
    return sorted({r["action"] for r in rows})
