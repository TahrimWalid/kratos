"""People's baseline decisions (E.3 §3.7, §3.8): "this is normal", forget, freeze, unfreeze,
reset.

All people-only: refused inside a tool run (the model never makes one), from MCP and from
the chat server; they need `baseline.accept` (the owner at the Kratos host, TUI or CLI).
Every decision is recorded in ``baseline_decisions`` with the actor.

- **accept** -- the key is normal for this subject from now on: it gains weight, is never
  raised again, and the matching BASE finding (if any) is marked a false positive with the
  reason "expected behaviour" through the ordinary lifecycle decision (same person).
- **forget** -- the key counts as new again (marked, not deleted).
- **freeze** -- after an incident: deviations are still raised, nothing is learned.
- **unfreeze** -- learning resumes.
- **reset** -- learning starts again from now (a new generation per dimension); the old
  profile is kept as history and still shown.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.baseline import dims as D
from kratos.baseline import learn as L
from kratos.baseline import store as S
from kratos.lifecycle.decide import Actor
from kratos.target_key import target_key

ACTOR_INTERFACES = ("tui", "cli")
MAX_REASON = 300


class BaselineError(ValueError):
    """A forbidden caller or a bad request; nothing was written."""


def _check_actor(actor: Any, data_dir: Path | str, machine: str, obj: str) -> None:
    tool = settings_store.in_tool_call()
    if tool is not None:
        raise BaselineError(f"agent tools may not change what's normal (tool {tool!r} tried)")
    if not isinstance(actor, Actor) or actor.interface not in ACTOR_INTERFACES or not str(actor.user or "").strip():
        raise BaselineError("a baseline decision needs a person: an Actor from the TUI or the CLI")
    from kratos import authz

    try:
        authz.require(actor, authz.P.BASELINE_ACCEPT, machine, data_dir=data_dir, obj=obj)
    except authz.Denied as e:
        raise BaselineError(str(e)) from None


def _reason(text: Any, default: str) -> str:
    out = " ".join(str(text or "").split())[:MAX_REASON]
    if any(ord(ch) < 32 or ch in "‪‫‬‭‮⁦⁧⁨⁩" for ch in out):
        raise BaselineError("the reason must be plain text")
    return out or default


def _dim(name: str) -> D.Dim:
    dim = D.BY_NAME.get(str(name or "").strip())
    if dim is None:
        raise BaselineError(f"kind is one of: {', '.join(D.BY_NAME)}")
    return dim


def _current_generation(conn, tk: str, dim: str) -> int:
    p = S.current_profiles(conn, tk).get(dim)
    if p is None:
        raise BaselineError("Kratos has not learned anything for this machine yet (run a collection first)")
    return int(p["generation"])


def accept(data_dir: Path | str, machine: str, dim: str, subject: str, key: str, *, actor: Actor,
           reason: str = "", now: float | None = None) -> dict[str, Any]:
    """Mark (subject, key) normal in this machine's current baseline, and the matching BASE
    finding a false positive ("expected behaviour"). Returns what changed."""
    d = _dim(dim)
    tk = target_key(machine)
    subject, key = str(subject or "").strip(), str(key or "").strip()
    if not subject or not key:
        raise BaselineError("say whose normal (account or program) and what (the key shown in /baseline)")
    _check_actor(actor, data_dir, tk, f"baseline accept {d.name}")
    why = _reason(reason, "expected behaviour")
    now = time.time() if now is None else now
    from kratos.lifecycle import keys as LK

    fkey = LK.finding_key(d.rule, tk, subject)
    exception_id = None
    finding_state = None
    try:
        from kratos.lifecycle import decide as LD
        from kratos.lifecycle import store as LS

        with LS.opened(data_dir) as lconn:
            rec = LS.get_record(lconn, fkey)
        if rec is not None and rec["state"] not in ("false_positive",):
            res = LD.mark_false_positive(fkey, actor=actor, reason=f"expected behaviour: {why}", data_dir=Path(data_dir),
                                         now=now)
            exception_id, finding_state = res.get("exception_id"), "false_positive"
    except Exception as e:  # noqa: BLE001 -- the baseline mark still applies; say why the finding wasn't decided
        finding_state = f"not changed ({type(e).__name__}: {e})"[:200]
    with S.opened(data_dir) as conn, S.immediate(conn):
        gen = _current_generation(conn, tk, d.name)
        rows = {r["key"]: r for r in S.entries(conn, tk, d.name, gen) if r["subject"] == subject}
        e = L.Entry.from_row(rows[key]) if key in rows else L.Entry(subject, key, 0.0, now, 0, now, now)
        e.forgotten_at = e.forgotten_by = None
        e.accepted_at, e.accepted_by = now, actor.user
        L.add_weight(e, now, 1.0, L.Settings.load(data_dir).half_life_days * L.DAY)
        S.upsert_entry(conn, tk, d.name, gen, e.as_row())
        S.add_decision(conn, target_key=tk, dim=d.name, kind="accept", subject=subject, key=key, actor=actor.user,
                       interface=actor.interface, user_id=actor.user_id, reason=why, at=now, finding_key=fkey,
                       details={"exception_id": exception_id} if exception_id is not None else None)
    return {"machine": tk, "dim": d.name, "subject": subject, "key": key, "finding_key": fkey,
            "finding": finding_state or "no open finding for it"}


def forget(data_dir: Path | str, machine: str, dim: str, subject: str, key: str, *, actor: Actor,
           reason: str = "", now: float | None = None) -> dict[str, Any]:
    d = _dim(dim)
    tk = target_key(machine)
    _check_actor(actor, data_dir, tk, f"baseline forget {d.name}")
    why = _reason(reason, "forgotten by a person")
    now = time.time() if now is None else now
    with S.opened(data_dir) as conn, S.immediate(conn):
        gen = _current_generation(conn, tk, d.name)
        rows = [r for r in S.entries(conn, tk, d.name, gen) if r["subject"] == subject and r["key"] == key]
        if not rows:
            raise BaselineError(f"nothing learned for {subject!r} / {key!r} in {d.name}")
        e = L.Entry.from_row(rows[0])
        e.forgotten_at, e.forgotten_by = now, actor.user
        e.accepted_at = e.accepted_by = None
        S.upsert_entry(conn, tk, d.name, gen, e.as_row())
        S.add_decision(conn, target_key=tk, dim=d.name, kind="forget", subject=subject, key=key, actor=actor.user,
                       interface=actor.interface, user_id=actor.user_id, reason=why, at=now)
    return {"machine": tk, "dim": d.name, "subject": subject, "key": key, "forgotten": True}


def _set_frozen(data_dir: Path | str, machine: str, frozen: bool, *, actor: Actor, reason: str,
                now: float | None) -> dict[str, Any]:
    tk = target_key(machine)
    kind = "freeze" if frozen else "unfreeze"
    _check_actor(actor, data_dir, tk, f"baseline {kind}")
    why = _reason(reason, "after an incident" if frozen else "learning resumes")
    now = time.time() if now is None else now
    with S.opened(data_dir) as conn, S.immediate(conn):
        profiles = S.current_profiles(conn, tk)
        if not profiles:
            raise BaselineError("Kratos has not learned anything for this machine yet (run a collection first)")
        for name, p in profiles.items():
            S.update_profile(conn, tk, name, int(p["generation"]), frozen=int(frozen),
                             status="frozen" if frozen else ("learning" if p["status"] == "frozen" else p["status"]),
                             updated_at=now)
        S.add_decision(conn, target_key=tk, dim=None, kind=kind, subject=None, key=None, actor=actor.user,
                       interface=actor.interface, user_id=actor.user_id, reason=why, at=now)
    return {"machine": tk, "frozen": frozen}


def freeze(data_dir: Path | str, machine: str, *, actor: Actor, reason: str = "",
           now: float | None = None) -> dict[str, Any]:
    return _set_frozen(data_dir, machine, True, actor=actor, reason=reason, now=now)


def unfreeze(data_dir: Path | str, machine: str, *, actor: Actor, reason: str = "",
             now: float | None = None) -> dict[str, Any]:
    return _set_frozen(data_dir, machine, False, actor=actor, reason=reason, now=now)


def reset(data_dir: Path | str, machine: str, *, actor: Actor, reason: str = "", dims: list[str] | None = None,
          now: float | None = None) -> dict[str, Any]:
    """Start learning again from now: a new generation per dimension (all, or `dims`). The
    old generation is kept and shown as history; nothing is deleted."""
    tk = target_key(machine)
    chosen = [_dim(n).name for n in dims] if dims else [d.name for d in D.DIMS]
    _check_actor(actor, data_dir, tk, "baseline reset")
    why = _reason(reason, "reset by a person")
    now = time.time() if now is None else now
    with S.opened(data_dir) as conn, S.immediate(conn):
        profiles = S.current_profiles(conn, tk)
        if not profiles:
            raise BaselineError("Kratos has not learned anything for this machine yet (run a collection first)")
        try:
            max_row = int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM host_events WHERE target = ?",
                                       (tk,)).fetchone()[0])
        except Exception:  # noqa: BLE001
            max_row = 0
        for name in chosen:
            p = profiles.get(name)
            if p is None:
                continue
            S.end_profile(conn, tk, name, int(p["generation"]), now)
            S.new_profile(conn, tk, name, generation=int(p["generation"]) + 1, started_at=now, high_water=max_row,
                          snapshot_high_water=now, tz=p["tz"], frozen=False,
                          note=f"reset by {actor.user}: learning starts again", now=now)
        S.add_decision(conn, target_key=tk, dim=None if dims is None else ",".join(chosen), kind="reset",
                       subject=None, key=None, actor=actor.user, interface=actor.interface, user_id=actor.user_id,
                       reason=why, at=now, details={"dims": chosen})
    return {"machine": tk, "reset": chosen}
