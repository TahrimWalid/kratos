"""People's compliance decisions (E.2 §3.6, §3.8): control owners, "not applicable"
decisions and the CIS level per machine.

All of them are people-only: refused inside a tool run (the model never sets one), from
MCP and from the chat server; they need `compliance.owner_set` (the owner at the Kratos
host). Every change is recorded in ``control_owner_events`` with the actor.

Scopes: ``machine:<target_key>`` (most specific), ``group:<name>``, ``all``. For a machine
the most specific matching scope wins. An N/A decision needs a reason and expires after
at most `compliance.na_max_days` (365) days; after that the computed status is back and
an ``na_expired`` event is recorded once.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.compliance import cac, frameworks as F
from kratos.compliance import store as S
from kratos.lifecycle.decide import Actor
from kratos.target_key import target_key

ACTOR_INTERFACES = ("tui", "cli")
MAX_TEXT = 300
_SECTION_RE = re.compile(r"^[0-9]{1,2}(\.[0-9]{1,3}){0,5}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ComplianceError(ValueError):
    """A forbidden caller, an unknown control, or a bad value; nothing was written."""


def _check_actor(actor: Any, data_dir: Path | str, obj: str) -> None:
    tool = settings_store.in_tool_call()
    if tool is not None:
        raise ComplianceError(f"agent tools may not change compliance decisions (tool {tool!r} tried)")
    if not isinstance(actor, Actor) or actor.interface not in ACTOR_INTERFACES or not str(actor.user or "").strip():
        raise ComplianceError("a compliance decision needs a person: an Actor from the TUI or the CLI")
    from kratos import authz

    try:
        authz.require(actor, authz.P.COMPLIANCE_OWNER_SET, data_dir=data_dir, obj=obj)
    except authz.Denied as e:
        raise ComplianceError(str(e)) from None


def _text(value: Any, name: str, required: bool = False) -> str:
    text = " ".join(str(value or "").split())
    if required and not text:
        raise ComplianceError(f"{name} is required")
    if len(text) > MAX_TEXT:
        raise ComplianceError(f"{name} is at most {MAX_TEXT} characters")
    if any(ord(ch) < 32 or ch in "‪‫‬‭‮⁦⁧⁨⁩" for ch in text):
        raise ComplianceError(f"{name} must be plain text")
    return text


def check_control(framework: str, control_id: str) -> tuple[str, str]:
    fw = str(framework or "").strip().lower()
    cid = str(control_id or "").strip()
    if fw not in F.FRAMEWORKS:
        raise ComplianceError(f"framework is one of: {', '.join(F.FRAMEWORKS)}")
    if fw == "cis":
        if not _SECTION_RE.fullmatch(cid) or not any(
                cid == c["id"] for p in cac.products() for c in cac.vendored()["products"][p]["controls"]):
            raise ComplianceError(f"{cid!r} is not a CIS section number in the vendored mapping")
    elif F.control(fw, cid) is None:
        raise ComplianceError(f"{cid!r} is not a {fw} control id")
    return fw, cid


def check_scope(scope: str) -> str:
    s = str(scope or "").strip()
    if s == "all":
        return s
    kind, _, value = s.partition(":")
    if kind == "machine" and value.strip():
        key = target_key(value.strip())
        if not key:
            raise ComplianceError("which machine?")
        return f"machine:{key}"
    if kind == "group" and value.strip():
        from kratos.fleet import groups as G

        try:
            return f"group:{G.check_name(value.strip().lstrip('@'))}"
        except G.GroupError as e:
            raise ComplianceError(str(e)) from None
    raise ComplianceError("scope is 'machine:<name>', 'group:<name>' or 'all'")


def _due(value: Any) -> str | None:
    v = str(value or "").strip()
    if not v:
        return None
    if not _DATE_RE.fullmatch(v):
        raise ComplianceError("due date is YYYY-MM-DD")
    try:
        date.fromisoformat(v)
    except ValueError:
        raise ComplianceError("due date is not a real date") from None
    return v


def set_owner(data_dir: Path | str, actor: Actor, framework: str, control_id: str, scope: str, owner: str, *,
              due: str | None = None, note: str = "") -> dict[str, Any]:
    fw, cid = check_control(framework, control_id)
    sc = check_scope(scope)
    _check_actor(actor, data_dir, f"owner of {fw} {cid}")
    name = _text(owner, "owner", required=True)
    from kratos.authz import users

    user = users.find(data_dir, name)
    row = {"owner_user_id": user.user_id if user else None, "owner_name": user.name if user else name,
           "due": _due(due), "note": _text(note, "note")}
    now = time.time()
    with S.opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("INSERT OR REPLACE INTO control_owners VALUES (?,?,?,?,?,?,?,?,?)",
                         (fw, cid, sc, row["owner_user_id"], row["owner_name"], row["due"], row["note"],
                          actor.user[:120], now))
            S.add_event(conn, kind="owner_set", framework=fw, control_id=cid, scope=sc, detail=row, actor=actor.user,
                        interface=actor.interface, at=now)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return {"framework": fw, "control": cid, "scope": sc, **row}


def clear_owner(data_dir: Path | str, actor: Actor, framework: str, control_id: str, scope: str) -> bool:
    fw, cid = check_control(framework, control_id)
    sc = check_scope(scope)
    _check_actor(actor, data_dir, f"owner of {fw} {cid}")
    with S.opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            n = conn.execute("DELETE FROM control_owners WHERE framework = ? AND control_id = ? AND scope = ?",
                             (fw, cid, sc)).rowcount
            if n:
                S.add_event(conn, kind="owner_clear", framework=fw, control_id=cid, scope=sc, actor=actor.user,
                            interface=actor.interface)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return bool(n)


def set_na(data_dir: Path | str, actor: Actor, framework: str, control_id: str, scope: str, reason: str,
           days: int) -> dict[str, Any]:
    fw, cid = check_control(framework, control_id)
    sc = check_scope(scope)
    _check_actor(actor, data_dir, f"'not applicable' for {fw} {cid}")
    why = _text(reason, "a reason", required=True)
    from kratos.compliance import settings as CS

    limit = int(CS.get(CS.NA_MAX_DAYS, data_dir))
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= limit:
        raise ComplianceError(f"how long it lasts: 1-{limit} days (compliance.na_max_days)")
    now = time.time()
    expires = now + days * 86400
    with S.opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("INSERT OR REPLACE INTO control_na VALUES (?,?,?,?,?,?,?)",
                         (fw, cid, sc, why, expires, actor.user[:120], now))
            S.add_event(conn, kind="na_set", framework=fw, control_id=cid, scope=sc,
                        detail={"reason": why, "expires_at": expires}, actor=actor.user, interface=actor.interface,
                        at=now)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return {"framework": fw, "control": cid, "scope": sc, "reason": why, "expires_at": expires}


def clear_na(data_dir: Path | str, actor: Actor, framework: str, control_id: str, scope: str) -> bool:
    fw, cid = check_control(framework, control_id)
    sc = check_scope(scope)
    _check_actor(actor, data_dir, f"'not applicable' for {fw} {cid}")
    with S.opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            n = conn.execute("DELETE FROM control_na WHERE framework = ? AND control_id = ? AND scope = ?",
                             (fw, cid, sc)).rowcount
            if n:
                S.add_event(conn, kind="na_clear", framework=fw, control_id=cid, scope=sc, actor=actor.user,
                            interface=actor.interface)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return bool(n)


def set_level(data_dir: Path | str, actor: Actor, machine: str, level: str) -> str:
    lv = {"1": "l1_server", "2": "l2_server"}.get(str(level).strip(), str(level).strip().lower())
    if lv not in cac.LEVELS:
        raise ComplianceError("CIS level is 1 (Level 1 Server) or 2 (Level 2 Server)")
    key = target_key(machine)
    if not key:
        raise ComplianceError("which machine?")
    _check_actor(actor, data_dir, f"CIS level of {key}")
    now = time.time()
    with S.opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("INSERT OR REPLACE INTO compliance_profiles VALUES (?,?,?,?)", (key, lv, actor.user[:120], now))
            S.add_event(conn, kind="level_set", scope=f"machine:{key}", detail={"level": lv}, actor=actor.user,
                        interface=actor.interface, at=now)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return lv


def level_for(data_dir: Path | str, machine: str) -> str:
    try:
        with S.opened(data_dir) as conn:
            r = conn.execute("SELECT cis_level FROM compliance_profiles WHERE target_key = ?",
                             (target_key(machine),)).fetchone()
    except Exception:  # noqa: BLE001
        return cac.DEFAULT_LEVEL
    return str(r[0]) if r else cac.DEFAULT_LEVEL


def _scopes_for(data_dir: Path | str, machine: str) -> list[str]:
    """Most specific first: the machine, its groups, everything."""
    key = target_key(machine)
    try:
        from kratos.fleet import groups as G

        groups = list(G.groups_of(data_dir, key))
    except Exception:  # noqa: BLE001
        groups = []
    return [f"machine:{key}", *[f"group:{g}" for g in groups], "all"]


@dataclass(frozen=True)
class Owner:
    name: str
    user_id: str | None
    due: str | None
    note: str
    scope: str
    still_a_user: bool = True

    def label(self) -> str:
        who = self.name if self.still_a_user else f"{self.name} (no longer a user)"
        return who + (f", due {self.due}" if self.due else "")


def owners_for(data_dir: Path | str, framework: str, machine: str) -> dict[str, Owner]:
    scopes = _scopes_for(data_dir, machine)
    rank = {s: i for i, s in enumerate(scopes)}
    out: dict[str, tuple[int, Owner]] = {}
    try:
        with S.opened(data_dir) as conn:
            rows = conn.execute("SELECT * FROM control_owners WHERE framework = ?", (framework,)).fetchall()
    except Exception:  # noqa: BLE001
        return {}
    from kratos.authz import users

    for r in rows:
        if r["scope"] not in rank:
            continue
        still = True
        if r["owner_user_id"]:
            u = users.get(data_dir, r["owner_user_id"])
            still = u is not None and not u.disabled
        o = Owner(r["owner_name"], r["owner_user_id"], r["due"], r["note"], r["scope"], still)
        cur = out.get(r["control_id"])
        if cur is None or rank[r["scope"]] < cur[0]:
            out[r["control_id"]] = (rank[r["scope"]], o)
    return {k: v for k, (_i, v) in out.items()}


def na_for(data_dir: Path | str, framework: str, machine: str, now: float | None = None) -> dict[tuple[str, str], dict]:
    """Active N/A decisions for `machine`, keyed (framework, control). Expired ones are
    recorded once as an `na_expired` event and no longer apply."""
    now = time.time() if now is None else now
    scopes = _scopes_for(data_dir, machine)
    rank = {s: i for i, s in enumerate(scopes)}
    out: dict[tuple[str, str], tuple[int, dict]] = {}
    try:
        with S.opened(data_dir) as conn:
            rows = conn.execute("SELECT * FROM control_na WHERE framework = ?", (framework,)).fetchall()
            for r in rows:
                if r["scope"] not in rank:
                    continue
                if float(r["expires_at"]) <= now:
                    seen = conn.execute(
                        "SELECT 1 FROM control_owner_events WHERE kind = 'na_expired' AND framework = ? AND "
                        "control_id = ? AND scope = ? AND at >= ?",
                        (r["framework"], r["control_id"], r["scope"], float(r["set_at"]))).fetchone()
                    if seen is None:
                        S.add_event(conn, kind="na_expired", framework=r["framework"], control_id=r["control_id"],
                                    scope=r["scope"], detail={"reason": r["reason"]}, actor="kratos",
                                    interface="expiry", at=now)
                    continue
                d = {"reason": r["reason"], "actor": r["set_by"], "scope": r["scope"],
                     "expires_at": datetime.fromtimestamp(float(r["expires_at"]), timezone.utc).date().isoformat()}
                cur = out.get((framework, r["control_id"]))
                if cur is None or rank[r["scope"]] < cur[0]:
                    out[(framework, r["control_id"])] = (rank[r["scope"]], d)
    except Exception:  # noqa: BLE001 -- no decisions readable = none applied
        return {}
    return {k: v for k, (_i, v) in out.items()}
