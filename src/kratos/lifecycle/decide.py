"""What a person can decide about a finding.

verify, accept the risk (owner, reason, expiry -- required, capped by
`findings.accept_max_days`), mark a false positive, mark out of scope, or
reopen. A decision applies to this finding, this rule on this machine, or this
rule everywhere; a newer decision at the same scope replaces the older one
(recorded as revoked).

A decision records what the person saw -- the finding's severity and entities.
If the finding later shows a new entity or a higher severity, it reopens
(lifecycle/apply.py).

People only: every function needs an Actor from the TUI or CLI, refuses inside
an agent tool call, and no agent tool or MCP tool imports this module (a test
scans for it). The model can suggest a decision; it can never make one.
"""
from __future__ import annotations

import getpass
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.lifecycle import settings as lc_settings
from kratos.lifecycle import store as S
from kratos.lifecycle.rules import is_run_note

INTERFACES = ("tui", "cli")
MAX_REASON = 500
MAX_OWNER = 120
# Picking "180 days" and confirming takes a moment; don't refuse the cap itself.
_CAP_SLACK_SECONDS = 600
SCOPE_WORDS = {"key": "this finding", "rule_target": "this rule on this machine", "rule": "this rule everywhere"}
KIND_WORDS = {"risk_accepted": "Risk accepted", "false_positive": "Not a real problem (false positive)",
              "out_of_scope": "Not relevant for this machine (out of scope)", "verified": "Confirmed real (verified)",
              "open": "Reopened"}


class DecisionError(ValueError):
    """A decision that can't be made as asked; the message is user-facing."""


@dataclass(frozen=True)
class Actor:
    user: str          # getpass.getuser()
    interface: str     # "tui" | "cli"

    @classmethod
    def current(cls, interface: str) -> "Actor":
        try:
            user = getpass.getuser()
        except Exception:  # noqa: BLE001 -- no login name (containers): still attributable
            user = "unknown"
        return cls(user=user, interface=interface)


def _check_actor(actor: Actor) -> None:
    tool = settings_store.in_tool_call()
    if tool is not None:
        raise DecisionError(f"agent tools may not decide about findings (tool {tool!r} tried)")
    if not isinstance(actor, Actor) or actor.interface not in INTERFACES or not str(actor.user or "").strip():
        raise DecisionError("a decision needs a person: an Actor from the TUI or the CLI")


def _check_reason(reason: str) -> str:
    text = str(reason or "")
    if not text.strip():
        raise DecisionError("a reason is required")
    if len(text) > MAX_REASON:
        raise DecisionError(f"the reason is too long ({len(text)} characters, at most {MAX_REASON})")
    return text


def _check_scope(scope: str) -> str:
    scope = str(scope or "key").replace("-", "_")
    if scope not in S.SCOPES:
        raise DecisionError(f"scope must be one of: {', '.join(S.SCOPES)}")
    return scope


def max_accept_seconds(data_dir: Path) -> float:
    return settings_store.get(lc_settings.ACCEPT_MAX_DAYS, data_dir=data_dir) * 86400.0


def _check_expiry(expires_at: float | None, *, required: bool, cap: float | None, now: float) -> float | None:
    if expires_at is None:
        if required:
            raise DecisionError("accepting a risk needs an expiry date")
        return None
    try:
        when = float(expires_at)
    except (TypeError, ValueError):
        raise DecisionError("the expiry must be a date") from None
    if when <= now:
        raise DecisionError("the expiry must be in the future")
    if cap is not None and when > now + cap + _CAP_SLACK_SECONDS:
        raise DecisionError(f"a risk can be accepted for at most {int(cap // 86400)} days "
                            "(Settings -> General: findings.accept_max_days)")
    return when


def _record(conn, key: str):
    try:
        full = S.resolve_key(conn, key)
    except LookupError as e:
        raise DecisionError(str(e)) from None
    rec = S.get_record(conn, full)
    if is_run_note(rec["rule_id"]):
        raise DecisionError(f"{rec['rule_id']} says how complete a run was; it can't be decided")
    return rec


def _event(conn, key: str, *, kind: str, frm: str, to: str, actor: Actor, reason: str, now: float,
           details: dict[str, Any] | None = None) -> None:
    S.add_event(conn, key, at=now, kind=kind, from_state=frm, to_state=to, actor=actor.user,
                interface=actor.interface, reason=reason, details=details)


def _revoke_key_scope(conn, key: str, *, actor: Actor, reason: str, now: float) -> None:
    conn.execute("UPDATE finding_exceptions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
                 "WHERE scope = 'key' AND finding_key = ? AND revoked_at IS NULL", (now, actor.user, reason, key))


def _decide(key: str, kind: str, *, actor: Actor, reason: str, scope: str, expires_at: float | None,
            owner: str | None, data_dir: Path, now: float | None) -> dict[str, Any]:
    _check_actor(actor)
    reason = _check_reason(reason)
    scope = _check_scope(scope)
    now = time.time() if now is None else now
    cap = max_accept_seconds(data_dir) if kind == "risk_accepted" else None
    expires = _check_expiry(expires_at, required=kind == "risk_accepted", cap=cap, now=now)
    owner_text = str(owner or "").strip()[:MAX_OWNER] or None
    with S.opened(data_dir) as conn, S.immediate(conn):
        rec = _record(conn, key)
        full = rec["finding_key"]
        match = {"key": ("finding_key = ?", (full,)),
                 "rule_target": ("rule_id = ? AND target = ?", (rec["rule_id"], rec["target"])),
                 "rule": ("rule_id = ?", (rec["rule_id"],))}[scope]
        conn.execute(f"UPDATE finding_exceptions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
                     f"WHERE scope = ? AND {match[0]} AND revoked_at IS NULL",
                     (now, actor.user, "replaced by a newer decision", scope, *match[1]))
        cur = conn.execute(
            "INSERT INTO finding_exceptions (scope, finding_key, rule_id, target, kind, owner, reason, "
            "decided_severity, decided_entities, created_at, created_by, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scope, full if scope == "key" else None, rec["rule_id"],
             rec["target"] if scope in ("key", "rule_target") else None, kind, owner_text, reason,
             rec["severity"], rec["entities"], now, actor.user, expires),
        )
        exc_id = cur.lastrowid
        exc = conn.execute("SELECT * FROM finding_exceptions WHERE id = ?", (exc_id,)).fetchone()
        # The finding acted on, plus (for a broader scope) every other finding the
        # decision covers as it stands now; others wait for their next run.
        where, params = match
        affected = conn.execute(f"SELECT * FROM finding_records WHERE {where}", params).fetchall()
        changed = []
        for r in affected:
            if r["finding_key"] != full:
                ok, _ = S.covers(exc, severity=r["severity"], entities=json.loads(r["entities"]))
                if not ok or r["state"] not in S.SHOWN_BY_DEFAULT:
                    continue
            if r["state"] != kind:
                S.set_state(conn, r["finding_key"], kind)
                _event(conn, r["finding_key"], kind="state_changed", frm=r["state"], to=kind, actor=actor,
                       reason=reason, now=now,
                       details={"exception_id": exc_id, "scope": scope, "expires_at": expires, "owner": owner_text})
                changed.append(r["finding_key"])
    return {"exception_id": exc_id, "finding_key": full, "scope": scope, "kind": kind, "expires_at": expires,
            "changed": changed}


def accept_risk(key: str, *, actor: Actor, reason: str, owner: str | None, expires_at: float,
                scope: str = "key", data_dir: Path, now: float | None = None) -> dict[str, Any]:
    return _decide(key, "risk_accepted", actor=actor, reason=reason, scope=scope, expires_at=expires_at,
                   owner=owner or actor.user, data_dir=data_dir, now=now)


def mark_false_positive(key: str, *, actor: Actor, reason: str, scope: str = "key",
                        expires_at: float | None = None, data_dir: Path, now: float | None = None) -> dict[str, Any]:
    return _decide(key, "false_positive", actor=actor, reason=reason, scope=scope, expires_at=expires_at,
                   owner=actor.user, data_dir=data_dir, now=now)


def mark_out_of_scope(key: str, *, actor: Actor, reason: str, scope: str = "key",
                      expires_at: float | None = None, data_dir: Path, now: float | None = None) -> dict[str, Any]:
    return _decide(key, "out_of_scope", actor=actor, reason=reason, scope=scope, expires_at=expires_at,
                   owner=actor.user, data_dir=data_dir, now=now)


def verify(key: str, *, actor: Actor, reason: str, data_dir: Path, now: float | None = None) -> dict[str, Any]:
    """Confirmed real: still shown. Takes the finding out of any decision."""
    _check_actor(actor)
    reason = _check_reason(reason)
    now = time.time() if now is None else now
    with S.opened(data_dir) as conn, S.immediate(conn):
        rec = _record(conn, key)
        full = rec["finding_key"]
        if rec["state"] == "verified":
            raise DecisionError("this finding is already verified")
        _revoke_key_scope(conn, full, actor=actor, reason="verified instead", now=now)
        S.set_state(conn, full, "verified")
        _event(conn, full, kind="state_changed", frm=rec["state"], to="verified", actor=actor, reason=reason, now=now)
    return {"finding_key": full, "state": "verified", "previous": rec["state"]}


def reopen(key: str, *, actor: Actor, reason: str, data_dir: Path, now: float | None = None) -> dict[str, Any]:
    """Undo a decision: the finding is shown again (open)."""
    _check_actor(actor)
    reason = _check_reason(reason)
    now = time.time() if now is None else now
    with S.opened(data_dir) as conn, S.immediate(conn):
        rec = _record(conn, key)
        full = rec["finding_key"]
        if rec["state"] not in S.DECIDED:
            raise DecisionError(f"only a decided finding can be reopened (this one is {rec['state'].replace('_', ' ')})")
        _revoke_key_scope(conn, full, actor=actor, reason="reopened", now=now)
        S.set_state(conn, full, "open")
        _event(conn, full, kind="reopened", frm=rec["state"], to="open", actor=actor, reason=reason, now=now)
    return {"finding_key": full, "state": "open", "previous": rec["state"]}



def expiry_from_days(days: float, *, now: float | None = None) -> float:
    """`days` from now, as an epoch."""
    try:
        n = float(days)
    except (TypeError, ValueError):
        raise DecisionError("days must be a number") from None
    if n <= 0:
        raise DecisionError("days must be more than 0")
    return (time.time() if now is None else now) + n * 86400.0


def parse_expiry(text: str, *, tz=None) -> float:
    """A date people type, as an epoch: 'YYYY-MM-DD' (the end of that day),
    'YYYY-MM-DD HH:MM', or an ISO time with an offset. Times without an offset are
    in the display time zone."""
    from datetime import datetime, time as dtime

    from kratos.utils.timeutil import resolve_display_tz

    raw = str(text or "").strip()
    if not raw:
        raise DecisionError("give a date, e.g. 2026-12-31 or 2026-12-31 18:00")
    tz = tz or resolve_display_tz()
    try:
        if len(raw) == 10:
            day = datetime.strptime(raw, "%Y-%m-%d").date()
            return datetime.combine(day, dtime(23, 59, 59), tzinfo=tz).timestamp()
        dt = datetime.fromisoformat(raw)
    except ValueError:
        raise DecisionError(f"not a date: {raw!r} (use 2026-12-31 or 2026-12-31 18:00)") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt.timestamp()
