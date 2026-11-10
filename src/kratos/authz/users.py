"""Kratos users, their scopes and gateway mappings (docs/phaseD/D.7 §3.1, §3.4, §3.6).

Users are Kratos's own, not OS accounts. The owner (the OS account that owns the data
folder) is always admin and can't be disabled or demoted. Every change here is an admin
action -- only the owner, at the Kratos host's TUI or CLI (require `users.manage`) -- and
is recorded in the audit trail by that check.
"""
from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from kratos.authz import permissions as P
from kratos.authz import store as S

OWNER_ID = S.OWNER_ID
PROVIDERS = ("openwebui",)
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
_EXTERNAL_RE = re.compile(r"^[A-Za-z0-9._:@+-]{1,128}$")
_GROUP_RE = re.compile(r"^@[a-z0-9][a-z0-9_-]{0,39}$")


class UserError(ValueError):
    """A user change that can't be made as asked; the message is user-facing."""


@dataclass(frozen=True)
class User:
    user_id: str
    name: str
    role: str
    created_at: float
    created_by: str
    disabled_at: float | None = None
    note: str = ""
    scopes: tuple[str, ...] = field(default_factory=tuple)    # 'web-01', '@lab'

    @property
    def is_owner(self) -> bool:
        return self.user_id == OWNER_ID

    @property
    def disabled(self) -> bool:
        return self.disabled_at is not None

    @property
    def scope_text(self) -> str:
        if self.is_owner:
            return "every machine"
        return ", ".join(self.scopes) if self.scopes else "nothing yet"


def _row_user(conn: Any, r: Any) -> User:
    scopes = tuple(("@" + s["value"]) if s["kind"] == "group" else s["value"] for s in conn.execute(
        "SELECT kind, value FROM user_scopes WHERE user_id = ? ORDER BY kind DESC, value", (r["user_id"],)))
    return User(user_id=r["user_id"], name=r["name"], role=r["role"], created_at=float(r["created_at"]),
                created_by=r["created_by"], disabled_at=r["disabled_at"], note=r["note"] or "", scopes=scopes)


def get(data_dir: Path | str, user_id: str) -> User | None:
    with S.opened(data_dir) as conn:
        r = conn.execute("SELECT * FROM users WHERE user_id = ?", (str(user_id or ""),)).fetchone()
        return _row_user(conn, r) if r is not None else None


def owner(data_dir: Path | str) -> User:
    u = get(data_dir, OWNER_ID)
    assert u is not None   # made by the migration
    return u


def find(data_dir: Path | str, ref: str) -> User | None:
    """By id or name (names are case-insensitive)."""
    ref = str(ref or "").strip()
    if not ref:
        return None
    with S.opened(data_dir) as conn:
        r = conn.execute("SELECT * FROM users WHERE user_id = ? OR lower(name) = lower(?)", (ref, ref)).fetchone()
        return _row_user(conn, r) if r is not None else None


def list_users(data_dir: Path | str) -> list[User]:
    with S.opened(data_dir) as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY user_id != 'owner', lower(name)").fetchall()
        return [_row_user(conn, r) for r in rows]


def _require(actor: Any, data_dir: Path | str, obj: str) -> None:
    from kratos.authz import check

    check.require(actor, P.USERS_MANAGE, data_dir=data_dir, obj=obj)


def _who(actor: Any) -> str:
    return f"{actor.interface}:{actor.user}"[:80]


def _check_role(role: str) -> str:
    role = str(role or "").strip().lower()
    if role not in P.ROLES:
        raise UserError(f"role must be one of: {', '.join(P.ROLES)}")
    return role


def _check_scope_entry(entry: str) -> tuple[str, str]:
    from kratos.utils.hostnames import is_ip_or_hostname

    value = str(entry or "").strip().lower()
    if value.startswith("@"):
        if not _GROUP_RE.match(value):
            raise UserError(f"{entry!r} is not a group name (like @web)")
        return "group", value[1:]
    if not value or not is_ip_or_hostname(value):
        raise UserError(f"{entry!r} is not a machine address or host name (or a group like @web)")
    return "machine", value


def add_user(data_dir: Path | str, name: str, role: str, actor: Any, *, scopes: Iterable[str] = (),
             note: str = "") -> User:
    name = str(name or "").strip()
    if not _NAME_RE.match(name):
        raise UserError("a user name is 1-40 letters, digits, dots, dashes or underscores")
    role = _check_role(role)
    entries = [_check_scope_entry(s) for s in scopes]
    _require(actor, data_dir, f"add user {name} as {role}")
    with S.opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if conn.execute("SELECT 1 FROM users WHERE lower(name) = lower(?)", (name,)).fetchone():
                raise UserError(f"a user named {name!r} already exists")
            uid = "u_" + secrets.token_hex(5)
            now = time.time()
            conn.execute("INSERT INTO users (user_id, name, role, created_at, created_by, note) VALUES (?, ?, ?, ?, ?, ?)",
                         (uid, name, role, now, _who(actor), str(note or "")[:200] or None))
            for kind, value in entries:
                conn.execute("INSERT OR IGNORE INTO user_scopes (user_id, kind, value, added_at, added_by) "
                             "VALUES (?, ?, ?, ?, ?)", (uid, kind, value, now, _who(actor)))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    out = get(data_dir, uid)
    assert out is not None
    return out


def _target(data_dir: Path | str, ref: str, *, allow_owner: bool = False) -> User:
    u = find(data_dir, ref)
    if u is None:
        raise UserError(f"no user {ref!r} (see kratos users list)")
    if u.is_owner and not allow_owner:
        raise UserError("the owner is always an admin with every machine; it can't be changed or disabled")
    return u


def set_role(data_dir: Path | str, ref: str, role: str, actor: Any) -> User:
    role = _check_role(role)
    u = _target(data_dir, ref)
    _require(actor, data_dir, f"role of {u.name}: {u.role} -> {role}")
    with S.opened(data_dir) as conn:
        conn.execute("UPDATE users SET role = ? WHERE user_id = ?", (role, u.user_id))
    return get(data_dir, u.user_id)  # type: ignore[return-value]


def set_disabled(data_dir: Path | str, ref: str, disabled: bool, actor: Any) -> User:
    u = _target(data_dir, ref)
    _require(actor, data_dir, f"{'disable' if disabled else 'enable'} {u.name}")
    with S.opened(data_dir) as conn:
        if disabled:
            conn.execute("UPDATE users SET disabled_at = ?, disabled_by = ? WHERE user_id = ?",
                         (time.time(), _who(actor), u.user_id))
        else:
            conn.execute("UPDATE users SET disabled_at = NULL, disabled_by = NULL WHERE user_id = ?", (u.user_id,))
    return get(data_dir, u.user_id)  # type: ignore[return-value]


def set_scopes(data_dir: Path | str, ref: str, scopes: Iterable[str], actor: Any) -> User:
    """Replace the user's scope. A running investigation on a machine taken out stops at
    its next read (kratos.authz.check.check_run_access)."""
    u = _target(data_dir, ref)
    entries = sorted({_check_scope_entry(s) for s in scopes})
    text = ", ".join(("@" + v) if k == "group" else v for k, v in entries) or "nothing"
    _require(actor, data_dir, f"scope of {u.name}: {text}")
    with S.opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("DELETE FROM user_scopes WHERE user_id = ?", (u.user_id,))
            now = time.time()
            for kind, value in entries:
                conn.execute("INSERT INTO user_scopes (user_id, kind, value, added_at, added_by) VALUES (?, ?, ?, ?, ?)",
                             (u.user_id, kind, value, now, _who(actor)))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return get(data_dir, u.user_id)  # type: ignore[return-value]


def add_scopes(data_dir: Path | str, ref: str, scopes: Iterable[str], actor: Any) -> User:
    u = _target(data_dir, ref)
    return set_scopes(data_dir, u.user_id, list(u.scopes) + list(scopes), actor)


def remove_scopes(data_dir: Path | str, ref: str, scopes: Iterable[str], actor: Any) -> User:
    u = _target(data_dir, ref)
    drop = {"{}{}".format("@" if k == "group" else "", v) for k, v in (_check_scope_entry(s) for s in scopes)}
    missing = drop - set(u.scopes)
    if missing:
        raise UserError(f"{u.name}'s scope doesn't include {', '.join(sorted(missing))}")
    return set_scopes(data_dir, u.user_id, [s for s in u.scopes if s not in drop], actor)


# --- gateway mappings ------------------------------------------------------------
@dataclass(frozen=True)
class Mapping:
    provider: str
    external_id: str
    email: str
    user_id: str
    user_name: str
    added_at: float


def map_gateway(data_dir: Path | str, provider: str, external_id: str, ref: str, actor: Any,
                *, email: str = "") -> Mapping:
    provider = str(provider or "").strip().lower()
    if provider not in PROVIDERS:
        raise UserError(f"provider must be one of: {', '.join(PROVIDERS)}")
    external_id = str(external_id or "").strip()
    if not _EXTERNAL_RE.match(external_id):
        raise UserError("the Open WebUI user id is 1-128 letters, digits and . _ : @ + -")
    u = _target(data_dir, ref)
    _require(actor, data_dir, f"map {provider} user {external_id} to {u.name}")
    with S.opened(data_dir) as conn:
        conn.execute("INSERT INTO user_gateway_ids (provider, external_id, email, user_id, added_at, added_by) "
                     "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(provider, external_id) DO UPDATE SET "
                     "user_id = excluded.user_id, email = excluded.email, added_at = excluded.added_at, "
                     "added_by = excluded.added_by",
                     (provider, external_id, str(email or "")[:200] or None, u.user_id, time.time(), _who(actor)))
    out = mapping_for(data_dir, provider, external_id)
    assert out is not None
    return out


def unmap_gateway(data_dir: Path | str, provider: str, external_id: str, actor: Any) -> None:
    m = mapping_for(data_dir, provider, external_id)
    if m is None:
        raise UserError(f"no mapping for {provider} user {external_id!r}")
    _require(actor, data_dir, f"unmap {provider} user {external_id}")
    with S.opened(data_dir) as conn:
        conn.execute("DELETE FROM user_gateway_ids WHERE provider = ? AND external_id = ?", (provider, external_id))


def mapping_for(data_dir: Path | str, provider: str, external_id: str) -> Mapping | None:
    with S.opened(data_dir) as conn:
        r = conn.execute("SELECT g.*, u.name AS user_name FROM user_gateway_ids g JOIN users u ON u.user_id = g.user_id "
                         "WHERE g.provider = ? AND g.external_id = ?", (provider, str(external_id or ""))).fetchone()
    if r is None:
        return None
    return Mapping(r["provider"], r["external_id"], r["email"] or "", r["user_id"], r["user_name"],
                   float(r["added_at"]))


def list_mappings(data_dir: Path | str) -> list[Mapping]:
    with S.opened(data_dir) as conn:
        rows = conn.execute("SELECT g.*, u.name AS user_name FROM user_gateway_ids g JOIN users u ON u.user_id = g.user_id "
                            "ORDER BY lower(u.name), g.external_id").fetchall()
    return [Mapping(r["provider"], r["external_id"], r["email"] or "", r["user_id"], r["user_name"],
                    float(r["added_at"])) for r in rows]
