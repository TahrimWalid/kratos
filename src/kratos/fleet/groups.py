"""Groups of machines (D.2 §3.1): named lists in kratos.db -> ``machine_groups`` and
``group_members``, plus the built-in group ``all`` (every machine with an asset record).

A machine may be in several groups. Edits are a person's (TUI or CLI): refused inside an
agent tool, recorded with the actor on the row and, for membership, in the machine's
``asset_events`` history (field ``groups``) -- the asset record's ``groups`` field is
this membership (README §4.2), read from here. Nothing is deleted: a deleted group and a
removed member keep their row with when and by whom.

Machines are stored in ``target_key`` form. A member typed as a paired sub-agent's name
(or target id) is stored as the address that agent is linked to, and two members that
reach the same sub-agent collapse to one machine at resolution -- so an SSH address and
an agent link to the same box are collected once and shown once (§5.3).
"""
from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from kratos import settings_store
from kratos.lifecycle.decide import Actor
from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.target_key import target_key

COMPONENT = "fleet_groups"
BUILTIN_ALL = "all"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
RESERVED = frozenset({BUILTIN_ALL, "none", "new", "list", "add", "remove", "delete", "show"})
EDIT_INTERFACES = ("tui", "cli")
MAX_MEMBERS = 200
MAX_NOTE = 200


class GroupError(ValueError):
    """A bad group name or member, a missing group, or no person behind the edit."""


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS machine_groups (
          name TEXT PRIMARY KEY,
          note TEXT NOT NULL DEFAULT '',
          created_at REAL NOT NULL, created_by TEXT NOT NULL, created_via TEXT NOT NULL,
          deleted_at REAL, deleted_by TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS group_members (
          group_name TEXT NOT NULL,
          target TEXT NOT NULL,                     -- target_key form
          added_at REAL NOT NULL, added_by TEXT NOT NULL, added_via TEXT NOT NULL,
          removed_at REAL, removed_by TEXT,
          PRIMARY KEY (group_name, target)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS group_members_target ON group_members(target)")
    # D.3 kept the asset record's groups as a JSON list on the row: carry those into the
    # membership table once, so nothing a person already typed is lost.
    try:
        rows = conn.execute("SELECT target, groups, updated_at, updated_by FROM assets").fetchall()
    except sqlite3.Error:
        rows = []
    now = time.time()
    for r in rows:
        try:
            names = [str(g) for g in json.loads(r[1] or "[]")]
        except (TypeError, ValueError):
            continue
        for raw in names:
            name = _normal_name(raw)
            if not NAME_RE.match(name) or name in RESERVED:
                continue
            who = str(r[3] or "upgrade")
            conn.execute("INSERT OR IGNORE INTO machine_groups (name, created_at, created_by, created_via) "
                         "VALUES (?, ?, ?, 'upgrade')", (name, r[2] or now, who))
            conn.execute("INSERT OR IGNORE INTO group_members (group_name, target, added_at, added_by, added_via) "
                         "VALUES (?, ?, ?, ?, 'upgrade')", (name, r[0], r[2] or now, who))


STEPS = (_step_1,)


def _db(data_dir: Path | str) -> Path:
    return Path(data_dir) / "kratos.db"


def _assets_ready(conn: sqlite3.Connection, path: Path) -> None:
    from kratos.assets import store as asset_store   # the assets table exists before step 1 reads it

    migrate_once(conn, path, asset_store.COMPONENT, asset_store.STEPS)


def connect(data_dir: Path | str) -> sqlite3.Connection:
    path = _db(data_dir)
    conn = connect_store(path)
    try:
        _assets_ready(conn, path)
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


@contextlib.contextmanager
def opened(data_dir: Path | str) -> Iterator[sqlite3.Connection]:
    conn = connect(data_dir)
    try:
        yield conn
    finally:
        conn.close()


def _normal_name(name: str) -> str:
    return str(name or "").strip().lstrip("@").strip().lower()


def check_name(name: str) -> str:
    n = _normal_name(name)
    if n == BUILTIN_ALL:
        raise GroupError("'all' is built in (every machine with an asset record) and can't be edited")
    if n in RESERVED:
        raise GroupError(f"{n!r} is a reserved word; pick another group name")
    if not NAME_RE.match(n):
        raise GroupError("a group name is 1-32 characters: lower-case letters, digits, '-' or '_', "
                         "starting with a letter or digit")
    return n


def _check_actor(actor: Actor, data_dir: Path | str | None = None, obj: str = "group edit") -> None:
    tool = settings_store.in_tool_call()
    if tool is not None:
        raise GroupError(f"agent tools may not change groups (tool {tool!r} tried)")
    if not isinstance(actor, Actor) or actor.interface not in EDIT_INTERFACES or not str(actor.user or "").strip():
        raise GroupError("a group edit needs a person: an Actor from the TUI or the CLI")
    from kratos import authz   # D.7: groups shape every user's scope -- the owner's, at the Kratos host

    try:
        authz.require(actor, authz.P.GROUPS_MANAGE, data_dir=data_dir, obj=obj)
    except authz.Denied as e:
        raise GroupError(str(e)) from None


def _who(actor: Actor) -> str:
    return str(actor.user)[:120]


# --- machine identity -------------------------------------------------------------


def _agent_hosts(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """sub-agent target id -> the session targets (addresses) linked to it."""
    out: dict[str, list[str]] = {}
    try:
        for host, tid in conn.execute("SELECT host, target_id FROM subagent_links ORDER BY host"):
            out.setdefault(str(tid), []).append(target_key(host))
    except sqlite3.Error:
        pass
    return out


def _agent_names(conn: sqlite3.Connection) -> dict[str, str]:
    """lower-cased sub-agent name / target id -> target id (never the token)."""
    out: dict[str, str] = {}
    try:
        for tid, name, hostname in conn.execute(
                "SELECT target_id, name, hostname FROM subagent_targets WHERE revoked_at IS NULL"):
            out[str(tid).lower()] = str(tid)
            for label in (name, hostname):
                if label:
                    out.setdefault(str(label).strip().lower(), str(tid))
    except sqlite3.Error:
        pass
    return out


def canonical_machine(conn: sqlite3.Connection, member: str) -> str:
    """What a typed member means: a sub-agent's name or id -> the address it is linked
    to (the machine Kratos investigates); anything else -> its target_key."""
    raw = str(member or "").strip()
    if not raw:
        raise GroupError("which machine?")
    if any(ord(ch) < 33 for ch in raw) or len(raw) > 255:
        raise GroupError(f"not a machine name: {raw[:40]!r}")
    tid = _agent_names(conn).get(raw.lower())
    if tid is not None:
        hosts = _agent_hosts(conn).get(tid) or []
        if hosts:
            return hosts[0]
    return target_key(raw)


def _agent_of(conn: sqlite3.Connection) -> dict[str, str]:
    """machine (target_key) -> the sub-agent target id it is linked to."""
    return {h: tid for tid, hosts in _agent_hosts(conn).items() for h in hosts}


# --- reads --------------------------------------------------------------------------


@dataclass(frozen=True)
class Group:
    name: str
    members: tuple[str, ...]
    note: str = ""
    builtin: bool = False
    created_by: str = ""


@dataclass
class Resolved:
    """A group (or a list of machines) as the machines a fleet run will cover."""

    name: str
    machines: list[str] = field(default_factory=list)      # target_key form, deduplicated, ordered
    duplicates: list[tuple[str, str]] = field(default_factory=list)   # (dropped entry, the machine it is)
    outside_scope: int = 0                                  # members the caller may not see (never named)

    @property
    def label(self) -> str:
        return f"@{self.name}" if self.name else ", ".join(self.machines)


def _members(conn: sqlite3.Connection, name: str) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT target FROM group_members WHERE group_name = ? AND removed_at IS NULL ORDER BY rowid",
        (name,))]


def _all_members(conn: sqlite3.Connection) -> list[str]:
    try:
        return [r[0] for r in conn.execute("SELECT target FROM assets ORDER BY target")]
    except sqlite3.Error:
        return []


def list_groups(data_dir: Path | str) -> list[Group]:
    """Every group: the built-in ``all`` first, then the named ones by name."""
    if not _db(data_dir).exists():
        return [Group(BUILTIN_ALL, (), "every machine with an asset record", True)]
    with opened(data_dir) as conn:
        out = [Group(BUILTIN_ALL, tuple(_all_members(conn)), "every machine with an asset record", True)]
        for r in conn.execute("SELECT name, note, created_by FROM machine_groups WHERE deleted_at IS NULL "
                              "ORDER BY name"):
            out.append(Group(r[0], tuple(_members(conn, r[0])), r[1] or "", False, r[2] or ""))
    return out


def outside_all(data_dir: Path | str, *, configured: str | None = None) -> list[str]:
    """Machines Kratos knows (the configured target, or data it holds) that are not in @all
    because they have no asset record yet -- so /groups can say why, instead of looking empty."""
    from kratos.assets.store import known_machines

    try:
        return [a.target for a in known_machines(Path(data_dir), configured=configured) if not a.set_up]
    except Exception:  # noqa: BLE001 -- an explanation only; never break the list
        return []


def get_group(data_dir: Path | str, name: str) -> Group | None:
    n = _normal_name(name)
    return next((g for g in list_groups(data_dir) if g.name == n), None)


def groups_of(data_dir: Path | str, target: str) -> tuple[str, ...]:
    """The named groups a machine is in (the asset record's ``groups`` field)."""
    if not _db(data_dir).exists():
        return ()
    with opened(data_dir) as conn:
        return tuple(r[0] for r in conn.execute(
            "SELECT m.group_name FROM group_members m JOIN machine_groups g ON g.name = m.group_name "
            "WHERE m.target = ? AND m.removed_at IS NULL AND g.deleted_at IS NULL ORDER BY m.rowid",
            (target_key(target),)))


def is_group_ref(text: str | None) -> bool:
    """True for '@name' -- how a target names a group everywhere (picker, /target, chat model)."""
    t = str(text or "").strip()
    return t.startswith("@") and len(t) > 1


def resolve(data_dir: Path | str, ref: str | Iterable[str], *, scope: Iterable[str] | None = None) -> Resolved:
    """``'@web'`` / ``'web'`` / ``'@all'`` or an explicit list of machines -> the machines
    a fleet run covers, deduplicated (a sub-agent reached under two names is one machine)
    and narrowed to ``scope`` (the caller's machines; None = everything). Raises
    GroupError for an unknown group or an empty result."""
    with opened(data_dir) as conn:
        if isinstance(ref, str):
            name = _normal_name(ref)
            if name == BUILTIN_ALL:
                entries = _all_members(conn)
            else:
                row = conn.execute("SELECT name FROM machine_groups WHERE name = ? AND deleted_at IS NULL",
                                   (name,)).fetchone()
                if row is None:
                    raise GroupError(f"no group named {name!r} (see /groups or `kratos groups list`)")
                entries = _members(conn, name)
        else:
            name = ""
            entries = [canonical_machine(conn, m) for m in ref]
        agent_of = _agent_of(conn)
    res = Resolved(name=name)
    # Scope first, then duplicates: a scoped caller must never see an out-of-scope name,
    # not even as "X is Y (counted once)", and an in-scope alias is never dropped in
    # favour of an out-of-scope twin (security review, D.2).
    allowed = {target_key(s) for s in scope} if scope is not None else None
    visible = [m for m in entries if allowed is None or m in allowed]
    hidden = [m for m in entries if allowed is not None and m not in allowed]
    seen_agents: dict[str, str] = {}
    for m in visible:
        if m in res.machines:
            res.duplicates.append((m, m))
            continue
        tid = agent_of.get(m)
        if tid is not None and tid in seen_agents:
            res.duplicates.append((m, seen_agents[tid]))
            continue
        if tid is not None:
            seen_agents[tid] = m
        res.machines.append(m)
    # Out of scope: counted as machines (two names of one box are one), never named; an
    # alias of a machine the caller can see is that machine, not one more outside it.
    hidden_ids: set[str] = set()
    for m in hidden:
        tid = agent_of.get(m)
        if tid is not None and tid in seen_agents:
            continue
        hidden_ids.add(f"agent:{tid}" if tid is not None else m)
    res.outside_scope = len(hidden_ids)
    if not res.machines:
        raise GroupError(f"no machines to ask about in {res.label or 'that group'}"
                         + (" that you may see" if res.outside_scope else ""))
    return res


# --- edits (people only) ------------------------------------------------------------


def _record_membership(conn: sqlite3.Connection, target: str, actor: Actor, old: list[str], new: list[str],
                       now: float) -> None:
    conn.execute("INSERT INTO asset_events (target, at, field, old_value, new_value, actor, interface) "
                 "VALUES (?, ?, 'groups', ?, ?, ?, ?)",
                 (target, now, json.dumps(old), json.dumps(new), _who(actor), actor.interface))


def _machine_groups(conn: sqlite3.Connection, target: str) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT m.group_name FROM group_members m JOIN machine_groups g ON g.name = m.group_name "
        "WHERE m.target = ? AND m.removed_at IS NULL AND g.deleted_at IS NULL ORDER BY m.rowid", (target,))]


def _ensure_asset_row(conn: sqlite3.Connection, target: str, actor: Actor, now: float) -> None:
    if conn.execute("SELECT 1 FROM assets WHERE target = ?", (target,)).fetchone() is None:
        conn.execute("INSERT INTO assets (target, created_at, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                     (target, now, now, _who(actor)))


def _sync_asset_groups(conn: sqlite3.Connection, target: str) -> None:
    """Keep the asset row's legacy JSON copy equal to the membership (old readers)."""
    conn.execute("UPDATE assets SET groups = ? WHERE target = ?", (json.dumps(_machine_groups(conn, target)), target))


def create_group(data_dir: Path | str, name: str, actor: Actor, *, members: Iterable[str] = (),
                 note: str = "") -> Group:
    _check_actor(actor, data_dir)
    n = check_name(name)
    note = " ".join(str(note or "").split())[:MAX_NOTE]
    now = time.time()
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT deleted_at FROM machine_groups WHERE name = ?", (n,)).fetchone()
            if row is not None and row[0] is None:
                raise GroupError(f"a group named {n!r} already exists")
            if row is None:
                conn.execute("INSERT INTO machine_groups (name, note, created_at, created_by, created_via) "
                             "VALUES (?, ?, ?, ?, ?)", (n, note, now, _who(actor), actor.interface))
            else:   # re-creating a deleted group: a fresh start, its old members stay removed
                conn.execute("UPDATE machine_groups SET note = ?, created_at = ?, created_by = ?, created_via = ?, "
                             "deleted_at = NULL, deleted_by = NULL WHERE name = ?",
                             (note, now, _who(actor), actor.interface, n))
                conn.execute("UPDATE group_members SET removed_at = COALESCE(removed_at, ?), "
                             "removed_by = COALESCE(removed_by, ?) WHERE group_name = ?", (now, _who(actor), n))
            _add(conn, n, members, actor, now)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    g = get_group(data_dir, n)
    assert g is not None
    return g


def _add(conn: sqlite3.Connection, group: str, members: Iterable[str], actor: Actor, now: float) -> list[str]:
    added: list[str] = []
    for m in members:
        target = canonical_machine(conn, m)
        current = conn.execute("SELECT removed_at FROM group_members WHERE group_name = ? AND target = ?",
                               (group, target)).fetchone()
        if current is not None and current[0] is None:
            continue
        count = conn.execute("SELECT COUNT(*) FROM group_members WHERE group_name = ? AND removed_at IS NULL",
                             (group,)).fetchone()[0]
        if count >= MAX_MEMBERS:
            raise GroupError(f"a group holds at most {MAX_MEMBERS} machines")
        _ensure_asset_row(conn, target, actor, now)
        old = _machine_groups(conn, target)
        if current is None:
            conn.execute("INSERT INTO group_members (group_name, target, added_at, added_by, added_via) "
                         "VALUES (?, ?, ?, ?, ?)", (group, target, now, _who(actor), actor.interface))
        else:
            conn.execute("UPDATE group_members SET removed_at = NULL, removed_by = NULL, added_at = ?, added_by = ?, "
                         "added_via = ? WHERE group_name = ? AND target = ?",
                         (now, _who(actor), actor.interface, group, target))
        _record_membership(conn, target, actor, old, _machine_groups(conn, target), now)
        _sync_asset_groups(conn, target)
        added.append(target)
    return added


def _require_group(conn: sqlite3.Connection, name: str) -> str:
    n = check_name(name)
    if conn.execute("SELECT 1 FROM machine_groups WHERE name = ? AND deleted_at IS NULL", (n,)).fetchone() is None:
        raise GroupError(f"no group named {n!r}")
    return n


def add_members(data_dir: Path | str, name: str, members: Iterable[str], actor: Actor) -> list[str]:
    """Add machines to a group; returns the ones newly added (target_key form)."""
    _check_actor(actor, data_dir)
    now = time.time()
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            added = _add(conn, _require_group(conn, name), members, actor, now)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return added


def remove_members(data_dir: Path | str, name: str, members: Iterable[str], actor: Actor) -> list[str]:
    _check_actor(actor, data_dir)
    now = time.time()
    removed: list[str] = []
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            n = _require_group(conn, name)
            for m in members:
                target = canonical_machine(conn, m)
                old = _machine_groups(conn, target)
                cur = conn.execute("UPDATE group_members SET removed_at = ?, removed_by = ? WHERE group_name = ? "
                                   "AND target = ? AND removed_at IS NULL", (now, _who(actor), n, target))
                if cur.rowcount:
                    _record_membership(conn, target, actor, old, _machine_groups(conn, target), now)
                    _sync_asset_groups(conn, target)
                    removed.append(target)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return removed


def delete_group(data_dir: Path | str, name: str, actor: Actor) -> None:
    """Mark a group deleted (its rows stay, with when and by whom); members lose it."""
    _check_actor(actor, data_dir)
    now = time.time()
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            n = _require_group(conn, name)
            members = _members(conn, n)
            olds = {t: _machine_groups(conn, t) for t in members}
            conn.execute("UPDATE machine_groups SET deleted_at = ?, deleted_by = ? WHERE name = ?", (now, _who(actor), n))
            for t in members:
                _record_membership(conn, t, actor, olds[t], _machine_groups(conn, t), now)
                _sync_asset_groups(conn, t)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise


def set_machine_groups_in(conn: sqlite3.Connection, target: str, names: list[str], actor: Actor, now: float) -> None:
    """The asset editor's "groups" field: make ``target``'s named groups exactly
    ``names`` (creating missing groups). Runs inside the caller's transaction."""
    key = target_key(target)
    wanted = [check_name(n) for n in names]
    old = _machine_groups(conn, key)
    for n in wanted:
        if conn.execute("SELECT 1 FROM machine_groups WHERE name = ? AND deleted_at IS NULL", (n,)).fetchone() is None:
            row = conn.execute("SELECT 1 FROM machine_groups WHERE name = ?", (n,)).fetchone()
            if row is None:
                conn.execute("INSERT INTO machine_groups (name, created_at, created_by, created_via) "
                             "VALUES (?, ?, ?, ?)", (n, now, _who(actor), actor.interface))
            else:
                conn.execute("UPDATE machine_groups SET deleted_at = NULL, deleted_by = NULL WHERE name = ?", (n,))
    for n in old:
        if n not in wanted:
            conn.execute("UPDATE group_members SET removed_at = ?, removed_by = ? WHERE group_name = ? AND target = ? "
                         "AND removed_at IS NULL", (now, _who(actor), n, key))
    for n in wanted:
        if n not in old:
            exists = conn.execute("SELECT 1 FROM group_members WHERE group_name = ? AND target = ?", (n, key)).fetchone()
            if exists:
                conn.execute("UPDATE group_members SET removed_at = NULL, removed_by = NULL, added_at = ?, added_by = ?, "
                             "added_via = ? WHERE group_name = ? AND target = ?",
                             (now, _who(actor), actor.interface, n, key))
            else:
                conn.execute("INSERT INTO group_members (group_name, target, added_at, added_by, added_via) "
                             "VALUES (?, ?, ?, ?, ?)", (n, key, now, _who(actor), actor.interface))
    conn.execute("UPDATE assets SET groups = ? WHERE target = ?", (json.dumps(_machine_groups(conn, key)), key))


def ensure_schema(conn: sqlite3.Connection, path: Path) -> None:
    """Bring the group tables up to date on a connection someone else opened."""
    migrate_once(conn, path, COMPONENT, STEPS)
