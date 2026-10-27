"""The ``pkg_inventory`` table in kratos.db: each machine's installed packages.

One row per distinct package set per machine. A check that finds exactly the
same packages as the newest row only moves that row's ``last_seen_at`` -- so the
table grows when software is installed or upgraded, not every time a check
runs. The package list is stored compressed; it never leaves the Kratos machine.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.target_key import target_key

COMPONENT = "pkg_inventory"


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pkg_inventory (
          id INTEGER PRIMARY KEY,
          target TEXT NOT NULL,           -- target_key of the machine
          taken_at REAL NOT NULL,         -- when this package set was first seen
          last_seen_at REAL NOT NULL,     -- the newest check that found exactly this set
          family TEXT,                    -- deb | rpm | apk
          os_id TEXT,
          os_version TEXT,
          selector TEXT,                  -- the release's advisory data (kratos.pkgvuln.ecosystems), or NULL
          packages_json BLOB NOT NULL,    -- zlib(JSON list of packages)
          hash TEXT NOT NULL,             -- sha256 of the canonical package list + os + kernel facts
          package_count INTEGER NOT NULL,
          system_json TEXT NOT NULL,      -- os-release, running kernel, kernel trees, reboot-required
          via TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS pkg_inventory_target ON pkg_inventory (target, last_seen_at)")


def _step_2(conn: sqlite3.Connection) -> None:
    # How the read went and which packages came from outside the distribution, so a
    # stored list can be matched again later exactly as it was the first time (not
    # part of the hash: a repository list refresh doesn't make a new package set).
    cols = {r[1] for r in conn.execute("PRAGMA table_info(pkg_inventory)")}
    if "read_json" not in cols:
        conn.execute("ALTER TABLE pkg_inventory ADD COLUMN read_json TEXT")


STEPS = (_step_1, _step_2)


@contextlib.contextmanager
def opened(data_dir: Path) -> Iterator[sqlite3.Connection]:
    path = Path(data_dir) / "kratos.db"
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
        yield conn
    finally:
        conn.close()


@dataclass(frozen=True)
class Inventory:
    id: int
    target: str
    taken_at: float
    last_seen_at: float
    family: str
    os_id: str
    os_version: str
    selector: str | None
    packages: list[dict[str, Any]]
    system: dict[str, Any]
    hash: str
    via: str
    read: dict[str, Any] = field(default_factory=dict)   # {} for a list stored before read_json existed


def _system(inv: dict[str, Any]) -> dict[str, Any]:
    return {"os": inv.get("os") or {}, "running_kernel": inv.get("running_kernel") or "",
            "kernel_trees": sorted(inv.get("kernel_trees") or []),
            "reboot_required": bool(inv.get("reboot_required")),
            "reboot_required_pkgs": sorted(inv.get("reboot_required_pkgs") or [])}


def inventory_hash(packages: list[dict[str, Any]], system: dict[str, Any]) -> str:
    canon = json.dumps({"p": sorted(packages, key=lambda p: (p.get("manager"), p.get("name"), p.get("arch"))),
                        "s": system}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


def save(data_dir: Path, target: str, inv: dict[str, Any], *, family: str, selector: str | None,
         now: float | None = None, read: dict[str, Any] | None = None) -> Inventory:
    """Record a fresh inventory. Returns the stored row (new, or the unchanged one
    whose last_seen_at moved). `read`: how this read went (complete, origins), kept
    with the row -- the newest read's, for an unchanged set."""
    when = time.time() if now is None else now
    key = target_key(target)
    packages = list(inv.get("packages") or [])
    system = _system(inv)
    digest = inventory_hash(packages, system)
    os_info = system["os"]
    read_json = json.dumps(read, separators=(",", ":"), default=str) if read is not None else None
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT id, hash FROM pkg_inventory WHERE target = ? ORDER BY last_seen_at DESC, id DESC "
                               "LIMIT 1", (key,)).fetchone()
            if row is not None and row["hash"] == digest:
                conn.execute("UPDATE pkg_inventory SET last_seen_at = ?, via = ?, selector = ?, read_json = ? "
                             "WHERE id = ?", (when, inv.get("via") or "ssh", selector, read_json, row["id"]))
                rid = int(row["id"])
            else:
                blob = zlib.compress(json.dumps(packages, separators=(",", ":")).encode(), 6)
                cur = conn.execute(
                    "INSERT INTO pkg_inventory (target, taken_at, last_seen_at, family, os_id, os_version, selector, "
                    "packages_json, hash, package_count, system_json, via, read_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (key, when, when, family, str(os_info.get("ID") or ""), str(os_info.get("VERSION_ID") or ""),
                     selector, blob, digest, len(packages), json.dumps(system), inv.get("via") or "ssh", read_json))
                rid = int(cur.lastrowid)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    got = get(data_dir, rid)
    assert got is not None
    return got


def _row(r: sqlite3.Row) -> Inventory:
    return Inventory(int(r["id"]), r["target"], float(r["taken_at"]), float(r["last_seen_at"]), r["family"] or "",
                     r["os_id"] or "", r["os_version"] or "", r["selector"],
                     json.loads(zlib.decompress(r["packages_json"])), json.loads(r["system_json"] or "{}"),
                     r["hash"], r["via"] or "", _read_of(r))


def _read_of(r: sqlite3.Row) -> dict[str, Any]:
    try:
        got = json.loads(r["read_json"] or "{}")
    except (IndexError, TypeError, ValueError):
        return {}
    return got if isinstance(got, dict) else {}


def get(data_dir: Path, inventory_id: int) -> Inventory | None:
    with opened(data_dir) as conn:
        r = conn.execute("SELECT * FROM pkg_inventory WHERE id = ?", (int(inventory_id),)).fetchone()
    return _row(r) if r is not None else None


def latest(data_dir: Path, target: str) -> Inventory | None:
    with opened(data_dir) as conn:
        r = conn.execute("SELECT * FROM pkg_inventory WHERE target = ? ORDER BY last_seen_at DESC, id DESC LIMIT 1",
                         (target_key(target),)).fetchone()
    return _row(r) if r is not None else None


def machines(data_dir: Path) -> list[str]:
    """Every machine with a stored package list, newest list first."""
    if not (Path(data_dir) / "kratos.db").exists():
        return []
    with opened(data_dir) as conn:
        return [r[0] for r in conn.execute("SELECT target FROM pkg_inventory GROUP BY target "
                                           "ORDER BY MAX(last_seen_at) DESC")]


def known_selectors(data_dir: Path) -> set[str]:
    """Every release a package inventory has been taken from (so `kratos vulndb-update`
    knows which data to download)."""
    if not (Path(data_dir) / "kratos.db").exists():
        return set()
    with opened(data_dir) as conn:
        return {r[0] for r in conn.execute("SELECT DISTINCT selector FROM pkg_inventory WHERE selector IS NOT NULL")}


def counts(data_dir: Path) -> dict[str, int]:
    with opened(data_dir) as conn:
        r = conn.execute("SELECT COUNT(*), COUNT(DISTINCT target) FROM pkg_inventory").fetchone()
    return {"rows": int(r[0]), "machines": int(r[1])}
