"""Kratos's FIRST look at a machine's persistence locations, in kratos.db.

"New" in A.1 means "not in the first inventory Kratos took of this machine"
(A.1 §3.4) -- so that first inventory has to be kept. One row per machine, the
items reduced to an identity each (path -> content fingerprint), plus the
authorized keys, the loaded modules, the areas the inventory covered and the
locations that could not be read at the time.

The baseline is never updated with items a later run found: that is what a
person's decision on the finding is for (A.1 §3.4, there is no
baseline-editing UI). It only ever GROWS in coverage -- when this Kratos knows
an area the baseline does not (a newer version), or when a location that was
unreadable then can be read now (an SSH read as a user, then the machine's
sub-agent as root), the items there are merged in as a first look, so a wider
read does not report a whole machine as new.
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

COMPONENT = "persist"


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS persistence_baseline (
          target TEXT PRIMARY KEY,
          taken_at REAL NOT NULL,
          areas TEXT NOT NULL,            -- JSON list: the areas this baseline covers
          gaps TEXT NOT NULL,             -- JSON list: locations that could not be read then
          inventory BLOB NOT NULL,        -- zlib(JSON): {items: {path: fingerprint}, keys: [...], modules: [...]}
          hash TEXT NOT NULL,             -- sha256 of that JSON
          reader_uid INTEGER,
          via TEXT,
          item_count INTEGER NOT NULL,
          updated_at REAL NOT NULL,
          run_id TEXT
        )
        """
    )


STEPS = (_step_1,)


def _connect(data_dir: Path) -> sqlite3.Connection:
    path = Path(data_dir) / "kratos.db"
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


@contextlib.contextmanager
def opened(data_dir: Path) -> Iterator[sqlite3.Connection]:
    conn = _connect(data_dir)
    try:
        yield conn
    finally:
        conn.close()


@dataclass(frozen=True)
class Baseline:
    target: str
    taken_at: float
    areas: tuple[str, ...]
    gaps: tuple[str, ...]
    items: dict[str, str] = field(default_factory=dict)       # path -> fingerprint
    keys: tuple[str, ...] = ()                                # "user:SHA256:..." identities
    modules: tuple[str, ...] = ()
    reader_uid: int | None = None
    via: str | None = None
    item_count: int = 0

    def covers_area(self, area: str) -> bool:
        return area in self.areas

    def under_a_gap(self, path: str) -> bool:
        """True when `path` sits under a location this baseline could not read."""
        return any(path == g or path.startswith(g.rstrip("/") + "/") for g in self.gaps)


def fingerprint_of(item: dict[str, Any]) -> str:
    """The identity of one inventory item: its content where we have it, else its
    link target, else just the fact that it was there."""
    if item.get("sha256"):
        return f"sha256:{item['sha256']}"
    if item.get("link"):
        return f"link:{item['link']}"
    lines = item.get("lines") or []
    if lines:
        digest = hashlib.sha256("\n".join(str(l.get("text") or "") for l in lines).encode()).hexdigest()
        return f"lines:{digest}"
    return "listed"


def key_identity(key: dict[str, Any]) -> str:
    """`user:fingerprint` (A.1 §3.5); an unparsable line falls back to its place."""
    user = str(key.get("user") or "?")
    fp = key.get("fingerprint")
    return f"{user}:{fp}" if fp else f"{user}:{key.get('path')}#{key.get('line')}"


def reduce_inventory(inv: dict[str, Any]) -> dict[str, Any]:
    """The inventory as a baseline: identities only, never file contents."""
    items = {path: fingerprint_of(it) for path, it in (inv.get("items") or {}).items()}
    keys = sorted({key_identity(k) for k in inv.get("keys") or []})
    modules = sorted((inv.get("modules") or {}).keys())
    return {"items": items, "keys": keys, "modules": modules}


def _hash(payload: dict[str, Any]) -> tuple[bytes, str]:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return zlib.compress(text.encode("utf-8"), 6), hashlib.sha256(text.encode("utf-8")).hexdigest()


def gap_paths(inv: dict[str, Any]) -> list[str]:
    out = {str(g.get("path") or "") for g in inv.get("gaps") or [] if g.get("path")}
    return sorted(p for p in out if p)


def load(data_dir: Path, target: str) -> Baseline | None:
    with opened(data_dir) as conn:
        row = conn.execute(
            "SELECT target, taken_at, areas, gaps, inventory, reader_uid, via, item_count "
            "FROM persistence_baseline WHERE target = ?", (target_key(target),)).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(zlib.decompress(row[4]).decode("utf-8"))
        areas = tuple(json.loads(row[2]))
        gaps = tuple(json.loads(row[3]))
    except (ValueError, zlib.error, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    items = payload.get("items") if isinstance(payload.get("items"), dict) else {}
    return Baseline(target=row[0], taken_at=float(row[1]), areas=areas, gaps=gaps,
                    items={str(k): str(v) for k, v in items.items()},
                    keys=tuple(str(k) for k in payload.get("keys") or ()),
                    modules=tuple(str(m) for m in payload.get("modules") or ()),
                    reader_uid=row[5], via=row[6], item_count=int(row[7] or 0))


def save_first_look(data_dir: Path, target: str, inv: dict[str, Any], *, areas: tuple[str, ...],
                    now: float | None = None, run_id: str | None = None) -> Baseline:
    """Record this inventory as Kratos's first look at the machine."""
    payload = reduce_inventory(inv)
    blob, digest = _hash(payload)
    when = time.time() if now is None else now
    tk = target_key(target)
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO persistence_baseline (target, taken_at, areas, gaps, inventory, hash, reader_uid, via, "
                "item_count, updated_at, run_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(target) DO UPDATE SET taken_at = excluded.taken_at, areas = excluded.areas, "
                "gaps = excluded.gaps, inventory = excluded.inventory, hash = excluded.hash, "
                "reader_uid = excluded.reader_uid, via = excluded.via, item_count = excluded.item_count, "
                "updated_at = excluded.updated_at, run_id = excluded.run_id",
                (tk, when, json.dumps(list(areas)), json.dumps(gap_paths(inv)), blob, digest,
                 inv.get("reader_uid"), inv.get("via"), len(payload["items"]), when, run_id))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    loaded = load(data_dir, target)
    assert loaded is not None
    return loaded


def extend_coverage(data_dir: Path, target: str, base: Baseline, inv: dict[str, Any], *,
                    new_areas: tuple[str, ...], first_look_paths: tuple[str, ...],
                    now: float | None = None) -> Baseline:
    """Grow an existing baseline's COVERAGE only: the areas this Kratos knows and
    the baseline does not, and the items under locations the baseline could not
    read. Nothing already covered is replaced, so a real change stays reported."""
    if not new_areas and not first_look_paths:
        return base
    items = dict(base.items)
    keys = set(base.keys)
    modules = set(base.modules)
    for path in first_look_paths:
        it = (inv.get("items") or {}).get(path)
        if it is not None:
            items.setdefault(path, fingerprint_of(it))
    if new_areas:
        for path, it in (inv.get("items") or {}).items():
            if str(it.get("area") or "") in new_areas:
                items.setdefault(path, fingerprint_of(it))
        if "ssh" in new_areas:
            keys |= {key_identity(k) for k in inv.get("keys") or []}
        if "kernel" in new_areas:
            modules |= set((inv.get("modules") or {}).keys())
    for k in inv.get("keys") or []:
        if base.under_a_gap(str(k.get("path") or "")):
            keys.add(key_identity(k))
    payload = {"items": items, "keys": sorted(keys), "modules": sorted(modules)}
    blob, digest = _hash(payload)
    areas = tuple(sorted(set(base.areas) | set(new_areas)))
    # A location that can be read now is no longer a gap of this baseline.
    still_gaps = sorted(set(base.gaps) & set(gap_paths(inv)))
    when = time.time() if now is None else now
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("UPDATE persistence_baseline SET areas = ?, gaps = ?, inventory = ?, hash = ?, "
                         "item_count = ?, updated_at = ? WHERE target = ?",
                         (json.dumps(list(areas)), json.dumps(still_gaps), blob, digest, len(items), when,
                          target_key(target)))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    loaded = load(data_dir, target)
    return loaded if loaded is not None else base
