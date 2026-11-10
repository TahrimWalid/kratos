"""`backup_runs`: one row per backup made, checked, drilled, restored or pruned (D.8 §5.1).

Never a secret: recipients are stored as fingerprints, errors are cleaned of anything
shaped like an age identity or a known secret before they are written.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.utils.timeutil import utc_now_iso

COMPONENT = "backup"
KINDS = ("create", "verify", "drill", "restore", "prune")
OUTCOMES = ("running", "ok", "failed", "refused")
_SECRET_RE = re.compile(r"AGE-SECRET-KEY-(?:PQ-)?1[0-9A-Z]+", re.IGNORECASE)


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS backup_runs (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,            -- create | verify | drill | restore | prune
            started_at TEXT NOT NULL,      -- ISO UTC
            ended_at TEXT,
            outcome TEXT NOT NULL,         -- running | ok | failed | refused
            file TEXT,                     -- the backup file (absolute path)
            sha256 TEXT,                   -- of the encrypted file
            size INTEGER,
            lock TEXT,                     -- recipients | passphrase
            recipients TEXT,               -- JSON: fingerprints of the recipients (never a secret)
            categories TEXT,               -- JSON: included / left out, with reasons
            actor TEXT NOT NULL,           -- the person (OS login or Kratos user)
            interface TEXT,                -- cli | tui | schedule
            user_id TEXT,
            scheduled INTEGER NOT NULL DEFAULT 0,
            same_disk INTEGER,             -- 1 when the backup sits on the data's own disk
            copies TEXT,                   -- JSON: each copy target and whether it verified
            detail TEXT,                   -- JSON: stage timings, counts, notes
            error TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_runs_kind ON backup_runs(kind, outcome, started_at)")


STEPS = (_step_1,)


def _db(data_dir: Path) -> sqlite3.Connection:
    path = Path(data_dir) / "kratos.db"
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


def clean_error(text: str | None) -> str | None:
    if text is None:
        return None
    from kratos.privacy import secrets as _secrets

    text = _SECRET_RE.sub("[REDACTED]", str(text))
    try:
        text = _secrets.redact(text)[0]
    except Exception:  # noqa: BLE001 -- cleaning must never stop the record
        pass
    return text[:2000]


def _json(value: Any) -> str | None:
    return None if value is None else json.dumps(value, sort_keys=True, default=str)


def start(data_dir: Path, kind: str, actor: Any, *, file: str | None = None, scheduled: bool = False,
          lock: str | None = None) -> int:
    if kind not in KINDS:
        raise ValueError(f"unknown backup run kind {kind!r}")
    conn = _db(data_dir)
    try:
        cur = conn.execute(
            "INSERT INTO backup_runs (kind, started_at, outcome, file, lock, actor, interface, user_id, scheduled) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (kind, utc_now_iso(), "running", file, lock, str(getattr(actor, "user", actor) or "?")[:200],
             getattr(actor, "interface", None), getattr(actor, "user_id", None), 1 if scheduled else 0))
        return int(cur.lastrowid)
    finally:
        conn.close()


def finish(data_dir: Path, run_id: int, outcome: str, *, file: str | None = None, sha256: str | None = None,
           size: int | None = None, lock: str | None = None, recipients: list[str] | None = None,
           categories: Any = None, same_disk: bool | None = None, copies: Any = None, detail: Any = None,
           error: str | None = None) -> None:
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown outcome {outcome!r}")
    conn = _db(data_dir)
    try:
        conn.execute(
            "UPDATE backup_runs SET ended_at = ?, outcome = ?, file = COALESCE(?, file), sha256 = ?, size = ?, "
            "lock = COALESCE(?, lock), recipients = ?, categories = ?, same_disk = ?, copies = ?, detail = ?, "
            "error = ? WHERE id = ?",
            (utc_now_iso(), outcome, file, sha256, size, lock, _json(recipients), _json(categories),
             None if same_disk is None else int(bool(same_disk)), _json(copies), _json(detail), clean_error(error),
             run_id))
    finally:
        conn.close()


def record(data_dir: Path, kind: str, actor: Any, outcome: str, **fields: Any) -> int:
    """A run that starts and ends at once (a refused restore, a prune)."""
    scheduled = bool(fields.pop("scheduled", False))
    run_id = start(data_dir, kind, actor, file=fields.get("file"), scheduled=scheduled, lock=fields.get("lock"))
    finish(data_dir, run_id, outcome, **fields)
    return run_id


def _row(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    for k in ("recipients", "categories", "copies", "detail"):
        if d.get(k):
            try:
                d[k] = json.loads(d[k])
            except ValueError:
                pass
    return d


def runs(data_dir: Path, *, kind: str | None = None, outcome: str | None = None, limit: int = 50) -> list[dict]:
    if not (Path(data_dir) / "kratos.db").exists():
        return []
    conn = _db(data_dir)
    try:
        q, args = "SELECT * FROM backup_runs", []
        conds = []
        if kind:
            conds.append("kind = ?")
            args.append(kind)
        if outcome:
            conds.append("outcome = ?")
            args.append(outcome)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        return [_row(r) for r in conn.execute(q, args)]
    finally:
        conn.close()


def last(data_dir: Path, kind: str, *, outcome: str = "ok") -> dict[str, Any] | None:
    rows = runs(data_dir, kind=kind, outcome=outcome, limit=1)
    return rows[0] if rows else None
