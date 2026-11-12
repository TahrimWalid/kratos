"""The evidence ledger: one hash-chained row per evidence file, written when the file is.

Each row holds the file's path (relative to the data folder), SHA-256, size, the time it
was written, what kind of evidence it is, the machine, the read and transport that
produced it, the run, and the Kratos build. ``entry_hash = sha256(prev_hash ‖ canonical
row)`` with the row's own sequence number inside the canonical form, so editing,
deleting, inserting or reordering a row breaks the chain from that row on.

Once per UTC day, before the first row of the day, a ``checkpoint`` row is added: the
chain head so far, signed with Kratos's Ed25519 signing key (``kratos/signing``). The
checkpoint is itself in the chain. Exports sign the head they were made at.

The honest limit: someone who can write ``kratos.db`` AND read the signing key can rebuild
a consistent chain. Without the key they can't re-sign the checkpoints; and a head sent
away in an export (or noted down) pins everything before it.

``record`` never raises: a file whose row couldn't be written is exported later with
"hash taken when exporting", which is true, instead of breaking the read that wrote it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.target_key import target_key

logger = logging.getLogger(__name__)

COMPONENT = "evidence"
GENESIS = "0" * 64
CHECKPOINT_CONTEXT = b"kratos-evidence-checkpoint\n"
CHUNK = 1 << 20

# Every folder (relative to the data folder) that holds evidence: what Kratos read from a
# machine, what it concluded from it, and the records of the runs. A file written into one
# of these is recorded here (tests/test_evidence_hooks.py scans the source for writers).
EVIDENCE_FOLDERS: tuple[str, ...] = (
    "scans", "logs", "context", "baseline", "integrity", "persistence", "live", "packages",
    "web_signals", "sshguess", "containers", "reports", "detect/results", "hunt/results", "hashdb/results",
    "compliance/facts", "compliance/results", "baseline_runs", "traces",
    "exports",
)


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_ledger (
          seq INTEGER PRIMARY KEY,         -- 1, 2, 3 ... with no gap
          kind TEXT NOT NULL,              -- file | checkpoint
          path TEXT,                       -- relative to the data folder, '/'-separated
          sha256 TEXT,                     -- of the file (a checkpoint: the head it signs)
          size INTEGER,
          written_at REAL NOT NULL,        -- epoch seconds UTC
          category TEXT,                   -- what kind of evidence (nmap_scan, findings_report, ...)
          machine TEXT,                    -- target_key; NULL for evidence about no one machine
          run_id TEXT, read TEXT, transport TEXT, build TEXT,
          detail TEXT,                     -- JSON (a checkpoint's signature)
          prev_hash TEXT NOT NULL,
          entry_hash TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS evidence_ledger_path ON evidence_ledger(path, seq)")
    conn.execute("CREATE INDEX IF NOT EXISTS evidence_ledger_machine ON evidence_ledger(machine, written_at)")
    for verb in ("UPDATE", "DELETE"):
        conn.execute(
            f"CREATE TRIGGER IF NOT EXISTS evidence_ledger_no_{verb.lower()} BEFORE {verb} ON evidence_ledger "
            "BEGIN SELECT RAISE(ABORT, 'evidence_ledger is append-only'); END")


STEPS = (_step_1,)


def db_path(data_dir: Path | str) -> Path:
    return Path(data_dir) / "kratos.db"


def connect(data_dir: Path | str) -> sqlite3.Connection:
    p = db_path(data_dir)
    conn = connect_store(p)
    try:
        migrate_once(conn, p, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    kind: str
    path: str | None
    sha256: str | None
    size: int | None
    written_at: float
    category: str | None
    machine: str | None
    run_id: str | None
    read: str | None
    transport: str | None
    build: str | None
    detail: dict[str, Any] | None
    prev_hash: str
    entry_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in _FIELDS} | {"prev_hash": self.prev_hash, "entry_hash": self.entry_hash}


_FIELDS = ("seq", "kind", "path", "sha256", "size", "written_at", "category", "machine", "run_id", "read",
           "transport", "build", "detail")


def canonical(entry: dict[str, Any]) -> bytes:
    """The bytes a row's hash covers: every field but the two hashes, sorted keys, the
    time as fixed six-decimal text (the same double always gives the same text)."""
    row = {k: entry.get(k) for k in _FIELDS}
    row["written_at"] = format(float(row["written_at"]), ".6f")
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def chain_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + b"\n" + canonical(entry)).hexdigest()


def _from_row(r: sqlite3.Row) -> LedgerEntry:
    detail = None
    if r["detail"]:
        try:
            detail = json.loads(r["detail"])
        except ValueError:
            detail = {"unreadable": r["detail"]}
    return LedgerEntry(r["seq"], r["kind"], r["path"], r["sha256"], r["size"], r["written_at"], r["category"],
                       r["machine"], r["run_id"], r["read"], r["transport"], r["build"], detail,
                       r["prev_hash"], r["entry_hash"])


def file_sha256(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def relative_path(path: Path | str, data_dir: Path | str) -> str | None:
    """`path` relative to the data folder ('/'-separated), or None if it isn't inside it."""
    try:
        rel = Path(os.path.realpath(path)).relative_to(os.path.realpath(data_dir))
    except ValueError:
        return None
    return PurePosixPath(*rel.parts).as_posix()


def is_evidence_path(rel: str) -> bool:
    return any(rel == f or rel.startswith(f + "/") for f in EVIDENCE_FOLDERS)


def _default_machine() -> str | None:
    from kratos import kratos_config, run_context

    pinned = kratos_config._pinned_target.get()
    if pinned:
        return target_key(pinned)
    ctx = run_context.current()
    if ctx is not None and ctx.target:
        return ctx.target
    return None


def _build() -> str | None:
    try:
        from kratos.utils.build_info import RUNNING_BUILD

        return RUNNING_BUILD
    except Exception:  # noqa: BLE001
        return None


def _day(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d")


def checkpoint_message(signs_seq: int, head: str) -> bytes:
    return CHECKPOINT_CONTEXT + f"{signs_seq}\n{head}\n".encode("ascii")


def _insert(conn: sqlite3.Connection, entry: dict[str, Any]) -> LedgerEntry:
    last = conn.execute("SELECT seq, entry_hash FROM evidence_ledger ORDER BY seq DESC LIMIT 1").fetchone()
    entry["seq"] = (last["seq"] + 1) if last else 1
    prev = last["entry_hash"] if last else GENESIS
    h = chain_hash(prev, entry)
    conn.execute(
        "INSERT INTO evidence_ledger (seq, kind, path, sha256, size, written_at, category, machine, run_id, read, "
        "transport, build, detail, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (entry["seq"], entry["kind"], entry.get("path"), entry.get("sha256"), entry.get("size"),
         float(entry["written_at"]), entry.get("category"), entry.get("machine"), entry.get("run_id"),
         entry.get("read"), entry.get("transport"), entry.get("build"),
         json.dumps(entry["detail"], sort_keys=True) if entry.get("detail") is not None else None, prev, h))
    row = conn.execute("SELECT * FROM evidence_ledger WHERE seq = ?", (entry["seq"],)).fetchone()
    return _from_row(row)


def _signed_checkpoint(data_dir: Path, signs_seq: int, head: str, now: float) -> dict[str, Any]:
    from kratos import signing

    key = signing.load_key(data_dir)
    assert key is not None
    sig = key.sign(checkpoint_message(signs_seq, head))
    return {"kind": "checkpoint", "path": None, "sha256": head, "size": None, "written_at": now,
            "category": "daily_checkpoint", "machine": None, "run_id": None, "read": None, "transport": None,
            "build": _build(),
            "detail": {"signs_seq": signs_seq, "head": head, "signature": base64.b64encode(sig).decode("ascii"),
                       "key": signing.fingerprint_of(key.public_key()),
                       "public_key": signing.public_key_openssh(data_dir)}}


def _maybe_checkpoint(conn: sqlite3.Connection, data_dir: Path, now: float) -> None:
    """At the first write of a new UTC day, sign the head the previous days left."""
    last = conn.execute("SELECT seq, entry_hash, kind, written_at FROM evidence_ledger "
                        "ORDER BY seq DESC LIMIT 1").fetchone()
    if last is None or last["kind"] == "checkpoint" or _day(last["written_at"]) == _day(now):
        return
    _insert(conn, _signed_checkpoint(data_dir, last["seq"], last["entry_hash"], now))


def checkpoint_now(data_dir: Path | str, *, now: float | None = None) -> LedgerEntry | None:
    """Sign the current head now (``kratos evidence checkpoint``); None when it is already signed."""
    t = now if now is not None else time.time()
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            last = conn.execute("SELECT seq, entry_hash, kind FROM evidence_ledger ORDER BY seq DESC LIMIT 1").fetchone()
            out = None
            if last is not None and last["kind"] != "checkpoint":
                out = _insert(conn, _signed_checkpoint(Path(data_dir), last["seq"], last["entry_hash"], t))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return out


def record(path: Path | str, *, data_dir: Path | str, category: str, machine: str | None = None,
           read: str | None = None, transport: str | None = None, run_id: str | None = None,
           detail: dict[str, Any] | None = None, now: float | None = None) -> LedgerEntry | None:
    """Record a just-written evidence file. Call it after the file is complete (after the
    rename, for a file written to a temp name first). Never raises."""
    try:
        return _record(Path(path), Path(data_dir), category=category, machine=machine, read=read,
                       transport=transport, run_id=run_id, detail=detail, now=now)
    except Exception as e:  # noqa: BLE001 -- the read that wrote the file must not fail over its receipt
        logger.warning("evidence ledger: %s not recorded (%s: %s); an export will hash it when exporting",
                       path, type(e).__name__, e)
        return None


def _record(path: Path, data_dir: Path, *, category: str, machine: str | None, read: str | None,
            transport: str | None, run_id: str | None, detail: dict[str, Any] | None,
            now: float | None) -> LedgerEntry | None:
    from kratos import run_context
    from kratos.evidence.transport import last_transport

    rel = relative_path(path, data_dir)
    if rel is None:
        raise ValueError(f"{path} is not inside the data folder {data_dir}")
    if not is_evidence_path(rel):
        raise ValueError(f"{rel} is not in an evidence folder ({', '.join(EVIDENCE_FOLDERS)})")
    digest, size = file_sha256(path)
    m = target_key(machine) if machine else _default_machine()
    t = now if now is not None else time.time()
    entry = {
        "kind": "file", "path": rel, "sha256": digest, "size": size, "written_at": t, "category": category,
        "machine": m or None, "run_id": run_id or run_context.current_run_id(), "read": read,
        "transport": transport or (last_transport(m) if m else None), "build": _build(),
        "detail": detail,
    }
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            _maybe_checkpoint(conn, data_dir, t)
            out = _insert(conn, entry)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return out


def entries(data_dir: Path | str, *, machine: str | None = None, start: float | None = None,
            end: float | None = None, upto_seq: int | None = None, kind: str | None = "file") -> list[LedgerEntry]:
    if not db_path(data_dir).exists():
        return []
    conn = connect(data_dir)
    try:
        sql, args = "SELECT * FROM evidence_ledger WHERE 1=1", []
        if kind:
            sql += " AND kind = ?"
            args.append(kind)
        if machine is not None:
            sql += " AND machine = ?"
            args.append(target_key(machine))
        if start is not None:
            sql += " AND written_at >= ?"
            args.append(start)
        if end is not None:
            sql += " AND written_at <= ?"
            args.append(end)
        if upto_seq is not None:
            sql += " AND seq <= ?"
            args.append(upto_seq)
        return [_from_row(r) for r in conn.execute(sql + " ORDER BY seq", args)]
    finally:
        conn.close()


def head(data_dir: Path | str) -> tuple[int, str]:
    """(seq, entry_hash) of the newest row; (0, GENESIS) for an empty ledger."""
    if not db_path(data_dir).exists():
        return 0, GENESIS
    conn = connect(data_dir)
    try:
        r = conn.execute("SELECT seq, entry_hash FROM evidence_ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return (r["seq"], r["entry_hash"]) if r else (0, GENESIS)
    finally:
        conn.close()


def latest_for_paths(data_dir: Path | str, rels: Iterable[str], *, upto_seq: int | None = None
                     ) -> dict[str, LedgerEntry]:
    """The newest file row of each path (a file replaced in place has several)."""
    wanted = set(rels)
    out: dict[str, LedgerEntry] = {}
    for e in entries(data_dir, upto_seq=upto_seq):
        if e.path in wanted:
            out[e.path] = e
    return out


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------
@dataclass
class ChainReport:
    rows: int = 0
    head_seq: int = 0
    head_hash: str = GENESIS
    checkpoints: int = 0
    first_written: float | None = None
    problems: list[str] = field(default_factory=list)       # the chain itself
    changed: list[str] = field(default_factory=list)        # files whose content no longer matches
    missing: list[str] = field(default_factory=list)        # files the ledger lists, gone from disk
    unrecorded: list[str] = field(default_factory=list)     # evidence files newer than the ledger, with no row

    @property
    def chain_ok(self) -> bool:
        return not self.problems

    @property
    def ok(self) -> bool:
        return not (self.problems or self.changed)


def _iter_rows(conn: sqlite3.Connection) -> Iterator[sqlite3.Row]:
    yield from conn.execute("SELECT * FROM evidence_ledger ORDER BY seq")


def _checkpoint_problem(e: LedgerEntry, by_seq: dict[int, str], public_keys: list[str]) -> str | None:
    from kratos import signing

    d = e.detail or {}
    try:
        signs, head_hash, sig = int(d["signs_seq"]), str(d["head"]), base64.b64decode(d["signature"])
    except (KeyError, TypeError, ValueError):
        return f"row {e.seq}: checkpoint without a readable signature"
    if by_seq.get(signs) != head_hash:
        return f"row {e.seq}: checkpoint signs row {signs} with a head that isn't that row's hash"
    msg = checkpoint_message(signs, head_hash)
    if not any(signing.verify(sig, msg, pk) for pk in public_keys):
        return f"row {e.seq}: checkpoint signature doesn't verify with Kratos's signing key (current or retired)"
    return None


def verify_chain(data_dir: Path | str, *, check_files: bool = True) -> ChainReport:
    """Walk the whole chain: contiguous sequence, every hash recomputed, every checkpoint's
    signature checked; then (``check_files``) each file's newest row against the file on disk."""
    from kratos import signing

    rep = ChainReport()
    if not db_path(data_dir).exists():
        return rep
    conn = connect(data_dir)
    try:
        rows = [_from_row(r) for r in _iter_rows(conn)]
    finally:
        conn.close()
    keys: list[str] = []
    try:
        if signing.load_key(data_dir, create=False) is not None:
            keys.append(signing.public_key_openssh(data_dir))
        keys += signing.retired_public_keys(data_dir)
    except Exception as e:  # noqa: BLE001
        rep.problems.append(f"signing key unreadable ({type(e).__name__}); checkpoints not checked")
    prev = GENESIS
    expected = 1
    by_seq: dict[int, str] = {}
    newest: dict[str, LedgerEntry] = {}
    for e in rows:
        rep.rows += 1
        if e.seq != expected:
            rep.problems.append(f"row {expected} is missing (next row is {e.seq}): a row was deleted or renumbered")
            expected = e.seq
        if e.prev_hash != prev:
            rep.problems.append(f"row {e.seq}: doesn't follow the row before it (a row before it was edited, "
                                "deleted, inserted or moved)")
        if chain_hash(e.prev_hash, e.as_dict()) != e.entry_hash:
            rep.problems.append(f"row {e.seq}: its content doesn't match its hash (the row was edited)")
        by_seq[e.seq] = e.entry_hash
        if e.kind == "checkpoint":
            rep.checkpoints += 1
            if keys:
                p = _checkpoint_problem(e, by_seq, keys)
                if p:
                    rep.problems.append(p)
        elif e.path:
            newest[e.path] = e
            if rep.first_written is None:
                rep.first_written = e.written_at
        prev = e.entry_hash
        expected += 1
    if rows:
        rep.head_seq, rep.head_hash = rows[-1].seq, rows[-1].entry_hash
    if check_files:
        root = Path(data_dir)
        for rel, e in newest.items():
            p = root / rel
            if not p.is_file():
                rep.missing.append(rel)
                continue
            try:
                digest, _size = file_sha256(p)
            except OSError:
                rep.missing.append(rel)
                continue
            if digest != e.sha256:
                rep.changed.append(rel)
        if rep.first_written is not None:
            rep.unrecorded = unrecorded_files(data_dir, since=rep.first_written, known=set(newest))
    return rep


def evidence_files(data_dir: Path | str) -> Iterator[tuple[str, Path]]:
    """Every file in the evidence folders: (relative path, path). Temp and partial files skipped."""
    root = Path(data_dir)
    for folder in EVIDENCE_FOLDERS:
        base = root / folder
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p.name.startswith(".") or p.suffix in (".tmp", ".partial"):
                continue
            rel = relative_path(p, root)
            if rel and (folder != "exports" or p.name == "manifest.json"):
                yield rel, p


def unrecorded_files(data_dir: Path | str, *, since: float, known: set[str]) -> list[str]:
    """Evidence files changed after the ledger began that have no row -- a writer that
    doesn't call ``record`` (the runtime twin of the source-scan test). A 2 s allowance
    for a file written just before its first row."""
    out = []
    for rel, p in evidence_files(data_dir):
        if rel in known:
            continue
        try:
            if p.stat().st_mtime >= since + 2:
                out.append(rel)
        except OSError:
            continue
    return out
