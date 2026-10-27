"""The hunt's search index over stored events: `host_event_terms` (C.3 §3.3).

One row per (machine, kind, value) an event carries in a TYPED field -- addresses,
account names, SHA-256 hashes, program names, paths, domains parsed from URLs --
pointing at the event's row in `host_events`. A hunt for an address or an account
reads this index instead of scanning messages.

- Filled at insert: `EventStore.add` calls `add_terms` inside its own transaction, so
  an event is never stored without its terms (one place adds events; a source scan
  test keeps it that way).
- Events stored before this index existed are filled in by `backfill`: resumable
  (progress is kept in `host_event_terms_state`, one batch per transaction) and
  idempotent (`INSERT OR IGNORE`). A hunt runs it for a few seconds first; `kratos
  hunt index` finishes it.
- Stale rows can't answer: a term row only counts when the event row it names still
  exists with the same machine and time (a row id reused after a person deleted
  events doesn't match). `kratos data prune --category host_events` removes the
  terms of the events it removes, in the same transaction.

Addresses are stored as `4`/`6` + the address's hex digits, so a CIDR network is one
range scan; every other value as itself (domains lower-case).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import posixpath
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit

from kratos.storage.migrations import migrate_once

logger = logging.getLogger(__name__)
_HOST = re.compile(r"^[a-z0-9_.:-]+$")

COMPONENT = "hunt_terms"
# kind codes in the table (short: there are a few rows per stored event)
CODES = {"ip": "i", "account": "a", "sha256": "h", "program": "g", "path": "p", "domain": "d"}
KINDS_BY_CODE = {v: k for k, v in CODES.items()}
MAX_VALUE = 1024             # a longer value is not indexed (a hunt still finds it by text search)
MAX_TERMS_PER_EVENT = 64
BACKFILL_BATCH = 5000

# ECS field -> the hunt kind it holds
IP_FIELDS = ("source.ip", "destination.ip", "related.ip")
ACCOUNT_FIELDS = ("user.name", "user.effective.name", "user.target.name", "related.user")
HASH_FIELDS = ("file.hash.sha256",)
PROGRAM_FIELDS = ("process.name",)
PATH_FIELDS = ("process.executable", "file.path", "kratos.audit.paths", "kratos.audit.created_paths")
URL_FIELDS = ("url.original",)
# Free text an address may be written in without a parser putting it in a typed field
# ("Connection closed by invalid user x 203.0.113.9 port 22"): validated, at most a few an event.
TEXT_FIELDS = ("message", "event.original", "process.command_line")
MAX_TEXT_ADDRESSES = 8
_V4_IN_TEXT = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
# not followed by "." or a hex digit: in "::ffff:203.0.113.9" only the IPv4 part counts (the
# IPv4 pattern takes it), never the fragment "::ffff:203"
_V6_IN_TEXT = re.compile(r"(?<![0-9A-Fa-f:])(?=[0-9A-Fa-f:]*::?[0-9A-Fa-f])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:.])")
FIELDS_BY_KIND = {"ip": IP_FIELDS, "account": ACCOUNT_FIELDS, "sha256": HASH_FIELDS,
                  "program": PROGRAM_FIELDS + ("process.executable",), "path": PATH_FIELDS, "domain": URL_FIELDS}


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS host_event_terms (
          target TEXT NOT NULL,          -- target_key, as in host_events
          kind TEXT NOT NULL,            -- CODES
          value TEXT NOT NULL,
          ts REAL NOT NULL,              -- the event's @timestamp (epoch UTC)
          row INTEGER NOT NULL,          -- host_events.id
          PRIMARY KEY (target, kind, value, ts, row)
        ) WITHOUT ROWID
        """
    )
    conn.execute("CREATE TABLE IF NOT EXISTS host_event_terms_state (name TEXT PRIMARY KEY, through INTEGER NOT "
                 "NULL, upto INTEGER NOT NULL, started_at REAL, done_at REAL)")
    exists = conn.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='host_events'").fetchone()
    upto = int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM host_events").fetchone()[0]) if exists else 0
    # events stored from now on are indexed as they are added; the ones already stored wait for the backfill
    conn.execute("INSERT OR IGNORE INTO host_event_terms_state (name, through, upto, started_at, done_at) "
                 "VALUES ('backfill', 0, ?, ?, ?)", (upto, time.time(), time.time() if upto == 0 else None))


def _step_2(conn: sqlite3.Connection) -> None:
    """Addresses written only in the log text are indexed too: index the stored events again
    (INSERT OR IGNORE keeps what is there and adds what is new)."""
    exists = conn.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='host_events'").fetchone()
    upto = int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM host_events").fetchone()[0]) if exists else 0
    conn.execute("UPDATE host_event_terms_state SET through = 0, upto = ?, started_at = ?, done_at = ? "
                 "WHERE name = 'backfill'", (upto, time.time(), time.time() if upto == 0 else None))


def _step_3(conn: sqlite3.Connection) -> None:
    """IPv4-mapped addresses are indexed as the IPv4 address they carry (Phase C audit):
    index the stored events again (INSERT OR IGNORE keeps what is there)."""
    _step_2(conn)


STEPS = (_step_1, _step_2, _step_3)


def migrate(conn: sqlite3.Connection, db_path: Path) -> None:
    migrate_once(conn, db_path, COMPONENT, STEPS)


# --------------------------------------------------------------------------- extraction
def address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """`value` as an address, an IPv4-mapped IPv6 one as the IPv4 address it carries; None if not one."""
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return addr.ipv4_mapped if addr.version == 6 and addr.ipv4_mapped is not None else addr


def ip_key(value: str) -> str | None:
    """`4`/`6` + the address's hex digits, or None for something that isn't an address.
    An IPv4-mapped IPv6 address (`::ffff:203.0.113.9`, written by servers on dual-stack
    sockets) is the IPv4 address it carries."""
    addr = address(value)
    if addr is None:
        return None
    return f"{addr.version}{int(addr):0{8 if addr.version == 4 else 32}x}"


def ip_range(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[str, str]:
    width = 8 if network.version == 4 else 32
    return (f"{network.version}{int(network.network_address):0{width}x}",
            f"{network.version}{int(network.broadcast_address):0{width}x}")


def ip_from_key(key: str) -> str:
    version, digits = key[0], key[1:]
    return str(ipaddress.ip_address(int(digits, 16)) if version == "4"
               else ipaddress.IPv6Address(int(digits, 16)))


def _get(doc: dict[str, Any], name: str) -> Any:
    node: Any = doc
    for part in name.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _values(doc: dict[str, Any], name: str) -> list[str]:
    v = _get(doc, name)
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if isinstance(x, (str, int))]
    return [str(v)] if isinstance(v, (str, int)) else []


def domain_of_url(url: str) -> str | None:
    """The host part of a URL (lower-case), or None (no host, or an address)."""
    text = str(url or "").strip()
    if "://" not in text[:16]:
        text = "//" + text if not text.startswith("/") else text
    try:
        host = urlsplit(text).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".").lower()
    if not host or len(host) > 253 or not _HOST.match(host):
        return None
    return host


def terms_of_doc(doc: dict[str, Any]) -> set[tuple[str, str]]:
    """{(code, value)} of one event's ECS document."""
    out: set[tuple[str, str]] = set()

    def add(kind: str, value: str | None) -> None:
        if value and len(value) <= MAX_VALUE and len(out) < MAX_TERMS_PER_EVENT:
            out.add((CODES[kind], value))

    for f in IP_FIELDS:
        for v in _values(doc, f):
            add("ip", ip_key(v))
    for f in ACCOUNT_FIELDS:
        for v in _values(doc, f):
            add("account", v.strip() or None)
    for v in _values(doc, "file.hash.sha256"):
        v = v.strip().lower()
        add("sha256", v if len(v) == 64 else None)
    for v in _values(doc, "process.name"):
        add("program", v.strip() or None)
    for v in _values(doc, "process.executable"):
        add("program", posixpath.basename(v.strip()) or None)
    for f in PATH_FIELDS:
        for v in _values(doc, f):
            v = v.strip()
            add("path", (v.rstrip("/") or "/") if v.startswith("/") else None)
    found = 0
    for f in TEXT_FIELDS:
        for text in _values(doc, f):
            for m in list(_V4_IN_TEXT.finditer(text)) + list(_V6_IN_TEXT.finditer(text)):
                if found >= MAX_TEXT_ADDRESSES:
                    break
                key = ip_key(m.group(0))
                if key is not None:
                    found += 1
                    add("ip", key)
    for v in _values(doc, "url.original"):
        host = domain_of_url(v)
        if host is None:
            continue
        key = ip_key(host.strip("[]"))
        if key is not None:
            add("ip", key)
        else:
            add("domain", host)
    return out


# --------------------------------------------------------------------------- writing
def add_terms(conn: sqlite3.Connection, rows: Iterable[tuple[int, str, float, dict[str, Any]]]) -> int:
    """Index events (row id, target, ts, ECS doc) inside the caller's transaction."""
    batch = [(target, code, value, ts, row_id) for row_id, target, ts, doc in rows
             for code, value in terms_of_doc(doc)]
    if batch:
        conn.executemany("INSERT OR IGNORE INTO host_event_terms (target, kind, value, ts, row) VALUES (?,?,?,?,?)",
                         batch)
    return len(batch)


def state(conn: sqlite3.Connection) -> dict[str, Any]:
    r = conn.execute("SELECT through, upto, started_at, done_at FROM host_event_terms_state "
                     "WHERE name = 'backfill'").fetchone()
    if r is None:
        return {"through": 0, "upto": 0, "done": True, "remaining": 0}
    remaining = 0
    if r[0] < r[1]:
        remaining = int(conn.execute("SELECT COUNT(*) FROM host_events WHERE id > ? AND id <= ?",
                                     (r[0], r[1])).fetchone()[0])
    return {"through": int(r[0]), "upto": int(r[1]), "started_at": r[2], "done_at": r[3],
            "done": r[0] >= r[1], "remaining": remaining}


def backfill(conn: sqlite3.Connection, *, seconds: float = 5.0, batch: int | None = None) -> dict[str, Any]:
    """Index events stored before the index existed, for at most `seconds`. Resumable:
    each batch commits with its progress. Returns the state afterwards."""
    deadline = time.monotonic() + max(0.0, seconds)
    batch = batch or BACKFILL_BATCH
    while True:
        conn.execute("BEGIN IMMEDIATE")
        try:
            r = conn.execute("SELECT through, upto FROM host_event_terms_state WHERE name = 'backfill'").fetchone()
            if r is None or r[0] >= r[1]:
                conn.execute("COMMIT")
                break
            through, upto = int(r[0]), int(r[1])
            rows = conn.execute("SELECT id, target, ts, doc FROM host_events WHERE id > ? AND id <= ? ORDER BY id "
                                "LIMIT ?", (through, upto, batch)).fetchall()
            docs = []
            for rid, target, ts, doc in rows:
                try:
                    docs.append((rid, target, ts, json.loads(doc)))
                except ValueError:
                    continue
            add_terms(conn, docs)
            new_through = int(rows[-1][0]) if rows else upto
            done = new_through >= upto
            conn.execute("UPDATE host_event_terms_state SET through = ?, done_at = ? WHERE name = 'backfill'",
                         (new_through, time.time() if done else None))
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        if done or time.monotonic() >= deadline:
            break
    return state(conn)


def delete_older_than(conn: sqlite3.Connection, cutoff: float) -> int:
    """The terms of events older than `cutoff` (the person's own host-events prune)."""
    exists = conn.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='host_event_terms'").fetchone()
    if not exists:
        return 0
    return conn.execute("DELETE FROM host_event_terms WHERE ts < ?", (cutoff,)).rowcount or 0


# --------------------------------------------------------------------------- reading
def match_clause(kind: str, value: str, network: Any = None) -> tuple[str, list[Any]]:
    """SQL over host_event_terms (alias t) for one indicator."""
    code = CODES[kind]
    if kind == "ip":
        net = network if network is not None else ipaddress.ip_network(value, strict=False)
        lo, hi = ip_range(net)
        if lo == hi:
            return "t.kind = ? AND t.value = ?", [code, lo]
        return "t.kind = ? AND t.value BETWEEN ? AND ?", [code, lo, hi]
    if kind == "path":
        # a folder finds what is inside it too: /tmp/x finds /tmp/x and /tmp/x/y
        # (a range, not LIKE, so the index serves it: '0' is the character after '/')
        if value == "/":
            return "t.kind = ?", [code]
        return "t.kind = ? AND (t.value = ? OR (t.value > ? AND t.value < ?))", [code, value, value + "/",
                                                                                   value + "0"]
    return "t.kind = ? AND t.value = ?", [code, value]


def iter_terms(conn: sqlite3.Connection, target: str) -> Iterator[tuple[str, str]]:
    for code, value in conn.execute("SELECT kind, value FROM host_event_terms WHERE target = ?", (target,)):
        yield KINDS_BY_CODE.get(code, code), value
