"""Records for the SSH certificate authority (Phase D.1) in `kratos.db`.

Three tables, none of which ever holds a private key:

- ``ssh_ca_keys`` — one row per CA key Kratos has made (user and host), with its
  role (active / next / retired), protection mode, public key and fingerprint.
  The private halves live as files in ``data_dir/ssh-ca/`` (kratos.sshca.ca);
  this table is the record of which fingerprints are Kratos's, so a machine's
  sshd log line can be traced and so own-login recognition (detect/own.py) knows
  which CAs are Kratos's (active, next, or retired inside the 7-day window).
- ``ssh_certs`` — one row per issued user certificate: serial (unique and
  increasing), key id, machine, principals, validity, source addresses, actor,
  run id. Never the certificate's private key.
- ``ssh_enrolment`` — one row per machine being or already moved to certificates:
  the state machine key → cert → cert-only, the login and principal, the address
  the machine sees Kratos from, which CA fingerprints its CA file trusts, and the
  host-certificate state.

All read-modify-write sequences open ``BEGIN IMMEDIATE`` (several processes share
the database). Times are epoch seconds, UTC.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.target_key import target_key

COMPONENT = "sshca"

RETIRED_WINDOW_SECONDS = 7 * 86400  # a retired CA still recognised as Kratos's for this long (spec §3.12)


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ssh_ca_keys (
            fingerprint  TEXT PRIMARY KEY,   -- "SHA256:..." (OpenSSH), the public key's
            kind         TEXT NOT NULL,       -- 'user' | 'host'
            role         TEXT NOT NULL,       -- 'active' | 'next' | 'retired'
            mode         TEXT NOT NULL,       -- 'file' | 'agent' | 'token' | 'tpm'
            public_key   TEXT NOT NULL,       -- the OpenSSH public key line
            key_ref      TEXT,                -- how ca.py finds the private half (file name / token slot)
            created_at   REAL NOT NULL,
            retired_at   REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ssh_certs (
            serial          INTEGER PRIMARY KEY,   -- unique and increasing
            key_id          TEXT NOT NULL,
            machine         TEXT NOT NULL,
            principals      TEXT NOT NULL,         -- JSON list
            valid_from      REAL NOT NULL,
            valid_to        REAL NOT NULL,
            source_addresses TEXT NOT NULL,        -- JSON list ([] = any, source-address off)
            ca_fingerprint  TEXT NOT NULL,
            actor           TEXT,
            run_id          TEXT,
            issued_at       REAL NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS ssh_certs_machine ON ssh_certs(machine)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ssh_enrolment (
            machine                 TEXT PRIMARY KEY,   -- target_key(host)
            host                    TEXT NOT NULL,       -- the address/name Kratos connects to
            login                   TEXT NOT NULL,
            state                   TEXT NOT NULL,       -- 'pending' | 'cert' | 'cert_only'
            principal               TEXT NOT NULL,
            principal_mode          TEXT NOT NULL,       -- 'machine' | 'simple'
            apparent_address        TEXT,                -- what $SSH_CONNECTION showed
            extra_source_addresses  TEXT NOT NULL,       -- JSON list (person-added)
            source_address_enabled  INTEGER NOT NULL,    -- 0 for a roaming Kratos host
            trusted_ca_fingerprints TEXT NOT NULL,       -- JSON list, read from the machine's CA file
            host_cert_state         TEXT NOT NULL,       -- 'none' | 'active'
            host_cert_fingerprint   TEXT,
            host_ca_fingerprint     TEXT,
            created_at              REAL NOT NULL,
            updated_at              REAL NOT NULL,
            actor                   TEXT
        )
        """
    )


_STEPS = (_step_1,)


def _db(data_dir: Path) -> sqlite3.Connection:
    db_path = Path(data_dir) / "kratos.db"
    conn = connect_store(db_path)
    try:
        migrate_once(conn, db_path, COMPONENT, _STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


# --------------------------------------------------------------------------- CA keys
@dataclass(frozen=True)
class CAKeyRecord:
    fingerprint: str
    kind: str
    role: str
    mode: str
    public_key: str
    key_ref: str | None
    created_at: float
    retired_at: float | None


def _ca_from_row(row: sqlite3.Row) -> CAKeyRecord:
    return CAKeyRecord(row["fingerprint"], row["kind"], row["role"], row["mode"],
                       row["public_key"], row["key_ref"], float(row["created_at"]),
                       float(row["retired_at"]) if row["retired_at"] is not None else None)


def record_ca_key(data_dir: Path, *, fingerprint: str, kind: str, role: str, mode: str,
                  public_key: str, key_ref: str | None, created_at: float | None = None) -> None:
    created_at = time.time() if created_at is None else created_at
    conn = _db(data_dir)
    try:
        conn.execute(
            "INSERT INTO ssh_ca_keys (fingerprint, kind, role, mode, public_key, key_ref, created_at, retired_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, NULL) "
            "ON CONFLICT(fingerprint) DO UPDATE SET role=excluded.role, mode=excluded.mode, "
            "public_key=excluded.public_key, key_ref=excluded.key_ref, retired_at=NULL",
            (fingerprint, kind, role, mode, public_key, key_ref, created_at),
        )
    finally:
        conn.close()


def set_ca_role(data_dir: Path, fingerprint: str, role: str, *, retired_at: float | None = None) -> None:
    conn = _db(data_dir)
    try:
        conn.execute("UPDATE ssh_ca_keys SET role=?, retired_at=? WHERE fingerprint=?",
                     (role, retired_at, fingerprint))
    finally:
        conn.close()


def ca_keys(data_dir: Path, *, kind: str | None = None) -> list[CAKeyRecord]:
    conn = _db(data_dir)
    try:
        if kind is None:
            rows = conn.execute("SELECT * FROM ssh_ca_keys ORDER BY created_at").fetchall()
        else:
            rows = conn.execute("SELECT * FROM ssh_ca_keys WHERE kind=? ORDER BY created_at", (kind,)).fetchall()
    finally:
        conn.close()
    return [_ca_from_row(r) for r in rows]


def ca_key(data_dir: Path, *, kind: str, role: str) -> CAKeyRecord | None:
    conn = _db(data_dir)
    try:
        row = conn.execute("SELECT * FROM ssh_ca_keys WHERE kind=? AND role=? ORDER BY created_at DESC LIMIT 1",
                           (kind, role)).fetchone()
    finally:
        conn.close()
    return _ca_from_row(row) if row else None


def trusted_user_fingerprints(data_dir: Path, *, now: float | None = None) -> list[str]:
    """User CA fingerprints Kratos still owns: active, next, and any retired within
    the 7-day window. Used by own-login recognition (detect/own.py)."""
    now = time.time() if now is None else now
    out: list[str] = []
    for rec in ca_keys(data_dir, kind="user"):
        if rec.role in ("active", "next"):
            out.append(rec.fingerprint)
        elif rec.role == "retired" and rec.retired_at is not None and now - rec.retired_at <= RETIRED_WINDOW_SECONDS:
            out.append(rec.fingerprint)
    return out


# --------------------------------------------------------------------------- certificates
def record_cert(data_dir: Path, *, key_id: str, machine: str, principals: Sequence[str],
                valid_from: float, valid_to: float, source_addresses: Sequence[str],
                ca_fingerprint: str, actor: str | None, run_id: str | None,
                serial: int | None = None) -> int:
    """Record one issued certificate and return its serial. When `serial` is None a
    fresh, strictly-increasing serial is allocated inside the write transaction."""
    conn = _db(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if serial is None:
                row = conn.execute("SELECT MAX(serial) FROM ssh_certs").fetchone()
                serial = int(row[0]) + 1 if row and row[0] is not None else 1
            conn.execute(
                "INSERT INTO ssh_certs (serial, key_id, machine, principals, valid_from, valid_to, "
                "source_addresses, ca_fingerprint, actor, run_id, issued_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (serial, key_id, target_key(machine), json.dumps(list(principals)), valid_from, valid_to,
                 json.dumps(list(source_addresses)), ca_fingerprint, actor, run_id, time.time()),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return serial


def next_serial(data_dir: Path) -> int:
    conn = _db(data_dir)
    try:
        row = conn.execute("SELECT MAX(serial) FROM ssh_certs").fetchone()
    finally:
        conn.close()
    return int(row[0]) + 1 if row and row[0] is not None else 1


def certs(data_dir: Path, *, machine: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    conn = _db(data_dir)
    try:
        if machine is None:
            rows = conn.execute("SELECT * FROM ssh_certs ORDER BY serial DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM ssh_certs WHERE machine=? ORDER BY serial DESC LIMIT ?",
                                (target_key(machine), limit)).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["principals"] = json.loads(d["principals"])
        d["source_addresses"] = json.loads(d["source_addresses"])
        out.append(d)
    return out


# --------------------------------------------------------------------------- enrolment
@dataclass(frozen=True)
class Enrolment:
    machine: str
    host: str
    login: str
    state: str                       # 'pending' | 'cert' | 'cert_only'
    principal: str
    principal_mode: str              # 'machine' | 'simple'
    apparent_address: str | None
    extra_source_addresses: list[str]
    source_address_enabled: bool
    trusted_ca_fingerprints: list[str]
    host_cert_state: str             # 'none' | 'active'
    host_cert_fingerprint: str | None
    host_ca_fingerprint: str | None
    created_at: float
    updated_at: float
    actor: str | None

    @property
    def uses_cert(self) -> bool:
        """Once the certificate login is proven, Kratos authenticates with a certificate
        (never the old key). A still-pending enrolment keeps using the old key."""
        return self.state in ("cert", "cert_only")

    @property
    def host_cert_active(self) -> bool:
        return self.host_cert_state == "active"

    @property
    def source_addresses(self) -> list[str]:
        """What a certificate's source-address list is built from: the address the machine
        sees Kratos from, plus any the person added. Empty when source-address is off."""
        if not self.source_address_enabled:
            return []
        out: list[str] = []
        if self.apparent_address:
            out.append(self.apparent_address)
        for a in self.extra_source_addresses:
            if a and a not in out:
                out.append(a)
        return out


def _enrol_from_row(row: sqlite3.Row) -> Enrolment:
    return Enrolment(
        machine=row["machine"], host=row["host"], login=row["login"], state=row["state"],
        principal=row["principal"], principal_mode=row["principal_mode"],
        apparent_address=row["apparent_address"],
        extra_source_addresses=json.loads(row["extra_source_addresses"] or "[]"),
        source_address_enabled=bool(row["source_address_enabled"]),
        trusted_ca_fingerprints=json.loads(row["trusted_ca_fingerprints"] or "[]"),
        host_cert_state=row["host_cert_state"], host_cert_fingerprint=row["host_cert_fingerprint"],
        host_ca_fingerprint=row["host_ca_fingerprint"], created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]), actor=row["actor"],
    )


def get_enrolment(data_dir: Path, host: str) -> Enrolment | None:
    conn = _db(data_dir)
    try:
        row = conn.execute("SELECT * FROM ssh_enrolment WHERE machine=?", (target_key(host),)).fetchone()
    finally:
        conn.close()
    return _enrol_from_row(row) if row else None


def list_enrolments(data_dir: Path) -> list[Enrolment]:
    conn = _db(data_dir)
    try:
        rows = conn.execute("SELECT * FROM ssh_enrolment ORDER BY machine").fetchall()
    finally:
        conn.close()
    return [_enrol_from_row(r) for r in rows]


def upsert_enrolment(data_dir: Path, host: str, *, login: str, principal: str,
                     principal_mode: str, actor: str | None,
                     apparent_address: str | None = None,
                     source_address_enabled: bool = True,
                     extra_source_addresses: Iterable[str] | None = None) -> Enrolment:
    """Create or refresh an enrolment row at state 'pending' (does not change the state
    of an existing row). People-only setup fields."""
    machine = target_key(host)
    now = time.time()
    conn = _db(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            existing = conn.execute("SELECT * FROM ssh_enrolment WHERE machine=?", (machine,)).fetchone()
            extra = json.dumps(list(extra_source_addresses) if extra_source_addresses is not None
                               else (json.loads(existing["extra_source_addresses"]) if existing else []))
            if existing is None:
                conn.execute(
                    "INSERT INTO ssh_enrolment (machine, host, login, state, principal, principal_mode, "
                    "apparent_address, extra_source_addresses, source_address_enabled, trusted_ca_fingerprints, "
                    "host_cert_state, host_cert_fingerprint, host_ca_fingerprint, created_at, updated_at, actor) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (machine, host, login, "pending", principal, principal_mode, apparent_address, extra,
                     1 if source_address_enabled else 0, "[]", "none", None, None, now, now, actor),
                )
            else:
                conn.execute(
                    "UPDATE ssh_enrolment SET host=?, login=?, principal=?, principal_mode=?, apparent_address=?, "
                    "extra_source_addresses=?, source_address_enabled=?, updated_at=?, actor=? WHERE machine=?",
                    (host, login, principal, principal_mode,
                     apparent_address if apparent_address is not None else existing["apparent_address"],
                     extra, 1 if source_address_enabled else 0, now, actor, machine),
                )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    result = get_enrolment(data_dir, host)
    assert result is not None
    return result


def _update(data_dir: Path, host: str, **fields: Any) -> None:
    if not fields:
        return
    fields["updated_at"] = time.time()
    cols = ", ".join(f"{k}=?" for k in fields)
    conn = _db(data_dir)
    try:
        conn.execute(f"UPDATE ssh_enrolment SET {cols} WHERE machine=?",  # noqa: S608 -- keys are literals below
                     (*fields.values(), target_key(host)))
    finally:
        conn.close()


def set_state(data_dir: Path, host: str, state: str) -> None:
    if state not in ("pending", "cert", "cert_only"):
        raise ValueError(f"unknown enrolment state {state!r}")
    _update(data_dir, host, state=state)


def set_apparent_address(data_dir: Path, host: str, address: str | None) -> None:
    _update(data_dir, host, apparent_address=address)


def set_trusted_ca_fingerprints(data_dir: Path, host: str, fingerprints: Sequence[str]) -> None:
    _update(data_dir, host, trusted_ca_fingerprints=json.dumps(list(fingerprints)))


def set_host_cert(data_dir: Path, host: str, *, state: str, cert_fingerprint: str | None,
                  ca_fingerprint: str | None) -> None:
    if state not in ("none", "active"):
        raise ValueError(f"unknown host-cert state {state!r}")
    _update(data_dir, host, host_cert_state=state, host_cert_fingerprint=cert_fingerprint,
            host_ca_fingerprint=ca_fingerprint)


def delete_enrolment(data_dir: Path, host: str) -> None:
    conn = _db(data_dir)
    try:
        conn.execute("DELETE FROM ssh_enrolment WHERE machine=?", (target_key(host),))
    finally:
        conn.close()
