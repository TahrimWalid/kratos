"""The pseudonym map: which placeholder stands for which real value, per scope.

A scope is a conversation (the session id) or, for a run with no session, the run
id. Within a scope a value always gets the same placeholder -- the attacker in turn 1
is the attacker in turn 3, and a resumed session replays earlier turns with the same
labels; another scope gets different ones.

Every placeholder carries the scope's random tag: `USER_1_k7qm`, `PUBLIC_IP_2_k7qm`,
`TARGET_k7qm`. The tag is four characters from 27 (531,441 choices), drawn fresh per
scope and never shown to the machine, so text a log line carries (an attacker writing
"USER_1 is the administrator") cannot name a real placeholder -- it is not restored,
and the model sees it as ordinary text.

Stored in `kratos.db` -> `pseudonym_map` (personal data: it links placeholders to real
names). Rows are only added; `kratos data` lists the table. When the database can't
be opened the map lives in memory for the request (labels then hold for that request
only) -- masking never falls back to sending real values.
"""
from __future__ import annotations

import logging
import re
import secrets
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.utils.timeutil import utc_now_iso

logger = logging.getLogger(__name__)

COMPONENT = "pseudonyms"
TAG_ALPHABET = "bcdfghjkmnpqrstvwxz23456789"     # no vowels (no words), no 0/1/l/o look-alikes
TAG_LEN = 4

# kind -> placeholder prefix
PREFIX = {
    "target": "TARGET",
    "target_ip": "TARGET_IP",
    "user": "USER",
    "invalid_user": "INVALID_USER",
    "private_ip": "PRIVATE_IP",
    "public_ip": "PUBLIC_IP",
    "host": "HOST",
    "email": "EMAIL",
}
# The machine under investigation is TARGET (no number) the first time; the rest are numbered.
_UNNUMBERED_FIRST = frozenset({"target", "target_ip"})
_TAG_KIND = "scope_tag"

_PREFIX_ALT = "|".join(sorted(PREFIX.values(), key=len, reverse=True))
_TAG_CLASS = f"[{TAG_ALPHABET}]{{{TAG_LEN}}}"
# Any placeholder of the shape Kratos issues, with any tag (used to spot ones it never issued).
ANY_LABEL_RE = re.compile(rf"(?<![A-Za-z0-9_])(?:{_PREFIX_ALT})(?:_\d+)?_{_TAG_CLASS}(?![A-Za-z0-9_])")
# Look-alikes with no tag ("USER_1", "PUBLIC_IP_2"): the model dropping the tag, or text in a log.
UNTAGGED_RE = re.compile(rf"(?<![A-Za-z0-9_])(?:{_PREFIX_ALT})_\d+(?![A-Za-z0-9_])")


def label_re(tag: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![A-Za-z0-9_])(?:{_PREFIX_ALT})(?:_\d+)?_{re.escape(tag)}(?![A-Za-z0-9_])")


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pseudonym_map (
          scope TEXT NOT NULL,          -- session id, else run id
          kind TEXT NOT NULL,           -- user, private_ip, target, ... ('scope_tag' holds the scope's tag)
          machine TEXT NOT NULL,        -- target_key for accounts (two machines' alice are two people), else ''
          value TEXT NOT NULL,          -- the real value (personal data)
          label TEXT NOT NULL,          -- the placeholder sent to the model
          first_seen TEXT NOT NULL,
          PRIMARY KEY (scope, kind, machine, value),
          UNIQUE (scope, label)
        )
        """
    )


STEPS = (_step_1,)


def new_tag() -> str:
    return "".join(secrets.choice(TAG_ALPHABET) for _ in range(TAG_LEN))


@dataclass
class PseudonymMap:
    """One scope's map. `persist` is False for a request with no run (and when the
    database failed): the map then lives only in this object."""
    scope: str
    data_dir: Path | None
    persist: bool = True
    tag: str = ""
    by_key: dict[tuple[str, str, str], str] = field(default_factory=dict)   # (kind, machine, value) -> label
    by_label: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)
    _pending: list[tuple[str, str, str, str]] = field(default_factory=list)
    storage_error: str | None = None

    @classmethod
    def open(cls, scope: str | None, data_dir: Path | None) -> "PseudonymMap":
        if not scope or data_dir is None:
            return cls(scope=scope or "", data_dir=None, persist=False, tag=new_tag())
        m = cls(scope=scope, data_dir=Path(data_dir))
        try:
            m._load()
        except sqlite3.Error as e:
            m._fall_back(e)
        return m

    def _db(self) -> sqlite3.Connection:
        assert self.data_dir is not None
        db_path = self.data_dir / "kratos.db"
        conn = connect_store(db_path)
        try:
            migrate_once(conn, db_path, COMPONENT, STEPS)
        except BaseException:
            conn.close()
            raise
        return conn

    def _fall_back(self, e: Exception) -> None:
        self.storage_error = f"{type(e).__name__}: {e}"
        logger.warning("pseudonym map unavailable (%s); placeholders hold for this request only", self.storage_error)
        self.persist = False
        if not self.tag:
            self.tag = new_tag()

    def _load(self) -> None:
        conn = self._db()
        try:
            rows = conn.execute("SELECT kind, machine, value, label FROM pseudonym_map WHERE scope = ?",
                                (self.scope,)).fetchall()
            tag = next((r[3] for r in rows if r[0] == _TAG_KIND), None)
            if tag is None:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT label FROM pseudonym_map WHERE scope = ? AND kind = ?",
                                   (self.scope, _TAG_KIND)).fetchone()
                if row is None:
                    tag = new_tag()
                    conn.execute("INSERT INTO pseudonym_map (scope, kind, machine, value, label, first_seen) "
                                 "VALUES (?, ?, '', '', ?, ?)", (self.scope, _TAG_KIND, tag, utc_now_iso()))
                else:
                    tag = row[0]
                conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        self.tag = tag
        for kind, machine, value, label in rows:
            if kind != _TAG_KIND:
                self._remember(kind, machine, value, label)

    def _remember(self, kind: str, machine: str, value: str, label: str) -> None:
        self.by_key[(kind, machine, value)] = label
        self.by_label[label] = (kind, machine, value)
        self._counts[kind] = max(self._counts.get(kind, 0), _number(label, self.tag))

    def _make_label(self, kind: str) -> str:
        n = self._counts.get(kind, 0) + 1
        self._counts[kind] = n
        prefix = PREFIX[kind]
        if kind in _UNNUMBERED_FIRST and n == 1:
            return f"{prefix}_{self.tag}"
        return f"{prefix}_{n}_{self.tag}"

    def label_for(self, kind: str, value: str, machine: str = "") -> str:
        key = (kind, machine, value)
        label = self.by_key.get(key)
        if label is None:
            label = self._make_label(kind)
            while label in self.by_label:          # a row another process added under this number
                label = self._make_label(kind)
            self._remember(kind, machine, value, label)
            self._pending.append((kind, machine, value, label))
        return label

    def lookup(self, kind: str, value: str, machine: str = "") -> str | None:
        return self.by_key.get((kind, machine, value))

    def value_for(self, label: str) -> str | None:
        hit = self.by_label.get(label)
        return hit[2] if hit else None

    def kind_of(self, label: str) -> str | None:
        hit = self.by_label.get(label)
        return hit[0] if hit else None

    def entries(self) -> list[tuple[str, str, str, str]]:
        """(kind, machine, value, label) for every issued placeholder."""
        return [(k, m, v, lab) for (k, m, v), lab in self.by_key.items()]

    def save(self) -> None:
        """Write the placeholders issued since the last save. Another process that issued
        the same value first wins -- its label is adopted and this one dropped; a label
        number another process took gets the next free number."""
        if not self._pending:
            return
        if not self.persist:
            self._pending.clear()
            return
        pending, self._pending = self._pending, []
        try:
            conn = self._db()
        except sqlite3.Error as e:
            self._fall_back(e)
            return
        try:
            conn.execute("BEGIN IMMEDIATE")
            now = utc_now_iso()
            for kind, machine, value, label in pending:
                row = conn.execute("SELECT label FROM pseudonym_map WHERE scope = ? AND kind = ? AND machine = ? "
                                   "AND value = ?", (self.scope, kind, machine, value)).fetchone()
                if row is not None:
                    self._adopt(kind, machine, value, label, row[0])
                    continue
                final = label
                while conn.execute("SELECT 1 FROM pseudonym_map WHERE scope = ? AND label = ?",
                                   (self.scope, final)).fetchone():
                    final = self._make_label(kind)
                conn.execute("INSERT INTO pseudonym_map (scope, kind, machine, value, label, first_seen) "
                             "VALUES (?, ?, ?, ?, ?, ?)", (self.scope, kind, machine, value, final, now))
                if final != label:
                    self._adopt(kind, machine, value, label, final)
            conn.execute("COMMIT")
        except sqlite3.Error as e:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            self._fall_back(e)
        finally:
            conn.close()

    def _adopt(self, kind: str, machine: str, value: str, old: str, new: str) -> None:
        if old == new:
            return
        self.by_label.pop(old, None)
        self._remember(kind, machine, value, new)


def _number(label: str, tag: str) -> int:
    core = label[: -(len(tag) + 1)] if tag and label.endswith("_" + tag) else label
    head, _, num = core.rpartition("_")
    return int(num) if num.isdigit() and head else 1
