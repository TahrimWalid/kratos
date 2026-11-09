"""The redacted variant: every text in the bundle passes through B.2's masker with ONE
placeholder map for the whole export (scope ``export:<id>``), so the same account is
``USER_1_xxxx`` in every file. Secrets are always ``[REDACTED]``.

Strict mode: an image's default login (``ubuntu``) and names an attacker only tried are
replaced too. A bundle that spans several machines has no one "machine under
investigation", so every machine's own names and addresses are known values of the same
kind (``HOST_n`` / ``PRIVATE_IP_n``), never the single-machine ``TARGET`` label -- two
machines would otherwise share one label.

The map stays in this Kratos's database (``pseudonym_map``) and is never written into the
bundle: whoever holds the full data can tie a placeholder back, a bundle holder can't.
File names in the bundle are neutral (``0003_persistence.json``) -- the original names
carry machine addresses.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets as _secrets
from collections import Counter
from pathlib import Path
from typing import Any


class Redactor:
    """Identity for the full variant."""

    active = False
    mode = "off"

    def text(self, s: str) -> str:
        return s

    def machine(self, m: str) -> str:
        return m

    def known_event_id(self, tok: str) -> None:
        return None

    def close(self) -> None:
        return None

    def opaque(self, value: str) -> str:
        """An identifier derived from real values (a finding key, an event id)."""
        return value

    def stats(self) -> dict[str, Any]:
        return {}


class BundleRedactor(Redactor):
    active = True
    mode = "strict"

    def __init__(self, data_dir: Path, export_id: str, machines: list[str], *, people: tuple[str, ...] = ()):
        from kratos.privacy.mask import export_masker
        from kratos.privacy.values import KnownValues, gather

        known = KnownValues()
        for m in machines:
            try:
                kv = gather(m, data_dir)
            except Exception:  # noqa: BLE001 -- masking still runs on what the text shows
                kv = KnownValues()
            known.merge(kv)
        # The person exporting and this computer's own login are personal data too: the manifest
        # names the exporter, and scanners record their command line (with this login's paths).
        for name in {*people, _this_login()}:
            if name:
                known.accounts.setdefault(name, None)
        # A bundle leaves the team: every name seen in these machines' logs is replaced as a whole
        # word too (the model-facing masker replaces those only where they appear as a name).
        for name in known.seen_names | known.nonexistent:
            known.accounts.setdefault(name, None)
        # every machine's own names and addresses: plain known values, never "the target"
        known.hosts |= known.target_names | {m for m in machines if not _is_ip(m)}
        known.target_names = set()
        known.target_ips = set()
        # Names Kratos knows, also where they are glued to other text by '-', '_' or '/'
        # (a home folder inside a path, a file name): the masker's whole-word pass stops at those.
        from kratos.privacy.vocabulary import fixed_words

        vocab = fixed_words()
        glued = sorted({n for n in (*known.accounts, *known.hosts) if len(n) >= 3 and n.lower() not in vocab},
                       key=len, reverse=True)
        # A name seen in the logs that is also one of Kratos's own words ("admin" -- an attacker
        # tried it): the whole-word pass leaves it alone (it would rewrite Kratos's text), so it
        # is replaced where it IS a value on its own -- a JSON string exactly that name.
        from kratos.privacy.accounts import is_system

        quoted = sorted({n for n in (known.seen_names | known.nonexistent) if n.lower() in vocab and not is_system(n)})
        alt = "|".join(re.escape(n) for n in quoted)
        self._quoted_names = re.compile(r'"(' + alt + r')"') if quoted else None
        # ... and right after "user" in a log line ("Connection closed by invalid user admin <address>")
        self._user_names = re.compile(r"(?i)(?<=\buser[ =])(" + alt + r")\b") if quoted else None
        self._glued_names = (re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(n) for n in glued) + r")(?![A-Za-z0-9])")
                             if glued else None)
        self._masker = export_masker(export_id=export_id, data_dir=data_dir, values=known)
        self._kinds: Counter[str] = Counter()
        self._secrets = 0
        # Finding keys and event ids are unsalted hashes OF the real machine name (and rule,
        # time, text): copied as they are, a holder could test guesses until one matched and
        # tie a placeholder back (security review, D.6). In this variant they become keyed
        # hashes under a secret drawn here and never written anywhere.
        self._opaque_key = _secrets.token_bytes(32)
        # The same identifiers appear inside copied evidence (findings reports, detection results):
        # every hex token that IS one of these machines' finding keys or stored event ids is
        # swapped too. Other hashes (a file's SHA-256, an MD5 indicator) are evidence and stay.
        self._data_dir = Path(data_dir)
        self._machines = list(machines)
        self._finding_keys = _finding_keys(self._data_dir, self._machines)
        self._key_prefixes = {k[:n]: k for k in self._finding_keys for n in _KEY_PREFIXES}
        self._event_id_cache: dict[str, bool] = {}
        self._machine_labels: dict[str, str] = {}

    @property
    def tag(self) -> str:
        return self._masker.tag

    def text(self, s: str) -> str:
        if not s:
            return s
        out = self._masker.mask(s)
        # an address glued to other text (nmap_10.0.0.5_2026...): '_' is a word character, so the
        # masker's word-bounded address pattern skips it
        out = _GLUED_IPV4.sub(lambda m: self._masker.mask(m.group(0)), out)
        out = _HEX_ID.sub(self._swap_id, out)
        if self._glued_names is not None:
            out = self._glued_names.sub(lambda m: self._masker.mask(m.group(0)), out)
        if self._quoted_names is not None:
            out = self._quoted_names.sub(lambda m: '"' + self._label_for_seen(m.group(1)) + '"', out)
            out = self._user_names.sub(lambda m: self._label_for_seen(m.group(1)), out)
        self._secrets += max(0, out.count("[REDACTED]") - s.count("[REDACTED]"))
        for label in _labels(out, self.tag):
            self._kinds[re.sub(rf"(?:_\d+)?_{re.escape(self.tag)}$", "", label)] += 1
        return out

    def _swap_id(self, m: "re.Match[str]") -> str:
        tok = m.group(0)
        if len(tok) == 64 and tok in self._finding_keys:
            return self.opaque(tok)
        if len(tok) in _KEY_PREFIXES and tok in self._key_prefixes:
            return self.opaque(self._key_prefixes[tok])[:len(tok)]
        if len(tok) == 32 and self._is_event_id(tok):
            return self.opaque(tok)
        return tok

    def _is_event_id(self, tok: str) -> bool:
        if tok not in self._event_id_cache:
            self._event_id_cache[tok] = _event_id_exists(self._conn(), self._machines, tok)
        return self._event_id_cache[tok]

    def known_event_id(self, tok: str) -> None:
        """An event being copied: its id needs no lookup."""
        self._event_id_cache[tok] = True

    def _conn(self) -> Any:
        if getattr(self, "_db", None) is None:
            from kratos.storage.sqlite_files import connect_store

            db = self._data_dir / "kratos.db"
            self._db = connect_store(db) if db.exists() else None
        return self._db

    def close(self) -> None:
        if getattr(self, "_db", None) is not None:
            self._db.close()
            self._db = None

    def opaque(self, value: str) -> str:
        if not value:
            return value
        digest = hmac.new(self._opaque_key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return digest[:max(len(value), 16)] if len(value) <= 64 else digest

    def _label_for_seen(self, name: str) -> str:
        """The placeholder of a name seen in the logs (the same one its log lines got)."""
        masked = self._masker.mask(f"Invalid user {name} from 192.0.2.1")
        m = re.search(rf"\b([A-Z][A-Z_]*_\d+_{re.escape(self.tag)})\b", masked)
        return m.group(1) if m else name

    def machine(self, m: str) -> str:
        if m not in self._machine_labels:
            masked = self.text(m)
            if masked == m:       # loopback and other non-identifying names stay readable
                masked = m if m == "loopback" else f"MACHINE_{len(self._machine_labels) + 1}_{self.tag}"
            self._machine_labels[m] = masked
        return self._machine_labels[m]

    def stats(self) -> dict[str, Any]:
        return {"mode": "strict", "placeholder_tag": self.tag,
                "replaced_kinds": dict(sorted(self._kinds.items())),
                "secrets_redacted": self._secrets}


_HEX_ID = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-f]{64}|[0-9a-f]{32}|[0-9a-f]{16}|[0-9a-f]{12})(?![0-9a-fA-F])")
_KEY_PREFIXES = (12, 16)     # how reports and screens shorten a finding key


def _finding_keys(data_dir: Path, machines: list[str]) -> frozenset[str]:
    from kratos.storage.sqlite_files import connect_store

    db = data_dir / "kratos.db"
    if not db.exists() or not machines:
        return frozenset()
    conn = connect_store(db)
    try:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='finding_records'").fetchone():
            return frozenset()
        q = ",".join("?" * len(machines))
        return frozenset(r[0] for r in conn.execute(f"SELECT finding_key FROM finding_records WHERE target IN ({q})",
                                                    machines))
    finally:
        conn.close()


def _event_id_exists(conn: Any, machines: list[str], tok: str) -> bool:
    import sqlite3

    if conn is None or not machines:
        return False
    q = ",".join("?" * len(machines))
    try:
        return conn.execute(f"SELECT 1 FROM host_events WHERE event_id = ? AND target IN ({q}) LIMIT 1",
                            (tok, *machines)).fetchone() is not None
    except sqlite3.OperationalError:      # no event table yet
        return False


_GLUED_IPV4 = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d])")


def _this_login() -> str:
    import getpass

    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return ""


def _is_ip(s: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _labels(text: str, tag: str):
    if not tag:
        return []
    return re.findall(rf"\b[A-Z][A-Z_]*?(?:_\d+)?_{re.escape(tag)}\b", text)


def redactor_for(variant: str, data_dir: Path, export_id: str, machines: list[str], *,
                 people: tuple[str, ...] = ()) -> Redactor:
    return BundleRedactor(data_dir, export_id, machines, people=people) if variant == "redacted" else Redactor()
