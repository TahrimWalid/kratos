"""
Kratos's side of the encrypted agent link (Phase C.4).

Kratos holds two key pairs in `data_dir/subagent-tls/` (folder 0700, files 0600):

- the **active** key, with a long-lived self-signed certificate the listener
  presents to agents, and
- a **backup** key, made at the same time, that no listener uses yet.

Every agent is given the SHA-256 of both keys' SubjectPublicKeyInfo (the
"pins") when it is installed or updated, and accepts a server only if its key
matches one of them (kratos.subagent.pinning). The certificate's names and
dates don't matter to the agent -- only the key does.

`rotate()` makes the backup key active (with a new certificate), makes a new
backup, and bumps the pin-set version; the listener notices within seconds,
starts presenting the new key and pushes the new pin pair to every connected
agent over its already-pinned link (a signed, versioned push). An agent that
was offline still holds the old backup pin, which is now the active key, so it
reconnects without help and then receives the new pair.

The keys never leave this machine, are never logged, and are inventoried as
secret (kratos.datainv). Losing both keys means re-pairing every agent.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import ssl
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec
from kratos.subagent import pinning

try:
    import fcntl
except ImportError:  # pragma: no cover -- Kratos runs on Linux
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger("kratos.subagent.tls")

TLS_DIR_NAME = "subagent-tls"
STATE_NAME = "keys.json"
README_NAME = "README.txt"
CERT_VALID_DAYS = 20 * 365
CERT_COMMON_NAME = "Kratos agent link"
MAX_PIN_VERSION = 2**31 - 1

REQUIRE = "subagent.tls.require"


def _yes_no(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise SettingError("on or off")


settings_store.register(SettingSpec(
    REQUIRE, False, _yes_no,
    "Refuse agents that connect without encryption (turn on once every paired agent shows 'encrypted').",
))

_README = """\
Kratos agent link keys -- SECRET, owner-only.

active key + certificate: what the Kratos listener presents to your servers'
agents. backup key: not used yet; every agent already trusts it, so
`kratos subagent-tls rotate` can switch to it without re-pairing anything.

Copy this whole folder somewhere safe (with your Kratos database backup) so a
lost disk doesn't mean re-pairing every server. Never share it: anyone holding
these keys and a pairing token can pose as this Kratos to your agents.
"""


class TLSKeyError(RuntimeError):
    """The key folder is missing, unreadable, or not owner-only."""


@dataclass(frozen=True)
class KeySet:
    directory: Path
    version: int
    active_pin: str
    backup_pin: str
    created_at: float
    rotated_at: float | None

    @property
    def cert_path(self) -> Path:
        return self.directory / _cert_name(self.active_pin)

    @property
    def key_path(self) -> Path:
        return self.directory / _key_name(self.active_pin)

    @property
    def backup_key_path(self) -> Path:
        return self.directory / _key_name(self.backup_pin)

    def pins(self) -> list[str]:
        """[active, backup] -- what an agent is given."""
        return [self.active_pin, self.backup_pin]

    def as_pin_set(self) -> dict[str, Any]:
        return {"version": self.version, "pins": self.pins()}


def tls_dir(data_dir: Path) -> Path:
    return Path(data_dir) / TLS_DIR_NAME


def _key_name(pin: str) -> str:
    return f"key-{pin[:16]}.pem"


def _cert_name(pin: str) -> str:
    return f"cert-{pin[:16]}.pem"


# ---------------------------------------------------------------------------
# File safety
# ---------------------------------------------------------------------------
def _check_private(path: Path, *, directory: bool) -> None:
    """Refuse a symlink, a file owned by someone else, or one others can read."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise TLSKeyError(f"{path} is missing") from None
    import stat as _stat

    if _stat.S_ISLNK(st.st_mode):
        raise TLSKeyError(f"{path} is a symbolic link -- the agent link keys must be plain files")
    if directory != _stat.S_ISDIR(st.st_mode):
        raise TLSKeyError(f"{path} is not a {'folder' if directory else 'file'}")
    if st.st_uid != os.geteuid():
        raise TLSKeyError(f"{path} belongs to another user (uid {st.st_uid}) -- the agent link keys must be yours")
    if st.st_mode & 0o077:
        want = "700" if directory else "600"
        raise TLSKeyError(f"{path} can be read by other users (mode {st.st_mode & 0o777:o}); "
                          f"run `chmod {want} {path}` -- the agent link keys are secret")


def _write_private(path: Path, data: bytes) -> None:
    """Atomic, 0600 from the first byte, never through a symlink."""
    if path.is_symlink():
        raise TLSKeyError(f"{path} is a symbolic link -- refusing to write a key through it")
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)  # deletion-scan: our own half-written temp file, never a kept key
        except OSError:
            pass
        raise


def _ensure_dir(path: Path) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        os.chmod(path, 0o700)  # mkdir's mode is filtered by the umask
    _check_private(path, directory=True)


@contextmanager
def _locked(directory: Path) -> Iterator[None]:
    """One writer at a time across processes (the TUI's listener, the always-on
    service and a CLI may all start at once)."""
    if fcntl is None:  # pragma: no cover
        yield
        return
    fd = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Keys and certificates (the `cryptography` package, Kratos host only)
# ---------------------------------------------------------------------------
def _new_private_key() -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1())


def _key_pem(key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _load_key(path: Path) -> Any:
    from cryptography.hazmat.primitives import serialization

    _check_private(path, directory=False)
    try:
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError) as e:
        raise TLSKeyError(f"{path} is not a readable private key ({type(e).__name__})") from None


def public_key_pin(key: Any) -> str:
    """SHA-256 of a key's SubjectPublicKeyInfo, as 64 hex characters."""
    from cryptography.hazmat.primitives import serialization

    pub = key.public_key() if hasattr(key, "public_key") else key
    spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _self_signed_cert(key: Any) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CERT_COMMON_NAME)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=CERT_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _cert_pin(path: Path) -> str:
    import ssl as _ssl

    pem = path.read_text(encoding="ascii")
    return pinning.spki_sha256(_ssl.PEM_cert_to_DER_cert(pem)).hex()


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def _read_state(directory: Path) -> dict[str, Any] | None:
    path = directory / STATE_NAME
    if not path.exists() and not path.is_symlink():
        return None
    _check_private(path, directory=False)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise TLSKeyError(f"{path} is unreadable ({type(e).__name__})") from None
    if not isinstance(doc, dict):
        raise TLSKeyError(f"{path} is not a key record")
    return doc


def _keyset_from(directory: Path, doc: dict[str, Any]) -> KeySet:
    try:
        version = doc["version"]
        active, backup = pinning.normalize_pin(doc["active"]), pinning.normalize_pin(doc["backup"])
    except (KeyError, pinning.PinError) as e:
        raise TLSKeyError(f"{directory / STATE_NAME} is damaged ({e})") from None
    if type(version) is not int or not 1 <= version <= MAX_PIN_VERSION or active == backup:
        raise TLSKeyError(f"{directory / STATE_NAME} is damaged (version/keys)")
    ks = KeySet(directory, version, active, backup, float(doc.get("created_at") or 0.0),
                float(doc["rotated_at"]) if doc.get("rotated_at") else None)
    # The files must be what the record says: a swapped or damaged key file is
    # refused, never served (an agent would refuse it anyway, but say why here).
    for path, pin in ((ks.key_path, active), (ks.backup_key_path, backup)):
        if public_key_pin(_load_key(path)) != pin:
            raise TLSKeyError(f"{path} doesn't hold the key its record names -- restore the folder from your copy")
    _check_private(ks.cert_path, directory=False)
    if _cert_pin(ks.cert_path) != active:
        raise TLSKeyError(f"{ks.cert_path} doesn't match the active key -- restore the folder from your copy")
    return ks


def _write_state(directory: Path, ks: KeySet) -> None:
    doc = {"version": ks.version, "active": ks.active_pin, "backup": ks.backup_pin,
           "created_at": ks.created_at, "rotated_at": ks.rotated_at}
    _write_private(directory / STATE_NAME, (json.dumps(doc, indent=2) + "\n").encode("utf-8"))


def load_keys(data_dir: Path) -> KeySet | None:
    """The current keys, or None if none were made yet. Never creates them.
    Raises TLSKeyError when they exist but are unsafe or damaged."""
    directory = tls_dir(data_dir)
    if not directory.exists() and not directory.is_symlink():
        return None
    _check_private(directory, directory=True)
    doc = _read_state(directory)
    return None if doc is None else _keyset_from(directory, doc)


def ensure_keys(data_dir: Path) -> KeySet:
    """The current keys, made once on first use: an active key with its
    certificate and a backup key. Safe to call from several processes at once."""
    directory = tls_dir(data_dir)
    _ensure_dir(directory)
    with _locked(directory):
        doc = _read_state(directory)
        if doc is not None:
            return _keyset_from(directory, doc)
        active, backup = _new_private_key(), _new_private_key()
        ks = KeySet(directory, 1, public_key_pin(active), public_key_pin(backup), time.time(), None)
        _write_private(ks.key_path, _key_pem(active))
        _write_private(ks.backup_key_path, _key_pem(backup))
        _write_private(ks.cert_path, _self_signed_cert(active))
        _write_private(directory / README_NAME, _README.encode("utf-8"))
        _write_state(directory, ks)  # last: until it exists, the keys don't count
        logger.info("made the agent link keys in %s", directory)
        return ks


def rotate(data_dir: Path, *, actor: str) -> tuple[KeySet, KeySet]:
    """Make the backup key active (new certificate), make a new backup, bump
    the pin-set version. Returns (before, after). People only."""
    tool = settings_store.in_tool_call()
    if tool:
        raise TLSKeyError(f"rotating the agent link keys is a person's decision -- refused inside the tool call {tool!r}")
    directory = tls_dir(data_dir)
    _ensure_dir(directory)
    with _locked(directory):
        doc = _read_state(directory)
        if doc is None:
            raise TLSKeyError("there are no agent link keys yet -- they are made when the listener first starts")
        before = _keyset_from(directory, doc)
        if before.version >= MAX_PIN_VERSION:
            raise TLSKeyError("the pin-set version can't go higher")
        promoted = _load_key(before.backup_key_path)
        fresh = _new_private_key()
        after = KeySet(directory, before.version + 1, before.backup_pin, public_key_pin(fresh),
                       before.created_at, time.time())
        _write_private(after.backup_key_path, _key_pem(fresh))
        _write_private(after.cert_path, _self_signed_cert(promoted))
        _write_state(directory, after)
        # The old active key is no longer trusted by anything Kratos hands out;
        # a person asked for this rotation, so the retired key goes now rather
        # than lingering as secret material.
        for retired in (directory / _key_name(before.active_pin), directory / _cert_name(before.active_pin)):
            try:
                retired.unlink()  # deletion-scan: person-initiated `kratos subagent-tls rotate`
            except FileNotFoundError:
                pass
        logger.info("rotated the agent link keys (pin-set version %d -> %d) by %s",
                    before.version, after.version, str(actor)[:80])
        return before, after


def state_stamp(data_dir: Path) -> tuple[int, int] | None:
    """A cheap change marker for the key record (inode, mtime_ns), for the
    listener's watch loop; None when there is none."""
    try:
        st = os.stat(tls_dir(data_dir) / STATE_NAME)
    except OSError:
        return None
    return st.st_ino, st.st_mtime_ns


# ---------------------------------------------------------------------------
# TLS server settings
# ---------------------------------------------------------------------------
def server_context(ks: KeySet) -> ssl.SSLContext:
    """The listener's TLS settings: TLS 1.2+, ECDHE suites, no compression, no
    renegotiation, presenting the active key's certificate. No client
    certificates: an agent proves itself with its token and signed messages."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(pinning.TLS12_CIPHERS)
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(str(ks.cert_path), str(ks.key_path))
    return ctx


def require_encryption(data_dir: Path) -> bool:
    try:
        return bool(settings_store.get(REQUIRE, data_dir=data_dir))
    except Exception:  # noqa: BLE001 -- a broken settings read never takes the listener down
        return False


# ---------------------------------------------------------------------------
# Status: which agents hold which pins
# ---------------------------------------------------------------------------
LINK_TLS = "tls-pinned"
LINK_PLAIN = "plaintext"


def agent_link_rows(store: Any, ks: KeySet | None) -> list[dict[str, Any]]:
    """One row per paired (not unpaired) agent: its last link and pin set."""
    rows = []
    for t in store.list_targets(include_revoked=False):
        mode, ver = t.get("link_mode"), t.get("pin_version")
        if mode == LINK_TLS:
            if ks is not None and ver == ks.version:
                state = "encrypted"
            elif ks is not None and isinstance(ver, int) and ver == ks.version - 1:
                state = "encrypted, previous pins"
            else:
                state = "encrypted, old pins"
        elif mode == LINK_PLAIN:
            state = "plaintext"
        else:
            state = "not connected since this Kratos version"
        rows.append({"target_id": t["target_id"], "name": t.get("name") or t.get("hostname") or t["target_id"],
                     "link_mode": mode, "pin_version": ver, "agent_version": t.get("agent_version"),
                     "state": state})
    return rows


def rotate_blockers(store: Any, ks: KeySet) -> list[dict[str, Any]]:
    """Encrypted agents that don't hold the current pin set yet. Rotating
    again now would leave them with neither key (they hold the key that is
    about to be retired and the one that is active now)."""
    return [r for r in agent_link_rows(store, ks)
            if r["link_mode"] == LINK_TLS and r["pin_version"] != ks.version]


def status(data_dir: Path, store: Any) -> dict[str, Any]:
    """Everything `kratos subagent-tls status`, /doctor and /subagent show."""
    out: dict[str, Any] = {"require": require_encryption(data_dir), "directory": str(tls_dir(data_dir))}
    try:
        ks = load_keys(data_dir)
    except TLSKeyError as e:
        out.update(ok=False, error=str(e), keys=None, agents=agent_link_rows(store, None))
        out["next"] = f"Fix the key folder: {e}"
        return out
    out["ok"] = ks is not None
    out["keys"] = None if ks is None else {
        "version": ks.version, "active": ks.active_pin, "backup": ks.backup_pin,
        "created_at": ks.created_at, "rotated_at": ks.rotated_at,
        "backup_key_path": str(ks.backup_key_path),
    }
    agents = agent_link_rows(store, ks)
    out["agents"] = agents
    plain = [a for a in agents if a["link_mode"] != LINK_TLS]
    behind = [a for a in agents if a["link_mode"] == LINK_TLS and ks is not None and a["pin_version"] != ks.version]
    if ks is None:
        out["next"] = "The keys are made when the listener first starts (or the first installer is made)."
    elif not agents:
        out["next"] = "No agents paired yet. Every installer Kratos makes now carries the pins."
    elif plain and not out["require"]:
        out["next"] = (f"Update {len(plain)} agent(s) still connecting without encryption: /subagent, select it, "
                       "press g. Then turn on 'require encryption' (Settings -> General).")
    elif plain:
        out["next"] = (f"{len(plain)} agent(s) can't connect: encryption is required and they aren't encrypted "
                       "yet. Update each one (/subagent, select it, press g).")
    elif behind:
        out["next"] = (f"{len(behind)} encrypted agent(s) haven't received the current pins yet; they get them "
                       "when they next connect. Don't rotate again until they have.")
    elif not out["require"]:
        out["next"] = "Every agent is encrypted: turn on 'require encryption' (Settings -> General)."
    else:
        out["next"] = "All agents are encrypted and plaintext is refused. Nothing to do."
    return out
