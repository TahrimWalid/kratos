"""Kratos's Ed25519 signing key (Phase D README §4.5).

Used for Standard Webhooks ``v1a`` signatures (D.4) and, from D.6, OpenSSH ``SSHSIG``
signatures on incident bundles. Never used for the agent link or SSH logins.

Files, in ``data_dir/signing/`` (folder 0700, private files 0600):

  ed25519.key            the active private key (PKCS#8 PEM)
  ed25519.pub            its public key, OpenSSH form (``ssh-ed25519 AAAA... kratos-signing``)
  backup/ed25519-<fp>.key  a copy of every private key made at creation
  retired/ed25519-<fp>.pub the public keys of rotated-out keys, so old signatures still verify

The key is created on first use. ``rotate`` makes a new active key and keeps the old
public key in ``retired/`` (and its private copy in ``backup/``).
"""
from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

FOLDER = "signing"
KEY_FILE = "ed25519.key"
PUB_FILE = "ed25519.pub"
COMMENT = "kratos-signing"


def folder(data_dir: Path | str) -> Path:
    return Path(data_dir) / FOLDER


def _ensure_dir(p: Path) -> Path:
    from kratos import paths

    paths.ensure_private_dir(p)
    return p


def _write_private_bytes(path: Path, data: bytes) -> None:
    from kratos import paths

    paths.write_private_text(path, data.decode("ascii"))


def _openssh_pub(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode("ascii")


def _raw_pub(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint_of(pub: Ed25519PublicKey) -> str:
    """OpenSSH-style ``SHA256:<base64 without padding>`` of the key's wire form."""
    blob = base64.b64decode(_openssh_pub(pub).split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def _fp_slug(pub: Ed25519PublicKey) -> str:
    return hashlib.sha256(_raw_pub(pub)).hexdigest()[:16]


def _create(data_dir: Path | str) -> Ed25519PrivateKey:
    d = _ensure_dir(folder(data_dir))
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    slug = _fp_slug(key.public_key())
    _write_private_bytes(_ensure_dir(d / "backup") / f"ed25519-{slug}.key", pem)   # backup first
    _write_private_bytes(d / KEY_FILE, pem)
    (d / PUB_FILE).write_text(_openssh_pub(key.public_key()) + f" {COMMENT}\n", encoding="ascii")
    return key


def load_key(data_dir: Path | str, *, create: bool = True) -> Ed25519PrivateKey | None:
    """The active private key; created on first use when ``create``."""
    p = folder(data_dir) / KEY_FILE
    if not p.exists():
        return _create(data_dir) if create else None
    key = serialization.load_pem_private_key(p.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{p} is not an Ed25519 key")
    return key


def sign(data: bytes, data_dir: Path | str) -> bytes:
    """A raw 64-byte Ed25519 signature of ``data`` with the active key."""
    key = load_key(data_dir)
    assert key is not None
    return key.sign(data)


@dataclass(frozen=True)
class KeyInfo:
    fingerprint: str
    public_openssh: str
    public_whpk: str              # Standard Webhooks form: whpk_<base64 raw key>
    created_at: float | None


def info(data_dir: Path | str, *, create: bool = False) -> KeyInfo | None:
    key = load_key(data_dir, create=create)
    if key is None:
        return None
    pub = key.public_key()
    try:
        created = (folder(data_dir) / KEY_FILE).stat().st_mtime
    except OSError:
        created = None
    return KeyInfo(fingerprint_of(pub), _openssh_pub(pub) + f" {COMMENT}", public_key_whpk(data_dir), created)


def public_key_openssh(data_dir: Path | str) -> str:
    key = load_key(data_dir)
    assert key is not None
    return _openssh_pub(key.public_key()) + f" {COMMENT}"


def public_key_whpk(data_dir: Path | str) -> str:
    key = load_key(data_dir)
    assert key is not None
    return "whpk_" + base64.b64encode(_raw_pub(key.public_key())).decode("ascii")


def retired_public_keys(data_dir: Path | str) -> list[str]:
    d = folder(data_dir) / "retired"
    if not d.is_dir():
        return []
    return [p.read_text(encoding="ascii").strip() for p in sorted(d.glob("ed25519-*.pub"))]


def rotate(data_dir: Path | str) -> KeyInfo:
    """A new active key; the old public key goes to ``retired/`` (still verifiable), its
    private copy stays in ``backup/``. A person's command (``kratos signing rotate``)."""
    old = load_key(data_dir, create=False)
    d = folder(data_dir)
    if old is not None:
        retired = _ensure_dir(d / "retired")
        (retired / f"ed25519-{_fp_slug(old.public_key())}.pub").write_text(
            _openssh_pub(old.public_key()) + f" {COMMENT} retired {int(time.time())}\n", encoding="ascii")
    _create(data_dir)
    out = info(data_dir)
    assert out is not None
    return out


def verify(signature: bytes, data: bytes, public_openssh: str) -> bool:
    """Check a signature against an OpenSSH public key line (for tests and receivers)."""
    from cryptography.exceptions import InvalidSignature

    pub = serialization.load_ssh_public_key(" ".join(public_openssh.split()[:2]).encode("ascii"))
    if not isinstance(pub, Ed25519PublicKey):
        return False
    try:
        pub.verify(signature, data)
        return True
    except InvalidSignature:
        return False
