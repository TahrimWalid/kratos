"""OpenSSH ``SSHSIG`` signatures with Kratos's Ed25519 key (PROTOCOL.sshsig).

A responder verifies a bundle with stock OpenSSH:

    ssh-keygen -Y verify -f allowed_signers -I kratos -n kratos-export -s SHA256SUMS.sig < SHA256SUMS

The format is small. The signed data is::

    byte[6]  "SSHSIG"
    string   namespace
    string   reserved          (empty)
    string   hash_algorithm    ("sha512")
    string   H(message)

and the signature file holds, armored::

    byte[6]  "SSHSIG"
    uint32   1                 (version)
    string   publickey         (ssh-ed25519 wire form)
    string   namespace
    string   reserved
    string   hash_algorithm
    string   signature         (string "ssh-ed25519" + string raw 64-byte signature)
"""
from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAGIC = b"SSHSIG"
VERSION = 1
HASH_ALG = "sha512"
KEY_TYPE = b"ssh-ed25519"
BEGIN = "-----BEGIN SSH SIGNATURE-----"
END = "-----END SSH SIGNATURE-----"
LINE = 70
NAMESPACE = "kratos-export"
PRINCIPAL = "kratos"


class SignatureError(ValueError):
    pass


def _string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _read_string(buf: bytes, pos: int) -> tuple[bytes, int]:
    if pos + 4 > len(buf):
        raise SignatureError("truncated signature")
    (n,) = struct.unpack(">I", buf[pos:pos + 4])
    pos += 4
    if pos + n > len(buf):
        raise SignatureError("truncated signature")
    return buf[pos:pos + n], pos + n


def _pub_blob(pub: Ed25519PublicKey) -> bytes:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _string(KEY_TYPE) + _string(raw)


def signed_data(message: bytes, namespace: str) -> bytes:
    digest = hashlib.sha512(message).digest()
    return MAGIC + _string(namespace.encode("ascii")) + _string(b"") + _string(HASH_ALG.encode("ascii")) + _string(digest)


def sign(message: bytes, key: Ed25519PrivateKey, *, namespace: str = NAMESPACE) -> str:
    """The armored SSHSIG signature of ``message`` (what ``ssh-keygen -Y sign`` writes)."""
    sig = key.sign(signed_data(message, namespace))
    blob = (MAGIC + struct.pack(">I", VERSION) + _string(_pub_blob(key.public_key()))
            + _string(namespace.encode("ascii")) + _string(b"") + _string(HASH_ALG.encode("ascii"))
            + _string(_string(KEY_TYPE) + _string(sig)))
    b64 = base64.b64encode(blob).decode("ascii")
    return BEGIN + "\n" + "\n".join(b64[i:i + LINE] for i in range(0, len(b64), LINE)) + "\n" + END + "\n"


@dataclass(frozen=True)
class Parsed:
    public_key: Ed25519PublicKey
    namespace: str
    hash_alg: str
    signature: bytes

    @property
    def public_openssh(self) -> str:
        return self.public_key.public_bytes(serialization.Encoding.OpenSSH,
                                            serialization.PublicFormat.OpenSSH).decode("ascii")


def parse(armored: str) -> Parsed:
    text = armored.strip()
    if not (text.startswith(BEGIN) and text.endswith(END)):
        raise SignatureError("not an SSH signature (missing the BEGIN/END lines)")
    try:
        blob = base64.b64decode("".join(text[len(BEGIN):-len(END)].split()), validate=True)
    except ValueError as e:
        raise SignatureError(f"signature isn't valid base64: {e}") from e
    if blob[:6] != MAGIC:
        raise SignatureError("not an SSHSIG signature")
    if len(blob) < 10 or struct.unpack(">I", blob[6:10])[0] != VERSION:
        raise SignatureError("unsupported SSHSIG version")
    pos = 10
    pub_blob, pos = _read_string(blob, pos)
    ns, pos = _read_string(blob, pos)
    _reserved, pos = _read_string(blob, pos)
    alg, pos = _read_string(blob, pos)
    sig_blob, pos = _read_string(blob, pos)
    if pos != len(blob):
        raise SignatureError("trailing bytes after the signature")
    ktype, p2 = _read_string(pub_blob, 0)
    raw_pub, p2 = _read_string(pub_blob, p2)
    if ktype != KEY_TYPE or len(raw_pub) != 32 or p2 != len(pub_blob):
        raise SignatureError("only ssh-ed25519 signatures are supported")
    stype, p3 = _read_string(sig_blob, 0)
    raw_sig, p3 = _read_string(sig_blob, p3)
    if stype != KEY_TYPE or len(raw_sig) != 64 or p3 != len(sig_blob):
        raise SignatureError("malformed ssh-ed25519 signature")
    return Parsed(Ed25519PublicKey.from_public_bytes(raw_pub), ns.decode("ascii", "replace"),
                  alg.decode("ascii", "replace"), raw_sig)


def verify(message: bytes, armored: str, *, namespace: str = NAMESPACE,
           allowed_public_keys: list[str] | None = None) -> Parsed:
    """Check the signature (and, given ``allowed_public_keys`` -- OpenSSH key lines --, that it
    was made by one of them). Raises SignatureError; returns the parsed signature."""
    p = parse(armored)
    if p.namespace != namespace:
        raise SignatureError(f"signature namespace is {p.namespace!r}, expected {namespace!r}")
    if p.hash_alg not in ("sha512", "sha256"):
        raise SignatureError(f"unsupported hash algorithm {p.hash_alg!r}")
    if allowed_public_keys is not None:
        mine = p.public_openssh.split()[1]
        if not any(len(k.split()) >= 2 and k.split()[1] == mine for k in allowed_public_keys):
            raise SignatureError("signed by a key that isn't the expected one")
    h = hashlib.sha512 if p.hash_alg == "sha512" else hashlib.sha256
    data = (MAGIC + _string(namespace.encode("ascii")) + _string(b"") + _string(p.hash_alg.encode("ascii"))
            + _string(h(message).digest()))
    try:
        p.public_key.verify(p.signature, data)
    except InvalidSignature as e:
        raise SignatureError("signature does not match the file") from e
    return p


def allowed_signers_line(public_openssh: str, *, principal: str = PRINCIPAL, namespace: str = NAMESPACE) -> str:
    kt, b64 = public_openssh.split()[:2]
    return f'{principal} namespaces="{namespace}" {kt} {b64}\n'
