"""
Server-key pinning for the agent's encrypted link to Kratos (Phase C.4).

The agent dials Kratos over TLS and accepts the server only if the hash of the
server certificate's public key (its SubjectPublicKeyInfo, SPKI) is one the
agent was given: Kratos's active key or its backup key. There is no CA and no
hostname check -- the pin replaces both. The TLS handshake itself proves the
server holds the private half of the key in its certificate (the server signs
the handshake with it), so a matching SPKI hash means "this is the Kratos this
agent was paired with", whatever network sits in between.

The agent writes NO protocol byte (no hello, no token, no pairing code) before
`check_server_pin` has passed on the established TLS connection.

Stdlib-only, Python 3.8: this file ships in the agent bundle. The standard
library can't parse a certificate, so `spki_der` is a small DER walker that
reads only as far as the SubjectPublicKeyInfo and fails closed on anything
unexpected (bad tags, indefinite or non-minimal lengths, lengths past the end,
trailing bytes).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import ssl
from typing import Any, Iterable

# A real certificate is a few KB; a chain-less self-signed one well under 2 KB.
MAX_CERT_BYTES = 64 * 1024
# How many pins an agent holds at once: the active key and a backup, with room
# for one more during a rotation. Never zero.
MAX_PINS = 4
_PIN_RE = re.compile(r"^[0-9a-f]{64}$")

# ASN.1 DER tags used below (universal class).
_SEQUENCE = 0x30
_INTEGER = 0x02
_BIT_STRING = 0x03
_VERSION_TAG = 0xA0  # [0] EXPLICIT, constructed -- TBSCertificate.version


class PinError(ValueError):
    """A certificate couldn't be parsed, or its key isn't a pinned one."""


# ---------------------------------------------------------------------------
# DER walker
# ---------------------------------------------------------------------------
def _read_tlv(buf: bytes, pos: int, end: int) -> "tuple[int, int, int]":
    """One DER element at `pos` (which must lie before `end`): returns
    (tag, content_start, content_end). Raises PinError for anything that
    isn't plain, minimal, definite-length DER inside [pos, end)."""
    if pos + 2 > end:
        raise PinError("certificate ends inside an element header")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise PinError("multi-byte tag in certificate")
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise PinError("indefinite length in certificate (not DER)")
    else:
        n = first & 0x7F
        if n > 4:
            raise PinError("length field too long in certificate")
        if pos + n > end:
            raise PinError("certificate ends inside a length field")
        raw = buf[pos:pos + n]
        if raw[0] == 0:
            raise PinError("non-minimal length in certificate (not DER)")
        length = int.from_bytes(raw, "big")
        if length < 0x80:
            raise PinError("non-minimal length in certificate (not DER)")
        pos += n
    if pos + length > end:
        raise PinError("element runs past the end of the certificate")
    return tag, pos, pos + length


def _expect(buf: bytes, pos: int, end: int, tag: int, what: str) -> "tuple[int, int]":
    got, start, stop = _read_tlv(buf, pos, end)
    if got != tag:
        raise PinError(f"certificate: expected {what} (tag 0x{tag:02x}), found tag 0x{got:02x}")
    return start, stop


def spki_der(der_cert: bytes) -> bytes:
    """The SubjectPublicKeyInfo element of an X.509 certificate, exactly as
    encoded (tag and length included) -- the bytes an SPKI pin hashes.

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
                                  issuer, validity, subject, subjectPublicKeyInfo, ... }"""
    if not isinstance(der_cert, (bytes, bytearray)):
        raise PinError("certificate is not bytes")
    buf = bytes(der_cert)
    if not buf:
        raise PinError("empty certificate")
    if len(buf) > MAX_CERT_BYTES:
        raise PinError(f"certificate is larger than {MAX_CERT_BYTES} bytes")
    cert_start, cert_end = _expect(buf, 0, len(buf), _SEQUENCE, "Certificate")
    if cert_end != len(buf):
        raise PinError("trailing bytes after the certificate")
    tbs_start, tbs_end = _expect(buf, cert_start, cert_end, _SEQUENCE, "TBSCertificate")
    # signatureAlgorithm and signatureValue must follow, and nothing else.
    _, sig_alg_end = _expect(buf, tbs_end, cert_end, _SEQUENCE, "signatureAlgorithm")
    _, sig_end = _expect(buf, sig_alg_end, cert_end, _BIT_STRING, "signatureValue")
    if sig_end != cert_end:
        raise PinError("unexpected data after the certificate signature")

    pos = tbs_start
    tag, _, stop = _read_tlv(buf, pos, tbs_end)
    if tag == _VERSION_TAG:
        pos = stop
    _, pos = _expect(buf, pos, tbs_end, _INTEGER, "serialNumber")
    for what in ("signature algorithm", "issuer", "validity", "subject"):
        _, pos = _expect(buf, pos, tbs_end, _SEQUENCE, what)
    spki_start = pos
    inner_start, spki_end = _expect(buf, pos, tbs_end, _SEQUENCE, "subjectPublicKeyInfo")
    # SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    _, alg_end = _expect(buf, inner_start, spki_end, _SEQUENCE, "public key algorithm")
    key_start, key_end = _expect(buf, alg_end, spki_end, _BIT_STRING, "public key")
    if key_end != spki_end:
        raise PinError("unexpected data inside subjectPublicKeyInfo")
    if key_end - key_start < 2 or buf[key_start] != 0:
        raise PinError("malformed public key bit string")
    return buf[spki_start:spki_end]


def spki_sha256(der_cert: bytes) -> bytes:
    """SHA-256 of the certificate's SubjectPublicKeyInfo (the pinned value)."""
    return hashlib.sha256(spki_der(der_cert)).digest()


# ---------------------------------------------------------------------------
# Pins
# ---------------------------------------------------------------------------
def normalize_pin(value: Any) -> str:
    """A pin as 64 lowercase hex characters; raises PinError otherwise."""
    if not isinstance(value, str):
        raise PinError("a server key pin must be text")
    pin = value.strip().lower()
    if not _PIN_RE.fullmatch(pin):
        raise PinError("a server key pin is 64 hex characters (a SHA-256 of the key)")
    return pin


def normalize_pins(values: Iterable[Any]) -> "list[str]":
    """A pin set: 1..MAX_PINS distinct valid pins, order kept. Never empty."""
    if isinstance(values, (str, bytes)) or values is None:
        raise PinError("a pin set is a list of pins")
    out: list[str] = []
    for v in values:
        pin = normalize_pin(v)
        if pin not in out:
            out.append(pin)
    if not out:
        raise PinError("a pin set can't be empty")
    if len(out) > MAX_PINS:
        raise PinError(f"a pin set holds at most {MAX_PINS} pins")
    return out


def pin_matches(digest: bytes, pins: Iterable[str]) -> bool:
    """Is `digest` (raw SHA-256 bytes) one of `pins`? Compares against every
    pin with hmac.compare_digest and never stops early."""
    if not isinstance(digest, (bytes, bytearray)) or len(digest) != 32:
        return False
    matched = False
    for pin in pins:
        try:
            want = bytes.fromhex(pin)
        except (TypeError, ValueError):
            continue
        if hmac.compare_digest(bytes(digest), want):
            matched = True
    return matched


def check_server_pin(ssl_object: Any, pins: Iterable[str]) -> str:
    """Check an established TLS connection's server key against `pins`.
    Returns the matching pin (hex); raises PinError when the server sent no
    certificate, the certificate can't be parsed, or its key isn't pinned."""
    if ssl_object is None:
        raise PinError("the connection to Kratos is not encrypted")
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        raise PinError("the server sent no certificate")
    digest = spki_sha256(der)
    if not pin_matches(digest, pins):
        raise PinError(f"the server's key ({digest.hex()[:16]}...) isn't the one this agent was given")
    return digest.hex()


# ---------------------------------------------------------------------------
# TLS client
# ---------------------------------------------------------------------------
# ECDHE key exchange only (forward secrecy); TLS 1.3 suites are all ECDHE-style
# and stay enabled. AES-GCM and ChaCha20-Poly1305 only.
TLS12_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL"


def client_context() -> ssl.SSLContext:
    """The agent's TLS settings: TLS 1.2 or newer (1.3 preferred), ECDHE
    suites, no compression, no renegotiation. Chain and hostname checks are
    off ON PURPOSE: there is no CA here -- `check_server_pin`, run before any
    protocol byte is written, is the check."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(TLS12_CIPHERS)
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    return ctx
