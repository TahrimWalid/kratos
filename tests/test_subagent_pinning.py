"""The agent's server-key pin check (Phase C.4): the stdlib DER walker that finds
a certificate's SubjectPublicKeyInfo, the pin comparison and the TLS client
settings. Certificates are made here with `cryptography` (a Kratos-host
dependency); the walker itself is stdlib-only and also runs on Python 3.8 in
tests/agent_bundle."""
from __future__ import annotations

import hashlib
import random
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from kratos.subagent import pinning


def _cert(key, *, cn: str = "test") -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30)).sign(key, algorithm))
    return cert.public_bytes(serialization.Encoding.DER)


def _spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


KEYS = {
    "p256": lambda: ec.generate_private_key(ec.SECP256R1()),
    "p384": lambda: ec.generate_private_key(ec.SECP384R1()),
    "rsa2048": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "ed25519": ed25519.Ed25519PrivateKey.generate,
}


@pytest.mark.parametrize("kind", sorted(KEYS))
def test_spki_from_real_certificates_equals_cryptographys(kind):
    key = KEYS[kind]()
    der = _cert(key)
    assert pinning.spki_der(der) == _spki(key)
    assert pinning.spki_sha256(der) == hashlib.sha256(_spki(key)).digest()


# --- a tiny DER encoder, to build shapes `cryptography` won't (v1, odd tags) ---
def _tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def _children(buf: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(buf):
        tag, start, stop = pinning._read_tlv(buf, pos, len(buf))
        out.append((tag, buf[start:stop]))
        pos = stop
    return out


def test_a_version_1_certificate_without_the_version_field_still_parses():
    key = KEYS["p256"]()
    der = _cert(key)
    (tag, cert_body), = _children(der)
    tbs, sig_alg, sig = _children(cert_body)
    fields = _children(tbs[1])
    assert fields[0][0] == 0xA0  # cryptography always writes v3
    v1_tbs = _tlv(0x30, b"".join(_tlv(t, c) for t, c in fields[1:]))
    v1 = _tlv(0x30, v1_tbs + _tlv(*sig_alg) + _tlv(*sig))
    assert pinning.spki_der(v1) == _spki(key)


def test_malformed_certificates_are_refused():
    der = _cert(KEYS["p256"]())
    bad = {
        "empty": b"",
        "not bytes": "0\x82",
        "trailing data": der + b"\x00",
        "wrong outer tag": b"\x31" + der[1:],
        "indefinite length": b"\x30\x80" + der[4:] + b"\x00\x00",
        "multi-byte tag": b"\x3f\x01\x00",
        "non-minimal length": b"\x30\x81\x05" + b"\x02\x01\x00\x05\x00",
        "length runs past the end": der[:-1],
        "huge length field": b"\x30\x85\x01\x00\x00\x00\x00",
        "oversized": b"\x30\x83\x01\x00\x00" + b"\x00" * 0x10000,
    }
    for what, blob in bad.items():
        with pytest.raises(pinning.PinError):
            pinning.spki_der(blob)
        assert what


def test_every_truncation_is_refused():
    der = _cert(KEYS["p256"]())
    for n in range(len(der)):
        with pytest.raises(pinning.PinError):
            pinning.spki_der(der[:n])


def test_fuzzed_certificates_fail_closed_never_with_another_error():
    """Random byte flips, insertions and deletions: the walker returns a
    well-formed SPKI slice of the input or raises PinError -- nothing else."""
    rng = random.Random(0xC4)
    certs = [_cert(KEYS[k]()) for k in sorted(KEYS)]
    for trial in range(4000):
        buf = bytearray(rng.choice(certs))
        for _ in range(rng.randint(1, 4)):
            op = rng.random()
            i = rng.randrange(len(buf))
            if op < 0.6:
                buf[i] = rng.randrange(256)
            elif op < 0.8:
                del buf[i]
            else:
                buf.insert(i, rng.randrange(256))
        try:
            out = pinning.spki_der(bytes(buf))
        except pinning.PinError:
            continue
        assert out[0] == 0x30 and out in bytes(buf), trial


def test_pins_match_constant_time_and_never_stop_early(monkeypatch):
    digest = hashlib.sha256(b"key").digest()
    pins = [hashlib.sha256(b"other").hexdigest(), digest.hex(), hashlib.sha256(b"third").hexdigest()]
    calls = []
    real = pinning.hmac.compare_digest

    def counting(a, b):
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(pinning.hmac, "compare_digest", counting)
    assert pinning.pin_matches(digest, pins)
    assert len(calls) == 3  # compared against every pin, not stopped at the match
    calls.clear()
    assert pinning.pin_matches(digest, [digest.hex(), pins[0]]) and len(calls) == 2
    assert not pinning.pin_matches(digest, [pins[0], pins[2]])
    assert not pinning.pin_matches(digest[:31], pins)
    assert not pinning.pin_matches("not bytes", pins)


def test_pin_sets_are_validated():
    a, b = hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"b").hexdigest()
    assert pinning.normalize_pins([a.upper(), b, a]) == [a, b]
    for bad in ([], None, "abc", [a, "xyz"], [a[:-1]], [a, b, *(hashlib.sha256(bytes([i])).hexdigest()
                                                                 for i in range(3))]):
        with pytest.raises(pinning.PinError):
            pinning.normalize_pins(bad)


class _FakeSSL:
    def __init__(self, der):
        self.der = der

    def getpeercert(self, binary_form=False):
        assert binary_form
        return self.der


def test_check_server_pin_accepts_active_and_backup_and_refuses_anything_else():
    active, backup, stranger = (KEYS["p256"]() for _ in range(3))
    pins = [hashlib.sha256(_spki(k)).hexdigest() for k in (active, backup)]
    assert pinning.check_server_pin(_FakeSSL(_cert(active)), pins) == pins[0]
    assert pinning.check_server_pin(_FakeSSL(_cert(backup)), pins) == pins[1]
    with pytest.raises(pinning.PinError, match="isn't the one this agent was given"):
        pinning.check_server_pin(_FakeSSL(_cert(stranger)), pins)
    for broken in (None, _FakeSSL(None), _FakeSSL(b""), _FakeSSL(b"\x30\x00")):
        with pytest.raises(pinning.PinError):
            pinning.check_server_pin(broken, pins)


def test_client_context_is_tls12_plus_ecdhe_with_the_pin_as_the_only_check():
    ctx = pinning.client_context()
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_NONE and ctx.check_hostname is False
    assert ctx.options & ssl.OP_NO_COMPRESSION
    tls12 = [c for c in ctx.get_ciphers() if c["protocol"] == "TLSv1.2"]
    assert tls12 and all("ECDHE" in c["name"] for c in tls12)
    assert all(("GCM" in c["name"] or "CHACHA20" in c["name"]) for c in tls12)
