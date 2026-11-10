"""The age v1 implementation (kratos.backup.agefmt) against the C2SP CCTV vectors, plus
the encryption direction and the spec's rules the vectors can't show (docs/phaseD/D.8 §7)."""
from __future__ import annotations

import hashlib
import io
import zlib
from pathlib import Path

import pytest

from kratos.backup import agefmt as A

VECTORS = Path(__file__).parent / "fixtures" / "age_cctv" / "testdata"


def _load(path: Path) -> tuple[dict[str, list[str]], bytes]:
    data = path.read_bytes()
    head, _, body = data.partition(b"\n\n")
    meta: dict[str, list[str]] = {}
    for line in head.decode().splitlines():
        k, _, v = line.partition(": ")
        meta.setdefault(k, []).append(v)
    if meta.get("compressed") == ["zlib"]:
        body = zlib.decompress(body)
    return meta, body


ALL = sorted(p.name for p in VECTORS.iterdir())


def test_the_vectors_are_all_there():
    assert len(ALL) == 147


def _identities(meta: dict[str, list[str]]) -> list[object]:
    out: list[object] = [A.X25519Identity.parse(i) for i in meta.get("identity", [])
                         if not i.startswith("AGE-SECRET-KEY-PQ-")]
    out += [A.ScryptIdentity(p.encode()) for p in meta.get("passphrase", [])]
    return out


@pytest.mark.parametrize("name", ALL)
def test_cctv_vector(name):
    meta, body = _load(VECTORS / name)
    if any(i.startswith("AGE-SECRET-KEY-PQ-") for i in meta.get("identity", [])):
        pytest.skip("post-quantum identity (mlkem768x25519 is not implemented)")
    expect = meta["expect"][0]
    released = bytearray()
    try:
        if meta.get("armored") == ["yes"]:
            body = A.dearmor(body)
        A.decrypt(io.BytesIO(body), _identities(meta), released.extend)
        got = "success"
    except A.AgeError as e:
        got = e.expect
    assert got == expect, f"{name}: {meta.get('comment', [''])[0]}"
    if "payload" in meta:
        assert hashlib.sha256(released).hexdigest() == meta["payload"][0]


def test_how_many_vectors_ran():
    pq = [n for n in ALL if any(i.startswith("AGE-SECRET-KEY-PQ-") for i in _load(VECTORS / n)[0].get("identity", []))]
    assert len(ALL) - len(pq) >= 120   # every vector without a post-quantum identity runs


# --- the encryption direction ------------------------------------------------------
@pytest.mark.parametrize("size", [0, 1, A.CHUNK - 1, A.CHUNK, A.CHUNK + 1, 2 * A.CHUNK, 3 * A.CHUNK + 5])
def test_round_trip_x25519_at_chunk_edges(size):
    ident = A.X25519Identity.generate()
    data = bytes(range(256)) * (size // 256 + 1)
    data = data[:size]
    enc = A.encrypt_bytes(data, [ident.recipient()])
    assert A.decrypt_bytes(enc, [ident]) == data
    # chunk count: one final chunk even when empty; a multiple of 64 KiB ends with a full final chunk
    header, hlen = A.read_header_only(io.BytesIO(enc))
    payload = len(enc) - hlen - A.NONCE_LEN
    chunks = max(1, -(-size // A.CHUNK))
    assert payload == size + chunks * A.TAG


def test_several_recipients_each_open_it():
    ids = [A.X25519Identity.generate() for _ in range(5)]
    enc = A.encrypt_bytes(b"hello", [i.recipient() for i in ids])
    for i in ids:
        assert A.decrypt_bytes(enc, [i]) == b"hello"
    with pytest.raises(A.NoMatchError):
        A.decrypt_bytes(enc, [A.X25519Identity.generate()])


def test_passphrase_round_trip_and_wrong_passphrase():
    enc = A.encrypt_bytes(b"x" * 100, [A.ScryptRecipient(b"correct horse battery", work_factor=10)])
    assert A.decrypt_bytes(enc, [A.ScryptIdentity(b"correct horse battery")]) == b"x" * 100
    with pytest.raises(A.NoMatchError):
        A.decrypt_bytes(enc, [A.ScryptIdentity(b"wrong")])


def test_scrypt_is_refused_alongside_another_recipient():
    with pytest.raises(ValueError, match="passphrase"):
        A.Encryptor(io.BytesIO(), [A.ScryptRecipient(b"p" * 20), A.X25519Identity.generate().recipient()])


def test_scrypt_work_factor_above_the_limit_is_refused_both_ways():
    with pytest.raises(ValueError):
        A.ScryptRecipient(b"p" * 20, work_factor=23)
    enc = A.encrypt_bytes(b"x", [A.ScryptRecipient(b"pass", work_factor=12)])
    with pytest.raises(A.HeaderError, match="above the limit"):
        A.decrypt_bytes(enc, [A.ScryptIdentity(b"pass", max_work_factor=11)])


def test_the_default_work_factor_is_ages():
    assert A.SCRYPT_DEFAULT_WORK_FACTOR == 18 and A.SCRYPT_MAX_WORK_FACTOR == 22


def test_a_stanza_body_of_exactly_64_columns_ends_with_an_empty_line():
    s = A.Stanza([b"x"], bytes(48))  # 48 bytes -> 64 base64 characters
    assert s.encode().endswith(b"\n\n")
    assert A.Stanza([b"x"], bytes(47)).encode().count(b"\n") == 2


def test_one_flipped_byte_fails_at_its_chunk():
    ident = A.X25519Identity.generate()
    data = b"a" * (3 * A.CHUNK + 10)
    enc = bytearray(A.encrypt_bytes(data, [ident.recipient()]))
    _, hlen = A.read_header_only(io.BytesIO(bytes(enc)))
    enc[hlen + A.NONCE_LEN + A.ENC_CHUNK * 2 + 7] ^= 1   # inside chunk 2
    out = bytearray()
    with pytest.raises(A.PayloadError) as e:
        A.decrypt(io.BytesIO(bytes(enc)), [ident], out.extend)
    assert e.value.chunk == 2 and len(out) == 2 * A.CHUNK


def test_truncation_at_a_chunk_boundary_is_caught():
    ident = A.X25519Identity.generate()
    enc = A.encrypt_bytes(b"b" * (2 * A.CHUNK + 1), [ident.recipient()])
    _, hlen = A.read_header_only(io.BytesIO(enc))
    cut = enc[:hlen + A.NONCE_LEN + A.ENC_CHUNK]       # drop everything after chunk 0
    with pytest.raises(A.PayloadError, match="truncated"):
        A.decrypt_bytes(cut, [ident])


def test_header_change_is_an_hmac_failure():
    ident = A.X25519Identity.generate()
    other = A.X25519Identity.generate()
    enc = A.encrypt_bytes(b"x", [ident.recipient(), other.recipient()])
    # drop the second stanza: still parses, still opens, but the MAC no longer matches
    text = enc.split(b"\n")
    stanza_lines = [i for i, line in enumerate(text) if line.startswith(b"-> ")]
    del text[stanza_lines[1]:stanza_lines[1] + 2]
    with pytest.raises(A.HMACError):
        A.decrypt_bytes(b"\n".join(text), [ident])


@pytest.mark.parametrize("text", ["", "age1", "AGE-SECRET-KEY-1", "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"])
def test_identity_parse_rejects_non_identities(text):
    with pytest.raises(ValueError):
        A.X25519Identity.parse(text)


def test_the_specs_example_keys_are_a_pair():
    ident = A.X25519Identity.parse("AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX")
    assert str(ident.recipient()) == "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
    assert A.X25519Recipient.parse(str(ident.recipient())) == ident.recipient()
    with pytest.raises(ValueError):
        A.X25519Recipient.parse("AGE1ZVKYG2LQZRAA2LNJVQEJ32NKUU0UES2S82HZRYE869XEEXVN73EQUNUJWJ")  # recipients are lower case
    with pytest.raises(ValueError):
        A.bech32_decode("age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwJ")  # mixed case
