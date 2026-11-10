"""The age v1 file format (C2SP age.md), written and read with `cryptography`'s primitives.

This module implements the *format* -- header, recipient stanzas, header MAC, the STREAM
payload and read-only ASCII armor -- and nothing else. Every cryptographic operation is a
vetted primitive from `cryptography` (X25519, ChaCha20-Poly1305, HKDF-SHA-256,
HMAC-SHA-256, scrypt); no construction is used that the spec doesn't define. It has no
Kratos imports so it can be read and tested on its own.

Recipient types: X25519 (`age1…` / `AGE-SECRET-KEY-1…`) and scrypt (a passphrase). The
post-quantum `mlkem768x25519` type is not offered: `cryptography` 49 exposes HPKE with the
X-Wing KEM but not the age identity's 32-byte seed form, and building that key from ML-KEM
plus X25519 by hand is exactly what docs/phaseD/D.8 §3.2 rules out. Stanzas of other types
are ignored, as the spec says.

Checked against the C2SP CCTV age vectors (tests/fixtures/age_cctv/) and round-tripped
with the real `age` binary. Every failure raises a subclass of `AgeError` whose `expect`
matches the vectors' names: header / no match / HMAC / payload / armor.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import os
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import BinaryIO, Callable, Iterable, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSION_LINE = b"age-encryption.org/v1"
CHUNK = 64 * 1024
TAG = 16
ENC_CHUNK = CHUNK + TAG
FILE_KEY_LEN = 16
NONCE_LEN = 16
MAX_HEADER = 1 << 20              # far above any real header (a stanza is < 2 KB)
SCRYPT_DEFAULT_WORK_FACTOR = 18   # the age CLI's default (checked against age 1.3.2 at build time)
SCRYPT_MAX_WORK_FACTOR = 22       # the age CLI's limit when decrypting
ARMOR_BEGIN = b"-----BEGIN AGE ENCRYPTED FILE-----"
ARMOR_END = b"-----END AGE ENCRYPTED FILE-----"
_ZERO_NONCE = bytes(12)
_B64_CHARS = re.compile(rb"^[A-Za-z0-9+/]*$")
_WF_RE = re.compile(rb"^[1-9][0-9]*$")


class AgeError(Exception):
    expect = "failure"


class HeaderError(AgeError):
    expect = "header failure"


class NoMatchError(AgeError):
    expect = "no match"


class HMACError(AgeError):
    expect = "HMAC failure"


class PayloadError(AgeError):
    expect = "payload failure"

    def __init__(self, message: str, *, chunk: int | None = None, released: int = 0) -> None:
        super().__init__(message)
        self.chunk = chunk          # 0-based index of the chunk that failed
        self.released = released    # plaintext bytes already handed out before the failure


class ArmorError(AgeError):
    expect = "armor failure"


# --------------------------------------------------------------------------- encodings
def b64encode_raw(data: bytes) -> bytes:
    return base64.b64encode(data).rstrip(b"=")


def b64decode_raw(text: bytes, *, what: str = "value") -> bytes:
    """Canonical unpadded base64 (RFC 4648 §3.5); anything else is a header failure."""
    if not _B64_CHARS.match(text):
        raise HeaderError(f"{what}: not unpadded base64")
    if len(text) % 4 == 1:
        raise HeaderError(f"{what}: bad base64 length")
    try:
        out = base64.b64decode(text + b"=" * (-len(text) % 4), validate=True)
    except binascii.Error as e:
        raise HeaderError(f"{what}: bad base64 ({e})") from None
    if b64encode_raw(out) != text:
        raise HeaderError(f"{what}: base64 is not canonical")
    return out


_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: Iterable[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data: Iterable[int], frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for v in data:
        if v < 0 or v >> frombits:
            raise ValueError("bad value")
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("non-zero padding")
    return out


def bech32_encode(hrp: str, data: bytes, *, upper: bool = False) -> str:
    hrp = hrp.lower()
    values = _convertbits(data, 8, 5, True)
    polymod = _polymod(_hrp_expand(hrp) + values + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    text = hrp + "1" + "".join(_BECH32[d] for d in values + checksum)
    return text.upper() if upper else text


def bech32_decode(text: str) -> tuple[str, bytes]:
    """(hrp, data). BIP173 without the length limit; all upper or all lower case."""
    if text != text.lower() and text != text.upper():
        raise ValueError("mixed case")
    if any(ord(c) < 33 or ord(c) > 126 for c in text):
        raise ValueError("bad character")
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        raise ValueError("no separator or too short")
    hrp, rest = text[:pos], text[pos + 1:]
    try:
        values = [_BECH32.index(c) for c in rest]
    except ValueError:
        raise ValueError("bad character") from None
    if _polymod(_hrp_expand(hrp) + values) != 1:
        raise ValueError("bad checksum")
    return hrp, bytes(_convertbits(values[:-6], 5, 8, False))


# --------------------------------------------------------------------------- keys
def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


class X25519Identity:
    """An `AGE-SECRET-KEY-1…` identity. Keep `secret` off the Kratos host."""

    HRP = "age-secret-key-"

    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32:
            raise ValueError("an X25519 identity is 32 bytes")
        self._key = X25519PrivateKey.from_private_bytes(raw)
        self._raw = raw

    @classmethod
    def generate(cls) -> "X25519Identity":
        return cls(os.urandom(32))

    @classmethod
    def parse(cls, text: str) -> "X25519Identity":
        text = text.strip()
        try:
            hrp, data = bech32_decode(text)
        except ValueError as e:
            raise ValueError(f"not an age identity ({e})") from None
        if hrp != cls.HRP or text != text.upper():
            raise ValueError("not an age X25519 identity (AGE-SECRET-KEY-1…)")
        return cls(data)

    @property
    def secret(self) -> str:
        return bech32_encode(self.HRP, self._raw, upper=True)

    def recipient(self) -> "X25519Recipient":
        from cryptography.hazmat.primitives import serialization

        pub = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return X25519Recipient(pub)

    def unwrap(self, stanza: "Stanza") -> bytes | None:
        if not stanza.args or stanza.args[0] != b"X25519":
            return None
        if len(stanza.args) != 2:
            raise HeaderError("X25519 stanza: wrong number of arguments")
        share = b64decode_raw(stanza.args[1], what="X25519 share")
        if len(share) != 32:
            raise HeaderError("X25519 stanza: share is not 32 bytes")
        if len(stanza.body) != FILE_KEY_LEN + TAG:
            raise HeaderError("X25519 stanza: body is not 32 bytes")
        try:
            shared = self._key.exchange(X25519PublicKey.from_public_bytes(share))
        except ValueError:   # cryptography refuses the all-zero (low-order) result itself
            shared = bytes(32)
        if not any(shared):
            raise HeaderError("X25519 stanza: the share gives an all-zero secret")
        key = _hkdf(shared, share + self.recipient().raw, b"age-encryption.org/v1/X25519")
        try:
            return ChaCha20Poly1305(key).decrypt(_ZERO_NONCE, stanza.body, None)
        except InvalidTag:
            return None


class X25519Recipient:
    """An `age1…` recipient (the public half)."""

    HRP = "age"

    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32:
            raise ValueError("an X25519 recipient is 32 bytes")
        self.raw = raw

    @classmethod
    def parse(cls, text: str) -> "X25519Recipient":
        text = text.strip()
        try:
            hrp, data = bech32_decode(text)
        except ValueError as e:
            raise ValueError(f"not an age recipient ({e})") from None
        if hrp != cls.HRP or text != text.lower():
            raise ValueError("not an age X25519 recipient (age1…)")
        return cls(data)

    def __str__(self) -> str:
        return bech32_encode(self.HRP, self.raw)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, X25519Recipient) and other.raw == self.raw

    def __hash__(self) -> int:
        return hash(self.raw)

    def wrap(self, file_key: bytes) -> "Stanza":
        from cryptography.hazmat.primitives import serialization

        eph = X25519PrivateKey.generate()
        share = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared = eph.exchange(X25519PublicKey.from_public_bytes(self.raw))
        key = _hkdf(shared, share + self.raw, b"age-encryption.org/v1/X25519")
        body = ChaCha20Poly1305(key).encrypt(_ZERO_NONCE, file_key, None)
        return Stanza([b"X25519", b64encode_raw(share)], body)


def _scrypt_key(passphrase: bytes, salt: bytes, work_factor: int) -> bytes:
    return Scrypt(salt=b"age-encryption.org/v1/scrypt" + salt, length=32, n=1 << work_factor, r=8,
                  p=1).derive(passphrase)


class ScryptRecipient:
    """Passphrase encryption. A file with an scrypt stanza has no other stanza."""

    def __init__(self, passphrase: bytes, work_factor: int = SCRYPT_DEFAULT_WORK_FACTOR) -> None:
        if not passphrase:
            raise ValueError("empty passphrase")
        if not 1 <= work_factor <= SCRYPT_MAX_WORK_FACTOR:
            raise ValueError(f"scrypt work factor must be 1..{SCRYPT_MAX_WORK_FACTOR}")
        self._passphrase = passphrase
        self.work_factor = work_factor

    def wrap(self, file_key: bytes) -> "Stanza":
        salt = os.urandom(16)
        key = _scrypt_key(self._passphrase, salt, self.work_factor)
        body = ChaCha20Poly1305(key).encrypt(_ZERO_NONCE, file_key, None)
        return Stanza([b"scrypt", b64encode_raw(salt), str(self.work_factor).encode()], body)


class ScryptIdentity:
    def __init__(self, passphrase: bytes, max_work_factor: int = SCRYPT_MAX_WORK_FACTOR) -> None:
        self._passphrase = passphrase
        self.max_work_factor = max_work_factor

    def unwrap(self, stanza: "Stanza") -> bytes | None:
        if not stanza.args or stanza.args[0] != b"scrypt":
            return None
        if len(stanza.args) != 3:
            raise HeaderError("scrypt stanza: wrong number of arguments")
        salt = b64decode_raw(stanza.args[1], what="scrypt salt")
        if len(salt) != 16:
            raise HeaderError("scrypt stanza: salt is not 16 bytes")
        if not _WF_RE.match(stanza.args[2]):
            raise HeaderError("scrypt stanza: work factor is not a plain decimal number")
        wf = int(stanza.args[2])
        if wf > self.max_work_factor:
            raise HeaderError(f"scrypt stanza: work factor {wf} is above the limit {self.max_work_factor}")
        if len(stanza.body) != FILE_KEY_LEN + TAG:
            raise HeaderError("scrypt stanza: body is not 32 bytes")
        try:
            return ChaCha20Poly1305(_scrypt_key(self._passphrase, salt, wf)).decrypt(_ZERO_NONCE, stanza.body, None)
        except InvalidTag:
            return None


Recipient = "X25519Recipient | ScryptRecipient"
Identity = "X25519Identity | ScryptIdentity"


# --------------------------------------------------------------------------- header
@dataclass
class Stanza:
    args: list[bytes]
    body: bytes

    def encode(self) -> bytes:
        out = b"-> " + b" ".join(self.args) + b"\n"
        text = b64encode_raw(self.body)
        for i in range(0, len(text), 64):
            out += text[i:i + 64] + b"\n"
        if len(text) % 64 == 0:
            out += b"\n"   # the body must end with a line shorter than 64 columns
        return out


@dataclass
class Header:
    stanzas: list[Stanza]
    mac: bytes
    raw_for_mac: bytes   # the header up to and including "---"


def _mac_key(file_key: bytes) -> bytes:
    return _hkdf(file_key, b"", b"header")


def encode_header(stanzas: Sequence[Stanza], file_key: bytes) -> bytes:
    raw = VERSION_LINE + b"\n" + b"".join(s.encode() for s in stanzas) + b"---"
    mac = hmac.new(_mac_key(file_key), raw, sha256).digest()
    return raw + b" " + b64encode_raw(mac) + b"\n"


class _Reader:
    """Buffered reads from a binary stream; tracks every byte consumed by the header."""

    def __init__(self, stream: BinaryIO) -> None:
        self._s = stream
        self._buf = b""
        self.header_bytes = 0

    def line(self) -> bytes:
        """One line without its LF; a header failure at EOF or past the size limit."""
        while b"\n" not in self._buf:
            more = self._s.read(4096)
            if not more:
                raise HeaderError("unexpected end of file in the header")
            self._buf += more
            if len(self._buf) > MAX_HEADER:
                raise HeaderError("header too long")
        i = self._buf.index(b"\n")
        out, self._buf = self._buf[:i], self._buf[i + 1:]
        self.header_bytes += i + 1
        if self.header_bytes > MAX_HEADER:
            raise HeaderError("header too long")
        return out

    def read(self, n: int) -> bytes:
        """Up to n payload bytes (fewer only at end of file)."""
        while len(self._buf) < n:
            more = self._s.read(max(n - len(self._buf), 65536))
            if not more:
                break
            self._buf += more
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


def _valid_arg(arg: bytes) -> bool:
    return bool(arg) and all(0x21 <= c <= 0x7E for c in arg)


def parse_header(r: _Reader) -> Header:
    if r.line() != VERSION_LINE:
        raise HeaderError("not an age v1 file (unknown or missing version line)")
    raw = VERSION_LINE + b"\n"
    stanzas: list[Stanza] = []
    line = r.line()
    while True:
        if line.startswith(b"-> "):
            args = line[3:].split(b" ")
            if not all(_valid_arg(a) for a in args):
                raise HeaderError("stanza: an empty or invalid argument")
            raw += line + b"\n"
            body_text = b""
            while True:
                bl = r.line()
                if len(bl) > 64 or not _B64_CHARS.match(bl):
                    raise HeaderError("stanza body: not a base64 line of at most 64 columns")
                raw += bl + b"\n"
                body_text += bl
                if len(bl) < 64:
                    break
            stanzas.append(Stanza(args, b64decode_raw(body_text, what="stanza body")))
            line = r.line()
            continue
        if line.startswith(b"---"):
            if not line.startswith(b"--- "):
                raise HeaderError("header MAC line: no space after ---")
            if not stanzas:
                raise HeaderError("header has no recipient stanza")
            mac_text = line[4:]
            if len(mac_text) != 43:
                raise HeaderError("header MAC: not 43 base64 characters")
            mac = b64decode_raw(mac_text, what="header MAC")
            return Header(stanzas, mac, raw + b"---")
        raise HeaderError("header: a line that is neither a stanza nor the MAC")


def _unwrap(header: Header, identities: Sequence[object]) -> bytes:
    if any(s.args and s.args[0] == b"scrypt" for s in header.stanzas) and len(header.stanzas) != 1:
        raise HeaderError("an scrypt stanza must be the only stanza in the header")
    for stanza in header.stanzas:
        for ident in identities:
            key = ident.unwrap(stanza)  # type: ignore[attr-defined]
            if key is not None:
                if len(key) != FILE_KEY_LEN:
                    raise HeaderError("the unwrapped file key is not 16 bytes")
                return key
    raise NoMatchError("none of the keys given can open this file (no matching recipient)")


# --------------------------------------------------------------------------- payload
def _chunk_nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


class Encryptor:
    """Write an age file: `w = Encryptor(out, recipients); w.write(...); w.close()`.
    Nothing is written in plaintext; `close()` writes the final chunk (it does not close
    `out`)."""

    def __init__(self, out: BinaryIO, recipients: Sequence[object]) -> None:
        if not recipients:
            raise ValueError("at least one recipient is needed")
        if any(isinstance(r, ScryptRecipient) for r in recipients) and len(recipients) != 1:
            raise ValueError("a passphrase can't be combined with other recipients (age spec)")
        file_key = os.urandom(FILE_KEY_LEN)
        stanzas = [r.wrap(file_key) for r in recipients]  # type: ignore[attr-defined]
        nonce = os.urandom(NONCE_LEN)
        self._out = out
        self._aead = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
        self._buf = bytearray()
        self._counter = 0
        self._closed = False
        out.write(encode_header(stanzas, file_key))
        out.write(nonce)
        del file_key

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("write after close")
        self._buf += data
        while len(self._buf) > CHUNK:   # keep at least one chunk back: it may be the last
            self._emit(bytes(self._buf[:CHUNK]), last=False)
            del self._buf[:CHUNK]
        return len(data)

    def _emit(self, chunk: bytes, *, last: bool) -> None:
        self._out.write(self._aead.encrypt(_chunk_nonce(self._counter, last), chunk, None))
        self._counter += 1

    def close(self) -> None:
        if not self._closed:
            self._emit(bytes(self._buf), last=True)
            self._buf.clear()
            self._closed = True

    def __enter__(self) -> "Encryptor":
        return self

    def __exit__(self, *exc: object) -> None:
        if exc[0] is None:
            self.close()


def decrypt(stream: BinaryIO, identities: Sequence[object], sink: Callable[[bytes], None]) -> int:
    """Decrypt an age file from `stream`, handing each verified chunk to `sink` as soon as
    it is authenticated. Returns the plaintext length. Raises a typed `AgeError`; on a
    PayloadError the chunks already handed to `sink` were authentic but the file is not
    complete -- callers must treat the result as failed."""
    r = _Reader(stream)
    header = parse_header(r)
    file_key = _unwrap(header, identities)
    if not hmac.compare_digest(hmac.new(_mac_key(file_key), header.raw_for_mac, sha256).digest(), header.mac):
        raise HMACError("the header MAC doesn't match (the header was changed, or the key is wrong)")
    nonce = r.read(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise HeaderError("the file ends before the payload nonce")
    aead = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
    counter = released = 0
    while True:
        chunk = r.read(ENC_CHUNK)
        if len(chunk) < TAG:
            raise PayloadError(f"the file is truncated at chunk {counter} (no final chunk)", chunk=counter,
                               released=released)
        last = len(chunk) < ENC_CHUNK
        try:
            plain = aead.decrypt(_chunk_nonce(counter, last), chunk, None)
        except InvalidTag:
            plain = None
        if plain is None and not last:   # a full-size chunk may be the final one
            try:
                plain = aead.decrypt(_chunk_nonce(counter, True), chunk, None)
                last = True
            except InvalidTag:
                plain = None
        if plain is None:
            what = "doesn't decrypt as the final chunk: the file is truncated or corrupted there" if last \
                else "is corrupted"
            raise PayloadError(f"chunk {counter} {what}", chunk=counter, released=released)
        if last and not plain and counter > 0:
            raise PayloadError("the final chunk is empty (not allowed after other chunks)", chunk=counter,
                               released=released)
        sink(plain)
        released += len(plain)
        if last:
            if r.read(1):
                raise PayloadError("data after the final chunk", chunk=counter + 1, released=released)
            return released
        counter += 1


def decrypt_bytes(data: bytes, identities: Sequence[object]) -> bytes:
    import io

    out = bytearray()
    decrypt(io.BytesIO(dearmor(data) if is_armored(data) else data), identities, out.extend)
    return bytes(out)


def encrypt_bytes(data: bytes, recipients: Sequence[object]) -> bytes:
    import io

    buf = io.BytesIO()
    enc = Encryptor(buf, recipients)
    enc.write(data)
    enc.close()
    return buf.getvalue()


def read_header_only(stream: BinaryIO) -> tuple[Header, int]:
    """Parse and check the header's shape without any key (for `kratos backup verify`).
    Returns the header and its length in bytes."""
    r = _Reader(stream)
    h = parse_header(r)
    return h, r.header_bytes


# --------------------------------------------------------------------------- armor (read only)
_WS = b" \t\r\n"


def is_armored(data: bytes) -> bool:
    return data.lstrip(_WS).startswith(b"-----BEGIN")


def dearmor(data: bytes) -> bytes:
    """Strict PEM per the spec: whitespace allowed only before and after the block, LF or
    CRLF line ends, 64-column lines, canonical padded base64."""
    s = data.lstrip(_WS)
    if not s.startswith(ARMOR_BEGIN):
        raise ArmorError("not an armored age file (no BEGIN AGE ENCRYPTED FILE line)")
    s = s[len(ARMOR_BEGIN):]
    if s.startswith(b"\r\n"):
        eol = b"\r\n"
    elif s.startswith(b"\n"):
        eol = b"\n"
    else:
        raise ArmorError("armor: the BEGIN line doesn't end with a line break")
    s = s[len(eol):]
    lines: list[bytes] = []
    while True:
        i = s.find(eol)
        line, rest = (s, b"") if i < 0 else (s[:i], s[i + len(eol):])
        if line == ARMOR_END:
            if rest.strip(_WS) or (i < 0 and rest):
                raise ArmorError("armor: data after the END line")
            break
        if i < 0:
            raise ArmorError("armor: no END line")
        if not line or len(line) > 64 or not re.fullmatch(rb"[A-Za-z0-9+/=]+", line):
            raise ArmorError("armor: a body line is empty, too long or has an invalid character")
        lines.append(line)
        s = rest
    if any(len(x) != 64 for x in lines[:-1]):
        raise ArmorError("armor: a line other than the last isn't 64 columns")
    text = b"".join(lines)
    if len(text) % 4 or b"=" in text.rstrip(b"="):
        raise ArmorError("armor: base64 padding is missing or misplaced")
    try:
        out = base64.b64decode(text, validate=True)
    except binascii.Error as e:
        raise ArmorError(f"armor: bad base64 ({e})") from None
    if base64.b64encode(out) != text:
        raise ArmorError("armor: base64 is not canonical")
    return out
