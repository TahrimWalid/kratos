"""A reader for DCSO-format Bloom filters (the format of CIRCL hashlookup's offline set).

The format (github.com/DCSO/bloom, `bloom.go`; Poppy calls it version 1): six
little-endian 64-bit header words -- flags (low byte = 1), n (capacity), p (false-positive
probability, an IEEE double), k (hash functions), m (bits), N (elements added) -- then
ceil(m / 64) little-endian 64-bit words of bits, then optional free-form data.

A value's k bit positions come from one 64-bit FNV-1 hash of its bytes, reduced modulo
the largest prime below 2**64 and stepped by a fixed multiplier. Go's uint64 multiply
wraps at 2**64 before the modulo, and so does this reader -- otherwise it would disagree
with every filter DCSO's tools write.

The file is read through mmap only, never loaded: CIRCL's filter is about a gigabyte,
and a lookup touches k words of it.
"""
from __future__ import annotations

import math
import mmap
import os
import random
import struct
from dataclasses import dataclass
from pathlib import Path

HEADER = struct.Struct("<QQdQQQ")
HEADER_BYTES = HEADER.size                 # 48
MAX_TRAILING_DATA = 64 * 1024 * 1024       # free-form data after the bits (DCSO lets tools attach some)
MAX_K = 64

_PRIME = 18446744073709551557              # largest prime < 2**64 (bloom.go: m)
_MULT = 18446744073709550147               # bloom.go: g
_MASK = (1 << 64) - 1
_FNV_OFFSET = 0xCBF29CE484222325
_FNV_PRIME = 0x100000001B3


class NotABloomFilter(ValueError):
    """The file is not a DCSO-format Bloom filter (or is cut short / implausible)."""


@dataclass(frozen=True)
class Header:
    flags: int
    capacity: int          # n
    fp_rate: float         # p
    hashes: int            # k
    bits: int              # m
    elements: int          # N
    words: int             # ceil(m / 64)
    data_bytes: int        # free-form data after the bits

    @property
    def expected_fp(self) -> float:
        """False-positive probability at the filter's actual fill (N elements, k hashes, m bits)."""
        if self.bits <= 0 or self.hashes <= 0:
            return 1.0
        return (1.0 - math.exp(-self.hashes * self.elements / self.bits)) ** self.hashes


def fnv1_64(data: bytes) -> int:
    """64-bit FNV-1 (Go's hash/fnv New64): multiply, then xor."""
    h = _FNV_OFFSET
    for b in data:
        h = (h * _FNV_PRIME) & _MASK
        h ^= b
    return h


def positions(value: bytes, hashes: int, bits: int) -> list[int]:
    hn = fnv1_64(value) % _PRIME
    out = []
    for _ in range(hashes):
        hn = ((hn * _MULT) & _MASK) % _PRIME
        out.append(hn % bits)
    return out


def parse_header(raw: bytes, file_size: int) -> Header:
    """The header, checked against the file's length. Raises NotABloomFilter."""
    if len(raw) < HEADER_BYTES or file_size < HEADER_BYTES:
        raise NotABloomFilter("too short to be a Bloom filter")
    flags, n, p, k, m, big_n = HEADER.unpack(raw[:HEADER_BYTES])
    if flags & 0xFF != 1:
        raise NotABloomFilter("not a hashlookup Bloom filter (wrong version byte)")
    if not 1 <= k <= MAX_K:
        raise NotABloomFilter(f"implausible number of hash functions ({k})")
    if m == 0 or n == 0:
        raise NotABloomFilter("empty filter dimensions")
    if not (p == p) or not 0.0 < p < 1.0:          # NaN or out of range
        raise NotABloomFilter("implausible false-positive rate")
    words = (m + 63) // 64
    need = HEADER_BYTES + 8 * words
    if file_size < need:
        raise NotABloomFilter(f"cut short: {file_size} bytes, the header says at least {need}")
    data = file_size - need
    if data > MAX_TRAILING_DATA:
        raise NotABloomFilter("more data after the bits than a Bloom filter carries")
    if big_n > 4 * n:
        raise NotABloomFilter("holds far more elements than its capacity")
    return Header(flags, n, p, k, m, big_n, words, data)


class BloomFilter:
    """An open filter. Use as a context manager, or call close()."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._fd = os.open(str(self.path), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            size = os.fstat(self._fd).st_size
            if size < HEADER_BYTES:
                raise NotABloomFilter("too short to be a Bloom filter")
            self._mm = mmap.mmap(self._fd, size, prot=mmap.PROT_READ)
            # lookups jump around the file: no readahead (each would map ~128 KB of neighbours)
            if hasattr(self._mm, "madvise") and hasattr(mmap, "MADV_RANDOM"):
                self._mm.madvise(mmap.MADV_RANDOM)
        except BaseException:
            os.close(self._fd)
            raise
        try:
            self.header = parse_header(self._mm[:HEADER_BYTES], size)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        mm = getattr(self, "_mm", None)
        if mm is not None:
            mm.close()
            self._mm = None  # type: ignore[assignment]
        if getattr(self, "_fd", -1) >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> "BloomFilter":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _bit(self, pos: int) -> bool:
        word = pos >> 6
        off = HEADER_BYTES + 8 * word
        (v,) = struct.unpack_from("<Q", self._mm, off)
        return bool((v >> (pos & 63)) & 1)

    def __contains__(self, value: bytes | str) -> bool:
        raw = value.encode("ascii") if isinstance(value, str) else bytes(value)
        h = self.header
        return all(self._bit(p) for p in positions(raw, h.hashes, h.bits))

    def fill_ratio(self, samples: int = 4096, seed: int = 0) -> float:
        """The share of bits set, estimated from `samples` random words (a full count would
        read the whole file)."""
        h = self.header
        rng = random.Random(seed)
        set_bits = 0
        n = min(samples, h.words)
        for _ in range(n):
            (v,) = struct.unpack_from("<Q", self._mm, HEADER_BYTES + 8 * rng.randrange(h.words))
            set_bits += bin(v).count("1")
        return set_bits / (64.0 * n) if n else 0.0


def check_plausible(bf: BloomFilter) -> str | None:
    """Why this filter isn't a usable known-good set, or None. A real filter with N elements
    has about 1 - exp(-kN/m) of its bits set; an all-zero or all-one file, or one far from
    that, is refused."""
    h = bf.header
    fill = bf.fill_ratio()
    expected = 1.0 - math.exp(-h.hashes * h.elements / h.bits) if h.bits else 0.0
    if h.elements == 0 or fill == 0.0:
        return "the filter is empty"
    if fill > 0.95:
        return f"almost every bit is set ({fill:.0%}): it would say yes to everything"
    if abs(fill - expected) > 0.15:
        return f"its bits don't match its own header ({fill:.0%} set, the header implies about {expected:.0%})"
    return None


def build(path: Path | str, values: list[bytes], *, capacity: int, fp_rate: float) -> None:
    """Write a DCSO-format filter (tests and lab vectors only; Kratos never ships one).
    Dimensions as bloom.go's Initialize."""
    m = int(abs(math.ceil(capacity * math.log(fp_rate) / (math.log(2.0) ** 2))))
    words = math.ceil(m / 64.0)
    k = int(math.ceil(math.log(2) * m / capacity))
    v = [0] * words
    count = 0
    for value in values:
        new = False
        for p in positions(value, k, m):
            bit = 1 << (p % 64)
            if not v[p // 64] & bit:
                new = True
            v[p // 64] |= bit
        count += new
    with open(path, "wb") as fh:
        fh.write(HEADER.pack(1, capacity, fp_rate, k, m, count))
        fh.write(struct.pack(f"<{words}Q", *v))
