"""E.4: the DCSO-format Bloom reader agrees with DCSO's own `bloom` CLI, reads through mmap
only, and refuses anything that isn't a hashlookup filter."""
from __future__ import annotations

import hashlib
import json
import resource
import struct
from pathlib import Path

import pytest

from kratos.hashdb import bloom

FIX = Path(__file__).parent / "fixtures" / "hashdb"


def _present(i: int) -> str:
    return hashlib.sha1(f"kratos-fixture-present-{i}".encode()).hexdigest().upper()


def _absent(i: int) -> str:
    return hashlib.sha1(f"kratos-fixture-absent-{i}".encode()).hexdigest().upper()


def test_reader_agrees_with_the_dcso_cli_fixture():
    expect = json.loads((FIX / "dcso_small.json").read_text())
    with bloom.BloomFilter(FIX / "dcso_small.bloom") as bf:
        assert bf.header.capacity == 400 and bf.header.fp_rate == 0.01
        assert all(_present(i) in bf for i in range(300))
        reported = {v for v in (_absent(i) for i in range(2000)) if v in bf}
    # the same false positives DCSO's `bloom check` reported, no more, no fewer
    assert reported == set(expect["absent_reported_present"])


def test_build_writes_the_same_bytes_as_the_dcso_cli(tmp_path):
    out = tmp_path / "ours.bloom"
    bloom.build(out, [_present(i).encode() for i in range(300)], capacity=400, fp_rate=0.01)
    assert out.read_bytes() == (FIX / "dcso_small.bloom").read_bytes()


def test_fnv1_64_matches_go():
    # Go: fnv.New64(); h.Write([]byte("a")); h.Sum64() == 0xaf63bd4c8601b7be
    assert bloom.fnv1_64(b"a") == 0xAF63BD4C8601B7BE
    assert bloom.fnv1_64(b"") == 0xCBF29CE484222325


@pytest.mark.parametrize("data, why", [
    (b"<html><body>error</body></html>" + b" " * 100, "wrong version"),
    (b"\x01" + b"\x00" * 10, "too short"),
    (struct.pack("<QQdQQQ", 2, 100, 0.01, 7, 1000, 10) + b"\x00" * 128, "wrong version"),
    (struct.pack("<QQdQQQ", 1, 100, 0.01, 7, 100000, 10) + b"\x00" * 64, "cut short"),
    (struct.pack("<QQdQQQ", 1, 100, 0.01, 999, 1000, 10) + b"\x00" * 128, "hash functions"),
    (struct.pack("<QQdQQQ", 1, 100, 1.5, 7, 1000, 10) + b"\x00" * 128, "false-positive"),
])
def test_bloom_header_validation(tmp_path, data, why):
    p = tmp_path / "x.bloom"
    p.write_bytes(data)
    with pytest.raises(bloom.NotABloomFilter, match=why):
        bloom.BloomFilter(p)


def test_plausibility_refuses_an_all_ones_or_empty_filter(tmp_path):
    m = 64 * 64
    for fill, why in ((b"\xff", "almost every bit"), (b"\x00", "empty")):
        p = tmp_path / f"f{fill.hex()}.bloom"
        p.write_bytes(struct.pack("<QQdQQQ", 1, 1000, 0.01, 7, m, 500) + fill * (m // 8))
        with bloom.BloomFilter(p) as bf:
            assert why in (bloom.check_plausible(bf) or "")


def test_mmap_only_memory_stays_flat_for_a_large_filter(tmp_path):
    # a 512 MB sparse filter: opening and looking up must not read it into memory
    p = tmp_path / "big.bloom"
    m = 512 * 1024 * 1024 * 8
    with open(p, "wb") as fh:
        fh.write(struct.pack("<QQdQQQ", 1, 10 ** 9, 0.0001, 14, m, 0))
        fh.truncate(48 + m // 8)
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    with bloom.BloomFilter(p) as bf:
        for i in range(100):       # each lookup touches at most k=14 pages of the file
            assert _absent(i) not in bf
    grew_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before
    # 100 lookups x 14 pages x 4 KB = 5.6 MB at most -- nowhere near the 512 MB file
    assert grew_kb < 16 * 1024, f"resident memory grew {grew_kb} KB"
