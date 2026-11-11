"""CIRCL hashlookup's offline known-good filter (E.4 §3.2).

`https://cra.circl.lu/hashlookup/hashlookup-full.bloom`: about a gigabyte, refreshed
monthly, SHA-1 values of files from NSRL and several distributions' packages (Ubuntu,
CentOS, Fedora EPEL, Kali, openSUSE, OpenBSD, ...; not Debian), false-positive rate
about 1 in 10,000, licence CC BY 4.0 (attribution: CIRCL hashlookup). Downloaded only
when a person asks (`kratos hashdb-update --circl`), never automatically.

The download is checked before it replaces anything: free space first (the file plus
2 GB), then resumable into `circl-hashlookup.bloom.tmp`, then the DCSO header and a
plausible fill ratio, then that it holds the sample SHA-1s CIRCL's own page lists (which
also tells Kratos the hex case it uses). How many of this computer's own programs it knows
is reported, never a reason to refuse. CIRCL publishes no checksum; the download's sha256
is recorded.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Callable

from kratos.hashdb import bloom
from kratos.hashdb import datasets as D

URL = "https://cra.circl.lu/hashlookup/hashlookup-full.bloom"
DATASET = D.Dataset(
    name="circl", label="CIRCL hashlookup known-good filter", file="circl-hashlookup.bloom", source_url=URL,
    licence="CC BY 4.0 -- CIRCL hashlookup (https://www.circl.lu/services/hashlookup/)",
    terms_url="https://www.circl.lu/services/hashlookup/", warn_days=60,
    update_hint="kratos hashdb-update --circl")
MAX_BYTES = 4 * 1024 ** 3
ASSUMED_BYTES = 1200 * 1024 ** 2         # when the server doesn't say how big it is
# The example SHA-1s CIRCL's own hashlookup page shows (https://www.circl.lu/services/hashlookup/,
# read 2026-11-11): a real filter holds them. Checked against the real filter with DCSO's own
# `bloom` CLI: all five present, upper-case hex. A wrong file -- or an HTML page -- holds none.
CIRCL_SAMPLES = ("FFFFFDAC1B1B4C513896C805C2C698D9688BE69F", "FFFFFF4DB8282D002893A9BAF00E9E9D4BA45E65",
                 "FFFFFE4C92E3F7282C7502F1734B243FA52326FB", "72F104BF11A12511154267328F069FE0541E841E",
                 "D3A21675A8F19518D8B8F3CEF0F6A21DE1DA6CC7")
SAMPLES_NEEDED = 4
# Programs every Ubuntu has: reported (how much of THIS computer's software the set knows), never a
# reason to refuse -- in the lab the November 2026 filter knew none of Ubuntu 22.04's or 24.04's own
# coreutils/bash binaries (the E.4 Handoff).
SPOT_FILES = ("/usr/bin/ls", "/usr/bin/cat", "/usr/bin/cp", "/usr/bin/grep", "/usr/bin/tar", "/usr/bin/gzip",
              "/usr/bin/sed", "/usr/bin/bash")

ABOUT = """\
CIRCL hashlookup known-good filter
  Source:   https://cra.circl.lu/hashlookup/hashlookup-full.bloom (about 1 GB, refreshed monthly)
  What:     SHA-1 values from NSRL, common Windows builds and the packages of Ubuntu, CentOS,
            Fedora EPEL, Kali, openSUSE, OpenBSD, CDNJS and Snap -- NOT Debian's. A Bloom filter:
            a match means "probably known-good" (about 1 false match in 10,000). Its Linux
            coverage is uneven: in Kratos's lab it knew none of Ubuntu 22.04's or 24.04's own
            coreutils/bash binaries -- package checksums do that job.
  Licence:  CC BY 4.0. Attribution: CIRCL hashlookup, https://www.circl.lu/services/hashlookup/
            (dataset: https://data.public.lu/en/datasets/circl-hashlookup-bloomfilter/).
  Use:      only ever read on this computer; no hash is sent to CIRCL by this filter.
            Downloaded only when you run `kratos hashdb-update --circl`.
"""


def _sha1(path: str) -> str | None:
    try:
        h = hashlib.sha1()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def spot_check(bf: bloom.BloomFilter, files: tuple[str, ...] = SPOT_FILES) -> tuple[int, int]:
    """(known, looked): how many of this computer's own programs the filter knows (as upper-case
    hex, the filter's own form). A fact for the person, not a test of the file."""
    known = looked = 0
    for f in files:
        h = _sha1(f)
        if h is None:
            continue
        looked += 1
        known += h.upper() in bf
    return known, looked


def validate(path: Path, *, samples: tuple[str, ...] = CIRCL_SAMPLES, needed: int = SAMPLES_NEEDED,
             spot: Callable[[bloom.BloomFilter], tuple[int, int]] = spot_check) -> dict[str, Any]:
    """Facts about a downloaded filter, or raises DatasetError naming why it is refused."""
    try:
        bf = bloom.BloomFilter(path)
    except bloom.NotABloomFilter as e:
        raise D.DatasetError(f"not a hashlookup Bloom filter: {e}") from None
    with bf:
        why = bloom.check_plausible(bf)
        if why:
            raise D.DatasetError(f"not a usable hashlookup Bloom filter: {why}")
        upper = sum(s.upper() in bf for s in samples)
        lower = sum(s.lower() in bf for s in samples)
        if max(upper, lower) < min(needed, len(samples)):
            raise D.DatasetError(f"not CIRCL's set: it holds {max(upper, lower)} of the {len(samples)} sample hashes "
                                 "CIRCL's own page lists")
        h = bf.header
        known, looked = spot(bf)
        facts: dict[str, Any] = {"capacity": h.capacity, "elements": h.elements, "fp_rate": h.fp_rate,
                                 "hashes": h.hashes, "bits": h.bits, "fill": round(bf.fill_ratio(), 4),
                                 "hash_case": "lower" if lower > upper else "upper",
                                 "samples_found": max(upper, lower),
                                 "spot_check": (f"it knows {known} of {looked} of this computer's own programs"
                                                if looked else "")}
    return facts


def update(data_dir: Path, *, session: Any = None, log: Callable[[str], None] | None = None,
           now: float | None = None, usage: Any = None, samples: tuple[str, ...] | None = None) -> tuple[bool, str]:
    """Download, check, swap in. (ok, message). The old filter stays on any failure; a
    partial download stays as .tmp and resumes next time."""
    log = log or (lambda _m: None)
    when = time.time() if now is None else now
    out = D.folder(data_dir)
    final, tmp = out / DATASET.file, out / (DATASET.file + ".tmp")
    try:
        with D.update_lock(data_dir, DATASET.name):
            s = D._session(session, "kratos-hashdb-update")
            size = D.remote_size(s, URL) or ASSUMED_BYTES
            have = tmp.stat().st_size if tmp.exists() else 0
            kw = {"usage": usage} if usage is not None else {}
            D.check_free_space(out, max(0, size - have), **kw)
            log(f"  downloading {size / 1e9:.2f} GB from {URL}" + (f" (resuming at {have / 1e9:.2f} GB)" if have else ""))
            started = time.monotonic()
            got = D.download(s, URL, tmp, max_bytes=MAX_BYTES, resume=True)
            log(f"  downloaded in {time.monotonic() - started:.0f} s; checking it")
            facts = validate(tmp, **({"samples": samples} if samples is not None else {}))
            digest = D.sha256_file(tmp)
            D.swap_in(tmp, final)
            facts["download_seconds"] = round(time.monotonic() - started, 1)
            D.record_installed(data_dir, DATASET, version=time.strftime("%Y-%m-%d", time.gmtime(when)),
                               sha256=digest, size=got, fetched_at=when, detail=facts)
    except D.DatasetError as e:
        if tmp.exists() and str(e).startswith(("not a ", "not CIRCL's")):
            tmp.unlink()        # a wrong file is never resumed: start clean next time
        D.record_attempt(data_dir, DATASET, at=when, error=str(e))
        kept = "the previous filter is kept" if final.exists() else "no filter is installed"
        return False, f"CIRCL filter not updated ({kept}): {e}"
    return True, (f"CIRCL known-good filter installed: {got / 1e9:.2f} GB, {facts['elements']:,} hashes"
                  + (f"; {facts['spot_check']}" if facts.get("spot_check") else "") + ".")


def lookup(data_dir: Path, sha1: str) -> bool | None:
    """True/False from the installed filter, None when none is installed."""
    path = D.installed_path(data_dir, DATASET)
    if path is None:
        return None
    row = D.get(data_dir, DATASET.name)
    case = (row.detail.get("hash_case") if row else None) or "upper"
    try:
        with bloom.BloomFilter(path) as bf:
            return (sha1.lower() if case == "lower" else sha1.upper()) in bf
    except (OSError, bloom.NotABloomFilter):
        return None


class Reader:
    """One open filter for a whole check (many lookups, one mmap)."""

    def __init__(self, data_dir: Path):
        self.bf: bloom.BloomFilter | None = None
        self.case = "upper"
        path = D.installed_path(data_dir, DATASET)
        row = D.get(data_dir, DATASET.name)
        if path is not None:
            try:
                self.bf = bloom.BloomFilter(path)
                self.case = (row.detail.get("hash_case") if row else None) or "upper"
            except (OSError, bloom.NotABloomFilter):
                self.bf = None
        self.row = row if self.bf is not None else None

    def __contains__(self, sha1: str) -> bool:
        if self.bf is None or not sha1:
            return False
        return (sha1.lower() if self.case == "lower" else sha1.upper()) in self.bf

    def close(self) -> None:
        if self.bf is not None:
            self.bf.close()
            self.bf = None

