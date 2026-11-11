"""E.4 datasets: resumable downloads into .tmp, swap only after checks, the old copy kept
on every failure, free space checked first, abuse.ch's interval respected, the key never
in a message, `datasets` rows, staleness and attribution text. All HTTP is faked."""
from __future__ import annotations

import hashlib
import io
import stat
import time
import zipfile
from collections import namedtuple
from pathlib import Path

import pytest

from kratos.hashdb import bloom, circl, datasets as D, malwarebazaar as M

KEY = "kratos-test-" + "k" * 20       # a placeholder, built at test time


class Resp:
    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def iter_content(self, chunk_size: int = 65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Session:
    """Serves `body` at any URL; honours Range; records every request."""

    def __init__(self, body: bytes, *, status: int = 200, cut_after: int | None = None):
        self.body, self.status, self.cut_after = body, status, cut_after
        self.requests: list[tuple[str, str, dict]] = []

    def head(self, url, **kw):
        self.requests.append(("HEAD", url, kw.get("headers") or {}))
        return Resp(200, b"", {"content-length": str(len(self.body))})

    def get(self, url, **kw):
        hdrs = kw.get("headers") or {}
        self.requests.append(("GET", url, hdrs))
        if self.status != 200:
            return Resp(self.status)
        start = int(hdrs["Range"].split("=")[1].rstrip("-")) if "Range" in hdrs else 0
        body = self.body[start:]
        if self.cut_after is not None:
            sent, self.cut_after = body[:self.cut_after], None      # cut once, then serve the rest
            return Resp(206 if start else 200, sent,
                        {"content-length": str(len(body))} if not start else
                        {"content-range": f"bytes {start}-{len(self.body) - 1}/{len(self.body)}"})
        if start:
            return Resp(206, body, {"content-range": f"bytes {start}-{len(self.body) - 1}/{len(self.body)}"})
        return Resp(200, body, {"content-length": str(len(body))})


Usage = namedtuple("Usage", "total used free")


def _bloom_bytes(tmp_path: Path, n: int = 3000) -> bytes:
    p = tmp_path / "src.bloom"
    bloom.build(p, [hashlib.sha1(str(i).encode()).hexdigest().upper().encode() for i in range(n)],
                capacity=n, fp_rate=0.001)
    return p.read_bytes()


def _plenty(_p):
    return Usage(10 ** 13, 0, 10 ** 13)


# --------------------------------------------------------------------------- CIRCL
def test_circl_update_resumes_and_never_uses_tmp(tmp_path):
    body = _bloom_bytes(tmp_path)
    s = Session(body, cut_after=len(body) // 3)
    ok, msg = circl.update(tmp_path, session=s, usage=_plenty, ubuntu_host=False)
    assert not ok and "ended early" in msg and "resume" in msg
    tmp = tmp_path / "hashdb" / (circl.DATASET.file + ".tmp")
    assert tmp.exists() and not (tmp_path / "hashdb" / circl.DATASET.file).exists()
    assert circl.lookup(tmp_path, "0" * 40) is None            # a half download is never read
    ok, msg = circl.update(tmp_path, session=s, usage=_plenty, ubuntu_host=False)
    assert ok, msg
    assert s.requests[-1][2].get("Range") == f"bytes={len(body) // 3}-"
    assert not tmp.exists()
    final = tmp_path / "hashdb" / circl.DATASET.file
    assert final.read_bytes() == body and stat.S_IMODE(final.stat().st_mode) == 0o600
    row = D.get(tmp_path, "circl")
    assert row.sha256 == hashlib.sha256(body).hexdigest() and row.size == len(body)
    assert circl.lookup(tmp_path, hashlib.sha1(b"5").hexdigest()) is True


def test_circl_refuses_an_html_page_and_keeps_the_old_filter(tmp_path):
    body = _bloom_bytes(tmp_path)
    assert circl.update(tmp_path, session=Session(body), usage=_plenty, ubuntu_host=False)[0]
    before = (tmp_path / "hashdb" / circl.DATASET.file).read_bytes()
    ok, msg = circl.update(tmp_path, session=Session(b"<html>blocked</html>" * 10), usage=_plenty, ubuntu_host=False)
    assert not ok and "not a hashlookup Bloom filter" in msg and "previous filter is kept" in msg
    assert (tmp_path / "hashdb" / circl.DATASET.file).read_bytes() == before
    assert not (tmp_path / "hashdb" / (circl.DATASET.file + ".tmp")).exists()     # a wrong file isn't resumed
    assert "not a hashlookup" in D.get(tmp_path, "circl").last_error


def test_circl_free_space_check(tmp_path):
    body = _bloom_bytes(tmp_path)
    s = Session(body)
    ok, msg = circl.update(tmp_path, session=s, usage=lambda _p: Usage(10 ** 12, 0, 2 * 1024 ** 3 + 10),
                           ubuntu_host=False)
    assert not ok and "not enough disk space" in msg and "2 GB to spare" in msg
    assert not [r for r in s.requests if r[0] == "GET"]          # refused before downloading anything
    assert not (tmp_path / "hashdb" / (circl.DATASET.file + ".tmp")).exists()


def test_free_space_margin_is_two_gigabytes(tmp_path):
    with pytest.raises(D.NotEnoughSpace):
        D.check_free_space(tmp_path, 10, usage=lambda _p: Usage(0, 0, 2 * 1024 ** 3))
    D.check_free_space(tmp_path, 10, usage=lambda _p: Usage(0, 0, 2 * 1024 ** 3 + 10))


def test_circl_spot_check_on_ubuntu_refuses_a_filter_without_its_own_programs(tmp_path):
    body = _bloom_bytes(tmp_path)
    ok, msg = circl.update(tmp_path, session=Session(body), usage=_plenty, ubuntu_host=True)
    assert not ok and "knows none of this Ubuntu computer's own" in msg


# --------------------------------------------------------------------------- MalwareBazaar
def _mb_zip(n: int, extra: list[str] | None = None) -> bytes:
    rows = ['# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess",'
            '"mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"']
    for i in range(n):
        h = hashlib.sha256(f"kratos-mb-{i}".encode()).hexdigest()
        rows.append(f'"2026-01-0{1 + i % 9} 00:00:00", "{h}", "x", "y", "r", "f", "elf", "m", "Fam{i % 3}", "n/a", "", "", "", ""')
    rows += extra or []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("full.csv", "\n".join(rows) + "\n")
    return buf.getvalue()


def test_mb_needs_a_key(tmp_path):
    ok, msg = M.update(tmp_path, session=Session(b""))
    assert not ok and "auth.abuse.ch" in msg


def test_mb_update_builds_the_set_and_never_shows_the_key(tmp_path):
    D.write_key(tmp_path, "malwarebazaar", KEY)
    s = Session(_mb_zip(50))
    ok, msg = M.update(tmp_path, session=s, min_rows=10)
    assert ok, msg
    assert KEY in s.requests[-1][1]                    # sent to abuse.ch (in its URL) ...
    row = D.get(tmp_path, "malwarebazaar")
    assert KEY not in row.source_url and KEY not in str(row.detail)   # ... never stored
    r = M.Reader(tmp_path)
    try:
        hit = r.get(hashlib.sha256(b"kratos-mb-4").hexdigest())
        assert hit and hit["signature"] == "Fam1" and hit["first_seen"].startswith("2026-01-05")
        assert r.get("0" * 64) is None
    finally:
        r.close()
    assert not list((tmp_path / "hashdb").glob("*.tmp"))


def test_mb_key_refused_keeps_old_set(tmp_path):
    D.write_key(tmp_path, "malwarebazaar", KEY)
    assert M.update(tmp_path, session=Session(_mb_zip(20)), min_rows=10)[0]
    before = (tmp_path / "hashdb" / M.DATASET.file).read_bytes()
    row = D.get(tmp_path, "malwarebazaar")
    ok, msg = M.update(tmp_path, session=Session(b"", status=401), now=time.time() + 7200, force_interval=True)
    assert not ok and "key was refused" in msg and "previous set is kept" in msg and KEY not in msg
    assert (tmp_path / "hashdb" / M.DATASET.file).read_bytes() == before
    assert D.get(tmp_path, "malwarebazaar").fetched_at == row.fetched_at


def test_mb_fetch_interval(tmp_path):
    D.write_key(tmp_path, "malwarebazaar", KEY)
    now = time.time()
    assert M.update(tmp_path, session=Session(_mb_zip(20)), min_rows=10, now=now)[0]
    s = Session(_mb_zip(20))
    ok, msg = M.update(tmp_path, session=s, now=now + 600, force_interval=True)
    assert not ok and "at most one fetch an hour" in msg and not s.requests     # refused before any request
    ok, msg = M.update(tmp_path, session=s, now=now + 7200)
    assert not ok and "Nothing was requested" in msg and not s.requests         # the 24 h setting
    assert M.update(tmp_path, session=s, now=now + 7200, force_interval=True, min_rows=10)[0]


def test_mb_refuses_a_file_that_is_not_the_export(tmp_path):
    D.write_key(tmp_path, "malwarebazaar", KEY)
    ok, msg = M.update(tmp_path, session=Session(b"<!doctype html><p>log in</p>"), min_rows=1)
    assert not ok and "web page" in msg
    ok, msg = M.update(tmp_path, session=Session(_mb_zip(3, ["this is not a row"])), min_rows=1,
                       now=time.time() + 7200)
    assert not ok and "neither a SHA-256 nor a CSV row" in msg
    assert not (tmp_path / "hashdb" / M.DATASET.file).exists()


def test_mb_reads_the_plain_sha256_list_too(tmp_path):
    hashes = [hashlib.sha256(f"p{i}".encode()).hexdigest() for i in range(30)]
    p = tmp_path / "plain.txt"
    p.write_text("# MalwareBazaar\n" + "\n".join(hashes) + "\n")
    assert M.build(p, tmp_path / "out.sqlite") == 30


def test_key_storage_is_owner_only(tmp_path):
    D.write_key(tmp_path, "malwarebazaar", KEY)
    f = tmp_path / D.SECRETS_DIR / "malwarebazaar.key"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600 and stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    assert D.read_key(tmp_path, "malwarebazaar") == KEY
    with pytest.raises(ValueError):
        D.write_key(tmp_path, "malwarebazaar", "two words")
    assert D.remove_key(tmp_path, "malwarebazaar") and D.read_key(tmp_path, "malwarebazaar") is None


def test_about_texts_carry_the_attribution_and_terms():
    assert "CC BY 4.0" in circl.ABOUT and "CIRCL hashlookup" in circl.ABOUT and "NOT Debian" in circl.ABOUT
    assert "abuse.ch" in M.ABOUT and "not-for-profit" in M.ABOUT and "Spamhaus" in M.ABOUT
    assert "https://abuse.ch/terms-of-use/" in M.ABOUT


def test_stale_dataset_wording(tmp_path, capsys):
    import argparse

    from kratos.cli import hashdb_cmd

    D.record_installed(tmp_path, M.DATASET, version="2026-01-01 00:00 UTC", sha256="a" * 64, size=10,
                       fetched_at=time.time() - 10 * 86400, detail={"rows": 5})
    (tmp_path / "hashdb").mkdir(exist_ok=True)
    (tmp_path / "hashdb" / M.DATASET.file).write_bytes(b"x")
    hashdb_cmd.cmd_hashdb_update(argparse.Namespace(data_dir=str(tmp_path), about=False, status=True, timer=None,
                                                    circl=False, malwarebazaar=False, auto=False))
    out = capsys.readouterr().out
    assert "fetched 10.0 days ago -- older than 7 days, refresh it" in out
    assert "CIRCL hashlookup known-good filter: not downloaded" in out


def test_one_update_at_a_time(tmp_path):
    with D.update_lock(tmp_path, "circl"):
        with pytest.raises(D.DatasetError, match="already running"):
            with D.update_lock(tmp_path, "circl"):
                pass


def test_datasets_rows_record_attempts_without_touching_the_installed_copy(tmp_path):
    D.record_installed(tmp_path, circl.DATASET, version="v1", sha256="a" * 64, size=5, fetched_at=100.0, detail={})
    D.record_attempt(tmp_path, circl.DATASET, at=200.0, error="boom")
    row = D.get(tmp_path, "circl")
    assert (row.version, row.fetched_at, row.last_attempt_at, row.last_error) == ("v1", 100.0, 200.0, "boom")


def test_backup_classes(tmp_path):
    """The datasets are rebuildable (left out, the plan names the rebuild command), the
    reputations travel, the key travels as a secret (left out by --without-secrets)."""
    from kratos import datainv
    from kratos.backup import plan as BP

    assert datainv.category("hash_datasets").backup == datainv.BACKUP_REBUILDABLE
    assert "kratos hashdb-update" in datainv.category("hash_datasets").backup_note
    assert datainv.category("hash_reputation").backup == datainv.BACKUP_INCLUDE
    assert datainv.category("dataset_secrets").backup == datainv.BACKUP_SECRET
    h = tmp_path / "hashdb"
    (h / "results").mkdir(parents=True)
    (h / circl.DATASET.file).write_bytes(b"x" * 10)
    (h / M.DATASET.file).write_bytes(b"y")
    (h / "results" / "hash_0123abcd.json").write_text("{}")
    D.write_key(tmp_path, "malwarebazaar", KEY)
    p = BP.build(tmp_path, roots=BP.Roots(tmp_path, tmp_path / "state", tmp_path / "cfg"))
    archived = {i.archive for i in p.items}
    assert "data/hashdb/results/hash_0123abcd.json" in archived
    assert "data/dataset-secrets/malwarebazaar.key" in archived
    assert not any(a.endswith((circl.DATASET.file, M.DATASET.file)) for a in archived)
    why = {d.key: d.reason for d in p.decisions}
    assert "kratos hashdb-update" in why["hash_datasets"]
    q = BP.build(tmp_path, without_secrets=True, roots=BP.Roots(tmp_path, tmp_path / "state", tmp_path / "cfg"))
    assert "data/dataset-secrets/malwarebazaar.key" not in {i.archive for i in q.items}
