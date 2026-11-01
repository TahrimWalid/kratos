"""D.3: CISA's SSVC inputs in the vulnerability index -- download, parse, store, swap."""
from __future__ import annotations

import json
import sqlite3

from kratos.pkgvuln import index as IX
from kratos.pkgvuln import ssvc_source as SS
from kratos.pkgvuln import update as U
from tests import test_pkgvuln as T
from tests._ssvc_util import build_tar, cve_record


def test_real_cisa_records_are_read(tmp_path):
    assert T.build(tmp_path).ok
    conn = IX.open_readonly(tmp_path)
    got = SS.lookup(conn, ["CVE-2023-38408", "CVE-2024-3094", "CVE-2099-0001"])
    assert got["CVE-2024-3094"]["exploitation"] == "none"
    assert got["CVE-2024-3094"]["automatable"] == "yes" and got["CVE-2024-3094"]["technical_impact"] == "total"
    assert got["CVE-2024-3094"]["assessed_at"].startswith("2024-04-02") and got["CVE-2024-3094"]["ssvc_version"] == "2.0.3"
    assert got["CVE-2023-38408"]["exploitation"] == "none" and got["CVE-2023-38408"]["automatable"] == "yes"
    assert "CVE-2099-0001" not in got
    meta = conn.execute("SELECT rows, detail, etag FROM meta WHERE source='ssvc'").fetchone()
    assert meta[0] > 10_000 and "0 option value(s) outside" in meta[1]


def test_malformed_options_are_counted_not_stored(tmp_path):
    bad = cve_record("CVE-2026-1111", {"Exploitation": "likely", "Automatable": "yes", "Technical Impact": "total"})
    other_org = cve_record("CVE-2026-2222", {"Exploitation": "active"}, short_name="NOT-CISA")
    mismatch = cve_record("CVE-2026-3333", {"Exploitation": "active"})
    mismatch["containers"]["adp"][0]["metrics"][0]["other"]["content"]["id"] = "CVE-2026-4444"
    files = T._feeds()
    files[U._ssvc.VULNRICHMENT_URL] = build_tar({"CVE-2026-1111": bad, "CVE-2026-2222": other_org,
                                                 "CVE-2026-3333": mismatch},
                                                raw={"vulnrichment-develop/2026/5xxx/CVE-2026-5555.json": b"{not json",
                                                     "../etc/passwd": b"root:x:0:0"})
    assert U.run_update(tmp_path, selectors=["debian:12"], session=T.FakeSession(files)).ok
    conn = IX.open_readonly(tmp_path)
    got = SS.lookup(conn, ["CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333", "CVE-2026-4444"])
    assert got["CVE-2026-1111"]["exploitation"] is None and got["CVE-2026-1111"]["automatable"] == "yes"
    assert "CVE-2026-2222" not in got and "CVE-2026-3333" not in got and "CVE-2026-4444" not in got
    detail = conn.execute("SELECT detail FROM meta WHERE source='ssvc'").fetchone()[0]
    assert "1 option value(s) outside CISA's sets dropped" in detail and "1 file(s) skipped" in detail


def test_a_failed_download_keeps_the_old_rows(tmp_path):
    assert T.build(tmp_path).ok
    before = IX.open_readonly(tmp_path).execute("SELECT COUNT(*) FROM ssvc_inputs").fetchone()[0]
    res = U.run_update(tmp_path, selectors=["debian:12"],
                       session=T.FakeSession(T._feeds(), fail={U._ssvc.VULNRICHMENT_URL}))
    assert res.ok and "CISA SSVC" in res.stale_sources
    assert IX.open_readonly(tmp_path).execute("SELECT COUNT(*) FROM ssvc_inputs").fetchone()[0] == before


def test_a_tiny_or_broken_archive_is_refused_and_the_old_rows_kept(tmp_path):
    assert T.build(tmp_path).ok
    for body in (build_tar(filler=5), b"\x1f\x8b not really gzip"):
        files = T._feeds()
        files[U._ssvc.VULNRICHMENT_URL] = body
        res = U.run_update(tmp_path, selectors=["debian:12"], session=T.FakeSession(files))
        assert res.ok and "CISA SSVC" in res.stale_sources, res.sources
        assert IX.open_readonly(tmp_path).execute("SELECT COUNT(*) FROM ssvc_inputs").fetchone()[0] > 10_000


def test_an_unchanged_archive_is_not_downloaded_again(tmp_path):
    files = T._feeds()
    etags = {U._ssvc.VULNRICHMENT_URL: '"abc"'}
    assert U.run_update(tmp_path, selectors=["debian:12"], session=T.FakeSession(files, etags=etags)).ok
    s = T.FakeSession(files, etags=etags)
    res = U.run_update(tmp_path, selectors=["debian:12"], session=s)
    assert res.sources["CISA SSVC"] == "unchanged"
    assert ("If-None-Match", '"abc"') in [kv for u, h in s.requests if u == U._ssvc.VULNRICHMENT_URL for kv in h.items()]


def test_an_index_built_before_d3_answers_with_no_cisa_rows(tmp_path):
    conn = sqlite3.connect(":memory:")
    assert SS.lookup(conn, ["CVE-2024-3094"]) == {}


def test_the_rows_are_swapped_with_the_rest_of_the_index(tmp_path):
    assert T.build(tmp_path).ok
    files = T._feeds()
    files[U._ssvc.VULNRICHMENT_URL] = build_tar({"CVE-2026-7777": cve_record(
        "CVE-2026-7777", {"Exploitation": "active", "Automatable": "yes", "Technical Impact": "total"})})
    old = IX.open_readonly(tmp_path)          # a reader holding the old file keeps reading the old rows
    assert U.run_update(tmp_path, selectors=["debian:12"], session=T.FakeSession(files)).ok
    assert SS.lookup(old, ["CVE-2026-7777"]) == {}
    assert SS.lookup(IX.open_readonly(tmp_path), ["CVE-2026-7777"])["CVE-2026-7777"]["exploitation"] == "active"


def test_notices_name_vulnrichment_and_the_cisa_guide():
    assert "vulnrichment" in U.NOTICES and "CC0" in U.NOTICES and "CISA Stakeholder-Specific" in U.NOTICES
    json.dumps(U.NOTICES)
