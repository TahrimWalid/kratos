"""E.4: candidates come from snapshots only, the decision order holds row by row, package
checksums per family, HASH-001/002/003 as specified -- and a reputation never lowers any
finding (README §1 rule 6)."""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time
from pathlib import Path

import pytest

from kratos.hashdb import annotate, candidates as C, datasets as D, judge as J, malwarebazaar as M, record
from kratos.hashdb import reputation as R

SHA_BAD = hashlib.sha256(b"kratos-test-known-bad").hexdigest()
SHA_OK = hashlib.sha256(b"kratos-test-ok").hexdigest()


class KB:
    def __init__(self, bad: dict[str, dict] | None = None):
        self.bad = bad or {}

    def get(self, h):
        return self.bad.get(h)


class KG(set):
    pass


def _fact(**kw):
    base = {"status": "ok", "sha256": SHA_OK, "sha1": "a" * 40, "md5": "c" * 32, "type": "elf64", "packers": [],
            "entropy": 6.0, "size": 10, "mode": "755", "uid": 0}
    base.update(kw)
    return base


def _decide(fact, cand=None, kb=None, kg=None, **kw):
    return R.decide(fact, cand or {"path": "/x"}, known_bad=kb, known_good=kg, entropy_threshold=7.2, **kw)


# --------------------------------------------------------------------------- the order
def test_precedence_table_row_by_row():
    kb = KB({SHA_BAD: {"signature": "Fam", "first_seen": "2026-01-01"}})
    kg = KG({"a" * 40})
    md5 = [{"algo": "md5", "digest": "c" * 32}]
    # known_bad beats a matching package checksum and a known-good SHA-1
    r = _decide(_fact(sha256=SHA_BAD, package="coreutils", pkg_digests=md5), kb=kb, kg=kg)
    assert r.verdict == "known_bad" and "reinstall it from the distribution" in r.note
    # package_modified beats known-good
    assert _decide(_fact(package="p", pkg_digests=[{"algo": "md5", "digest": "0" * 32}]), kb=kb, kg=kg).verdict \
        == "package_modified"
    assert _decide(_fact(package="p", pkg_digests=md5), kb=kb, kg=kg).verdict == "package"
    assert _decide(_fact(), kb=kb, kg=kg).verdict == "known_good"
    assert _decide(_fact(sha1="b" * 40), kb=kb, kg=kg).verdict == "unknown"
    nc = _decide({"status": "unreadable"}, kb=kb, kg=kg)
    assert nc.verdict == "not_checked" and nc.reason == "unreadable"


def test_known_bad_from_the_snapshot_hash_when_the_file_cant_be_read_now():
    kb = KB({SHA_BAD: {"signature": "", "first_seen": ""}})
    r = _decide({"status": "unreadable"}, {"path": "/x", "sha256": SHA_BAD}, kb=kb, not_read="unreadable_ssh")
    assert r.verdict == "known_bad" and "earlier read" in r.note


def test_reputation_without_datasets():
    r = _decide(_fact())
    assert r.verdict == "unknown" and "no known-good set" in r.note and "no known-bad set" in r.note
    assert _decide(_fact(package="p", pkg_digests=[{"algo": "md5", "digest": "c" * 32}])).verdict == "package"


@pytest.mark.parametrize("algo, field, value", [
    ("md5", "md5", "c" * 32), ("sha1", "sha1", "a" * 40), ("sha256", "sha256", SHA_OK),
    ("apk-q1", "sha1", "Q1" + base64.b64encode(bytes.fromhex("a" * 40)).decode()),
])
def test_package_checksum_per_family(algo, field, value):
    good = _decide(_fact(package="p", pkg_digests=[{"algo": algo, "digest": value}]))
    assert good.verdict == "package", algo
    bad_value = ("Q1" + base64.b64encode(bytes.fromhex("b" * 40)).decode() if algo == "apk-q1"
                 else value[:-4] + ("0000" if not value.endswith("0000") else "1111"))
    bad = _decide(_fact(package="p", pkg_digests=[{"algo": algo, "digest": bad_value}]))
    assert bad.verdict == "package_modified", algo


def test_package_modified_precedence_uses_the_verify_read():
    r = _decide({"status": "hardlink"}, {"path": "/x", "package": "p", "package_verify": "changed"})
    assert r.verdict == "package_modified"
    r = _decide({"status": "hardlink"}, {"path": "/x", "package": "p", "package_verify": "unchanged"})
    assert r.verdict == "package" and "hard-linked" in r.note
    assert _decide({"status": "hardlink"}, {"path": "/x"}).reason == "hardlink"


# --------------------------------------------------------------------------- findings
def _judge(cands, facts, reps):
    return J.judge(cands, facts, reps, over_cap=0, target="m", via="ssh", datasets_note="")


def test_hash001_present_and_running_severities_and_entity():
    kb = KB({SHA_BAD: {"signature": "TestFam", "first_seen": "2026-01-01 00:00:00"}})
    for running, sev in (([], "high"), ([42], "critical")):
        c = {"path": "/tmp/a", "uses": ["dropped"], "running": running}
        f = _fact(sha256=SHA_BAD)
        sig = [s for s in _judge([c], {0: f}, [_decide(f, c, kb=kb)]) if s["rule"] == "HASH-001"]
        assert len(sig) == 1 and sig[0]["severity"] == sev
        assert sig[0]["entities"] == [f"/tmp/a#{SHA_BAD[:12]}"] and sig[0]["subject"] == "/tmp/a"
        assert "TestFam" not in sig[0]["title"] and "/tmp/a" not in sig[0]["title"]    # third-party text: evidence only
        assert any("TestFam" in e for e in sig[0]["evidence"])


def test_hash002_suppression_list():
    packed = dict(packers=["upx"])
    c = {"path": "/dev/shm/p"}
    assert [s["rule"] for s in _judge([c], {0: _fact(**packed)}, [_decide(_fact(**packed))])] == ["HASH-002"]
    assert [s["rule"] for s in _judge([c], {0: _fact(entropy=7.9)}, [_decide(_fact(entropy=7.9))])] == ["HASH-002"]
    for fact, kg in ((_fact(package="p", pkg_digests=[{"algo": "md5", "digest": "c" * 32}], **packed), None),
                     (_fact(package="p", pkg_digests=[{"algo": "md5", "digest": "0" * 32}], **packed), None),
                     (_fact(package="p", **packed), None),                 # owned, checksum not comparable
                     (_fact(**packed), KG({"a" * 40}))):
        assert not _judge([c], {0: fact}, [_decide(fact, kg=kg)]), fact


def test_compressed_not_high_entropy_finding():
    f = _fact(type="other", entropy=7.99)
    assert not _judge([{"path": "/tmp/x.gz"}], {0: f}, [_decide(f)])


def test_hash003_reasons_with_their_fixes():
    cands = [{"path": f"/p{i}"} for i in range(3)]
    reps = [_decide(None, c, not_read=why) for c, why in zip(cands, ("unreadable_ssh", "old_agent", "too_large"))]
    sig = J.judge(cands, {}, reps, over_cap=7, target="m", via="ssh", datasets_note="")
    text = "\n".join(sig[0]["evidence"])
    assert sig[0]["rule"] == "HASH-003" and sig[0]["severity"] == "info"
    assert "only root can read this -- read this machine through its sub-agent" in text
    assert "update the agent (`g` in /subagent)" in text and "hashdb.max_run_mb" in text
    assert "7 file(s) not checked: more candidates than one check looks at -- raise hashdb.max_files" in text


# --------------------------------------------------------------------------- never lowers
def _every_rule():
    from kratos.lifecycle.rules import RULES

    return sorted(RULES)


@pytest.mark.parametrize("rule_id", _every_rule())
@pytest.mark.parametrize("verdict", R.VERDICTS)
def test_reputation_never_lowers_any_rule(rule_id, verdict):
    from dataclasses import asdict

    from kratos.adapters.findings_engine import Finding

    for sev in ("critical", "high", "medium", "low", "info"):
        f = Finding(id=rule_id, title="t", severity=sev, evidence=["e"], recommendation=["r"], subject="/tmp/.b",
                    entities=[f"/tmp/.b#{SHA_OK[:12]}", "/tmp/.b|7|100"])
        before = asdict(f)
        annotate.attach([f], {"checked_at": "now", "files": [
            {"path": "/tmp/.b", "sha256": SHA_OK, "verdict": verdict, "note": "", "sources": []}]})
        after = asdict(f)
        assert after.pop("reputation")[0]["verdict"] == verdict
        before.pop("reputation")
        assert after == before          # severity, title, entities, state: untouched


def test_known_good_setuid_in_tmp_stays_persist003_high(tmp_path, monkeypatch):
    """The README §5.1 promise end to end: a known-good bash copied setuid into /tmp."""
    from kratos.adapters.findings_engine import Finding

    f = Finding(id="PERSIST-003", title="A setuid program that no package installed", severity="high",
                evidence=[], recommendation=[], entities=[f"/tmp/.b#{SHA_OK[:12]}"])
    annotate.attach([f], {"checked_at": "now", "files": [
        {"path": "/tmp/.b", "sha256": SHA_OK, "verdict": "known_good", "sources": [],
         "note": "probably known-good (CIRCL set, Bloom filter) -- a known program in an unusual place or with "
                 "unusual permissions is still a risk"}]})
    assert f.severity == "high" and f.reputation[0]["label"] == "probably known-good (CIRCL)"
    assert "still a risk" in f.reputation[0]["note"]


# --------------------------------------------------------------------------- candidates
def test_candidates_come_only_from_snapshots_and_are_ordered_and_capped():
    docs = {"persistence": {"checked_at": "t1", "hash_candidates": [
                {"path": f"/usr/bin/s{i}", "uses": ["setuid program"], "suid": True, "package": "pkg"}
                for i in range(5)] + [{"path": "/opt/known", "sha256": SHA_BAD, "uses": ["x"]},
                                      {"path": "/etc/cron.daily/job", "uses": ["startup"]}]},
            "live_response": {"checked_at": "t2", "hash_candidates": [
                {"path": "/tmp/run", "running": [5], "uses": ["running"]},
                {"path": "/tmp/drop", "dropped": True, "uses": ["dropped"]}]}}
    sel = C.select(docs, max_files=4, known_bad=lambda h: h == SHA_BAD)
    assert [c["path"] for c in sel.chosen] == ["/opt/known", "/tmp/run", "/usr/bin/s0", "/usr/bin/s1"]
    assert len(sel.over_cap) == 5 and "/tmp/drop" in sel.snapshot_paths
    assert C.select({"persistence": None, "live_response": None}, max_files=10).missing == ["persistence",
                                                                                           "live_response"]


def test_candidate_cap_order_on_a_busy_host():
    docs = {"persistence": {"hash_candidates": [{"path": f"/usr/lib/x/{i:05d}", "package": "p", "uses": ["u"]}
                                                for i in range(10000)]},
            "live_response": {"hash_candidates": [{"path": "/tmp/r", "running": [1], "uses": ["r"]}]}}
    sel = C.select(docs, max_files=500)
    assert len(sel.chosen) == 500 and sel.chosen[0]["path"] == "/tmp/r" and len(sel.over_cap) == 9501


def test_container_layers_are_never_candidates():
    # the persistence read prunes image layers before anything is listed; a candidate list built from its
    # inventory therefore has none -- and from_live never lists a packaged program running normally
    inv = {"procs": {7: {"pid": 7, "exe": "/usr/bin/sleep", "exe_package": "coreutils", "uid": 0},
                     8: {"pid": 8, "exe": "/var/lib/docker/overlay2/x/merged/bin/sh", "exe_package": None, "uid": 0},
                     9: {"pid": 9, "exe": "/opt/app (deleted)", "uid": 0}}, "temp_files": {}}
    paths = {c["path"] for c in C.from_live(inv)}
    assert "/usr/bin/sleep" not in paths and "/proc/9/exe" in paths


def test_from_persistence_picks_executables_refs_and_modules():
    inv = {"items": {"/usr/bin/su": {"perm": "4755", "type": "regular file", "suid_bits": True, "package": "util"},
                     "/etc/cron.d/job": {"perm": "644", "type": "regular file"},
                     "/etc/cron.daily/run": {"perm": "755", "type": "regular file", "sha256": SHA_OK}},
           "refs": {"/opt/bin/agent": None}, "modules": {"m": {"name": "m", "path": "/lib/modules/m.ko"}},
           "verify": {"done": True, "changed": {"/usr/bin/su": {"content_changed": True}}}}
    by = {c["path"]: c for c in C.from_persistence(inv)}
    assert set(by) == {"/usr/bin/su", "/etc/cron.daily/run", "/opt/bin/agent", "/lib/modules/m.ko"}
    assert by["/usr/bin/su"]["suid"] and by["/usr/bin/su"]["package_verify"] == "changed"


# --------------------------------------------------------------------------- record + engine
def _scratch_known_bad(data_dir: Path, sha: str) -> None:
    D.folder(data_dir)
    c = sqlite3.connect(data_dir / "hashdb" / M.DATASET.file)
    c.execute("CREATE TABLE samples (sha256 TEXT PRIMARY KEY, first_seen TEXT, signature TEXT, tags TEXT)")
    c.execute("INSERT INTO samples VALUES (?, '2026-01-01', 'KratosTestFamily', '')", (sha,))
    c.commit()
    c.close()
    D.record_installed(data_dir, M.DATASET, version="scratch", sha256="0" * 64, size=1, fetched_at=time.time(),
                       detail={"rows": 1})


DOCS = {"persistence": {"checked_at": "t", "hash_candidates": [
            {"path": "/tmp/.b", "uses": ["setuid program"], "suid": True}]},
        "live_response": {"checked_at": "t", "hash_candidates": [
            {"path": "/tmp/m", "uses": ["running (pid 9)"], "running": [9]}]}}


def _fetch(by_path):
    def f(paths, **kw):
        return {"via": "ssh", "reader_uid": 1000, "complete": True,
                "files": {i: by_path[p.decode()] for i, p in enumerate(paths)}}
    return f


def test_record_end_to_end_with_a_scratch_known_bad_set(tmp_path):
    _scratch_known_bad(tmp_path, SHA_BAD)
    doc = record.run(tmp_path, "10.0.0.9", docs=DOCS, fetch=_fetch({
        "/tmp/.b": _fact(), "/tmp/m": _fact(sha256=SHA_BAD)}))
    rules = {s["rule"]: s for s in doc["signals"]}
    assert rules["HASH-001"]["severity"] == "critical" and "HASH-003" in rules    # CIRCL missing is said
    from kratos.hashdb import store
    rows = store.lookup(tmp_path, SHA_BAD)
    assert rows[0]["verdict"] == "known_bad" and rows[0]["target_key"] == "10.0.0.9"
    saved = json.loads(Path(doc["file"]).read_text())
    assert saved["counts"]["known_bad"] == 1 and saved["datasets"]["malwarebazaar"] == "scratch"


def test_file_changed_since_snapshot_is_judged_on_the_new_content(tmp_path):
    docs = {"persistence": {"hash_candidates": [{"path": "/tmp/x", "sha256": SHA_OK, "uses": ["u"]}]},
            "live_response": {"hash_candidates": []}}
    _scratch_known_bad(tmp_path, SHA_BAD)
    doc = record.run(tmp_path, "m", docs=docs, fetch=_fetch({"/tmp/x": _fact(sha256=SHA_BAD)}))
    sig = [s for s in doc["signals"] if s["rule"] == "HASH-001"][0]
    assert sig["entities"] == [f"/tmp/x#{SHA_BAD[:12]}"]
    assert any("changed since Kratos last saw it" in e for e in sig["evidence"])


def test_file_gone_and_ssh_unreadable_wording(tmp_path):
    docs = {"persistence": {"hash_candidates": [{"path": "/tmp/gone", "uses": ["u"]},
                                                {"path": "/root/x", "uses": ["u"]}]}, "live_response": None}
    doc = record.run(tmp_path, "m", docs=docs, fetch=_fetch({"/tmp/gone": {"status": "missing"},
                                                              "/root/x": {"status": "unreadable"}}))
    text = "\n".join(next(s for s in doc["signals"] if s["rule"] == "HASH-003")["evidence"])
    assert "the file is gone" in text and "only root can read this (" not in text
    assert "only root can read this -- read this machine through its sub-agent" in text
    assert "no recent running-process read" in " ".join(doc["coverage_gaps"]) and not doc["complete"]


def test_old_agent_degrades(tmp_path):
    from kratos.adapters.ssh_remote import SSHResult

    def old(paths, **kw):
        return SSHResult(ok=False, returncode=-1, stdout="", via="subagent", stderr=(
            "via the sub-agent: this box runs sub-agent 0.11.1; the file_facts read needs 0.12.0 or newer -- update "
            "the agent (`g` in /subagent, select the box). Nothing was read for this part."))
    doc = record.run(tmp_path, "m", docs=DOCS, fetch=old)
    text = "\n".join(next(s for s in doc["signals"] if s["rule"] == "HASH-003")["evidence"])
    assert "2 file(s) not checked: this machine's sub-agent is too old" in text and "`g` in /subagent" in text
    assert doc["status"] == "ok" and not doc["complete"]


def test_per_machine_rows(tmp_path):
    for m in ("10.0.0.1", "10.0.0.2"):
        record.run(tmp_path, m, docs=DOCS, fetch=_fetch({"/tmp/.b": _fact(), "/tmp/m": _fact()}))
    from kratos.hashdb import store
    assert sorted(r["target_key"] for r in store.lookup(tmp_path, SHA_OK)) == ["10.0.0.1", "10.0.0.2"]


def test_hash_findings_reach_the_report_with_lifecycle_and_attack(tmp_path, monkeypatch):
    from kratos.adapters import findings_engine as FE

    monkeypatch.setattr("kratos.kratos_config.get_active_target", lambda: "10.0.0.9")
    _scratch_known_bad(tmp_path, SHA_BAD)
    record.run(tmp_path, "10.0.0.9", docs=DOCS, fetch=_fetch({"/tmp/.b": _fact(packers=["upx"]),
                                                             "/tmp/m": _fact(sha256=SHA_BAD)}))
    out = FE.write_findings_report(tmp_path)
    rep = json.loads(Path(out["json_path"] if isinstance(out, dict) and "json_path" in out else
                          sorted((tmp_path / "reports").glob("findings_*.json"))[-1]).read_text())
    by = {f["id"]: f for f in rep["findings"]}
    assert by["HASH-001"]["severity"] == "critical" and by["HASH-001"]["attack"][0]["technique_id"] == "T1105"
    assert by["HASH-002"]["attack"][0]["technique_id"] == "T1027.002"
    assert by["HASH-001"]["reputation"][0]["verdict"] == "known_bad"
    assert by["HASH-001"].get("state") in ("open", "new") or by["HASH-001"].get("change")
    md = sorted((tmp_path / "reports").glob("findings_*.md"))[-1].read_text()
    assert "**Reputation** of `/tmp/m`: known-bad (MalwareBazaar)" in md


def test_a_copy_of_a_packaged_program_is_known_good_and_still_never_lowers():
    copy = [{"package": "bash", "path": "/usr/bin/bash"}]
    r = _decide(_fact(package_copy=copy))
    assert r.verdict == "known_good" and r.sources[0]["source"] == "package_copy"
    assert "copy of a packaged program" in R.short_tag(r.as_dict()) and "still a risk" in r.note
    # known-bad still wins, and an owned file is judged by its own package, not as a copy
    kb = KB({SHA_OK: {"signature": "", "first_seen": ""}})
    assert _decide(_fact(package_copy=copy), kb=kb).verdict == "known_bad"
    owned = _fact(package="p", package_copy=copy, pkg_digests=[{"algo": "md5", "digest": "0" * 32}])
    assert _decide(owned).verdict == "package_modified"
    # and HASH-002 is not raised for it even when packed
    f = _fact(package_copy=copy, packers=["upx"])
    assert not _judge([{"path": "/tmp/x"}], {0: f}, [_decide(f)])


def test_a_dpkg_configuration_file_is_compared_with_its_recorded_checksum():
    same = _decide(_fact(package="cron", pkg_digests=[{"algo": "md5c", "digest": "c" * 32}]))
    assert same.verdict == "package"
    edited = _decide(_fact(package="cron", pkg_digests=[{"algo": "md5c", "digest": "0" * 32}]))
    assert edited.verdict == "package_modified" and "configuration file" in edited.note
