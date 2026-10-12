"""Tamper checks (spec §6): each signal on fixtures, and the things that must NOT
fire -- rotations (rename, copytruncate, logrotate), retention gaps, interleaved
journals, clean boots, a first look."""
from __future__ import annotations

import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from kratos.logsources import integrity, state_store, tamper, utmp
from kratos.adapters.ssh_remote import SSHResult

T0 = 1_791_700_000.0
P = "/var/log/auth.log"


def _st(inode, size, head="h1", status="ok", path=P, mtime=1):
    return {"path": path, "status": status, "inode": inode, "size": size, "mtime": mtime, "head_hash": head}


def test_a_small_file_growing_is_not_a_rewrite():
    # under 4 KiB the hashed "head" is the whole file, so a plain append changes it
    res, _ = _check(_st(10, 900, head="grew"), _prev(10, 0, head="empty"))
    assert res["status"] == "ok" and not res["items"]


def _prev(inode, size, head="h1", rot=None, status="ok"):
    row = {"path": P, "inode": inode, "size": size, "mtime": 1, "head_hash": head, "status": status,
           "rot_path": None, "rot_inode": None, "rot_size": None, "rot_mtime": None, "checked_at": T0}
    if rot:
        row.update(rot_path=P + ".1", rot_inode=rot[0], rot_size=rot[1], rot_mtime=rot[2])
    return {P: row}


def _check(cur, prev, rot=None, lr=None, lr_before=None):
    current = {"files": {P: cur}, "rotations": {P: rot} if rot else {}, "logrotate": lr or {}}
    return tamper.check_file_states(current, prev, lr_before)


def test_first_look_is_a_baseline_only():
    res, rows = _check(_st(10, 500), {})
    assert res["status"] == "ok" and not res["items"] and "baseline" in res["coverage"]
    assert rows[0]["inode"] == 10


def test_rename_rotation_is_not_tampering():
    res, _ = _check(_st(11, 40), _prev(10, 500, rot=(5, 900, 1)), rot=_st(10, 520, path=P + ".1", mtime=2))
    assert res["status"] == "ok", res


def test_copytruncate_rotation_is_not_tampering():
    res, _ = _check(_st(10, 30, head="new"), _prev(10, 500, rot=(5, 900, 1)), rot=_st(7, 510, path=P + ".1", mtime=2))
    assert res["status"] == "ok", res


def test_logrotate_record_corroborates_a_rotation():
    res, _ = _check(_st(12, 30), _prev(10, 500, rot=(5, 900, 1)), rot=_st(5, 900, path=P + ".1", mtime=1),
                    lr={P: "2026-10-12-0:0:3"}, lr_before={P: "2026-10-11-0:0:2"})
    assert res["status"] == "ok", res


@pytest.mark.parametrize("cur, rot, kind", [
    (_st(10, 0, head="e3b0"), _st(5, 900, path=P + ".1", mtime=1), "truncated"),          # truncate -s 0
    (_st(10, 200, head="h1"), None, "truncated"),                                           # cut, no rotation file at all
    (_st(99, 480), _st(5, 900, path=P + ".1", mtime=1), "replaced"),                        # sed -i / rm + recreate
    (_st(10, 6000, head="CHANGED"), _st(5, 900, path=P + ".1", mtime=1), "rewritten"),      # edited in place
    (_st(None, None, head=None, status="missing"), _st(5, 900, path=P + ".1", mtime=1), "deleted"),
    (_st(None, None, head=None, status="symlink"), _st(5, 900, path=P + ".1", mtime=1), "linked"),   # ln -sf /dev/null
])
def test_tampering_signals(cur, rot, kind):
    res, _ = _check(cur, _prev(10, 5000, rot=(5, 900, 1)), rot=rot)
    assert res["status"] == "suspicious"
    assert [i["kind"] for i in res["items"]] == [kind]
    assert P in res["evidence"][0]


def test_copytruncate_with_a_too_small_copy_is_still_truncation():
    res, _ = _check(_st(10, 30), _prev(10, 5000, rot=(5, 900, 1)), rot=_st(7, 100, path=P + ".1", mtime=2))
    assert [i["kind"] for i in res["items"]] == ["truncated"]


def test_wtmp_shrink_is_marked_as_a_login_record():
    path = "/var/log/wtmp"
    current = {"files": {path: _st(10, 384, path=path)}, "rotations": {}}
    prev = {path: {**_prev(10, 3840)[P], "path": path}}
    res, _ = tamper.check_file_states(current, prev)
    assert res["items"][0]["login_record"] and res["items"][0]["kind"] == "truncated"


# --- journal continuity ------------------------------------------------------
def _jf(name, sid, head, tail, journal="system", entries=None, d="/var/log/journal/" + "a" * 32):
    return {"dir": d, "name": name, "journal": journal, "seqnum_id": sid, "head_seqnum": head, "tail_seqnum": tail,
            "header_read": True, "head_realtime": T0 + head, "tail_realtime": T0 + tail,
            "header": {"Entry objects": str(entries if entries is not None else tail - head + 1)}}


def test_journal_gap_in_the_middle_is_flagged():
    files = [_jf("system@1.journal", "s", 1, 1000), _jf("system@3.journal", "s", 2001, 3000),
             _jf("system.journal", "s", 3001, 3100)]
    res = tamper.check_journal({"available": True, "files": files})
    assert res["status"] == "suspicious"
    assert res["items"][0]["missing_from"] == 1001 and res["items"][0]["missing_to"] == 2000


def test_journal_gap_at_the_start_is_normal_retention():
    files = [_jf("system@3.journal", "s", 2001, 3000), _jf("system.journal", "s", 3001, 3100)]
    assert tamper.check_journal({"available": True, "files": files})["status"] == "ok"


def test_real_interleaved_system_and_user_journals_are_not_a_gap():
    # kratos-tt-skew (systemd 249), 2026-10-11: user journal numbers fill the system journal's small gaps.
    files = [_jf("s1", "ca", 1, 1216), _jf("s2", "ca", 1217, 2067), _jf("s3", "ca", 2068, 2249),
             _jf("system.journal", "ca", 2252, 9259),
             _jf("u1", "5e", 1236, 2043, journal="user-1000", entries=300),
             _jf("u2", "5e", 2163, 2251, journal="user-1000", entries=40),
             _jf("user-1000.journal", "5e", 2254, 9433, journal="user-1000", entries=500)]
    assert tamper.check_journal({"available": True, "files": files})["status"] == "ok"


def test_deleting_the_middle_system_file_of_the_real_layout_is_caught():
    files = [_jf("s1", "ca", 1, 1216), _jf("s3", "ca", 2068, 2249), _jf("system.journal", "ca", 2252, 9259),
             _jf("u1", "5e", 1236, 2043, journal="user-1000", entries=300),
             _jf("u2", "5e", 2163, 2251, journal="user-1000", entries=40)]
    res = tamper.check_journal({"available": True, "files": files})
    assert res["status"] == "suspicious" and res["items"][0]["after"] == "s1"


def test_one_deleted_file_is_one_gap_even_when_it_shows_in_two_journals():
    # real kratos-target layout after `rm` of a middle system archive: the user journal's
    # own gap was explained by that very file, so it opens too -- still one deletion.
    files = [_jf("s1", "a6", 1, 4540), _jf("s2", "a6", 4541, 4690), _jf("s4", "a6", 4842, 4990),
             _jf("system.journal", "a6", 4991, 5100),
             _jf("u1", "18", 1553, 2094, journal="user-1000", entries=300),
             _jf("user-1000.journal", "18", 4700, 5200, journal="user-1000", entries=20)]
    res = tamper.check_journal({"available": True, "files": files})
    assert len(res["items"]) == 1 and len(res["evidence"]) == 1
    assert (res["items"][0]["after"], res["items"][0]["before"]) == ("s2", "s4")   # the precise place


def test_unreadable_journal_is_unknown_not_ok():
    res = tamper.check_journal({"available": True, "files": [], "unreadable_dirs": ["/run/log/journal/x"]})
    assert res["status"] == "unknown" and "systemd-journal" in res["coverage"]


# --- boots -------------------------------------------------------------------
def test_unclean_previous_boot_is_context_and_clean_is_not():
    hist = {"available": True, "container": None, "boots": [
        {"boot_id": "a" * 32, "last_ts": T0, "entries": 60, "clean": False, "marker": None},
        {"boot_id": "b" * 32, "last_ts": T0 + 10, "entries": 60, "clean": True, "marker": "Reached target Power-Off"},
        {"boot_id": "c" * 32, "last_ts": T0 - 90 * 86400, "entries": 60, "clean": False, "marker": None}]}
    res = tamper.check_boots(hist, now=T0 + 100)
    assert [i["boot_id"][0] for i in res["items"]] == ["a"]
    assert "not proof of tampering" in res["evidence"][0]


def test_boot_parser_on_real_shapes():
    from kratos.logsources import hostfiles as H

    clean = '{"MESSAGE":"Reached target Power-Off.","_PID":"1","__REALTIME_TIMESTAMP":"1791700000000000"}'
    unclean = '{"MESSAGE":"Stopped User Runtime Directory /run/user/1000.","_PID":"1","__REALTIME_TIMESTAMP":"1791700001000000"}'
    out = H.parse_boot_history("\n".join([
        "M\tcontainer\tlxc", "M\tcurrent_boot\t" + "c" * 32,
        "B\t" + "a" * 32, "BE\t" + "a" * 32 + "\t" + clean,
        "B\t" + "b" * 32, "BE\t" + "b" * 32 + "\t" + unclean,
        "B\t" + "c" * 32, "BE\t" + "c" * 32 + "\t" + unclean]))
    assert [(b["boot_id"][0], b["clean"]) for b in out["boots"]] == [("a", True), ("b", False)]
    assert out["container"] == "lxc"


# --- login records -----------------------------------------------------------
def _rec(t, user="alice", typ=7, line="pts/0"):
    return utmp.RECORD.pack(typ, 0, 100, line.encode(), b"ts/0", user.encode(), b"10.0.0.1", 0, 0, 0, int(t), 0,
                            0, 0, 0, 0, b"")


def test_zeroed_record_between_real_ones():
    data = _rec(T0) + b"\0" * 384 + _rec(T0 + 60)
    res = tamper.check_login_records({"wtmp": {"status": "ok", "data": data, "size": len(data), "offset": 0}})
    assert res["status"] == "suspicious" and res["items"] == [{"file": "wtmp", "kind": "zeroed", "record": 1}]


def test_time_going_backwards_and_clock_change_records():
    data = _rec(T0) + _rec(T0 - 3600)
    res = tamper.check_login_records({"wtmp": {"status": "ok", "data": data, "size": len(data), "offset": 0}})
    assert [i["kind"] for i in res["items"]] == ["out_of_order"]
    ok = _rec(T0) + _rec(T0 - 3600, typ=4, user="") + _rec(T0 - 3590, typ=3, user="") + _rec(T0 - 3500)
    assert tamper.check_login_records({"wtmp": {"status": "ok", "data": ok, "size": len(ok), "offset": 0}})["items"] == []


def test_trailing_zero_records_and_a_clean_file_are_fine():
    data = _rec(T0) + _rec(T0 + 1) + b"\0" * 384
    assert tamper.check_login_records({"wtmp": {"status": "ok", "data": data, "size": len(data), "offset": 0}})["status"] == "ok"


def test_wrong_record_size_is_an_unknown_format():
    res = utmp.check(b"x" * 400, size=400, offset=0, name="wtmp")
    assert res["status"] == "unknown" and "384" in res["coverage"]
    junk = b"\x7f" * 768
    assert utmp.check(junk, size=768, offset=0, name="wtmp")["status"] == "unknown"


def test_unreadable_btmp_over_ssh_is_a_coverage_note():
    res = tamper.check_login_records({"wtmp": None, "btmp": {"status": "unreadable"}})
    assert res["status"] == "unknown" and "sub-agent" in res["coverage"]


# --- auditd ------------------------------------------------------------------
_RUNNING = {"installed": True, "active": "active", "enabled": "enabled", "rules_read": True, "rules": 3,
            "status_read": True, "kernel_enabled": 1}


def test_auditd_stopped_after_running_is_high():
    res, state = tamper.check_auditd({**_RUNNING, "active": "inactive"}, {"active": True, "rules": 3, "_checked_at": T0})
    assert res["status"] == "suspicious" and res["items"][0]["kind"] == "stopped"
    assert state["active"] is False


def test_auditd_rules_emptied_and_kernel_disabled():
    res, _ = tamper.check_auditd({**_RUNNING, "rules": 0, "kernel_enabled": 0},
                                 {"active": True, "rules": 3, "kernel_enabled": 1, "_checked_at": T0})
    assert sorted(i["kind"] for i in res["items"]) == ["disabled", "rules_emptied"]


def test_auditd_not_installed_is_no_finding_and_first_look_is_a_baseline():
    res, state = tamper.check_auditd({"installed": False}, None)
    assert res["status"] == "ok" and not res["items"] and state is None
    assert "process execution history is unavailable" in res["coverage"]
    res2, _ = tamper.check_auditd(_RUNNING, None)
    assert res2["status"] == "ok" and not res2["items"] and "baseline" in res2["coverage"]
    res3, _ = tamper.check_auditd({**_RUNNING, "active": "inactive"}, None)
    assert res3["status"] == "ok" and [i["severity"] for i in res3["items"]] == ["info"]


# --- orchestrator ------------------------------------------------------------
class FakeReader(integrity.Reader):
    def __init__(self):
        self.files = {"files": {P: _st(10, 500)}, "rotations": {}, "logrotate": {}, "via": "ssh"}
        self.fail_journal = False

    def file_states(self):
        return self.files

    def journal_headers(self):
        if self.fail_journal:
            return SSHResult(ok=False, returncode=255, stdout="", stderr="ssh: connect to host x port 22: refused")
        return {"available": True, "files": []}

    def boot_history(self):
        return {"available": True, "boots": []}

    def utmp(self, name):
        return {"status": "missing"}

    def audit_status(self):
        return {"installed": False}


def test_run_remembers_state_and_catches_a_truncation_on_the_next_run(tmp_path):
    r = FakeReader()
    first = integrity.run(tmp_path, "10.136.28.168", reader=r, now=T0)
    assert first["checks"]["file_state"]["status"] == "ok"
    assert Path(first["file"]).exists() and json.loads(Path(first["file"]).read_text())["target"] == "10.136.28.168"
    r.files = {"files": {P: _st(10, 0, head="empty")}, "rotations": {}, "logrotate": {}}
    second = integrity.run(tmp_path, "10.136.28.168", reader=r, now=T0 + 60)
    assert second["checks"]["file_state"]["items"][0]["kind"] == "truncated"
    assert state_store.file_states(tmp_path, "10.136.28.168")[P]["size"] == 0


def test_a_failed_read_is_unknown_with_its_reason_never_ok(tmp_path):
    r = FakeReader()
    r.fail_journal = True
    doc = integrity.run(tmp_path, "h", reader=r, now=T0)
    assert doc["checks"]["journal"]["status"] == "unknown" and "refused" in doc["checks"]["journal"]["coverage"]
    summary = integrity.summary_for_model(doc)
    assert "journal" in summary["coverage_gap"] and summary["sealing"]["status"] == "not set up"


def test_state_is_per_machine(tmp_path):
    r = FakeReader()
    integrity.run(tmp_path, "10.0.0.1", reader=r, now=T0)
    r.files = {"files": {P: _st(10, 0, head="empty")}, "rotations": {}, "logrotate": {}}
    other = integrity.run(tmp_path, "10.0.0.2", reader=r, now=T0 + 60)
    assert other["checks"]["file_state"]["items"] == []    # a first look at the other machine
