"""Journal sealing (spec §7, §10 FSS): the key's format and storage, the
verification engine's decisions, the key never leaving this machine, and a
background verification never blocking anything."""
from __future__ import annotations

import json
import logging
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from kratos import kratos_config
from kratos.logsources import seal, state_store

KEY = "a1b2c3-d4e5f6-a7b8c9-d0e1f2/1a2b3c-35a4e900"
TARGET = "10.136.28.102"
MID = "db5cc976a5f14db789f534fc70e309ab"
T0 = 1_791_700_000.0
JDIR = "/var/log/journal/" + MID


def _f(name, *, sealed=True, head=T0, tail=None, size=1000, archived=None):
    return {"dir": JDIR, "name": name, "header_read": True, "sealed": sealed, "head_realtime": head,
            "tail_realtime": tail or head + 100, "size": size, "archived": ("@" in name) if archived is None else archived,
            "journal": name.split("@")[0].split(".")[0], "seqnum_id": "x", "head_seqnum": 1, "tail_seqnum": 2,
            "dirty": name.endswith("~")}


A1 = "system@" + "c" * 32 + "-0000000000000001-0000000000000001.journal"
A2 = "system@" + "c" * 32 + "-0000000000000100-0000000000000002.journal"


class FakeSealReader(seal.SealReader):
    def __init__(self, files, *, contents=None, mid=MID):
        self.files, self.mid = files, mid
        self.contents = contents or {}
        self.copies: list[str] = []
        self.hashes: list[str] = []
        self.copy_delay = 0.0

    def journal_headers(self):
        return {"available": True, "machine_id": self.mid, "files": self.files}

    def file_hash(self, directory, name):
        self.hashes.append(name)
        data = self.contents.get(name, name.encode())
        import hashlib

        return {"name": name, "size": len(data), "inode": 1, "sha256": hashlib.sha256(data).hexdigest()}

    def copy(self, directory, name, dest, max_bytes):
        time.sleep(self.copy_delay)
        self.copies.append(name)
        data = self.contents.get(name, name.encode())
        Path(dest).write_bytes(data)
        import hashlib

        return {"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


@pytest.fixture
def keyed(tmp_path, monkeypatch):
    seal.set_key(tmp_path, TARGET, KEY, set_by="tester", machine_id=MID)
    results: dict[str, dict[str, Any]] = {}

    def fake_verify(path, key):
        assert key == KEY and Path(path).exists()
        name = Path(path).read_bytes().decode(errors="replace")
        return results.get(name, {"result": "pass", "detail": "=> Validated", "unsealed_tail": 0})

    monkeypatch.setattr(seal, "verify_file_locally", fake_verify)
    return tmp_path, results


# --- the key -----------------------------------------------------------------
@pytest.mark.parametrize("good", [KEY, "000000-000000-000000-000000/1-35a4e900",
                                  "abcdef-abcdef-abcdef-abcdef/65d9-35a4e900"])
def test_key_format_accepts_systemd_keys(good):
    assert seal.validate_key("  " + good + "\n") == good


@pytest.mark.parametrize("bad", ["", "hello", KEY.upper(), KEY + " extra", KEY.replace("/", "-"),
                                 "a1b2c3-d4e5f6-a7b8c9/1a2b3c-35a4e900", "a1b2c3-d4e5f6-a7b8c9-d0e1f2"])
def test_key_format_rejects_anything_else(bad):
    with pytest.raises(seal.SealKeyError):
        seal.validate_key(bad)


def test_key_file_is_owner_only_and_never_written_through_a_link(tmp_path):
    path = seal.set_key(tmp_path, TARGET, KEY, set_by="me")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert seal.load_key(tmp_path, TARGET)["key"] == KEY
    assert "key" not in json.dumps(seal.keys_on_file(tmp_path)).replace('"key_', "")  # listing never shows it
    elsewhere = tmp_path / "elsewhere.json"
    path.unlink()
    path.symlink_to(elsewhere)
    with pytest.raises(seal.SealKeyError):
        seal.set_key(tmp_path, TARGET, KEY, set_by="me")
    assert not elsewhere.exists()
    assert seal.load_key(tmp_path, TARGET) is None


def test_machine_binding_and_a_different_machine(keyed):
    data_dir, _ = keyed
    s = seal.verify(data_dir, TARGET, reader=FakeSealReader([_f("system.journal")], mid="f" * 32), now=T0)
    assert s["status"] == "unverifiable" and "different machine" in s["unverifiable"]
    seal.set_key(data_dir, "10.0.0.9", KEY, set_by="me")            # no machine-id known at setup
    seal.verify(data_dir, "10.0.0.9", reader=FakeSealReader([_f("system.journal")]), now=T0)
    assert seal.load_key(data_dir, "10.0.0.9")["machine_id"] == MID  # bound at the first verification


# --- verification ------------------------------------------------------------
def test_archives_are_verified_once_then_skipped_and_a_changed_one_is_caught(keyed):
    data_dir, _ = keyed
    r = FakeSealReader([_f(A1), _f(A2), _f("system.journal", archived=False)])
    s1 = seal.verify(data_dir, TARGET, reader=r, now=T0)
    assert s1["status"] == "verified" and sorted(s1["passed"]) == sorted([A1, A2, "system.journal"])
    r.copies.clear()
    s2 = seal.verify(data_dir, TARGET, reader=r, now=T0 + 3600)
    assert s2["skipped_unchanged"] == 2 and r.copies == ["system.journal"]   # only the live file again
    r.contents[A1] = b"edited by an attacker"
    s3 = seal.verify(data_dir, TARGET, reader=r, now=T0 + 7200)
    assert s3["status"] == "failed" and [c["name"] for c in s3["changed_archives"]] == [A1]
    assert seal.latest_summary(data_dir, TARGET)["changed_archives"][0]["name"] == A1


def test_a_failed_seal_is_a_failure(keyed):
    data_dir, results = keyed
    results[A1] = {"result": "fail", "detail": "Tag failed verification", "tag_failed": True}
    s = seal.verify(data_dir, TARGET, reader=FakeSealReader([_f(A1)]), now=T0)
    assert s["status"] == "failed" and s["failed"][0]["name"] == A1
    rows = state_store.verifications(data_dir, TARGET)
    assert rows[0]["result"] == "fail" and rows[0]["file_name"] == A1


def test_live_file_corruption_is_retried_once_and_not_a_seal_failure(keyed):
    data_dir, results = keyed
    results["system.journal"] = {"result": "fail", "detail": "File corruption detected", "tag_failed": False}
    r = FakeSealReader([_f("system.journal", archived=False)])
    s = seal.verify(data_dir, TARGET, reader=r, now=T0)
    assert r.copies == ["system.journal", "system.journal"]
    assert s["status"] == "verified" and not s["failed"] and "verified once journald archives it" in " ".join(s["notes"])


def test_entries_from_before_sealing_and_dirty_files_are_not_edits(keyed):
    data_dir, results = keyed
    dirty = "user-1000@00065d99cb1f09ae-8a36662ef8eefdea.journal~"
    results[dirty] = {"result": "before_seal", "detail": "entries from before sealing began"}
    dirty2 = "system@00065d99cb0571ec-c5da174542971a35.journal~"
    results[dirty2] = {"result": "fail", "detail": "File corruption detected", "tag_failed": False}
    s = seal.verify(data_dir, TARGET, reader=FakeSealReader([_f(dirty), _f(dirty2)]), now=T0)
    assert s["status"] == "verified" and not s["failed"]
    assert any("before sealing began" in n for n in s["notes"]) and any("unclean stop" in n for n in s["notes"])
    results[dirty2] = {"result": "fail", "detail": "Tag failed verification", "tag_failed": True}
    s2 = seal.verify(data_dir, TARGET, reader=FakeSealReader([_f(dirty2)]), now=T0 + 7200)
    assert [f["name"] for f in s2["failed"]] == [dirty2]


def test_unsealed_files_newer_than_sealing_mean_sealing_stopped(keyed):
    data_dir, _ = keyed
    files = [_f(A1, head=T0), _f("system.journal", sealed=False, head=T0 + 500, archived=False),
             _f("user-1000@" + "d" * 32 + "-0000000000000001-0000000000000001.journal", sealed=False, head=T0 - 999)]
    s = seal.verify(data_dir, TARGET, reader=FakeSealReader(files), now=T0 + 600)
    assert [u["name"] for u in s["unsealed_after_setup"]] == ["system.journal"]


def test_this_hosts_journalctl_too_old_is_unverifiable_not_tampered(keyed):
    data_dir, results = keyed
    results[A1] = {"result": "unsupported", "detail": "Protocol not supported"}
    s = seal.verify(data_dir, TARGET, reader=FakeSealReader([_f(A1)]), now=T0)
    assert s["status"] == "unverifiable" and "newer" in s["unverifiable"] and not s["failed"]


def test_budget_defers_older_archives(keyed, monkeypatch):
    data_dir, _ = keyed
    from kratos import settings_store

    settings_store.set(seal.SEAL_BUDGET_KEY, 16, data_dir=data_dir, actor="test")
    big = 10 * 1024 * 1024
    files = [_f(A1, size=big, tail=T0 + 10), _f(A2, size=big, tail=T0 + 20)]
    s = seal.verify(data_dir, TARGET, reader=FakeSealReader(files), now=T0)
    assert s["passed"] == [A2] and s["deferred"] == [A1] and "budget" in " ".join(s["notes"])


def test_unreadable_journal_and_no_key(tmp_path, keyed):
    data_dir, _ = keyed

    class Unreadable(FakeSealReader):
        def journal_headers(self):
            return {"available": True, "machine_id": MID, "files": [], "unreadable_dirs": [JDIR]}

    s = seal.verify(data_dir, TARGET, reader=Unreadable([]), now=T0)
    assert s["status"] == "unverifiable" and "systemd-journal" in s["unverifiable"]
    assert seal.verify(tmp_path / "other", TARGET) is None


def test_verify_file_locally_reads_real_journalctl_output(tmp_path, monkeypatch):
    """Output shapes captured from systemd 255 verifying a systemd-249 sealed file."""
    fake = tmp_path / "journalctl"
    outputs = {
        "pass": ("000000: This log file was sealed with an old journald version where the sequence of seals "
                 "might not be continuous. We cannot guarantee completeness.\nPASS: f\n"
                 "=> Validated from Sun 2026-10-11 17:55:10 UTC to Sun 2026-10-11 18:00:00 UTC, final 3 entries not sealed.\n", 0),
        "tag": ("364570: Tag failed verification\nFile corruption detected at f:3556720 (of 8388608 bytes, 42%).\n"
                "FAIL: f (Bad message)\n", 1),
        "corrupt": ("0015e0: Invalid object contents: Bad message\nFile corruption detected at f:5600\n"
                    "FAIL: f (Bad message)\n", 1),
        "old": ("Journal file f uses an unsupported feature, ignoring file.\nFAIL: f (Protocol not supported)\n", 1),
        "early": ("3b3810: Entry realtime (1791741741754637, Sun 2026-10-11 18:02:21 UTC) is too early with respect "
                  "to tag (1791764100000000, Mon 2026-10-12 00:15:00 UTC)\nFile corruption detected at f:3880976\n"
                  "FAIL: f (Bad message)\n", 1),
    }
    got = {}
    for name, (text, rc) in outputs.items():
        fake.write_text(f"#!/bin/sh\ncat <<'EOF' >&2\n{text}EOF\nexit {rc}\n")
        fake.chmod(0o755)
        monkeypatch.setattr(seal.shutil, "which", lambda _n, p=str(fake): p)
        got[name] = seal.verify_file_locally(tmp_path / "x", KEY)
    assert got["pass"]["result"] == "pass" and got["pass"]["unsealed_tail"] == 3 and got["pass"]["old_format_note"]
    assert got["tag"]["result"] == "fail" and got["tag"]["tag_failed"]
    assert got["corrupt"]["result"] == "fail" and not got["corrupt"]["tag_failed"]
    assert got["old"]["result"] == "unsupported"
    assert got["early"]["result"] == "before_seal"      # real systemd-249 output, not an edit


def test_seal_results_reach_the_integrity_file_and_findings(keyed):
    data_dir, results = keyed
    results[A1] = {"result": "fail", "detail": "Tag failed verification", "tag_failed": True}
    seal.verify(data_dir, TARGET, reader=FakeSealReader([_f(A1)]), now=T0)
    from kratos.adapters import findings_engine as FE
    from kratos.logsources import integrity
    from tests.test_logsources_tamper import FakeReader

    doc = integrity.run(data_dir, TARGET, reader=FakeReader())
    assert doc["seal"]["failed"][0]["name"] == A1
    assert "SEAL-001" in {f.id for f in FE._log_integrity_findings(doc)}


# --- the key never leaves this machine ----------------------------------------
def test_the_key_appears_on_no_outbound_or_stored_surface(keyed, monkeypatch, caplog):
    """Model requests, transcripts, logs, SSH argv, sub-agent read params, events and
    finding evidence -- the key is in none of them, through a whole verification and
    an investigation that reads the result."""
    data_dir, results = keyed
    results[A1] = {"result": "fail", "detail": "Tag failed verification", "tag_failed": True}
    caplog.set_level(logging.DEBUG)
    ssh_argv: list[list[str]] = []
    agent_params: list[dict] = []
    http_bodies: list[str] = []
    from kratos.adapters import ssh_remote
    from kratos.subagent import routing

    def fake_run(argv, *a, **k):
        ssh_argv.append(list(argv))
        return subprocess.CompletedProcess(argv, 255, "", "ssh: connect to host refused")

    monkeypatch.setattr(ssh_remote.subprocess, "run", fake_run)
    monkeypatch.setattr(routing, "agent_read", lambda link, probe, params: agent_params.append(params) or
                        {"status": "offline", "reason": "x"})

    class FakeResp:
        status_code = 200

        def __init__(self, body):
            self._body = body

        def json(self):
            return self._body

        def raise_for_status(self):
            return None

    script = iter([json.dumps({"reasoning": "r", "tool": "correlate_findings", "args": {}}),
                   json.dumps({"reasoning": "r", "final_answer": "A sealed journal file failed verification (SEAL-001)."})])

    def fake_post(url, *a, json=None, data=None, **k):
        import json as _j

        http_bodies.append(_j.dumps(json) if json is not None else str(data))
        return FakeResp({"choices": [{"message": {"content": next(script)}}],
                         "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    import requests

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests.Session, "post", lambda self, *a, **k: fake_post(*a, **k))
    # Don't depend on a real reachable LLM endpoint (there is none in CI): the request
    # path is what this test exercises, and fake_post captures it.
    import kratos.llm_interface as _llm
    monkeypatch.setattr(_llm, "check_endpoint_reachable", lambda *a, **k: (True, None))
    kratos_config.set_active_target(TARGET)
    seal.verify(data_dir, TARGET, reader=FakeSealReader([_f(A1)]), now=time.time())
    from kratos.logsources import integrity
    from tests.test_logsources_tamper import FakeReader

    integrity.run(data_dir, TARGET, reader=FakeReader())
    from kratos.agent import loop as agent_loop

    result = agent_loop.run_agent("were the logs edited?", data_dir, max_iters=4)
    surfaces = {
        "model requests": "\n".join(http_bodies),
        "transcript": json.dumps(result, default=str),
        "logs": caplog.text,
        "ssh argv": json.dumps(ssh_argv),
        "agent params": json.dumps(agent_params),
        "events/findings db": (data_dir / "kratos.db").read_bytes().decode("latin-1"),
        "reports": "".join(p.read_text() for p in (data_dir / "reports").glob("*")),
        "integrity files": "".join(p.read_text() for p in (data_dir / "integrity").glob("*")),
    }
    assert http_bodies, "the model was never called -- the test isn't exercising the request path"
    for name, text in surfaces.items():
        assert KEY not in text, f"the verification key leaked into {name}"
    # the only place it is stored
    hits = [p for p in data_dir.rglob("*") if p.is_file() and KEY.encode() in p.read_bytes()]
    assert hits == [seal._key_file(data_dir, TARGET)]


def test_redaction_masks_a_key_anywhere():
    from kratos.events.redact import mask
    from kratos.utils.redact import redact_secrets

    assert KEY not in redact_secrets(f"error: journalctl --verify-key={KEY} failed")
    masked, changed = mask(f"COMMAND=/usr/bin/journalctl --verify --verify-key={KEY}")
    assert KEY not in masked and changed


# --- never blocking -----------------------------------------------------------
def test_a_pending_background_verification_never_slows_the_caller(keyed):
    data_dir, _ = keyed
    r = FakeSealReader([_f(A1), _f(A2)])
    r.copy_delay = 2.0
    started = time.monotonic()
    assert seal.maybe_verify_in_background(data_dir, TARGET, reader=r)
    assert time.monotonic() - started < 0.5
    assert not seal.maybe_verify_in_background(data_dir, TARGET, reader=r)   # one at a time per machine
    seal.stop_background(timeout=5)                                           # stops between files
    assert len(r.copies) <= 1


def test_background_reads_stay_on_their_machine_when_the_target_changes(keyed):
    data_dir, _ = keyed
    seen = []

    class Watch(FakeSealReader):
        def journal_headers(self):
            seen.append(kratos_config.get_active_target())
            kratos_config.set_active_target("10.9.9.9")   # the user switches machines meanwhile
            return super().journal_headers()

        def copy(self, *a, **k):
            seen.append(kratos_config.get_active_target())
            return super().copy(*a, **k)

    kratos_config.set_active_target(TARGET)
    seal.maybe_verify_in_background(data_dir, TARGET, reader=Watch([_f(A1)]))
    for t in list(seal._bg_running.values()):
        t.join(10)
    assert seen and set(seen) == {TARGET}
    kratos_config.set_active_target(None)


def test_due_honours_the_interval(keyed):
    data_dir, _ = keyed
    assert seal.due(data_dir, TARGET)
    seal.verify(data_dir, TARGET, reader=FakeSealReader([_f(A1)]), now=time.time())
    assert not seal.due(data_dir, TARGET)
    assert seal.due(data_dir, TARGET, now=time.time() + 61 * 60)


# --- CLI ------------------------------------------------------------------------
def test_cli_reads_the_key_from_stdin_and_never_prints_it(tmp_path):
    env = {**os.environ, "KRATOS_HOME": str(tmp_path / "home")}
    cmd = [sys.executable, "-m", "kratos.cli.app", "--data-dir", str(tmp_path), "seal", "set-key", TARGET]
    r = subprocess.run(cmd, input=KEY + "\n", capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    assert KEY not in r.stdout + r.stderr and KEY not in " ".join(cmd)   # stdin, never argv
    assert seal.load_key(tmp_path, TARGET)["key"] == KEY
    st = subprocess.run([sys.executable, "-m", "kratos.cli.app", "--data-dir", str(tmp_path), "seal", "status"],
                        capture_output=True, text=True, env=env, timeout=60)
    assert TARGET in st.stdout and KEY not in st.stdout
    bad = subprocess.run([sys.executable, "-m", "kratos.cli.app", "--data-dir", str(tmp_path), "seal", "set-key", TARGET],
                         input="not a key\n", capture_output=True, text=True, env=env, timeout=60)
    assert bad.returncode == 1 and "verification key" in bad.stderr


# --- people decide ----------------------------------------------------------------
def test_no_tool_module_or_the_mcp_server_can_touch_a_sealing_key():
    import ast
    import inspect

    import kratos.mcp_server as mcp_server
    from kratos.agent.tools import TOOL_REGISTRY

    files = {inspect.getsourcefile(t.handler) for t in TOOL_REGISTRY.values()} | {inspect.getsourcefile(mcp_server)}
    offenders = []
    for f in files:
        for node in ast.walk(ast.parse(Path(f).read_text(encoding="utf-8"))):
            name = node.attr if isinstance(node, ast.Attribute) else (node.id if isinstance(node, ast.Name) else None)
            if name in ("set_key", "remove_key", "_bind_machine"):
                offenders.append(f"{f}:{node.lineno} {name}")
    assert offenders == []


def test_setting_or_removing_a_key_is_refused_inside_a_tool_call(tmp_path):
    from kratos import settings_store

    with settings_store.tool_call_scope("check_log_integrity"):
        with pytest.raises(seal.SealKeyError):
            seal.set_key(tmp_path, TARGET, KEY, set_by="model")
        with pytest.raises(seal.SealKeyError):
            seal.remove_key(tmp_path, TARGET)
    assert seal.load_key(tmp_path, TARGET) is None
