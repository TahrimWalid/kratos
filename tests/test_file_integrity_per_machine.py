"""File-integrity baselines are per machine (found during B.3's real run: with two machines
in one data folder, checking the second diffed against the first one's baseline and the
answer said its /etc/passwd and /etc/crontab had changed)."""
from __future__ import annotations

import json

from kratos.agent import tools

A, B = "ubuntu@192.0.2.10", "ubuntu@192.0.2.11"
HASHES_A = {"/etc/passwd": "a1", "/etc/crontab": "a2"}
HASHES_B = {"/etc/passwd": "b1", "/etc/crontab": "b2"}


def _check(monkeypatch, tmp_path, target, hashes, name="default"):
    monkeypatch.setattr(tools, "_ssh_target_label", lambda: target)
    monkeypatch.setattr(tools, "_fetch_file_hashes", lambda: dict(hashes))
    return tools.tool_check_file_integrity(tmp_path, baseline_name=name)


def test_another_machines_baseline_is_never_used(monkeypatch, tmp_path):
    assert _check(monkeypatch, tmp_path, A, HASHES_A)["status"] == "baseline_established"
    first_b = _check(monkeypatch, tmp_path, B, HASHES_B)
    assert first_b["status"] == "baseline_established"          # not "ok" with every file "changed"
    again_b = _check(monkeypatch, tmp_path, B, HASHES_B)
    assert again_b["status"] == "ok" and again_b["diff"]["changed"] == []
    again_a = _check(monkeypatch, tmp_path, A, HASHES_A)
    assert again_a["status"] == "ok" and again_a["diff"]["changed"] == []


def test_a_new_baseline_name_falls_back_only_to_this_machines_baseline(monkeypatch, tmp_path):
    _check(monkeypatch, tmp_path, A, HASHES_A)
    out = _check(monkeypatch, tmp_path, B, HASHES_B, name="initial_audit")
    assert out["status"] == "baseline_established"
    tampered = dict(HASHES_B, **{"/etc/passwd": "evil"})
    out = _check(monkeypatch, tmp_path, B, tampered, name="another_name")
    assert out["status"] == "ok" and "baseline_fallback" in out
    assert [c["path"] for c in out["diff"]["changed"]] == ["/etc/passwd"]


def test_a_baseline_written_before_this_change_still_serves_its_own_machine(monkeypatch, tmp_path):
    legacy = tmp_path / "baseline" / "file_integrity_default.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text(json.dumps({"baseline_name": "default", "target": A, "created_at": "2026-01-01T00:00:00+00:00",
                                  "hashes": HASHES_A}))
    out = _check(monkeypatch, tmp_path, A, dict(HASHES_A, **{"/etc/crontab": "changed"}))
    assert out["status"] == "ok" and [c["path"] for c in out["diff"]["changed"]] == ["/etc/crontab"]
    assert _check(monkeypatch, tmp_path, B, HASHES_B)["status"] == "baseline_established"
