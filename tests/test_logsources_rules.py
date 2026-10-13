"""LOG-*/SEAL-* rules (spec §6, §10 Findings): every rule is registered (engine
inputs, lifecycle, ATT&CK v19 labels checked against the official data), comes out
of a check_log_integrity result with the right severity and entities, is scoped
to its machine and freshness, never closes itself (sticky), and the answer guards
still fire on a high tamper finding."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

from kratos import kratos_config
from kratos.adapters import findings_engine as FE
from kratos.agent import loop as agent_loop
from kratos.agent.tools import TOOL_REGISTRY
from kratos.lifecycle import apply as lc_apply
from kratos.lifecycle.coverage import Coverage
from kratos.lifecycle.rules import RULES
from kratos.logsources import attack
from kratos.run_context import run_scope

ATTACK_REF = json.loads((Path(__file__).parent / "fixtures" / "attack_v19_subset.json").read_text())
NEW_RULES = ("LOG-001", "LOG-002", "LOG-003", "LOG-004", "LOG-005", "LOG-006", "SEAL-001", "SEAL-002", "SEAL-003")
TARGET = "10.136.28.168"


def test_every_new_rule_is_registered_everywhere():
    for rid in NEW_RULES:
        assert rid in RULES, rid
        assert FE.rule_inputs(rid) == ("log_integrity",), rid
        assert rid in FE.FINDING_SUMMARY_TEMPLATES, rid
    assert RULES["LOG-003"].kind == "occurrence" and RULES["SEAL-003"].kind == "run_note"


@pytest.mark.parametrize("rule, labels", sorted(attack.RULE_ATTACK.items()))
def test_attack_labels_match_the_official_v19_data(rule, labels):
    assert ATTACK_REF["version"] == attack.ATTACK_VERSION == "19.0"
    for label in labels:
        ref = ATTACK_REF["techniques"][label["technique_id"]]
        assert not ref["revoked"], f"{label['technique_id']} is revoked in v19"
        assert ref["name"] == label["technique"]
        tactics = {ATTACK_REF["tactics"][t]["name"]: ATTACK_REF["tactics"][t]["id"] for t in ref["tactics"]}
        assert tactics.get(label["tactic"]) == label["tactic_id"]
        assert label["url"] == ref["url"]


def test_the_old_ids_the_spec_named_are_revoked_in_v19():
    for old, new in (("T1070.002", "T1685.006"), ("T1562.012", "T1685.004"), ("T1562.001", "T1685")):
        assert ATTACK_REF["techniques"][old]["revoked"] and not ATTACK_REF["techniques"][new]["revoked"]


DOC: dict[str, Any] = {
    "target": TARGET, "checked_at": "2026-10-11T18:00:00+00:00",
    "checks": {
        "file_state": {"status": "suspicious", "coverage": "compared 7 log file(s)", "evidence": [], "items": [
            {"path": "/var/log/auth.log", "kind": "truncated", "detail": "shrank from 5000 to 0", "login_record": False},
            {"path": "/var/log/wtmp", "kind": "truncated", "detail": "shrank", "login_record": True}]},
        "journal": {"status": "suspicious", "coverage": "4 files", "evidence": [], "items": [
            {"after": "system@a.journal", "before": "system@c.journal", "detail": "entries 1001-2000 missing"}]},
        "boots": {"status": "suspicious", "coverage": "2 boots", "evidence": [], "items": [
            {"boot_id": "2f5bd599ff5a4180a24db87a8b4f22a0", "detail": "boot 2f5bd599ff5a ended without a clean shutdown"}]},
        "login_records": {"status": "suspicious", "coverage": "wtmp read", "evidence": ["wtmp: 1 all-zero record"],
                          "items": [{"file": "wtmp", "kind": "zeroed", "record": 7}]},
        "auditd": {"status": "suspicious", "coverage": "auditd inactive", "evidence": ["auditd was running ..."],
                   "items": [{"kind": "stopped", "severity": "high", "detail": "auditd was running ..."}]},
    },
    "seal": {"failed": [{"name": "system@x.journal", "detail": "tag/entry mismatch at offset 0x1234"}],
             "changed_archives": [], "unsealed_after_setup": [{"name": "system@y.journal"}],
             "unverifiable": "the active file is being written -- retried once, still busy"},
}


def test_findings_from_an_integrity_result():
    out = {f.id: f for f in FE._log_integrity_findings(DOC)}
    assert set(out) == set(NEW_RULES) - {"LOG-006"}   # auditd stopped (high), so not the "not running" note
    assert {k: v.severity for k, v in out.items()} == {
        "LOG-001": "high", "LOG-002": "high", "LOG-003": "low", "LOG-004": "high", "LOG-005": "high",
        "SEAL-001": "high", "SEAL-002": "medium", "SEAL-003": "info"}
    # entities name the incident, not just the file (a decision covers what was seen)
    assert out["LOG-001"].entities == ["/var/log/auth.log (detected 2026-10-11 18:00:00 UTC)"]
    assert out["LOG-004"].entities == ["/var/log/wtmp (detected 2026-10-11 18:00:00 UTC)",
                                       "/var/log/wtmp record 7 (zeroed)"]
    assert out["LOG-005"].entities == ["stopped (detected 2026-10-11 18:00:00 UTC)"]
    assert out["LOG-003"].entities == ["2f5bd599ff5a4180a24db87a8b4f22a0"] and out["LOG-003"].attack == []
    assert out["LOG-001"].attack[0]["technique_id"] == "T1685.006"
    assert out["LOG-005"].attack[0]["technique_id"] == "T1685.004"
    assert out["SEAL-002"].attack[0]["technique_id"] == "T1685"
    assert all(f.attack for k, f in out.items() if k in attack.RULE_ATTACK)


def test_shrink_only_login_record_change_is_medium():
    doc = {"target": TARGET, "checks": {"file_state": {"items": [
        {"path": "/var/log/btmp", "kind": "truncated", "detail": "shrank", "login_record": True}]}}}
    (f,) = FE._log_integrity_findings(doc)
    assert (f.id, f.severity) == ("LOG-004", "medium")


def _write_integrity(data_dir: Path, target: str, *, age: float = 0.0) -> Path:
    d = data_dir / "integrity"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"log_integrity_{target.replace('.', '_')}_{int(age)}.json"
    p.write_text(json.dumps({**DOC, "target": target, "checked_at_epoch": time.time() - age}))
    t = time.time() - age
    os.utime(p, (t, t))
    return p


def test_report_uses_only_a_fresh_result_for_this_machine(tmp_path):
    kratos_config.set_active_target(TARGET)
    _write_integrity(tmp_path, "10.9.9.9")                      # another machine, newer
    out_json, _ = FE.write_findings_report(tmp_path)
    assert not [f for f in json.loads(out_json.read_text())["findings"] if f["id"].startswith(("LOG-", "SEAL-"))]
    _write_integrity(tmp_path, TARGET, age=2 * 86400)          # this machine, but stale
    out_json, _ = FE.write_findings_report(tmp_path)
    assert not [f for f in json.loads(out_json.read_text())["findings"] if f["id"].startswith("LOG-")]
    _write_integrity(tmp_path, TARGET, age=60)
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    ids = {f["id"] for f in report["findings"]}
    assert {"LOG-001", "LOG-002", "SEAL-001"} <= ids
    log1 = next(f for f in report["findings"] if f["id"] == "LOG-001")
    assert log1["attack"][0]["tactic"] == "Defense Impairment" and log1["finding_key"]
    assert report["inputs"]["log_integrity"]


def test_tamper_evidence_never_closes_itself(tmp_path):
    finding = {"id": "LOG-001", "title": "t", "severity": "high", "entities": ["/var/log/auth.log"], "subject": ""}
    covered = Coverage(inputs={"log_integrity": None})
    with run_scope("cli", target=TARGET) as run:
        _, s1 = lc_apply.apply_run([finding], target=TARGET, coverage=covered, run=run, data_dir=tmp_path)
    assert len(s1["new"]) == 1
    with run_scope("cli", target=TARGET) as run2:
        _, s2 = lc_apply.apply_run([], target=TARGET, coverage=covered, run=run2, data_dir=tmp_path)
    assert s2["fixed"] == [] and s2["still_open"] == s1["new"]
    # an ordinary condition in the same situation IS closed -- the difference is the rule
    other = {"id": "NET-002", "title": "t", "severity": "medium", "entities": ["22/tcp"], "subject": ""}
    cov2 = Coverage(inputs={"nmap_parsed": None})
    with run_scope("cli", target=TARGET) as run3:
        lc_apply.apply_run([other], target=TARGET, coverage=cov2, run=run3, data_dir=tmp_path)
    with run_scope("cli", target=TARGET) as run4:
        _, s4 = lc_apply.apply_run([], target=TARGET, coverage=cov2, run=run4, data_dir=tmp_path)
    assert len(s4["fixed"]) == 1


# --- the answer guards still fire on a high tamper finding -------------------
LOG_FINDING = {
    "id": "LOG-001", "title": "Log file cut short, replaced or edited outside log rotation", "severity": "high",
    "evidence": ["/var/log/auth.log: shrank from 5000 to 0 bytes"], "recommendation": [], "playbooks": [],
    "source_ips": [], "also_matched": [], "collected_at": None, "subject": "", "entities": ["/var/log/auth.log"],
    "attack": attack.labels("LOG-001"),
}


@pytest.fixture
def guarded(tmp_path, monkeypatch):
    def correlate(**kwargs):
        return {"findings_json_file": "f.json", "findings_md_file": "f.md", "inputs_used": {}, "missing_inputs": [],
                "input_errors": {}, "staleness_warning": None, "findings": [LOG_FINDING], "count": 1}
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", correlate)
    kratos_config.set_active_target(TARGET)
    return tmp_path


def test_guard3_rejects_a_clean_verdict_over_a_high_tamper_finding(guarded, monkeypatch):
    from tests.test_agent_loop_guards import ScriptedChat, _final_json, _tool_json

    answer = "No suspicious activity -- the system looks clean."
    chat = ScriptedChat([_tool_json("correlate_findings"), _final_json(answer), _final_json(answer), _final_json(answer)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("did anyone tamper with this machine?", guarded, max_iters=10)
    assert any("dismissive_verdict_contradiction" in s.get("violations", [])
               for s in result["transcript"] if s.get("status") == "final_answer_rejected")


def test_check_log_integrity_tool_with_fake_reads(tmp_path, monkeypatch):
    from kratos.logsources import integrity
    from tests.test_logsources_tamper import FakeReader

    monkeypatch.setattr(integrity, "Reader", FakeReader)
    kratos_config.set_active_target(TARGET)
    out = TOOL_REGISTRY["check_log_integrity"].handler(data_dir=tmp_path)
    assert out["status"] == "ok" and out["file_state"]["status"] == "ok"
    assert Path(out["result_file"]).exists() and "next_step" in out
    t = TOOL_REGISTRY["check_log_integrity"]
    assert not t.requires_approval and "SSH TARGET DEVICE" in t.description


def test_the_model_sees_one_log_tool_and_tampering_runs_through_it(tmp_path, monkeypatch):
    from kratos.agent.loop import build_system_prompt, execute_tool_call
    from kratos.logsources import integrity
    from tests.test_logsources_tamper import FakeReader

    monkeypatch.setattr(integrity, "Reader", FakeReader)
    kratos_config.set_active_target(TARGET)
    prompt = build_system_prompt("did an attacker cover their tracks on this box?")
    assert "- read_host_logs:" in prompt and "tampering (were the logs cleared or edited)" in prompt
    assert "- check_log_integrity:" not in prompt          # listed through read_host_logs only (eval A1)
    out = TOOL_REGISTRY["read_host_logs"].handler(data_dir=tmp_path, source="tampering")
    assert out["status"] == "ok" and out["source"] == "tampering" and "file_state" in out
    # still a real tool: a call by name (or /use, a pipeline) runs it
    res = execute_tool_call("check_log_integrity", {}, tmp_path)
    assert res.get("status") == "ok", res



@pytest.mark.parametrize("goal", [
    "check for suspicious activity on this system", "is my server okay", "who has privileged access on this system",
    "has anything on this system been tampered with", "what ran on this box last night?", "list cron jobs that ran",
])
def test_read_host_logs_is_listed_for_every_goal(goal):
    """Kratos collects the basics by code now (phase A.0), so the 0.3 goal regex that hid this
    tool from broad goals is gone: one fixed tool list."""
    from kratos.agent.loop import build_system_prompt

    kratos_config.set_active_target(TARGET)
    assert "- read_host_logs:" in build_system_prompt(goal)
    assert build_system_prompt(goal) == build_system_prompt("something else entirely")


def test_a_call_by_name_runs_even_when_not_listed(tmp_path, monkeypatch):
    from kratos.agent import tools as T
    from kratos.agent.loop import execute_tool_call

    kratos_config.set_active_target(TARGET)
    monkeypatch.setattr(T, "_fetch_host_logs", lambda *a, **k: T._SSHResult(ok=False, returncode=255, stdout="",
                                                                          stderr="ssh: unreachable"))
    res = execute_tool_call("read_host_logs", {"source": "cron"}, tmp_path)
    assert "were NOT read" in json.dumps(res)            # it ran (and reported the gap), it wasn't refused


# --- a person's decision covers the incident they saw, not the next one (audit) ---
def _lifecycle(tmp_path, doc: dict[str, Any], t: float):
    """Apply one integrity result's tamper findings to the lifecycle as one run."""
    from dataclasses import asdict

    findings = [asdict(f) for f in FE._log_integrity_findings(doc)]
    cov = Coverage(inputs={"log_integrity": None})
    with run_scope("cli", target=TARGET) as run:
        return lc_apply.apply_run(findings, target=TARGET, coverage=cov, run=run, data_dir=tmp_path, now=t)


def _only(check: str, items: list[dict[str, Any]], checked_at: str, seal: dict[str, Any] | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = {"target": TARGET, "checked_at": checked_at,
                           "checks": {check: {"status": "suspicious", "coverage": "c", "evidence": [], "items": items}}}
    if seal is not None:
        doc = {"target": TARGET, "checked_at": checked_at, "checks": {}, "seal": seal}
    return doc


def _decide_fp(tmp_path, rule: str, t: float) -> None:
    from kratos.lifecycle import decide as D
    from kratos.lifecycle.keys import finding_key

    D.mark_false_positive(finding_key(rule, TARGET, ""), actor=D.Actor(user="alice", interface="cli"),
                          reason="that was me", data_dir=tmp_path, now=t)


def _state(out: list[dict[str, Any]], rule: str) -> str:
    return next(f["state"] for f in out if f["id"] == rule)


def test_a_second_truncation_of_the_same_log_reopens_a_decided_finding(tmp_path):
    item = {"path": "/var/log/auth.log", "kind": "truncated", "detail": "shrank", "login_record": False}
    _lifecycle(tmp_path, _only("file_state", [item], "2026-10-11T18:00:00+00:00"), 1_000_000.0)
    _decide_fp(tmp_path, "LOG-001", 1_000_010.0)
    out, summary = _lifecycle(tmp_path, _only("file_state", [item], "2026-10-12T09:00:00+00:00"), 1_000_100.0)
    assert _state(out, "LOG-001") == "open" and summary["new"]
    out, _ = _lifecycle(tmp_path, _only("file_state", [item], "2026-10-12T09:00:00+00:00"), 1_000_200.0)
    assert _state(out, "LOG-001") == "open"          # the same result read again is the same incident


def test_zeroed_wtmp_record_reported_every_run_stays_covered_a_new_one_reopens(tmp_path):
    rec7 = {"file": "wtmp", "kind": "zeroed", "record": 7}
    _lifecycle(tmp_path, _only("login_records", [rec7], "2026-10-11T18:00:00+00:00"), 1_000_000.0)
    _decide_fp(tmp_path, "LOG-004", 1_000_010.0)
    out, _ = _lifecycle(tmp_path, _only("login_records", [rec7], "2026-10-12T09:00:00+00:00"), 1_000_100.0)
    assert _state(out, "LOG-004") == "false_positive"
    rec9 = {"file": "wtmp", "kind": "zeroed", "record": 9}
    out, _ = _lifecycle(tmp_path, _only("login_records", [rec7, rec9], "2026-10-12T10:00:00+00:00"), 1_000_200.0)
    assert _state(out, "LOG-004") == "open"


def test_auditd_stopped_again_reopens_and_not_running_is_its_own_closing_rule(tmp_path):
    from kratos.logsources import tamper

    stopped = {"kind": "stopped", "severity": "high", "detail": "auditd was running ... now inactive"}
    _lifecycle(tmp_path, _only("auditd", [stopped], "2026-10-11T18:00:00+00:00"), 1_000_000.0)
    _decide_fp(tmp_path, "LOG-005", 1_000_010.0)
    out, _ = _lifecycle(tmp_path, _only("auditd", [stopped], "2026-10-12T09:00:00+00:00"), 1_000_100.0)
    assert _state(out, "LOG-005") == "open"

    # installed but not running -> LOG-006 (info) every run, and it closes once auditd runs
    status = {"installed": True, "active": "inactive", "enabled": "disabled", "rules_read": True, "rules": 0}
    first, state = tamper.check_auditd(status, None)
    second, _ = tamper.check_auditd(status, state)
    for res in (first, second):
        doc = {"target": TARGET, "checked_at": "2026-10-12T10:00:00+00:00", "checks": {"auditd": res}}
        assert [f.id for f in FE._log_integrity_findings(doc)] == ["LOG-006"]
    out, _ = _lifecycle(tmp_path, {"target": TARGET, "checked_at": "2026-10-12T10:00:00+00:00",
                                   "checks": {"auditd": second}}, 1_000_300.0)
    assert _state(out, "LOG-006") == "open"
    running, _ = tamper.check_auditd({**status, "active": "active", "rules": 3}, state)
    _, summary = _lifecycle(tmp_path, {"target": TARGET, "checked_at": "2026-10-12T11:00:00+00:00",
                                       "checks": {"auditd": running}}, 1_000_400.0)
    assert len(summary["fixed"]) == 1


def test_a_changed_archive_is_one_incident_until_it_changes_again(tmp_path):
    def seal(sha: str) -> dict[str, Any]:
        return {"failed": [], "unsealed_after_setup": [], "unverifiable": None,
                "changed_archives": [{"name": "system@a.journal", "sha256": sha, "detail": "changed"}]}

    _lifecycle(tmp_path, _only("", [], "2026-10-11T18:00:00+00:00", seal("f3348bef" + "0" * 56)), 1_000_000.0)
    _decide_fp(tmp_path, "SEAL-001", 1_000_010.0)
    out, _ = _lifecycle(tmp_path, _only("", [], "2026-10-12T09:00:00+00:00", seal("f3348bef" + "0" * 56)), 1_000_100.0)
    assert _state(out, "SEAL-001") == "false_positive"
    out, _ = _lifecycle(tmp_path, _only("", [], "2026-10-12T10:00:00+00:00", seal("9a1b2c3d" + "0" * 56)), 1_000_200.0)
    assert _state(out, "SEAL-001") == "open"
