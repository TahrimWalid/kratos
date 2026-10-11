"""Coverage (0.1 §5.5): a finding is marked gone only by a run that really re-collected
every input its rule needs, about this machine, completely."""
from __future__ import annotations

import json
import os
import time
import uuid

from kratos.lifecycle import coverage as C
from kratos.run_context import RunContext

T = "10.0.0.5"


def run(started_at):
    return RunContext(run_id=uuid.uuid4().hex, source="interactive", target=T, session_id=None,
                      started_at=started_at)


def write(tmp_path, name, data, mtime=None):
    p = tmp_path / name
    p.write_text(json.dumps(data))
    if mtime is not None:
        os.utime(p, (mtime, mtime))
    return p


def test_fresh_inputs_about_this_machine_cover_their_rules(tmp_path):
    now = time.time()
    nmap = write(tmp_path, "parsed.json", {"target": T, "hosts": []})
    pats = write(tmp_path, "pats.json", {"target": f"ubuntu@{T}", "bursts": []})
    cov = C.for_report({"nmap_parsed": nmap, "auth_patterns": pats, "auth_stats": None}, target=T,
                       run=run(now - 5))
    assert cov.covered("NET-002") and cov.covered("CORR-SSH-001") and cov.covered("AUTH-004")
    assert not cov.covered("AUTH-001")              # auth_stats not used by this report
    assert "not used" in cov.why_not("AUTH-001")
    assert not cov.covered("COV-001")               # run notes never have coverage


def test_an_input_from_before_the_run_does_not_cover(tmp_path):
    now = time.time()
    nmap = write(tmp_path, "parsed.json", {"target": T, "hosts": []}, mtime=now - 600)
    cov = C.for_report({"nmap_parsed": nmap}, target=T, run=run(now - 60))
    assert "not re-collected" in cov.why_not("NET-002")
    # within the 10 s slack it does
    os.utime(nmap, (now - 65, now - 65))
    assert C.for_report({"nmap_parsed": nmap}, target=T, run=run(now - 60)).covered("NET-002")


def test_an_input_about_another_machine_does_not_cover(tmp_path):
    nmap = write(tmp_path, "parsed.json", {"target": "10.9.9.9", "hosts": []})
    cov = C.for_report({"nmap_parsed": nmap}, target=T, run=run(time.time() - 5))
    assert "not about this machine" in cov.why_not("NET-002")


def test_partial_auth_coverage_does_not_cover_login_rules(tmp_path):
    stats = {"target": T, "coverage": {"sshd": {"truncated": True, "returned": 500}}}
    pats = write(tmp_path, "pats.json", {"target": T, "bursts": []})
    st = write(tmp_path, "stats.json", stats)
    incomplete = C.incomplete_auth_inputs({"auth_stats": stats, "auth_patterns": stats})
    assert incomplete == {"auth_stats", "auth_patterns"}
    cov = C.for_report({"auth_patterns": pats, "auth_stats": st}, target=T, run=run(time.time() - 5),
                       incomplete=incomplete)
    assert "only part of its time window" in cov.why_not("CORR-SSH-001")
    assert not cov.covered("AUTH-001")
    assert C.incomplete_auth_inputs({"auth_stats": {"coverage": {"sshd": {"truncated": False}}}}) == set()


def test_no_run_context_covers_nothing(tmp_path):
    nmap = write(tmp_path, "parsed.json", {"target": T, "hosts": []})
    cov = C.for_report({"nmap_parsed": nmap}, target=T, run=None)
    assert not cov.covered("NET-002") and "no run context" in cov.why_not("NET-002")


def test_missing_file_does_not_cover(tmp_path):
    cov = C.for_report({"nmap_parsed": tmp_path / "gone.json"}, target=T, run=run(time.time() - 5))
    assert "could not be read" in cov.why_not("NET-002")


def test_end_to_end_a_real_rerun_marks_the_open_port_mitigated(tmp_path, monkeypatch):
    """write_findings_report inside a run: the port closes, nmap re-ran -> mitigated;
    then a run with no fresh scan leaves a re-opened port's absence unclaimed."""
    from kratos import kratos_config
    from kratos.adapters import findings_engine as FE
    from kratos.run_context import run_scope

    monkeypatch.setattr(kratos_config, "get_active_target", lambda: T)
    scans = tmp_path / "scans"
    scans.mkdir()
    open22 = {"target": T, "hosts": [{"ip": T, "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}]}]}
    with run_scope("cli", target=T):
        write(scans, "parsed_1.json", open22)
        first = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    assert first["lifecycle"]["new"]
    time.sleep(0.01)
    with run_scope("cli", target=T):
        write(scans, "parsed_2.json", {"target": T, "hosts": [{"ip": T, "open_ports": []}]})
        second = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    assert second["lifecycle"]["fixed"] == first["lifecycle"]["new"]
    assert [x["id"] for x in second["findings"]] == ["NET-001"]
