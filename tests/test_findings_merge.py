"""One SSH brute-force burst on an exposed SSH used to produce three findings at three
severities (CORR-SSH-001 high, CORR-001 medium, AUTH-004 info) -- read as three problems.
They are one finding now; rules naming the absorbed ids still match it."""
from __future__ import annotations

from types import SimpleNamespace

from kratos.adapters import findings_engine as FE

_NMAP = {"hosts": [{"address": "203.0.113.5", "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}]}]}
_SSH_BURST = {"event_type": "ssh_failed_login", "count": 4, "start": "2026-10-04T08:55:24+00:00",
              "end": "2026-10-04T08:55:25+00:00", "top_source_ips": [{"ip": "203.0.113.52", "count": 4}]}
_SUDO_BURST = {"event_type": "sudo_auth_failure", "count": 3, "start": "2026-10-04T09:00:00+00:00",
               "end": "2026-10-04T09:01:00+00:00"}


def _findings(*bursts):
    return FE.generate_findings(_NMAP, None, {"bursts": list(bursts)}, None)


def test_one_burst_is_one_finding_at_the_highest_severity():
    out = _findings(_SSH_BURST)
    ids = [f.id for f in out]
    assert "CORR-SSH-001" in ids and "CORR-001" not in ids and "AUTH-004" not in ids
    main = next(f for f in out if f.id == "CORR-SSH-001")
    assert main.severity == "high" and main.also_matched == ["CORR-001", "AUTH-004"]
    assert "203.0.113.52" in main.source_ips
    assert any(line.startswith("One finding for this burst -- also matched: CORR-001") for line in main.evidence)


def test_sudo_bursts_keep_their_own_finding():
    out = _findings(_SSH_BURST, _SUDO_BURST)
    ids = [f.id for f in out]
    assert "AUTH-004" in ids and "CORR-001" not in ids
    assert next(f for f in out if f.id == "CORR-SSH-001").also_matched == ["CORR-001"]


def test_rules_naming_an_absorbed_id_still_match():
    from kratos.agent import trigger_eval
    from kratos.agent.pipeline_when import compile_when

    found = [{"id": "CORR-SSH-001", "severity": "high", "also_matched": ["CORR-001", "AUTH-004"]}]
    trig = SimpleNamespace(finding_id="corr-001", min_severity=None)
    assert trigger_eval._matched(trig, found) == found
    ctx = SimpleNamespace(findings=found)
    assert compile_when("finding_id == 'AUTH-004'")(ctx) is True
    assert compile_when("finding_id == 'NET-001'")(ctx) is False
    assert FE.finding_ids({"id": "NET-002"}) == {"NET-002"}     # old reports: just the id
