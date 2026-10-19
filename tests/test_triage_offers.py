"""After a fix, a retest is offered for the finding the action targeted (B.1 §5.3).
The fix channel is off, so this is exercised with a seeded finding, not a real dispatch."""
from __future__ import annotations

import time
import uuid

from kratos.lifecycle import apply as A
from kratos.lifecycle.coverage import nothing
from kratos.lifecycle.keys import finding_key
from kratos.run_context import RunContext
from kratos.triage import offers

T = "10.0.0.8"


def _seed(tmp_path):
    r = RunContext(run_id=uuid.uuid4().hex, source="interactive", target=T, session_id=None, started_at=time.time())
    A.apply_run([{"id": "CORR-SSH-001", "title": "SSH brute force", "severity": "high", "evidence": [],
                  "subject": "", "entities": ["203.0.113.9"]}],
                target=T, coverage=nothing(), run=r, data_dir=tmp_path)


def test_rule_ids_in_ignores_audit_check_references():
    assert offers.rule_ids_in(("CORR-SSH-001", "CORR-001", "run_config_audit:fail2ban_status:FAIL")) == \
        ["CORR-SSH-001", "CORR-001"]
    assert offers.rule_ids_in(()) == []
    assert offers.rule_ids_in(None) == []


def test_offer_points_at_the_open_finding(tmp_path):
    _seed(tmp_path)
    offer = offers.retest_offer(tmp_path, ("CORR-SSH-001", "CORR-001", "AUTH-004"), T)
    assert offer is not None
    assert offer["rule_id"] == "CORR-SSH-001"
    assert finding_key("CORR-SSH-001", T, "")[:12] == offer["short_key"]
    text = offers.retest_offer_text(offer)
    assert "retest" in text.lower() and offer["short_key"] in text


def test_no_offer_when_no_matching_open_finding(tmp_path):
    _seed(tmp_path)
    # an action recommended only for a config-audit check, no finding-rule token
    assert offers.retest_offer(tmp_path, ("run_config_audit:firewall:FAIL",), T) is None
    # a rule with no open finding
    assert offers.retest_offer(tmp_path, ("PKG-001",), T) is None
