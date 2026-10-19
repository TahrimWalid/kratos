"""Each verifier returns reproduced / partly / not_reproduced / couldn't check on
fixtures, with the reads stubbed -- no SSH, no lab (docs/phaseB/B.1 §7).
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from kratos.lifecycle.keys import finding_key
from kratos.target_key import target_key
from kratos.triage import verifiers as V
from kratos.triage.context import VerifyContext

TARGET = "10.0.0.5"


def _finding(rule_id, *, subject="", entities=(), severity="high", first_seen=None):
    key = finding_key(rule_id, target_key(TARGET), subject)
    return {"id": rule_id, "finding_key": key, "subject": subject, "entities": list(entities),
            "severity": severity, "title": f"{rule_id} title", "first_seen": first_seen}


def _report(findings=(), *, checks=(), transport="ssh", disabled_reason=None):
    def _mk(name, status="ok", reason="", summary="", gaps=()):
        return SimpleNamespace(name=name, status=status, reason=reason, summary=summary, gaps=list(gaps))
    return SimpleNamespace(findings=list(findings),
                           checks=[c if not isinstance(c, tuple) else _mk(*c) for c in checks],
                           transport=transport, disabled_reason=disabled_reason)


def _ctx(finding, *, recollect=None, dispatch=None, now=1000.0):
    return VerifyContext(finding=finding, target=TARGET, data_dir="/tmp/does-not-matter", now=now,
                         recollect=recollect or (lambda names: _report()),
                         dispatch=dispatch or (lambda t, a: {"status": "ok", "result": {}}))


# --------------------------------------------------------------------------- conditions
def test_condition_reproduced_when_present():
    f = _finding("PERSIST-003", subject="/usr/bin/x")
    ctx = _ctx(f, recollect=lambda names: _report([dict(f)], checks=[("persistence", "ok")]))
    v = V._verify_persistence(ctx)
    assert v.verdict == "reproduced"


def test_condition_not_reproduced_when_gone_and_read_complete():
    f = _finding("PERSIST-003", subject="/usr/bin/x")
    ctx = _ctx(f, recollect=lambda names: _report([], checks=[("persistence", "ok")]))
    v = V._verify_persistence(ctx)
    assert v.verdict == "not_reproduced"


def test_condition_couldnt_check_when_read_failed():
    f = _finding("PERSIST-003", subject="/usr/bin/x")
    ctx = _ctx(f, recollect=lambda names: _report([], checks=[("persistence", "failed", "SSH refused")]))
    v = V._verify_persistence(ctx)
    assert v.verdict == "couldnt_check"
    assert "SSH refused" in v.detail


def test_condition_couldnt_check_when_collection_disabled():
    f = _finding("PKG-001", subject="openssl")
    ctx = _ctx(f, recollect=lambda names: _report(disabled_reason="no target is set"))
    v = V._verify_packages(ctx)
    assert v.verdict == "couldnt_check"
    assert "no target" in v.detail


def test_pkg003_reproduced_sentence_is_about_the_reboot():
    f = _finding("PKG-003", subject="linux")
    ctx = _ctx(f, recollect=lambda names: _report([dict(f)], checks=[("packages", "ok")]))
    v = V._verify_packages(ctx)
    assert v.verdict == "reproduced"
    assert "reboot" in v.sentence.lower()


# --------------------------------------------------------------------------- NET reachability
def test_net_reproduced_from_kratos():
    f = _finding("NET-001", subject="22/tcp", entities=["22/tcp"])
    ctx = _ctx(f, recollect=lambda names: _report([dict(f)], checks=[("ports", "ok")]))
    v = V._verify_net(ctx)
    assert v.verdict == "reproduced"
    assert "from here" in v.sentence.lower()


def test_net_not_reproduced_says_kratos_vantage():
    f = _finding("NET-001", subject="22/tcp", entities=["22/tcp"])
    ctx = _ctx(f, recollect=lambda names: _report([], checks=[("ports", "ok")]))
    v = V._verify_net(ctx)
    assert v.verdict == "not_reproduced"
    assert "public internet" in v.sentence.lower()


# --------------------------------------------------------------------------- auth occurrence
def _auth_result(*, failed=0, bursts=(), sources=(), bans=0, coverage=100, problems=False, truncated=False):
    return {"status": "ok", "result": {
        "window": {"label": "the burst window", "coverage_percent": coverage,
                   "problems": problems, "truncated": truncated},
        "counts": {"ssh_failed_login": failed},
        "bursts": list(bursts),
        "failed_login_sources": [{"ip": ip, "failed_logins": 9} for ip in sources],
        "fail2ban": {"bans": bans, "unbans": 0},
    }}


def test_auth_reproduced_from_window():
    f = _finding("CORR-SSH-001", entities=["10.136.28.52"], first_seen="2026-10-19T00:00:00+00:00")
    ctx = _ctx(f, dispatch=lambda t, a: _auth_result(failed=40, bursts=[{"x": 1}], sources=["10.136.28.52"]))
    v = V._verify_auth(ctx)
    assert v.verdict == "reproduced"
    assert "same source" in v.sentence.lower()


def test_auth_partly_when_source_now_banned():
    f = _finding("CORR-SSH-001", entities=["10.136.28.52"], first_seen="2026-10-19T00:00:00+00:00")
    ctx = _ctx(f, dispatch=lambda t, a: _auth_result(failed=40, bursts=[{"x": 1}], sources=["10.136.28.52"], bans=1))
    v = V._verify_auth(ctx)
    assert v.verdict == "partly"
    assert "fail2ban" in v.detail.lower()


def test_auth_not_reproduced_when_window_clean_and_covered():
    f = _finding("CORR-SSH-001", entities=["10.136.28.52"], first_seen="2026-10-19T00:00:00+00:00")
    ctx = _ctx(f, dispatch=lambda t, a: _auth_result(failed=0, coverage=100))
    v = V._verify_auth(ctx)
    assert v.verdict == "not_reproduced"


def test_auth_couldnt_check_when_logs_for_that_time_are_gone():
    f = _finding("CORR-SSH-001", entities=["10.136.28.52"], first_seen="2026-10-19T00:00:00+00:00")
    ctx = _ctx(f, dispatch=lambda t, a: _auth_result(failed=0, coverage=30, problems=True))
    v = V._verify_auth(ctx)
    assert v.verdict == "couldnt_check"
    assert "no longer" in v.detail.lower()


def test_auth_couldnt_check_when_measurement_errored():
    f = _finding("CORR-SSH-001", entities=["10.136.28.52"])
    ctx = _ctx(f, dispatch=lambda t, a: {"status": "error", "observation": "SSH down"})
    v = V._verify_auth(ctx)
    assert v.verdict == "couldnt_check"


# --------------------------------------------------------------------------- VULN-001 cross-check
def test_vuln001_reproduced_when_no_package_fixes_it(monkeypatch):
    f = _finding("VULN-001", entities=["CVE-2024-0001"], severity="medium")
    monkeypatch.setattr(V, "_latest_packages_doc", lambda d, t: {"selector": "ubuntu:22.04", "inventory_id": 1})
    monkeypatch.setattr("kratos.pkgvuln.crosscheck.fixed_by_packages", lambda *a, **k: {})
    ctx = _ctx(f, recollect=lambda names: _report(checks=[("packages", "ok")]))
    v = V._verify_vuln001(ctx)
    assert v.verdict == "reproduced"


def test_vuln001_partly_when_backport_fixes_it(monkeypatch):
    f = _finding("VULN-001", entities=["CVE-2024-0001"], severity="medium")
    monkeypatch.setattr(V, "_latest_packages_doc", lambda d, t: {"selector": "ubuntu:22.04", "inventory_id": 1})
    monkeypatch.setattr("kratos.pkgvuln.crosscheck.fixed_by_packages",
                        lambda data_dir, doc, cves, fixers=None: {"CVE-2024-0001": "backported"})
    ctx = _ctx(f, recollect=lambda names: _report(checks=[("packages", "ok")]))
    v = V._verify_vuln001(ctx)
    assert v.verdict == "partly"


def test_vuln001_couldnt_check_without_inventory(monkeypatch):
    f = _finding("VULN-001", entities=["CVE-2024-0001"], severity="medium")
    monkeypatch.setattr(V, "_latest_packages_doc", lambda d, t: None)
    ctx = _ctx(f, recollect=lambda names: _report(checks=[("packages", "ok")]))
    v = V._verify_vuln001(ctx)
    assert v.verdict == "couldnt_check"


def test_vuln001_couldnt_check_without_a_cve():
    f = _finding("VULN-001", entities=[], severity="medium")
    ctx = _ctx(f)
    v = V._verify_vuln001(ctx)
    assert v.verdict == "couldnt_check"
