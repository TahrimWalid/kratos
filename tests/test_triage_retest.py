"""/retest: force the covering checks, re-correlate + lifecycle update, then verify;
report before/after state and the verdict; an incomplete read leaves it open (§3.3, §5.3)."""
from __future__ import annotations

from types import SimpleNamespace

from kratos.lifecycle import apply as A
from kratos.lifecycle import coverage as C
from kratos.lifecycle import store as LS
from kratos.lifecycle.keys import finding_key
from kratos.target_key import target_key
from kratos.triage import run as R
from kratos.triage.verdict import Verdict

TARGET = "10.0.0.11"


def _seed_open(tmp_path, rule_id="PKG-001", subject="openssl"):
    f = {"id": rule_id, "severity": "high", "title": "t", "subject": subject, "entities": ["CVE-2024-1"]}
    A.apply_run([f], target=TARGET, coverage=C.nothing(), run=None, data_dir=tmp_path, now=100.0)
    return finding_key(rule_id, target_key(TARGET), subject)


def _report(ok=True):
    status = "ok" if ok else "failed"
    return SimpleNamespace(findings=[], disabled_reason=None,
                           checks=[SimpleNamespace(name="packages", status=status, reason="SSH down",
                                                   summary="", gaps=[])])


def test_retest_fixed_shows_mitigated_and_not_reproduced(tmp_path, monkeypatch):
    key = _seed_open(tmp_path)

    def fake_recollect(target, data_dir, names, *, run):
        # a real forced collection + correlation would run the lifecycle update; simulate it
        with LS.opened(data_dir) as conn, LS.immediate(conn):
            LS.set_state(conn, key, "mitigated")
        return _report(ok=True)

    monkeypatch.setattr(R, "_recollect", fake_recollect)
    monkeypatch.setattr(R, "verify_finding",
                        lambda finding, **kw: Verdict("not_reproduced", "gone"))
    out = R.retest(key, data_dir=tmp_path, target=TARGET)
    assert out["before_state"] == "open"
    assert out["after_state"] == "mitigated"
    assert out["fixed"] is True
    assert out["verdict"]["verdict"] == "not_reproduced"
    assert out["incomplete"] is None


def test_retest_incomplete_read_leaves_it_open(tmp_path, monkeypatch):
    key = _seed_open(tmp_path)
    monkeypatch.setattr(R, "_recollect", lambda target, data_dir, names, *, run: _report(ok=False))
    monkeypatch.setattr(R, "verify_finding", lambda finding, **kw: Verdict("couldnt_check", "x", detail="SSH down"))
    out = R.retest(key, data_dir=tmp_path, target=TARGET)
    assert out["before_state"] == "open"
    assert out["after_state"] == "open"
    assert out["fixed"] is False
    assert out["incomplete"] and "SSH down" in out["incomplete"]
