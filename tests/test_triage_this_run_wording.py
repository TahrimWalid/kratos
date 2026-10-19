"""The automatic pass never says "reproduced" (B.1 follow-up).

The automatic verification after an investigation or a scheduled run judges against the
collection Kratos just ran -- the same read that raised the finding. That is not a second
look, so its verdict is "seen in this run's read -- not re-checked yet" and points to
recheck / retest. Only a genuine second read (recheck, retest, the slow verifiers) may say
"reproduced" or "not reproduced". These tests run every registered verifier in reuse mode,
with the finding present and absent, and check every surface the verdict reaches.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from kratos import finding_facts
from kratos.collect.digest import _finding_tag
from kratos.lifecycle.keys import finding_key
from kratos.target_key import target_key
from kratos.triage import run as R
from kratos.triage import store as S
from kratos.triage.registry import Verifier, registered
from kratos.triage.verdict import SECOND_READ, THIS_RUN, Verdict, from_this_run

TARGET = "10.0.0.9"


def _rule_ids() -> list[str]:
    import kratos.triage.verifiers  # noqa: F401 -- registers every verifier

    verifiers, _ = registered()
    out: list[str] = []
    for v in verifiers:
        for r in v.rules:
            out.append(r + "001" if r.endswith("-") else r)
    return sorted(dict.fromkeys(out))


def _finding(rule_id: str) -> dict:
    key = finding_key(rule_id, target_key(TARGET), "")
    return {"id": rule_id, "finding_key": key, "subject": "", "entities": ["192.0.2.7"],
            "severity": "high", "title": f"{rule_id} title", "change": "new"}


def _report(findings, check_names):
    return SimpleNamespace(findings=list(findings), transport="ssh", disabled_reason=None,
                           checks=[SimpleNamespace(name=n, status="ok", reason="", summary="", gaps=[])
                                   for n in check_names])


def _all_check_names() -> list[str]:
    from kratos.collect import checks as _checks  # noqa: F401 -- registers the checks
    from kratos.collect.registry import checks

    return [c.name for c in checks()]


def _present_dispatch(tool, args):
    # what a second read would answer if a verifier ignored reuse mode -- the conversion
    # must still apply, so the test can't pass by accident.
    return {"status": "ok", "result": {"window": {"label": "w", "coverage_percent": 100},
                                       "counts": {"ssh_failed_login": 40}, "bursts": [{"x": 1}],
                                       "failed_login_sources": [{"ip": "192.0.2.7"}],
                                       "fail2ban": {"bans": 0}}}


def _no_reproduced(verdict_dict: dict) -> None:
    blob = json.dumps(verdict_dict).lower()
    assert "reproduced" not in blob, verdict_dict


@pytest.mark.parametrize("present", [True, False])
@pytest.mark.parametrize("rule_id", _rule_ids())
def test_reuse_mode_verdict_never_says_reproduced(tmp_path, rule_id, present):
    f = _finding(rule_id)
    names = _all_check_names()
    report = _report([dict(f)] if present else [], names)
    v = R.verify_finding(f, data_dir=tmp_path, target=TARGET, reuse=True, report=report,
                         recollect=lambda n: report, dispatch=_present_dispatch)
    assert v.basis == THIS_RUN
    assert v.verdict in ("seen", "partly", "couldnt_check")
    _no_reproduced(f["verdict"])
    _no_reproduced(v.as_dict())
    # and what got stored reads back the same way (/findings, CLI, MCP read the store)
    stored = S.latest_verdict(tmp_path, f["finding_key"])
    assert stored is not None and stored.verdict.basis == THIS_RUN
    _no_reproduced(stored.verdict.as_dict())


def test_present_finding_is_seen_and_points_to_recheck(tmp_path):
    f = _finding("CORR-SSH-001")
    report = _report([dict(f)], ["auth_activity"])
    v = R.verify_finding(f, data_dir=tmp_path, target=TARGET, reuse=True, report=report)
    assert v.verdict == "seen"
    assert v.tag() == "seen in this run's read -- not re-checked yet"
    assert "recheck" in v.sentence and "retest" in v.sentence


def test_auto_verify_on_every_surface_never_shows_reproduced(tmp_path):
    findings = [_finding("CORR-SSH-001"), _finding("PERSIST-001")]
    report = _report([dict(x) for x in findings], _all_check_names())
    R.auto_verify(findings, data_dir=tmp_path, target=TARGET, budget_seconds=10, report=report,
                  recollect=lambda n: report, dispatch=_present_dispatch)
    for f in findings:
        assert f["verdict"]["verdict"] in ("seen", "partly", "couldnt_check")
    # the answer's findings block and the model's digest
    block = finding_facts.answer_block(findings, "analysis text")
    assert "seen in this run's read" in block
    assert "reproduced" not in block.lower()
    for f in findings:
        assert "reproduced" not in _finding_tag(f, True).lower()
        # the scheduled-run notification line uses the same tag
        assert "reproduced" not in (finding_facts.verdict_tag(f) or "").lower()
    # /findings, `kratos findings show`, MCP kratos_finding_states: enrich_rows from the store
    rows = [{"finding_key": f["finding_key"]} for f in findings]
    R.enrich_rows(rows, tmp_path)
    for r in rows:
        _no_reproduced(r["verdict"])
    # TUI verdict cell
    from kratos.tui_mk2.screens.findings import FindingsScreen

    cell = FindingsScreen._verdict_cell(None, rows[0])
    assert "reproduced" not in cell.plain.lower()


def test_a_second_read_may_still_say_reproduced(tmp_path):
    # recheck: no reuse, the verifier issues its own read
    f = _finding("CORR-SSH-001")
    v = R.verify_finding(f, data_dir=tmp_path, target=TARGET, dispatch=_present_dispatch)
    assert v.verdict == "reproduced" and v.basis == SECOND_READ
    assert v.tag() == "reproduced by a fresh read"


def test_verdict_refuses_reproduced_on_this_runs_read():
    with pytest.raises(ValueError):
        Verdict("reproduced", "x", basis=THIS_RUN)
    with pytest.raises(ValueError):
        Verdict("not_reproduced", "x", basis=THIS_RUN)
    with pytest.raises(ValueError):
        Verdict("seen", "x")                      # seen is only for this run's read


def test_from_this_run_maps_each_verdict():
    assert from_this_run(Verdict("reproduced", "x")).verdict == "seen"
    gone = from_this_run(Verdict("not_reproduced", "x"))
    assert gone.verdict == "couldnt_check" and "recheck" in gone.detail
    part = from_this_run(Verdict("partly", "Still true.", detail="distro backported the fix"))
    assert part.verdict == "partly" and part.basis == THIS_RUN
    assert part.tag() == "partly: distro backported the fix (this run's read, not re-checked yet)"


def test_store_migrates_an_old_verdict_table(tmp_path):
    # a kratos.db that ran only B.1's first triage step (no basis column) still reads
    import sqlite3

    from kratos.storage.migrations import migrate_once
    from kratos.storage.sqlite_files import connect_store

    path = tmp_path / "kratos.db"
    conn = connect_store(path)
    migrate_once(conn, path, S.COMPONENT, S.STEPS[:1])
    conn.execute("INSERT INTO finding_verdicts (finding_key, run_id, at, verdict, cost, verifier, detail, "
                 "sentence, checks, evidence, duration) VALUES ('k', NULL, 1.0, 'reproduced', 'quick', 'v', "
                 "NULL, 's', '[]', '[]', 0.1)")
    conn.commit()
    conn.close()
    got = S.latest_verdict(tmp_path, "k")
    assert got is not None and got.verdict.basis == SECOND_READ
    assert "basis" in {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(finding_verdicts)")}


def test_every_registered_verifier_is_covered():
    verifiers, _ = registered()
    assert verifiers and all(isinstance(v, Verifier) for v in verifiers)
    assert len(_rule_ids()) >= len(verifiers)
