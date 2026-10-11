"""Finding lifecycle (0.1): identity across runs, the automatic moves, people's
decisions and their scopes, expiry, reopen-on-new-entity, audit, idempotency,
concurrency, and a lifecycle failure never losing the report."""
from __future__ import annotations

import json
import multiprocessing
import uuid

import pytest

from kratos.lifecycle import apply as A, decide as D, query as Q, store as S
from kratos.lifecycle.coverage import Coverage, nothing
from kratos.lifecycle.keys import finding_key
from kratos.run_context import RunContext

T = "10.0.0.5"
ALL = Coverage(inputs={k: None for k in ("nmap_parsed", "auth_stats", "auth_patterns", "system_context",
                                          "auth_trends", "file_integrity", "privileged_accounts", "vuln_scan")})
NONE = nothing()
ME = D.Actor(user="alice", interface="cli")
DAY = 86400.0


def run(source="interactive", t0=1_000_000.0):
    return RunContext(run_id=uuid.uuid4().hex, source=source, target=T, session_id=None, started_at=t0)


def f(rid="CORR-SSH-001", severity="high", entities=("203.0.113.9",), **extra):
    return {"id": rid, "title": f"{rid} title", "severity": severity, "evidence": ["x"], "subject": "",
            "entities": list(entities), **extra}


def apply(tmp_path, findings, *, cov=ALL, r=None, now=1_000_000.0, target=T):
    return A.apply_run(findings, target=target, coverage=cov, run=r or run(), data_dir=tmp_path, now=now)


def rows(tmp_path, sql, *args):
    with S.opened(tmp_path) as conn:
        return [dict(x) for x in conn.execute(sql, args).fetchall()]


def key(rid="CORR-SSH-001", target=T):
    return finding_key(rid, target, "")


# -- identity -------------------------------------------------------------------------

def test_same_issue_across_five_runs_is_one_record(tmp_path):
    for i in range(5):
        out, summary = apply(tmp_path, [f()], now=1_000_000.0 + i * 60)
    recs = rows(tmp_path, "SELECT * FROM finding_records")
    assert len(recs) == 1
    assert recs[0]["times_seen"] == 5 and recs[0]["last_seen"] == 1_000_240.0 and recs[0]["first_seen"] == 1_000_000.0
    assert out[0]["finding_key"] == key() and out[0]["change"] == "unchanged" and summary["still_open"] == [key()]
    # only transitions are events, not every sighting
    assert [e["kind"] for e in rows(tmp_path, "SELECT kind FROM finding_events")] == ["created"]


def test_first_sighting_is_new_and_annotated(tmp_path):
    out, summary = apply(tmp_path, [f()])
    a = out[0]
    assert a["state"] == "open" and a["change"] == "new" and a["first_seen"].startswith("1970-01-12")
    assert summary["new"] == [key()] and summary["hidden_total"] == 0
    assert "decision" not in a


def test_same_run_applied_twice_changes_nothing(tmp_path):
    r = run()
    first = apply(tmp_path, [f(), f("NET-002", "medium", ["22/tcp"])], r=r)
    before = (rows(tmp_path, "SELECT * FROM finding_records ORDER BY finding_key"),
              rows(tmp_path, "SELECT * FROM finding_events ORDER BY id"))
    second = apply(tmp_path, [f(), f("NET-002", "medium", ["22/tcp"])], r=r, now=1_000_030.0)
    after_events = rows(tmp_path, "SELECT * FROM finding_events ORDER BY id")
    recs = rows(tmp_path, "SELECT * FROM finding_records ORDER BY finding_key")
    assert after_events == before[1]
    assert [x["times_seen"] for x in recs] == [x["times_seen"] for x in before[0]] == [1, 1]
    assert [x["change"] for x in first[0]] == [x["change"] for x in second[0]] == ["new", "new"]
    assert first[1]["new"] == second[1]["new"]


def test_different_machines_are_different_findings(tmp_path):
    apply(tmp_path, [f()])
    apply(tmp_path, [f()], target="10.0.0.6")
    assert len(rows(tmp_path, "SELECT * FROM finding_records")) == 2


# -- run notes ------------------------------------------------------------------------

def test_run_notes_get_no_record_and_are_always_shown(tmp_path):
    out, summary = apply(tmp_path, [f("COV-001", "info", ()), f("VULN-003", "info", ())])
    assert all(a["state"] == "run_note" and "finding_key" not in a for a in out)
    assert rows(tmp_path, "SELECT * FROM finding_records") == []
    assert summary["new"] == [] and summary["hidden_total"] == 0
    with pytest.raises(D.DecisionError):
        D.mark_false_positive(finding_key("COV-001", T, ""), actor=ME, reason="no", data_dir=tmp_path)


# -- automatic moves ------------------------------------------------------------------

def test_absent_and_covered_condition_is_mitigated(tmp_path):
    apply(tmp_path, [f("NET-002", "medium", ["22/tcp"])])
    _out, summary = apply(tmp_path, [], now=1_000_100.0)
    rec = rows(tmp_path, "SELECT * FROM finding_records")[0]
    assert rec["state"] == "mitigated" and rec["last_checked"] == 1_000_100.0
    assert summary["fixed"] == [key("NET-002")]


def test_absent_and_covered_occurrence_is_inactive(tmp_path):
    apply(tmp_path, [f()])
    apply(tmp_path, [], now=1_000_100.0)
    assert rows(tmp_path, "SELECT state FROM finding_records")[0]["state"] == "inactive"
    ev = rows(tmp_path, "SELECT * FROM finding_events WHERE kind = 'state_changed'")[0]
    assert ev["reason"] == "no recurrence in a run that re-checked it" and ev["actor"] == "kratos"


def test_absent_but_not_covered_is_unchanged_and_not_rechecked(tmp_path):
    apply(tmp_path, [f()])
    _out, summary = apply(tmp_path, [], cov=NONE, now=1_000_100.0)
    rec = rows(tmp_path, "SELECT * FROM finding_records")[0]
    assert rec["state"] == "open" and rec["last_checked"] == 1_000_000.0
    assert summary["not_rechecked"] == [key()] and summary["fixed"] == []


def test_partially_covered_run_only_moves_what_it_covered(tmp_path):
    apply(tmp_path, [f(), f("NET-002", "medium", ["22/tcp"])])
    only_nmap = Coverage(inputs={"nmap_parsed": None, "auth_patterns": "auth_patterns covered only part"})
    _out, summary = apply(tmp_path, [], cov=only_nmap, now=1_000_100.0)
    assert summary["fixed"] == [key("NET-002")] and summary["not_rechecked"] == [key()]


def test_mitigated_then_present_reopens_as_regressed(tmp_path):
    apply(tmp_path, [f("NET-002", "medium", ["22/tcp"])])
    apply(tmp_path, [], now=1_000_100.0)
    out, summary = apply(tmp_path, [f("NET-002", "medium", ["22/tcp"])], now=1_000_200.0)
    assert out[0]["state"] == "open" and out[0]["change"] == "reopened" and summary["new"] == [key("NET-002")]
    assert rows(tmp_path, "SELECT reason FROM finding_events WHERE kind = 'reopened'")[0]["reason"] == "regressed"


def test_inactive_then_present_reopens_as_recurred(tmp_path):
    apply(tmp_path, [f()])
    apply(tmp_path, [], now=1_000_100.0)
    out, _ = apply(tmp_path, [f()], now=1_000_200.0)
    assert out[0]["change"] == "recurred"
    assert rows(tmp_path, "SELECT reason FROM finding_events WHERE kind = 'reopened'")[0]["reason"] == "recurred"


# -- decisions ------------------------------------------------------------------------

def test_accepting_hides_it_from_the_default_view_with_a_count(tmp_path):
    apply(tmp_path, [f()])
    D.accept_risk(key()[:12], actor=ME, reason="lab scanner", owner=None, expires_at=1_000_000.0 + DAY,
                  data_dir=tmp_path, now=1_000_010.0)
    out, summary = apply(tmp_path, [f()], now=1_000_100.0)
    assert out[0]["state"] == "risk_accepted"
    assert out[0]["decision"]["owner"] == "alice" and out[0]["decision"]["reason"] == "lab scanner"
    assert summary["hidden"]["risk_accepted"] == 1 and summary["hidden_total"] == 1 and summary["still_open"] == []
    assert Q.list_findings(tmp_path, target=T) == []
    assert [r["state"] for r in Q.list_findings(tmp_path, target=T, state="decided")] == ["risk_accepted"]
    assert A.footer_line(summary) == "New 0 · Still open 0 · Fixed 0 · Hidden by your decisions 1"


def test_expired_acceptance_reopens(tmp_path):
    apply(tmp_path, [f()])
    D.accept_risk(key(), actor=ME, reason="lab", owner="bob", expires_at=1_000_000.0 + 60, data_dir=tmp_path,
                  now=1_000_010.0)
    out, summary = apply(tmp_path, [f()], now=1_000_030.0)
    assert out[0]["state"] == "risk_accepted"
    out, summary = apply(tmp_path, [f()], now=1_000_100.0)
    assert out[0]["state"] == "open" and out[0]["change"] == "reopened"
    assert summary["expired_this_run"] == [key()] and summary["new"] == [key()]
    # and it stays open afterwards (no flip-flop back under the expired decision)
    out, _ = apply(tmp_path, [f()], now=1_000_200.0)
    assert out[0]["state"] == "open" and out[0]["change"] == "unchanged"


def test_expiry_reopens_even_when_the_finding_is_absent(tmp_path):
    apply(tmp_path, [f()])
    D.accept_risk(key(), actor=ME, reason="lab", owner=None, expires_at=1_000_060.0, data_dir=tmp_path,
                  now=1_000_010.0)
    _out, summary = apply(tmp_path, [], cov=NONE, now=1_000_100.0)
    assert summary["expired_this_run"] == [key()]
    assert rows(tmp_path, "SELECT state FROM finding_records")[0]["state"] == "open"


def test_decided_and_absent_stays_decided(tmp_path):
    apply(tmp_path, [f()])
    D.mark_false_positive(key(), actor=ME, reason="scanner", data_dir=tmp_path, now=1_000_010.0)
    apply(tmp_path, [], now=1_000_100.0)
    rec = rows(tmp_path, "SELECT * FROM finding_records")[0]
    assert rec["state"] == "false_positive" and rec["last_checked"] == 1_000_100.0


def test_false_positive_stays_suppressed_on_later_runs(tmp_path):
    apply(tmp_path, [f()])
    D.mark_false_positive(key(), actor=ME, reason="my scanner", data_dir=tmp_path, now=1_000_010.0)
    for i in range(3):
        out, summary = apply(tmp_path, [f()], now=1_000_100.0 + i)
        assert out[0]["state"] == "false_positive" and summary["hidden"]["false_positive"] == 1


def test_a_new_entity_reopens_and_names_it(tmp_path):
    apply(tmp_path, [f()])
    D.accept_risk(key(), actor=ME, reason="lab scanner", owner=None, expires_at=1_000_000.0 + DAY,
                  data_dir=tmp_path, now=1_000_010.0)
    out, summary = apply(tmp_path, [f(entities=("203.0.113.9", "198.51.100.7"))], now=1_000_100.0)
    assert out[0]["state"] == "open" and out[0]["change"] == "reopened" and summary["new"] == [key()]
    reason = rows(tmp_path, "SELECT reason FROM finding_events WHERE kind = 'reopened'")[0]["reason"]
    assert "198.51.100.7" in reason
    # the key-scope decision is revoked, so the old IP alone doesn't re-hide it
    out, _ = apply(tmp_path, [f()], now=1_000_200.0)
    assert out[0]["state"] == "open"


def test_a_higher_severity_reopens(tmp_path):
    apply(tmp_path, [f("NET-002", "medium", ["22/tcp"])])
    D.mark_out_of_scope(key("NET-002"), actor=ME, reason="lab", data_dir=tmp_path, now=1_000_010.0)
    out, _ = apply(tmp_path, [f("NET-002", "high", ["22/tcp"])], now=1_000_100.0)
    assert out[0]["state"] == "open"
    assert "severity rose from medium to high" in rows(
        tmp_path, "SELECT reason FROM finding_events WHERE kind = 'reopened'")[0]["reason"]


def test_counts_changing_do_not_reopen(tmp_path):
    apply(tmp_path, [f(evidence=["Bursts: 1"])])
    D.accept_risk(key(), actor=ME, reason="lab", owner=None, expires_at=1_000_000.0 + DAY, data_dir=tmp_path,
                  now=1_000_010.0)
    out, _ = apply(tmp_path, [f(evidence=["Bursts: 9"])], now=1_000_100.0)
    assert out[0]["state"] == "risk_accepted"
    # fewer entities is still covered
    out, _ = apply(tmp_path, [f(entities=())], now=1_000_200.0)
    assert out[0]["state"] == "risk_accepted"


def test_verify_keeps_it_shown_and_reopen_undoes_a_decision(tmp_path):
    apply(tmp_path, [f()])
    D.verify(key(), actor=ME, reason="real attack", data_dir=tmp_path, now=1_000_010.0)
    out, summary = apply(tmp_path, [f()], now=1_000_100.0)
    assert out[0]["state"] == "verified" and summary["still_open"] == [key()]
    D.mark_false_positive(key(), actor=ME, reason="no", data_dir=tmp_path, now=1_000_110.0)
    D.reopen(key(), actor=ME, reason="changed my mind", data_dir=tmp_path, now=1_000_120.0)
    out, _ = apply(tmp_path, [f()], now=1_000_200.0)
    assert out[0]["state"] == "open"
    with pytest.raises(D.DecisionError):
        D.reopen(key(), actor=ME, reason="again", data_dir=tmp_path)


@pytest.mark.parametrize("bad", [
    dict(reason=""), dict(reason="   "), dict(reason="x" * 501),
    dict(expires_at=None), dict(expires_at=999_000.0), dict(expires_at=1_000_000.0 + 181 * DAY),
    dict(scope="planet"),
])
def test_accept_validation(tmp_path, bad):
    apply(tmp_path, [f()])
    args = dict(reason="ok", owner=None, expires_at=1_000_000.0 + DAY, scope="key")
    args.update(bad)
    with pytest.raises(D.DecisionError):
        D.accept_risk(key(), actor=ME, data_dir=tmp_path, now=1_000_000.0, **args)


def test_accept_cap_follows_the_setting(tmp_path):
    from kratos import settings_store
    from kratos.lifecycle import settings as LS

    apply(tmp_path, [f()])
    settings_store.set(LS.ACCEPT_MAX_DAYS, 7, data_dir=tmp_path, actor="test")
    with pytest.raises(D.DecisionError, match="at most 7 days"):
        D.accept_risk(key(), actor=ME, reason="r", owner=None, expires_at=1_000_000.0 + 8 * DAY,
                      data_dir=tmp_path, now=1_000_000.0)
    D.accept_risk(key(), actor=ME, reason="r", owner=None, expires_at=1_000_000.0 + 7 * DAY,
                  data_dir=tmp_path, now=1_000_000.0)


def test_decisions_need_a_person(tmp_path):
    apply(tmp_path, [f()])
    with pytest.raises(D.DecisionError):
        D.verify(key(), actor=D.Actor(user="x", interface="mcp"), reason="r", data_dir=tmp_path)
    from kratos import settings_store

    with settings_store.tool_call_scope("sneaky"), pytest.raises(D.DecisionError, match="agent tools"):
        D.mark_false_positive(key(), actor=ME, reason="r", data_dir=tmp_path)


# -- scopes ---------------------------------------------------------------------------

def test_scope_precedence_key_then_rule_target_then_rule(tmp_path):
    apply(tmp_path, [f()])
    D.mark_out_of_scope(key(), actor=ME, reason="everywhere", scope="rule", data_dir=tmp_path, now=1_000_010.0)
    D.mark_false_positive(key(), actor=ME, reason="here", scope="rule_target", data_dir=tmp_path, now=1_000_020.0)
    D.accept_risk(key(), actor=ME, reason="this one", owner=None, expires_at=1_000_000.0 + DAY,
                  data_dir=tmp_path, now=1_000_030.0)
    out, _ = apply(tmp_path, [f()], now=1_000_100.0)
    assert out[0]["state"] == "risk_accepted" and out[0]["decision"]["scope"] == "key"
    D.reopen(key(), actor=ME, reason="r", data_dir=tmp_path, now=1_000_110.0)
    # the reopen releases it from the older broad decisions too; a newer broad one applies
    out, _ = apply(tmp_path, [f()], now=1_000_120.0)
    assert out[0]["state"] == "open"
    D.mark_false_positive(key(), actor=ME, reason="here again", scope="rule_target", data_dir=tmp_path,
                          now=1_000_130.0)
    out, _ = apply(tmp_path, [f()], now=1_000_140.0)
    assert out[0]["state"] == "false_positive" and out[0]["decision"]["scope"] == "rule_target"


def test_newer_decision_at_the_same_scope_revokes_the_older(tmp_path):
    apply(tmp_path, [f()])
    D.mark_false_positive(key(), actor=ME, reason="one", data_dir=tmp_path, now=1_000_010.0)
    D.mark_out_of_scope(key(), actor=ME, reason="two", data_dir=tmp_path, now=1_000_020.0)
    exc = rows(tmp_path, "SELECT * FROM finding_exceptions ORDER BY id")
    assert exc[0]["revoked_at"] == 1_000_020.0 and exc[0]["revoke_reason"] == "replaced by a newer decision"
    assert exc[1]["revoked_at"] is None
    assert apply(tmp_path, [f()], now=1_000_100.0)[0][0]["state"] == "out_of_scope"


def test_rule_everywhere_covers_another_machine_and_future_findings(tmp_path):
    apply(tmp_path, [f("NET-002", "medium", ["22/tcp"])])
    D.mark_out_of_scope(key("NET-002"), actor=ME, reason="ssh is fine", scope="rule", data_dir=tmp_path,
                        now=1_000_010.0)
    out, summary = apply(tmp_path, [f("NET-002", "medium", ["22/tcp"])], target="10.0.0.9", now=1_000_100.0)
    assert out[0]["state"] == "out_of_scope" and summary["hidden_total"] == 1
    # ...but not one showing something the person never saw
    out, _ = apply(tmp_path, [f("NET-002", "medium", ["22/tcp", "80/tcp"])], target="10.0.0.10", now=1_000_200.0)
    assert out[0]["state"] == "open"


# -- audit ----------------------------------------------------------------------------

def test_every_transition_is_attributed(tmp_path):
    r = run(source="schedule")
    apply(tmp_path, [f(), f("NET-002", "medium", ["22/tcp"])], r=r)
    D.accept_risk(key(), actor=ME, reason="lab", owner=None, expires_at=1_000_060.0, data_dir=tmp_path,
                  now=1_000_010.0)
    apply(tmp_path, [f()], now=1_000_100.0)          # expired + NET-002 mitigated
    apply(tmp_path, [f(entities=("1.2.3.4",))], now=1_000_200.0)
    events = rows(tmp_path, "SELECT * FROM finding_events")
    assert {e["kind"] for e in events} >= {"created", "state_changed", "expired", "entities_changed"}
    for e in events:
        assert e["actor"] and e["interface"] and e["reason"], e
        if e["actor"] == "kratos":
            assert e["run_id"], e
        else:
            assert e["actor"] == "alice" and e["interface"] == "cli"
    assert {e["interface"] for e in events if e["run_id"] == r.run_id} == {"scheduled"}
    with S.opened(tmp_path) as conn, pytest.raises(Exception, match="append-only"):
        conn.execute("UPDATE finding_events SET reason = 'x'")


# -- concurrency ----------------------------------------------------------------------

def _worker(data_dir: str, n: int, q) -> None:
    try:
        from pathlib import Path

        for i in range(n):
            A.apply_run([f()], target=T, coverage=ALL, run=run(), data_dir=Path(data_dir), now=1_000_000.0 + i)
        q.put("ok")
    except Exception as e:  # noqa: BLE001
        q.put(repr(e))


def test_two_processes_applying_runs_lose_no_update(tmp_path):
    ctx = multiprocessing.get_context("fork")
    q = ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(str(tmp_path), 15, q)) for _ in range(2)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    assert [q.get(timeout=5) for _ in procs] == ["ok", "ok"]
    recs = rows(tmp_path, "SELECT * FROM finding_records")
    assert len(recs) == 1 and recs[0]["times_seen"] == 30
    assert [e["kind"] for e in rows(tmp_path, "SELECT kind FROM finding_events")] == ["created"]


# -- the report -----------------------------------------------------------------------

def _scan_dir(tmp_path, monkeypatch):
    from kratos import kratos_config

    monkeypatch.setattr(kratos_config, "get_active_target", lambda: T)
    scans = tmp_path / "scans"
    scans.mkdir(exist_ok=True)
    (scans / "parsed_1.json").write_text(json.dumps(
        {"target": T, "hosts": [{"ip": T, "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}]}]}))


def test_report_carries_target_lifecycle_and_leads_with_it(tmp_path, monkeypatch):
    from kratos.adapters import findings_engine as FE

    _scan_dir(tmp_path, monkeypatch)
    out_json, out_md = FE.write_findings_report(tmp_path)
    report = json.loads(out_json.read_text())
    assert report["target"] == T
    assert set(A.SUMMARY_KEYS) <= set(report["lifecycle"])
    net = next(x for x in report["findings"] if x["id"] == "NET-002")
    assert net["state"] == "open" and net["change"] == "new" and len(net["finding_key"]) == 64
    md = out_md.read_text()
    assert md.index("## New") < md.index("## Still open") < md.index("## Fixed since last run") < md.index("## Findings")
    assert "Hidden by your decisions: 0" in md


def test_a_lifecycle_failure_still_writes_the_report(tmp_path, monkeypatch):
    from kratos.adapters import findings_engine as FE

    _scan_dir(tmp_path, monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(A, "apply_run", boom)
    out_json, out_md = FE.write_findings_report(tmp_path)
    report = json.loads(out_json.read_text())
    assert report["lifecycle_error"] == "RuntimeError: disk on fire" and "lifecycle" not in report
    assert [x["id"] for x in report["findings"]] == ["NET-002"] and "state" not in report["findings"][0]
    assert "Finding history unavailable" in out_md.read_text()
