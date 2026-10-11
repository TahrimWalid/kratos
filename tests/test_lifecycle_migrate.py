"""0.1 §5.10: old findings reports are imported once, attributed to a machine by the
best available evidence, never changed, and a bad file never stops the import."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3

from kratos.lifecycle import migrate as M, store as S
from kratos.lifecycle.keys import finding_key


def _report(tmp_path, name, generated_at, findings, **extra):
    d = tmp_path / "reports"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_text(json.dumps({"generated_at": generated_at, "findings": findings, **extra}))
    return p


def _f(rid, sev="medium"):
    return {"id": rid, "title": f"{rid} t", "severity": sev, "evidence": []}


def _rows(tmp_path, sql, *args):
    with S.opened(tmp_path) as conn:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]


def _fingerprint(paths):
    return {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), os.stat(p).st_mtime_ns) for p in paths}


def test_import_twice_gives_the_same_rows_and_leaves_files_untouched(tmp_path):
    files = [
        _report(tmp_path, "findings_20261001_100000.json", "2026-10-01T10:00:00+00:00",
                [_f("NET-002"), _f("CORR-SSH-001", "high"), _f("COV-001", "info")], target="10.0.0.5"),
        _report(tmp_path, "findings_20261002_100000.json", "2026-10-02T10:00:00+00:00",
                [_f("NET-002")], target="10.0.0.5"),
    ]
    before = _fingerprint(files)
    first = M.import_reports(tmp_path)
    rows1 = _rows(tmp_path, "SELECT * FROM finding_records ORDER BY finding_key")
    second = M.import_reports(tmp_path)
    assert _rows(tmp_path, "SELECT * FROM finding_records ORDER BY finding_key") == rows1
    assert first["imported"] == 2 and second["imported"] == 0 and first["records_created"] == 2
    assert _fingerprint(files) == before
    net = next(r for r in rows1 if r["rule_id"] == "NET-002")
    corr = next(r for r in rows1 if r["rule_id"] == "CORR-SSH-001")
    # in the newest report -> open; only in an older one -> no recurrence; times from the reports
    assert net["state"] == "open" and net["times_seen"] == 2 and net["last_checked"] is None
    assert corr["state"] == "inactive"
    assert net["first_seen"] == 1790848800.0 and net["last_seen"] == 1790935200.0
    assert not [r for r in rows1 if r["rule_id"] == "COV-001"]        # run notes never become records
    ev = _rows(tmp_path, "SELECT * FROM finding_events WHERE finding_key = ?", corr["finding_key"])[0]
    assert ev["kind"] == "imported" and ev["interface"] == "migration" and "from history import" in ev["reason"]
    assert json.loads(ev["details"])["target_source"] == "report"
    assert len(_rows(tmp_path, "SELECT * FROM finding_imports")) == 2


def test_target_from_input_files_then_sessions_then_unknown(tmp_path):
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / "parsed_a.json").write_text(json.dumps({"target": "ubuntu@10.0.0.7", "hosts": []}))
    _report(tmp_path, "findings_20261001_100000.json", "2026-10-01T10:00:00+00:00", [_f("NET-002")],
            inputs={"nmap_parsed": "parsed_a.json"})
    _report(tmp_path, "findings_20261002_100000.json", "2026-10-02T10:00:00+00:00", [_f("PRIV-004", "info")],
            inputs={"nmap_parsed": "parsed_gone.json"})
    _report(tmp_path, "findings_20261003_100000.json", "2026-10-03T10:00:00+00:00", [_f("AUTH-003", "info")])
    # a session whose saved transcript names the second report
    (tmp_path / "sessions").mkdir()
    conn = sqlite3.connect(tmp_path / "kratos.db")
    conn.execute("CREATE TABLE sessions (session_id TEXT, targets TEXT)")
    conn.execute("INSERT INTO sessions VALUES ('abc', ?)", (json.dumps(["10.0.0.8"]),))
    conn.commit()
    conn.close()
    (tmp_path / "sessions" / "abc_turn1.json").write_text(json.dumps([{"tool": "correlate_findings", "observation": {
        "status": "ok", "result": {"findings_json_file": str(tmp_path / "reports" / "findings_20261002_100000.json")}}}]))
    result = M.import_reports(tmp_path)
    assert result["by_source"] == {"inputs": 1, "session": 1, "unknown": 1}
    targets = {r["rule_id"]: r["target"] for r in _rows(tmp_path, "SELECT * FROM finding_records")}
    assert targets == {"NET-002": "10.0.0.7", "PRIV-004": "10.0.0.8", "AUTH-003": "unknown"}


def test_a_malformed_report_is_skipped_recorded_and_not_fatal(tmp_path, caplog):
    bad = tmp_path / "reports"
    bad.mkdir()
    (bad / "findings_20261001_000000.json").write_text("{ not json")
    (bad / "findings_20261001_000001.json").write_text(json.dumps(["not", "a", "report"]))
    _report(tmp_path, "findings_20261002_000000.json", "2026-10-02T00:00:00+00:00", [_f("NET-002")], target="h")
    result = M.import_reports(tmp_path)
    assert result["malformed"] == 2 and result["imported"] == 1
    assert "skipping malformed findings report" in caplog.text
    names = {r["report_name"] for r in _rows(tmp_path, "SELECT * FROM finding_imports")}
    assert len(names) == 3
    assert M.import_reports(tmp_path)["malformed"] == 0       # not retried every start


def test_reports_written_with_lifecycle_are_only_recorded(tmp_path):
    _report(tmp_path, "findings_20261005_000000.json", "2026-10-05T00:00:00+00:00", [_f("NET-002")],
            target="h", lifecycle={"new": []})
    result = M.import_reports(tmp_path)
    assert result["skipped_lifecycle"] == 1 and result["records_created"] == 0


def test_history_then_live_run_continues_the_same_finding(tmp_path):
    import time
    import uuid

    from kratos.lifecycle import apply as A
    from kratos.lifecycle.coverage import nothing
    from kratos.run_context import RunContext

    _report(tmp_path, "findings_20261001_100000.json", "2026-10-01T10:00:00+00:00", [_f("NET-002")], target="h")
    M.import_reports(tmp_path)
    r = RunContext(run_id=uuid.uuid4().hex, source="cli", target="h", session_id=None, started_at=time.time())
    out, summary = A.apply_run([{**_f("NET-002"), "entities": []}], target="h", coverage=nothing(), run=r,
                               data_dir=tmp_path)
    assert out[0]["finding_key"] == finding_key("NET-002", "h", "") and out[0]["change"] != "new"
    assert summary["still_open"] == [finding_key("NET-002", "h", "")]
