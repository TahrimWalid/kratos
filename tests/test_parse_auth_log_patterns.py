"""
Sprint 1 backlog #5: parse_auth_log (Kratos's OWN local host) must run the
burst/brute-force detector and persist auth_patterns_*.json, so a LOCAL-host
brute force also reaches the rule engine — previously only the target-facing
read_journalctl path did this, so a local brute force produced no
CORR-SSH-001-class finding. Scripted/offline (no LLM/SSH).
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from kratos.adapters.findings_engine import _bursts_of, write_findings_report
from kratos.agent.tools import tool_parse_auth_log


def _write_brute_force_log(tmp_path: Path) -> Path:
    """4 failed SSH logins within ~1 minute — above analyze_auth_patterns's
    default (threshold=3 in a 5-minute window). ISO-prefixed (year-bearing) so
    the burst window is unambiguous."""
    yr = datetime.now().year
    lines = [
        f"{yr}-09-06T12:00:{sec}.000000+00:00 host sshd[100{i}]: "
        f"Failed password for baduser from 10.0.0.9 port 51000 ssh2"
        for i, sec in enumerate(("01", "20", "40", "55"))
    ]
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return log


def test_parse_auth_log_emits_patterns_with_ssh_burst(tmp_path):
    log = _write_brute_force_log(tmp_path)
    result = tool_parse_auth_log(tmp_path, log_path=log, source="file")

    # The fix: a patterns file is now produced (was absent before).
    assert "patterns_file" in result
    patterns = json.loads(Path(result["patterns_file"]).read_text())

    # And the burst the rule engine keys CORR-SSH-001 off is present, in exactly
    # the shape findings_engine._bursts_of consumes.
    bursts = _bursts_of(patterns, ("ssh_failed_login",))
    assert len(bursts) == 1
    assert bursts[0]["count"] == 4


def test_local_brute_force_now_produces_corr_ssh_001(tmp_path):
    # SSH exposed (nmap) + the now-wired local burst => CORR-SSH-001, which the
    # local path could never raise before this fix.
    (tmp_path / "scans").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scans" / "parsed_20260906_120000.json").write_text(
        json.dumps({"hosts": [{"ip": "127.0.0.1", "open_ports": [{"port": 22, "service": "ssh"}]}]}),
        encoding="utf-8")

    log = _write_brute_force_log(tmp_path)
    tool_parse_auth_log(tmp_path, log_path=log, source="file")

    out_json, _out_md = write_findings_report(tmp_path)
    ids = [f["id"] for f in json.loads(Path(out_json).read_text())["findings"]]
    assert "CORR-SSH-001" in ids


def test_no_patterns_file_means_no_burst_finding_regression_guard(tmp_path):
    # Sanity: a clean log (no failed-login burst) still parses and emits a
    # patterns file, just with no bursts — so the wiring is unconditional but
    # only a real burst raises a finding.
    yr = datetime.now().year
    (tmp_path / "auth.log").write_text(
        f"{yr}-09-06T12:00:01.000000+00:00 host sshd[1]: Accepted password for alice from 10.0.0.2 port 5 ssh2\n",
        encoding="utf-8")
    result = tool_parse_auth_log(tmp_path, log_path=tmp_path / "auth.log", source="file")
    patterns = json.loads(Path(result["patterns_file"]).read_text())
    assert _bursts_of(patterns, ("ssh_failed_login",)) == []
