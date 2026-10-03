"""VULN-* findings: run_vuln_scan's results reach the findings report (and so
/run's audit), from a fresh scan of the active target only, with what the scan
could not check reported instead of read as clean."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kratos import kratos_config as kc
from kratos.adapters import findings_engine as FE

TARGET = "203.0.113.10"


@pytest.fixture(autouse=True)
def _active_target():
    before = kc.get_active_target()
    kc.set_active_target(TARGET)
    yield
    kc.set_active_target(before)


def _now(offset_hours: float = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=offset_hours)).isoformat(timespec="seconds")


def _scan(target=TARGET, scanned_at=None, findings=None, **extra) -> dict:
    data = {"target": target, "scanned_at": scanned_at or _now(), "cve_matching": "done",
            "active_checks": "done", "services_checked": [{"port": 22, "service": "ssh"}],
            "database_newest_cve_year": 2026, "database_note": None, "findings": findings or [], "errors": []}
    data.update(extra)
    return data


def _write(scans: Path, data, name: str, mtime_offset: float = 0) -> Path:
    scans.mkdir(parents=True, exist_ok=True)
    path = scans / f"vuln_scan_{name}.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    t = time.time() + mtime_offset
    os.utime(path, (t, t))
    return path


def _vulscan(port=22, cves=("CVE-2023-28531",), product="OpenSSH", version="8.9p1", host=TARGET):
    return {"source": "vulscan", "host": host, "port": port, "product": product, "version": version,
            "cve_ids": list(cves), "detail": "..."}


def _nuclei(severity, name="check", cves=()):
    return {"source": "nuclei", "template_id": name, "name": name, "severity": severity,
            "cve_ids": list(cves), "host": TARGET, "matched_at": f"http://{TARGET}:80/"}


def _ids(findings) -> list[str]:
    return [f.id for f in findings]


# ---------------------------------------------------------------- which scan is used


def test_no_scans_means_no_scan(tmp_path):
    assert FE._load_recent_vuln_scan(tmp_path / "scans") == (None, None)


def test_a_fresh_scan_of_the_active_target_is_used(tmp_path):
    path = _write(tmp_path / "scans", _scan(), "a")
    data, used = FE._load_recent_vuln_scan(tmp_path / "scans")
    assert used == path and data["target"] == TARGET


def test_a_newer_scan_of_another_machine_does_not_hide_this_ones(tmp_path):
    scans = tmp_path / "scans"
    mine = _write(scans, _scan(), "mine", mtime_offset=-60)
    _write(scans, _scan(target="198.51.100.99"), "other")
    assert FE._load_recent_vuln_scan(scans)[1] == mine


def test_only_other_machines_scans_means_none(tmp_path):
    _write(tmp_path / "scans", _scan(target="198.51.100.99"), "other")
    assert FE._load_recent_vuln_scan(tmp_path / "scans") == (None, None)


def test_a_stale_scan_is_not_used_and_an_older_one_does_not_stand_in(tmp_path):
    scans = tmp_path / "scans"
    _write(scans, _scan(scanned_at=_now(-30)), "older")  # file time says newest; its scan time says oldest
    _write(scans, _scan(scanned_at=_now(-25)), "stale", mtime_offset=-120)
    assert FE._load_recent_vuln_scan(scans) == (None, None)


def test_the_scans_own_time_decides_not_the_file_time(tmp_path):
    """A copied or restored data folder resets file times."""
    scans = tmp_path / "scans"
    _write(scans, _scan(scanned_at=_now(-30)), "copied_late")             # newest file, oldest scan
    fresh = _write(scans, _scan(scanned_at=_now(-1)), "real", mtime_offset=-3600)
    assert FE._load_recent_vuln_scan(scans)[1] == fresh
    _write(scans, _scan(scanned_at=_now(-0.5)), "newer_but_old_file", mtime_offset=-7200)
    assert FE._load_recent_vuln_scan(scans)[1].name == "vuln_scan_newer_but_old_file.json"


def test_a_scan_dated_in_the_future_is_distrusted(tmp_path):
    _write(tmp_path / "scans", _scan(scanned_at=_now(+3)), "future")
    assert FE._load_recent_vuln_scan(tmp_path / "scans") == (None, None)


def test_unreadable_or_malformed_files_are_skipped(tmp_path):
    scans = tmp_path / "scans"
    good = _write(scans, _scan(), "good", mtime_offset=-300)
    _write(scans, "{not json", "corrupt", mtime_offset=-10)
    _write(scans, json.dumps(["a", "list"]), "list", mtime_offset=-20)
    _write(scans, _scan(findings="nope"), "badfindings", mtime_offset=-30)
    _write(scans, {"scanned_at": _now()}, "notarget", mtime_offset=-40)
    assert FE._load_recent_vuln_scan(scans)[1] == good


def test_a_bad_timestamp_falls_back_to_the_file_time(tmp_path):
    scans = tmp_path / "scans"
    _write(scans, _scan(scanned_at="yesterday-ish"), "fresh")
    assert FE._load_recent_vuln_scan(scans)[0] is not None
    _write(scans, _scan(scanned_at="yesterday-ish"), "fresh", mtime_offset=-26 * 3600)
    assert FE._load_recent_vuln_scan(scans) == (None, None)


def test_without_an_active_target_the_newest_scan_is_used(tmp_path):
    kc.set_active_target(None)
    scans = tmp_path / "scans"
    _write(scans, _scan(target="198.51.100.1"), "old", mtime_offset=-60)
    newest = _write(scans, _scan(target="198.51.100.2"), "new")
    assert FE._load_recent_vuln_scan(scans)[1] == newest


@pytest.mark.parametrize("active,scanned", [("127.0.0.1", "localhost"), ("localhost", "::1"),
                                            ("Web-01.Example", "web-01.example"), ("web-01", "ubuntu@web-01"),
                                            ("2001:db8::1", "[2001:db8::1]")])
def test_the_same_machine_written_differently_matches(tmp_path, active, scanned):
    kc.set_active_target(active)
    _write(tmp_path / "scans", _scan(target=scanned), "a")
    assert FE._load_recent_vuln_scan(tmp_path / "scans")[0] is not None


# ---------------------------------------------------------------- what it reports


def test_cve_matches_become_one_medium_finding_newest_first():
    scan = _scan(findings=[_vulscan(cves=["CVE-1999-0661", "CVE-2023-28531", "CVE-2021-36368", "CVE-2023-9"])])
    [f] = FE._vulnerability_findings(scan)
    assert (f.id, f.severity) == ("VULN-001", "medium")
    line = next(e for e in f.evidence if "port 22" in e)
    assert line.index("CVE-2023-28531") < line.index("CVE-2023-9") < line.index("CVE-2021-36368") < line.index("CVE-1999-0661")
    assert any("not confirmed" in e for e in f.evidence)
    assert any("goes up to 2026" in e for e in f.evidence)


def test_long_lists_are_capped_and_say_how_much_was_left_out():
    many = [f"CVE-20{10 + i}-{i}" for i in range(12)]
    services = [_vulscan(port=p, cves=many) for p in range(1, 14)]
    [f] = FE._vulnerability_findings(_scan(findings=services))
    assert "(+4 older)" in f.evidence[2]
    assert any("3 more service(s)" in e for e in f.evidence)
    assert f.evidence[1].startswith("13 service(s) match 12 known CVE")


def test_ports_sort_numerically_and_duplicates_merge():
    scan = _scan(findings=[_vulscan(port="8080", cves=["CVE-2020-1"]), _vulscan(port="22", cves=["CVE-2020-2"]),
                           _vulscan(port="22", cves=["CVE-2020-3", "not-a-cve"])])
    [f] = FE._vulnerability_findings(scan)
    lines = [e for e in f.evidence if " port " in e]
    assert len(lines) == 2 and "port 22" in lines[0] and "port 8080" in lines[1]
    assert "CVE-2020-3, CVE-2020-2" in lines[0] and "not-a-cve" not in lines[0]


def test_a_match_without_cve_ids_is_not_a_finding():
    assert FE._vulnerability_findings(_scan(findings=[_vulscan(cves=[])])) == []


@pytest.mark.parametrize("nuclei_sev,expected", [("critical", "high"), ("high", "high"), ("medium", "medium"),
                                                 ("low", "low"), ("info", "info"), ("weird", "info"), (None, "info")])
def test_active_check_severity_follows_nuclei(nuclei_sev, expected):
    [f] = FE._vulnerability_findings(_scan(findings=[_nuclei(nuclei_sev)]))
    assert (f.id, f.severity) == ("VULN-002", expected)


def test_active_checks_list_the_worst_first_with_their_cves():
    scan = _scan(findings=[_nuclei("info", "tech"), _nuclei("critical", "rce", cves=["CVE-2024-1"]),
                           _nuclei("low", "header")])
    [f] = FE._vulnerability_findings(scan)
    assert f.severity == "high" and f.title.startswith("Active checks found issues")
    assert f.evidence[2].startswith("[high] rce") and "CVE-2024-1" in f.evidence[2]
    assert "2 above informational" in f.evidence[1]


def test_informational_only_results_say_so():
    [f] = FE._vulnerability_findings(_scan(findings=[_nuclei("info")]))
    assert f.title == "Active checks reported informational results" and "all informational" in f.evidence[1]


@pytest.mark.parametrize("extra,phrase", [
    ({"cve_matching": "not_installed"}, "CVE list isn't installed"),
    ({"cve_matching": "failed"}, "version scan it relies on failed"),
    ({"database_note": "The local CVE list only goes up to 2013."}, "only goes up to 2013"),
    ({"active_checks": "not_installed"}, "nuclei isn't installed"),
    ({"active_checks": "failed"}, "Active web checks failed"),
    ({"services_checked": []}, "No open services were detected"),
])
def test_every_coverage_limit_is_reported_and_a_quiet_scan_is_not_called_clean(extra, phrase):
    [f] = FE._vulnerability_findings(_scan(**extra))
    assert (f.id, f.severity) == ("VULN-003", "info")
    assert any(phrase in e for e in f.evidence)
    assert "not evidence the services are up to date" in f.evidence[-1]


def test_limits_next_to_real_results_say_more_may_exist():
    out = FE._vulnerability_findings(_scan(findings=[_vulscan()], active_checks="not_installed"))
    assert _ids(out) == ["VULN-001", "VULN-003"]
    assert out[1].evidence[-1] == "Issues may exist beyond those listed."


def test_a_failed_version_scan_does_not_also_complain_about_no_services():
    [f] = FE._vulnerability_findings(_scan(cve_matching="failed", services_checked=[]))
    assert not any("No open services" in e for e in f.evidence)


def test_a_full_clean_scan_adds_nothing():
    assert FE._vulnerability_findings(_scan()) == []


def test_findings_are_ranked_with_everything_else():
    nmap = {"hosts": [{"address": TARGET, "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}]}]}
    out = FE.generate_findings(nmap, None, None, None, vuln_scan=_scan(findings=[_nuclei("critical")]))
    assert out[0].id == "VULN-002" and out[0].severity == "high"
    assert FE.FINDING_SUMMARY_TEMPLATES.get("VULN-001") and FE.FINDING_SUMMARY_TEMPLATES.get("VULN-003")


# ---------------------------------------------------------------- end to end


def test_the_findings_report_includes_a_fresh_scan(tmp_path):
    _write(tmp_path / "scans", _scan(findings=[_vulscan()]), "a")
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    assert "VULN-001" in [f["id"] for f in report["findings"]]
    assert report["inputs"]["vuln_scan"] == "vuln_scan_a.json"
    assert "vuln_scan" not in report["missing_inputs"]
    md = (tmp_path / "reports").glob("findings_*.md")
    assert "VULN-001" in next(md).read_text()


def test_explicit_core_inputs_no_longer_drop_the_on_demand_snapshots(tmp_path):
    _write(tmp_path / "scans", _scan(findings=[_vulscan()]), "a")
    files = {}
    for name in ("nmap_parsed", "auth_stats", "auth_patterns", "system_context"):
        files[name] = tmp_path / f"{name}.json"
        files[name].write_text("{}")
    report_json, _ = FE.write_findings_report(
        tmp_path, nmap_parsed_file=files["nmap_parsed"], auth_stats_file=files["auth_stats"],
        auth_patterns_file=files["auth_patterns"], system_context_file=files["system_context"])
    assert "VULN-001" in [f["id"] for f in json.loads(report_json.read_text())["findings"]]


def test_another_machines_scan_never_reaches_this_report(tmp_path):
    _write(tmp_path / "scans", _scan(target="198.51.100.99", findings=[_nuclei("critical")]), "other")
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    assert not [f for f in report["findings"] if f["id"].startswith("VULN-")]
    assert report["inputs"]["vuln_scan"] is None


# ---------------------------------------------------------------- the tool's snapshot


def _patch_tool(monkeypatch, *, nmap_error=None, nuclei_error=None, installed=True, ports=(22,)):
    from kratos.agent import tools

    def fake_nmap(target, data_dir, use_vulscan=True):
        if nmap_error:
            raise RuntimeError(nmap_error)
        out = Path(data_dir) / "x.xml"
        out.write_text("<nmaprun/>")
        return out

    def fake_nuclei(*a):
        if nuclei_error:
            raise RuntimeError(nuclei_error)
        return Path("n.jsonl")

    monkeypatch.setattr(tools, "_vulscan_installed", lambda: installed)
    monkeypatch.setattr(tools, "_run_nmap_vulscan", fake_nmap)
    monkeypatch.setattr(tools, "_parse_vulscan_xml", lambda p: [_vulscan()])
    monkeypatch.setattr(tools, "_parse_nmap_xml_to_dict", lambda p: {"hosts": [{"open_ports": [
        {"port": p, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.9p1"} for p in ports]}]})
    monkeypatch.setattr(tools, "_run_nuclei_scan", fake_nuclei)
    monkeypatch.setattr(tools, "_parse_nuclei_jsonl", lambda p: [])
    monkeypatch.setattr(tools, "_network_scan_gap", lambda t: None)
    monkeypatch.setattr(tools, "_check_vulscan_db_staleness", lambda: {
        "exists": installed, "last_updated": "x", "age_days": 0, "newest_cve_year": 2026 if installed else None,
        "stale": not installed, "note": None})
    return tools


def test_the_tool_saves_a_snapshot_the_report_then_uses(monkeypatch, tmp_path):
    tools = _patch_tool(monkeypatch)
    out = tools.tool_run_vuln_scan(tmp_path, target=TARGET)
    snap = json.loads(Path(out["snapshot_file"]).read_text())
    assert snap["target"] == TARGET and snap["cve_matching"] == "done" and snap["active_checks"] == "done"
    assert snap["services_checked"][0]["product"] == "OpenSSH" and snap["scanned_at"].endswith("+00:00")
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    assert "VULN-001" in [f["id"] for f in report["findings"]]


def test_a_failed_version_scan_is_a_coverage_gap_even_with_a_current_cve_list(monkeypatch, tmp_path):
    """Before: nmap failing with a current list left no gap, so "no CVEs" read as clean."""
    tools = _patch_tool(monkeypatch, nmap_error="nmap+vulscan timed out after 120s")
    out = tools.tool_run_vuln_scan(tmp_path, target=TARGET)
    assert out["cve_matching"] == "failed" and "version scan" in out["coverage_gap"]
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    vuln3 = next(f for f in report["findings"] if f["id"] == "VULN-003")
    assert any("version scan it relies on failed" in e for e in vuln3["evidence"])


@pytest.mark.parametrize("error,state", [("nuclei not found (optional...)", "not_installed"),
                                         ("nuclei timed out", "failed")])
def test_the_active_checks_outcome_is_recorded(monkeypatch, tmp_path, error, state):
    tools = _patch_tool(monkeypatch, nuclei_error=error)
    assert tools.tool_run_vuln_scan(tmp_path, target=TARGET)["active_checks"] == state


def test_without_a_cve_list_matching_is_recorded_as_not_installed(monkeypatch, tmp_path):
    tools = _patch_tool(monkeypatch, installed=False)
    out = tools.tool_run_vuln_scan(tmp_path, target=TARGET)
    assert out["cve_matching"] == "not_installed" and out["vulscan_finding_count"] == 0


def test_a_snapshot_that_cannot_be_written_does_not_lose_the_scan(monkeypatch, tmp_path):
    tools = _patch_tool(monkeypatch)
    (tmp_path / "scans").write_text("a file where the folder should be")
    out = tools.tool_run_vuln_scan(tmp_path, target=TARGET)
    assert out["vulscan_finding_count"] == 1 and "snapshot_file" not in out
    assert any("could not save the scan" in e for e in out["errors"])


def test_a_refused_scan_saves_nothing(monkeypatch, tmp_path):
    tools = _patch_tool(monkeypatch)
    monkeypatch.setattr(tools, "_network_scan_gap", lambda t: {"status": "error", "observation": "no network path",
                                                               "coverage_gap": "network exposure (open ports/services)"})
    tools.tool_run_vuln_scan(tmp_path, target=TARGET)
    assert not list(tmp_path.glob("scans/vuln_scan_*.json"))
