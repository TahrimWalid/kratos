"""Every finding carries `subject` and `entities` (0.1 step 1): the concrete things
it is about, sorted and normalised, so a person's decision can cover exactly what
they saw and a new attacker / port / account / path / CVE reopens it."""
from __future__ import annotations

from kratos.adapters import findings_engine as FE

_NMAP = {"hosts": [{"ip": "10.0.0.5", "open_ports": [
    {"port": 443, "protocol": "tcp", "service": "https"},
    {"port": 22, "protocol": "tcp", "service": "ssh"},
    {"port": 53, "protocol": "udp", "service": "domain"},
]}]}


def _by_id(findings):
    return {f.id: f for f in findings}


def _burst(ips, event_type="ssh_failed_login"):
    return {"event_type": event_type, "count": sum(n for _, n in ips), "start": "2026-10-04T08:55:24+00:00",
            "end": "2026-10-04T08:56:24+00:00", "top_source_ips": [{"ip": ip, "count": n} for ip, n in ips]}


def test_every_finding_has_an_empty_subject_and_a_list_of_entities():
    out = FE.generate_findings(_NMAP, None, {"bursts": [_burst([("203.0.113.9", 4)])]}, None)
    assert out
    for f in out:
        assert f.subject == ""
        assert isinstance(f.entities, list) and f.entities == sorted(f.entities)


def test_net_002_names_each_open_port_and_protocol():
    f = _by_id(FE.generate_findings(_NMAP, None, None, None))["NET-002"]
    assert f.entities == ["22/tcp", "443/tcp", "53/udp"]
    assert _by_id(FE.generate_findings({"hosts": [{"ip": "x", "open_ports": []}]}, None, None, None))[
        "NET-001"].entities == []


def test_burst_findings_name_every_source_ip_normalised():
    bursts = [_burst([("2001:0db8:0000:0000:0000:0000:0000:0001", 3), ("203.0.113.9", 4)]),
              _burst([(f"198.51.100.{i}", 3) for i in range(1, 7)])]
    f = _by_id(FE.generate_findings(_NMAP, None, {"bursts": bursts}, None))["CORR-SSH-001"]
    # all eight IPs, not just the five most active in source_ips; IPv6 in compressed form
    assert "2001:db8::1" in f.entities and len(f.entities) == 8
    assert len(f.source_ips) == 5


def test_auth_004_without_ssh_exposure_names_its_ips():
    f = _by_id(FE.generate_findings(None, None, {"bursts": [_burst([("203.0.113.9", 4)])]}, None))["AUTH-004"]
    assert f.entities == ["203.0.113.9"]


def test_tied_source_ips_are_ordered_by_ip_so_the_first_is_stable():
    a = FE.generate_findings(_NMAP, None, {"bursts": [_burst([("203.0.113.9", 3), ("198.51.100.1", 3)])]}, None)
    b = FE.generate_findings(_NMAP, None, {"bursts": [_burst([("198.51.100.1", 3), ("203.0.113.9", 3)])]}, None)
    assert _by_id(a)["CORR-SSH-001"].source_ips == _by_id(b)["CORR-SSH-001"].source_ips == ["198.51.100.1",
                                                                                         "203.0.113.9"]


def test_sudo_rules_name_the_users_involved():
    stats = {"events_by_type": {"sudo_auth_failure": 2, "sudo_pam_auth_failure": 1, "sudo_session_open": 3},
             "top_sudo_auth_fail_users": [{"user": "bob", "count": 2}],
             "top_sudo_pam_auth_fail_users": [{"user": "Alice", "count": 1}],
             "top_sudo_users": [{"user": "ubuntu", "count": 3}]}
    out = _by_id(FE.generate_findings(None, stats, None, None))
    assert out["AUTH-001"].entities == ["Alice", "bob"]     # case kept: Linux user names are case-sensitive
    assert out["AUTH-003"].entities == ["ubuntu"]


def test_integ_001_names_changed_added_and_removed_paths():
    fi = {"diff": {"changed": [{"path": "/etc/passwd"}], "added": [{"path": "/etc/cron.d/x"}],
                   "removed": [{"path": "/etc/hosts"}]}}
    f = _by_id(FE.generate_findings(None, None, None, None, file_integrity=fi))["INTEG-001"]
    assert f.entities == ["/etc/cron.d/x", "/etc/hosts", "/etc/passwd"]


def test_priv_rules_name_accounts_and_grant_groups():
    snap = {"target": "10.0.0.5", "checked_at": "2026-10-04T08:00:00+00:00",
            "accounts": {"root": {"uid": 0, "via": ["uid 0"]}, "toor": {"uid": 0, "via": ["uid 0"]},
                         "eve": {"uid": 1001, "via": ["sudo group"]}, "new": {"uid": 1002, "via": ["docker"]}},
            "recent_privilege_grants": [{"user": "eve", "group": "sudo", "in_effect": True, "time": "t",
                                         "source": "usermod"}],
            "changed_since_last_check": {"added": ["new", "eve"]}}
    out = _by_id(FE.generate_findings(None, None, None, None, privileged_accounts=snap))
    assert out["PRIV-001"].entities == ["eve:sudo"]
    assert out["PRIV-002"].entities == ["toor"]
    assert out["PRIV-003"].entities == ["new"]
    assert out["PRIV-004"].entities == ["eve", "new", "root", "toor"]


def test_vuln_rules_name_cves_and_templates():
    scan = {"target": "10.0.0.5", "scanned_at": "2026-10-04T08:00:00+00:00", "findings": [
        {"source": "vulscan", "host": "10.0.0.5", "port": 22, "cve_ids": ["cve-2023-28531", "CVE-2021-1"]},
        {"source": "nuclei", "severity": "high", "template_id": "tech-detect", "name": "x"},
    ], "cve_matching": "done", "services_checked": 1}
    out = _by_id(FE.generate_findings(None, None, None, None, vuln_scan=scan))
    assert out["VULN-001"].entities == ["CVE-2021-1"]   # only CVE- prefixed ids are matched
    assert out["VULN-002"].entities == ["tech-detect"]


def test_entities_reach_the_report_dict(tmp_path, monkeypatch):
    import json

    from kratos import kratos_config

    monkeypatch.setattr(kratos_config, "get_active_target", lambda: "10.0.0.5")
    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "parsed_1.json").write_text(json.dumps(_NMAP))
    out_json, _ = FE.write_findings_report(tmp_path)
    found = json.loads(out_json.read_text())["findings"]
    net = next(f for f in found if f["id"] == "NET-002")
    assert net["subject"] == "" and net["entities"] == ["22/tcp", "443/tcp", "53/udp"]
