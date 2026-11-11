"""E.2 compliance mapping: the vendored ids, the closed check table, the six control
statuses, COMP-001, people's decisions and the reports."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from kratos.adapters import hardening as H
from kratos.compliance import cac, checks as C, frameworks as F
from kratos.compliance import judge as J
from kratos.compliance import owners as O
from kratos.compliance import record, report as RP
from kratos.compliance import status as ST
from kratos.compliance.facts import Facts, Source
from kratos.lifecycle.decide import Actor

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000.0
OWNER = Actor("owner", "cli")


def good_hardening() -> dict:
    """A hardened Ubuntu 24.04: every hardening check passes."""
    d = H.parse_output("")
    d.update(format="1", complete=True, os={"ID": "ubuntu", "ID_LIKE": "debian", "VERSION_ID": "24.04",
                                            "PRETTY_NAME": "Ubuntu 24.04.1 LTS"}, uid=0, virt="none", init="systemd")
    for key, ok, _w, _f, _n in C._SYSCTLS:
        d["sysctl"][key] = ok[0]
        d["sysctl_conf"][key] = ok[0]
    d["sysctl_conf_read"] = True
    for path, mode, users, groups, _stem, _o in C._PERMS:
        d["stat"][path] = {"mode": mode, "uid": 0, "gid": 0, "user": users[0], "group": groups[0], "type": "file"}
    d["stat"]["/etc/sudoers"] = {"mode": 0o440, "uid": 0, "gid": 0, "user": "root", "group": "root", "type": "file"}
    for point, _s in C._MOUNTS:
        d["mounts"][point] = {"fstype": "tmpfs", "options": sorted({"rw", *C._MOUNT_OPTS[point]})}
    d["login_defs"] = {"PASS_MAX_DAYS": "365", "PASS_MIN_DAYS": "1", "PASS_WARN_AGE": "7", "UMASK": "027",
                       "ENCRYPT_METHOD": "YESCRYPT"}
    d["pam"] = {
        "common-auth": {"state": "present", "lines": [
            {"type": "auth", "control": "required", "module": "pam_faillock.so", "args": ["preauth", "deny=5"]},
            {"type": "auth", "control": "[success=1,default=ignore]", "module": "pam_unix.so", "args": []}]},
        "common-password": {"state": "present", "lines": [
            {"type": "password", "control": "requisite", "module": "pam_pwquality.so", "args": ["minlen=14"]},
            {"type": "password", "control": "[success=1,default=ignore]", "module": "pam_unix.so",
             "args": ["yescrypt", "use_authtok"]}]}}
    d["time"] = {"NTPSynchronized": "yes"}
    for m in H.MODULES:
        d["modules"][m] = {"install": "false", "blacklisted": True, "loaded": False, "shipped": True}
    d["services"] = {"auditd": {"load": "loaded", "enabled": "enabled", "active": "active"},
                     "systemd-timesyncd": {"load": "loaded", "enabled": "enabled", "active": "active"}}
    d["audit"] = {"installed": True, "enabled": 2, "pid": 99, "rules": 30, "watched": list(C._IDENTITY)}
    d["mac"] = {"apparmor_enabled": True, "apparmor_profiles": 40, "apparmor_enforce": 30}
    d["journald"] = {"storage": "persistent", "var_log_journal": "yes"}
    d["sshd_state"] = "ok"
    d["sshd_match_blocks"] = 0
    d["sshd"] = {"permitrootlogin": "no", "passwordauthentication": "no", "permitemptypasswords": "no",
                 "maxauthtries": "4", "loglevel": "verbose", "ignorerhosts": "yes", "hostbasedauthentication": "no",
                 "permituserenvironment": "no", "usepam": "yes", "banner": "/etc/issue.net",
                 "clientaliveinterval": "15", "clientalivecountmax": "3", "logingracetime": "60",
                 "maxstartups": "10:30:60", "maxsessions": "10", "disableforwarding": "yes",
                 "gssapiauthentication": "no", "allowgroups": 1, "allowusers": 0, "denyusers": 0, "denygroups": 0,
                 "ciphers": "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
                 "macs": "hmac-sha2-512-etm@openssh.com", "kexalgorithms": "curve25519-sha256"}
    d["firewall"] = {"ufw_enabled": "yes", "ufw_input_policy": "DROP", "nft_read": "ok",
                     "nft_input_policies": ["drop"]}
    return d


def facts_of(h: dict | None = None, *, read_at: float = NOW - 60, via: str = "ssh", complete: bool = True,
             extra: dict | None = None) -> Facts:
    f = Facts("10.0.0.5")
    if h is not None:
        f.sources["hardening"] = Source("hardening", h, read_at, via, complete)
    base = {
        "inventory": Source("inventory", {"names": ["sudo", "aide", "openssh-server"]}, NOW - 60, "ssh", True),
        "persistence": Source("persistence", {"signals": []}, NOW - 60, "ssh", True),
        "packages": Source("packages", {"signals": [], "act_now_packages": [], "selector": "ubuntu:24.04"},
                           NOW - 60, "ssh", True),
        "privileged": Source("privileged", {"accounts": {"root": {"user": "root", "uid": 0}}}, NOW - 60, "", True),
        "config_audit": Source("config_audit", {"unattended_upgrades": {"status": "PASS"},
                                                "world_writable_etc": {"status": "PASS"},
                                                "firewall": {"status": "PASS"}}, NOW - 60, "ssh", True),
        "log_integrity": Source("log_integrity", {"seal": {"status": "ok"}}, NOW - 60, "ssh", True),
    }
    f.sources.update(base)
    f.sources.update(extra or {})
    return f


def run(f: Facts, **kw) -> dict[str, ST.CheckRun]:
    return {r.id: r for r in ST.run_checks(f, max_age_hours=24, now=NOW, **kw)}


# --------------------------------------------------------------------------- vendor
def test_vendored_mapping_is_ids_only_and_pinned():
    sys.path.insert(0, str(ROOT / "scripts" / "dev"))
    import build_compliance_vendor as B

    data = cac.vendored()
    B.assert_ids_only(data)                       # no string with a space (every CIS title has one), none > 100
    assert data["source"]["licence"] == "BSD-3-Clause" and len(data["source"]["commit"]) == 40
    src = (ROOT / "src/kratos/compliance/vendor/SOURCE.txt").read_text()
    assert data["source"]["commit"] in src and "BSD-3-Clause" in src and "non-commercial" in src
    assert (ROOT / "src/kratos/compliance/vendor/LICENSE.ComplianceAsCode").read_text().startswith("SPDX")
    assert set(data["products"]) >= {"ubuntu2204", "ubuntu2404", "debian12", "rhel9"}
    for p in data["products"].values():
        for c in p["controls"]:
            assert set(c) == {"id", "levels", "rules", "vars", "status"}       # no title, no notes


def test_no_cis_text_vendored_builder_refuses_and_drops_titles(tmp_path):
    sys.path.insert(0, str(ROOT / "scripts" / "dev"))
    import build_compliance_vendor as B

    with pytest.raises(B.VendorError):
        B._str("Ensure cramfs kernel module is not available", B.SECTION_RE, "x")
    raw = [{"id": "1.1.1.1", "title": "Ensure cramfs kernel module is not available (Automated)",
            "levels": ["l1_server"], "rules": ["kernel_module_cramfs_disabled", "var_x=5_minutes"],
            "status": "automated", "notes": "Long CIS prose here"}]
    out = B._controls(raw, "ubuntu2404")
    assert out == [{"id": "1.1.1.1", "levels": ["l1_server"], "rules": ["kernel_module_cramfs_disabled"],
                    "vars": {"var_x": "5_minutes"}, "status": "automated"}]
    text = B.render({"format": 1, "products": {"ubuntu2404": {"controls": out}}})
    assert "Ensure" not in text and "prose" not in text
    assert B.render({"format": 1, "products": {"ubuntu2404": {"controls": out}}}) == text     # deterministic
    with pytest.raises(B.VendorError):
        B.assert_ids_only({"x": [{"title": "Ensure something here"}]})


def test_iso_table_has_the_93_annex_a_ids_and_nis2_refs_are_real():
    ids = F.iso_ids()
    assert len(ids) == 93 and len(set(ids)) == 93
    themes = {t: sum(1 for c in F.ISO_CONTROLS if c.theme == t) for t in ("organisational", "people", "physical",
                                                                       "technological")}
    assert themes == {"organisational": 37, "people": 8, "physical": 14, "technological": 34}
    assert all(F.valid_nis2_ref(c.id) for c in F.NIS2_CONTROLS)
    assert not F.valid_nis2_ref("21(2)(k)") and not F.valid_nis2_ref("14") and not F.valid_nis2_ref("6.11")
    assert all(len(c.text) < 110 for c in F.ISO_CONTROLS)        # Kratos's one line, not the standard's text


def test_mapping_integrity_every_check_maps_to_real_ids():
    rules = cac.all_rule_ids()
    for chk in C.CHECKS:
        assert set(chk.cac_rules) <= rules, chk.id
        assert set(chk.iso) <= set(F.CONTROLS["iso27001"]), chk.id
        assert all(F.valid_nis2_ref(r) and r in F.CONTROLS["nis2"] for r in chk.nis2), chk.id
        assert chk.fix and chk.text
    mapped_iso = {i for c in C.CHECKS for i in c.iso}
    mapped_nis = {i for c in C.CHECKS for i in c.nis2}
    assert all(c.id in mapped_iso or c.person for c in F.ISO_CONTROLS)         # every control has a status rule
    assert all(c.id in mapped_nis or c.person for c in F.NIS2_CONTROLS)
    for c in F.ISO_CONTROLS:                                                    # 5.x/6.x/7.x: always a person
        if c.theme != "technological":
            assert c.person, c.id


# --------------------------------------------------------------------------- products
@pytest.mark.parametrize("os_facts,pid,note", [
    ({"ID": "ubuntu", "VERSION_ID": "24.04"}, "ubuntu2404", ""),
    ({"ID": "ubuntu", "VERSION_ID": "22.04"}, "ubuntu2204", ""),
    ({"ID": "debian", "VERSION_ID": "12"}, "debian12", ""),
    ({"ID": "rocky", "ID_LIKE": "rhel centos fedora", "VERSION_ID": "9.6"}, "rhel9", "Rocky Linux uses the RHEL 9"),
    ({"ID": "almalinux", "ID_LIKE": "rhel", "VERSION_ID": "9.4"}, "rhel9", "AlmaLinux uses the RHEL 9"),
])
def test_rhel_rebuilds_mapping(os_facts, pid, note):
    p = cac.detect(os_facts)
    assert p.id == pid and note in p.note


def test_unknown_product_no_cis():
    for os_facts in ({"ID": "alpine", "VERSION_ID": "3.22.0", "PRETTY_NAME": "Alpine Linux v3.22"},
                     {"ID": "ubuntu", "VERSION_ID": "20.04"}, {}):
        p = cac.detect(os_facts)
        assert p.id is None and "no CIS mapping for this system" in p.note
    h = good_hardening()
    h["os"] = {"ID": "alpine", "VERSION_ID": "3.22.0"}
    runs = ST.run_checks(facts_of(h), max_age_hours=24, now=NOW)
    assert ST.controls_for("cis", runs, product=cac.detect(h["os"])) == []
    iso = {r.control: r for r in ST.controls_for("iso27001", runs)}
    assert iso["8.17"].status == "pass"                         # ISO rows still come from Kratos's checks


# --------------------------------------------------------------------------- checks and statuses
def test_a_hardened_machine_passes_every_check():
    r = run(facts_of(good_hardening()))
    bad = {k: (v.status, v.found, v.reason) for k, v in r.items() if v.status not in ("pass",)}
    assert bad == {"firewall.nft_default_deny": ("na", "ufw is this machine's firewall",
                                                 "this machine's firewall is ufw, not nftables directly")}
    cis = ST.controls_for("cis", list(r.values()), product=cac.Product("ubuntu2404", ""))
    st = {c.control: c.status for c in cis}
    assert st["1.1.1.1"] == "pass" and st["5.1.20"] == "pass"
    assert st["3.3.5"] == "pass"                                # every rule of the section checked and passing


def test_six_statuses():
    h = good_hardening()
    h["sysctl"]["kernel.randomize_va_space"] = 0
    runs = list(run(facts_of(h)).values())
    cis = {c.control: c for c in ST.controls_for("cis", runs, product=cac.Product("ubuntu2404", ""))}
    assert cis["1.5.1"].status == "fail" and "sysctl.kernel.randomize_va_space" in cis["1.5.1"].reason
    assert cis["1.1.1.1"].status == "pass"
    assert cis["5.4.1.1"].status == "partial"                   # PASS_MAX_DAYS checked; existing users' expiry not
    assert "accounts_password_set_max_life_existing" in cis["5.4.1.1"].uncovered_rules
    assert cis["1.2.1.1"].status in ("not_checked", "needs_person")
    iso = {c.control: c for c in ST.controls_for("iso27001", runs)}
    assert iso["5.1"].status == "needs_person" and iso["5.1"].person
    rows = ST.controls_for("iso27001", runs)
    ST.apply_na(rows, {("iso27001", "8.9"): {"reason": "lab", "actor": "o", "expires_at": "2027-01-01"}})
    r89 = next(r for r in rows if r.control == "8.9")
    assert r89.status == "not_applicable" and r89.computed == "fail"


def test_stale_is_not_pass():
    r = run(facts_of(good_hardening(), read_at=NOW - 30 * 3600))
    assert all(v.status == "unknown" and v.stale for k, v in r.items() if C.BY_ID[k].facts[0] == "hardening")
    assert "last read 30 h ago" in r["sysctl.kernel.randomize_va_space"].reason
    cis = ST.controls_for("cis", list(r.values()), product=cac.Product("ubuntu2404", ""))
    assert {c.control: c.status for c in cis}["1.1.1.1"] == "not_checked"


def test_incomplete_read_never_passes():
    r = run(facts_of(good_hardening(), complete=False))
    assert r["sysctl.kernel.randomize_va_space"].status == "unknown"
    assert "incomplete" in r["sysctl.kernel.randomize_va_space"].reason


def test_partial_over_ssh():
    h = good_hardening()
    h["audit"] = {}
    h["gaps"] = {"audit": "unreadable"}
    r = run(facts_of(h))
    assert r["auditd.running"].status == "unknown" and "sub-agent" in r["auditd.running"].reason
    iso = {c.control: c for c in ST.controls_for("iso27001", list(r.values()))}
    assert iso["8.15"].status == "partial" and "auditd.running" in iso["8.15"].reason


def test_sshd_t_unavailable():
    h = good_hardening()
    h["sshd_state"] = "unavailable"
    h["sshd"] = {}
    r = run(facts_of(h))
    for cid in ("sshd.root_login", "sshd.maxstartups", "sshd.ciphers"):
        assert r[cid].status == "unknown" and "/usr/sbin/sshd -T" in r[cid].reason


def test_sshd_match_note():
    h = good_hardening()
    h["sshd_match_blocks"] = 2
    r = run(facts_of(h))
    assert r["sshd.root_login"].status == "pass" and "Match blocks present" in r["sshd.root_login"].note


def test_firewall_backends():
    def fw(**v):
        h = good_hardening()
        h["firewall"] = v
        return run(facts_of(h))["firewall.default_deny"]

    assert fw(ufw_enabled="no", nft_read="ok", nft_input_policies=["drop"]).status == "pass"
    assert fw(ufw_enabled="no", nft_read="ok", nft_input_policies=["accept"]).status == "fail"
    assert fw(ufw_enabled="yes", ufw_input_policy="DROP").status == "pass"
    assert fw(iptables_input="DROP").status == "pass"
    assert fw(iptables_input="ACCEPT").status == "fail"
    assert fw(nft_read="unreadable", iptables_read="unreadable").status == "unknown"
    h = good_hardening()
    h["firewall"] = {}
    h["services"]["firewalld"] = {"load": "loaded", "enabled": "enabled", "active": "active"}
    assert run(facts_of(h))["firewall.default_deny"].status == "pass"
    h["firewall"] = {"firewalld_zone": "trusted"}
    assert run(facts_of(h))["firewall.default_deny"].status == "fail"


def test_openrc_services():
    h = good_hardening()
    h["init"] = "openrc"
    h["os"] = {"ID": "alpine", "VERSION_ID": "3.22.0"}
    h["services"] = {"cups": {"load": "loaded", "enabled": "enabled", "active": "active"},
                     "chronyd": {"load": "loaded", "enabled": "enabled", "active": "active"}}
    h["time"] = {"chrony_leap": "Normal"}
    r = run(facts_of(h))
    assert r["service.cups.off"].status == "fail" and r["time.synchronised"].status == "pass"
    assert r["journald.persistent"].status == "na"
    assert "pam.no_nullok" in r and r["pam.no_nullok"].status == "na"


def test_mount_absent():
    h = good_hardening()
    h["mounts"]["/tmp"] = None
    r = run(facts_of(h))
    assert r["mount./tmp.nodev"].status == "na" and "not a separate mount" in r["mount./tmp.nodev"].reason
    cis = {c.control: c for c in ST.controls_for("cis", list(r.values()), product=cac.Product("ubuntu2404", ""))}
    assert cis["1.1.2.1.2"].status == "not_checked"            # never a silent pass


def test_modprobe_shapes():
    def mod(**m):
        h = good_hardening()
        h["modules"]["cramfs"] = {"install": "none", "blacklisted": False, "loaded": False, "shipped": True, **m}
        return run(facts_of(h))["module.cramfs"]

    assert mod(install="false").status == "pass"
    assert mod(install="true").status == "pass"
    assert mod(shipped=False).status == "pass"
    assert mod(blacklisted=True).status == "fail"                # blacklist alone doesn't stop a load
    assert mod(install="false", loaded=True).status == "fail"
    assert mod(shipped=None).status == "unknown"
    assert mod(install="other").status == "fail"
    h = good_hardening()
    h["virt"] = "container"
    assert run(facts_of(h))["module.cramfs"].status == "na"


def test_hostile_fact_values():
    from tests.test_compliance_hardening_read import H as HR

    raw = ("HFACTS\t1\nOS\tID=ubuntu\nOS\tVERSION_ID=24.04\nSYSCTL\tkernel.randomize_va_space\t2\x1b[31m\n"
           "SSHDSTATE\tok\nSSHD\tpermitrootlogin\tno‮\nLDEF\tUMASK\t$(id)\nEND\n")
    h = HR.parse_output(raw)
    r = run(facts_of(h))
    assert r["sysctl.kernel.randomize_va_space"].status == "unknown"
    assert "unexpected" in r["sysctl.kernel.randomize_va_space"].reason
    assert r["sshd.root_login"].status == "unknown" and r["logindefs.umask"].status == "unknown"


def test_transport_disagreement():
    old = good_hardening()
    old["sysctl"]["kernel.randomize_va_space"] = 0
    f = facts_of(good_hardening(), read_at=NOW - 60, via="subagent")
    f.other_hardening = Source("hardening", old, NOW - 7200, "ssh", True)
    r = run(f)["sysctl.kernel.randomize_va_space"]
    assert r.status == "pass" and r.other_read["via"] == "ssh" and r.other_read["status"] == "fail"


def test_a_check_crash_is_unknown_never_pass(monkeypatch):
    h = good_hardening()
    h["stat"]["/etc/passwd"] = {"mode": "not-a-number"}
    assert run(facts_of(h))["perm./etc/passwd"].status == "unknown"


def test_group_rollup_unread():
    assert ST.group_status(["pass", "pass"]) == "pass"
    assert ST.group_status(["pass", "not_checked"]) == "partial"
    assert ST.group_status(["not_checked", "not_checked"]) == "not_checked"
    assert ST.group_status(["pass", "fail"]) == "fail"
    sec = {"status": "read", "product": "ubuntu2404", "controls": [{"framework": "iso27001", "control": "8.17",
                                                                   "text": "x", "status": "pass"}]}
    unread = {"status": "not_checked", "machine": "b", "controls": []}
    roll = RP.rollup([sec, unread])
    assert roll[0]["status"] != "pass" and roll[0]["counts"] == {"pass": 1, "not_checked": 1}


# --------------------------------------------------------------------------- COMP-001
def test_comp001_entities_and_severity():
    h = good_hardening()
    h["sysctl"]["kernel.randomize_va_space"] = 0
    h["sshd"]["permitrootlogin"] = "yes"
    runs = list(run(facts_of(h)).values())
    low = J.judge(runs, target="10.0.0.5", internet=False)
    assert len(low) == 1 and low[0]["severity"] == "low"
    assert low[0]["entities"] == ["sshd.root_login", "sysctl.kernel.randomize_va_space"]
    assert low[0]["subject"] == "10.0.0.5" and low[0]["title"] == "2 hardening checks fail on this machine"
    med = J.judge(runs, target="10.0.0.5", internet=True, exposure_why="sshd listens on 0.0.0.0")
    assert med[0]["severity"] == "medium" and "exposed to the internet" in " ".join(med[0]["evidence"])
    h["sshd"]["permitrootlogin"] = "no"
    runs = list(run(facts_of(h)).values())
    assert J.judge(runs, target="10.0.0.5", internet=True)[0]["severity"] == "low"     # not a remote-access check


def test_no_duplicate_with_existing_findings():
    h = good_hardening()
    h["sshd"]["passwordauthentication"] = "yes"
    f = facts_of(h, extra={"persistence": Source("persistence", {"signals": [{"rule": "PERSIST-003"}]}, NOW - 60,
                                                 "ssh", True)})
    runs = ST.run_checks(f, max_age_hours=24, now=NOW, open_rules={"CORR-SSH-001"})
    byid = {r.id: r for r in runs}
    assert byid["sshd.password_auth"].linked == "CORR-SSH-001"
    assert byid["persistence.no_unowned_setuid"].linked == "PERSIST-003"
    assert J.judge(runs, target="m", internet=True) == []         # both already findings: nothing to add
    runs = ST.run_checks(f, max_age_hours=24, now=NOW, open_rules=set())
    assert J.judge(runs, target="m", internet=False)[0]["entities"] == ["sshd.password_auth"]


def test_report_only_checks_never_in_comp001():
    f = facts_of(good_hardening(), extra={"log_integrity": Source("log_integrity", {"seal": None}, NOW - 60, "ssh",
                                                                  True)})
    runs = ST.run_checks(f, max_age_hours=24, now=NOW)
    assert {r.id: r for r in runs}["kratos.log_sealing"].status == "fail"
    assert J.judge(runs, target="m", internet=False) == []


def test_comp001_is_a_posture_condition_with_a_verifier():
    from kratos.attack import mapping
    from kratos.lifecycle import rules
    from kratos.triage import registry

    assert rules.RULES["COMP-001"].kind == "condition" and rules.RULES["COMP-001"].inputs == ("compliance",)
    assert isinstance(mapping.RULE_ATTACK["COMP-001"], mapping.Posture)
    v = registry.verifier_for("COMP-001")
    assert v is not None and "hardening" in getattr(v, "label", "")


def test_run_writes_result_and_finding(tmp_path):
    h = good_hardening()
    h["stat"]["/etc/crontab"]["mode"] = 0o666
    doc = record.run(tmp_path, "10.0.0.5", fetch=lambda: dict(h, via="ssh"), now=time.time())
    assert doc["complete"] and doc["product"] == "ubuntu2404"
    assert doc["signals"][0]["entities"] == ["perm./etc/crontab"]
    assert Path(doc["file"]).exists() and record.hardening_paths(tmp_path, "10.0.0.5")
    from kratos.adapters import findings_engine as FE
    from kratos.compliance import findings as CF

    built = CF.build(CF.load_recent(Path(doc["file"])))
    assert [f.id for f in built] == ["COMP-001"] and built[0].severity == "low"
    assert FE.find_latest_inputs(tmp_path, "10.0.0.5")["compliance"] == Path(doc["file"])
    from kratos.compliance import store

    run_row = store.latest_run(tmp_path, "10.0.0.5")
    assert run_row["mapping_version"] == cac.mapping_version()          # stored per run
    with store.opened(tmp_path) as c:
        assert c.execute("SELECT COUNT(*) FROM compliance_results WHERE run_id = ?",
                         (run_row["run_id"],)).fetchone()[0] > 300


def test_failed_read_is_not_checked_never_pass(tmp_path):
    class R:
        ok = False
        stderr = "ssh: connect to host 10.0.0.5 port 22: Connection timed out"

    doc = record.run(tmp_path, "10.0.0.5", fetch=lambda: R(), now=time.time())
    assert not doc["complete"] and "timed out" in doc["coverage_gaps"][0]
    assert all(c["status"] != "pass" for c in doc["checks"] if C.BY_ID[c["id"]].facts[0] == "hardening")
    assert doc["signals"] == []


def test_mapping_version_stored_per_run(tmp_path):
    from kratos.compliance import store

    h = good_hardening()
    record.run(tmp_path, "m1", fetch=lambda: dict(h, via="ssh"), now=time.time())
    with store.opened(tmp_path) as c:
        c.execute("UPDATE compliance_runs SET mapping_version = 'ComplianceAsCode oldcommit'")
        c.commit()
    record.run(tmp_path, "m1", fetch=lambda: dict(h, via="ssh"), now=time.time() + 1)
    versions = [r["mapping_version"] for r in store.runs(tmp_path, "m1")]
    assert versions == [cac.mapping_version(), "ComplianceAsCode oldcommit"]


# --------------------------------------------------------------------------- people's decisions
def test_people_only_owner_and_na(tmp_path, monkeypatch):
    from kratos import settings_store

    for actor in (Actor("bot", "mcp"), Actor("bot", "serve", credential="token:x"), Actor("s", "schedule")):
        with pytest.raises(O.ComplianceError):
            O.set_owner(tmp_path, actor, "iso27001", "8.9", "all", "alice")
        with pytest.raises(O.ComplianceError):
            O.set_na(tmp_path, actor, "iso27001", "8.9", "all", "lab only", 30)
    token = settings_store._IN_TOOL.set("correlate_findings")
    try:
        with pytest.raises(O.ComplianceError, match="agent tools"):
            O.set_owner(tmp_path, OWNER, "iso27001", "8.9", "all", "alice")
    finally:
        settings_store._IN_TOOL.reset(token)
    with pytest.raises(O.ComplianceError):
        O.set_owner(tmp_path, OWNER, "iso27001", "9.9", "all", "alice")       # no such control
    with pytest.raises(O.ComplianceError):
        O.set_na(tmp_path, OWNER, "cis", "1.1.1.1", "all", "", 30)            # reason required
    with pytest.raises(O.ComplianceError):
        O.set_na(tmp_path, OWNER, "cis", "1.1.1.1", "all", "why", 400)        # longer than na_max_days


def test_na_expiry(tmp_path):
    from kratos.compliance import store

    O.set_na(tmp_path, OWNER, "iso27001", "8.17", "machine:10.0.0.5", "clock is the host's", 1)
    assert ("iso27001", "8.17") in O.na_for(tmp_path, "iso27001", "10.0.0.5")
    later = time.time() + 2 * 86400
    assert O.na_for(tmp_path, "iso27001", "10.0.0.5", now=later) == {}
    O.na_for(tmp_path, "iso27001", "10.0.0.5", now=later)                     # recorded once
    kinds = [e["kind"] for e in store.events(tmp_path)]
    assert kinds.count("na_expired") == 1 and "na_set" in kinds


def test_owner_disabled_user(tmp_path):
    from kratos.authz import users

    users.add_user(tmp_path, "alice", "viewer", OWNER)
    O.set_owner(tmp_path, OWNER, "iso27001", "8.9", "all", "alice", due="2027-03-01")
    assert O.owners_for(tmp_path, "iso27001", "m")["8.9"].label() == "alice, due 2027-03-01"
    users.set_disabled(tmp_path, "alice", True, OWNER)
    assert O.owners_for(tmp_path, "iso27001", "m")["8.9"].label() == "alice (no longer a user), due 2027-03-01"
    O.set_owner(tmp_path, OWNER, "iso27001", "8.9", "machine:m", "Bob from ops")
    assert O.owners_for(tmp_path, "iso27001", "m")["8.9"].name == "Bob from ops"          # most specific wins


def test_repair_keeps_owners(tmp_path):
    """Owners, N/A and results follow the machine's address (target_key), not a sub-agent id."""
    O.set_owner(tmp_path, OWNER, "cis", "5.1.20", "machine:ubuntu@10.0.0.5", "alice")
    O.set_na(tmp_path, OWNER, "cis", "3.3.1", "machine:10.0.0.5", "a router", 30)
    assert O.owners_for(tmp_path, "cis", "10.0.0.5")["5.1.20"].name == "alice"
    assert ("cis", "3.3.1") in O.na_for(tmp_path, "cis", "root@10.0.0.5")


def test_level_two_is_a_per_machine_setting(tmp_path):
    assert O.level_for(tmp_path, "m") == "l1_server"
    O.set_level(tmp_path, OWNER, "m", "2")
    assert O.level_for(tmp_path, "m") == "l2_server" and O.level_for(tmp_path, "other") == "l1_server"
    runs = list(run(facts_of(good_hardening())).values())
    l1 = {c.control for c in ST.controls_for("cis", runs, product=cac.Product("ubuntu2404", ""))}
    l2 = {c.control for c in ST.controls_for("cis", runs, product=cac.Product("ubuntu2404", ""), level="l2_server")}
    assert l1 < l2 and "1.1.1.8" in l2 - l1                     # udf is Level 2


# --------------------------------------------------------------------------- reports
@pytest.fixture
def two_machines(tmp_path):
    h = good_hardening()
    record.run(tmp_path, "10.0.0.5", fetch=lambda: dict(h, via="ssh"), now=time.time())
    bad = copy.deepcopy(h)
    bad["stat"]["/etc/crontab"]["mode"] = 0o666
    bad["os"]["PRETTY_NAME"] = "=cmd|' /C calc'!A0"
    record.run(tmp_path, "10.0.0.6", fetch=lambda: dict(bad, via="ssh"), now=time.time())
    return tmp_path


def test_report_formats(two_machines):
    doc = RP.build(two_machines, "cis", ["10.0.0.5", "10.0.0.6", "10.0.0.7"], label="@lab")
    assert doc["machines"][2]["status"] == "not_checked" and doc["rollup"]
    md = RP.render(doc, "md")
    assert "not a certification" in md and "2.4.1.2" in md and "@lab" in md.replace("\\@", "@")
    js = json.loads(RP.render(doc, "json"))
    assert js["mapping"]["compliance_as_code_commit"] == cac.source()["commit"]
    nis = RP.build(two_machines, "nis2", ["10.0.0.5"])
    assert "2024/2690 binds" in RP.render(nis, "md")


def test_csv_injection_safe(two_machines):
    doc = RP.build(two_machines, "iso27001", ["10.0.0.6"])
    doc["machines"][0]["controls"][0]["owner"] = "=HYPERLINK(\"http://x\")"
    text = RP.render(doc, "csv")
    for cell in (c for line in text.splitlines()[1:] for c in line.split(",")):
        assert not cell.startswith(("=", "+", "-", "@")), cell


def test_markdown_escapes_machine_text(two_machines):
    doc = RP.build(two_machines, "iso27001", ["10.0.0.6"])
    doc["machines"][0]["os"] = "![x](http://evil/a.png) <script>|"
    md = RP.render(doc, "md")
    assert "![x](" not in md and "<script>" not in md


def test_scope_in_rollup(two_machines, monkeypatch):
    from kratos.authz import users
    from kratos.fleet import groups as G

    users.add_user(two_machines, "vic", "viewer", OWNER, scopes=["10.0.0.5"])
    G.create_group(two_machines, "lab", OWNER, members=["10.0.0.5", "10.0.0.6"])
    vic = users.find(two_machines, "vic")
    actor = Actor("vic", "tui", user_id=vic.user_id)
    machines, outside, label = RP.resolve_machines(two_machines, actor, group="lab")
    assert machines == ["10.0.0.5"] and outside == 1
    doc = RP.build(two_machines, "iso27001", machines, outside_scope=outside, label=label)
    md = RP.render(doc, "md")
    assert "10.0.0.6" not in md and "1 machine(s) in this group are outside your access" in md
    with pytest.raises(RP.ReportError):
        RP.resolve_machines(two_machines, actor, machine="10.0.0.6")


# --------------------------------------------------------------------------- found in the lab
def test_sshd_options_not_built_in():
    """Alpine's OpenSSH has no PAM or GSSAPI: sshd -T doesn't list them."""
    h = good_hardening()
    del h["sshd"]["usepam"], h["sshd"]["gssapiauthentication"]
    r = run(facts_of(h))
    assert r["sshd.use_pam"].status == "na" and "no usepam option" in r["sshd.use_pam"].reason
    assert r["sshd.gssapi"].status == "pass"


def test_reboot_check_trusts_kernel_facts_without_vulnerability_data():
    f = facts_of(good_hardening(), extra={"packages": Source(
        "packages", {"signals": [], "act_now_packages": [], "selector": "rocky:9"}, NOW - 60, "ssh", False)})
    r = run(f)
    assert r["packages.no_pending_reboot"].status == "pass"
    assert r["packages.no_kev"].status == "unknown"            # no vulnerability matching: never a pass


def test_alpine_without_gshadow_or_login_defs_checks():
    h = good_hardening()
    h["os"] = {"ID": "alpine", "VERSION_ID": "3.22.0"}
    h["stat"]["/etc/gshadow"] = {"absent": "missing"}
    r = run(facts_of(h))
    assert r["perm./etc/gshadow"].status == "na"
    assert "logindefs.pass_max_days" not in r                  # login.defs checks are Debian/RHEL only


def test_privileged_history_gaps_dont_block_the_uid0_check(tmp_path):
    from kratos.compliance.facts import load
    from kratos.utils.timeutil import epoch_to_utc_iso

    ctx = tmp_path / "context"
    ctx.mkdir()
    (ctx / "privileged_accounts_20261111_120000_000000.json").write_text(json.dumps({
        "status": "ok", "target": "ubuntu@10.0.0.5", "checked_at": epoch_to_utc_iso(time.time()),
        "accounts": {"root": {"user": "root", "uid": 0}},
        "evidence_gaps": ["the journal starts 3 days ago, shorter than the 30-day window"]}))
    f = load(tmp_path, "10.0.0.5", hardening=[])
    assert f.get("privileged") is not None and f.get("privileged").complete
    f.sources["hardening"] = Source("hardening", good_hardening(), time.time(), "ssh", True)
    r = {x.id: x for x in ST.run_checks(f, max_age_hours=24)}
    assert r["accounts.uid0_only_root"].status == "pass"


def test_comp001_opens_is_mitigated_and_a_new_failing_check_reopens(tmp_path, monkeypatch):
    """Through the real findings report: a failing check opens COMP-001; a fresh, complete
    read with nothing failing mitigates it; after a person accepts it, a NEW failing check
    (a new entity) brings it back."""
    from kratos.adapters import findings_engine as FE
    from kratos.lifecycle import decide as D
    from kratos.lifecycle import query
    from kratos.run_context import run_scope

    monkeypatch.setattr("kratos.kratos_config.get_active_target", lambda: "10.0.0.5")

    def cycle(h):
        with run_scope("cli", target="10.0.0.5"):
            record.run(tmp_path, "10.0.0.5", fetch=lambda: dict(h, via="ssh"), now=time.time())
            FE.write_findings_report(tmp_path)
        return {r["rule_id"]: r for r in query.list_findings(tmp_path, target="10.0.0.5", state="all")}

    bad = good_hardening()
    bad["stat"]["/etc/crontab"]["mode"] = 0o666
    assert cycle(bad)["COMP-001"]["state"] == "open"
    assert cycle(good_hardening())["COMP-001"]["state"] == "mitigated"
    row = cycle(bad)["COMP-001"]
    assert row["state"] == "open"
    D.accept_risk(row["finding_key"], actor=OWNER, reason="lab box", owner=None,
                  expires_at=D.expiry_from_days(30), data_dir=tmp_path)
    assert cycle(bad)["COMP-001"]["state"] == "risk_accepted"
    worse = copy.deepcopy(bad)
    worse["sshd"]["permitrootlogin"] = "yes"
    assert cycle(worse)["COMP-001"]["state"] == "open"          # a newly failing check reopens the decision


def test_sysctl_must_be_set_in_a_file_too():
    h = good_hardening()
    del h["sysctl_conf"]["kernel.randomize_va_space"]
    r = run(facts_of(h))["sysctl.kernel.randomize_va_space"]
    assert r.status == "fail" and "no sysctl file sets it" in r.found
    h["sysctl_conf"]["kernel.randomize_va_space"] = 0
    assert "sets it to 0" in run(facts_of(h))["sysctl.kernel.randomize_va_space"].found
    h["sysctl_conf_read"] = False
    assert run(facts_of(h))["sysctl.kernel.randomize_va_space"].status == "unknown"


def test_mode_owner_and_group_are_separate_rules():
    h = good_hardening()
    h["stat"]["/etc/crontab"]["mode"] = 0o644
    r = run(facts_of(h))
    assert r["perm./etc/crontab"].status == "fail"
    assert r["owner./etc/crontab"].status == "pass" and r["group./etc/crontab"].status == "pass"


def test_rollup_keeps_needs_person_for_an_unread_machine():
    read = {"status": "read", "product": None, "controls": [
        {"framework": "iso27001", "control": "5.1", "text": "x", "status": "needs_person", "checks": []},
        {"framework": "iso27001", "control": "8.17", "text": "y", "status": "pass", "checks": ["time.synchronised"]}]}
    roll = {r["control"]: r for r in RP.rollup([read, {"status": "not_checked", "controls": []}])}
    assert roll["5.1"]["status"] == "needs_person" and roll["5.1"]["counts"] == {"needs_person": 2}
    assert roll["8.17"]["status"] == "partial" and roll["8.17"]["counts"] == {"pass": 1, "not_checked": 1}


def test_unchanged_results_are_stored_once(tmp_path):
    from kratos.compliance import store

    h = good_hardening()
    for i in range(3):
        record.run(tmp_path, "m1", fetch=lambda: dict(h, via="ssh"), now=time.time() + i)
    runs = store.runs(tmp_path, "m1")
    assert len(runs) == 3 and len({r["results_run"] for r in runs}) == 1
    with store.opened(tmp_path) as c:
        assert c.execute("SELECT COUNT(DISTINCT run_id) FROM compliance_results").fetchone()[0] == 1
    assert len(store.results_of(tmp_path, runs[0]["run_id"])) > 300
    bad = copy.deepcopy(h)
    bad["stat"]["/etc/crontab"]["mode"] = 0o666
    record.run(tmp_path, "m1", fetch=lambda: dict(bad, via="ssh"), now=time.time() + 9)
    latest = store.runs(tmp_path, "m1")[0]
    assert latest["results_run"] == latest["run_id"]
    assert any(r["control_id"] == "2.4.1.2" and r["status"] == "fail" for r in store.results_of(tmp_path, latest["run_id"]))
