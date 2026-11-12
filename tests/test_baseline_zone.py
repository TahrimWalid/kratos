"""E.3: the machine's time zone for sign-in hours, from the SSH config audit's appended row or
the saved setup probe, when the measurement didn't read it (kratos.baseline.zone)."""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timedelta

import pytest

from _baseline_history import END, add_logins, machine, run, write
from kratos.baseline import zone as Z


def _no_measured_zone(data):
    for f in (data / "logs").glob("auth_stats_*.json"):
        f.unlink()


def _audit(data, target, zone=None, *, rows=(), at=None):
    from kratos.adapters import ssh_guessing

    return ssh_guessing.save_snapshot(data, target, [{"check": "ssh_root_login", "status": "PASS", "detail": "no"},
                                                     *rows], via="ssh", zone=zone, now=at)


def _deploy_at_eight(zone: str):
    """A journald-only machine (no zone in its sign-in measurement) where deploy signs in at 08:10
    local time every weekday."""
    m = machine(0, zone=zone)
    for day in range(21):
        local = (END.astimezone(m.zone) - timedelta(days=21 - day)).replace(hour=8, minute=10, second=0, microsecond=0)
        if local.weekday() < 5:
            for k in range(3):
                m.logins.append(((local + timedelta(minutes=k)).timestamp(), "deploy", "10.20.0.5", "publickey"))
    return m


def _hours(data, subject="deploy"):
    con = sqlite3.connect(data / "kratos.db")
    return {r[0] for r in con.execute("SELECT key FROM baseline_entries WHERE dim = 'login_time' AND subject = ? AND "
                                      "generation = (SELECT MAX(generation) FROM baseline_profiles WHERE "
                                      "dim = 'login_time')", (subject,))}


# ---------------------------------------------------------------- the one parser
@pytest.mark.parametrize("detail, want", [
    ("Target system timezone: Europe/Helsinki (journald log timestamps are stored as absolute UTC regardless)",
     "Europe/Helsinki"),
    ("Box timezone: America/New_York (journald timestamps are absolute UTC regardless)", "America/New_York"),
    ("Target system timezone: Etc/UTC (journald ...)", "Etc/UTC"),
    ("Box timezone: unknown (journald timestamps are absolute UTC regardless)", None),
    ("Target system timezone:  (journald ...)", None),
    ("Box timezone: $(reboot) (x)", None),                      # text from the machine never becomes a zone
    ("Box timezone: Not/AZone (x)", None),
    ("something else entirely", None),
])
def test_both_wordings_parse(detail, want):
    assert Z.parse_row(detail) == want


# ---------------------------------------------------------------- where the zone comes from
def test_journald_machine_with_a_config_audit_zone_learns_in_that_zone(tmp_path):
    m = _deploy_at_eight("Europe/Helsinki")
    data = write(tmp_path / "home", [m])
    _no_measured_zone(data)
    _audit(data, m.target, "Europe/Helsinki")
    doc = run(data, m.target)
    assert doc["zone"] == "Europe/Helsinki" and doc["zone_source"] == "config_audit"
    assert _hours(data) == {"08 weekday"}                       # machine time, across the October DST change
    assert "zone_note" not in doc["dims"]["login_time"]


def test_unknown_falls_back_to_utc_with_the_label(tmp_path):
    m = _deploy_at_eight("Europe/Helsinki")
    data = write(tmp_path / "home", [m])
    _no_measured_zone(data)
    _audit(data, m.target, None, rows=[{"check": "target_timezone", "status": "INFO",
                                        "detail": "Target system timezone: unknown (journald ...)"}])
    doc = run(data, m.target)
    assert doc["zone"] == Z.ASSUMED_UTC and doc["zone_source"] == "assumed"
    assert "hours in UTC" in doc["dims"]["login_time"]["zone_note"]


def test_the_measurement_comes_first_then_the_config_audit_then_the_probe(tmp_path):
    from kratos.logsources import setup_probe

    m = machine(0)
    data = write(tmp_path / "home", [m], days=1)
    assert Z.for_hours(data, m.target).source == "measurement"           # the generator's measured zone
    _no_measured_zone(data)
    assert Z.for_hours(data, m.target).assumed
    setup_probe.finish_rows([{"check": "target_timezone", "status": "INFO",
                              "detail": "Box timezone: Asia/Tokyo (journald timestamps are absolute UTC regardless)"}],
                            data, m.target)
    z = Z.for_hours(data, m.target)
    assert (z.name, z.source) == ("Asia/Tokyo", "setup_probe")
    _audit(data, m.target, "Europe/Berlin")
    assert Z.for_hours(data, m.target).name == "Europe/Berlin"           # the config audit before the probe


def test_a_zone_change_in_a_later_snapshot_starts_a_new_generation(tmp_path):
    m = _deploy_at_eight("Europe/Helsinki")
    data = write(tmp_path / "home", [m])
    _no_measured_zone(data)
    _audit(data, m.target, "Europe/Helsinki", at=END.timestamp() - 7200)
    first = run(data, m.target)
    assert first["dims"]["login_time"]["generation"] == 1
    taken = END.timestamp() + 1800
    time.sleep(0.01)
    _audit(data, m.target, "America/New_York", at=taken)
    add_logins(data, m.target, [(END.timestamp() + 3600, "deploy", "10.20.0.5", "publickey")])
    doc = run(data, m.target, now=END.timestamp() + 5 * 3600)
    s = doc["dims"]["login_time"]
    assert s["generation"] == 2 and not [d for d in doc["deviations"] if d["rule"] == "BASE-002"]
    con = sqlite3.connect(data / "kratos.db")
    started = con.execute("SELECT started_at FROM baseline_profiles WHERE dim = 'login_time' AND generation = 2"
                          ).fetchone()[0]
    assert started == pytest.approx(taken)                                # dated from the snapshot, not the run
    assert any("changed from Europe/Helsinki to America/New_York" in n for n in doc["notes"])


def test_assumed_utc_then_a_real_zone_starts_a_new_generation_but_real_utc_does_not(tmp_path):
    m = _deploy_at_eight("Europe/Helsinki")
    data = write(tmp_path / "home", [m])
    _no_measured_zone(data)
    assert run(data, m.target)["zone"] == Z.ASSUMED_UTC
    _audit(data, m.target, "Etc/UTC")
    doc = run(data, m.target, now=END.timestamp() + 60)
    assert doc["dims"]["login_time"]["generation"] == 1 and doc["zone"] == "Etc/UTC"   # UTC was right
    time.sleep(0.01)
    _audit(data, m.target, "Europe/Helsinki")
    doc = run(data, m.target, now=END.timestamp() + 120)
    assert doc["dims"]["login_time"]["generation"] == 2
    assert any("changed from Etc/UTC to Europe/Helsinki" in n for n in doc["notes"])


def test_assumed_utc_then_a_real_zone_relearns_in_machine_time(tmp_path):
    m = _deploy_at_eight("Europe/Helsinki")
    data = write(tmp_path / "home", [m])
    _no_measured_zone(data)
    assert run(data, m.target)["zone"] == Z.ASSUMED_UTC
    _audit(data, m.target, "Europe/Helsinki")
    doc = run(data, m.target, now=END.timestamp() + 60)
    assert doc["dims"]["login_time"]["generation"] == 2 and doc["zone"] == "Europe/Helsinki"
    assert any("time zone is now known (Europe/Helsinki)" in n for n in doc["notes"])


# ---------------------------------------------------------------- the two reads
def test_ssh_config_audit_appends_the_zone_line_and_keeps_it_out_of_the_rows(monkeypatch):
    from kratos.adapters import ssh_remote as R

    sent = {}

    def fake_script(script, **kw):
        sent["script"] = script
        return R.SSHResult(True, 0, "ssh_root_login\tPASS\tno\nfirewall\tPASS\tufw active\n"
                                    "target_timezone\tINFO\tTarget system timezone: Europe/Helsinki (journald log "
                                    "timestamps are stored as absolute UTC regardless)\n", "")

    monkeypatch.setattr(R, "_route", lambda probe, params, ssh_call, **kw: ssh_call())
    monkeypatch.setattr(R, "run_remote_script", fake_script)
    rows = R.run_config_audit_checks()
    assert [r["check"] for r in rows] == ["ssh_root_login", "firewall"]    # the summary counts are unchanged
    assert R.last_config_audit_zone() == "Europe/Helsinki"
    assert sent["script"].endswith(Z.SSH_ROW_SH) and "target_timezone" in sent["script"]


def test_the_shared_config_audit_script_is_unchanged():
    """The appended line lives in ssh_remote, never in the agent bundle's script."""
    from kratos.subagent import reads

    assert "timezone" not in reads.config_audit_script("sudo -n")


def test_the_setup_probe_zone_is_saved_per_machine(tmp_path):
    from kratos.logsources import setup_probe

    rows = [{"check": "target_timezone", "status": "INFO",
             "detail": "Target system timezone: Europe/Helsinki (journald log timestamps ...)"},
            {"check": "machine_id", "status": "INFO", "detail": "abc"}]
    setup_probe.finish_rows(rows, tmp_path, "10.0.0.5")
    setup_probe.finish_rows([{"check": "target_timezone", "status": "INFO", "detail": "Box timezone: unknown (x)"}],
                            tmp_path, "10.0.0.6")
    assert Z.probe_path(tmp_path, "10.0.0.5").exists() and not Z.probe_path(tmp_path, "10.0.0.6").exists()
    assert Z._from_probe(tmp_path, "10.0.0.5")[0] == "Europe/Helsinki"
    assert Z._from_probe(tmp_path, "10.0.0.6") is None


def test_baseline_view_shows_the_machine_zone(tmp_path):
    from kratos.baseline import present

    m = _deploy_at_eight("Europe/Helsinki")
    data = write(tmp_path / "home", [m])
    _no_measured_zone(data)
    _audit(data, m.target, "Europe/Helsinki")
    run(data, m.target)
    text = present.to_text(present.view(data, m.target))
    assert "machine zone Europe/Helsinki" in text and "hours in UTC" not in text

