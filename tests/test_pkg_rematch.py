"""After new vulnerability data, each machine's STORED package list is matched again --
nothing is read from the machine -- and what's new or more severe reaches the person's
triggers (PHP2Shell follow-up: a CVE that starts being exploited this morning shouldn't
wait for the next live read of every machine)."""
from __future__ import annotations

import sqlite3
from datetime import timezone

import pytest

from kratos.adapters import findings_engine as FE
from kratos.agent import triggers as T
from kratos.pkgvuln import index as IX
from kratos.pkgvuln import inventory_store
from kratos.pkgvuln import record as REC
from kratos.pkgvuln import rematch as RM
from kratos.pkgvuln import settings as PS
from kratos import settings_store
from test_pkgvuln import _deb_inv, deb_index  # noqa: F401  (fixture)

HOST = "10.0.0.5"
T0 = 1_790_000_000.0
DAY = 86400.0


@pytest.fixture(autouse=True)
def _utc(monkeypatch):
    monkeypatch.setattr("kratos.utils.timeutil.resolve_display_tz", lambda data_dir=None: timezone.utc)


def _collect():
    sent: list[tuple[str, str]] = []
    return sent, (lambda message, severity: sent.append((message, severity)) or {"status": "sent"})


def _no_investigation(goal, data_dir):
    raise AssertionError("an investigation must not start")


def _kev(data_dir, cve: str, *, add: bool = True) -> None:
    """The index is read-only to Kratos; tests change it the way an update would."""
    conn = sqlite3.connect(str(IX.path_for(data_dir)))
    with conn:
        if add:
            conn.execute("INSERT OR REPLACE INTO kev (cve, date_added, due_date) VALUES (?, '2026-10-26', "
                         "'2026-11-16')", (cve,))
        else:
            conn.execute("DELETE FROM kev WHERE cve = ?", (cve,))
    conn.close()


def _store(data_dir, inv=None, when=T0):
    return REC.run(data_dir, HOST, reader=lambda: inv or _deb_inv(), now=when)


def _by(result, subject):
    return next(f for f in result.news if f["id"] == "PKG-001" and f["subject"] == subject)


def test_the_stored_list_is_matched_again_without_reading_the_machine(deb_index):
    _store(deb_index)
    before = inventory_store.latest(deb_index, HOST)
    doc = REC.rematch(deb_index, HOST, now=T0 + 2 * DAY)
    assert doc["rematched"] and doc["list_read_at"].startswith("2026-09-21")
    curl = next(s for s in doc["signals"] if s["rule"] == "PKG-001" and s["subject"] == "curl")
    assert any("read at 2026-09-21" in e and "nothing was read from the machine" in e for e in curl["evidence"])
    after = inventory_store.latest(deb_index, HOST)
    assert after.last_seen_at == before.last_seen_at and after.id == before.id   # the list wasn't "seen" again
    assert REC.rematch(deb_index, "10.0.0.99") is None                            # never checked: nothing to match


def test_a_newly_exploited_cve_makes_an_open_finding_worse_and_fires_a_trigger(deb_index):
    _store(deb_index)
    T.save_trigger(deb_index, name="crit", min_severity="critical", only_new_or_reopened=True, cooldown_minutes=0)
    sent, notifier = _collect()
    first = RM.rematch_all(deb_index, notifier=notifier, investigate_fn=_no_investigation, now=T0 + 60)
    curl = _by(first[0], "curl")
    assert curl["severity"] == "low" and curl["change"] == "new"
    assert [f["trigger"] for f in first[0].fired] == ["crit"]                      # openssh is already on KEV
    sent.clear()

    _kev(deb_index, "CVE-2023-46218")                # curl's fixable CVE is now exploited in the wild
    second = RM.rematch_all(deb_index, notifier=notifier, investigate_fn=_no_investigation, now=T0 + 120)
    curl = _by(second[0], "curl")
    assert curl["severity"] == "critical" and curl["change"] == "worse"
    assert [f["subject"] for f in second[0].news] == ["curl"]                       # openssh: still open, not news
    assert [f["trigger"] for f in second[0].fired] == ["crit"] and len(sent) == 1
    lines = RM.report_lines(second)
    assert any("[CRITICAL]" in ln and "curl" in ln and "(more severe)" in ln for ln in lines)

    _kev(deb_index, "CVE-2023-46218", add=False)     # severity going down is a change, not news
    third = RM.rematch_all(deb_index, notifier=notifier, investigate_fn=_no_investigation, now=T0 + 180)
    assert third[0].news == []


def test_a_rematched_list_never_closes_a_finding(deb_index):
    src = FE.SNAPSHOT_SOURCES["packages"]
    assert src.closes_findings({"complete": True}) is True
    assert src.closes_findings({"complete": True, "rematched": True}) is False


def test_an_old_list_is_not_matched_again(deb_index):
    _store(deb_index)
    settings_store.set(PS.REMATCH_MAX_LIST_AGE_DAYS, 10, data_dir=deb_index, actor="test")
    [r] = RM.rematch_all(deb_index, now=T0 + 11 * DAY)
    assert r.status == "skipped_old" and r.news == []
    assert "11 days old" in RM.report_lines([r])[0]


def test_packages_from_outside_the_distribution_stay_out_when_matched_again(deb_index):
    inv = _deb_inv()
    for name in ("curl", "libcurl4"):
        inv["origins"][name] = {"exact": ["LP-PPA-someone"], "any": ["LP-PPA-someone"]}
    _store(deb_index, inv)
    doc = REC.rematch(deb_index, HOST, now=T0 + 60)
    assert not [s for s in doc["signals"] if s["rule"] == "PKG-001" and s["subject"] == "curl"]
    note = next(s for s in doc["signals"] if s["rule"] == "PKG-004")
    assert any("from LP-PPA-someone: curl, libcurl4" in e for e in note["evidence"])


def test_a_list_stored_before_origins_were_recorded_says_so(deb_index):
    _store(deb_index)
    conn = sqlite3.connect(str(deb_index / "kratos.db"))
    with conn:
        conn.execute("UPDATE pkg_inventory SET read_json = NULL")
    conn.close()
    doc = REC.rematch(deb_index, HOST, now=T0 + 60)
    note = next(s for s in doc["signals"] if s["rule"] == "PKG-004")
    assert any("earlier Kratos that didn't record where each package came from" in e for e in note["evidence"])


def test_malformed_stored_origins_never_read_as_nothing_outside():
    from kratos.pkgvuln.origin import OriginReport

    assert OriginReport.from_dict("junk").reason and not OriginReport.from_dict("junk").checked
    rep = OriginReport.from_dict({"checked": True, "outside": [["a", "1", "X", "third_party"], ["b", "1"],
                                                               ["c", "1", "Y", "evil"]]})
    assert rep.names == {"a"}
    assert OriginReport.from_dict(rep.to_dict()).names == {"a"}


# ------------------------------------------------------------- the update timer
def test_the_timer_runs_the_update_and_is_spread_per_install(tmp_path):
    import shutil
    import subprocess

    from kratos.pkgvuln import timer as TM

    service, timer = TM.write_units("weekly", tmp_path, bin_path="/opt/kratos/bin/kratos")
    assert f"ExecStart=/opt/kratos/bin/kratos vulndb-update --data-dir {tmp_path.resolve()}" in service.read_text()
    text = timer.read_text()
    assert "Persistent=true" in text and "RandomizedDelaySec=1h" in text
    cal = TM.oncalendar("weekly", tmp_path)
    assert cal.startswith("Mon ") and cal == TM.oncalendar("weekly", tmp_path)          # stable per install
    assert TM.oncalendar("daily", tmp_path) == cal[4:]
    with pytest.raises(ValueError):
        TM.oncalendar("hourly", tmp_path)
    if shutil.which("systemd-analyze"):
        r = subprocess.run(["systemd-analyze", "calendar", cal], capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr
    assert any("enable --now kratos-vulndb-update.timer" in c for c in TM.install_commands(service, timer))


def test_the_cli_writes_the_timer_and_never_runs_systemctl(tmp_path, capsys, monkeypatch):
    import argparse
    import subprocess

    from kratos.cli import app

    def refuse(*a, **k):
        raise AssertionError("Kratos must not run systemctl itself")

    monkeypatch.setattr(subprocess, "run", refuse)
    ns = argparse.Namespace(data_dir=str(tmp_path), about=False, status=False, timer="daily", ecosystems=None,
                            full=False)
    assert app.cmd_vulndb_update(ns) == 0
    out = capsys.readouterr().out
    assert (tmp_path / "vulndb/systemd/kratos-vulndb-update.timer").exists()
    assert "systemctl --user enable --now kratos-vulndb-update.timer" in out
    ns.timer = "off"
    assert app.cmd_vulndb_update(ns) == 0
    assert "disable --now kratos-vulndb-update.timer" in capsys.readouterr().out


def test_the_update_command_reports_what_the_new_data_changed(deb_index, capsys, monkeypatch):
    """`kratos vulndb-update` ends by matching the stored lists again and saying what's new."""
    import argparse

    from kratos.cli import app
    from kratos.pkgvuln import update as UP

    import time
    from types import SimpleNamespace

    _store(deb_index, when=time.time())            # the command uses the real clock
    monkeypatch.setattr(UP, "run_update", lambda *a, **k: SimpleNamespace(ok=True, message="updated", seconds=1.0))
    ns = argparse.Namespace(data_dir=str(deb_index), about=False, status=False, timer=None, ecosystems=None,
                            full=False)
    assert app.cmd_vulndb_update(ns) == 0
    out = capsys.readouterr().out
    assert "Matched each machine's stored package list against the new data" in out
    assert f"{HOST}: " in out and "[CRITICAL]" in out and "openssh" in out
