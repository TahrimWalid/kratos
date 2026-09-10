"""Scripted tests for A6.3 systemd unit generation (agent/schedule_units.py)."""
from __future__ import annotations

from kratos.agent import schedules as S
from kratos.agent import schedule_units as U


def test_service_unit_is_oneshot_with_abs_paths(tmp_path):
    sch = S.save_schedule(tmp_path, name="wk", kind="audit", cadence="weekly")
    text = U.service_unit_text(sch, tmp_path, bin_path="/opt/venv/bin/kratos")
    assert "Type=oneshot" in text                       # no self-overlap
    assert "scheduled-run wk --data-dir" in text
    assert str(tmp_path.resolve()) in text              # absolute data-dir
    assert "/opt/venv/bin/kratos scheduled-run wk" in text


def test_timer_unit_has_persistent_and_correct_oncalendar(tmp_path):
    for cadence, oncal in [("hourly", "hourly"), ("daily", "daily"),
                           ("weekly", "weekly"), ("monthly", "monthly")]:
        sch = S.save_schedule(tmp_path, name=f"s-{cadence}", kind="audit", cadence=cadence)
        text = U.timer_unit_text(sch)
        assert f"OnCalendar={oncal}" in text
        assert "Persistent=true" in text                # catch-up on miss
        assert "WantedBy=timers.target" in text


def test_write_units_stages_inside_data_dir(tmp_path):
    sch = S.save_schedule(tmp_path, name="wk", kind="audit")
    sp, tp = U.write_units(sch, tmp_path, bin_path="/opt/venv/bin/kratos")
    assert sp.exists() and tp.exists()
    assert sp.name == "kratos-wk.service" and tp.name == "kratos-wk.timer"
    # Staged inside data_dir/schedules/systemd -- no side effects elsewhere.
    assert U.units_dir(tmp_path) in sp.parents


def test_install_and_uninstall_commands(tmp_path):
    sch = S.save_schedule(tmp_path, name="wk", kind="audit")
    sp, tp = U.write_units(sch, tmp_path, bin_path="/opt/venv/bin/kratos")
    install = U.install_commands(sch, sp, tp)
    assert any("systemctl --user enable --now kratos-wk.timer" in c for c in install)
    assert any("daemon-reload" in c for c in install)
    uninstall = U.uninstall_commands(sch)
    assert any("disable --now kratos-wk.timer" in c for c in uninstall)


def test_kratos_bin_prefers_venv_sibling():
    # Just assert it returns a non-empty string and doesn't raise.
    assert isinstance(U.kratos_bin(), str) and U.kratos_bin()
