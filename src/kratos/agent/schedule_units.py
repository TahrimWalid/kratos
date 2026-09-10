"""A6.3 -- systemd user-timer generation for a schedule.

The decided cadence mechanism (owner, 2026-09-10): **systemd user timers**.
Kratos does NOT run ``systemctl`` itself -- it GENERATES the ``.service`` +
``.timer`` unit files (into a staging dir under ``data_dir``) and hands the human
the exact install commands, exactly the way ``adapters/target_setup.py`` generates
a copy-pasteable checklist rather than acting. Installing is one command the user
runs; systemd then owns timing, reboot-survival, catch-up (``Persistent=true``),
single-instance, and no-overlap -- the doc's five hardest scheduler edge cases,
handled by the OS instead of reinvented in Kratos.

The unit invokes ``kratos scheduled-run <name>`` (scheduled_run.py), which runs
headlessly with approval-gated tools excluded by construction.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Optional

from kratos.agent.schedules import Schedule, schedules_dir


def kratos_bin() -> str:
    """Absolute path to the ``kratos`` console script. Prefers the one next to
    the running interpreter (correct inside a venv even when systemd's minimal
    PATH wouldn't find it), then PATH, then a bare 'kratos' fallback."""
    candidate = Path(sys.executable).with_name("kratos")
    if candidate.exists():
        return str(candidate)
    found = shutil.which("kratos")
    return found or "kratos"


def units_dir(data_dir: Path) -> Path:
    return schedules_dir(data_dir) / "systemd"


def service_unit_text(
    schedule: Schedule,
    data_dir: Path,
    *,
    bin_path: Optional[str] = None,
    working_dir: Optional[Path] = None,
) -> str:
    """The oneshot .service unit. ``Type=oneshot`` means systemd will not start a
    second copy while one is still running -- the doc's 'overlapping runs' guard,
    for free. Paths are absolute (systemd does not expand ~ or relatives)."""
    bin_path = bin_path or kratos_bin()
    data_dir_abs = Path(data_dir).resolve()
    working_dir = Path(working_dir).resolve() if working_dir else Path.cwd()
    return (
        f"[Unit]\n"
        f"Description=Kratos scheduled run: {schedule.name}\n"
        f"After=network-online.target\n"
        f"Wants=network-online.target\n"
        f"\n"
        f"[Service]\n"
        f"Type=oneshot\n"
        f"WorkingDirectory={working_dir}\n"
        f"ExecStart={bin_path} scheduled-run {schedule.name} --data-dir {data_dir_abs}\n"
    )


def timer_unit_text(schedule: Schedule) -> str:
    """The .timer unit. ``Persistent=true`` runs a missed job once on next boot
    (the doc's 'missed runs / machine off' guard); ``OnCalendar`` handles cadence
    and DST."""
    return (
        f"[Unit]\n"
        f"Description=Timer for Kratos scheduled run: {schedule.name}\n"
        f"\n"
        f"[Timer]\n"
        f"OnCalendar={schedule.oncalendar}\n"
        f"Persistent=true\n"
        f"\n"
        f"[Install]\n"
        f"WantedBy=timers.target\n"
    )


def write_units(
    schedule: Schedule,
    data_dir: Path,
    *,
    bin_path: Optional[str] = None,
    working_dir: Optional[Path] = None,
) -> tuple[Path, Path]:
    """Write the .service and .timer files into ``data_dir/schedules/systemd/``
    (a staging area inside Kratos's own data dir -- no side effects outside it).
    Returns (service_path, timer_path)."""
    d = units_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    service_path = d / f"{schedule.unit_name}.service"
    timer_path = d / f"{schedule.unit_name}.timer"
    service_path.write_text(service_unit_text(schedule, data_dir, bin_path=bin_path, working_dir=working_dir), encoding="utf-8")
    timer_path.write_text(timer_unit_text(schedule), encoding="utf-8")
    return service_path, timer_path


def install_commands(schedule: Schedule, service_path: Path, timer_path: Path) -> list[str]:
    """The exact commands a human runs to activate the timer (Kratos never runs
    systemctl itself). The enable-linger line is what lets a USER timer keep
    firing when you're logged out — without it a user timer only runs while you
    have an active login session, so a weekly audit would silently not run."""
    return [
        "loginctl enable-linger $USER   # so the timer runs even when you're logged out",
        "mkdir -p ~/.config/systemd/user",
        f"cp {service_path} {timer_path} ~/.config/systemd/user/",
        "systemctl --user daemon-reload",
        f"systemctl --user enable --now {schedule.unit_name}.timer",
        f"systemctl --user list-timers {schedule.unit_name}.timer   # verify it's scheduled",
    ]


def uninstall_commands(schedule: Schedule) -> list[str]:
    return [
        f"systemctl --user disable --now {schedule.unit_name}.timer",
        f"rm -f ~/.config/systemd/user/{schedule.unit_name}.service ~/.config/systemd/user/{schedule.unit_name}.timer",
        "systemctl --user daemon-reload",
    ]
