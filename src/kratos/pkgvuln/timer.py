"""A systemd user timer that runs `kratos vulndb-update` on a cadence.

Same mechanism as the saved schedules (agent/schedule_units.py): Kratos writes the
.service and .timer files into its own data folder and prints the exact commands to
install them -- it never runs systemctl itself. Each run downloads only what changed
(usually under a minute) and then matches every machine's stored package list
against the new data (pkgvuln/rematch.py), so a CVE that starts being exploited
reaches the person's triggers within a day, not at the next live package check.

The time of day is fixed per installation (derived from the data folder's path, not
random each run) and spread over an hour with RandomizedDelaySec, so many Kratos
installs don't all hit the public data servers on the same minute.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from kratos.agent.schedule_units import kratos_bin

UNIT = "kratos-vulndb-update"
CADENCES = ("daily", "weekly")


def units_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "vulndb" / "systemd"


def _minute_of(data_dir: Path) -> tuple[int, int]:
    n = int(hashlib.sha256(str(Path(data_dir).resolve()).encode()).hexdigest()[:8], 16)
    return 3 + n % 3, n // 3 % 60          # 03:00-05:59


def oncalendar(cadence: str, data_dir: Path) -> str:
    if cadence not in CADENCES:
        raise ValueError(f"cadence must be one of: {', '.join(CADENCES)}")
    hour, minute = _minute_of(data_dir)
    day = "Mon " if cadence == "weekly" else ""
    return f"{day}*-*-* {hour:02d}:{minute:02d}:00"


def service_text(data_dir: Path, *, bin_path: str | None = None) -> str:
    return (
        "[Unit]\n"
        "Description=Kratos: update the package-vulnerability data and re-match stored package lists\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={bin_path or kratos_bin()} vulndb-update --data-dir {Path(data_dir).resolve()}\n"
        "Nice=10\n"
    )


def timer_text(cadence: str, data_dir: Path) -> str:
    return (
        "[Unit]\n"
        f"Description=Kratos: {cadence} package-vulnerability data update\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={oncalendar(cadence, data_dir)}\n"
        "RandomizedDelaySec=1h\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def write_units(cadence: str, data_dir: Path, *, bin_path: str | None = None) -> tuple[Path, Path]:
    d = units_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    service, timer = d / f"{UNIT}.service", d / f"{UNIT}.timer"
    service.write_text(service_text(data_dir, bin_path=bin_path), encoding="utf-8")
    timer.write_text(timer_text(cadence, data_dir), encoding="utf-8")
    return service, timer


def install_commands(service: Path, timer: Path) -> list[str]:
    return [
        "loginctl enable-linger $USER   # so the timer runs even when you're logged out",
        "mkdir -p ~/.config/systemd/user",
        f"cp {service} {timer} ~/.config/systemd/user/",
        "systemctl --user daemon-reload",
        f"systemctl --user enable --now {UNIT}.timer",
        f"systemctl --user list-timers {UNIT}.timer   # verify it's scheduled",
    ]


def uninstall_commands() -> list[str]:
    return [
        f"systemctl --user disable --now {UNIT}.timer",
        f"rm -f ~/.config/systemd/user/{UNIT}.service ~/.config/systemd/user/{UNIT}.timer",
        "systemctl --user daemon-reload",
    ]
