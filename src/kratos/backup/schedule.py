"""Scheduled backups (docs/phaseD/D.8 §3.11).

`kratos backup schedule daily|weekly|off` writes a systemd user timer the same way the
vulnerability-data timer does (kratos.pkgvuln.timer: Kratos writes the unit files into
its data folder and prints the exact commands; it never runs systemctl itself). The timer
runs ``kratos backup create --scheduled``: the same consistent database copy, so it is safe
while the listener runs. It needs recipient-key mode -- nobody is there to type a
passphrase.

A failed scheduled backup, a failed copy, or no successful drill in
`backup.drill_warn_days` goes out through the outbox (D.4) as a notification. The text
names no path, account or address (it may cross a public ntfy server).
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from kratos import paths
from kratos.agent.schedule_units import kratos_bin
from kratos.backup import settings as BS
from kratos.pkgvuln import timer as _timer

UNIT = "kratos-backup"
CADENCES = ("daily", "weekly")


class ScheduleError(ValueError):
    pass


def units_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "backup" / "systemd"


def oncalendar(cadence: str, data_dir: Path) -> str:
    if cadence not in CADENCES:
        raise ScheduleError(f"cadence must be one of: {', '.join(CADENCES)}")
    n = int(hashlib.sha256(("backup:" + str(Path(data_dir).resolve())).encode()).hexdigest()[:8], 16)
    hour, minute = 1 + n % 2, n // 2 % 60          # 01:00-02:59, before the vulnerability-data update
    day = "Sun " if cadence == "weekly" else ""
    return f"{day}*-*-* {hour:02d}:{minute:02d}:00"


def service_text(data_dir: Path, *, bin_path: str | None = None) -> str:
    env = ""
    if paths.LAYOUT == "custom":
        env = f"Environment=KRATOS_HOME={paths.STATE_ROOT}\n"
    return (
        "[Unit]\n"
        "Description=Kratos: encrypted backup of everything Kratos keeps\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"{env}"
        f"ExecStart={bin_path or kratos_bin()} --data-dir {Path(data_dir).resolve()} backup create --scheduled\n"
        "Nice=10\n"
        "IOSchedulingClass=idle\n"
    )


def timer_text(cadence: str, data_dir: Path) -> str:
    return (
        "[Unit]\n"
        f"Description=Kratos: {cadence} encrypted backup\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={oncalendar(cadence, data_dir)}\n"
        "RandomizedDelaySec=15min\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def set_schedule(data_dir: Path, cadence: str, *, actor: Any, copy_to: list[str] | None = None,
                 bin_path: str | None = None) -> dict[str, Any]:
    """Write the timer (or say how to remove it) and record the cadence. People-only."""
    from kratos import settings_store
    from kratos.backup.create import _authorize

    data_dir = Path(data_dir)
    _authorize(actor, data_dir, f"backup schedule {cadence}")
    if cadence == "off":
        settings_store.set(BS.SCHEDULE, "off", data_dir=data_dir, actor=f"{actor.interface}:backup schedule")
        return {"cadence": "off", "commands": _timer.uninstall_commands(UNIT)}
    if cadence not in CADENCES:
        raise ScheduleError(f"cadence must be one of: off, {', '.join(CADENCES)}")
    if not BS.get(BS.RECIPIENTS, data_dir):
        raise ScheduleError("scheduled backups need a backup key (nobody is there to type a passphrase): run "
                            "`kratos backup key new` first")
    if copy_to is not None:
        settings_store.set(BS.COPY_TARGETS, list(copy_to), data_dir=data_dir,
                           actor=f"{actor.interface}:backup schedule")
    settings_store.set(BS.SCHEDULE, cadence, data_dir=data_dir, actor=f"{actor.interface}:backup schedule")
    service, timer = _timer.write_timer_units(units_dir(data_dir), UNIT, service_text(data_dir, bin_path=bin_path),
                                              timer_text(cadence, data_dir))
    for p in (service, timer):
        os.chmod(p, 0o600)
    return {"cadence": cadence, "service": str(service), "timer": str(timer),
            "commands": _timer.install_commands(service, timer, UNIT), "oncalendar": oncalendar(cadence, data_dir),
            "copy_targets": list(BS.get(BS.COPY_TARGETS, data_dir))}


def notify(data_dir: Path, text: str, *, severity: str = "warning") -> dict[str, Any]:
    """One notification through the outbox (never sends directly, never raises)."""
    try:
        from kratos.outbox.alerts import enqueue_alert

        return enqueue_alert(text, severity, data_dir=data_dir, kind="alert", source="schedule", name="backup",
                             worst="medium" if severity == "warning" else "high")
    except Exception as e:  # noqa: BLE001 -- a notification problem must not hide the backup's own result
        return {"status": "failed", "observation": f"{type(e).__name__}: {e}"}


def reason_word(error: BaseException | str) -> str:
    """A short, path-free reason for the notification text."""
    text = str(error).lower()
    for needle, word in (("no space", "no space left on the disk"), ("no backup key", "no backup key is set up"),
                         ("another backup", "another backup was running"), ("tpm", "the TPM could not unseal "
                                                                            "the SSH CA key"),
                         ("refused", "it was refused"), ("copy", "a copy failed")):
        if needle in text:
            return word
    return "an error (details in `kratos backup status`)"


def drill_overdue(data_dir: Path) -> bool:
    from kratos.backup import status

    s = status.summary(data_dir)
    days = int(s["drill_warn_days"])
    age = s["last_drill_age"]
    return age is None or age > days * 86400
