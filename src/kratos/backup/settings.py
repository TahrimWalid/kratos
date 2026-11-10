"""D.8 settings (`backup.*`, people-only like every setting).

There is deliberately no `backup.keep`: the owner decided (2026-11-10) that Kratos never
deletes a backup on its own. Old backups go only by `kratos backup prune --keep N`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

RECIPIENTS = "backup.recipients"
DESTINATION = "backup.destination"
COPY_TARGETS = "backup.copy_targets"
DRILL_WARN_DAYS = "backup.drill_warn_days"
SCHEDULE = "backup.schedule"

MAX_RECIPIENTS = 5
SCHEDULES = ("off", "daily", "weekly")


def _recipients(value: Any) -> list[str]:
    from kratos.backup.agefmt import X25519Recipient

    if not isinstance(value, list):
        raise SettingError("a list of age1… public keys")
    out: list[str] = []
    for v in value:
        try:
            r = str(X25519Recipient.parse(str(v)))
        except ValueError as e:
            raise SettingError(f"{str(v)[:20]}…: {e}") from None
        if r not in out:
            out.append(r)
    if len(out) > MAX_RECIPIENTS:
        raise SettingError(f"at most {MAX_RECIPIENTS} keys can open a backup")
    return out


def _destination(value: Any) -> str:
    text = str(value or "").strip()
    if text and not Path(text).expanduser().is_absolute():
        raise SettingError("an absolute folder (or empty for ~/kratos-backups)")
    return text


def _copy_targets(value: Any) -> list[str]:
    from kratos.backup.copies import parse_target

    if not isinstance(value, list):
        raise SettingError("a list of folders or sftp://user@host/path targets")
    out = []
    for v in value:
        try:
            out.append(parse_target(str(v)).text)
        except ValueError as e:
            raise SettingError(str(e)) from None
    return out


def _days(value: Any) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise SettingError("a whole number of days from 1 to 365") from None
    if not 1 <= n <= 365:
        raise SettingError("a whole number of days from 1 to 365")
    return n


def _schedule(value: Any) -> str:
    v = str(value or "").strip().lower()
    if v not in SCHEDULES:
        raise SettingError("off, daily or weekly")
    return v


for _spec in (
    SettingSpec(RECIPIENTS, [], _recipients,
                "The public keys (age1…) backups are encrypted to. Only the person holding a matching secret key can "
                "open a backup; Kratos keeps no secret key."),
    SettingSpec(DESTINATION, "", _destination,
                "Where backups are written (empty: ~/kratos-backups). Kratos's data folder is refused."),
    SettingSpec(COPY_TARGETS, [], _copy_targets,
                "Where each backup is copied too: a folder on another disk, or sftp://user@host/path."),
    SettingSpec(DRILL_WARN_DAYS, 30, _days,
                "Warn in /doctor when no restore drill has passed for this many days."),
    SettingSpec(SCHEDULE, "off", _schedule,
                "How often the backup timer runs (written by `kratos backup schedule`), so /doctor can say when a "
                "backup is late."),
):
    settings_store.register(_spec)


def get(key: str, data_dir: Path) -> Any:
    return settings_store.get(key, data_dir=Path(data_dir))
