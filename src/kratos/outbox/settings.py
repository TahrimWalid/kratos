"""The ``outbox.*`` settings (Settings -> General -> Delivery)."""
from __future__ import annotations

from pathlib import Path

from kratos import settings_store
from kratos.collect.settings import _whole
from kratos.settings_store import SettingSpec

ALERT_AFTER = "outbox.alert_after_minutes"
SCHEDULED_FLUSH = "outbox.scheduled_flush_seconds"

for _spec in (
    SettingSpec(ALERT_AFTER, 60, _whole(5, 7 * 24 * 60, "minutes"),
                "After how long a channel that keeps failing is announced through your other channels "
                "(once per outage, and once more when it recovers)."),
    SettingSpec(SCHEDULED_FLUSH, 30, _whole(0, 600, "seconds"),
                "How long a scheduled run waits to deliver its messages before it exits, when no "
                "always-on Kratos process delivers them (the rest go out when Kratos next runs)."),
):
    settings_store.register(_spec)


def alert_after_minutes(data_dir: Path | str) -> int:
    return int(settings_store.get(ALERT_AFTER, data_dir=Path(data_dir)))


def scheduled_flush_seconds(data_dir: Path | str) -> int:
    return int(settings_store.get(SCHEDULED_FLUSH, data_dir=Path(data_dir)))
