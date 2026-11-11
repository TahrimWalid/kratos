"""The `compliance.*` settings (Settings -> General -> Compliance)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.collect.settings import _on_off, _whole
from kratos.settings_store import SettingSpec

MAX_AGE_HOURS = "compliance.max_age_hours"
NA_MAX_DAYS = "compliance.na_max_days"
ASK_OWNERS = "compliance.show_owner_hint"

for _spec in (
    SettingSpec(MAX_AGE_HOURS, 24, _whole(1, 168, "hours"),
                "A control passes only on facts read within this many hours; older facts make it 'not checked'."),
    SettingSpec(NA_MAX_DAYS, 365, _whole(1, 365, "days"),
                "The longest a person's 'not applicable' decision on a control lasts before Kratos asks again."),
    SettingSpec(ASK_OWNERS, True, _on_off,
                "Show 'no owner yet' beside failed controls in compliance reports."),
):
    settings_store.register(_spec)


def get(key: str, data_dir: Any) -> Any:
    return settings_store.get(key, data_dir=data_dir)
