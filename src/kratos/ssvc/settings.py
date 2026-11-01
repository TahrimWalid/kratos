"""The ``ssvc.*`` settings (people-only, via kratos.settings_store)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

ASK_CRITICALITY = "ssvc.ask_criticality"


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise SettingError("on or off")


settings_store.register(SettingSpec(
    ASK_CRITICALITY, True, _bool,
    "Ask once per machine how much it matters (criticality ranks its vulnerabilities with CISA's SSVC tree); "
    "off: never ask -- an unset machine is assumed medium and says so."))
