"""The `collect.*` settings (Settings -> General -> Collection). Per-check freshness
limits (`collect.ttl.<check>_minutes`) are registered with the checks themselves."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

ENABLED = "collect.enabled"
START_BUDGET = "collect.start_budget_seconds"


def _on_off(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("on", "yes", "true", "1"):
        return True
    if text in ("off", "no", "false", "0"):
        return False
    raise SettingError("on or off")


def _whole(lo: int, hi: int, what: str):
    def check(value: Any) -> int:
        if isinstance(value, bool):
            raise SettingError(f"a whole number of {what}, {lo:,}-{hi:,}")
        try:
            n = int(str(value).strip()) if not isinstance(value, (int, float)) else int(value)
        except (TypeError, ValueError):
            raise SettingError(f"a whole number of {what}, {lo:,}-{hi:,}") from None
        if isinstance(value, float) and n != value or not lo <= n <= hi:
            raise SettingError(f"a whole number of {what}, {lo:,}-{hi:,}")
        return n
    return check


for _spec in (
    SettingSpec(ENABLED, True, _on_off,
                "Check the basics (open ports, sign-ins, altered logs, ...) before an investigation starts."),
    SettingSpec(START_BUDGET, 15, _whole(1, 300, "seconds"),
                "The most time Kratos spends checking the basics before the model starts; what is not done is "
                "reported as not checked."),
):
    settings_store.register(_spec)
