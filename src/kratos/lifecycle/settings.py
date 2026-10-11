"""The finding-lifecycle settings people edit (Settings -> General, `app_settings`)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

ACCEPT_MAX_DAYS = "findings.accept_max_days"
DEFAULT_VIEW = "findings.default_view"
VIEWS = ("open_verified", "all")


def _days(value: Any) -> int:
    if isinstance(value, bool):
        raise SettingError("a number of days, 1-365")
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise SettingError("a number of days, 1-365") from None
    if n != value and not (isinstance(value, str) and value.strip().isdigit()):
        raise SettingError("a whole number of days, 1-365")
    if not 1 <= n <= 365:
        raise SettingError("a number of days, 1-365")
    return n


def _view(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text not in VIEWS:
        raise SettingError(f"one of: {', '.join(VIEWS)}")
    return text


settings_store.register(SettingSpec(
    key=ACCEPT_MAX_DAYS, default=180, validate=_days,
    doc="The longest a risk can be accepted for, in days, before the finding comes back (1-365).",
))
settings_store.register(SettingSpec(
    key=DEFAULT_VIEW, default="open_verified", validate=_view,
    doc="What /findings shows first: open and verified findings (open_verified), or everything (all).",
))
