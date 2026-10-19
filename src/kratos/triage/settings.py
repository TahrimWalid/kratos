"""The triage settings people edit (Settings -> General, `app_settings`)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

AUTO_SECONDS = "triage.auto_seconds"


def _seconds(value: Any) -> int:
    if isinstance(value, bool):
        raise SettingError("a whole number of seconds, 0-120")
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise SettingError("a whole number of seconds, 0-120") from None
    if n != value and not (isinstance(value, str) and value.strip().lstrip("-").isdigit()):
        raise SettingError("a whole number of seconds, 0-120")
    if not 0 <= n <= 120:
        raise SettingError("a whole number of seconds, 0-120")
    return n


settings_store.register(SettingSpec(
    key=AUTO_SECONDS, default=20, validate=_seconds,
    doc="How long Kratos spends automatically re-checking serious findings before an answer, "
        "in seconds (0 turns auto re-checking off; slow checks still run on /verify).",
))
