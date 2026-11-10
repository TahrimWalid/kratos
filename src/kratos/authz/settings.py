"""D.7 settings (`users.*`, people-only like every setting)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

TOKEN_DAYS = "users.token_days"
EXPIRY_WARN_DAYS = "users.token_expiry_warn_days"


def _days(lo: int, hi: int):
    def check(value: Any) -> int:
        try:
            n = int(value)
        except (TypeError, ValueError):
            raise SettingError(f"a whole number of days from {lo} to {hi}") from None
        if not lo <= n <= hi:
            raise SettingError(f"a whole number of days from {lo} to {hi}")
        return n
    return check


for _spec in (
    SettingSpec(TOKEN_DAYS, 90, _days(1, 3650),
                "How long a new chat/MCP token is valid (days). Only the owner's own tokens may never expire."),
    SettingSpec(EXPIRY_WARN_DAYS, 14, _days(1, 365),
                "Show a token as 'expires soon' in /users and /doctor this many days before it expires."),
):
    settings_store.register(_spec)
