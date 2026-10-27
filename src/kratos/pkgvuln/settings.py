"""The ``vulndb.*`` settings (people-only, via kratos.settings_store)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

MAX_AGE_DAYS = "vulndb.max_age_days"
EPSS_HIGH = "vulndb.epss_high"
REMATCH_MAX_LIST_AGE_DAYS = "vulndb.rematch_max_list_age_days"


def _days(value: Any) -> int:
    try:
        n = int(str(value).strip()) if not isinstance(value, int) or isinstance(value, bool) else value
    except (TypeError, ValueError):
        raise SettingError("a whole number of days, 1-365") from None
    if isinstance(n, bool) or not 1 <= n <= 365:
        raise SettingError("a whole number of days, 1-365")
    return n


def _probability(value: Any) -> float:
    try:
        x = float(str(value).strip().rstrip("%")) / (100.0 if str(value).strip().endswith("%") else 1.0)
    except (TypeError, ValueError):
        raise SettingError("a chance between 0 and 1 (for example 0.1, or 10%)") from None
    if isinstance(value, bool) or not 0.0 < x <= 1.0:
        raise SettingError("a chance between 0 and 1 (for example 0.1, or 10%)")
    return x


settings_store.register(SettingSpec(
    MAX_AGE_DAYS, 7, _days,
    "After how many days the downloaded vulnerability data counts as out of date (run `kratos vulndb-update`)."))
settings_store.register(SettingSpec(
    EPSS_HIGH, 0.1, _probability,
    "A fixable vulnerability this likely to be exploited in the next 30 days (EPSS) and serious (CVSS 7+) is "
    "rated high."))
settings_store.register(SettingSpec(
    REMATCH_MAX_LIST_AGE_DAYS, 30, _days,
    "After `kratos vulndb-update`, each machine's stored package list is matched again against the new data -- "
    "unless the list is older than this many days (then only a fresh package check says anything useful)."))
