"""The `baseline.*` settings (Settings -> General -> What's normal here). Read fresh per run."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.collect.settings import _whole
from kratos.settings_store import SettingError, SettingSpec

LEARN_DAYS = "baseline.learn_days"
HALF_LIFE_DAYS = "baseline.half_life_days"
MAX_ENTRIES = "baseline.max_entries"
FORGET_DAYS = "baseline.forget_days"
RARE_WEIGHT = "baseline.rare_weight"
TIME_SHARE = "baseline.time_share"
MAX_PER_DAY = "baseline.max_per_day"
COOLDOWN_HOURS = "baseline.cooldown_hours"
MAX_EVENTS_PER_RUN = "baseline.max_events_per_run"


def _fraction(lo: float, hi: float):
    def check(value: Any) -> float:
        if isinstance(value, bool):
            raise SettingError(f"a number from {lo} to {hi}")
        try:
            f = float(str(value).strip())
        except (TypeError, ValueError):
            raise SettingError(f"a number from {lo} to {hi}") from None
        if f != f or not lo <= f <= hi:
            raise SettingError(f"a number from {lo} to {hi}")
        return f
    return check


for _spec in (
    SettingSpec(LEARN_DAYS, 14, _whole(3, 90, "days"),
                "Days of covered history a machine needs before a deviation from what's normal becomes a finding "
                "(until then Kratos says 'still learning')."),
    SettingSpec(HALF_LIFE_DAYS, 30, _whole(3, 365, "days"),
                "How fast old activity fades from what's normal: after this many days it counts half."),
    SettingSpec(MAX_ENTRIES, 500, _whole(50, 5000, "entries"),
                "The most usual things Kratos keeps per machine and kind; the least used ones are set aside."),
    SettingSpec(FORGET_DAYS, 90, _whole(14, 730, "days"),
                "After this many days unseen, something counts as new again."),
    SettingSpec(RARE_WEIGHT, 0.5, _fraction(0.0, 5.0),
                "Something seen at most twice, whose faded count is below this, is treated like a first time."),
    SettingSpec(TIME_SHARE, 0.02, _fraction(0.001, 0.2),
                "A sign-in hour that makes up less than this share of an account's sign-ins is unusual."),
    SettingSpec(MAX_PER_DAY, 5, _whole(1, 100, "findings"),
                "The most new deviation findings per machine per day; the rest are counted in one note."),
    SettingSpec(COOLDOWN_HOURS, 24, _whole(1, 720, "hours"),
                "The same unusual thing is raised at most once in this many hours."),
    SettingSpec(MAX_EVENTS_PER_RUN, 200_000, _whole(1000, 5_000_000, "events"),
                "The most stored events one run learns from; the rest wait for the next run."),
):
    settings_store.register(_spec)


def get(key: str, data_dir: Any) -> Any:
    return settings_store.get(key, data_dir=data_dir)


def values(data_dir: Any) -> dict[str, Any]:
    keys = (LEARN_DAYS, HALF_LIFE_DAYS, MAX_ENTRIES, FORGET_DAYS, RARE_WEIGHT, TIME_SHARE, MAX_PER_DAY,
            COOLDOWN_HOURS, MAX_EVENTS_PER_RUN)
    return {k.split(".", 1)[1]: get(k, data_dir) for k in keys}
