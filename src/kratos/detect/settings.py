"""The `detect.*` settings (Settings -> General -> Detection rules)."""
from __future__ import annotations

from kratos import settings_store
from kratos.collect.settings import _whole
from kratos.settings_store import SettingSpec

LOOKBACK_HOURS = "detect.lookback_hours"
PASS_BUDGET = "detect.pass_budget_seconds"
MAX_EVENTS = "detect.max_events_per_pass"
FINDING_WINDOW_HOURS = "detect.finding_window_hours"
COVERAGE_DAYS = "detect.coverage_days"

for _spec in (
    SettingSpec(LOOKBACK_HOURS, 24, _whole(1, 24 * 30, "hours"),
                "When the rule pack is new or changes, how far back the stored logs are checked once."),
    SettingSpec(PASS_BUDGET, 20, _whole(1, 600, "seconds"),
                "The most time one detection pass spends on one machine; what is left is checked next time."),
    SettingSpec(MAX_EVENTS, 50_000, _whole(100, 1_000_000, "events"),
                "The most stored log events one detection pass reads for one machine; the rest wait for the next."),
    SettingSpec(FINDING_WINDOW_HOURS, 24, _whole(1, 24 * 30, "hours"),
                "How long a rule match stays an open finding without a new match."),
    SettingSpec(COVERAGE_DAYS, 7, _whole(1, 90, "days"),
                "A log source counts as collected on a machine when Kratos holds events from it this recent."),
):
    settings_store.register(_spec)
