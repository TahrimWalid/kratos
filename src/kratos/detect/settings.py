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
# C.2: continuous detection on agents (pushed to each agent as data, bounds checked there too)
WATCH_SPOOL_DETECTIONS = "detect.watch.spool_detections"
WATCH_SPOOL_MB = "detect.watch.spool_mb"
WATCH_CATCHUP_HOURS = "detect.watch.max_catchup_hours"
WATCH_CATCHUP_ENTRIES = "detect.watch.max_catchup_entries"
WATCH_PER_RULE_MINUTE = "detect.watch.max_per_rule_minute"
WATCH_CPU_PERCENT = "detect.watch.max_cpu_percent"
WATCH_OFFLINE_MINUTES = "detect.watch.offline_minutes"
ALERT_BATCH_SECONDS = "detect.alert_batch_seconds"

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
    SettingSpec(WATCH_SPOOL_DETECTIONS, 2000, _whole(100, 20000, "detections"),
                "Watched machines keep this many unsent detections while the link is down; past it the oldest go "
                "(and the drop is reported)."),
    SettingSpec(WATCH_SPOOL_MB, 5, _whole(1, 64, "MB"),
                "The most disk the unsent detections may use on a watched machine."),
    SettingSpec(WATCH_CATCHUP_HOURS, 6, _whole(1, 168, "hours"),
                "After a restart, a watched machine catches up on at most this much of its logs; older is reported "
                "as not watched."),
    SettingSpec(WATCH_CATCHUP_ENTRIES, 200_000, _whole(1000, 2_000_000, "entries"),
                "After a restart, a watched machine catches up on at most this many log entries."),
    SettingSpec(WATCH_PER_RULE_MINUTE, 20, _whole(1, 1000, "matches"),
                "A watched machine sends at most this many matches of one rule a minute, then one summary."),
    SettingSpec(WATCH_CPU_PERCENT, 25, _whole(5, 100, "percent of one core"),
                "The most CPU the watcher's rule evaluation may use while catching up; past it, it slows down."),
    SettingSpec(WATCH_OFFLINE_MINUTES, 10, _whole(2, 1440, "minutes"),
                "A watched machine whose link has been down this long is reported as not watched (DETECT-002)."),
    SettingSpec(ALERT_BATCH_SECONDS, 5, _whole(1, 120, "seconds"),
                "Live detections from one machine arriving within this many seconds become one alert."),
):
    settings_store.register(_spec)
