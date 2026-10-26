"""The `hunt.*` settings (Settings -> General -> Hunting)."""
from __future__ import annotations

from kratos import settings_store
from kratos.collect.settings import _whole
from kratos.settings_store import SettingSpec

MAX_HITS = "hunt.max_hits"
SCAN_SECONDS = "hunt.scan_seconds"
SCAN_DAYS = "hunt.scan_days"
SNAPSHOT_FILES = "hunt.snapshot_files"
INDEX_SECONDS = "hunt.index_seconds"
AUTO_MAX_INDICATORS = "hunt.auto_max_indicators"

for _spec in (
    SettingSpec(MAX_HITS, 200, _whole(10, 5000, "hits"),
                "A hunt lists at most this many of the newest matching records; past it, it shows counts and "
                "asks you to narrow the search."),
    SettingSpec(SCAN_SECONDS, 3, _whole(1, 60, "seconds"),
                "The most time a hunt spends searching log text (what isn't in a typed field); the report says "
                "how much it searched."),
    SettingSpec(SCAN_DAYS, 7, _whole(1, 365, "days"),
                "How far back a hunt searches log text (typed fields such as addresses and accounts are searched "
                "over everything Kratos holds)."),
    SettingSpec(SNAPSHOT_FILES, 500, _whole(10, 20000, "files"),
                "The most saved snapshots (persistence, running processes) one hunt reads per machine, newest "
                "first."),
    SettingSpec(INDEX_SECONDS, 5, _whole(0, 600, "seconds"),
                "Before a hunt, Kratos spends up to this long indexing log events stored before hunting existed "
                "(`kratos hunt index` finishes it)."),
    SettingSpec(AUTO_MAX_INDICATORS, 1000, _whole(10, 100000, "addresses"),
                "When the threat-intel cache learns new malicious addresses, Kratos hunts at most this many of "
                "them per update; the rest wait for the next."),
):
    settings_store.register(_spec)
