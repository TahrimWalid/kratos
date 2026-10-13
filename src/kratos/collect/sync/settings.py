"""The `collect.sync_*` settings: which sources are kept up to date, how far back a first
sync reaches, and how many lines one sync round takes per source."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.collect.settings import _whole
from kratos.logsources import catalog
from kratos.settings_store import SettingError, SettingSpec

SOURCES = "collect.sync_sources"
INITIAL_HOURS = "collect.sync_initial_hours"
MAX_LINES = "collect.sync_max_lines"


def _sources(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [v.strip() for v in value.replace(";", ",").split(",") if v.strip()]
    if not isinstance(value, (list, tuple)):
        raise SettingError(f"a list of log sources from: {', '.join(catalog.SYNC_SOURCE_NAMES)}")
    clean = []
    for v in value:
        name = str(v).strip().lower()
        if name not in catalog.SYNC_SOURCE_NAMES:
            raise SettingError(f"{v!r} is not a log source Kratos syncs; choose from: "
                               f"{', '.join(catalog.SYNC_SOURCE_NAMES)}")
        if name not in clean:
            clean.append(name)
    return clean


for _spec in (
    SettingSpec(SOURCES, list(catalog.DEFAULT_SYNC_SOURCES), _sources,
                "Which logs Kratos keeps up to date on its own (web server logs are off by default: they can be huge)."),
    SettingSpec(INITIAL_HOURS, 24, _whole(1, 720, "hours"),
                "How far back the very first sync of a machine reaches."),
    SettingSpec(MAX_LINES, 20000, _whole(100, 200000, "lines"),
                "The most lines taken from one log in one sync round; if there are more, the next round continues."),
):
    settings_store.register(_spec)
