"""The `export.*` settings (Settings -> General -> Incident export)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.collect.settings import _whole
from kratos.settings_store import SettingError, SettingSpec

MAX_EVENTS = "export.max_events"
NARRATIVE_MAX_USD = "export.narrative_max_usd"
TIMELINE_ROWS = "export.timeline_rows"


def _usd(lo: float, hi: float):
    def check(v: Any) -> float:
        try:
            f = float(v)
        except (TypeError, ValueError) as e:
            raise SettingError(f"expected an amount in US dollars, got {v!r}") from e
        if not lo <= f <= hi:
            raise SettingError(f"expected between {lo} and {hi} US dollars, got {f}")
        return round(f, 4)
    return check


for _spec in (
    SettingSpec(MAX_EVENTS, 2_000_000, _whole(1000, 50_000_000, "events"),
                "The most stored log events one incident export copies; past it the export stops copying "
                "events and says where it stopped."),
    SettingSpec(NARRATIVE_MAX_USD, 0.25, _usd(0.0, 20.0),
                "The most an export's written summary (by the model, which holds no tools) may cost; an "
                "estimate above it skips the summary and says so."),
    SettingSpec(TIMELINE_ROWS, 2000, _whole(100, 50000, "rows"),
                "The most rows the export's HTML report shows in its timeline; the full events are in the "
                "bundle either way."),
):
    settings_store.register(_spec)


def get(key: str, data_dir) -> Any:
    return settings_store.get(key, data_dir=data_dir)
