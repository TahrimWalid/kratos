"""The `trace.*` settings (Settings -> General -> Run records)."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

ENABLED = "trace.enabled"
MAX_RESULT_BYTES = "trace.max_result_bytes"
STORE_PROMPTS = "trace.store_prompts"
OTEL_EXPORT = "trace.otel_export"


def _on_off(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("on", "yes", "true", "1"):
        return True
    if text in ("off", "no", "false", "0"):
        return False
    raise SettingError("on or off")


def _bytes(value: Any) -> int:
    lo, hi = 1024, 64 * 1024 * 1024
    if isinstance(value, bool):
        raise SettingError(f"a whole number of bytes, {lo:,}-{hi:,}")
    try:
        n = int(str(value).strip()) if not isinstance(value, (int, float)) else int(value)
    except (TypeError, ValueError):
        raise SettingError(f"a whole number of bytes, {lo:,}-{hi:,}") from None
    if isinstance(value, float) and n != value or not lo <= n <= hi:
        raise SettingError(f"a whole number of bytes, {lo:,}-{hi:,}")
    return n


for _spec in (
    SettingSpec(ENABLED, True, _on_off,
                "Write a run record (trace) for every investigation, audit, scheduled run and trigger. "
                "Turn off only to measure what recording costs."),
    SettingSpec(MAX_RESULT_BYTES, 256 * 1024, _bytes,
                "The most of one tool result a run record keeps; a larger result keeps its start and a "
                "fingerprint (sha256) of the whole."),
    SettingSpec(STORE_PROMPTS, False, _on_off,
                "Also keep the full text sent to the model in run records (for debugging; large)."),
    SettingSpec(OTEL_EXPORT, False, _on_off,
                "Also send each run record's timings and token counts (never tool results or prompts) to your "
                "own OpenTelemetry collector at OTEL_EXPORTER_OTLP_ENDPOINT. Needs the 'otel' extra."),
):
    settings_store.register(_spec)
