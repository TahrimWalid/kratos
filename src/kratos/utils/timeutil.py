"""
Timezone-correct time handling for Kratos -- the single, shared place that
separates *when things actually happened* (storage) from *how they're shown*
(display), so nothing breaks when the user's physical location changes
between sessions.

The load-bearing rule: every timestamp Kratos records or reasons about is an
absolute UTC instant. Storage helpers here (utc_now_iso, epoch_to_utc_iso)
produce tz-aware UTC ISO strings; parse_stored_instant reads any stored value
back as a tz-aware UTC datetime, so a relative-time computation ("what
happened 2 hours ago") is always a comparison between two unambiguous UTC
instants -- correct regardless of what timezone the querying session happens
to be in.

Display is a separate, purely-cosmetic layer: resolve_display_tz() picks the
zone to render in (explicit override > auto-detected system local zone >
UTC), and format_for_display()/now_for_display() convert a stored UTC instant
into that zone for humans. Changing the display zone never touches stored
data, so an event recorded in Helsinki still renders correctly after the user
flies to Dhaka -- it's the same UTC instant, shown in a different zone.

No network dependency anywhere: local-zone detection reads only the OS's own
timezone setting via the standard library.

Backward compatibility: values written before UTC-storage existed are naive
(no offset). parse_stored_instant treats a naive value as the recording
machine's local time (best effort -- the original zone can't be recovered
from the string alone), so on the same machine such legacy values keep
displaying at the same wall-clock they always did; only genuinely relocated
legacy data can drift, which is unrecoverable regardless.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Any

try:  # zoneinfo is stdlib on 3.9+, which this project targets.
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover - defensive only
    ZoneInfo = None  # type: ignore[assignment]

    class ZoneInfoNotFoundError(Exception):  # type: ignore[no-redef]
        pass


# ---------------------------------------------------------------------------
# Storage side -- always UTC, always tz-aware.
# ---------------------------------------------------------------------------
def utc_now() -> datetime:
    """The current instant, tz-aware in UTC. Use instead of datetime.now()
    (which returns a naive value in the machine's local zone) for anything
    that gets stored or compared."""
    return datetime.now(timezone.utc)


def utc_now_iso(timespec: str = "seconds") -> str:
    """Current UTC instant as an ISO-8601 string carrying an explicit
    `+00:00` offset -- the presence of that offset is what lets
    parse_stored_instant tell a new UTC-stored value apart from a legacy
    naive one."""
    return utc_now().isoformat(timespec=timespec)


def epoch_to_utc_iso(epoch_seconds: float, timespec: str = "seconds") -> str:
    """Convert a Unix epoch (e.g. journald's __REALTIME_TIMESTAMP, which is
    an absolute UTC instant regardless of the source host's own timezone)
    into a UTC ISO string. This is the correct conversion for any epoch
    value; the previous datetime.fromtimestamp() (no tz) silently rebased it
    onto the Kratos host's local zone and stored it naive."""
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat(timespec=timespec)


def parse_stored_instant(value: Any) -> datetime | None:
    """Read a stored timestamp back as a tz-aware UTC datetime.

    - Accepts a datetime or an ISO string. Returns None for empty/unparseable
      input (callers fall back to showing the raw value).
    - A tz-aware value (the new UTC-stored form) is normalized to UTC.
    - A naive value (legacy, pre-UTC-storage) is interpreted as the local
      system time it was almost certainly written in, then normalized to UTC
      -- best effort, since the original zone isn't recorded in the string.
    """
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except (ValueError, TypeError):
            return None
    if dt.tzinfo is None:
        # astimezone() on a naive datetime presumes it is in the system
        # local zone and attaches that zone -- exactly the legacy assumption
        # we want (the value was written by datetime.now() on this machine).
        dt = dt.astimezone()
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Display side -- cosmetic only, never touches stored data.
# ---------------------------------------------------------------------------
_OVERRIDE_CONFIG_KEY = "display_timezone"


def zone_from_name(name: str | None) -> tzinfo | None:
    """Resolve a timezone name (e.g. "UTC", "Europe/Helsinki",
    "Asia/Dhaka") to a tzinfo, or None if it isn't a real zone. "UTC" is
    handled without needing the tz database installed."""
    if not name:
        return None
    if name.upper() == "UTC":
        return timezone.utc
    if ZoneInfo is None:
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def detect_local_tz() -> tzinfo | None:
    """The OS's own local timezone, read with zero network access. Returns
    None only if even the system-local zone can't be determined (a genuinely
    misconfigured/minimal environment -- rare), which is what gates the
    one-time manual-entry fallback in the REPL."""
    try:
        local = datetime.now().astimezone().tzinfo
    except (ValueError, OSError):  # pragma: no cover - defensive only
        return None
    return local


def local_tz_name() -> str | None:
    """A human-readable name for the detected local zone (an IANA key like
    "Asia/Dhaka" when available, else a short offset name like "+06"), or
    None if detection failed."""
    tz = detect_local_tz()
    if tz is None:
        return None
    key = getattr(tz, "key", None)  # ZoneInfo exposes .key; fixed-offset tz doesn't.
    if key:
        return key
    try:
        return datetime.now().astimezone().tzname()
    except (ValueError, OSError):  # pragma: no cover - defensive only
        return None


def _read_override(data_dir: Path | None) -> str | None:
    if data_dir is None:
        return None
    # Imported lazily to avoid any import-order coupling with kratos_config.
    from kratos.kratos_config import load_local_config

    value = load_local_config(data_dir).get(_OVERRIDE_CONFIG_KEY)
    return value if isinstance(value, str) and value.strip() else None


def display_tz_status(data_dir: Path | None = None) -> tuple[str, tzinfo]:
    """Resolve the display zone AND say how it was resolved, so the REPL can
    decide whether the rare manual-entry fallback prompt is warranted.

    Returns (source, tz) where source is:
      - "override"  : a user-configured fixed display zone (setting #5)
      - "auto"      : the auto-detected system local zone (the normal case)
      - "fallback"  : detection genuinely failed -> defaulted to UTC (#4)
    """
    override = _read_override(data_dir)
    if override:
        tz = zone_from_name(override)
        if tz is not None:
            return "override", tz
        # A stored override that no longer resolves (e.g. a renamed zone)
        # shouldn't wedge display -- fall through to auto-detection.
    local = detect_local_tz()
    if local is not None:
        return "auto", local
    return "fallback", timezone.utc


def resolve_display_tz(data_dir: Path | None = None) -> tzinfo:
    """Just the zone to render in -- override > system local > UTC."""
    return display_tz_status(data_dir)[1]


def set_display_timezone_override(data_dir: Path, name: str | None) -> None:
    """Persist (setting #5) or clear a fixed display-zone override. `name`
    is a zone name to pin, or None/"" to revert to auto-detection."""
    from kratos.kratos_config import _local_config_path, load_local_config, save_local_config

    if name and name.strip():
        save_local_config(data_dir, **{_OVERRIDE_CONFIG_KEY: name.strip()})
    else:
        # Clear the key without disturbing the rest of the local config
        # (save_local_config only ever merges, it can't remove a key). Reuses
        # kratos_config's own path resolver so the filename isn't duplicated.
        config = load_local_config(data_dir)
        if _OVERRIDE_CONFIG_KEY in config:
            del config[_OVERRIDE_CONFIG_KEY]
            _local_config_path(data_dir).write_text(json.dumps(config, indent=2), encoding="utf-8")


def format_for_display(
    value: Any,
    fmt: str = "%H:%M",
    data_dir: Path | None = None,
    tz: tzinfo | None = None,
) -> str:
    """Render a stored UTC instant in the display zone. Pass an already-
    resolved `tz` to avoid re-resolving it per call in a tight render loop;
    otherwise the zone is resolved from `data_dir`. Falls back to the raw
    string if the value can't be parsed, never raising into a render path."""
    dt = parse_stored_instant(value)
    if dt is None:
        return str(value) if value not in (None, "") else ""
    zone = tz or resolve_display_tz(data_dir)
    return dt.astimezone(zone).strftime(fmt)


def now_for_display(
    fmt: str = "%H:%M",
    data_dir: Path | None = None,
    tz: tzinfo | None = None,
) -> str:
    """The current instant rendered in the display zone -- for live
    (as-it-happens) timestamps. Equivalent to format_for_display(utc_now())
    but skips the parse round-trip."""
    zone = tz or resolve_display_tz(data_dir)
    return utc_now().astimezone(zone).strftime(fmt)
