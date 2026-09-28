"""
Kratos-side resolution of a caller-supplied time bound (``since``/``until``) to an
absolute UTC instant, so the monitored target is only ever sent an absolute epoch
(``journalctl --since @<epoch>``) -- never a relative string the TARGET would
interpret against its own clock and timezone.

This is step 1 of docs/time_window_design.md (the full resolver -- structured
intents, ambiguity detection, named windows -- is step 2 and will build on the
conventions fixed here):

- minutes/hours/seconds are exact ELAPSED time, computed on UTC epochs. (Python's
  aware-datetime subtraction within one zone is wall-clock arithmetic and silently
  gains/loses the DST hour -- never used here for elapsed units.)
- days/weeks are the same local WALL-CLOCK time N days earlier, in Kratos's
  display timezone (``timeutil.resolve_display_tz``).
- ``today``/``yesterday`` are local midnights in the display timezone.
- a date/time with no UTC offset is local wall-clock time in the display timezone.
- months/years, vague words ("recently", "a few days ago") and anything in the
  future are REJECTED with an explanation rather than guessed -- a rejected value
  costs the model one corrected retry; a silently guessed one costs a wrong answer.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo

from kratos.utils.timeutil import resolve_display_tz

ACCEPTED_FORMATS = (
    "'<N> minutes|hours|days|weeks ago' (also '-<N>h' / '-<N> days'), 'today', 'yesterday', "
    "'now', an ISO date/time such as '2026-07-05' or '2026-07-05 14:00' (no offset = Kratos's "
    "configured display timezone) or with an offset ('2026-07-05T14:00:00Z'), or '@<unix epoch>'"
)

# Clock-skew tolerance for "is this in the future?" -- a bound a few seconds ahead of
# Kratos's own clock is a normal race, not a request for future data.
_FUTURE_TOLERANCE_SECONDS = 60

_UNIT_SECONDS = {"second": 1, "minute": 60, "hour": 3600}
_UNIT_ALIASES = {
    "s": "second", "sec": "second", "secs": "second", "second": "second", "seconds": "second",
    "m": "minute", "min": "minute", "mins": "minute", "minute": "minute", "minutes": "minute",
    "h": "hour", "hr": "hour", "hrs": "hour", "hour": "hour", "hours": "hour",
    "d": "day", "day": "day", "days": "day",
    "w": "week", "wk": "week", "wks": "week", "week": "week", "weeks": "week",
}
_REJECTED_UNITS = {"month", "months", "mo", "year", "years", "y", "yr", "yrs"}

_RELATIVE_RE = re.compile(r"^(?:-\s*(\d+)\s*([a-z]+)|(\d+)\s*([a-z]+)\s+ago)$")
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class TimeBoundError(ValueError):
    """A since/until value that can't be resolved safely. The message is written
    to be shown to the model verbatim so it can correct its own tool call."""


def resolve_time_bound(value: str, *, now: datetime | None = None, tz: tzinfo | None = None) -> float:
    """Resolve one ``since``/``until`` value to a UTC epoch (float seconds).

    ``now`` (aware) and ``tz`` exist for tests; production callers pass neither.
    Raises TimeBoundError for anything ambiguous, unsupported, or in the future.
    """
    if not isinstance(value, str) or not value.strip():
        raise TimeBoundError(f"empty time value; use one of: {ACCEPTED_FORMATS}")
    tz = tz or resolve_display_tz()
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    raw = value.strip()
    text = raw.lower()

    epoch = _resolve(raw, text, now_utc, tz)
    if epoch > now_utc.timestamp() + _FUTURE_TOLERANCE_SECONDS:
        raise TimeBoundError(
            f"{raw!r} is in the future -- only past activity can be investigated"
        )
    return epoch


def _resolve(raw: str, text: str, now_utc: datetime, tz: tzinfo) -> float:
    if text == "now":
        return now_utc.timestamp()
    if text.startswith("@"):
        try:
            return float(text[1:])
        except ValueError:
            raise TimeBoundError(f"{raw!r} is not a valid '@<unix epoch>' value") from None
    if text in ("today", "yesterday"):
        local_now = now_utc.astimezone(tz)
        day = local_now.date() - timedelta(days=1 if text == "yesterday" else 0)
        return datetime(day.year, day.month, day.day, tzinfo=tz).timestamp()

    m = _RELATIVE_RE.match(text)
    if m:
        amount = int(m.group(1) or m.group(3))
        unit_word = m.group(2) or m.group(4)
        if unit_word in _REJECTED_UNITS:
            raise TimeBoundError(
                f"{raw!r}: months/years have no fixed length -- give the span in days "
                "(e.g. '30 days ago') or as a date ('2026-07-01')"
            )
        unit = _UNIT_ALIASES.get(unit_word)
        if unit is None:
            raise TimeBoundError(f"{raw!r}: unknown time unit {unit_word!r}; use one of: {ACCEPTED_FORMATS}")
        if unit in _UNIT_SECONDS:  # elapsed time -- epoch arithmetic, DST-proof
            return now_utc.timestamp() - amount * _UNIT_SECONDS[unit]
        # days/weeks: same local wall-clock time N days earlier
        days = amount * (7 if unit == "week" else 1)
        local_naive = now_utc.astimezone(tz).replace(tzinfo=None) - timedelta(days=days)
        return local_naive.replace(tzinfo=tz).timestamp()

    iso = raw.replace(" ", "T", 1) if " " in raw and not _ISO_DATE_RE.match(raw) else raw
    if iso.endswith(("Z", "z")):
        iso = iso[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        raise TimeBoundError(f"could not understand {raw!r}; use one of: {ACCEPTED_FORMATS}") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz)
    return parsed.timestamp()


def epoch_to_iso_utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")
