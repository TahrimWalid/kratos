"""
The one place Kratos turns a time *intent* into exact instants
(docs/time_window_design.md §1-§2B).

The model never computes a timestamp. It (or the deterministic phrase parser in
`timewin.phrases`) produces a small structured TimeIntent; `resolve_intent` turns that
into a `TimeWindow` -- half-open `[start, end)` in UTC -- using conventions fixed here and
tested in tests/test_timewin_*:

- minutes/hours: exact ELAPSED time, computed on UTC epochs (aware-datetime arithmetic
  within one zone is wall-clock arithmetic in Python and silently gains/loses the DST
  hour -- see E11).
- days/weeks/months (rolling): the same local WALL-CLOCK time N units earlier; months
  clamp to the target month's length (Mar 31 - 1 month = Feb 28/29).
- calendar units: local midnight boundaries in the user's timezone; weeks start Monday.
- a local time that does not exist (DST spring-forward gap) shifts FORWARD to the first
  valid instant; an ambiguous one (fall-back repeat) takes the EARLIER instant. Both are
  recorded in `TimeWindow.notes` so they are disclosed, never silent.
- any window reaching into the future is rejected (`TimeIntentError`), never clamped.

`TimeContext` holds one investigation's anchor "now" (captured once, so every tool call
in a run agrees), the user's timezone, the windows resolved so far (ids w1, w2, ...) and
named windows. `current_context()` lets tools reach it without threading it through
every call signature (same pattern as kratos_config.get_active_target()).
"""
from __future__ import annotations

import calendar
import contextvars
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any

UTC = timezone.utc

ROLLING_UNITS = ("minute", "hour", "day", "week", "month")
CALENDAR_UNITS = ("day", "week", "month", "year")
INTENT_KINDS = ("rolling", "calendar", "local_range", "local_since", "relative_to", "ago_range",
                "named", "id", "epoch", "ambiguous")

# A bound a few seconds past "now" is a clock race, not a request for future data.
_FUTURE_TOLERANCE_SECONDS = 60.0
_NAME_RE = re.compile(r"^[a-z][a-z0-9_ -]{0,40}$")


class TimeIntentError(ValueError):
    """An intent that can't be resolved safely. Messages are shown to the model
    verbatim so it can correct its own call."""


@dataclass
class TimeWindow:
    id: str
    start_utc: float
    end_utc: float
    tz: str
    label: str
    intent: dict[str, Any]
    anchor_now: float
    phrase: str | None = None
    name: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def seconds(self) -> float:
        return self.end_utc - self.start_utc

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["start_iso"] = iso_utc(self.start_utc)
        d["end_iso"] = iso_utc(self.end_utc)
        return d

    def summary(self) -> str:
        """One human line -- what the TUI/CLI window chip shows."""
        tz = _zone(self.tz)
        s = datetime.fromtimestamp(self.start_utc, tz)
        e = datetime.fromtimestamp(self.end_utc, tz)
        span = f"{s:%Y-%m-%d %H:%M} → {e:%Y-%m-%d %H:%M} ({self.tz})"
        extra = f" · {'; '.join(self.notes)}" if self.notes else ""
        return f"{self.id} {self.label}: {span}{extra}"


def iso_utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds")


def _zone(name: str) -> tzinfo:
    if name in ("UTC", "Etc/UTC"):
        return UTC
    from zoneinfo import ZoneInfo

    return ZoneInfo(name)


def zone_name(tz: tzinfo) -> str:
    return getattr(tz, "key", None) or ("UTC" if tz in (UTC,) else str(tz))


# ---------------------------------------------------------------------------
# Wall-clock -> instant, with explicit DST gap/repeat handling
# ---------------------------------------------------------------------------
def localize(naive: datetime, tz: tzinfo) -> tuple[float, str | None]:
    """Epoch for local wall time `naive` in `tz`, plus a disclosure note when the wall
    time falls in a DST gap (shifted forward) or repeat (earlier instant taken)."""
    first = naive.replace(tzinfo=tz, fold=0)
    second = naive.replace(tzinfo=tz, fold=1)
    e0, e1 = first.timestamp(), second.timestamp()
    if e0 == e1:
        return e0, None
    back0 = datetime.fromtimestamp(e0, tz).replace(tzinfo=None)
    if back0 == naive:
        # Real repeat (fall back): both instants are valid wall-clock readings.
        return min(e0, e1), f"{naive:%Y-%m-%d %H:%M} occurs twice (DST ends); used the earlier one"
    # Gap (spring forward): the wall time never happened. First valid instant is the
    # transition itself, which lies between the two fold interpretations.
    lo, hi = sorted((e0, e1))
    while hi - lo > 1:
        mid = (lo + hi) / 2
        if datetime.fromtimestamp(mid, tz).utcoffset() == datetime.fromtimestamp(lo, tz).utcoffset():
            lo = mid
        else:
            hi = mid
    return float(int(hi)), f"{naive:%Y-%m-%d %H:%M} does not exist (DST starts); used the first valid time"


def _local_midnight(d: date, tz: tzinfo) -> tuple[float, str | None]:
    return localize(datetime(d.year, d.month, d.day), tz)


def _shift_months(naive: datetime, months: int) -> datetime:
    m = naive.month - 1 + months
    y = naive.year + m // 12
    m = m % 12 + 1
    return naive.replace(year=y, month=m, day=min(naive.day, calendar.monthrange(y, m)[1]))


def _parse_local(value: str, what: str, tz: tzinfo | None = None) -> tuple[datetime, bool]:
    """(naive local datetime, is_date_only) for an intent's local wall-clock bound.
    Offsets are the code's job: a model that writes '10:00Z' for the user's local 10am
    would silently shift the window. The one exception is an offset EQUAL to the user's
    own zone offset at that time (e.g. 'Z' when the user's zone is UTC) -- wall clock and
    instant agree, nothing can shift (seen live: refusing that cost the model two steps)."""
    if not isinstance(value, str) or not value.strip():
        raise TimeIntentError(f"{what} must be a local date/time string like '2026-07-05' or '2026-07-05T14:00'")
    v = value.strip().replace(" ", "T", 1)
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            return datetime.fromisoformat(v), True
        parsed = datetime.fromisoformat(v)
    except ValueError:
        raise TimeIntentError(f"{what} {value!r} is not an ISO date/time (use YYYY-MM-DD or YYYY-MM-DDTHH:MM)") from None
    if parsed.tzinfo is not None and tz is not None:
        naive = parsed.replace(tzinfo=None)
        if parsed.utcoffset() == naive.replace(tzinfo=tz).utcoffset():
            return naive, False
    if parsed.tzinfo is not None:
        raise TimeIntentError(f"{what} {value!r}: give LOCAL wall-clock time without an offset; "
                              "Kratos applies the user's timezone itself")
    return parsed, False


# ---------------------------------------------------------------------------
# Intent -> window
# ---------------------------------------------------------------------------
def resolve_intent(intent: dict[str, Any], ctx: "TimeContext") -> tuple[float, float, str, list[str]]:
    """(start_epoch, end_epoch, label, notes) for one intent. Pure given ctx.now/tz."""
    if not isinstance(intent, dict):
        raise TimeIntentError("a time window must be a JSON object like "
                              '{"kind": "rolling", "amount": 24, "unit": "hour"} or {"id": "w1"}')
    kind = intent.get("kind")
    if kind is None and "id" in intent:
        kind = "id"
    if kind is None and "name" in intent and len(intent) <= 2:
        kind = "named"
    if kind not in INTENT_KINDS:
        raise TimeIntentError(f"unknown window kind {kind!r}; use one of {', '.join(INTENT_KINDS[:-1])}")
    tz, now = ctx.tz, ctx.now
    now_local = datetime.fromtimestamp(now, tz).replace(tzinfo=None)
    notes: list[str] = []

    def note(n: str | None) -> None:
        if n:
            notes.append(n)

    if kind == "ambiguous":
        raise TimeIntentError(f"ambiguous time reference: {intent.get('reason') or 'unspecified'} -- ask the user")

    if kind in ("id", "named"):
        w = ctx.get(intent.get("id") or intent.get("name"))
        return w.start_utc, w.end_utc, w.label, list(w.notes)

    if kind == "epoch":
        try:
            start, end = float(intent["start"]), float(intent["end"]) if intent.get("end") is not None else now
        except (KeyError, TypeError, ValueError):
            raise TimeIntentError("an epoch window needs numeric 'start' (and optional 'end')") from None
        return start, end, f"{iso_utc(start)} to {iso_utc(end)}", notes

    if kind == "ago_range":  # e.g. "the hour starting 3 hours ago": exact elapsed bounds
        unit, a, b = intent.get("unit"), intent.get("from"), intent.get("to")
        if unit not in ("minute", "hour") or not all(isinstance(x, int) and not isinstance(x, bool) for x in (a, b)) \
                or not (a > b >= 0):
            raise TimeIntentError('ago_range needs {"from": N, "to": M, "unit": "minute|hour"} with N > M >= 0')
        sec = 60 if unit == "minute" else 3600
        return now - a * sec, now - b * sec, f"{a} to {b} {unit}s ago", notes

    if kind == "rolling":
        unit = intent.get("unit")
        amount = intent.get("amount")
        if unit not in ROLLING_UNITS:
            raise TimeIntentError(f"rolling unit must be one of {ROLLING_UNITS}, got {unit!r}")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise TimeIntentError(f"rolling amount must be a positive whole number, got {amount!r}")
        if unit in ("minute", "hour"):
            start = now - amount * (60 if unit == "minute" else 3600)
        else:
            naive = (_shift_months(now_local, -amount) if unit == "month"
                     else now_local - timedelta(days=amount * (7 if unit == "week" else 1)))
            start, n = localize(naive, tz)
            note(n)
        return start, now, f"last {amount} {unit}{'s' if amount != 1 else ''}", notes

    if kind == "calendar":
        unit = intent.get("unit")
        offset = intent.get("offset", 0)
        if unit not in CALENDAR_UNITS:
            raise TimeIntentError(f"calendar unit must be one of {CALENDAR_UNITS}, got {unit!r}")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset > 0:
            raise TimeIntentError("calendar offset must be 0 (current) or negative (-1 = previous); "
                                  "future periods cannot be investigated")
        today = now_local.date()
        if unit == "day":
            first = today + timedelta(days=offset)
            nxt = first + timedelta(days=1)
            label = {0: "today", -1: "yesterday"}.get(offset, f"{first:%a %Y-%m-%d}")
        elif unit == "week":
            first = today - timedelta(days=today.weekday()) + timedelta(weeks=offset)
            nxt = first + timedelta(days=7)
            label = {0: "this week", -1: "last calendar week"}.get(offset, f"week of {first:%Y-%m-%d}")
        elif unit == "month":
            m0 = _shift_months(datetime(today.year, today.month, 1), offset)
            first = m0.date()
            nxt = _shift_months(m0, 1).date()
            label = {0: "this month"}.get(offset, f"{first:%B %Y}")
        else:
            first = date(today.year + offset, 1, 1)
            nxt = date(today.year + offset + 1, 1, 1)
            label = {0: "this year"}.get(offset, str(first.year))
        start, n1 = _local_midnight(first, tz)
        end, n2 = _local_midnight(nxt, tz)
        note(n1)
        note(n2)
        if intent.get("to_now") or end > now:
            if end > now:
                label += " so far"
            end = now
        return start, end, label, notes

    if kind == "local_since":
        naive, _ = _parse_local(intent.get("start"), "start", tz)
        start, n = localize(naive, tz)
        note(n)
        return start, now, f"since {naive:%Y-%m-%d %H:%M}", notes

    if kind == "local_range":
        s_naive, _ = _parse_local(intent.get("start"), "start", tz)
        e_naive, e_date_only = _parse_local(intent.get("end"), "end", tz)
        if e_date_only:
            # Date-granularity end is INCLUSIVE of that whole day (design §2C default).
            e_naive = e_naive + timedelta(days=1)
            notes.append(f"end date {e_naive - timedelta(days=1):%Y-%m-%d} included in full")
        start, n1 = localize(s_naive, tz)
        end, n2 = localize(e_naive, tz)
        note(n1)
        note(n2)
        return start, end, f"{s_naive:%Y-%m-%d %H:%M} to {e_naive:%Y-%m-%d %H:%M}", notes

    # relative_to: shift an existing window, keeping its length.
    base = ctx.get(intent.get("window") or intent.get("id") or "")
    shift = intent.get("shift") or {}
    amount, unit = shift.get("amount"), shift.get("unit")
    if isinstance(amount, bool) or not isinstance(amount, int) or unit not in ROLLING_UNITS:
        raise TimeIntentError('relative_to needs {"window": "<id>", "shift": {"amount": <int>, '
                              '"unit": "minute|hour|day|week|month"}}')
    if unit in ("minute", "hour"):
        delta = amount * (60 if unit == "minute" else 3600)
        return base.start_utc + delta, base.end_utc + delta, f"{base.label} shifted {amount} {unit}(s)", notes
    b_start = datetime.fromtimestamp(base.start_utc, tz).replace(tzinfo=None)
    b_end = datetime.fromtimestamp(base.end_utc, tz).replace(tzinfo=None)
    if unit == "month":
        s2, e2 = _shift_months(b_start, amount), _shift_months(b_end, amount)
    else:
        d = timedelta(days=amount * (7 if unit == "week" else 1))
        s2, e2 = b_start + d, b_end + d
    start, n1 = localize(s2, tz)
    end, n2 = localize(e2, tz)
    note(n1)
    note(n2)
    return start, end, f"{base.label} shifted {amount} {unit}(s)", notes


# ---------------------------------------------------------------------------
# Per-investigation context
# ---------------------------------------------------------------------------
class TimeContext:
    """Anchor + timezone + the windows resolved in one investigation. Named windows
    persist across turns when `store_path` is given (a per-session JSON file)."""

    def __init__(self, tz: tzinfo, now: float | None = None, store_path: Path | None = None):
        self.tz = tz
        self.tz_name = zone_name(tz)
        self.now = float(now if now is not None else datetime.now(UTC).timestamp())
        self.windows: dict[str, TimeWindow] = {}
        self.named: dict[str, TimeWindow] = {}
        # window id -> tools that actually queried it (time-scope guard, claims)
        self.queried: dict[str, set[str]] = {}
        # goal phrases that need the user (status "ask") or refer to the future
        self.unresolved: list[dict[str, Any]] = []
        # ids of windows resolved from the investigation goal itself
        self.goal_ids: list[str] = []
        # window id -> exhaustive measurement summary (timewin.claims.METRICS values,
        # coverage percent, every integer the tool reported) -- what Guard 7 verifies against
        self.measurements: dict[str, dict[str, Any]] = {}
        # window id -> the full timewin.measure.Measurement (comparisons reuse it)
        self.measurement_objects: dict[str, Any] = {}
        self.store_path = store_path
        self._load_named()

    # -- lookup -------------------------------------------------------------
    def get(self, key: str) -> TimeWindow:
        if not key:
            raise TimeIntentError("missing window id/name")
        if key in self.windows:
            return self.windows[key]
        name = key.strip().lower()
        if name in self.named:
            return self.named[name]
        known = sorted(self.windows) + sorted(self.named)
        raise TimeIntentError(f"unknown window {key!r}; known: {', '.join(known) or 'none yet'}")

    # -- resolution ---------------------------------------------------------
    def resolve(self, intent: dict[str, Any], *, phrase: str | None = None, name: str | None = None,
                allow_future: bool = False) -> TimeWindow:
        if isinstance(intent, dict) and intent.get("kind") in (None, "id") and intent.get("id") in self.windows:
            existing = self.windows[intent["id"]]
            if name:
                self.name(existing.id, name)
            return existing
        start, end, label, notes = resolve_intent(intent, self)
        if end <= start:
            raise TimeIntentError(f"window {label!r} is empty or inverted (start must be before end)")
        if not allow_future and end > self.now + _FUTURE_TOLERANCE_SECONDS:
            raise TimeIntentError(f"window {label!r} reaches into the future -- only past activity can be investigated")
        for w in self.windows.values():  # same window twice -> same id (stable references)
            if abs(w.start_utc - start) < 1 and abs(w.end_utc - end) < 1:
                if name:
                    self.name(w.id, name)
                return w
        wid = f"w{len(self.windows) + 1}"
        w = TimeWindow(id=wid, start_utc=start, end_utc=end, tz=self.tz_name, label=label,
                       intent=dict(intent), anchor_now=self.now, phrase=phrase, notes=notes)
        self.windows[wid] = w
        if name:
            self.name(wid, name)
        return w

    def name(self, wid: str, name: str) -> TimeWindow:
        key = name.strip().lower()
        if not _NAME_RE.fullmatch(key):
            raise TimeIntentError(f"window name {name!r} must be a short lowercase label")
        if re.fullmatch(r"w\d+", key):
            if key == wid:
                # A model "naming" window w1 as "w1" (seen live): harmless, nothing to save --
                # failing the tool call for it only showed the user a red error.
                return self.get(wid)
            # live run: a model saved a window as "w2", colliding with Kratos's own ids
            raise TimeIntentError(f"window name {name!r} looks like a window id; pick a descriptive "
                                  "name such as 'incident' or 'baseline'")
        w = self.get(wid)
        w.name = key
        self.named[key] = w
        self._save_named()
        return w

    # -- persistence of named windows (absolute bounds, so a resumed session
    #    never re-interprets yesterday's "today") -----------------------------
    def _load_named(self) -> None:
        if not self.store_path or not self.store_path.exists():
            return
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for key, d in (data.get("named") or {}).items():
            try:
                self.named[key] = TimeWindow(
                    id=f"named:{key}", start_utc=float(d["start_utc"]), end_utc=float(d["end_utc"]),
                    tz=d.get("tz") or self.tz_name, label=d.get("label") or key, intent={"kind": "named", "name": key},
                    anchor_now=float(d.get("anchor_now") or d["end_utc"]), name=key, notes=list(d.get("notes") or []),
                )
            except (KeyError, TypeError, ValueError):
                continue

    def _save_named(self) -> None:
        if not self.store_path:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"named": {k: {"start_utc": w.start_utc, "end_utc": w.end_utc, "tz": w.tz, "label": w.label,
                                 "anchor_now": w.anchor_now, "notes": w.notes} for k, w in self.named.items()}}
        tmp = self.store_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.store_path)

    def describe(self) -> list[dict[str, Any]]:
        return [w.as_dict() for w in self.windows.values()]


_CURRENT: contextvars.ContextVar[TimeContext | None] = contextvars.ContextVar("kratos_time_context", default=None)


def current_context() -> TimeContext | None:
    return _CURRENT.get()


def set_current_context(ctx: TimeContext | None) -> contextvars.Token:
    return _CURRENT.set(ctx)


def reset_current_context(token: contextvars.Token) -> None:
    _CURRENT.reset(token)
