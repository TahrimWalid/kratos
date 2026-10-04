"""
Deterministic detection of time expressions in text (docs/time_window_design.md §2C).

Why this exists: the validation experiment (E10) showed models silently GUESS on
ambiguous phrases ("03/04", "between Feb 20 and Feb 25", "a couple of days ago") -- they
flagged ambiguity once in ten chances. So ambiguity handling is code, not model judgment.

`find_time_phrases(text, now_local)` returns every recognized expression as a
`PhraseMatch` with one of four statuses:

- ``resolved`` -- one correct reading; `intent` is the TimeIntent to resolve.
- ``default``  -- a documented default applies (e.g. "a couple of" = 2, "last week" =
  rolling 7 days); `intent` is set and `note` says what was assumed, so it is always
  disclosed to the user, never silent.
- ``ask``      -- readings differ materially and no safe default exists (numeric dates
  like 03/04, "last Friday" said on a Friday, "N hours ago" as a point); `options` lists
  the candidate intents for a clarifying question.
- ``future``   -- the phrase refers to the future ("tomorrow", "next week"); cannot be
  investigated.

Intents use the `timewin.windows` schema; absolute dates are emitted as explicit
`local_range`/`local_since` wall-clock bounds so they resolve in the user's timezone.
Pure functions -- `now_local` is a naive wall-clock datetime in the user's zone.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

MONTHS = {m.lower(): i for i, m in enumerate(
    ["January", "February", "March", "April", "May", "June", "July", "August", "September",
     "October", "November", "December"], 1)}
MONTHS.update({k[:3]: v for k, v in list(MONTHS.items())})
MONTHS["sept"] = 9
WEEKDAYS = {d: i for i, d in enumerate(["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"])}
WEEKDAYS.update({k[:3]: v for k, v in list(WEEKDAYS.items())})
NUMBER_WORDS = {"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
                "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "twenty-four": 24,
                "twenty four": 24, "thirty": 30}
FUZZY = {"couple of": 2, "a couple of": 2, "couple": 2, "few": 3, "a few": 3, "several": 5}
UNIT_ALIASES = {"min": "minute", "mins": "minute", "minute": "minute", "minutes": "minute",
                "hr": "hour", "hrs": "hour", "hour": "hour", "hours": "hour",
                "day": "day", "days": "day", "week": "week", "weeks": "week", "wk": "week", "wks": "week",
                "month": "month", "months": "month", "year": "year", "years": "year"}
DAY_PARTS = {"morning": (6, 12), "afternoon": (12, 18), "evening": (18, 24)}

_MONTH_RE = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
_WEEKDAY_RE = r"(?:mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:rs(?:day)?)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?)"
_NUM_RE = r"(?:\d+|a|an|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|twenty[- ]four|thirty)"
_FUZZY_RE = r"(?:a\s+couple\s+of|couple\s+of|a\s+few|few|several)"
_UNIT_RE = r"(?:mins?|minutes?|hrs?|hours?|days?|weeks?|wks?|months?|years?)"
_TIME_RE = r"(?:\d{1,2}(?::\d{2})?\s*(?:am|pm)|\d{1,2}:\d{2}|noon|midnight)"
_ORD = r"(?:st|nd|rd|th)?"
_DATE_RE = (
    rf"(?:\d{{4}}-\d{{2}}-\d{{2}}"
    rf"|{_MONTH_RE}\.?\s+\d{{1,2}}{_ORD}(?:,?\s+\d{{4}})?"
    rf"|\d{{1,2}}{_ORD}\s+(?:of\s+)?{_MONTH_RE}(?:,?\s+\d{{4}})?"
    # numeric: d/m[/y] with slashes, or d.m.yyyy with dots (a dotted pair WITHOUT a year is
    # almost always a version or part of an IP -- "8.9", "10.136.28.5" -- never a date);
    # never adjacent to other digits/dots.
    rf"|(?<![\d./])\d{{1,2}}/\d{{1,2}}(?:/\d{{2,4}})?(?![\d./])"
    rf"|(?<![\d./])\d{{1,2}}\.\d{{1,2}}\.\d{{4}}(?![\d./]))"
)


@dataclass
class PhraseMatch:
    text: str
    start: int
    end: int
    status: str  # resolved | default | ask | future
    intent: dict[str, Any] | None = None
    note: str | None = None
    options: list[dict[str, Any]] = field(default_factory=list)
    pattern: str = ""  # which rule matched (e.g. "date", "rolling_n") -- keep LAST: built positionally


def _num(token: str) -> int:
    token = token.strip().lower()
    if token.isdigit():
        return int(token)
    return NUMBER_WORDS[token]


def _unit(token: str) -> str:
    return UNIT_ALIASES[token.strip().lower().rstrip(".")]


def _day_range(d: date, days: int = 1) -> dict[str, Any]:
    return {"kind": "local_range", "start": d.isoformat(), "end": (d + timedelta(days=days)).isoformat() + "T00:00"}


def _parse_time(tok: str) -> tuple[int, int]:
    t = tok.strip().lower().replace(" ", "")
    if t == "noon":
        return 12, 0
    if t == "midnight":
        return 0, 0
    m = re.fullmatch(r"(\d{1,2})(?::(\d{2}))?(am|pm)?", t)
    if not m:
        raise ValueError(tok)
    h, mi, ap = int(m.group(1)), int(m.group(2) or 0), m.group(3)
    if ap == "pm" and h != 12:
        h += 12
    if ap == "am" and h == 12:
        h = 0
    if not (0 <= h <= 23 and 0 <= mi <= 59):
        raise ValueError(tok)
    return h, mi


def _past_occurrence(month: int, day: int, today: date) -> date:
    year = today.year if (month, day) <= (today.month, today.day) else today.year - 1
    return date(year, month, day)


def _parse_date(tok: str, today: date, date_order: str | None) -> tuple[list[date], str | None]:
    """Candidate dates for a date token (more than one = ambiguous), plus a note."""
    t = tok.strip().lower().replace(",", "")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", t):
        return [date.fromisoformat(t)], None
    m = re.fullmatch(rf"({_MONTH_RE})\.?\s+(\d{{1,2}}){_ORD}(?:\s+(\d{{4}}))?", t)
    if m:
        mon, day = MONTHS[m.group(1)[:4] if m.group(1).startswith("sept") else m.group(1)[:3]], int(m.group(2))
        if m.group(3):
            return [date(int(m.group(3)), mon, day)], None
        d = _past_occurrence(mon, day, today)
        return [d], (f"no year given: took the most recent {d:%b %d} ({d.year})" if d.year != today.year else None)
    m = re.fullmatch(rf"(\d{{1,2}}){_ORD}\s+(?:of\s+)?({_MONTH_RE})(?:\s+(\d{{4}}))?", t)
    if m:
        day, mon = int(m.group(1)), MONTHS[m.group(2)[:3]]
        if m.group(3):
            return [date(int(m.group(3)), mon, day)], None
        d = _past_occurrence(mon, day, today)
        return [d], (f"no year given: took the most recent {d:%b %d} ({d.year})" if d.year != today.year else None)
    m = re.fullmatch(r"(\d{1,2})[/.](\d{1,2})(?:[/.](\d{2,4}))?", t)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        year = m.group(3)
        cands: list[tuple[int, int]] = []
        if date_order == "dmy":
            cands = [(b, a)]
        elif date_order == "mdy":
            cands = [(a, b)]
        else:
            for mon, day in ((a, b), (b, a)):
                if 1 <= mon <= 12 and 1 <= day <= 31 and (mon, day) not in cands:
                    cands.append((mon, day))
        out = []
        for mon, day in cands:
            try:
                if year:
                    y = int(year) + (2000 if len(year) == 2 else 0)
                    out.append(date(y, mon, day))
                else:
                    out.append(_past_occurrence(mon, day, today))
            except ValueError:
                continue
        return out, None
    raise ValueError(tok)


def _weekday_before(target: int, today: date, include_today: bool) -> date:
    back = (today.weekday() - target) % 7
    if back == 0 and not include_today:
        back = 7
    return today - timedelta(days=back)


# ---------------------------------------------------------------------------
# Pattern table -- ORDER MATTERS: longer/more specific first; overlaps are resolved
# by keeping the earliest-starting, then longest match.
# ---------------------------------------------------------------------------
def _patterns() -> list[tuple[re.Pattern[str], str]]:
    p = [
        (rf"\b(?:(?P<dayb>today|yesterday|on\s+(?P<ondayb>{_DATE_RE}))\s*,?\s+)?(?:between|from)\s+(?P<a>{_DATE_RE}|{_TIME_RE})"
         rf"\s+(?:and|to|until|till|-)\s+(?P<b>{_DATE_RE}|{_TIME_RE})"
         rf"(?:\s+(?P<day>today|yesterday|on\s+(?P<onday>{_DATE_RE})))?", "range"),
        (rf"\b(?:(?P<dayb>today|yesterday|on\s+(?P<ondayb>{_DATE_RE}))\s*,?\s+)?(?P<a>\d{{1,2}}:\d{{2}}|{_TIME_RE})\s*(?:-|–|to|until|till)\s*"
         rf"(?P<b>\d{{1,2}}:\d{{2}}|{_TIME_RE})(?:\s+(?P<day>today|yesterday|on\s+(?P<onday>{_DATE_RE})))?", "range"),
        (rf"\b(?:in|over|during|for|within)?\s*(?:the\s+)?(?:last|past|previous)\s+(?P<fz>{_FUZZY_RE})\s+(?P<u>{_UNIT_RE})\b", "rolling_fuzzy"),
        (rf"\b(?:in|over|during|for|within)?\s*(?:the\s+)?(?:last|past|previous)\s+(?P<n>{_NUM_RE})\s+(?P<u>{_UNIT_RE})\b", "rolling_n"),
        (r"\b(?:in|over|during|for|within)?\s*(?:the\s+)?(?:last|past|previous)\s+(?P<u>hour|day|week|month|year|night)\b", "rolling_1"),
        (rf"\b(?P<fz>{_FUZZY_RE})\s+(?P<u>{_UNIT_RE})\s+ago\b", "ago_fuzzy"),
        (rf"\b(?P<n>{_NUM_RE})\s+(?P<u>{_UNIT_RE})\s+ago\b", "ago_n"),
        (r"\bthe\s+day\s+before\s+yesterday\b", "day_before_yesterday"),
        (r"\b(?P<rel>this|yesterday|today)\s+(?P<part>morning|afternoon|evening)\b", "day_part"),
        (r"\btonight\b", "tonight"),
        (r"\b(?:today|so\s+far\s+today)\b", "today"),
        (r"\byesterday\b", "yesterday"),
        (r"\bthis\s+(?P<u>week|month|year)(?:\s+so\s+far)?\b", "this_period"),
        (r"\bsince\s+(?:the\s+|my\s+|our\s+)?(?:last|previous)\s+(?:run|scan|check|audit|investigation|time\s+(?:I|we)\s+(?:checked|asked|looked))\b", "since_last_run"),
        (rf"\bsince\s+(?:last\s+)?(?P<wd>{_WEEKDAY_RE})\b", "since_weekday"),
        (rf"\bsince\s+(?P<t>{_TIME_RE})\b", "since_time"),
        (rf"\bsince\s+(?P<d>{_DATE_RE})\b", "since_date"),
        (rf"\blast\s+(?P<wd>{_WEEKDAY_RE})\b", "last_weekday"),
        (rf"\b(?:on\s+)(?P<wd>{_WEEKDAY_RE})\b", "on_weekday"),
        (rf"\b(?:in|during|for|throughout)\s+(?P<m>{_MONTH_RE})(?:\s+(?P<y>\d{{4}}))?\b(?!\s+\d)", "month_name"),
        (rf"\b(?:on\s+)?(?P<d>{_DATE_RE})\b", "date"),
        (r"\b(?:tomorrow|next\s+(?:week|month|year|hour|" + _WEEKDAY_RE + r")|in\s+\d+\s+" + _UNIT_RE + r"(?!\s+ago))\b", "future"),
        (r"\brecently\b", "recently"),
        (r"\blately\b", "lately"),
        (r"\ba\s+while\s+(?:ago|back)\b", "vague"),
    ]
    return [(re.compile(rx, re.IGNORECASE), kind) for rx, kind in p]


_PATTERNS = _patterns()


def find_time_phrases(text: str, now_local: datetime, date_order: str | None = None) -> list[PhraseMatch]:
    """Every time expression in `text`, left to right, non-overlapping."""
    found: list[PhraseMatch] = []
    taken: list[tuple[int, int]] = []
    candidates = []
    for rx, kind in _PATTERNS:
        for m in rx.finditer(text):
            candidates.append((m.start(), -(m.end() - m.start()), kind, m))
    for start, _neglen, kind, m in sorted(candidates, key=lambda c: (c[0], c[1])):
        if any(start < e and m.end() > s for s, e in taken):
            continue
        try:
            pm = _interpret(kind, m, now_local, date_order)
        except (ValueError, KeyError):
            continue
        if pm is None:
            continue
        pm.text, pm.start, pm.end, pm.pattern = m.group(0).strip(), m.start(), m.end(), kind
        taken.append((m.start(), m.end()))
        found.append(pm)
    _pair_calendar_weeks(found)
    return sorted(found, key=lambda p: p.start)


_LAST_7_DAYS = {"kind": "rolling", "amount": 7, "unit": "day"}


def _pair_calendar_weeks(found: list[PhraseMatch]) -> None:
    """'this week ... last week' compares two calendar weeks. Alone, 'last week' means
    the last 7 days, but next to 'this week' (Monday to now) that rolling window would
    OVERLAP it and make the comparison meaningless (seen live: a '65% decrease'
    between overlapping periods). So, paired with 'this week', 'last week' is the
    previous calendar week."""
    has_this_week = any(p.pattern == "this_period" and (p.intent or {}).get("unit") == "week"
                        and (p.intent or {}).get("offset") == 0 for p in found)
    if not has_this_week:
        return
    for p in found:
        if p.pattern == "rolling_1" and p.intent == _LAST_7_DAYS and "week" in p.text.lower():
            p.intent = {"kind": "calendar", "unit": "week", "offset": -1}
            p.note = "'last week' taken as the previous calendar week (Mon-Sun), to compare with 'this week'"


def _interpret(kind: str, m: re.Match[str], now: datetime, date_order: str | None) -> PhraseMatch | None:
    today = now.date()
    g = m.groupdict()

    if kind == "future":
        return PhraseMatch("", 0, 0, "future", note="refers to the future; only past activity can be investigated")

    if kind in ("rolling_n", "rolling_fuzzy"):
        unit = _unit(g["u"])
        n = FUZZY[re.sub(r"\s+", " ", g["fz"].lower())] if kind == "rolling_fuzzy" else _num(g["n"])
        note = f"'{g['fz'].strip()}' taken as {n}" if kind == "rolling_fuzzy" else None
        if unit == "year":
            return PhraseMatch("", 0, 0, "default" if note else "resolved",
                               {"kind": "rolling", "amount": 12 * n, "unit": "month"}, note)
        return PhraseMatch("", 0, 0, "default" if note else "resolved",
                           {"kind": "rolling", "amount": n, "unit": unit}, note)

    if kind == "rolling_1":
        u = g["u"].lower()
        if u == "week":
            return PhraseMatch("", 0, 0, "default", {"kind": "rolling", "amount": 7, "unit": "day"},
                               "'last week' taken as the last 7 days (rolling), not the previous calendar week")
        if u == "month":
            prev = "past" in m.group(0).lower()
            if prev:
                return PhraseMatch("", 0, 0, "resolved", {"kind": "rolling", "amount": 1, "unit": "month"})
            return PhraseMatch("", 0, 0, "default", {"kind": "calendar", "unit": "month", "offset": -1},
                               "'last month' taken as the previous calendar month")
        if u == "year":
            if "past" in m.group(0).lower():
                return PhraseMatch("", 0, 0, "resolved", {"kind": "rolling", "amount": 12, "unit": "month"})
            return PhraseMatch("", 0, 0, "default", {"kind": "calendar", "unit": "year", "offset": -1},
                               "'last year' taken as the previous calendar year")
        if u == "night":
            y = today - timedelta(days=1)
            return PhraseMatch("", 0, 0, "default",
                               {"kind": "local_range", "start": f"{y}T18:00", "end": f"{today}T06:00"},
                               "'last night' taken as 18:00 yesterday to 06:00 today")
        if u == "day":
            return PhraseMatch("", 0, 0, "resolved", {"kind": "rolling", "amount": 24, "unit": "hour"})
        return PhraseMatch("", 0, 0, "resolved", {"kind": "rolling", "amount": 1, "unit": "hour"})

    if kind in ("ago_n", "ago_fuzzy"):
        unit = _unit(g["u"])
        n = FUZZY[re.sub(r"\s+", " ", g["fz"].lower())] if kind == "ago_fuzzy" else _num(g["n"])
        fuzzy_note = f"'{g['fz'].strip()}' taken as {n}; " if kind == "ago_fuzzy" else ""
        if unit in ("minute", "hour"):
            return PhraseMatch("", 0, 0, "ask", note=f"'{m.group(0).strip()}' could mean around that moment or everything since then",
                               options=[{"label": f"everything in the last {n} {unit}s", "intent": {"kind": "rolling", "amount": n, "unit": unit}},
                                        {"label": f"the {unit} starting {n} {unit}s ago",
                                         "intent": {"kind": "ago_range", "from": n, "to": n - 1, "unit": unit}}])
        if unit == "day":
            d = today - timedelta(days=n)
            return PhraseMatch("", 0, 0, "default" if fuzzy_note else "resolved", _day_range(d),
                               (fuzzy_note + f"means the day {d:%a %Y-%m-%d}") if fuzzy_note else None)
        if unit == "week":
            return PhraseMatch("", 0, 0, "default", {"kind": "calendar", "unit": "week", "offset": -n},
                               fuzzy_note + f"'{m.group(0).strip()}' taken as that calendar week (Mon-Sun)")
        if unit == "month":
            return PhraseMatch("", 0, 0, "default", {"kind": "calendar", "unit": "month", "offset": -n},
                               fuzzy_note + f"'{m.group(0).strip()}' taken as that calendar month")
        return PhraseMatch("", 0, 0, "default", {"kind": "calendar", "unit": "year", "offset": -n},
                           fuzzy_note + f"'{m.group(0).strip()}' taken as that calendar year")

    if kind == "day_before_yesterday":
        return PhraseMatch("", 0, 0, "resolved", _day_range(today - timedelta(days=2)))
    if kind == "today":
        return PhraseMatch("", 0, 0, "resolved", {"kind": "calendar", "unit": "day", "offset": 0, "to_now": True})
    if kind == "yesterday":
        return PhraseMatch("", 0, 0, "resolved", {"kind": "calendar", "unit": "day", "offset": -1})
    if kind == "tonight":
        return PhraseMatch("", 0, 0, "default", {"kind": "local_since", "start": f"{today}T18:00"},
                           "'tonight' taken as since 18:00 today")
    if kind == "day_part":
        rel, part = g["rel"].lower(), g["part"].lower()
        d = today - timedelta(days=1) if rel == "yesterday" else today
        h0, h1 = DAY_PARTS[part]
        note = f"'{part}' taken as {h0:02d}:00-{h1 % 24:02d}:00"
        if d == today and now.hour < h1:
            # still in progress: the part so far, never a window reaching into the future
            if now.hour < h0:
                return PhraseMatch("", 0, 0, "future", note=f"this {part} hasn't started yet")
            return PhraseMatch("", 0, 0, "default", {"kind": "local_since", "start": f"{d}T{h0:02d}:00"},
                               note + " (so far)")
        end = f"{d + timedelta(days=1)}T00:00" if h1 == 24 else f"{d}T{h1:02d}:00"
        return PhraseMatch("", 0, 0, "default", {"kind": "local_range", "start": f"{d}T{h0:02d}:00", "end": end}, note)
    if kind == "this_period":
        return PhraseMatch("", 0, 0, "resolved", {"kind": "calendar", "unit": g["u"].lower(), "offset": 0, "to_now": True})

    if kind == "since_last_run":
        # resolved against the run's own history by agentwin (scheduler watermark, or
        # Kratos's newest saved scan when run interactively)
        return PhraseMatch("", 0, 0, "resolved", {"kind": "named", "name": "since last run"})
    if kind == "since_weekday":
        wd = WEEKDAYS[g["wd"].lower()[:3]]
        d = _weekday_before(wd, today, include_today=False)
        return PhraseMatch("", 0, 0, "resolved", {"kind": "local_since", "start": d.isoformat()})
    if kind == "since_time":
        h, mi = _parse_time(g["t"])
        d = today if (h, mi) <= (now.hour, now.minute) else today - timedelta(days=1)
        note = None if d == today else f"'{g['t']}' is later than now, so taken as yesterday {h:02d}:{mi:02d}"
        return PhraseMatch("", 0, 0, "default" if note else "resolved",
                           {"kind": "local_since", "start": f"{d}T{h:02d}:{mi:02d}"}, note)
    if kind == "since_date":
        cands, note = _parse_date(g["d"], today, date_order)
        return _date_result(cands, note, lambda d: {"kind": "local_since", "start": d.isoformat()}, g["d"])

    if kind in ("last_weekday", "on_weekday"):
        wd = WEEKDAYS[g["wd"].lower()[:3]]
        if wd == today.weekday():
            prev = today - timedelta(days=7)
            return PhraseMatch("", 0, 0, "ask", note=f"today is {today:%A}: '{m.group(0).strip()}' could mean today or {prev:%b %d}",
                               options=[{"label": f"today ({today:%a %b %d})", "intent": _day_range(today)},
                                        {"label": f"a week ago ({prev:%a %b %d})", "intent": _day_range(prev)}])
        d = _weekday_before(wd, today, include_today=False)
        return PhraseMatch("", 0, 0, "resolved", _day_range(d))

    if kind == "month_name":
        mon = MONTHS[g["m"].lower()[:3]]
        if g.get("y"):
            y = int(g["y"])
        else:
            y = today.year if mon <= today.month else today.year - 1
        start = date(y, mon, 1)
        nxt = date(y + (mon == 12), mon % 12 + 1, 1)
        note = None if g.get("y") or y == today.year else f"no year given: took the most recent {start:%B} ({y})"
        return PhraseMatch("", 0, 0, "default" if note else "resolved",
                           {"kind": "local_range", "start": start.isoformat(), "end": f"{nxt}T00:00"}, note)

    if kind == "date":
        cands, note = _parse_date(g["d"], today, date_order)
        return _date_result(cands, note, _day_range, g["d"])

    if kind == "range":
        a, b = g["a"], g["b"]
        base_day: date | None = None
        day_word, on_day = (g.get("day"), g.get("onday")) if g.get("day") else (g.get("dayb"), g.get("ondayb"))
        if day_word:
            dword = day_word.lower()
            if dword == "today":
                base_day = today
            elif dword == "yesterday":
                base_day = today - timedelta(days=1)
            else:
                cands, _ = _parse_date(on_day, today, date_order)
                if len(cands) != 1:
                    return None
                base_day = cands[0]
        a_is_time = re.fullmatch(_TIME_RE, a.strip(), re.IGNORECASE) is not None
        b_is_time = re.fullmatch(_TIME_RE, b.strip(), re.IGNORECASE) is not None
        if a_is_time and b_is_time:
            d = base_day or today
            (h0, m0), (h1, m1) = _parse_time(a), _parse_time(b)
            end_day = d if (h1, m1) > (h0, m0) else d + timedelta(days=1)
            return PhraseMatch("", 0, 0, "resolved",
                               {"kind": "local_range", "start": f"{d}T{h0:02d}:{m0:02d}", "end": f"{end_day}T{h1:02d}:{m1:02d}"})
        if a_is_time or b_is_time:
            return None
        ca, na = _parse_date(a, today, date_order)
        cb, nb = _parse_date(b, today, date_order)
        if len(ca) != 1 or len(cb) != 1:
            return PhraseMatch("", 0, 0, "ask", note=f"'{m.group(0).strip()}' contains a date that could be read two ways",
                               options=[{"label": f"{x} to {y}", "intent": {"kind": "local_range", "start": x.isoformat(), "end": y.isoformat()}}
                                        for x in ca for y in cb if x <= y][:4])
        # Date granularity: end date is included in full (design §2C) -- windows.py
        # applies that rule to a date-only end, and the note discloses it.
        return PhraseMatch("", 0, 0, "default",
                           {"kind": "local_range", "start": ca[0].isoformat(), "end": cb[0].isoformat()},
                           "; ".join(x for x in (na, nb, f"{cb[0]:%b %d} included in full") if x))

    if kind == "recently":
        return PhraseMatch("", 0, 0, "default", {"kind": "rolling", "amount": 24, "unit": "hour"},
                           "'recently' taken as the last 24 hours")
    if kind == "lately":
        return PhraseMatch("", 0, 0, "default", {"kind": "rolling", "amount": 7, "unit": "day"},
                           "'lately' taken as the last 7 days")
    if kind == "vague":
        return PhraseMatch("", 0, 0, "ask", note=f"'{m.group(0).strip()}' has no definite time span",
                           options=[{"label": "the last 7 days", "intent": {"kind": "rolling", "amount": 7, "unit": "day"}},
                                    {"label": "the last 30 days", "intent": {"kind": "rolling", "amount": 30, "unit": "day"}}])
    return None


def _date_result(cands: list[date], note: str | None, make, raw: str) -> PhraseMatch:
    if not cands:
        raise ValueError(raw)
    if len(cands) == 1:
        return PhraseMatch("", 0, 0, "default" if note else "resolved", make(cands[0]), note)
    return PhraseMatch("", 0, 0, "ask",
                       note=f"'{raw}' could be {' or '.join(f'{c:%B %d}' for c in cands)} (day/month order)",
                       options=[{"label": f"{c:%A %B %d, %Y}", "intent": make(c)} for c in cands])
