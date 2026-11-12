"""Learning: decayed counts per key, coverage-aware learning days, poisoning holds (E.3 §3.3-§3.7).

The model of normal is counting. Per (dimension, subject, key): a weight that halves every
`baseline.half_life_days`, a count, first and last seen. An observation is judged against
what was learned BEFORE it, then learned -- unless it is held back (near an open serious
finding, or one a person confirmed real), the profile is frozen, or it is Kratos's own
activity, which is never learned and never raised.

Learning days count covered time only: a UTC day counts when log sync covered at least
COVERED_HOURS of it for the dimension's source, or -- for running-process reads -- when at
least two reads were saved that day. Until a profile has `baseline.learn_days` such days
(and its minimum samples), it says "still learning" and raises nothing.
"""
from __future__ import annotations

import bisect
import json
import math
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from typing import Any, Iterable

from kratos.baseline import dims as D
from kratos.baseline import store as S

DAY = 86400.0
HOUR = 3600.0
COVERED_HOURS = 20
SNAPSHOT_DAY_MIN = 2
HOLD_SECONDS = 3600.0                  # ±1 h around a serious finding (§3.7)
RAISE_LOOKBACK_DAYS = 7                # older deviations found in history are learned, not raised
MAX_SNAPSHOTS_PER_RUN = 2000
_EPOCH_IN_ENTITY = re.compile(r"(?<![0-9])(1[5-9][0-9]{8}|2[0-9]{9})(?![0-9])")


@dataclass
class Settings:
    learn_days: int = 14
    half_life_days: int = 30
    max_entries: int = 500
    forget_days: int = 90
    rare_weight: float = 0.5
    time_share: float = 0.02
    max_per_day: int = 5
    cooldown_hours: int = 24
    max_events_per_run: int = 200_000

    @classmethod
    def load(cls, data_dir: Any) -> "Settings":
        from kratos.baseline import settings as BS

        return cls(**BS.values(data_dir))


def day_of(ts: float) -> int:
    return int(ts // DAY)


def day_text(day: int) -> str:
    return datetime.fromtimestamp(day * DAY, timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------
@dataclass
class Entry:
    subject: str
    key: str
    weight: float = 0.0
    weight_at: float = 0.0
    count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    held: dict[str, list[float]] = field(default_factory=dict)
    accepted_at: float | None = None
    accepted_by: str | None = None
    forgotten_at: float | None = None
    forgotten_by: str | None = None
    evicted_at: float | None = None
    last_raised: float | None = None
    dirty: bool = False

    @classmethod
    def from_row(cls, r: sqlite3.Row) -> "Entry":
        try:
            held = json.loads(r["held"] or "{}")
        except ValueError:
            held = {}
        return cls(r["subject"], r["key"], float(r["weight"]), float(r["weight_at"]), int(r["count"]),
                   float(r["first_seen"]), float(r["last_seen"]), held if isinstance(held, dict) else {},
                   r["accepted_at"], r["accepted_by"], r["forgotten_at"], r["forgotten_by"], r["evicted_at"],
                   r["last_raised"])

    def as_row(self) -> dict[str, Any]:
        return {c: getattr(self, c) for c in S.ENTRY_COLS}

    @property
    def live(self) -> bool:
        return self.forgotten_at is None


def decayed(e: Entry, t: float, half_life_s: float) -> float:
    if t <= e.weight_at:
        return e.weight
    return e.weight * math.pow(0.5, (t - e.weight_at) / half_life_s)


def add_weight(e: Entry, t: float, amount: float, half_life_s: float) -> None:
    if t >= e.weight_at:
        e.weight = decayed(e, t, half_life_s) + amount
        e.weight_at = t
    else:                                   # an older observation arriving late: its share, faded
        e.weight += amount * math.pow(0.5, (e.weight_at - t) / half_life_s)


# ---------------------------------------------------------------------------
# Covered learning days
# ---------------------------------------------------------------------------
def covered_days_from_spans(spans: Iterable[tuple[float, float]], *, hours: int = COVERED_HOURS) -> list[int]:
    """UTC days with at least `hours` covered by the union of the complete spans."""
    merged: list[list[float]] = []
    for s, e in sorted((float(a), float(b)) for a, b in spans if b > a):
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    per_day: dict[int, float] = {}
    for s, e in merged:
        d = day_of(s)
        while d * DAY < e:
            lo, hi = max(s, d * DAY), min(e, (d + 1) * DAY)
            if hi > lo:
                per_day[d] = per_day.get(d, 0.0) + (hi - lo)
            d += 1
    return sorted(d for d, secs in per_day.items() if secs >= hours * HOUR)


def coverage_spans(conn: sqlite3.Connection, target_key: str, source: str) -> list[tuple[float, float]]:
    try:
        return [(float(r[0]), float(r[1])) for r in conn.execute(
            "SELECT start_ts, end_ts FROM sync_coverage WHERE target = ? AND source = ? AND complete = 1",
            (target_key, source))]
    except sqlite3.OperationalError:          # log sync never ran on this data folder
        return []


def gap_notes(conn: sqlite3.Connection, target_key: str, source: str, limit: int = 3) -> list[str]:
    try:
        rows = conn.execute("SELECT start_ts, end_ts, note FROM sync_coverage WHERE target = ? AND source = ? AND "
                            "complete = 0 ORDER BY start_ts DESC LIMIT ?", (target_key, source, limit)).fetchall()
    except sqlite3.OperationalError:
        return []
    out = []
    for s, e, note in rows:
        out.append(f"{day_text(day_of(s))} to {day_text(day_of(e))}: {note or 'not synced'}")
    return out


@dataclass
class Learning:
    """How far one profile has learned at a given moment."""
    covered: list[int]                      # sorted covered UTC days (since the profile started)
    started_at: float

    def covered_before(self, t: float) -> int:
        lo = bisect.bisect_left(self.covered, day_of(self.started_at))
        hi = bisect.bisect_left(self.covered, day_of(t))
        return max(0, hi - lo)

    def days_since_start(self, t: float) -> int:
        return max(0, int((t - self.started_at) // DAY))


# ---------------------------------------------------------------------------
# Poisoning holds
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Hold:
    start: float
    end: float
    finding_key: str
    rule_id: str


def holds(conn: sqlite3.Connection, target_key: str) -> list[Hold]:
    """Windows whose events are not learned: ±1 h around an OPEN high/critical finding, or any
    finding a person verified as real, on this machine. A condition finding's moment is when
    it first appeared; an occurrence's also its latest sighting and any event times its
    entities name (CORR-SSH-002's `user@ip@epoch`)."""
    try:
        rows = conn.execute(
            "SELECT finding_key, rule_id, kind, state, severity, first_seen, last_seen, entities FROM "
            "finding_records WHERE target = ? AND ((state IN ('open', 'verified') AND severity IN "
            "('high', 'critical')) OR state = 'verified')", (target_key,)).fetchall()
    except sqlite3.OperationalError:
        return []
    out: list[Hold] = []
    for r in rows:
        moments = [float(r["first_seen"])]
        if r["kind"] == "occurrence":
            moments.append(float(r["last_seen"]))
            try:
                ents = json.loads(r["entities"] or "[]")
            except ValueError:
                ents = []
            for ent in ents[:200]:
                moments.extend(float(m) for m in _EPOCH_IN_ENTITY.findall(str(ent)))
        for m in moments:
            out.append(Hold(m - HOLD_SECONDS, m + HOLD_SECONDS, r["finding_key"], r["rule_id"]))
    return out


def released(conn: sqlite3.Connection, finding_keys: Iterable[str]) -> set[str]:
    """Of these findings, the ones closed as false positive or mitigated (their held-back
    observations may now be learned)."""
    keys = sorted(set(finding_keys))
    if not keys:
        return set()
    try:
        rows = conn.execute(f"SELECT finding_key FROM finding_records WHERE finding_key IN "
                            f"({', '.join('?' for _ in keys)}) AND state IN ('false_positive', 'mitigated')",
                            keys).fetchall()
    except sqlite3.OperationalError:
        return set()
    return {r[0] for r in rows}


def held_by(hold_list: list[Hold], t: float) -> Hold | None:
    for h in hold_list:
        if h.start <= t <= h.end:
            return h
    return None


# ---------------------------------------------------------------------------
# One dimension's model for a machine
# ---------------------------------------------------------------------------
@dataclass
class Deviation:
    dim: str
    rule: str
    subject: str
    key: str
    ts: float
    kind: str                       # new | rare | unusual_time
    detail: dict[str, Any]
    seen_before: int = 0
    last_seen_before: float | None = None
    subject_seen: int = 0           # observations of this subject before this one
    machine_sudo_users: int = 0
    held: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"dim": self.dim, "rule": self.rule, "subject": self.subject, "key": self.key, "ts": self.ts,
                "kind": self.kind, "detail": self.detail, "seen_before": self.seen_before,
                "last_seen_before": self.last_seen_before, "subject_seen": self.subject_seen, "held": self.held}


@dataclass
class Model:
    dim: D.Dim
    generation: int
    profile: dict[str, Any]
    entries: dict[tuple[str, str], Entry]
    learning: Learning
    settings: Settings
    frozen: bool = False
    samples: int = 0
    held_back: int = 0
    snapshot_days: dict[str, int] = field(default_factory=dict)
    by_subject: dict[str, dict[str, Entry]] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # How much of a subject has been seen gates judging it (e.g. 20 sign-ins for an account).
        # A forgotten key still counts here: forgetting makes that key new again, it doesn't
        # make the account unknown.
        for (subj, key), e in self.entries.items():
            self.by_subject.setdefault(subj, {})[key] = e
            self.counts[subj] = self.counts.get(subj, 0) + e.count

    def _put(self, e: Entry) -> None:
        old = self.entries.get((e.subject, e.key))
        if old is not None:
            self.counts[e.subject] = self.counts.get(e.subject, 0) - old.count
        self.entries[(e.subject, e.key)] = e
        self.by_subject.setdefault(e.subject, {})[e.key] = e

    @property
    def half_life_s(self) -> float:
        return self.settings.half_life_days * DAY

    def subject_count(self, subject: str) -> int:
        return self.counts.get(subject, 0)

    def subject_entries(self, subject: str) -> list[Entry]:
        return [e for e in self.by_subject.get(subject, {}).values() if e.live]

    def ready(self, t: float, subject: str) -> bool:
        """Learned enough, before time t, to judge an observation of `subject`."""
        if self.learning.covered_before(t) < self.settings.learn_days:
            return False
        if self.dim.min_snapshot_days and self.learning.days_since_start(t) < self.dim.min_snapshot_days:
            return False
        if self.dim.per_subject:
            return self.subject_count(subject) >= self.dim.min_samples
        return self.samples >= self.dim.min_samples

    def judge(self, o: D.Obs) -> Deviation | None:
        if not self.ready(o.ts, o.subject):
            return None
        if self.dim.name == "login_time":
            return self._judge_time(o)
        e = self.entries.get((o.subject, o.key))
        forget_s = self.settings.forget_days * DAY
        if e is not None and e.accepted_at is not None and e.live:
            return None
        if e is None or not e.live or (o.ts - e.last_seen > forget_s and e.count > 0):
            kind = "new"
        elif e.count <= 2 and decayed(e, o.ts, self.half_life_s) < self.settings.rare_weight:
            kind = "rare"
        else:
            return None
        return Deviation(self.dim.name, self.dim.rule, o.subject, o.key, o.ts, kind, dict(o.detail),
                         seen_before=e.count if e is not None and e.live else 0,
                         last_seen_before=e.last_seen if e is not None and e.live else None,
                         subject_seen=self.subject_count(o.subject))

    def _judge_time(self, o: D.Obs) -> Deviation | None:
        e = self.entries.get((o.subject, o.key))
        if e is not None and e.accepted_at is not None and e.live:
            return None
        hour, _, daytype = o.key.partition(" ")
        mine = self.subject_entries(o.subject)
        same_type = [x for x in mine if x.key.endswith(" " + daytype)]
        pool = same_type if sum(x.count for x in same_type) >= 10 else mine
        weights: dict[str, float] = {}
        for x in pool:
            h = x.key.split(" ", 1)[0]
            weights[h] = weights.get(h, 0.0) + decayed(x, o.ts, self.half_life_s)
        total = sum(weights.values())
        share = (weights.get(hour, 0.0) + 1.0) / (total + 24.0)
        if share >= self.settings.time_share:
            return None
        return Deviation(self.dim.name, self.dim.rule, o.subject, o.key, o.ts, "unusual_time",
                         {**o.detail, "share": round(share, 4)}, seen_before=e.count if e else 0,
                         last_seen_before=e.last_seen if e else None, subject_seen=self.subject_count(o.subject))

    def learn(self, o: D.Obs, hold: Hold | None) -> None:
        e = self.entries.get((o.subject, o.key))
        forget_s = self.settings.forget_days * DAY
        if e is None:
            e = Entry(o.subject, o.key, 0.0, o.ts, 0, o.ts, o.ts)
            self._put(e)
        elif not e.live or (o.ts - e.last_seen > forget_s and e.count > 0 and e.accepted_at is None):
            # forgotten, or unseen for forget_days: learned again from this observation (the
            # count stays, so the subject isn't treated as unknown)
            e.forgotten_at = e.forgotten_by = None
            e.weight, e.weight_at, e.first_seen = 0.0, o.ts, o.ts
        e.dirty = True
        if e.evicted_at is not None:
            e.evicted_at = None
        if hold is not None:
            n, last = e.held.get(hold.finding_key, [0, 0.0])
            e.held[hold.finding_key] = [int(n) + 1, max(float(last), o.ts)]
            self.held_back += 1
            return
        add_weight(e, o.ts, 1.0, self.half_life_s)
        e.count += 1
        self.counts[o.subject] = self.counts.get(o.subject, 0) + 1
        e.first_seen = min(e.first_seen, o.ts)
        e.last_seen = max(e.last_seen, o.ts)
        if self.dim.source == D.EVENT:
            self.samples += 1           # snapshot dimensions count reads, not items (record._count_snapshot)

    def release(self, done: set[str]) -> int:
        n = 0
        for e in self.entries.values():
            for fk in [k for k in e.held if k in done]:
                cnt, last = e.held.pop(fk)
                add_weight(e, float(last), float(cnt), self.half_life_s)
                e.count += int(cnt)
                self.counts[e.subject] = self.counts.get(e.subject, 0) + int(cnt)
                e.last_seen = max(e.last_seen, float(last))
                e.dirty = True
                n += int(cnt)
        return n

    def held_keys(self) -> set[str]:
        return {fk for e in self.entries.values() for fk in e.held}

    def held_now(self) -> int:
        return sum(int(c) for e in self.entries.values() for c, _ in e.held.values())

    def evict(self, now: float) -> int:
        live = [e for e in self.entries.values() if e.live and e.evicted_at is None]
        over = len(live) - self.settings.max_entries
        if over <= 0:
            return 0
        candidates = sorted((e for e in live if e.accepted_at is None),
                            key=lambda e: (decayed(e, now, self.half_life_s), e.last_seen))
        for e in candidates[:over]:
            e.evicted_at = now
            e.dirty = True
        return min(over, len(candidates))


# ---------------------------------------------------------------------------
# Usual pattern (shown next to every deviation)
# ---------------------------------------------------------------------------
def top(model: Model, subject: str, t: float, n: int = 3) -> list[tuple[str, float, int]]:
    rows = [(e.key, decayed(e, t, model.half_life_s), e.count) for e in model.subject_entries(subject)
            if e.evicted_at is None]
    rows.sort(key=lambda r: (-r[1], r[0]))
    return [(k, round(w, 1), c) for k, w, c in rows[:n]]


def top_all(model: Model, t: float, n: int = 4) -> list[tuple[str, str, float]]:
    rows = [(e.subject, e.key, decayed(e, t, model.half_life_s)) for e in model.entries.values()
            if e.live and e.evicted_at is None]
    rows.sort(key=lambda r: (-r[2], r[0], r[1]))
    return [(s, k, round(w, 1)) for s, k, w in rows[:n]]


def usual_hours(model: Model, subject: str, t: float) -> str:
    """Compact hour ranges an account usually signs in at ("weekdays 08:00-18:59")."""
    out = []
    for daytype in ("weekday", "weekend"):
        ws, counts = {}, {}
        for e in model.subject_entries(subject):
            if e.key.endswith(" " + daytype):
                ws[int(e.key[:2])] = decayed(e, t, model.half_life_s)
                counts[int(e.key[:2])] = e.count
        total = sum(ws.values())
        if total <= 0:
            continue
        # shown as usual: at least two sign-ins in that hour and a share above the threshold
        hours = sorted(h for h, w in ws.items()
                       if counts.get(h, 0) >= 2 and (w + 1.0) / (total + 24.0) >= model.settings.time_share)
        if not hours:
            continue
        ranges, start, prev = [], hours[0], hours[0]
        for h in hours[1:]:
            if h != prev + 1:
                ranges.append((start, prev))
                start = h
            prev = h
        ranges.append((start, prev))
        text = ", ".join(f"{a:02d}:00-{b:02d}:59" for a, b in ranges[:4]) + (" ..." if len(ranges) > 4 else "")
        out.append(f"{daytype}s {text}")
    return "; ".join(out)
