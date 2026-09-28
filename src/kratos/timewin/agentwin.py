"""
Agent-side time handling (docs/time_window_design.md §2C, §4, §12 item 10).

`prepare_time_context` runs once at the start of an investigation:

1. anchors "now" and the user's timezone in a TimeContext (named windows reloaded from
   the session, so a resumed session never re-reads yesterday's "today");
2. scans the GOAL with the deterministic phrase detector and resolves every time
   expression by code -- the model is handed window ids, never asked to compute dates;
3. for a phrase that needs the user ("03/04", "3 hours ago", "last Friday" on a Friday)
   it asks through the existing clarify provider; with nobody to ask (CLI/MCP/scheduled)
   it registers EVERY candidate reading as its own window and tells the model to report
   each separately -- never a silent guess;
4. renders the TIME CONTEXT block placed in the never-compacted prompt preamble.

`check_model_window` is the double-entry cross-check: a window the model builds itself
that nearly-but-not-exactly matches a goal window is rejected in favour of the goal's id
(the typical model error is an off-by-an-hour / calendar-vs-rolling version of the right
window). `unqueried_goal_windows` powers the time-scope guard in agent/loop.py: a goal
that names a period must actually get that period queried.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from kratos.timewin.claims import METRICS
from kratos.timewin.phrases import find_time_phrases
from kratos.timewin.windows import TimeContext, TimeIntentError, TimeWindow, zone_name
from kratos.utils.timeutil import resolve_display_tz, zone_from_name

ClarifyProvider = Callable[[str, list[dict[str, Any]]], "str | None"]


def prepare_time_context(
    goal: str,
    data_dir: Path,
    *,
    timezone_name: str | None = None,
    session_id: str | None = None,
    now: float | None = None,
    clarify: ClarifyProvider | None = None,
    date_order: str | None = None,
    named_windows: dict[str, tuple[float, float, str]] | None = None,
) -> tuple[TimeContext, list[dict[str, Any]]]:
    """Returns (ctx, clarify_log). Raises TimeIntentError for an invalid timezone name."""
    if timezone_name:
        tz = zone_from_name(timezone_name)
        if tz is None:
            raise TimeIntentError(f"unknown timezone {timezone_name!r} (use an IANA name like 'Asia/Dhaka')")
    else:
        tz = resolve_display_tz(data_dir)
    store = (Path(data_dir) / "sessions" / f"{session_id}_windows.json") if session_id else None
    ctx = TimeContext(tz, now=now, store_path=store)
    for name, (start, end, note) in (named_windows or {}).items():  # e.g. the scheduler's watermark
        ctx.named[name] = TimeWindow(id=f"named:{name}", start_utc=start, end_utc=end, tz=ctx.tz_name, label=name,
                                     intent={"kind": "named", "name": name}, anchor_now=ctx.now, name=name,
                                     notes=[note] if note else [])
    log: list[dict[str, Any]] = []
    now_local = datetime.fromtimestamp(ctx.now, tz).replace(tzinfo=None)

    for m in find_time_phrases(goal, now_local, date_order=date_order):
        if m.status == "future":
            ctx.unresolved.append({"phrase": m.text, "status": "future", "note": m.note})
            continue
        if m.status in ("resolved", "default"):
            if m.pattern == "since_last_run" and "since last run" not in ctx.named:
                _add_last_scan_window(ctx, Path(data_dir))
            _register(ctx, m.intent, m.text, m.note)
            continue
        # status == "ask"
        chosen = None
        if clarify is not None and m.options:
            question = f"In your question, what does \"{m.text}\" mean? {m.note or ''}".strip()
            opts = [{"label": o["label"], "explanation": "", "recommended": False} for o in m.options]
            answer = clarify(question, opts)
            log.append({"phrase": m.text, "question": question, "answer": answer})
            if answer:
                chosen = next((o for o in m.options if o["label"].strip().lower() == answer.strip().lower()), None)
                if chosen is None:
                    # free-text answer: resolve it with the same deterministic detector
                    sub = [p for p in find_time_phrases(answer, now_local, date_order=date_order)
                           if p.status in ("resolved", "default")]
                    if len(sub) == 1:
                        chosen = {"label": answer, "intent": sub[0].intent}
        if chosen is not None:
            _register(ctx, chosen["intent"], m.text, f"user chose: {chosen['label']}")
        else:
            ids = []
            for o in m.options:
                w = _register(ctx, o["intent"], m.text, f"one reading of an ambiguous phrase: {o['label']}")
                if w is not None:
                    ids.append(w.id)
            ctx.unresolved.append({"phrase": m.text, "status": "ambiguous", "note": m.note, "window_ids": ids})
    return ctx, log


def _add_last_scan_window(ctx: TimeContext, data_dir: Path) -> None:
    """Interactive "since the last scan/check": from Kratos's newest saved observation of
    the target (findings or scan snapshot), disclosed as such."""
    try:
        from kratos.kratos_config import get_active_target
        from kratos.timewin.snapshots import latest

        snaps = [s for s in (latest(data_dir, c, get_active_target()) for c in ("findings", "open_ports")) if s]
    except Exception:  # noqa: BLE001 -- no history is simply "can't resolve", never a crash
        snaps = []
    if not snaps:
        return
    s = max(snaps, key=lambda x: x.captured_at)
    if s.captured_at >= ctx.now:
        return
    ctx.named["since last run"] = TimeWindow(
        id="named:since last run", start_utc=s.captured_at, end_utc=ctx.now, tz=ctx.tz_name, label="since last run",
        intent={"kind": "named", "name": "since last run"}, anchor_now=ctx.now, name="since last run",
        notes=[f"'the last run' taken as Kratos's newest saved {s.category} snapshot ({s.as_dict()['captured_at']})"])


def _register(ctx: TimeContext, intent: dict[str, Any] | None, phrase: str, note: str | None) -> TimeWindow | None:
    if not intent:
        return None
    try:
        w = ctx.resolve(intent, phrase=phrase)
    except TimeIntentError as e:
        ctx.unresolved.append({"phrase": phrase, "status": "invalid", "note": str(e)})
        return None
    if note and note not in w.notes:
        w.notes.append(note)
    if w.id not in ctx.goal_ids:
        ctx.goal_ids.append(w.id)
    return w


def render_time_block(ctx: TimeContext) -> str:
    now_local = datetime.fromtimestamp(ctx.now, ctx.tz)
    lines = [
        "TIME CONTEXT (computed by Kratos -- never compute dates or timestamps yourself):",
        f"- Now: {now_local:%Y-%m-%d %H:%M} {ctx.tz_name} ({datetime.fromtimestamp(ctx.now, timezone.utc):%Y-%m-%dT%H:%MZ}).",
    ]
    goal = [ctx.windows[i] for i in ctx.goal_ids if i in ctx.windows]
    if goal:
        lines.append("- Time periods in the goal, already resolved:")
        for w in goal:
            lines.append(f"  - {w.summary()}  [from: \"{w.phrase}\"]")
    for u in ctx.unresolved:
        if u["status"] == "ambiguous":
            lines.append(f"- AMBIGUOUS, NOT GUESSED: \"{u['phrase']}\" ({u['note']}). Investigate EACH of "
                         f"{', '.join(u['window_ids'])} separately and report them separately, stating the ambiguity.")
        elif u["status"] == "future":
            lines.append(f"- \"{u['phrase']}\" refers to the future and cannot be investigated -- say so plainly.")
        else:
            lines.append(f"- \"{u['phrase']}\" could not be resolved ({u['note']}) -- say so; do not guess a period.")
    if ctx.named:
        lines.append("- Saved windows from earlier in this conversation: " + "; ".join(
            f"{k} = {w.summary()}" for k, w in sorted(ctx.named.items())))
    lines += [
        "- To scope a time-aware tool, pass \"window\": {\"id\": \"w1\"} (or a saved window's name).",
        "- For any OTHER period, pass a time intent instead of dates: {\"kind\": \"rolling\", \"amount\": 3, \"unit\": \"day\"}, "
        "{\"kind\": \"calendar\", \"unit\": \"month\", \"offset\": -1}, {\"kind\": \"local_range\", \"start\": \"2026-09-20\", "
        "\"end\": \"2026-09-21T06:00\"} (local wall-clock, no offsets), {\"kind\": \"relative_to\", \"window\": \"w1\", "
        "\"shift\": {\"amount\": -1, \"unit\": \"month\"}}. Add \"save_as\": \"<name>\" to remember a window for later.",
        "- In the final answer, only state time periods you actually queried, and say when coverage was partial.",
        "- When the final answer states a count, a 'none', or a period, add \"claims\" next to \"final_answer\" -- "
        "one per statement, each tied to a window id; Kratos checks them against its own measurements: "
        "[{\"kind\": \"count\", \"metric\": \"ssh_failed_logins\", \"window\": \"w1\", \"value\": 5}, "
        "{\"kind\": \"absence\", \"metric\": \"sudo_failures\", \"window\": \"w1\"}, "
        "{\"kind\": \"unknown\", \"window\": \"w1\", \"reason\": \"logs start at 22:08\"}]. Metrics: "
        + ", ".join(METRICS) + ". Quote measured numbers exactly; never estimate.",
    ]
    return "\n".join(lines)


def check_model_window(ctx: TimeContext, w: TimeWindow, intent: Any) -> str | None:
    """Double-entry check (design §2C): a model-built window that is a plausible
    MIS-READING of a goal period is rejected in favour of the goal's id. Two shapes:

    - near miss: similar length (0.5-2x) and mostly overlapping, but bounds differ --
      the off-by-the-DST-hour / midnight-vs-now errors seen in validation (E9);
    - alternative reading: same length (within 10%) starting less than one period away
      -- e.g. "last week" built as the calendar week instead of the rolling 7 days.

    A clearly narrower/wider window (a 15-minute slice of "yesterday") or an adjacent
    baseline ("the 7 days before that") is a genuinely different period and passes.
    Returns a correction message, or None."""
    if isinstance(intent, dict) and (intent.get("id") or intent.get("kind") in ("id", "named", "relative_to")):
        return None
    for gid in ctx.goal_ids:
        g = ctx.windows.get(gid)
        if g is None or g.id == w.id or g.seconds <= 0:
            continue
        differs = abs(g.start_utc - w.start_utc) > 60 or abs(g.end_utc - w.end_utc) > 60
        if not differs:
            continue
        ratio = w.seconds / g.seconds
        overlap = max(0.0, min(g.end_utc, w.end_utc) - max(g.start_utc, w.start_utc))
        near_miss = 0.5 <= ratio <= 2.0 and overlap / (min(g.seconds, w.seconds) or 1) >= 0.5
        alt_reading = abs(ratio - 1.0) <= 0.1 and abs(g.start_utc - w.start_utc) < 0.99 * g.seconds
        if near_miss or alt_reading:
            return (f"your window {w.summary()} looks like a different reading of the goal's \"{g.phrase}\", "
                    f"which Kratos resolved as {g.summary()}. Use \"window\": {{\"id\": \"{g.id}\"}}; build a "
                    "different window only for a genuinely different period (e.g. relative_to it for a baseline).")
    return None


def unqueried_goal_windows(ctx: TimeContext | None) -> list[TimeWindow]:
    if ctx is None:
        return []
    return [ctx.windows[i] for i in ctx.goal_ids if i in ctx.windows and i not in ctx.queried]


def result_metadata(ctx: TimeContext) -> dict[str, Any]:
    return {
        "timezone": ctx.tz_name,
        "now_utc": datetime.fromtimestamp(ctx.now, timezone.utc).isoformat(timespec="seconds"),
        "windows": ctx.describe(),
        "goal_window_ids": list(ctx.goal_ids),
        "unresolved": list(ctx.unresolved),
        "queried": {k: sorted(v) for k, v in ctx.queried.items()},
    }


__all__ = ["prepare_time_context", "render_time_block", "check_model_window", "unqueried_goal_windows",
           "result_metadata", "zone_name"]
