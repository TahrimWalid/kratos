"""
Structured claims and their verification -- Guard 7 (docs/time_window_design.md §9, §14).

Why: a time-scoped answer's two classic failures are (a) claiming more than was seen
("no failed logins last month" when only 5 days of logs existed) and (b) stating numbers
that were never measured (a live run reported "5,023 distinct IPs" while the tool it had
just called said 4,980). Checking prose alone is fuzzy NLP, so the answer carries
machine-checkable claims next to the prose:

    "claims": [{"kind": "count",   "metric": "ssh_failed_logins", "window": "w1", "value": 5},
               {"kind": "absence", "metric": "sudo_failures",     "window": "w1"},
               {"kind": "unknown", "window": "w1", "reason": "journal starts 22:08"}]

`verify_claims` checks every claim deterministically against what THIS run measured
(TimeContext.measurements, filled by measure_auth_activity) and cross-checks the prose:
numbers stated next to a count word must be values that were actually measured, and time
periods named in the prose must be backed by a claimed window. Violations come back as
correction text for the model (bounded retry, then a visible [NOTE:...], same as every
other guard).
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kratos.timewin.phrases import find_time_phrases
from kratos.timewin.windows import UTC, TimeContext, TimeIntentError, resolve_intent

# metric name -> how to read it from a Measurement (see measure_auth_activity)
METRICS: dict[str, str] = {
    "ssh_failed_logins": "failed SSH logins (incl. invalid users)",
    "ssh_successful_logins": "successful SSH logins (Kratos's own excluded)",
    "sudo_failures": "sudo authentication failures",
    "sudo_commands": "sudo commands run",
    "sudo_sessions": "sudo sessions opened",
    "distinct_failed_login_ips": "distinct source IPs with failed SSH logins",
    "bursts": "brute-force bursts (>=3 failures within 5 minutes)",
    "fail2ban_bans": "IP bans issued by fail2ban",
}
CLAIM_KINDS = ("count", "absence", "presence", "unknown", "trend", "state")

# a number next to one of these words is treated as a claimed measurement
_COUNT_WORD = r"(?:failed|failures?|attempts?|logins?|log-ins?|IPs?|addresses|sources?|hosts?|events?|bursts?|sessions?|commands?|users?|accounts?)"
_NUM = r"(?<![\w.:/-])(\d{1,3}(?:,\d{3})+|\d+)(?![\w.:/%-])"
_NUM_NEAR_WORD = re.compile(rf"{_NUM}\s+(?:\w+\s+){{0,3}}{_COUNT_WORD}\b|\b{_COUNT_WORD}\W+(?:\w+\W+){{0,2}}?{_NUM}", re.IGNORECASE)
# numbers that are durations/percentages/ports/years are never measurements
_NOT_A_COUNT = re.compile(r"^\s*(?:%|percent|hours?|minutes?|mins?|seconds?|secs?|days?|weeks?|months?|years?|h\b|m\b|s\b|am\b|pm\b)", re.IGNORECASE)


_TREND_WORDS = {
    "increase": "increase", "increased": "increase", "up": "increase", "higher": "increase", "more": "increase",
    "decrease": "decrease", "decreased": "decrease", "down": "decrease", "lower": "decrease", "fewer": "decrease",
    "no_meaningful_change": "no_meaningful_change", "no meaningful change": "no_meaningful_change",
    "no change": "no_meaningful_change", "unchanged": "no_meaningful_change", "same": "no_meaningful_change",
    "not_comparable": "not_comparable", "not comparable": "not_comparable",
}


def _trend_word(value: Any) -> str | None:
    """A trend claim's direction in compare_periods' own words. Models copy the tool's
    'verdict' key or write 'decreased' -- the same claim, not an unverifiable one."""
    if value is None:
        return None
    return _TREND_WORDS.get(str(value).strip().lower().replace("-", " "), str(value).strip().lower())


# The answer itself says part of the window was not seen.
_PARTIAL_ACK_RE = re.compile(
    r"\bunknown\b|\bnot (?:been )?(?:covered|seen|visible|available)\b|\bunavailable\b|"
    r"\bonly \d+(?:\.\d+)?\s?%|\b(?:partial|limited) (?:coverage|visibility)\b|\bno (?:logs?|records?|data) "
    r"(?:before|prior to|for)\b",
    re.IGNORECASE,
)


def measurement_summary(m: Any) -> dict[str, Any]:
    """What gets recorded per window for later verification (from a Measurement)."""
    counts = m.counts
    metrics = {
        "ssh_failed_logins": int(counts.get("ssh_failed_login", 0)),
        "ssh_successful_logins": int(counts.get("ssh_success_login", 0)),
        "sudo_failures": int(counts.get("sudo_auth_failure", 0)) + int(counts.get("sudo_pam_auth_failure", 0)),
        "sudo_commands": int(counts.get("sudo_command", 0)),
        "sudo_sessions": int(counts.get("sudo_session_open", 0)),
        "distinct_failed_login_ips": len(m.by_ip),
        "bursts": len(m.bursts),
        "fail2ban_bans": sum(1 for e in m.fail2ban if e["action"] == "ban"),
    }
    values = set(metrics.values())
    values.update(int(d["count"]) for d in m.by_ip.values())
    values.update(int(v) for v in m.by_user.values())
    values.update(int(v) for v in counts.values())
    values.update(int(b["count"]) for b in m.bursts)
    return {"metrics": metrics, "coverage_percent": m.coverage()["percent"], "values": values}


_ABSENCE_NEAR_WORD = re.compile(rf"\b(?:no|zero|none of the|not a single|not any)\s+(?:\w+\s+){{0,3}}{_COUNT_WORD}\b",
                                re.IGNORECASE)


def _states_a_measurement(answer: str) -> bool:
    """Does the prose state a count or a 'none'? Only those need a claims list. Seen live
    (demo): 'I cannot confirm whether port 22 was open yesterday' -- no number, no
    'none' -- was stamped 'carries no claims list, treat as unverified'."""
    for m in _NUM_NEAR_WORD.finditer(answer or ""):
        end = m.end(1) if m.group(1) else m.end(2)
        if not _NOT_A_COUNT.match(answer[end:]):
            return True
    return bool(_ABSENCE_NEAR_WORD.search(answer or ""))


def is_time_scoped(ctx: TimeContext | None) -> bool:
    return bool(ctx and (ctx.goal_ids or ctx.measurements))


def _num(text: str) -> int:
    return int(text.replace(",", ""))


def verify_claims(ctx: TimeContext, answer: str, claims: Any) -> tuple[list[str], list[dict[str, Any]]]:
    """(problems, annotated_claims). `problems` empty => the answer's time/number
    statements are all backed by this run's measurements."""
    problems: list[str] = []
    annotated: list[dict[str, Any]] = []
    if claims is None:
        claims = []
    if not isinstance(claims, list):
        return ["\"claims\" must be a list of claim objects"], []

    measured_values: set[int] = set()
    for rec in ctx.measurements.values():
        measured_values |= rec.get("values", set())

    if not claims and ctx.measurements and _states_a_measurement(answer):
        problems.append("this answer is about a time period but carries no \"claims\" list -- add one claim per "
                        "number or 'none' statement, each tied to a window id")

    claimed_windows: set[str] = set()
    for i, c in enumerate(claims):
        tag = f"claim #{i + 1}"
        if not isinstance(c, dict):
            problems.append(f"{tag} is not an object")
            continue
        kind, metric, wid = c.get("kind"), c.get("metric"), str(c.get("window") or "")
        rec: dict[str, Any] = {**c, "verified": False}
        annotated.append(rec)
        if kind not in CLAIM_KINDS:
            problems.append(f"{tag}: kind must be one of {CLAIM_KINDS}")
            continue
        if kind == "state":
            # a past-state statement must cite a snapshot state_as_of actually returned
            if f"snapshot:{c.get('snapshot')}" not in ctx.measurements:
                problems.append(f"{tag}: a state claim must cite a snapshot_id returned by state_as_of in this run")
                continue
            rec["verified"] = True
            continue
        if kind == "trend":
            # only a compare_periods verdict can back a trend (never the model's own arithmetic)
            comp = ctx.measurements.get(f"compare:{c.get('comparison')}")
            if comp is None:
                problems.append(f"{tag}: a trend claim must cite a compare_periods result: \"comparison\": \"c1\"")
                continue
            pairs = comp["pairs"]
            if c.get("from") and c.get("to"):
                pairs = [p for p in pairs if p["from"] == c["from"] and p["to"] == c["to"]]
            if len(pairs) != 1:
                problems.append(f"{tag}: comparison {c.get('comparison')} has {len(comp['pairs'])} pairs -- "
                                "say which with \"from\"/\"to\" window ids")
                continue
            claimed = _trend_word(c.get("direction", c.get("verdict", c.get("trend"))))
            if claimed != pairs[0]["verdict"]:
                problems.append(f"{tag}: compare_periods concluded {pairs[0]['verdict']!r}, not {claimed!r}"
                                + ("" if claimed else " (give it as \"direction\")"))
                continue
            rec["verified"] = True
            claimed_windows.update({pairs[0]["from"], pairs[0]["to"]})
            continue
        try:
            w = ctx.get(wid)
        except TimeIntentError:
            problems.append(f"{tag}: window {wid!r} is not a window of this investigation")
            continue
        claimed_windows.add(w.id)
        if kind == "unknown":
            rec["verified"] = True
            continue
        if w.id not in ctx.queried:
            problems.append(f"{tag}: window {w.id} was never queried -- you cannot state anything about it")
            continue
        if metric not in METRICS:
            problems.append(f"{tag}: unknown metric {metric!r}; use one of {', '.join(METRICS)}")
            continue
        meas = ctx.measurements.get(w.id)
        if meas is None:
            problems.append(f"{tag}: {w.id} has no exhaustive measurement -- counts and 'none' statements must "
                            "come from measure_auth_activity for that window, not from reading log lines")
            continue
        actual = meas["metrics"][metric]
        cov = meas["coverage_percent"]
        if kind == "count":
            try:
                claimed = int(str(c.get("value")).replace(",", ""))
            except (TypeError, ValueError):
                problems.append(f"{tag}: a count claim needs an integer \"value\"")
                continue
            if claimed != actual:
                problems.append(f"{tag}: {metric} in {w.id} was measured as {actual}, not {claimed}")
                continue
        elif kind == "absence":
            if actual != 0:
                problems.append(f"{tag}: {metric} in {w.id} is {actual}, so 'none' is false")
                continue
            if cov < 100.0:
                if _PARTIAL_ACK_RE.search(answer or ""):
                    # The prose already says the rest is unknown (seen live: "no failed logins in
                    # the observed period ... activity before 15:24 is unknown") -- the 'none' is
                    # about the covered part, which is what was measured.
                    rec["partial"] = True
                else:
                    problems.append(f"{tag}: only {cov:g}% of {w.id} was covered, so 'none' cannot be claimed for the "
                                    "whole window -- claim the covered part and mark the rest \"unknown\"")
                    continue
        elif kind == "presence" and actual <= 0:
            problems.append(f"{tag}: {metric} in {w.id} was measured as 0")
            continue
        rec["verified"] = True
        rec["measured"] = actual
        rec["coverage_percent"] = cov

    # --- prose cross-checks -------------------------------------------------
    if ctx.measurements:
        for m in _NUM_NEAR_WORD.finditer(answer):
            raw = m.group(1) or m.group(2)
            end = m.end(1) if m.group(1) else m.end(2)
            if _NOT_A_COUNT.match(answer[end:]):
                continue
            n = _num(raw)
            if n not in measured_values and n not in (0, 1):
                problems.append(f"the answer states \"{m.group(0).strip()}\", but no measurement in this run "
                                f"produced {n} -- quote the measured numbers exactly")
    utc_ctx = TimeContext(UTC, now=ctx.now)
    now_local = datetime.fromtimestamp(ctx.now, ctx.tz).replace(tzinfo=None)
    for p in find_time_phrases(answer, now_local):
        # a bare date ("on 2026-09-27 ...") only locates the day of a more specific statement
        if p.status not in ("resolved", "default") or not p.intent or p.pattern in ("date", "on_weekday"):
            continue
        explicit_utc = re.match(r"\s*(?:UTC|GMT|Z)\b", answer[p.end:p.end + 6] or "")
        try:
            start, end, _, _ = resolve_intent(p.intent, utc_ctx if explicit_utc else ctx)
        except TimeIntentError:
            continue
        if not any(_covers(ctx.windows[wid], start, end) for wid in claimed_windows | set(ctx.queried) if wid in ctx.windows):
            problems.append(f"the answer mentions \"{p.text}\", a period no query in this run covered -- "
                            "only state periods you actually queried")
    return problems, annotated


def _covers(w: Any, start: float, end: float, slack: float = 120.0) -> bool:
    return start >= w.start_utc - slack and end <= w.end_utc + slack
