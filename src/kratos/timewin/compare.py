"""
Period comparisons computed in code (docs/time_window_design.md §2F "Comparisons").

The model never compares two numbers itself. `compare_measurements` takes the exhaustive
measurement of each window and returns a table plus a verdict per consecutive pair
(chronological order), with three safeguards:

- **rates, not totals**: every value is also expressed per day of COVERED time, so
  February vs March, or "this month so far" vs all of last month, compare fairly;
- **coverage first**: a window with under MIN_COVERAGE_PERCENT coverage, or two windows
  whose coverage differs by more than MAX_COVERAGE_GAP points, is "not_comparable" -- a
  trend can't be read off data that isn't there;
- **noise is not a trend**: under "the rate didn't change", B's share of the combined
  count is Binomial(n = a + b, p = t_B / (t_A + t_B)). A difference counts as an increase
  or decrease only if that is unlikely (two-sided p < ALPHA); otherwise the verdict is
  "no_meaningful_change" -- so 3 vs 5 is not reported as "+67 %".

The verdict is the ONLY thing a structured `trend` claim can cite (timewin.claims).
"""
from __future__ import annotations

import math
from typing import Any

MIN_COVERAGE_PERCENT = 50.0
MAX_COVERAGE_GAP = 30.0
ALPHA = 0.05
_EXACT_LIMIT = 2000  # exact binomial up to this many events, normal approximation above

VERDICTS = ("increase", "decrease", "no_meaningful_change", "not_comparable")


def _binom_two_sided_p(k: int, n: int, p: float) -> float:
    """Two-sided p-value of observing k successes in n trials with success prob p."""
    if n == 0:
        return 1.0
    if n <= _EXACT_LIMIT:
        logs = [math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
                + (i * math.log(p) if p > 0 else (0.0 if i == 0 else -math.inf))
                + ((n - i) * math.log(1 - p) if p < 1 else (0.0 if i == n else -math.inf))
                for i in range(n + 1)]
        pk = logs[k]
        total = sum(math.exp(lp) for lp in logs if lp <= pk + 1e-9)
        return min(1.0, total)
    mu, sd = n * p, math.sqrt(n * p * (1 - p))
    if sd == 0:
        return 1.0 if k == mu else 0.0
    z = abs(k - mu) / sd
    return math.erfc(z / math.sqrt(2))


def pair_verdict(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """a = earlier window row, b = later row (see compare_measurements)."""
    reasons: list[str] = []
    if min(a["coverage_percent"], b["coverage_percent"]) < MIN_COVERAGE_PERCENT:
        reasons.append(f"coverage too low ({a['coverage_percent']:g}% vs {b['coverage_percent']:g}%)")
    if abs(a["coverage_percent"] - b["coverage_percent"]) > MAX_COVERAGE_GAP:
        reasons.append(f"coverage differs too much ({a['coverage_percent']:g}% vs {b['coverage_percent']:g}%)")
    if a["covered_seconds"] <= 0 or b["covered_seconds"] <= 0:
        reasons.append("a window has no covered time")
    if reasons:
        return {"from": a["window"], "to": b["window"], "verdict": "not_comparable", "reasons": reasons}
    ca, cb = int(a["value"]), int(b["value"])
    ta, tb = a["covered_seconds"], b["covered_seconds"]
    p_value = _binom_two_sided_p(cb, ca + cb, tb / (ta + tb))
    ra, rb = a["rate_per_day"], b["rate_per_day"]
    if p_value >= ALPHA or ra == rb:
        verdict = "no_meaningful_change"
    else:
        verdict = "increase" if rb > ra else "decrease"
    change = None if ra == 0 else round(100.0 * (rb - ra) / ra, 1)
    return {"from": a["window"], "to": b["window"], "verdict": verdict, "p_value": round(p_value, 4),
            "rate_change_percent": change,
            "explanation": (f"{ca} in {ta / 86400:.2f} covered days vs {cb} in {tb / 86400:.2f}: "
                            + ("a real difference" if verdict in ("increase", "decrease")
                               else "within normal variation -- not a meaningful change"))}


def compare_measurements(metric: str, windows: list[tuple[Any, dict[str, Any]]]) -> dict[str, Any]:
    """`windows`: [(TimeWindow, measurement_summary + coverage info)] in any order.
    Each summary needs metrics[metric], coverage_percent and covered_seconds."""
    rows = []
    spans: list[tuple[float, float]] = []
    for w, summ in sorted(windows, key=lambda x: x[0].start_utc):
        end = getattr(w, "end_utc", None)
        spans.append((float(w.start_utc), float(end if end is not None else w.start_utc + getattr(w, "seconds", 0.0))))
        value = int(summ["metrics"][metric])
        covered = float(summ["covered_seconds"])
        rows.append({
            "window": w.id, "label": w.label, "value": value,
            "coverage_percent": float(summ["coverage_percent"]), "covered_seconds": covered,
            "rate_per_day": round(value / (covered / 86400.0), 3) if covered > 0 else None,
        })
    pairs = []
    for i, (a, b) in enumerate(zip(rows, rows[1:])):
        # Overlapping periods count the same events twice, so their difference means
        # nothing (seen live: 'this week so far' vs 'the last 7 days', a '65% decrease').
        overlap = min(spans[i][1], spans[i + 1][1]) - max(spans[i][0], spans[i + 1][0])
        if overlap > 60:
            pairs.append({"from": a["window"], "to": b["window"], "verdict": "not_comparable", "reasons": [
                f"the periods overlap by {overlap / 86400:.1f} days, so the same events are counted in both"]})
        else:
            pairs.append(pair_verdict(a, b))
    return {"metric": metric, "windows": rows, "pairs": pairs}
