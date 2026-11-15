"""Cost of a review: the estimate, the ceiling, and the stop at the agreed amount (E.7b
§3.10, gate answer 2).

The estimate is built from the **real batches** a prepare produced (not a guess at the code
size): the hunter calls are the batches, the verifier and fix calls are an estimated lead
count (``review.lead_factor`` per slice), each priced at the chosen profile's rate. A review
is **refused above ``review.max_run_usd``** unless a person raises it for that run, and is also
refused if it wouldn't fit **what is left of today's ``budget.daily_cost_usd``**. For a review
run the estimate's calls and tokens **become the run's limits plus a fixed margin** (replacing
0.4's 40-call / 300,000-token per-run caps, which run.py overrides for the review scope only);
every other run keeps 0.4's limits. The run stops cleanly when actual spend reaches the agreed
amount, keeping every verdict reached.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from kratos.budget.pricing import tokens_cost

EPS = 1e-9
# Rough per-call shape for the estimate (the spec calls the estimate approximate). A margin on
# the agreed amount absorbs the imprecision.
PER_CALL_OVERHEAD_TOKENS = 400        # fixed system prompt + framing around a slice
COMPLETION_TOKENS_PER_CALL = 300      # a leads list / a disproof / a small patch
FIXED_MARGIN = 0.25                   # the run's call/token limits are estimate * (1 + margin) + floors
MARGIN_CALLS_FLOOR = 2
MARGIN_TOKENS_FLOOR = 2000


@dataclass(frozen=True)
class Estimate:
    hunter_calls: int
    verifier_calls: int
    fix_calls: int
    input_tokens: int
    output_tokens: int
    usd: float                        # 0.0 when the profile has no rate (local / unpriced model)
    priced: bool

    @property
    def calls(self) -> int:
        return self.hunter_calls + self.verifier_calls + self.fix_calls

    @property
    def tokens(self) -> int:
        return self.input_tokens + self.output_tokens


def estimate(batch_input_tokens: list[int], num_slices: int, avg_slice_tokens: int, *, lead_factor: float,
             rate: tuple[float, float] | None, max_leads: int) -> Estimate:
    """`batch_input_tokens`: the input tokens of each hunter batch (framing included).
    `avg_slice_tokens`: a typical slice's token count, for the per-lead verifier and fix calls."""
    hunter_calls = len(batch_input_tokens)
    hunter_in = sum(int(t) for t in batch_input_tokens)
    est_leads = min(int(max_leads), max(0, math.ceil(lead_factor * max(0, num_slices))))
    verifier_calls = est_leads
    fix_calls = est_leads                 # one fix call per finding; leads is the upper bound
    per_lead_in = max(0, int(avg_slice_tokens)) + PER_CALL_OVERHEAD_TOKENS
    input_tokens = hunter_in + (verifier_calls + fix_calls) * per_lead_in
    calls = hunter_calls + verifier_calls + fix_calls
    output_tokens = calls * COMPLETION_TOKENS_PER_CALL
    if rate is None:
        return Estimate(hunter_calls, verifier_calls, fix_calls, input_tokens, output_tokens, 0.0, False)
    usd = tokens_cost(rate, input_tokens, output_tokens) or 0.0
    return Estimate(hunter_calls, verifier_calls, fix_calls, input_tokens, output_tokens, float(usd), True)


def ceiling_for(max_run_usd: float, raised_to: float | None) -> float:
    """The dollar ceiling in force for this run: the raised amount if a person raised it, else
    `review.max_run_usd`."""
    if raised_to is not None and raised_to > 0:
        return float(raised_to)
    return float(max_run_usd)


def fits_ceiling(estimate_usd: float, max_run_usd: float, raised_to: float | None = None) -> bool:
    return estimate_usd <= ceiling_for(max_run_usd, raised_to) + EPS


def fits_daily(estimate_usd: float, remaining_daily_usd: float) -> bool:
    """A priced estimate must fit what is left of today's daily cost cap. An unpriced
    (local) estimate always fits -- it spends no dollars."""
    if estimate_usd <= EPS:
        return True
    return estimate_usd <= remaining_daily_usd + EPS


def run_limits(est_calls: int, est_tokens: int) -> tuple[int, int]:
    """The review run's own call and token limits: the estimate plus a fixed margin. These
    replace 0.4's per-run caps for the review scope only."""
    call_limit = int(math.ceil(est_calls * (1 + FIXED_MARGIN))) + MARGIN_CALLS_FLOOR
    token_limit = int(math.ceil(est_tokens * (1 + FIXED_MARGIN))) + MARGIN_TOKENS_FLOOR
    return call_limit, token_limit


def would_exceed(spent_usd: float, reserve_usd: float, agreed_usd: float) -> bool:
    """True when the next call's reserve would push actual spend past the agreed amount; the
    run stops cleanly before making it (§3.10)."""
    return spent_usd + max(0.0, reserve_usd) > agreed_usd + EPS
