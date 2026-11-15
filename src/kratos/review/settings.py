"""The `review.*` settings (Settings -> General -> "AI review of deployed code"), people-only
like every setting, read fresh per run. `review.max_read_mb` belongs to E.7a's read
(kratos.code.settings); everything else about a review is here."""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.budget.limits import _dollars, _on_off
from kratos.collect.settings import _whole
from kratos.settings_store import SettingError, SettingSpec

MAX_RUN_USD = "review.max_run_usd"
LLM_PROFILE = "review.llm_profile"
VERIFIER_LLM_PROFILE = "review.verifier_llm_profile"
MAX_SLICES = "review.max_slices"
MAX_SLICE_BYTES = "review.max_slice_bytes"
SLICE_DEPTH = "review.slice_depth"
MAX_LEADS = "review.max_leads"
MAX_LEADS_PER_CALL = "review.max_leads_per_call"
LEAD_FACTOR = "review.lead_factor"
PLAN_TTL_MINUTES = "review.plan_ttl_minutes"
SANDBOX_REPRODUCTION = "review.sandbox_reproduction"
PARALLEL_CALLS = "review.parallel_calls"


def _profile_name(value: Any) -> str:
    """A saved profile is named by its model (adapters.llm_profiles). Empty = none chosen."""
    if not isinstance(value, str):
        raise SettingError("the name of a saved model profile (see /model), or empty")
    text = value.strip()
    if len(text) > 200 or any(ord(c) < 32 for c in text):
        raise SettingError("the name of a saved model profile (see /model), or empty")
    return text


def _fraction(value: Any) -> float:
    try:
        f = float(str(value).strip())
    except (TypeError, ValueError):
        raise SettingError("a number from 0.05 to 5") from None
    if isinstance(value, bool) or not 0.05 <= f <= 5:
        raise SettingError("a number from 0.05 to 5")
    return f


for _spec in (
    SettingSpec(MAX_RUN_USD, 2.00, _dollars,
                "The most one AI code review may cost; a review estimated above it is refused unless a person "
                "raises it for that run. It never raises the daily budget."),
    SettingSpec(LLM_PROFILE, "", _profile_name,
                "The saved model profile code reviews use when a person doesn't pick one. Empty: a person picks "
                "one for each review (nothing is sent to the active model by default)."),
    SettingSpec(VERIFIER_LLM_PROFILE, "", _profile_name,
                "A second saved profile that tries to disprove each lead. Empty: the review's own profile."),
    SettingSpec(MAX_SLICES, 300, _whole(1, 5000, "slices"),
                "The most code slices one review sends; changed-on-server code is always reviewed first, and the "
                "rest is counted, never silently skipped."),
    SettingSpec(MAX_SLICE_BYTES, 64 * 1024, _whole(1024, 1024 * 1024, "bytes"),
                "The largest slice sent in one piece; a longer one is split by function, and one function over "
                "it is skipped and counted."),
    SettingSpec(SLICE_DEPTH, 4, _whole(1, 8, "calls"),
                "How many calls deep a slice follows from a network route into the folder's own functions."),
    SettingSpec(MAX_LEADS, 200, _whole(1, 2000, "leads"),
                "The most leads one review checks; more are counted."),
    SettingSpec(MAX_LEADS_PER_CALL, 20, _whole(1, 200, "leads"),
                "The most leads Kratos accepts from one model reply."),
    SettingSpec(LEAD_FACTOR, 0.3, _fraction,
                "How many leads per slice the cost estimate assumes."),
    SettingSpec(PLAN_TTL_MINUTES, 10, _whole(1, 120, "minutes"),
                "How long a prepared review plan stays valid before it is prepared again."),
    SettingSpec(SANDBOX_REPRODUCTION, True, _on_off,
                "Reproduce Python leads in Kratos's no-network sandbox, with the dangerous call replaced by a "
                "recorder (needs Incus on this computer)."),
    SettingSpec(PARALLEL_CALLS, 2, _whole(1, 8, "calls"),
                "How many review requests may be in flight at once."),
):
    settings_store.register(_spec)


def get(key: str, data_dir: Any) -> Any:
    return settings_store.get(key, data_dir=data_dir)
