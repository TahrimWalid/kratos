"""The fix proposal (E.7b §3.8): for each confirmed and needs_validation finding, one extra
tool-less model call proposes the smallest safe change as a patch to the slice. This module only
GETS the proposal and keeps the model's words plus **only the lines the patch adds** (never the
machine's own lines). Whether the fix actually works is checked in the sandbox by reproduce.py
(for a reproduced finding); the fix channel stays OFF -- nothing is ever written to the machine.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from kratos.review import modelcall
from kratos.review import prompts as P
from kratos.review.profiles import ReviewProfile
from kratos.review.slice import Slice

FIX_MAX_TOKENS = 1024
Caller = Callable[..., str]


@dataclass(frozen=True)
class FixProposal:
    words: str                 # the model's one-sentence explanation (secrets removed, <= 500)
    added: str                 # ONLY the lines the patch adds (<= 40), never the machine's own lines
    patch: str                 # the full diff, shown only while the run's screen is open; never stored
    check: str = ""            # set by reproduce.py: 'checked' | 'not_confirmed' | 'not_checked'


def _default_caller(profile: ReviewProfile) -> Caller:
    def call(system_prompt: str, user_prompt: str, *, stage: str, cls: str) -> str:
        return modelcall.call_model(profile, system_prompt, user_prompt, max_tokens=FIX_MAX_TOKENS,
                                    stage=stage, cls=cls)
    return call


def propose(profile: ReviewProfile, sl: Slice, cls: str, *, run_id: str,
            call: Caller | None = None) -> FixProposal:
    from kratos.privacy.secrets import redact
    from kratos.untrusted import frame_text

    call = call or _default_caller(profile)
    clean, _ = redact(sl.text)
    framed = frame_text(clean, kind="code", run_id=run_id, call_id=f"{run_id}-fix-{sl.id}")
    reply = call(P.SYSTEM_FIX, P.fix_user_prompt(cls, framed), stage="fix", cls=cls)
    patch = P.parse_patch(reply)
    return FixProposal(words=patch["explanation"], added=patch["added"], patch=patch["patch"])
