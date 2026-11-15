"""The verifier (E.7b §3.6): each lead goes to a FRESH, tool-less call -- a separate
conversation, optionally on a different saved profile, so its mistakes are less correlated with
the hunter's. Its only job is to name a concrete reason the lead is NOT reachable with outside
input. A disproof must point at a line IN THE SLICE; one that doesn't counts as "could not
disprove". No verdict or severity is read from the reply.
"""
from __future__ import annotations

from typing import Callable

from kratos.review import modelcall
from kratos.review import prompts as P
from kratos.review.profiles import ReviewProfile
from kratos.review.slice import Slice
from kratos.review.verdict import Disproof

VERIFIER_MAX_TOKENS = 512
Caller = Callable[..., str]


def _line_in_slice(sl: Slice, line: int) -> bool:
    return any(a <= line <= b for _rel, a, b in sl.segments)


def _default_caller(profile: ReviewProfile) -> Caller:
    def call(system_prompt: str, user_prompt: str, *, stage: str, cls: str) -> str:
        return modelcall.call_model(profile, system_prompt, user_prompt, max_tokens=VERIFIER_MAX_TOKENS,
                                    stage=stage, cls=cls)
    return call


def verify(profile: ReviewProfile, lead: P.Lead, sl: Slice, *, run_id: str,
           call: Caller | None = None) -> Disproof | None:
    """A disproof for `lead`, or None ('could not disprove'). The slice is framed as data and
    masked (secrets removed first)."""
    from kratos.privacy.secrets import redact
    from kratos.untrusted import frame_text

    call = call or _default_caller(profile)
    clean, _ = redact(sl.text)
    framed = frame_text(clean, kind="code", run_id=run_id, call_id=f"{run_id}-verify-{sl.id}")
    user = P.verifier_user_prompt(lead.cls, lead.line, lead.file, framed)
    reply = call(P.SYSTEM_VERIFIER, user, stage="verifier", cls=lead.cls)
    d = P.parse_disproof(reply)
    if d is None:
        return None
    if not _line_in_slice(sl, d["line"]):
        return None                             # a disproof must cite a line in the slice
    return Disproof(reason=d["reason"], line=int(d["line"]))
