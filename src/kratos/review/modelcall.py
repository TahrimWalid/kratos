"""The one model door for a review (E.7b §5.3): every hunter/verifier/fix call goes through
`llm_interface.send_review_request` -> `_metered_call` (the 0.4 budget guard, B.2 masking, the
usage ledger) with no tool list, to the chosen SAVED profile's endpoint.

Two review-specific guarantees here:
- **no code in the run record** (§11): the call runs inside `trace.suppress_prompts()`, so the
  request text is never stored even when `trace.store_prompts` is on; a `review_request` span
  instead records the request's byte size and sha256 and that the code was not kept;
- **secrets are already gone** before this is called: the caller removed secrets from every
  slice (`privacy.secrets.redact`) in every masking mode, so a local or `off`-mode endpoint
  still never receives a secret. Masking of names/addresses happens inside `_metered_call`.
"""
from __future__ import annotations

import hashlib

from kratos.review.profiles import ReviewProfile


class ReviewModelError(RuntimeError):
    """The endpoint returned nothing usable; the review stops cleanly, keeping partial verdicts."""


def call_model(profile: ReviewProfile, system_prompt: str, user_prompt: str, *, max_tokens: int,
               stage: str, cls: str) -> str:
    """Send one review request to `profile`'s endpoint and return the restored reply text."""
    from kratos.llm_interface import send_review_request
    from kratos.trace import recorder as trace

    body_bytes = user_prompt.encode("utf-8", "surrogatepass")
    span = trace.start_span("review_request", f"{stage} {cls}", stage=stage, cls=cls,
                            request_bytes=len(body_bytes), request_sha256=hashlib.sha256(body_bytes).hexdigest(),
                            code_kept=False)
    ok = False
    try:
        with trace.suppress_prompts():
            reply = send_review_request(profile.base_url, profile.api_key, profile.model,
                                        system_prompt=system_prompt, prompt=user_prompt, max_tokens=int(max_tokens))
        if reply is None:
            raise ReviewModelError(f"the {stage} model call returned nothing")
        ok = True
        return reply
    finally:
        span.finish("ok" if ok else "error")
