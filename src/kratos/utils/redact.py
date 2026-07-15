"""
Secret redaction -- a small, explicit guard applied wherever exception text,
response bodies, or other request-derived strings might reach a print/log
call in a code path that used an API key (LLM_API_KEY, OTX_API_KEY,
ABUSEIPDB_API_KEY).

Confirmed via real testing (llm_interface.py's openai_compatible query
path, not assumed): `requests`'s own exception __str__ methods (ConnectionError,
HTTPError, Timeout, JSONDecodeError -- the realistic failure modes for an
HTTP call) do NOT currently embed the Authorization header, so there was no
active leak to fix. This module exists anyway as an explicit, proactive
guard rather than relying on that being true by the library's incidental
behavior -- a future exception type, a raw response/request dump, or a
stray debug print could otherwise reintroduce a real leak with nothing
structural stopping it.
"""
from __future__ import annotations

_REDACTED = "***REDACTED***"


def redact_secrets(text: str, *secrets: str | None) -> str:
    """
    Returns text with every occurrence of each non-empty secret replaced by
    a placeholder. Call this on any string derived from an exception,
    response, or request before it is ever printed or logged in a code path
    that used one of these secrets. Secrets that are None/empty are skipped
    (nothing to redact -- also avoids the pathological case of replacing
    every occurrence of an empty string).
    """
    for secret in secrets:
        if secret:
            text = text.replace(secret, _REDACTED)
    return text
