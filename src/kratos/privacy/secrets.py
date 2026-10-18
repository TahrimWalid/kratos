"""Secrets removed from text before it is sent to the model -- never put back.

Applied first, before any value gets a placeholder, so a secret can never be turned
into something that is later restored. Reuses what Kratos already masks
(`events.redact.mask`: credential flags and assignments, URL passwords, HTTP
Authorization values, mysql/sshpass `-p`, the API keys Kratos holds, journal
verification keys) and adds the shapes that matter in model text: private-key
blocks, `"password": "..."` / `token: ...` pairs, bearer tokens, and the key formats
of AWS, Google Cloud, GitHub, Slack and JSON web tokens.
"""
from __future__ import annotations

import re

from kratos.events import redact as _events_redact

REDACTED = "[REDACTED]"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL)
_SECRET_KEYS = (r"password|passwd|secret|token|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
                r"refresh[_-]?token|client[_-]?secret|private[_-]?key|secret[_-]?key|aws_secret_access_key")
# "password": "x", 'token': 'x', password: x (YAML), \"secret\": \"x\" (JSON inside a JSON string)
_KEY_VALUE = re.compile(
    rf"""(?P<pre>(?<![\w-])(?P<q>\\?["']?)(?:{_SECRET_KEYS})(?P=q)\s*:\s*)"""
    rf"""(?P<val>\\?"(?:[^"\\]|\\[^"])*\\?"|\\?'[^']*\\?'|[^\s,;}}\]]+)""",
    re.IGNORECASE)
_BEARER = re.compile(r"(?P<pre>\bbearer\s+)(?P<val>[A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE)
_TOKEN_SHAPES = re.compile(
    r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"      # AWS access key ids
    r"|\bAIza[0-9A-Za-z_-]{35}\b"                              # Google API key
    r"|\bya29\.[0-9A-Za-z_-]{20,}"                             # Google OAuth access token
    r"|\bgh[pousr]_[A-Za-z0-9]{36,}\b"                         # GitHub tokens
    r"|\bgithub_pat_[A-Za-z0-9_]{22,}\b"
    r"|\bglpat-[A-Za-z0-9_-]{20,}\b"                           # GitLab
    r"|\bxox[abposr]-[A-Za-z0-9-]{10,}\b"                      # Slack
    r"|\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"                    # OpenAI-style API keys
    r"|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")  # JSON web tokens


_NOT_A_SECRET = re.compile(r"^(?:-?\d+(?:\.\d+)?|true|false|null|none)$", re.IGNORECASE)


def _value_mask(m: re.Match[str]) -> str:
    val = m.group("val")
    if _NOT_A_SECRET.match(val):          # a count or flag ("token": 5), not a secret
        return m.group(0)
    # keep the value's own quotes so the surrounding JSON stays valid
    for q in ('\\"', '"', "\\'", "'"):
        if len(val) >= 2 * len(q) and val.startswith(q) and val.endswith(q):
            return f"{m.group('pre')}{q}{REDACTED}{q}"
    return f"{m.group('pre')}{REDACTED}"


def redact(text: str) -> tuple[str, int]:
    """(text with every secret replaced by `[REDACTED]`, how many were replaced)."""
    if not text:
        return text, 0
    out = _PRIVATE_KEY.sub(REDACTED, text)
    out = _TOKEN_SHAPES.sub(REDACTED, out)
    out = _BEARER.sub(lambda m: f"{m.group('pre')}{REDACTED}", out)
    out = _KEY_VALUE.sub(_value_mask, out)
    out, _changed = _events_redact.mask(out)
    out = out.replace(_events_redact.MASK, REDACTED)
    return out, max(0, out.count(REDACTED) - text.count(REDACTED) - text.count(_events_redact.MASK))
