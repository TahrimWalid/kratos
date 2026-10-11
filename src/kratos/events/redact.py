"""Credential masking and size caps for event text, applied at conversion --
before anything is stored.

Masked: values after credential flags (`--password`, `--passwd`, `--token`,
`--secret`, `--api-key`), credential assignments (`PASSWORD=`, `DB_PASSWORD=`,
`TOKEN=`, `SECRET=`, `API_KEY=`, any case), `-p<x>` for the MySQL/MariaDB
clients and `-p <x>`/`-p<x>` for sshpass (only those programs: `ssh -p 22` is a
port), URL userinfo passwords (`scheme://user:PASS@`), HTTP `Authorization:`
values, and the API keys Kratos itself holds (utils/redact.redact_secrets).

Left alone on purpose: a user literally named "password", paths like
/etc/passwd, other programs' `-p` options.
"""
from __future__ import annotations

import os
import re

from kratos.utils.redact import _REDACTED as MASK
from kratos.utils.redact import redact_secrets

_VALUE = r"""(?:"[^"]*"|'[^']*'|[^\s"'&;|]+)"""

# --password=x / --password x / --api-key=x ...
_FLAG = re.compile(
    rf"(?P<key>--(?:password|passwd|pass|token|secret|api[-_]?key|access[-_]token|auth[-_]token))"
    rf"(?P<sep>=|\s+)(?P<val>{_VALUE})", re.IGNORECASE)
# PASSWORD=x, DB_PASSWORD=x, github_token=x ... (not "user=password")
_ASSIGN = re.compile(
    rf"(?<![\w.-])(?P<key>[A-Za-z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY))=(?P<val>{_VALUE})",
    re.IGNORECASE)
# scheme://user:PASS@host
_URL_USERINFO = re.compile(r"(?P<pre>\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)(?P<val>[^\s@/]+)(?=@)", re.IGNORECASE)
# Authorization: Bearer xyz / Authorization: xyz
_AUTH_HEADER = re.compile(
    r"(?P<pre>\b(?:proxy-)?authorization\s*:\s*(?:(?:basic|bearer|digest|token|negotiate)\s+)?)(?P<val>[^\s,;]+)",
    re.IGNORECASE)
# The clients whose -p carries a password. mysql/mariadb: only the attached form
# (`-p secret` there means "prompt", and `secret` is the database name).
_MYSQL_LIKE = re.compile(r"(?<![\w/.-])(?:\S*/)?(?:mysql|mariadb|mysqldump|mysqladmin|mariadb-dump)(?=\s)")
_SSHPASS = re.compile(r"(?<![\w/.-])(?:\S*/)?sshpass(?=\s)")
_SEGMENT_END = re.compile(r"[;&|]")
_MYSQL_P = re.compile(r"(?<!\S)-p(?P<val>[^\s-][^\s]*)")
_SSHPASS_P = re.compile(rf"(?<!\S)-p(?:\s+)?(?P<val>{_VALUE})")

# Secrets Kratos holds, by the environment variables that carry them.
_KNOWN_SECRET_VARS = ("LLM_API_KEY", "OTX_API_KEY", "ABUSEIPDB_API_KEY")


def _known_secrets() -> list[str]:
    values = [os.environ.get(v) for v in _KNOWN_SECRET_VARS]
    try:
        from kratos.llm_config import get_active_llm_api_key

        values.append(get_active_llm_api_key())
    except Exception:  # noqa: BLE001 -- masking must never fail on config trouble
        pass
    # Too-short values (Ollama's "ollama" placeholder) would mask ordinary words.
    return [v for v in values if v and len(v) >= 12]


def _mask_client_p(text: str, client: re.Pattern[str], option: re.Pattern[str]) -> str:
    out, pos = [], 0
    for m in client.finditer(text):
        if m.start() < pos:
            continue
        end_m = _SEGMENT_END.search(text, m.end())
        seg_end = end_m.start() if end_m else len(text)
        opt = option.search(text, m.end(), seg_end)
        if opt is None:
            continue
        out.append(text[pos:opt.start("val")])
        out.append(MASK)
        pos = opt.end("val")
    out.append(text[pos:])
    return "".join(out)


def mask(text: str) -> tuple[str, bool]:
    """(masked text, whether anything changed)."""
    if not text:
        return text, False
    masked = _FLAG.sub(lambda m: f"{m['key']}{m['sep']}{MASK}", text)
    masked = _ASSIGN.sub(lambda m: f"{m['key']}={MASK}", masked)
    masked = _URL_USERINFO.sub(lambda m: f"{m['pre']}{MASK}", masked)
    masked = _AUTH_HEADER.sub(lambda m: f"{m['pre']}{MASK}", masked)
    masked = _mask_client_p(masked, _MYSQL_LIKE, _MYSQL_P)
    masked = _mask_client_p(masked, _SSHPASS, _SSHPASS_P)
    masked = redact_secrets(masked, *_known_secrets())
    return masked, masked != text


def cap(text: str, max_bytes: int) -> tuple[str, bool]:
    """`text` cut to at most `max_bytes` UTF-8 bytes on a character boundary."""
    raw = text.encode("utf-8", "surrogatepass")
    if len(raw) <= max_bytes:
        return text, False
    return raw[:max_bytes].decode("utf-8", "ignore"), True


def clean(text: str | None, max_bytes: int) -> tuple[str | None, bool, bool]:
    """Mask, then cap (a secret must never survive half-cut). Returns
    (text, redacted, truncated)."""
    if text is None:
        return None, False, False
    masked, redacted = mask(text)
    capped, truncated = cap(masked, max_bytes)
    return capped, redacted, truncated
