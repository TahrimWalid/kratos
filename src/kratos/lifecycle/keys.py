"""A finding's stable identity across runs.

finding_key = sha256(rule_id ␟ target_key ␟ subject), full hex stored, the
first 12 characters shown. The same issue on the same machine is the same
finding every run; `subject` separates per-entity findings of one rule (empty
for every current rule: one finding per rule per machine).
"""
from __future__ import annotations

import hashlib
import re

SHORT = 12
_SEP = "\x1f"   # ␟ -- can't appear in a rule id, a target key or a normalised subject
_SPACE_RE = re.compile(r"\s+")


def normalise_subject(subject: object) -> str:
    """Whitespace-trimmed and collapsed, control characters removed. Case is kept:
    a subject can be a user name or a path, which are case-sensitive on Linux."""
    text = "".join(ch for ch in str(subject or "") if ch.isprintable() or ch.isspace())
    return _SPACE_RE.sub(" ", text).strip()


def finding_key(rule_id: str, target: str, subject: object = "") -> str:
    raw = _SEP.join((str(rule_id), str(target), normalise_subject(subject)))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def short(key: str | None) -> str:
    return (key or "")[:SHORT]
