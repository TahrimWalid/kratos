"""Pure judgement: which successful SSH logins came from an address that was guessing.

"Guessing" means password-type failures only (wrong password, unknown user, PAM
authentication failure, keyboard-interactive failure). Failed *publickey* attempts are
not guessing: an SSH client with several keys tries each one, and an admin's normal
login shows a few "Failed publickey" lines before "Accepted publickey".

Severity of a hit: the login used a password / keyboard-interactive -> critical (the
guessing most likely worked); the login used a key -> high (the address that was
guessing passwords also holds a key that works here: a stolen key, or the same person
-- worth a look either way).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

LOOKBACK_SECONDS = 24 * 3600          # failures before a login that count toward it
MIN_FAILURES = 3                      # the burst threshold (auth_log_patterns: 3 in 5 min)

_GUESS = re.compile(r"\b(Failed password|Failed keyboard-interactive|Invalid user|authentication failure|"
                    r"maximum authentication attempts exceeded|Failed none)\b", re.IGNORECASE)
_PUBKEY_FAIL = re.compile(r"\bFailed publickey\b", re.IGNORECASE)
_METHOD = re.compile(r"\bAccepted (password|keyboard-interactive(?:/pam)?|publickey|gssapi-with-mic|hostbased)\b",
                     re.IGNORECASE)


@dataclass(frozen=True)
class Login:
    ts: float
    ip: str
    user: str
    message: str
    event_id: str = ""


@dataclass(frozen=True)
class Failure:
    ts: float
    ip: str
    user: str
    message: str


@dataclass
class Hit:
    ip: str
    user: str
    login_ts: float
    method: str                        # password | keyboard-interactive | publickey | other
    failures: int
    first_failure_ts: float
    last_failure_ts: float
    users_tried: list[str] = field(default_factory=list)
    login_event_id: str = ""

    @property
    def severity(self) -> str:
        return "critical" if self.method in ("password", "keyboard-interactive") else "high"


def is_guess(message: str) -> bool:
    return bool(_GUESS.search(message or "")) and not _PUBKEY_FAIL.search(message or "")


def method_of(message: str) -> str:
    m = _METHOD.search(message or "")
    if not m:
        return "other"
    word = m.group(1).lower()
    return "keyboard-interactive" if word.startswith("keyboard-interactive") else word


def judge(logins: Iterable[Login], failures_by_ip: dict[str, list[Failure]]) -> list[Hit]:
    """One hit per (address, user, login) whose address had >= MIN_FAILURES guesses in
    the LOOKBACK_SECONDS before the login."""
    hits: list[Hit] = []
    for login in sorted(logins, key=lambda x: x.ts):
        prior = [f for f in failures_by_ip.get(login.ip, [])
                 if login.ts - LOOKBACK_SECONDS <= f.ts < login.ts and is_guess(f.message)]
        if len(prior) < MIN_FAILURES:
            continue
        tried = sorted({f.user for f in prior if f.user})
        hits.append(Hit(ip=login.ip, user=login.user, login_ts=login.ts, method=method_of(login.message),
                        failures=len(prior), first_failure_ts=min(f.ts for f in prior),
                        last_failure_ts=max(f.ts for f in prior), users_tried=tried[:10],
                        login_event_id=login.event_id))
    return hits


def as_dict(hit: Hit) -> dict[str, Any]:
    return {"ip": hit.ip, "user": hit.user, "login_ts": hit.login_ts, "method": hit.method,
            "failures": hit.failures, "first_failure_ts": hit.first_failure_ts,
            "last_failure_ts": hit.last_failure_ts, "users_tried": hit.users_tried,
            "login_event_id": hit.login_event_id, "severity": hit.severity}
