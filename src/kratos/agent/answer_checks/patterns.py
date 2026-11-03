"""The phrase patterns and small text helpers the answer checks use.

Moved here from ``agent/loop.py`` unchanged (D.2 §5.1) so a single-machine answer and
each machine's part of a fleet answer are judged by the same code. ``agent/loop.py``
re-exports every name for the callers and tests that import them from there.
"""

from __future__ import annotations

import json
import re
from typing import Any

from kratos import finding_facts as _finding_facts


def _plain_claim_problem(problem: str, time_ctx: Any) -> str:
    """A Guard 7 problem as the USER reads it: without the instruction meant for the
    model (after ' -- ') or the 'claim #N:' tag, and with window ids as their period
    ('w1' -> 'the last 24 hours')."""
    text = re.sub(r"^claim #\d+:\s*", "", problem.split(" -- ")[0]).strip()
    windows = getattr(time_ctx, "windows", None) or {}

    def period(wid: str) -> str | None:
        w = windows.get(wid)
        lab = str(getattr(w, "label", "") or "") if w is not None else ""
        if not lab:
            return None
        return f"the {lab}" if re.match(r"(last|past|previous|first)\b", lab) else lab

    def with_preposition(m: re.Match) -> str:
        p = period(m.group(1))
        if p is None:
            return m.group(0)
        return p if p.startswith("since ") else f"for {p}"     # "in yesterday" -> "for yesterday"

    def bare(m: re.Match) -> str:
        return period(m.group(0)) or m.group(0)

    text = re.sub(r"\bin (w\d+)\b", with_preposition, text)
    text = re.sub(r"\bw\d+\b", bare, text)
    return re.sub(r"\b([a-z]+(?:_[a-z]+)+)\b", lambda m: m.group(1).replace("_", " "), text)


def _names_finding(answer: str, finding: dict[str, Any]) -> bool:
    ids = [str(finding.get("id") or "")] + [str(x) for x in finding.get("also_matched") or []]
    if any(i and re.search(rf"\b{re.escape(i)}\b", answer) for i in ids):
        return True
    title = str(finding.get("title") or "").strip().lower()
    return bool(title) and title in answer.lower()


# Guard 10: an /investigate-host answer calls Kratos's own machine "the target"
# (seen live despite the prompt saying not to) -- the user then can't tell which
# machine it's about. Asked once to reword; never rewritten silently.
_HOST_AS_TARGET_RE = re.compile(
    r"\bthe (?:monitored )?target(?: device| system| machine| host)?\b|\btarget device\b"
    r"|\bmonitored (?:device|system|machine|host|server)\b",
    re.IGNORECASE)

# Guard 9: state_as_of said Kratos has NO record of a past state (e.g. open ports
# yesterday); an answer must say so instead of inferring that state from other data.
# Live incident (2026-10-04): "was port 22 open yesterday?" -> state_as_of "no
# record" -> answer "confirmed open" because sudo sessions were logged.
_NO_RECORD_ACK_RE = re.compile(
    r"\bno (?:saved |stored |earlier |prior |such )?(?:record|snapshot|scan|data|history)s?\b"
    r"|\bnot (?:recorded|saved|captured)\b|\bhas no (?:record|snapshot)|\bhave no (?:record|snapshot)"
    r"|\b(?:do|does)(?:n't| not) have (?:a |any )?(?:saved |stored )?(?:record|snapshot|scan)"
    r"|\b(?:can(?:no|')t|could(?:n't| not)|unable to) (?:tell|say|confirm|determine|verify)\b"
    r"|\bunknown\b",
    re.IGNORECASE,
)

# Guard 8: the answer states Kratos lacks a capability. Deliberately narrow --
# the subject must be Kratos/the agent (or a check that "was not performed
# because" of a missing capability), and it must name a tool/capability, so an
# ordinary "no evidence of X" never matches.
_CAPABILITY_GAP_RE = re.compile(
    r"\b(?:kratos|i|we)\b[^.\n]{0,40}?\b(?:lacks?|do(?:es)?(?:n't| not) (?:currently )?(?:have|possess|include|provide|offer)|"
    r"has no|have no|is missing)\b[^.\n]{0,60}?\b(?:tool|capabilit(?:y|ies)|integration|feature)"
    r"|\bno (?:[\w-]+ ){0,3}tools? (?:is |are |was |were )?(?:currently )?(?:available|exists|in (?:my|the|kratos'?s?) (?:registry|suite|toolset))"
    r"|\bno (?:[\w-]+ ){0,3}tools?\b[^.\n]{0,60}?\b(?:is|are) (?:currently )?available"
    r"|\b(?:not (?:possible|supported|available)|unsupported) (?:with|by|in|using) (?:the )?(?:current|available|existing) (?:kratos )?tool"
    r"|\b(?:such a |this |that |the required )?capability (?:is |was )?(?:currently )?(?:unavailable|not available)"
    r"|\bnot part of (?:my|kratos'?s?|the) (?:current )?(?:toolkit|toolset|tools|registry)"
    r"|\b(?:could not|couldn't|cannot|can't|(?:am|was|is) unable to|unable to) (?:\w+ ){0,3}"
    r"(?:enumerate|list|scan|audit|check|map|determine|identify|perform|search|inspect)\b[^.\n]{0,80}?"
    r"\b(?:because|as|since|due to)\b[^.\n]{0,80}?"
    r"\b(?:tool|toolkit|capabilit|inability to (?:run|execute)|shell (?:access|execution)|not supported)"
    r"|\bkratos\b[^.\n]{0,20}?\b(?:does(?:n't| not)|cannot|can't) support\b"
    r"|\bno (?:existing|available|built-in|suitable|dedicated|current|registered) (?:kratos )?(?:tool|capability)"
    r"|\b(?:was|were|could) not (?:be )?(?:performed|audited|checked|done|determined|mapped|enumerated)\b"
    r"[^.\n]{0,40}?\b(?:because|as|since)\b[^.\n]{0,80}?\b(?:tool|not supported|capabilit|requires local)",
    re.IGNORECASE,
)


# A stated "Kratos can't ..." that is really a reported coverage limit of how the
# target is reached (no network path through a sub-agent), not a missing tool.
_KNOWN_COVERAGE_LIMIT_RE = re.compile(
    r"sub-?agent|network (?:scan|exposure|path)|open ports?|port scan|nmap|vulnerabilit", re.IGNORECASE)


def _gap_sentence(text: str, match: re.Match[str]) -> str:
    """The sentence of `text` containing `match`, trimmed."""
    start = max(text.rfind(". ", 0, match.start()), text.rfind("\n", 0, match.start())) + 1
    ends = [e for e in (text.find(". ", match.end()), text.find("\n", match.end())) if e != -1]
    end = min(ends) + 1 if ends else len(text)
    return text[start:end].strip()[:400]


_GAP_ACKNOWLEDGED_RE = re.compile(
    r"\b(not|n't|never|unable to|could ?not|couldn't|cannot|can't)\b[^.]{0,60}\b(check|checked|scan|scanned|"
    r"available|covered|examined|assessed|verified)", re.IGNORECASE)


def _unstated_coverage_gaps(gaps: list[str], answer: str) -> list[str]:
    """Gaps the answer doesn't acknowledge. Deliberately simple: an answer that
    says anything was not checked/scanned is taken as acknowledging them; the
    NOTE is the backstop for one that says nothing at all."""
    if not gaps or _GAP_ACKNOWLEDGED_RE.search(answer or ""):
        return []
    return gaps


# not inside a longer dotted number; a sentence-ending "." after the address is fine
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")


def _ungrounded_ips(answer: str, goal: str, transcript: list[dict[str, Any]]) -> list[str]:
    """IPv4 addresses in the answer that appear in no observation, digest or the goal."""
    named = {m for m in _IPV4_RE.findall(answer or "") if _finding_facts.is_ip(m)}
    if not named:
        return []
    seen = json.dumps([e.get("observation") for e in transcript] + [e.get("digest") for e in transcript]
                      + [goal], default=str)
    seen_ips = set(_IPV4_RE.findall(seen))       # whole addresses: 10.136.28.1 is not in 10.136.28.168
    return sorted(ip for ip in named if ip not in seen_ips)


_SSH_LOGIN_LIMIT = "over this SSH login"
_SSH_LOGIN_FIX = ("A normal SSH login can't read what belongs to other users or root; the machine's sub-agent "
                  "(it reads as root) covers it.")


def _coverage_note(gaps: list[str]) -> str:
    """The answer's "not checked" NOTE: one short line per gap, and the shared fix for
    what a normal SSH login cannot read said once, not after every line."""
    text = "; ".join(g.rstrip(" .") for g in gaps)
    fix = f" {_SSH_LOGIN_FIX}" if any(_SSH_LOGIN_LIMIT in g for g in gaps) else ""
    return f"[NOTE: not checked in this investigation: {text}. Nothing above covers it.{fix}]\n\n"
