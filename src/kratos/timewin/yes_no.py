"""Does a yes/no answer to a "more/fewer ... than ..." question match Kratos's own
comparison verdict?

Seen live (demo pass 4): "were there more failed logins this week than last week?"
was answered "Yes, there were fewer ... (136 vs 257)" -- right numbers, wrong yes/no.
The verdict comes from timewin.compare (computed in code); this only reads which
window the question is about and which direction it asks, and says what the opening
word must be. Anything it can't read with certainty returns None (no opinion).
"""
from __future__ import annotations

import re
from typing import Any

_UP = ("more", "higher", "greater", "bigger", "larger", "busier")
_DOWN = ("fewer", "less", "lower", "smaller", "quieter")
_ASK_RE = re.compile(r"\b(" + "|".join(_UP + _DOWN) + r")\b(?P<mid>[^.?!]*?)\bthan\b", re.IGNORECASE)
_OPENING_RE = re.compile(r"^\s*(?:\[NOTE:[^\]]*\]\s*)*(?P<word>yes|no)\b", re.IGNORECASE)
_FLIP = {"increase": "decrease", "decrease": "increase"}
_SAID = {"increase": "went up", "decrease": "went down", "no_meaningful_change": "did not meaningfully change"}


def _window_at(goal: str, windows: dict[str, Any], lo: int, hi: int) -> str | None:
    """The one window whose goal phrase sits inside goal[lo:hi]; None if not exactly one."""
    low = goal.lower()
    hits = []
    for wid, w in windows.items():
        phrase = (getattr(w, "phrase", None) or "").strip().lower()
        if phrase:
            at = low.find(phrase, lo, hi)
            if at >= 0:
                hits.append(wid)
    return hits[0] if len(hits) == 1 else None


def yes_no_problem(goal: str, answer: str, pairs: list[dict[str, Any]],
                   windows: dict[str, Any]) -> dict[str, str] | None:
    """{"expected", "got", "why"} when the answer's opening Yes/No contradicts the
    comparison verdict for the windows the question names; otherwise None."""
    ask = _ASK_RE.search(goal or "")
    said = _OPENING_RE.match(answer or "")
    if not ask or not said:
        return None
    asked_up = ask.group(1).lower() in _UP
    subject = _window_at(goal, windows, 0, ask.end())
    reference = _window_at(goal, windows, ask.end(), len(goal))
    if not subject or not reference or subject == reference:
        return None
    pair = next((p for p in pairs if {p.get("from"), p.get("to")} == {subject, reference}), None)
    verdict = (pair or {}).get("verdict")
    if verdict not in _SAID:
        return None
    direction = verdict if pair["to"] == subject else _FLIP.get(verdict, verdict)
    expected = "Yes" if direction == ("increase" if asked_up else "decrease") else "No"
    got = said.group("word").capitalize()
    if got == expected:
        return None
    sub = getattr(windows[subject], "label", subject)
    ref = getattr(windows[reference], "label", reference)
    return {"expected": expected, "got": got,
            "why": f"compared with {ref}, {sub} {_SAID[direction]} (Kratos's comparison verdict)"}
