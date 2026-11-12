"""Which deviations become findings, and how serious they are (E.3 §3.5, §3.6, §3.10).

Severity by rule, then the cap: a deviation from what's normal is never above medium on its
own (owner decision, 2026-11-12). Then the noise budget: at most `baseline.max_per_day`
findings per machine per rolling day, most severe and rarest first; the same key at most
once per `baseline.cooldown_hours`. What doesn't fit is counted in BASE-007, never dropped
silently. Nothing here reads or changes any other rule's finding.
"""
from __future__ import annotations

from typing import Any, Iterable

from kratos.baseline.learn import Deviation

SEVERITY_CAP = "medium"
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
KIND_RANK = {"new": 0, "rare": 1, "unusual_time": 2}
INTERACTIVE_METHODS = ("password", "keyboard-interactive")
ROOT_NAMES = ("root",)


def cap(severity: str) -> str:
    return severity if RANK.get(severity, 0) <= RANK[SEVERITY_CAP] else SEVERITY_CAP


def severity(dev: Deviation, *, privileged: set[str], sudo_users: set[str]) -> str:
    """Before the cap. `privileged`: accounts the privileged-accounts read lists (plus root);
    `sudo_users`: users this machine's baseline has seen use sudo before this deviation."""
    sev = "low"
    if dev.rule == "BASE-001":
        public = dev.detail.get("class") == "public"
        if public and (dev.subject in privileged or dev.subject in ROOT_NAMES):
            sev = "medium"
        if dev.detail.get("usual_elsewhere"):
            sev = "low"          # first time HERE, usual for this account on another machine in the group
    elif dev.rule == "BASE-003":
        sev = "medium" if dev.key in INTERACTIVE_METHODS else "low"
    elif dev.rule == "BASE-004":
        run_as = str(dev.detail.get("run_as") or "")
        if run_as in ROOT_NAMES and dev.subject not in sudo_users:
            sev = "medium"
    return cap(sev)


def rank_key(d: dict[str, Any]) -> tuple:
    return (-RANK.get(str(d.get("severity")), 0), KIND_RANK.get(str(d.get("kind")), 9),
            int(d.get("seen_before") or 0), -float(d.get("ts") or 0))


def select(candidates: Iterable[dict[str, Any]], *, room: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(raised, over budget) -- most severe and rarest first."""
    ordered = sorted(candidates, key=rank_key)
    room = max(0, room)
    return ordered[:room], ordered[room:]
