"""Plain-language, one-line descriptions of tools, for people.

A tool's registered ``description`` is written for the model: long, with
ALL-CAPS steering ("NON-NEGOTIABLE", "Do NOT use this to answer ...") that
reads as noise to a person browsing /tools, /use, /evolve list, Settings →
Tools or a /plan preview. Those screens show ``human_summary`` instead, plus
``where_it_runs``; the full model-facing text stays one key away (Settings →
Tools → view) for anyone who wants it.

Built-in tools have a hand-written line here. A kept (self-written) tool uses
the short description saved with it if there is one, else the first sentence
of its own description, shortened at a word boundary.
"""
from __future__ import annotations

import re
from typing import Any

TARGET = "the target"
KRATOS_HOST = "this Kratos machine"
SAVED = "saved results"     # works on what Kratos already collected
NOWHERE = "—"              # neither machine: an alert service, a reputation lookup

# name -> (where it runs, what it does)
_BUILT_IN: dict[str, tuple[str, str]] = {
    "run_nmap_scan": (TARGET, "Finds which network ports and services are open."),
    "run_vuln_scan": (TARGET, "Checks the open services for known vulnerabilities (CVE matches, web checks)."),
    "run_config_audit": (TARGET, "Checks security settings: SSH login rules, firewall, fail2ban."),
    "read_journalctl": (TARGET, "Reads the system logs, e.g. login attempts and sudo use."),
    "measure_auth_activity": (TARGET, "Counts every login and sudo event in a time window, exactly."),
    "compare_periods": (TARGET, "Compares login activity between periods, e.g. this week vs last."),
    "list_processes": (TARGET, "Lists the programs currently running."),
    "list_open_files": (TARGET, "Lists files and network connections that programs have open."),
    "list_privileged_accounts": (TARGET, "Shows who can become root or admin, and who was just given that access."),
    "check_file_integrity": (TARGET, "Checks whether key system files changed since a saved baseline."),
    "run_yara_scan": (TARGET, "Scans files for known malware and web-shell signatures."),
    "state_as_of": (SAVED, "Shows what the target looked like at a past time, from saved results."),
    "correlate_findings": (SAVED, "Turns everything collected so far into ranked findings."),
    "check_ip_reputation": (NOWHERE, "Checks whether an IP address is known to be malicious."),
    "send_notification": (NOWHERE, "Sends you an alert through ntfy."),
    "collect_system_context": (KRATOS_HOST, "Gathers basic facts about this Kratos machine (users, services, network)."),
    "parse_auth_log": (KRATOS_HOST, "Reads this Kratos machine's own login log."),
    "capture_traffic": (KRATOS_HOST, "Records this Kratos machine's network traffic for a short time (asks first)."),
    "run_linux_command": (KRATOS_HOST, "Runs one command on this Kratos machine (asks first)."),
}

_MAX = 96
_CAPS_RUN = re.compile(r"\b[A-Z][A-Z/'\-]{3,}(?:\s+[A-Z][A-Z/'\-]{1,})*\b")


_ABBREV = re.compile(r"\b(?:e\.g|i\.e|etc|vs|approx|incl)\.$", re.IGNORECASE)


def _first_sentence(text: str) -> str:
    text = " ".join((text or "").split())
    # The first sentence end that isn't an abbreviation ("e.g." used to end it).
    match = next((m for m in re.finditer(r"(?<=[.!?])\s", text) if not _ABBREV.search(text[: m.start()])), None)
    sentence = text[: match.start()] if match else text
    if len(sentence) > _MAX:
        sentence = sentence[:_MAX].rsplit(" ", 1)[0].rstrip(",;:-") + "…"
    return sentence


def _calm(text: str) -> str:
    """Model steering in capitals reads as shouting: lower-case a run of capital
    words, keeping acronyms of up to four letters (SSH, YARA, CVE)."""
    def fix(m: re.Match[str]) -> str:
        return " ".join(w if len(w.strip("/'-")) <= 4 else w.lower() for w in m.group(0).split())
    calm = _CAPS_RUN.sub(fix, text)
    return calm[:1].upper() + calm[1:]


def human_summary(name: str, tool: Any = None, metadata: dict[str, Any] | None = None) -> str:
    """One plain sentence about what `name` does."""
    if name in _BUILT_IN:
        return _BUILT_IN[name][1]
    saved = str((metadata or {}).get("description") or "").strip()
    if saved:
        return _first_sentence(saved)
    description = getattr(tool, "description", "") if tool is not None else ""
    return _calm(_first_sentence(description)) or name.replace("_", " ").capitalize()


def where_it_runs(name: str, tool: Any = None) -> str:
    """Where the tool looks: the target, this Kratos machine, saved results, or "—"."""
    if name in _BUILT_IN:
        return _BUILT_IN[name][0]
    text = (getattr(tool, "description", "") or "").lower() if tool is not None else ""
    source = ""
    try:
        import inspect

        source = inspect.getsource(tool.handler) if tool is not None else ""
    except (OSError, TypeError):
        pass
    if "ssh_remote" in source or "target" in text:
        return TARGET
    return SAVED  # kept tools that don't reach the target work on collected data


_SHORT_WHERE = {TARGET: "target", KRATOS_HOST: "Kratos host", SAVED: "saved data", NOWHERE: ""}


def short_where(name: str, tool: Any = None) -> str:
    """A compact where-it-looks tag for narrow lists (the /use picker)."""
    return _SHORT_WHERE.get(where_it_runs(name, tool), "")
