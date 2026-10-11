"""What `read_host_logs` tells the model about one source read: a summary, never a dump.

Counts by action and outcome, the top source IPs, users and a per-source detail
(programs, commands, units, ports, packages, paths), up to NOTABLE_MAX notable
lines (already masked by the event converter), and what the read covered --
files read, files that exist but couldn't be read (with the setup fix),
rotations not read, journal problems and whether the whole window was seen.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

from kratos.logsources import catalog
from kratos.utils.timeutil import epoch_to_utc_iso

NOTABLE_MAX = 12
TOP_N = 5
# Kratos's own reads, run through sudo by the SSH user (the same list
# timewin.measure leaves out of its counts), plus the 0.3 auditd status reads.
_OWN_COMMAND = re.compile(r"^/usr/s?bin/(journalctl|sshd|fail2ban-client|ufw|lsof|ps|date|nft|iptables|cat|ss|find|"
                          r"stat|gzip|auditctl|true)\b")

# The detail worth a top-N list, per source (Event attribute, label).
_DETAIL: dict[str, tuple[tuple[str, str], ...]] = {
    "auditd": (("process_executable", "programs_run"), ("process_command_line", "commands")),
    "sudo": (("process_command_line", "commands"), ("user_effective_name", "run_as")),
    "cron": (("process_command_line", "commands"),),
    "systemd": (("service_name", "units"),),
    "firewall": (("destination_port", "destination_ports"), ("network_transport", "protocols")),
    "packages": (("package_name", "packages"),),
    "web": (("url_original", "paths"), ("http_response_status_code", "status_codes"),
            ("user_agent_original", "user_agents")),
}
# What makes an event worth showing as a line: a failure, a block, a change.
_NOTABLE_ACTIONS = {
    "auditd": {"user_login", "user_auth", "user_added", "user_deleted", "user_changed", "group_added",
               "group_deleted", "group_changed", "password_changed", "audit_disabled", "audit_rule_removed",
               "audit_config_change", "auditd_stopped", "auditd_aborted", "sudo_command"},
    "systemd": {"unit_failed"},
    "firewall": {"blocked"},
    "packages": {"package_installed", "package_removed", "package_upgraded", "package_downgraded",
                 "package_transaction", "package_command"},
    "web": {"web_error"},
    "cron": {"cron_command"},
    "sudo": {"sudo_command", "sudo_auth_failure", "sudo_pam_auth_failure"},
}


def _top(values: list[Any]) -> list[dict[str, Any]]:
    counts = Counter(v for v in values if v not in (None, ""))
    return [{"value": v, "count": n} for v, n in sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))[:TOP_N]]


def _line(e: Any) -> str:
    when = epoch_to_utc_iso(e.ts)
    text = e.message or e.original or e.action or ""
    if e.process_command_line and e.process_command_line not in text:
        text = f"{text} -- {e.process_command_line}"
    return f"{when} {e.action}: {' '.join(str(text).split())[:300]}"


def coverage(read: Any, source: str) -> dict[str, Any]:
    src = catalog.SOURCES[source]
    files_read = [f.path for f in read.files if f.status == "read"]
    unreadable = [{"path": f.path, "why": f.status if f.status != "unreadable" or f.detail != "directory"
                   else "its directory isn't readable", "fix": src.access or "-"}
                  for f in read.files if f.status in ("unreadable", "no_content")]
    refused = [{"path": f.path, "why": f"{f.status} (refused: Kratos never follows links in log directories)"}
               for f in read.files if f.status in ("symlink", "hardlink", "not_regular", "changed", "refused")]
    missing = [f.path for f in read.files if f.status == "missing" and f.slot == 0]
    oldest = min((f.first for f in read.files if f.status == "read" and f.first is not None), default=None)
    gaps = list(read.gaps)
    problems: list[str] = []
    if read.journal_errors:
        problems += [f"journal ({m}): {e}" for m, e in read.journal_errors.items()]
    if unreadable:
        problems.append("could not read " + ", ".join(u["path"] for u in unreadable) + f" -- fix: {src.access}")
    if refused:
        problems.append("refused " + ", ".join(r["path"] for r in refused) + " (a link in a log directory)")
    reaches_back = True
    # The files read start after the window does AND older rotations exist that
    # weren't read (compressed or older): that part of the window is unknown. With
    # no older rotation, the log simply begins there.
    if (read.since is not None and files_read and not read.journal_counts and oldest is not None
            and oldest > read.since and read.skipped):
        reaches_back = False
        problems.append(f"the files read only go back to {epoch_to_utc_iso(oldest)}; older rotations were not "
                        f"read ({', '.join(read.skipped[:4])}) -- that earlier part of the window is unknown")
    if read.truncated:
        problems.append("the window held more lines than the cap: only the newest were read")
    present = [f for f in read.files if f.status not in ("missing", "skipped_journal")]
    nothing = not present and not read.journal_counts and not read.journal_errors
    complete = not problems and not gaps and not nothing
    if nothing and not gaps:
        gaps.append("no log for this source exists on the machine (" + (", ".join(missing) or "no paths") + ")")
    return {
        "complete": complete,
        "files_read": files_read,
        "files_not_readable": unreadable,
        "files_refused": refused,
        "files_missing": missing,
        "rotations_not_read": list(read.skipped),
        "journal": {m: n for m, n in read.journal_counts.items()},
        "journal_errors": dict(read.journal_errors),
        "oldest_line_seen": epoch_to_utc_iso(oldest) if oldest is not None else None,
        "window_fully_covered": reaches_back and not read.truncated,
        "gaps": gaps,
        "problems": problems,
        "distribution": read.family,
    }


def _kratos_own(e: Any, own_user: str | None) -> bool:
    return (bool(own_user) and e.action == "sudo_command" and e.user_name == own_user
            and bool(_OWN_COMMAND.match(e.process_command_line or "")))


def summarize(read: Any, events: list[Any], own_user: str | None = None) -> dict[str, Any]:
    """`own_user`: the SSH user Kratos reads as -- its own sudo reads are counted
    apart (kratos_own_reads), not shown as notable activity."""
    source = read.source
    own = [e for e in events if _kratos_own(e, own_user)]
    if own:
        events = [e for e in events if not _kratos_own(e, own_user)]
    out: dict[str, Any] = {
        "source": source,
        "what_it_tells_you": catalog.SOURCES[source].doc,
        "events": len(events),
        "by_action": dict(Counter(e.action for e in events).most_common(15)),
        "by_outcome": dict(Counter(e.outcome or "unknown" for e in events)),
        "top_source_ips": _top([e.source_ip for e in events]),
        "top_users": _top([e.user_name for e in events]),
    }
    for attr, label in _DETAIL.get(source, ()):
        out[f"top_{label}"] = _top([getattr(e, attr) for e in events])
    notable_actions = _NOTABLE_ACTIONS.get(source, set())
    notable = [e for e in events if e.action in notable_actions or e.outcome == "failure"]
    out["notable_lines"] = [_line(e) for e in notable[:NOTABLE_MAX]]
    out["notable_total"] = len(notable)
    if events:
        out["newest"] = epoch_to_utc_iso(max(e.ts for e in events))
        out["oldest"] = epoch_to_utc_iso(min(e.ts for e in events))
    if own:
        out["kratos_own_reads"] = {"count": len(own), "note": f"sudo commands Kratos itself ran as {own_user} to "
                                                               "read this machine -- left out of the counts above"}
    cov = coverage(read, source)
    out["coverage"] = cov
    gap_parts = cov["gaps"] + cov["problems"]
    if gap_parts:
        out["coverage_gap"] = f"{source} logs were not fully read: " + "; ".join(gap_parts)
    return out
