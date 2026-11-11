"""COMP-001: "N hardening checks fail on this machine" (E.2 §3.7).

One finding per machine (subject = the machine; entities = the failed check ids, so a
newly failing check reopens a person's decision). Severity is posture: **low**, and
**medium** when a failed check is about reaching the machine from outside (SSH root or
password logins, no default-deny firewall) and the machine is exposed to the internet.

It never repeats another finding: a failed check that is already a finding (PERSIST-003,
PKG-001, an open CORR-SSH-001 or CONT-004, ...) is linked in the report instead of counted
here. Checks about Kratos's own features (in_finding=False) are report-only.
"""
from __future__ import annotations

from typing import Any

from kratos.compliance import checks as C
from kratos.compliance.status import CheckRun

MAX_EVIDENCE = 15
MAX_FIXES = 3


def judge(runs: list[CheckRun], *, target: str, internet: bool, exposure_why: str = "") -> list[dict[str, Any]]:
    failed = [r for r in runs if r.status == "fail" and not r.linked and C.BY_ID[r.id].in_finding]
    if not failed:
        return []
    remote = [r for r in failed if C.BY_ID[r.id].remote_access]
    severity = "medium" if remote and internet else "low"
    n = len(failed)
    evidence = [f"{C.BY_ID[r.id].text} -- found: {r.found}" for r in failed[:MAX_EVIDENCE]]
    if n > MAX_EVIDENCE:
        evidence.append(f"... and {n - MAX_EVIDENCE} more (see the compliance report)")
    if remote:
        evidence.append("About reaching the machine from outside: " + ", ".join(r.id for r in remote)
                        + (f" -- and the machine is exposed to the internet ({exposure_why})" if internet else ""))
    linked = sorted({r.linked for r in runs if r.status == "fail" and r.linked})
    if linked:
        evidence.append("Other failed checks are already findings of their own: " + ", ".join(linked))
    recs = [f"{C.BY_ID[r.id].text}: {C.BY_ID[r.id].fix}" for r in (remote + [x for x in failed if x not in remote])
            [:MAX_FIXES]]
    recs.append(f"Every failed check with its fix: `kratos compliance report --machine {target}` (or /compliance).")
    return [{"rule": "COMP-001", "severity": severity,
             "title": f"{n} hardening check{'s' if n != 1 else ''} fail on this machine",
             "subject": target, "entities": sorted(r.id for r in failed),
             "evidence": evidence, "recommendation": recs}]
