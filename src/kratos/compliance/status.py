"""Check results and control statuses, by code (E.2 §3.6, §3.9).

A check result is pass / fail / unknown / na from its predicate, then made honest about
time: a result whose facts are older than `compliance.max_age_hours` (24) is never a
pass or a fail -- it is "not checked: last read N h ago". A pass also needs the read it
came from to be complete.

A control's status:

- ``fail``           any mapped check fails;
- ``pass``           every mapped check passes on fresh, complete facts -- and, for CIS,
                     Kratos checks every ComplianceAsCode rule of the section; a control
                     that also needs a person (organisational part) is never ``pass``:
                     it is ``needs_person`` with the technical checks shown;
- ``partial``        some mapped checks pass, others couldn't be read, don't apply, or
                     (CIS) aren't checked by Kratos;
- ``not_checked``    Kratos has no usable result (stale, unreachable, no check for it);
- ``needs_person``   no Kratos check for it -- policy, people, premises;
- ``not_applicable`` only from a person's decision (kratos.compliance.owners), with a
                     reason and an expiry.

Group roll-ups count machines per status and never call a group passing while one
machine is not checked.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

from kratos.compliance import cac, checks as C
from kratos.compliance import frameworks as F
from kratos.compliance.facts import Facts, Source, age_hours

STATUSES = ("pass", "fail", "partial", "not_checked", "needs_person", "not_applicable")
STATUS_WORDS = {"pass": "pass", "fail": "fail", "partial": "partial", "not_checked": "not checked",
                "needs_person": "needs a person", "not_applicable": "not applicable"}


@dataclass
class CheckRun:
    id: str
    status: str                       # pass | fail | unknown | na
    found: str
    reason: str = ""
    note: str = ""
    stale: bool = False
    sources: list[dict[str, Any]] = field(default_factory=list)   # [{name, read_at, via}]
    linked: str = ""                  # the finding a failure already is ("PERSIST-003")
    other_read: dict[str, Any] | None = None   # the other transport's result when it differs

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in ("", None, [], False) or k in ("id", "status", "found")}


def _src_info(src: Source | None) -> dict[str, Any] | None:
    if src is None:
        return None
    return {"name": src.name, "read_at": src.read_at, "via": src.via, "complete": bool(src.complete)}


def run_checks(facts: Facts, *, max_age_hours: float, now: float | None = None,
               open_rules: set[str] | None = None) -> list[CheckRun]:
    """Every applicable check, evaluated and made honest about time. `open_rules`: rule
    ids of findings open now for this machine (a failure already a finding is linked)."""
    now = time.time() if now is None else now
    fam = facts.family()
    open_rules = open_rules or set()
    out: list[CheckRun] = []
    for chk in C.CHECKS:
        if facts.get("hardening") is not None and fam not in chk.os_families:
            continue
        res = C.evaluate(chk, facts)
        primary = facts.get(chk.facts[0])
        srcs = [i for i in (_src_info(facts.get(n)) for n in chk.facts) if i]
        run = CheckRun(chk.id, res.status, res.found, res.reason, res.note, sources=srcs)
        age = age_hours(primary, now)
        if primary is not None and res.status in ("pass", "fail", "na") and (age is None or age > max_age_hours):
            run.status, run.stale = "unknown", True
            run.reason = (f"last read {age:.0f} h ago (older than {max_age_hours:g} h)" if age is not None
                          else "the read has no time")
        elif res.status == "pass" and primary is not None and not primary.complete and not chk.trust_incomplete:
            run.status = "unknown"
            run.reason = f"the {primary.label()} was incomplete, so a pass can't be confirmed"
        if run.status == "fail":
            linked = [r for r in chk.linked_rules if r in open_rules]
            if chk.id.startswith(("persistence.", "packages.")) and chk.linked_rules:
                linked = list(chk.linked_rules)      # these checks fail only because the finding was raised
            if linked:
                run.linked = linked[0]
        # The other transport's read (README §5.3 / spec §6: SSH and agent disagree)
        if facts.other_hardening is not None and chk.facts[0] == "hardening":
            alt = Facts(facts.target, dict(facts.sources, hardening=facts.other_hardening))
            alt_res = C.evaluate(chk, alt)
            if alt_res.status != res.status:
                run.other_read = {"via": facts.other_hardening.via, "read_at": facts.other_hardening.read_at,
                                  "status": alt_res.status, "found": alt_res.found or alt_res.reason}
        out.append(run)
    return out


@dataclass
class ControlStatus:
    framework: str
    control: str
    text: str
    status: str
    reason: str = ""
    checks: list[str] = field(default_factory=list)          # check ids that gave evidence
    uncovered_rules: list[str] = field(default_factory=list)  # CIS: rules Kratos doesn't check
    rules: list[str] = field(default_factory=list)            # CIS: the section's rules
    person: str = ""
    na: dict[str, Any] | None = None                          # an active person's N/A decision
    computed: str = ""                                        # the status before an N/A decision

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in ("", None, [])
                or k in ("framework", "control", "status", "text")}


def _combine(runs: list[CheckRun], *, extra_missing: list[str], person: str) -> tuple[str, str]:
    if not runs and not extra_missing:
        return ("needs_person", person) if person else ("not_checked", "Kratos has no check for this")
    st = [r.status for r in runs]
    if "fail" in st:
        bad = [r.id for r in runs if r.status == "fail"]
        return "fail", f"failed: {', '.join(bad[:6])}"
    passed = st.count("pass")
    if runs and passed == len(runs) and not extra_missing:
        if person:
            return "needs_person", f"Kratos's checks for the technical part pass; a person supplies {person}"
        return "pass", ""
    reasons = []
    for r in runs:
        if r.status == "unknown":
            reasons.append(f"{r.id}: {r.reason}")
        elif r.status == "na":
            reasons.append(f"{r.id}: doesn't apply here ({r.reason})")
    if extra_missing:
        reasons.append("not checked by Kratos: ComplianceAsCode rule(s) " + ", ".join(extra_missing[:8]))
    if passed:
        return "partial", "; ".join(reasons[:6])
    if runs and all(r.status == "na" for r in runs) and not extra_missing:
        return "not_checked", "Kratos's checks don't apply on this machine: " + "; ".join(reasons[:4])
    return "not_checked", "; ".join(reasons[:6]) or "Kratos has no usable result"


def controls_for(framework: str, runs: list[CheckRun], *, product: cac.Product | None = None,
                 level: str = cac.DEFAULT_LEVEL) -> list[ControlStatus]:
    by_id = {r.id: r for r in runs}
    out: list[ControlStatus] = []
    if framework == "cis":
        if product is None or product.id is None:
            return []
        rule_checks: dict[str, list[str]] = {}
        for chk in C.CHECKS:
            if chk.id in by_id:
                for rule in chk.cac_rules:
                    rule_checks.setdefault(rule, []).append(chk.id)
        for c in cac.controls(product.id, level):
            rules = list(c.get("rules") or [])
            ids = sorted({cid for r in rules for cid in rule_checks.get(r, [])})
            missing = [r for r in rules if r not in rule_checks]
            if not rules and c.get("status") in ("manual", "partial", "pending", "planned", "supported", "unknown"):
                status, reason = "needs_person", "CIS marks this as a manual check: a person reviews it"
            elif not ids:
                status, reason = "not_checked", ("not checked by Kratos" + (
                    f": ComplianceAsCode rule(s) {', '.join(rules[:8])}" if rules else ""))
            else:
                status, reason = _combine([by_id[i] for i in ids], extra_missing=missing, person="")
            out.append(ControlStatus("cis", c["id"], _cis_text(ids, rules), status, reason, ids, missing, rules))
        return out
    for ctl in (F.ISO_CONTROLS if framework == "iso27001" else F.NIS2_CONTROLS):
        ids = [chk.id for chk in C.CHECKS if chk.id in by_id and ctl.id in (chk.iso if framework == "iso27001"
                                                                              else chk.nis2)]
        status, reason = _combine([by_id[i] for i in ids], extra_missing=[], person=ctl.person)
        out.append(ControlStatus(framework, ctl.id, ctl.text, status, reason, ids, person=ctl.person))
    return out


def _cis_text(ids: list[str], rules: list[str]) -> str:
    """Kratos's own description of a CIS section: what its checks test (never CIS's title)."""
    if ids:
        texts = []
        for i in ids:
            t = C.BY_ID[i].text
            if t not in texts:
                texts.append(t)
        return "; ".join(texts[:3]) + (f" (+{len(texts) - 3} more)" if len(texts) > 3 else "")
    if rules:
        return "ComplianceAsCode rule(s): " + ", ".join(rules[:4]) + ("…" if len(rules) > 4 else "")
    return "a manual review item"


def apply_na(rows: list[ControlStatus], decisions: dict[tuple[str, str], dict[str, Any]]) -> None:
    for r in rows:
        d = decisions.get((r.framework, r.control))
        if d:
            r.computed, r.status, r.na = r.status, "not_applicable", d
            r.reason = f"marked not applicable by {d.get('actor')}: {d.get('reason')} (until {d.get('expires_at')})"


def counts(rows: list[ControlStatus]) -> dict[str, int]:
    out = {s: 0 for s in STATUSES}
    for r in rows:
        out[r.status] = out.get(r.status, 0) + 1
    return out


def summary_line(framework: str, rows: list[ControlStatus], product: cac.Product | None = None,
                 level: str = cac.DEFAULT_LEVEL) -> str:
    c = counts(rows)
    head = F.FRAMEWORK_NAMES[framework].split(" (")[0]
    if framework == "cis":
        if product is None or product.id is None:
            return f"CIS: {product.note if product else 'no CIS mapping for this system'}"
        head = f"CIS {cac.LEVEL_WORDS.get(level, level)} ({product.id})"
    nc = c["not_checked"]
    return (f"{head}: {c['pass']} pass · {c['fail']} fail · {c['partial']} partial · {nc} not checked"
            f"{' by Kratos' if framework == 'cis' else ''} · {c['needs_person']} need a person · "
            f"{c['not_applicable']} N/A")


def group_status(statuses: list[str]) -> str:
    """One word for a control across machines: never 'pass' while any machine isn't passing."""
    if not statuses:
        return "not_checked"
    if "fail" in statuses:
        return "fail"
    if all(s == "pass" for s in statuses):
        return "pass"
    if all(s == "not_applicable" for s in statuses):
        return "not_applicable"
    if "not_checked" in statuses:
        return "not_checked" if not any(s in ("pass", "partial") for s in statuses) else "partial"
    if all(s == "needs_person" for s in statuses):
        return "needs_person"
    return "partial"
