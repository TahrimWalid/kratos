"""Compliance reports (E.2 §5.2, §3.9, §3.11): one framework, one machine or a group,
as JSON, Markdown or CSV.

A report is re-evaluated from the SAVED facts at the moment it is made (no read, no
model): a pass needs facts read within `compliance.max_age_hours` NOW, not when the
check ran, and a person's owners and N/A decisions are the current ones.

Scope: the caller resolves the machines it may see (`resolve_machines`); a group's
members outside the caller's access are counted, never named. Every text that came from
a machine is cleaned for the format it goes into (A.4): Markdown escaping, CSV cells
that a spreadsheet would run as a formula are quoted.
"""
from __future__ import annotations

import csv
import io
import json
import time
from pathlib import Path
from typing import Any

from kratos.compliance import cac
from kratos.compliance import checks as C
from kratos.compliance import facts as FX
from kratos.compliance import frameworks as F
from kratos.compliance import status as ST
from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso

FORMATS = ("md", "csv", "json")


class ReportError(ValueError):
    """A request Kratos can't answer: unknown framework, a machine outside the caller's access."""


def resolve_machines(data_dir: Path | str, actor: Any, *, machine: str | None = None,
                     group: str | None = None) -> tuple[list[str], int, str]:
    """(machines, members outside the caller's access, label). Needs compliance.read; a
    machine outside the caller's scope is refused, never widened."""
    from kratos import authz

    p = authz.require(actor, authz.P.COMPLIANCE_READ, data_dir=data_dir, obj="compliance report")
    scope = None if p.scope.every else list(p.scope.names)
    if machine and group:
        raise ReportError("give a machine or a group, not both")
    if group:
        from kratos.fleet import groups as G

        try:
            res = G.resolve(data_dir, group.lstrip("@"), scope=scope)
        except G.GroupError as e:
            if "outside" in str(e) or "empty" in str(e).lower():
                return [], 0, f"@{group.lstrip('@')}"
            raise ReportError(str(e)) from None
        return list(res.machines), int(res.outside_scope), res.label
    if not machine:
        from kratos.kratos_config import get_active_target

        machine = get_active_target()
    if not machine:
        raise ReportError("which machine? (--machine or --group)")
    if not p.scope.allows(machine):
        authz.record_refusal(actor, authz.P.COMPLIANCE_READ, "machine outside the caller's access", machine=machine,
                             data_dir=data_dir)
        raise ReportError(f"no machine {machine!r} that you may see")
    return [target_key(machine)], 0, target_key(machine)


def _owner_label(owners: dict[str, Any], control: str) -> tuple[str, str]:
    o = owners.get(control)
    return (o.label(), o.due or "") if o else ("", "")


def machine_section(data_dir: Path, framework: str, machine: str, *, now: float) -> dict[str, Any]:
    from kratos.compliance import owners as O
    from kratos.compliance import record

    facts = FX.load(data_dir, machine)
    hard = facts.get("hardening")
    base: dict[str, Any] = {"machine": target_key(machine), "os": (facts.h().get("os") or {}).get("PRETTY_NAME", "")}
    if hard is None:
        return {**base, "status": "not_checked", "reason": "Kratos has no hardening read of this machine yet "
                "(run `kratos collect " + target_key(machine) + "`)", "controls": [], "summary": "not checked"}
    ev = record.evaluate(data_dir, machine, facts, now=now)
    runs = {r.id: r for r in ev["runs"]}
    owners = O.owners_for(data_dir, framework, machine)
    product: cac.Product = ev["product"]
    controls = []
    for row in ev["frameworks"][framework]:
        owner, due = _owner_label(owners, row["control"])
        checks = []
        for cid in row.get("checks") or []:
            r, chk = runs[cid], C.BY_ID[cid]
            src = (r.sources or [{}])[0]
            checks.append({"id": cid, "text": chk.text, "status": r.status, "found": r.found, "reason": r.reason,
                           "note": r.note, "read_at": epoch_to_utc_iso(src["read_at"]) if src.get("read_at") else None,
                           "via": src.get("via") or "", "fix": chk.fix if r.status == "fail" else "",
                           "linked_finding": r.linked, "other_read": r.other_read})
        controls.append({**row, "owner": owner, "due": due, "check_results": checks})
    return {**base, "status": "read", "product": product.id, "product_note": product.note,
            "benchmark_version": product.benchmark_version, "level": ev["level"],
            "read_at": epoch_to_utc_iso(hard.read_at) if hard.read_at else None, "via": hard.via,
            "other_read": ({"via": facts.other_hardening.via, "read_at": epoch_to_utc_iso(facts.other_hardening.read_at)}
                           if facts.other_hardening and facts.other_hardening.read_at else None),
            "summary": ev["summaries"][framework], "controls": controls,
            "counts": ST.counts([_R(c["status"]) for c in controls])}


class _R:
    def __init__(self, status: str):
        self.status = status


def build(data_dir: Path | str, framework: str, machines: list[str], *, outside_scope: int = 0,
          label: str = "", now: float | None = None) -> dict[str, Any]:
    fw = str(framework or "").lower()
    if fw not in F.FRAMEWORKS:
        raise ReportError(f"framework is one of: {', '.join(F.FRAMEWORKS)}")
    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    sections = [machine_section(data_dir, fw, m, now=now) for m in machines]
    src = cac.source()
    doc: dict[str, Any] = {
        "framework": fw, "framework_name": F.FRAMEWORK_NAMES[fw], "generated_at": epoch_to_utc_iso(now),
        "scope": label or ", ".join(machines), "disclaimer": F.NOT_A_CERTIFICATION,
        "mapping": {"compliance_as_code_commit": src.get("commit"), "commit_date": src.get("commit_date"),
                    "licence": "BSD-3-Clause (ids only; no CIS text is shipped)"} if fw == "cis" else
                   {"kratos_mapping": "Kratos's own advisory mapping of its checks to these ids"},
        "machines": sections, "outside_scope": int(outside_scope),
    }
    if fw == "nis2":
        doc["nis2_note"] = F.NIS2_SCOPE_NOTE
    if len(sections) > 1:
        doc["rollup"] = rollup(sections)
    return doc


def rollup(sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per control (CIS: per product + section), counts of machines in each status; a machine
    with no read counts as not checked for every control, so a group never 'passes' past it."""
    keys: dict[tuple[str, str], dict[str, Any]] = {}
    unread = [s for s in sections if s.get("status") != "read"]
    for s in sections:
        for c in s.get("controls") or []:
            k = (str(s.get("product") or ""), c["control"]) if c["framework"] == "cis" else ("", c["control"])
            e = keys.setdefault(k, {"product": k[0] or None, "control": c["control"], "text": c.get("text", ""),
                                    "statuses": [], "has_checks": False})
            e["statuses"].append(c["status"])
            e["has_checks"] = e["has_checks"] or bool(c.get("checks"))
    out = []
    for e in keys.values():
        # A control no Kratos check reads needs a person on an unread machine too; one Kratos
        # checks is simply not checked there -- never a pass for the group.
        filler = "needs_person" if not e.pop("has_checks") and all(s == "needs_person" for s in e["statuses"]) \
            else "not_checked"
        sts = e.pop("statuses") + [filler] * len(unread)
        e["counts"] = {st: sts.count(st) for st in ST.STATUSES if sts.count(st)}
        e["status"] = ST.group_status(sts)
        out.append(e)
    return out


# --------------------------------------------------------------------------- rendering
def _csv_cell(v: Any) -> str:
    from kratos.untrusted import for_display

    s = for_display("" if v is None else str(v))
    if s and s[0] in "=+-@\t\r":
        s = "'" + s
    return s


def to_csv(doc: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["machine", "framework", "control", "status", "description", "reason", "checks", "evidence",
                "read_at", "via", "owner", "due", "fix"])
    for s in doc["machines"]:
        if s.get("status") != "read":
            w.writerow([_csv_cell(x) for x in (s["machine"], doc["framework"], "", "not_checked", "", s.get("reason"),
                                               "", "", "", "", "", "", "")])
            continue
        for c in s["controls"]:
            ev = "; ".join(f"{r['id']}: {r['status']}: {r['found'] or r['reason']}" for r in c["check_results"])
            fixes = "; ".join(r["fix"] for r in c["check_results"] if r.get("fix"))
            reads = sorted({r["read_at"] for r in c["check_results"] if r.get("read_at")})
            w.writerow([_csv_cell(x) for x in (s["machine"], doc["framework"], c["control"], c["status"],
                                               c.get("text"), c.get("reason"), ",".join(c.get("checks") or []), ev,
                                               reads[-1] if reads else "", s.get("via"), c.get("owner"), c.get("due"),
                                               fixes)])
    return buf.getvalue()


def to_json(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=1, ensure_ascii=True, default=str) + "\n"


_MD_SPECIAL = str.maketrans({c: "\\" + c for c in "\\`*_[]<>|#!~"})


def md(value: Any) -> str:
    """Plain text for a Markdown line or table cell: cleaned (A.4), one line, every
    character Markdown would act on escaped -- no link, image, HTML or table break."""
    from kratos.untrusted import for_display

    return for_display("" if value is None else str(value)).replace("\r", " ").replace("\n", " ").translate(
        _MD_SPECIAL)


def to_markdown(doc: dict[str, Any], *, include_not_checked: bool = False) -> str:
    from kratos.untrusted import md_code

    out = [f"# Compliance report: {md(doc['framework_name'])}", "",
           f"Scope: {md(doc['scope'])} · generated {md(doc['generated_at'])}", "",
           f"> {md(doc['disclaimer'])}", ""]
    if doc.get("nis2_note"):
        out += [f"> {md(doc['nis2_note'])}", ""]
    m = doc.get("mapping") or {}
    if m.get("compliance_as_code_commit"):
        out += [f"CIS sections and rule ids from ComplianceAsCode commit {md_code(str(m['compliance_as_code_commit'])[:12])} "
                f"({md(str(m.get('commit_date') or '')[:10])}, BSD-3-Clause). The descriptions are Kratos's own: "
                "no CIS text is shipped.", ""]
    if doc.get("outside_scope"):
        out += [f"{doc['outside_scope']} machine(s) in this group are outside your access and are not shown.", ""]
    if doc.get("rollup"):
        out += ["## Across machines", "", "| Control | Status | Machines |", "|---|---|---|"]
        for r in doc["rollup"]:
            cnt = ", ".join(f"{ST.STATUS_WORDS[k]} {v}" for k, v in r["counts"].items())
            ctl = (f"{r['product']} {r['control']}" if r.get("product") else r["control"])
            out.append(f"| {md(ctl)} | {ST.STATUS_WORDS[r['status']]} | {md(cnt)} |")
        out.append("")
    for s in doc["machines"]:
        out += [f"## {md(s['machine'])}" + (f" — {md(s['os'])}" if s.get("os") else ""), ""]
        if s.get("status") != "read":
            out += [f"**Not checked:** {md(s.get('reason'))}", ""]
            continue
        bits = [f"read {md(s.get('read_at'))} via {md(s.get('via'))}"]
        if s.get("other_read"):
            bits.append(f"also read via {md(s['other_read']['via'])} at {md(s['other_read']['read_at'])}")
        if doc["framework"] == "cis":
            if s.get("product"):
                bits.append(f"ComplianceAsCode product {md(s['product'])} (CIS benchmark "
                            f"{md(s.get('benchmark_version'))}), {cac.LEVEL_WORDS.get(s.get('level'), s.get('level'))}")
        if s.get("product_note"):
            bits.append(md(s["product_note"]))
        out += ["; ".join(bits), "", f"**{md(s['summary'])}**", ""]
        rows = [c for c in s["controls"] if include_not_checked or c["status"] not in ("not_checked",)
                or c.get("checks")]
        if doc["framework"] == "cis" and not include_not_checked:
            hidden = len(s["controls"]) - len(rows)
            if hidden:
                out += [f"{hidden} CIS section(s) Kratos has no check for are not listed (`--all` lists them with "
                        "their ComplianceAsCode rule ids).", ""]
        out += ["| Control | Status | What Kratos looks at | Owner |", "|---|---|---|---|"]
        for c in rows:
            out.append(f"| {md(c['control'])} | {ST.STATUS_WORDS[c['status']]} | {md(c.get('text'))} | "
                       f"{md(c.get('owner') or '')} |")
        out.append("")
        details = [c for c in rows if c["status"] in ("fail", "partial", "not_applicable") or
                   (c["status"] == "not_checked" and c.get("checks"))]
        if details:
            out += ["### Details", ""]
        for c in details:
            out.append(f"**{md(c['control'])} — {ST.STATUS_WORDS[c['status']]}**" +
                       (f": {md(c['reason'])}" if c.get("reason") else ""))
            for r in c["check_results"]:
                line = f"- {md_code(r['id'])} {md(r['status'])}: {md(r['found'] or r['reason'])}"
                if r.get("read_at"):
                    line += f" (read {md(r['read_at'])})"
                if r.get("linked_finding"):
                    line += f" — already finding {md(r['linked_finding'])}"
                if r.get("note"):
                    line += f" — {md(r['note'])}"
                out.append(line)
                if r.get("other_read"):
                    o = r["other_read"]
                    out.append(f"  - the {md(o.get('via'))} read said {md(o.get('status'))}: {md(o.get('found'))}")
                if r.get("fix"):
                    out.append(f"  - fix: {md_code(r['fix'])}")
            out.append("")
    return "\n".join(out) + "\n"


def render(doc: dict[str, Any], fmt: str, *, include_not_checked: bool = False) -> str:
    if fmt == "json":
        return to_json(doc)
    if fmt == "csv":
        return to_csv(doc)
    if fmt == "md":
        return to_markdown(doc, include_not_checked=include_not_checked)
    raise ReportError(f"format is one of: {', '.join(FORMATS)}")


def compact(doc: dict[str, Any], *, max_controls: int = 40) -> dict[str, Any]:
    """A short form for MCP and chat: per machine, the summary line and only the controls that
    fail, are partial or a person marked not applicable (with each check's evidence); the
    rest are counted. Never a status the report doesn't hold."""
    out = {k: doc[k] for k in ("framework", "framework_name", "generated_at", "scope", "disclaimer",
                               "outside_scope") if k in doc}
    if doc.get("nis2_note"):
        out["nis2_note"] = doc["nis2_note"]
    machines = []
    for s in doc.get("machines") or []:
        if s.get("status") != "read":
            machines.append({"machine": s["machine"], "status": "not_checked", "reason": s.get("reason")})
            continue
        shown = [c for c in s["controls"] if c["status"] in ("fail", "partial", "not_applicable")][:max_controls]
        machines.append({
            "machine": s["machine"], "os": s.get("os"), "product": s.get("product"),
            "product_note": s.get("product_note"), "read_at": s.get("read_at"), "via": s.get("via"),
            "summary": s.get("summary"), "counts": s.get("counts"),
            "controls": [{"control": c["control"], "status": c["status"], "text": c.get("text"),
                          "reason": c.get("reason"), "owner": c.get("owner") or None,
                          "checks": [{"id": r["id"], "status": r["status"], "found": r["found"] or r["reason"],
                                      "read_at": r.get("read_at"), "fix": r.get("fix") or None,
                                      "already_finding": r.get("linked_finding") or None}
                                     for r in c["check_results"] if r["status"] in ("fail", "unknown")]}
                         for c in shown]})
    out["machines"] = machines
    if doc.get("rollup"):
        out["rollup_counts"] = {st: sum(1 for r in doc["rollup"] if r["status"] == st) for st in ST.STATUSES}
    return out


def compact_text(doc: dict[str, Any], *, max_lines: int = 25) -> str:
    """Plain text for a chat reply."""
    c = compact(doc)
    lines = [f"{c['framework_name']} -- {c['scope']}", c["disclaimer"]]
    if c.get("outside_scope"):
        lines.append(f"{c['outside_scope']} machine(s) in this group are outside your access (not shown).")
    for m in c["machines"]:
        if m.get("status") == "not_checked":
            lines.append(f"{m['machine']}: not checked -- {m.get('reason')}")
            continue
        lines.append(f"{m['machine']}: {m['summary']} (read {m.get('read_at')} via {m.get('via')})")
        for ctl in m["controls"][:max_lines]:
            first = (ctl["checks"] or [{}])[0]
            lines.append(f"  {ctl['control']:<10} {ctl['status']:<14} {ctl.get('text') or ''}"
                         + (f" -- {first.get('found')}" if first.get("found") else ""))
    lines.append("The full report with evidence and fixes: `kratos compliance report` or /compliance in the app.")
    return "\n".join(lines)
