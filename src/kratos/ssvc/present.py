"""How an SSVC decision reads to a person -- one wording for every surface (D.3 §5.4).

TUI /findings, `kratos findings show`, the Markdown report, the terminal panels and
MCP all show the same lines: the decision, CISA's definition of it, the four inputs
with where each came from and when, the measured exposure in plain words, and per CVE
the two facts people act on -- used in ransomware campaigns (KEV), and whether the
distribution has a fix today. Machine-written text (a program path inside an exposure
reason) is cleaned by the caller's display layer like any other evidence.
"""
from __future__ import annotations

from typing import Any

from kratos.ssvc import inputs as I
from kratos.ssvc import tree as T

_INPUT_NAMES = (("exploitation", "Exploitation"), ("automatable", "Automatable"),
                ("technical_impact", "Technical impact"))
_VALUE_WORDS = {
    "exploitation": {"none": "none", "poc": "public proof of concept", "active": "active (exploited in the wild)"},
    "automatable": {"yes": "yes", "no": "no"},
    "technical_impact": {"total": "total", "partial": "partial"},
}
CVES_SHOWN = 5


def ssvc_of(f: Any) -> dict[str, Any]:
    s = f.get("ssvc") if isinstance(f, dict) else getattr(f, "ssvc", None)
    return s if isinstance(s, dict) and s.get("label") else {}


def cell(f: Any) -> str:
    """The Decision column: 'Act' / 'Attend' / 'Track*' / 'Track' / 'no data' / ''."""
    s = ssvc_of(f)
    if not s:
        return ""
    return T.LABELS.get(str(s.get("outcome") or ""), "no data")


def exposure_cell(f: Any) -> str:
    s = ssvc_of(f)
    return str((s.get("exposure") or {}).get("value") or "") if s else ""


def _input_line(name: str, label: str, d: dict[str, Any]) -> str:
    value = d.get("value")
    words = _VALUE_WORDS.get(name, {}).get(str(value), str(value)) if value else "unknown"
    src = str(d.get("source") or I.NOT_ASSESSED)
    where = I.SOURCE_WORDS.get(src, src)
    if d.get("date"):
        where += f", {str(d['date'])[:10]}"
    if src == I.ESTIMATE and d.get("note"):
        where += f" ({d['note']})"
    note = f" -- {d['note']}" if d.get("note") and src != I.ESTIMATE else ""
    return f"{label}: {words}  [{where}]{note}"


def _mission_line(m: dict[str, Any]) -> str:
    if m.get("assumed"):
        crit = "criticality not set -- assumed medium (set it: /assets or `kratos assets set`)"
    else:
        crit = f"criticality {m.get('criticality')} (your setting)"
    return (f"Mission & well-being: {m.get('value')}  [{crit}; mission prevalence {m.get('prevalence')}, "
            f"public well-being impact {m.get('wellbeing')}]")


def _cve_line(c: dict[str, Any], fix_known: bool) -> str:
    bits = [f"{c.get('cve')}: {c.get('label') or T.label(c.get('outcome'))}"]
    vals = [str(c.get(k) or "?") for k in ("exploitation", "automatable", "technical_impact")]
    bits.append(f"({'/'.join(vals)})")
    if c.get("ransomware"):
        bits.append("used in ransomware campaigns (CISA KEV)")
    elif c.get("kev"):
        bits.append("on CISA's exploited list")
    if c.get("epss") is not None:
        bits.append(f"EPSS {float(c['epss']):.2f}")
    if fix_known:
        bits.append(f"fixed in {c['fixed_in']}" if c.get("fixed_in") else "no fix yet from the distribution")
    return " ".join(bits[:2]) + (" -- " + ", ".join(bits[2:]) if len(bits) > 2 else "")


def detail_lines(s: dict[str, Any]) -> list[str]:
    """Everything that produced a decision, in plain words (most important first)."""
    if not s:
        return []
    out = [f"SSVC decision: {s.get('label')} (CISA SSVC tree {s.get('tree')}; worst CVE {s.get('cve')})"]
    if s.get("definition"):
        out.append(f"What {s.get('label')} means (CISA): {s['definition']}")
    elif not s.get("outcome"):
        out.append("Not enough data: CISA hasn't assessed this CVE and it has no CVSS vector to estimate from, so "
                   "Kratos shows no decision rather than guess one.")
    inp = s.get("inputs") or {}
    for name, label in _INPUT_NAMES:
        out.append(_input_line(name, label, inp.get(name) or {}))
    if inp.get("mission_wellbeing"):
        out.append(_mission_line(inp["mission_wellbeing"]))
    ex = s.get("exposure") or {}
    if ex:
        line = f"Exposure on this machine (measured by Kratos, not part of CISA's tree): {ex.get('value')} -- " \
               f"{ex.get('reason')}"
        if ex.get("measured_at"):
            line += f" [read {str(ex['measured_at'])[:16].replace('T', ' ')}" + (f" via {ex['via']}" if ex.get("via") else "") + "]"
        if ex.get("fix"):
            line += f" To see more: {ex['fix']}."
        out.append(line)
    action = action_line(s)
    if action:
        out.append(action)
    fix_known = s.get("fix_available") is not None
    cves = s.get("cves") or []
    for c in cves[:CVES_SHOWN]:
        out.append("  " + _cve_line(c, fix_known))
    total = int(s.get("cve_count") or len(cves))
    if total > CVES_SHOWN:
        out.append(f"  ... and {total - CVES_SHOWN} more CVE(s)")
    for e in (s.get("entries") or [])[:CVES_SHOWN] if s.get("entries") else []:
        out.append(f"  {e.get('package')}: {e.get('label')} ({e.get('cve')}); exposure "
                   f"{(e.get('exposure') or {}).get('value')}")
    return out


def action_line(s: dict[str, Any]) -> str:
    """What to do, by the decision and whether a fix exists today."""
    outcome = s.get("outcome")
    if outcome not in (T.ACT, T.ATTEND):
        return ""
    when = "as soon as possible" if outcome == T.ACT else "sooner than your normal update schedule"
    if s.get("fix_available") is False:
        return (f"No fix yet -- limit who can reach it ({when}): firewall the service, or stop it if it isn't "
                "needed, until the distribution ships a fix.")
    if s.get("fix"):
        return f"Fix {when}: {s['fix']}."
    if s.get("fix_available"):
        return f"Upgrade {when} (CISA's guidance for {T.LABELS[outcome]})."
    return f"Check and fix {when} (CISA's guidance for {T.LABELS[outcome]})."


def one_line(s: dict[str, Any]) -> str:
    """'Act -- exploited, automatable, total impact, mission high; exposure internet'."""
    from kratos.ssvc.decide import summary_words

    if not s:
        return ""
    ex = (s.get("exposure") or {}).get("value")
    return f"{s.get('label')} -- {summary_words(s)}" + (f"; exposure {ex}" if ex else "")
