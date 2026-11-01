"""CISA BOD 26-04's remediation timeline, shown beside the SSVC decision (pure, no I/O).

Binding Operational Directive 26-04, "Prioritizing Security Updates Based on Risk"
(CISA, issued 2026-06-10; implementation guidance updated 2026-08-25), binds U.S.
federal civilian agencies; it replaced BOD 19-02 and BOD 22-01. Kratos shows its
timeline as a guide for everyone else: it never changes the SSVC decision, the
severity or the ranking.

The table (the directive's Table 1) takes four inputs -- In KEV, Publicly Exposed,
Automatable, Technical Impact -- and returns one of five timelines. The directive
prints it as an image; the rows below were checked against CERT/CC's machine copy,
``data/csv/cisa/cisa_bod_26_04_1_0_0.csv`` in https://github.com/CERTCC/SSVC
(Copyright 2026 Carnegie Mellon University, MIT (SEI)-style licence; added
2026-06-11, sha256 78b0e953...). Mission & Well-being is not an input.

Where each input comes from:

- **In KEV**: CISA's Known Exploited Vulnerabilities list, from the local index.
- **Publicly Exposed** is about the *machine* (CISA: the asset "is accessible to
  unauthenticated or untrusted entities via a public network"), not about one
  package: the person's /assets setting if made, else Kratos's measurement (anything
  listening on a public address, or a scan that reached a public address), else
  CISA's rule for missing exposure data -- public if the machine uses a publicly
  routable address, otherwise internal.
- **Automatable**, **Technical Impact**: CISA's own assessment (vulnrichment), else
  CISA's rule for missing values: "no" and "total". Kratos's CVSS estimate (used for
  the SSVC decision) is not used here -- the directive names CISA's values.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Final, Iterable

from kratos.ssvc import exposure as X
from kratos.ssvc import inputs as I

TABLE_VERSION: Final = "cisa-bod-26-04-1.0.0"

FORENSIC, DAYS_3, DAYS_14, DAYS_60, UPGRADE = "3d_forensic", "3d", "14d", "60d", "upgrade"
TIMELINES = (UPGRADE, DAYS_60, DAYS_14, DAYS_3, FORENSIC)          # least urgent first
RANK = {t: i for i, t in enumerate(TIMELINES)}
LABELS = {FORENSIC: "3 days + forensic check", DAYS_3: "3 days", DAYS_14: "14 days", DAYS_60: "60 days",
          UPGRADE: "fix on system upgrade"}
DAYS = {FORENSIC: 3, DAYS_3: 3, DAYS_14: 14, DAYS_60: 60, UPGRADE: None}
MEANING = {
    FORENSIC: "fix or mitigate within 3 days, and check the machine for signs it was already compromised "
              "(CISA's forensic triage)",
    DAYS_3: "fix or mitigate within 3 days",
    DAYS_14: "fix or mitigate within 14 days",
    DAYS_60: "fix or mitigate within 60 days",
    UPGRADE: "no deadline: fix at the machine's next scheduled major upgrade or rebuild, unless it is added to "
             "CISA's exploited list",
}
CLOCK = ("The clock starts when CISA adds the CVE to its exploited list or when the vulnerability is found on the "
         "machine, whichever comes first.")
SCOPE = "binding on U.S. federal agencies; a guide for everyone else"

# (in KEV, publicly exposed, automatable, technical impact) -> timeline: CISA's Table 1.
_ROWS: Final = (
    ("no", "no", "no", "partial", UPGRADE), ("yes", "no", "no", "partial", DAYS_14),
    ("no", "yes", "no", "partial", DAYS_60), ("no", "no", "yes", "partial", DAYS_60),
    ("no", "no", "no", "total", UPGRADE), ("yes", "yes", "no", "partial", DAYS_14),
    ("yes", "no", "yes", "partial", DAYS_14), ("no", "yes", "yes", "partial", DAYS_14),
    ("yes", "no", "no", "total", DAYS_14), ("no", "yes", "no", "total", DAYS_14),
    ("no", "no", "yes", "total", DAYS_60), ("yes", "yes", "yes", "partial", DAYS_3),
    ("yes", "yes", "no", "total", FORENSIC), ("yes", "no", "yes", "total", FORENSIC),
    ("no", "yes", "yes", "total", DAYS_3), ("yes", "yes", "yes", "total", FORENSIC),
)
TABLE: Final = {row[:4]: row[4] for row in _ROWS}

# Where an input came from (shown beside it).
PERSON, MEASURED, CISA_RULE = "person", "measured", "cisa-missing-rule"
SOURCE_WORDS = {I.CISA: "CISA's assessment", I.KEV: "CISA's exploited list (KEV)", PERSON: "your /assets setting",
                MEASURED: "measured by Kratos", CISA_RULE: "CISA's rule for missing data"}


def rows() -> tuple[tuple[str, str, str, str, str], ...]:
    return _ROWS


def timeline(in_kev: str, publicly_exposed: str, automatable: str, technical_impact: str) -> str:
    """Raises KeyError for a value outside the table's sets."""
    return TABLE[(in_kev, publicly_exposed, automatable, technical_impact)]


def label(value: str | None) -> str:
    return LABELS.get(str(value or ""), "")


def rank(value: str | None) -> int:
    """3 days + forensic check 4 ... fix on system upgrade 0; none -1."""
    return RANK.get(str(value or ""), -1)


def _input(value: str, source: str, date: str = "", note: str = "") -> dict[str, Any]:
    return {"value": value, "source": source, "date": date, "note": note}


def _public_address(addresses: Iterable[Any]) -> str:
    for a in addresses:
        try:
            ip = ipaddress.ip_address(str(a or "").split("%", 1)[0].strip("[]"))
        except ValueError:
            continue
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if X._public(ip):
            return str(ip)
    return ""


def publicly_exposed(*, override: str | None, measured: Iterable[dict[str, Any] | None],
                     addresses: Iterable[Any] = ()) -> dict[str, Any]:
    """The machine's Publicly Exposed input, with where it came from.

    `measured` are Kratos's exposures for this machine (the machine's most exposed
    point, a scan's); `addresses` are addresses the machine is known by (its own, the
    one Kratos reaches it at) for CISA's missing-data rule."""
    if override == "internet":
        return _input("yes", PERSON, note="you marked this machine as reachable from the internet")
    if override == "private":
        return _input("no", PERSON, note="you marked this machine as not reachable from the internet")
    known = [m for m in measured if isinstance(m, dict) and m.get("value") and m.get("value") != X.UNKNOWN]
    hit = next((m for m in known if m.get("value") == X.INTERNET), None)
    if hit is not None:
        return _input("yes", MEASURED, str(hit.get("measured_at") or ""), str(hit.get("reason") or ""))
    if known:
        return _input("no", MEASURED, str(known[0].get("measured_at") or ""), str(known[0].get("reason") or ""))
    public = _public_address(addresses)
    if public:
        return _input("yes", CISA_RULE, note=f"Kratos couldn't measure exposure; the machine uses the publicly "
                                             f"routable address {public}")
    return _input("no", CISA_RULE, note="Kratos couldn't measure exposure and knows no publicly routable address "
                                        "for this machine, so it counts as internal -- if it is reachable from the "
                                        "internet, say so in /assets")


def _cisa_or_default(i: I.Input, default: str) -> dict[str, Any]:
    if i.source == I.CISA and i.value:
        return _input(str(i.value), I.CISA, i.date)
    return _input(default, CISA_RULE, note=f"CISA hasn't assessed it; the directive counts a missing value as "
                                           f"\"{default}\"")


def for_cve(c: I.CveInputs, exposed: dict[str, Any]) -> dict[str, Any]:
    kev = _input("yes" if c.kev else "no", I.KEV,
                 c.exploitation.date if c.kev and c.exploitation.source == I.KEV else "")
    auto = _cisa_or_default(c.automatable, "no")
    impact = _cisa_or_default(c.technical_impact, "total")
    t = timeline(kev["value"], exposed["value"], auto["value"], impact["value"])
    return {"cve": c.cve, "timeline": t, "label": LABELS[t], "days": DAYS[t],
            "inputs": {"in_kev": kev, "publicly_exposed": exposed, "automatable": auto, "technical_impact": impact}}


def for_finding(cves: Iterable[I.CveInputs], exposed: dict[str, Any]) -> dict[str, Any] | None:
    """The finding's timeline: its most urgent CVE's, with the inputs that set it."""
    per = [for_cve(c, exposed) for c in cves if c.cve]
    if not per:
        return None
    per.sort(key=lambda d: (-rank(d["timeline"]), d["cve"]))
    worst = per[0]
    counts: dict[str, int] = {}
    for d in per:
        counts[d["timeline"]] = counts.get(d["timeline"], 0) + 1
    return {"timeline": worst["timeline"], "label": worst["label"], "days": worst["days"], "cve": worst["cve"],
            "meaning": MEANING[worst["timeline"]], "inputs": worst["inputs"], "table": TABLE_VERSION,
            "counts": counts}


def short(b: dict[str, Any] | None) -> str:
    """'CISA BOD 26-04: 14 days' or ''."""
    return f"CISA BOD 26-04: {b['label']}" if isinstance(b, dict) and b.get("label") else ""


_INPUT_NAMES = (("in_kev", "In KEV"), ("publicly_exposed", "Publicly exposed"), ("automatable", "Automatable"),
                ("technical_impact", "Technical impact"))


def detail_lines(b: dict[str, Any] | None) -> list[str]:
    """The timeline, what it means, its four inputs with their sources, and the clock."""
    if not isinstance(b, dict) or not b.get("label"):
        return []
    out = [f"CISA BOD 26-04 deadline: {b['label']} ({SCOPE}; worst CVE {b.get('cve')}) -- {b.get('meaning')}."]
    inp = b.get("inputs") or {}
    parts = []
    for key, name in _INPUT_NAMES:
        d = inp.get(key) or {}
        where = SOURCE_WORDS.get(str(d.get("source") or ""), str(d.get("source") or ""))
        if d.get("date"):
            where += f", {str(d['date'])[:10]}"
        parts.append(f"{name}: {d.get('value')} [{where}]")
    out.append("  " + " · ".join(parts))
    exp = inp.get("publicly_exposed") or {}
    if exp.get("source") in (PERSON, CISA_RULE) and exp.get("note"):
        out.append(f"  Publicly exposed: {exp['note']}.")
    for key, name in (("automatable", "Automatable"), ("technical_impact", "Technical impact")):
        if (inp.get(key) or {}).get("source") == CISA_RULE:
            out.append(f"  {name}: {inp[key]['note']}.")
    out.append(f"  {CLOCK}")
    return out
