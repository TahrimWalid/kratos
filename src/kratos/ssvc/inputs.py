"""The three per-CVE SSVC inputs, each with where it came from (D.3 §3 decision 2).

- **CISA's own assessment** (vulnrichment, ``kratos.pkgvuln.ssvc_source``) where it
  exists, with CISA's date.
- **Exploitation** without one: on CISA's Known Exploited Vulnerabilities list ->
  active (source ``kev``); otherwise ``none`` labelled "not assessed" -- never
  guessed from EPSS (EPSS is shown beside it). A CVE CISA assessed as none/poc that
  KEV lists since is active, from KEV: both are CISA's word, KEV the newer one.
- **Automatable** and **Technical Impact** without one: estimated from the CVSS
  vector by a small rule (below), labelled "estimated from CVSS", never as CISA's.
- Neither CISA nor a CVSS vector: that input is missing and the decision is "not
  enough data", never a guessed outcome.

The CVSS estimate:

- Automatable yes  <=>  network attack, low complexity, no privileges, no user
  interaction (v3: AV:N AC:L PR:N UI:N; v4 adds AT:N; v2: AV:N AC:L Au:N).
- Technical Impact total  <=>  high confidentiality AND high integrity impact, or a
  changed scope with high confidentiality or integrity impact (v3: C:H I:H, or S:C
  with C:H or I:H; v4: VC:H VI:H, or SC:H and SI:H; v2: C:C I:C).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CISA, KEV, ESTIMATE, NOT_ASSESSED = "cisa-adp", "kev", "cvss-estimate", "not-assessed"
SOURCE_WORDS = {CISA: "CISA's assessment", KEV: "CISA's exploited list (KEV)",
                ESTIMATE: "estimated from CVSS", NOT_ASSESSED: "not assessed"}


@dataclass(frozen=True)
class Input:
    value: str | None           # None: no data for it
    source: str                 # cisa-adp | kev | cvss-estimate | not-assessed
    date: str = ""              # CISA's assessment date, the KEV date added
    note: str = ""              # e.g. the CVSS vector an estimate came from

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "source": self.source, "date": self.date, "note": self.note}

    @classmethod
    def from_dict(cls, d: Any) -> "Input":
        d = d if isinstance(d, dict) else {}
        value = d.get("value")
        return cls(str(value) if value else None, str(d.get("source") or NOT_ASSESSED), str(d.get("date") or ""),
                   str(d.get("note") or ""))

    def words(self) -> str:
        where = SOURCE_WORDS.get(self.source, self.source)
        if self.date:
            where += f", {self.date[:10]}"
        return where


@dataclass(frozen=True)
class CveInputs:
    cve: str
    exploitation: Input
    automatable: Input
    technical_impact: Input
    epss: float | None = None
    kev: bool = False
    ransomware: bool = False      # KEV's knownRansomwareCampaignUse == "Known"
    fixed_in: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def enough(self) -> bool:
        return all(i.value for i in (self.exploitation, self.automatable, self.technical_impact))

    def to_dict(self) -> dict[str, Any]:
        return {"cve": self.cve, "exploitation": self.exploitation.to_dict(),
                "automatable": self.automatable.to_dict(), "technical_impact": self.technical_impact.to_dict(),
                "epss": self.epss, "kev": self.kev, "ransomware": self.ransomware, "fixed_in": self.fixed_in}

    @classmethod
    def from_dict(cls, d: Any) -> "CveInputs":
        d = d if isinstance(d, dict) else {}
        epss = d.get("epss")
        return cls(str(d.get("cve") or ""), Input.from_dict(d.get("exploitation")), Input.from_dict(d.get("automatable")),
                   Input.from_dict(d.get("technical_impact")), float(epss) if isinstance(epss, (int, float)) else None,
                   bool(d.get("kev")), bool(d.get("ransomware")), d.get("fixed_in") or None)


def _metrics(vector: str) -> tuple[str, dict[str, str]]:
    """('3' | '4' | '2' | '', {metric: value}) from a CVSS vector string."""
    v = str(vector or "").strip()
    version = ""
    if v.startswith("CVSS:3"):
        version = "3"
    elif v.startswith("CVSS:4"):
        version = "4"
    elif "Au:" in v and "AV:" in v:
        version = "2"
    out: dict[str, str] = {}
    for part in v.split("/"):
        k, sep, val = part.partition(":")
        if sep and k and not k.startswith("CVSS"):
            out[k.strip()] = val.strip()
    return version, out


def estimate_automatable(vector: str) -> str | None:
    version, m = _metrics(vector)
    if version == "3":
        need = {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
    elif version == "4":
        need = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N"}
    elif version == "2":
        need = {"AV": "N", "AC": "L", "Au": "N"}
    else:
        return None
    if any(k not in m for k in need):
        return None
    return "yes" if all(m[k] == v for k, v in need.items()) else "no"


def estimate_technical_impact(vector: str) -> str | None:
    version, m = _metrics(vector)
    if version == "3":
        if not all(k in m for k in ("C", "I", "S")):
            return None
        total = (m["C"] == "H" and m["I"] == "H") or (m["S"] == "C" and (m["C"] == "H" or m["I"] == "H"))
    elif version == "4":
        if not all(k in m for k in ("VC", "VI")):
            return None
        total = (m["VC"] == "H" and m["VI"] == "H") or (m.get("SC") == "H" and m.get("SI") == "H")
    elif version == "2":
        if not all(k in m for k in ("C", "I")):
            return None
        total = m["C"] == "C" and m["I"] == "C"
    else:
        return None
    return "total" if total else "partial"


def for_cve(cve: str, *, cisa: dict[str, Any] | None, kev: dict[str, Any] | None, cvss: dict[str, Any] | None,
            epss: float | None = None, fixed_in: str | None = None) -> CveInputs:
    """The inputs for one CVE from what the index holds about it."""
    cisa = cisa or {}
    cisa_date = str(cisa.get("assessed_at") or "")
    kev_date = str((kev or {}).get("date_added") or "")
    vector = str((cvss or {}).get("vector") or "")

    cisa_expl = cisa.get("exploitation")
    if kev:
        note = (f"CISA's assessment of {cisa_date[:10] or 'an earlier date'} said {cisa_expl}; it is on CISA's "
                "exploited list since") if cisa_expl and cisa_expl != "active" else ""
        exploitation = Input("active", KEV, kev_date, note) if cisa_expl != "active" else Input("active", CISA, cisa_date)
    elif cisa_expl:
        exploitation = Input(str(cisa_expl), CISA, cisa_date)
    else:
        exploitation = Input("none", NOT_ASSESSED, "", "no CISA assessment and not on CISA's exploited list")

    def pick(key: str, estimate: Any) -> Input:
        if cisa.get(key):
            return Input(str(cisa[key]), CISA, cisa_date)
        value = estimate(vector) if vector else None
        if value:
            return Input(value, ESTIMATE, "", vector)
        return Input(None, NOT_ASSESSED, "", "no CISA assessment and no CVSS vector")

    return CveInputs(str(cve).upper(), exploitation, pick("automatable", estimate_automatable),
                     pick("technical_impact", estimate_technical_impact),
                     float(epss) if epss is not None else None, bool(kev),
                     str((kev or {}).get("known_ransomware") or "").strip().lower() == "known", fixed_in)
