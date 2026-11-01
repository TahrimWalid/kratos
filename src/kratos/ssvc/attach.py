"""Put SSVC decisions and measured exposure on findings, and rank findings by them (D.3).

Which findings get a decision (§3 decision 5): PKG-001 (one package: its worst CVE's
decision, each CVE's own listed), PKG-002 (each package:CVE entry; the finding takes the
worst), PKG-003 (the running kernel's CVEs; exposure = the machine's most exposed point),
VULN-001 (network-matched CVEs; exposure = the scanned ports). Nothing else -- config,
persistence, live-process rules aren't vulnerabilities.

The per-CVE inputs were stored with the package check (``pkgvuln.record``); VULN-001's
are looked up in the local index here (offline). Mission & Well-being comes from the
asset record as it is now, so a criticality change applies at the next report without
reading the machine. ``severity`` is never changed: the decision ranks.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

from kratos.ssvc import exposure as X
from kratos.ssvc import tree as T
from kratos.ssvc.decide import for_finding
from kratos.ssvc.inputs import CveInputs, for_cve
from kratos.ssvc.mission import mission as _mission

logger = logging.getLogger(__name__)

RULES = ("PKG-001", "PKG-002", "PKG-003", "VULN-001")
_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# A decision's place among severities when one list mixes both: Act sits with critical.
_BAND = {T.ACT: 4, T.ATTEND: 3, T.TRACK_STAR: 2, T.TRACK: 1}
ENTRIES_KEPT = 20


def _get(f: Any, key: str, default: Any = None) -> Any:
    return f.get(key, default) if isinstance(f, dict) else getattr(f, key, default)


def _set(f: Any, key: str, value: Any) -> None:
    if isinstance(f, dict):
        f[key] = value
    else:
        setattr(f, key, value)


def _firewall(config_audit: dict[str, Any] | None) -> dict[str, Any] | None:
    for row in (config_audit or {}).get("checks") or []:
        if isinstance(row, dict) and str(row.get("check")) == "firewall":
            return row
    return None


def _signals(doc: dict[str, Any] | None) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for s in (doc or {}).get("signals") or []:
        if isinstance(s, dict) and s.get("rule") in ("PKG-001", "PKG-002", "PKG-003"):
            out[(str(s["rule"]), str(s.get("subject") or ""))] = s
    return out


def _inputs(sig: dict[str, Any]) -> list[CveInputs]:
    return [CveInputs.from_dict(d) for d in sig.get("ssvc_inputs") or [] if isinstance(d, dict)]


def _vuln_inputs(data_dir: Path, cves: list[str]) -> list[CveInputs]:
    from kratos.pkgvuln import index as _index
    from kratos.pkgvuln import ssvc_source

    conn = _index.open_readonly(data_dir)
    if conn is None:
        return [for_cve(c, cisa=None, kev=None, cvss=None) for c in cves]
    try:
        info = _index.enrichment(conn, cves)
        cisa = ssvc_source.lookup(conn, cves)
    finally:
        conn.close()
    return [for_cve(c, cisa=cisa.get(c), kev=(info.get(c) or {}).get("kev"), cvss=(info.get(c) or {}).get("cvss"),
                    epss=((info.get(c) or {}).get("epss") or {}).get("score")) for c in cves]


def _vuln_ports(vuln_scan: dict[str, Any] | None, cves: set[str]) -> list[Any]:
    ports: list[Any] = []
    for x in (vuln_scan or {}).get("findings") or []:
        if isinstance(x, dict) and x.get("source") == "vulscan" and cves & {str(c).upper() for c in x.get("cve_ids") or []}:
            if x.get("port") not in ports:
                ports.append(x.get("port"))
    return ports


def _pkg002(sig: dict[str, Any], mission: Any, live: dict[str, Any] | None, override: str | None,
            firewall: dict[str, Any] | None) -> dict[str, Any] | None:
    by_pkg: dict[str, list[CveInputs]] = {}
    for d in sig.get("ssvc_inputs") or []:
        if isinstance(d, dict) and d.get("package"):
            by_pkg.setdefault(str(d["package"]), []).append(CveInputs.from_dict(d))
    binaries = {str(p.get("package")): p.get("binaries") or [] for p in sig.get("packages") or [] if isinstance(p, dict)}
    entries = []
    for pkg, items in by_pkg.items():
        s = for_finding(items, mission, fix_available=False)
        if s is None:
            continue
        ex = X.for_packages(binaries.get(pkg) or [pkg], live, override=override, firewall=firewall, label=pkg)
        entries.append({"package": pkg, "outcome": s["outcome"], "label": s["label"], "cve": s["cve"],
                        "exposure": ex.to_dict(), "decision": s})
    if not entries:
        return None
    entries.sort(key=lambda e: (-T.rank(e["outcome"]), X.rank(e["exposure"]["value"]), e["package"]))
    top = dict(entries[0]["decision"])
    top["exposure"] = entries[0]["exposure"]
    top["package"] = entries[0]["package"]
    top["entries"] = [{k: v for k, v in e.items() if k != "decision"} for e in entries[:ENTRIES_KEPT]]
    top["entry_count"] = len(entries)
    return top


def attach(findings: Iterable[Any], *, data_dir: Path, target: str, packages_doc: dict[str, Any] | None,
           live_doc: dict[str, Any] | None, config_audit: dict[str, Any] | None = None,
           vuln_scan: dict[str, Any] | None = None) -> None:
    """Set `ssvc` on every finding SSVC applies to (Finding objects or dicts). Never
    raises: a failure leaves findings without a decision and is logged."""
    try:
        _attach(list(findings), Path(data_dir), target, packages_doc, live_doc, config_audit, vuln_scan)
    except Exception:  # noqa: BLE001 -- a decision must never cost the report
        logger.exception("SSVC decisions could not be attached; the findings are kept without them")


def _attach(findings: list[Any], data_dir: Path, target: str, packages_doc: dict[str, Any] | None,
            live_doc: dict[str, Any] | None, config_audit: dict[str, Any] | None,
            vuln_scan: dict[str, Any] | None) -> None:
    wanted = [f for f in findings if _get(f, "id") in RULES]
    if not wanted:
        return
    from kratos.assets import store as assets

    asset = assets.get(data_dir, target)
    mission = _mission(asset.criticality if asset else None, asset.wellbeing if asset else None)
    override = asset.exposure_override if asset else None
    firewall = _firewall(config_audit)
    signals = _signals(packages_doc)
    for f in wanted:
        fid = str(_get(f, "id"))
        sig = signals.get((fid, str(_get(f, "subject") or "")))
        decision: dict[str, Any] | None = None
        if fid == "PKG-001" and sig:
            decision = for_finding(_inputs(sig), mission, fix_available=True)
            if decision is not None:
                decision["exposure"] = X.for_packages(sig.get("binaries") or [sig.get("subject")], live_doc,
                                                      override=override, firewall=firewall,
                                                      label=str(sig.get("subject") or "")).to_dict()
        elif fid == "PKG-002" and sig:
            decision = _pkg002(sig, mission, live_doc, override, firewall)
        elif fid == "PKG-003" and sig:
            decision = for_finding(_inputs(sig), mission, fix_available=True)
            if decision is not None:
                decision["exposure"] = X.machine_highest(live_doc, override=override, firewall=firewall).to_dict()
                decision["fix"] = "reboot into the newer kernel that is already installed"
        elif fid == "VULN-001":
            cves = [str(e).upper() for e in _get(f, "entities") or [] if str(e).upper().startswith("CVE-")]
            if cves:
                decision = for_finding(_vuln_inputs(data_dir, cves), mission, fix_available=None)
                if decision is not None:
                    ex = X.for_scanned_ports(_vuln_ports(vuln_scan, set(cves)), target, override=override,
                                             scanned_at=str((vuln_scan or {}).get("scanned_at") or ""))
                    decision["exposure"] = ex.to_dict()
                    decision["fix_available"] = None        # a network text match says nothing about fixes
        if decision is not None:
            _set(f, "ssvc", decision)


# ------------------------------------------------------------------ ranking (every surface)
def outcome_of(f: Any) -> str | None:
    s = _get(f, "ssvc") or {}
    return s.get("outcome") if isinstance(s, dict) else None


def exposure_of(f: Any) -> str | None:
    s = _get(f, "ssvc") or {}
    return ((s.get("exposure") or {}).get("value")) if isinstance(s, dict) else None


def sort_key(f: Any) -> tuple[Any, ...]:
    """Most urgent first. A finding with an SSVC decision ranks by it (Act with critical,
    Attend with high, Track* with medium, Track with low) and, at the same level, before
    one ranked only by severity; within one decision: exposure, then KEV, then EPSS."""
    s = _get(f, "ssvc") or {}
    outcome = s.get("outcome") if isinstance(s, dict) else None
    sev = _SEVERITY.get(str(_get(f, "severity") or "info").lower(), 0)
    band = _BAND.get(str(outcome), sev) if outcome else sev
    return (-band, -T.rank(outcome), X.rank(exposure_of(f)) if outcome else 9, not bool(s.get("kev")) if outcome else True,
            -float(s.get("epss") or 0.0) if outcome else 0.0, -sev, str(_get(f, "id") or ""))


def at_least(f: Any, floor: str) -> bool:
    """Does the finding's decision reach `floor` (track | track* | attend | act)?"""
    return T.rank(outcome_of(f)) >= T.rank(floor) >= 0


def short_line(ssvc: dict[str, Any] | None) -> str:
    """'Act (exploited, automatable, total impact, mission high; exposure internet)' -- for the model."""
    from kratos.ssvc.decide import summary_words

    if not isinstance(ssvc, dict) or not ssvc.get("label"):
        return ""
    ex = (ssvc.get("exposure") or {}).get("value")
    return f"{ssvc['label']} ({summary_words(ssvc)}" + (f"; exposure {ex}" if ex else "") + ")"


def _listening_fact(ssvc: dict[str, Any]) -> str:
    """'listening on 0.0.0.0:22' from an exposure, or '' -- only validated values
    (an IP address and a port number), never a program path from the machine."""
    ex = ssvc.get("exposure") or {}
    if ex.get("value") not in (X.INTERNET, X.NETWORK):
        return f"exposure {ex.get('value')}" if ex.get("value") else ""
    import re

    for m in re.finditer(r"(\[[0-9a-fA-F:.]+\]|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", str(ex.get("reason") or "")):
        addr = m.group(1).strip("[]")
        if _valid_ip(addr):
            return f"listening on {m.group(1)}:{m.group(2)}; exposure {ex['value']}"
    return f"exposure {ex['value']}"


def _valid_ip(text: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def digest_lead(findings: Iterable[Any], machine: str, *, limit: int = 2) -> str:
    """'Act: openssh on web-01 (exploited, automatable, total impact, mission high;
    listening on 0.0.0.0:22)' for the most urgent decided package findings (Act, else
    Attend). '' when none. Package names come from the vulnerability index (validated
    shape), never free text from the machine."""
    import re

    from kratos.ssvc.decide import summary_words

    pkg_re = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,99}$")
    decided = sorted((f for f in findings if _get(f, "id") in RULES and outcome_of(f) in (T.ACT, T.ATTEND)
                      and str(_get(f, "state") or "open") not in ("risk_accepted", "false_positive", "out_of_scope")),
                     key=sort_key)
    if not decided:
        return ""
    top = outcome_of(decided[0])
    parts = []
    for f in [f for f in decided if outcome_of(f) == top][:limit]:
        s = _get(f, "ssvc") or {}
        fid = str(_get(f, "id"))
        name = str(_get(f, "subject") or s.get("package") or "")
        what = name if pkg_re.match(name) else {"PKG-003": "the running kernel", "VULN-001": "a network service"
                                                }.get(fid, "a package")
        fact = _listening_fact(s)
        parts.append(f"{what} on {machine} ({summary_words(s)}" + (f"; {fact}" if fact else "") + ")")
    more = sum(1 for f in decided if outcome_of(f) == top) - len(parts)
    return f"{T.LABELS[top]}: " + "; ".join(parts) + (f" (+{more} more)" if more > 0 else "")
