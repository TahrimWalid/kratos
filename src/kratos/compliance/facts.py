"""The facts a compliance check reads, each with when and how it was read (E.2 §3.3/§3.4).

One `Facts` per machine: the new `hardening_facts` read, plus facts Kratos already
collected and saves (reused, never re-read): the config audit (firewall, automatic
updates, world-writable /etc), the persistence read (setuid programs no package
installed, /etc/ld.so.preload), the package read (known-exploited vulnerabilities,
pending reboot, which packages are installed), the privileged-accounts read (UID 0),
the log-integrity check (journal sealing) and the running-process read (exposure).

A source that is missing is simply absent: a check reading it says "not checked" with
the source's fix, never pass. Freshness is judged by `status.py`, not here.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The sources, and the plain words used for them in the report.
SOURCES: dict[str, str] = {
    "hardening": "hardening read",
    "config_audit": "config audit",
    "persistence": "persistence read",
    "packages": "package read",
    "inventory": "installed-package list",
    "privileged": "privileged-accounts read",
    "log_integrity": "log-integrity check",
    "live": "running-process read",
}
SOURCE_FIX: dict[str, str] = {
    "hardening": "run a check of the machine (`kratos collect <machine>`)",
    "config_audit": "run a check of the machine (`kratos collect <machine>`)",
    "persistence": "run a check of the machine (`kratos collect <machine>`)",
    "packages": "run a check of the machine (`kratos collect <machine>`)",
    "inventory": "run a check of the machine (`kratos collect <machine>`)",
    "privileged": "run a check of the machine (`kratos collect <machine>`)",
    "log_integrity": "run a check of the machine (`kratos collect <machine>`)",
    "live": "run a check of the machine (`kratos collect <machine>`)",
}


@dataclass
class Source:
    name: str
    data: Any
    read_at: float | None             # epoch seconds
    via: str = ""                     # "ssh" | "subagent" | ...
    complete: bool = True
    gaps: dict[str, str] = field(default_factory=dict)

    def label(self) -> str:
        return SOURCES.get(self.name, self.name)


@dataclass
class Facts:
    target: str
    sources: dict[str, Source] = field(default_factory=dict)
    # The other transport's hardening read, when there is one (the fresher one is `sources["hardening"]`).
    other_hardening: Source | None = None

    def get(self, name: str) -> Source | None:
        return self.sources.get(name)

    def h(self) -> dict[str, Any]:
        src = self.sources.get("hardening")
        return src.data if src is not None and isinstance(src.data, dict) else {}

    def family(self) -> str:
        return os_family(self.h().get("os") or {})


def os_family(os_facts: dict[str, Any]) -> str:
    ids = {str(os_facts.get("ID") or "").lower(), *str(os_facts.get("ID_LIKE") or "").lower().split()}
    if ids & {"debian", "ubuntu"}:
        return "debian"
    if ids & {"rhel", "fedora", "centos", "rocky", "almalinux"}:
        return "rhel"
    if "alpine" in ids:
        return "alpine"
    return "other"


def _epoch(doc: dict[str, Any], *keys: str) -> float | None:
    from kratos.utils.timeutil import epoch_of

    for k in keys:
        v = doc.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
            return float(v)
        if isinstance(v, str) and v:
            try:
                return float(epoch_of(v))
            except (TypeError, ValueError):
                continue
    return None


def _json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def hardening_source(doc: dict[str, Any] | None) -> Source | None:
    """A saved hardening read (kratos.compliance.record keeps one per transport)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("facts"), dict):
        return None
    return Source("hardening", doc["facts"], _epoch(doc, "read_at_epoch"), str(doc.get("via") or ""),
                  bool(doc["facts"].get("complete")), dict(doc["facts"].get("gaps") or {}))


def load(data_dir: Path, target: str, hardening: list[dict[str, Any]] | None = None) -> Facts:
    """Every source for `target`: the saved hardening reads (or `hardening`, given), and
    the newest saved snapshot of each reused read."""
    from kratos.adapters import findings_engine as FE

    data_dir = Path(data_dir)
    facts = Facts(target)
    reads = [hardening_source(d) for d in (hardening if hardening is not None else _saved_hardening(data_dir, target))]
    reads = sorted((r for r in reads if r is not None), key=lambda r: r.read_at or 0, reverse=True)
    if reads:
        facts.sources["hardening"] = reads[0]
        facts.other_hardening = reads[1] if len(reads) > 1 else None
    found = FE.find_latest_inputs(data_dir, target)
    ca = _json(found.get("config_audit"))
    if ca and isinstance(ca.get("checks"), list):
        rows = {str(r.get("check")): r for r in ca["checks"] if isinstance(r, dict)}
        facts.sources["config_audit"] = Source("config_audit", rows, _epoch(ca, "collected_at_epoch", "collected_at"),
                                               str(ca.get("via") or ""))
    pe = _json(found.get("persistence"))
    if pe:
        facts.sources["persistence"] = Source("persistence", pe, _epoch(pe, "checked_at_epoch", "checked_at"),
                                              str(pe.get("via") or ""), bool(pe.get("complete")))
    pk = _json(found.get("packages"))
    if pk:
        facts.sources["packages"] = Source("packages", pk, _epoch(pk, "checked_at_epoch", "checked_at"),
                                           str(pk.get("via") or ""), bool(pk.get("complete")))
    try:
        from kratos.pkgvuln import inventory_store

        inv = inventory_store.latest(data_dir, target)
    except Exception:  # noqa: BLE001 -- a missing store is a missing source, never a crash
        inv = None
    if inv is not None:
        names = sorted({str(p.get("name")) for p in inv.packages if isinstance(p, dict) and p.get("name")})
        facts.sources["inventory"] = Source("inventory", {"names": names, "family": inv.family},
                                            float(inv.last_seen_at), inv.via, bool(names))
    pr = _json(found.get("privileged_accounts"))
    if pr and str(pr.get("status") or "ok") == "ok":
        # evidence_gaps are about account-change HISTORY (a short journal); the account list
        # itself (UID 0, sudoers) is read in full whenever the read succeeds.
        facts.sources["privileged"] = Source("privileged", pr, _epoch(pr, "checked_at"), "", True)
    li = _json(found.get("log_integrity"))
    if li:
        facts.sources["log_integrity"] = Source("log_integrity", li, _epoch(li, "checked_at_epoch", "checked_at"),
                                                str(li.get("via") or ""))
    lv = _json(found.get("live_response"))
    if lv:
        facts.sources["live"] = Source("live", lv, _epoch(lv, "checked_at_epoch", "checked_at"),
                                       str(lv.get("via") or ""), bool(lv.get("complete", True)))
    return facts


def _saved_hardening(data_dir: Path, target: str) -> list[dict[str, Any]]:
    from kratos.compliance import record

    out = []
    for p in record.hardening_paths(data_dir, target):
        d = _json(p)
        if d:
            out.append(d)
    return out


def age_hours(src: Source | None, now: float | None = None) -> float | None:
    if src is None or src.read_at is None:
        return None
    return max(0.0, ((time.time() if now is None else now) - src.read_at) / 3600.0)
