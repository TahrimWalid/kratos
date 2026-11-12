"""The vendored ComplianceAsCode CIS mapping (E.2 §3.2, §3.10).

`vendor/cac_cis.json` holds, per product, the CIS section numbers, their levels and the
ComplianceAsCode rule ids -- ids only (scripts/dev/build_compliance_vendor.py). This
module reads it and detects the product from a machine's ``/etc/os-release``. A system
without a ComplianceAsCode product gets no CIS section, said plainly.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

DEFAULT_LEVEL = "l1_server"
LEVELS = ("l1_server", "l2_server")
LEVEL_WORDS = {"l1_server": "Level 1 Server", "l2_server": "Level 2 Server"}
_REBUILDS = {"rocky": "Rocky Linux", "almalinux": "AlmaLinux", "centos": "CentOS Stream", "ol": "Oracle Linux"}


@lru_cache(maxsize=1)
def vendored() -> dict[str, Any]:
    text = resources.files("kratos.compliance").joinpath("vendor/cac_cis.json").read_text(encoding="utf-8")
    return json.loads(text)


def source() -> dict[str, str]:
    return dict(vendored().get("source") or {})


def mapping_version() -> str:
    s = source()
    return f"ComplianceAsCode {str(s.get('commit') or '')[:12]} ({str(s.get('commit_date') or '')[:10]})"


def products() -> list[str]:
    return sorted((vendored().get("products") or {}).keys())


@dataclass(frozen=True)
class Product:
    id: str | None                 # e.g. "ubuntu2404"; None = no CIS mapping
    note: str                      # e.g. "Rocky Linux uses the RHEL 9 mapping"
    benchmark_version: str = ""


def detect(os_facts: dict[str, Any]) -> Product:
    os_id = str(os_facts.get("ID") or "").lower()
    like = str(os_facts.get("ID_LIKE") or "").lower().split()
    version = str(os_facts.get("VERSION_ID") or "")
    major = version.split(".")[0]
    pid, note = None, ""
    if os_id == "ubuntu" and version in ("22.04", "24.04"):
        pid = "ubuntu" + version.replace(".", "")
    elif os_id == "debian" and major in ("12", "13"):
        pid = "debian" + major
    elif os_id == "rhel" and major in ("8", "9", "10"):
        pid = "rhel" + major
    elif (os_id in _REBUILDS or "rhel" in like) and major in ("8", "9", "10"):
        pid = "rhel" + major
        note = f"{_REBUILDS.get(os_id, os_id or 'This system')} uses the RHEL {major} mapping"
    prods = vendored().get("products") or {}
    if pid is None or pid not in prods:
        name = str(os_facts.get("PRETTY_NAME") or os_id or "this system")
        return Product(None, f"no CIS mapping for this system ({name}): ComplianceAsCode has no CIS control file "
                             "for it")
    return Product(pid, note, str(prods[pid].get("benchmark_version") or ""))


def _levels_of(product: str, level: str) -> set[str]:
    """`level` plus every level it inherits from."""
    lv = (vendored()["products"][product].get("levels") or {})
    out, todo = set(), [level]
    while todo:
        x = todo.pop()
        if x in out:
            continue
        out.add(x)
        todo += list(lv.get(x) or [])
    return out


def controls(product: str, level: str = DEFAULT_LEVEL) -> list[dict[str, Any]]:
    """The product's CIS sections in `level` (with what it inherits), in section order."""
    want = _levels_of(product, level)
    return [c for c in vendored()["products"][product]["controls"] if set(c.get("levels") or []) & want]


def all_rule_ids() -> set[str]:
    out: set[str] = set()
    for p in (vendored().get("products") or {}).values():
        for c in p.get("controls") or []:
            out.update(c.get("rules") or [])
    return out


def sections_for_rule(product: str, rule: str, level: str = DEFAULT_LEVEL) -> list[str]:
    return [c["id"] for c in controls(product, level) if rule in (c.get("rules") or [])]
