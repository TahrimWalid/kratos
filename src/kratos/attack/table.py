"""The pinned MITRE ATT&CK table (v19.x), and labels built from it.

`v19_table.json` is generated from MITRE's official Enterprise STIX bundle by
`scripts/dev/build_attack_table.py` (never fetched at runtime, never edited by
hand). Every technique name, tactic and url Kratos shows comes from it, so a
label can't drift from the official data: `label()` refuses an id the table
doesn't have, a revoked or deprecated one, or a tactic the technique isn't
listed under.
"""
from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

_TABLE_FILE = "v19_table.json"


@lru_cache(maxsize=1)
def table() -> dict[str, Any]:
    return json.loads(resources.files("kratos.attack").joinpath(_TABLE_FILE).read_text(encoding="utf-8"))


def attack_version() -> str:
    """'19.2' -- the exact release the table was built from."""
    return str(table()["attack_version"])


def major_version() -> str:
    """'19' -- what a Navigator layer names (versions.attack)."""
    return attack_version().split(".")[0]


def technique(tid: str) -> dict[str, Any] | None:
    """The table entry for a technique id (any state), or None."""
    entry = table()["techniques"].get(str(tid or "").strip().upper())
    return dict(entry, id=str(tid).strip().upper()) if entry else None


def tactic(shortname: str) -> dict[str, Any] | None:
    entry = table()["tactics"].get(shortname)
    return dict(entry, shortname=shortname) if entry else None


def tactic_by_name(name: str) -> dict[str, Any] | None:
    for short, entry in table()["tactics"].items():
        if entry["name"] == name:
            return dict(entry, shortname=short)
    return None


def is_current(tid: str) -> bool:
    t = technique(tid)
    return bool(t) and not t["revoked"] and not t["deprecated"]


class LabelError(ValueError):
    """A mapping names a technique or tactic the pinned table doesn't allow."""


def label(tid: str, *tactics: str) -> dict[str, Any]:
    """One finding label for technique `tid`, under the given tactic shortnames
    (default: every tactic the technique is listed under), in the shape findings
    carry: {technique_id, technique, tactic_id, tactic, tactics, version, url}.
    `tactic_id`/`tactic` are the first (the main one); `tactics` lists all."""
    t = technique(tid)
    if t is None:
        raise LabelError(f"{tid} is not in ATT&CK v{attack_version()}")
    if t["revoked"] or t["deprecated"]:
        repl = f" (replaced by {t['revoked_by']})" if t.get("revoked_by") else ""
        raise LabelError(f"{tid} is {'revoked' if t['revoked'] else 'deprecated'} in ATT&CK v{attack_version()}{repl}")
    chosen = list(tactics) or list(t["tactics"])
    bad = [s for s in chosen if s not in t["tactics"]]
    if bad:
        raise LabelError(f"{tid} ({t['name']}) is not listed under {bad}; it is under {t['tactics']}")
    tacs = [{"id": table()["tactics"][s]["id"], "name": table()["tactics"][s]["name"], "shortname": s} for s in chosen]
    return {"technique_id": t["id"], "technique": t["name"], "tactic_id": tacs[0]["id"], "tactic": tacs[0]["name"],
            "tactics": tacs, "version": attack_version(), "url": t["url"]}
