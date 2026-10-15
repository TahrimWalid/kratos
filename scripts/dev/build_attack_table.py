#!/usr/bin/env python3
"""Build Kratos's pinned MITRE ATT&CK table from an official STIX bundle.

    python scripts/dev/build_attack_table.py enterprise-attack-19.2.json [--url URL]

The bundle comes from https://github.com/mitre-attack/attack-stix-data
(`enterprise-attack/enterprise-attack-<version>.json`). A developer downloads it
once; Kratos never fetches it at runtime. The full bundle is ~50 MB; the table
this writes (src/kratos/attack/v19_table.json, package data) keeps only what
Kratos needs to label findings and draw a Navigator layer: for every Enterprise
technique and sub-technique its id, name, tactics, platforms, url and
revoked/deprecated flags (plus what replaced a revoked one), and every tactic in matrix order.

The output is deterministic: the same bundle gives the same bytes (sorted keys,
no timestamps of its own), so a re-run proves the shipped table is unedited.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

DEFAULT_OUT = Path(__file__).resolve().parents[2] / "src" / "kratos" / "attack" / "v19_table.json"
EXPECTED_MAJOR = "19"
NOTICE = ("(c) The MITRE Corporation. This work is reproduced and distributed with the permission of "
          "The MITRE Corporation. Derived from the official Enterprise ATT&CK STIX bundle "
          "(https://github.com/mitre-attack/attack-stix-data); used to label Kratos findings and "
          "draw ATT&CK Navigator layers.")


def _attack_id(obj: dict) -> tuple[str, str] | None:
    for ref in obj.get("external_references") or ():
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]), str(ref.get("url") or "")
    return None


def build(bundle: dict, *, sha256: str, url: str) -> dict:
    objects = bundle.get("objects") or []
    collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
    if len(collections) != 1:
        raise SystemExit("not an ATT&CK bundle: expected exactly one x-mitre-collection")
    collection = collections[0]
    version = str(collection.get("x_mitre_version") or "")
    if version.split(".")[0] != EXPECTED_MAJOR:
        raise SystemExit(f"expected ATT&CK v{EXPECTED_MAJOR}.x, this bundle is v{version}")

    by_stix = {o["id"]: o for o in objects if "id" in o}

    # Tactics, in the order the Enterprise matrix lists them (Navigator's columns).
    matrices = [o for o in objects if o.get("type") == "x-mitre-matrix" and not o.get("revoked")]
    if len(matrices) != 1:
        raise SystemExit("expected exactly one Enterprise matrix")
    tactics: dict[str, dict] = {}
    for order, ref in enumerate(matrices[0].get("tactic_refs") or ()):
        tac = by_stix[ref]
        tid, turl = _attack_id(tac) or ("", "")
        tactics[str(tac["x_mitre_shortname"])] = {"id": tid, "name": str(tac["name"]), "order": order, "url": turl}

    # What replaced a revoked technique ("revoked-by" relationships).
    revoked_by: dict[str, str] = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            src, dst = by_stix.get(o.get("source_ref")), by_stix.get(o.get("target_ref"))
            if src and dst and src.get("type") == "attack-pattern" and dst.get("type") == "attack-pattern":
                a, b = _attack_id(src), _attack_id(dst)
                if a and b:
                    revoked_by[a[0]] = b[0]

    techniques: dict[str, dict] = {}
    for o in objects:
        if o.get("type") != "attack-pattern" or "enterprise-attack" not in (o.get("x_mitre_domains") or ()):
            continue
        ident = _attack_id(o)
        if not ident:
            continue
        tid, turl = ident
        entry = {
            "name": str(o.get("name") or ""),
            "tactics": sorted({str(p["phase_name"]) for p in o.get("kill_chain_phases") or ()
                               if p.get("kill_chain_name") == "mitre-attack"},
                              key=lambda s: tactics.get(s, {}).get("order", 99)),
            "url": turl,
            "platforms": sorted(str(p) for p in o.get("x_mitre_platforms") or ()),
            "revoked": bool(o.get("revoked", False)),
            "deprecated": bool(o.get("x_mitre_deprecated", False)),
            "subtechnique": bool(o.get("x_mitre_is_subtechnique", False)),
        }
        if entry["revoked"] and tid in revoked_by:
            entry["revoked_by"] = revoked_by[tid]
        unknown = set(entry["tactics"]) - set(tactics)
        if unknown:
            raise SystemExit(f"{tid} names a tactic the matrix doesn't have: {sorted(unknown)}")
        prev = techniques.get(tid)
        # The same id can appear on a revoked object and on its live successor;
        # the live one wins.
        if prev is None or (prev["revoked"] or prev["deprecated"]) and not (entry["revoked"] or entry["deprecated"]):
            techniques[tid] = entry

    return {
        "_source": NOTICE,
        "attack_version": version,
        "bundle": {"url": url, "sha256": sha256, "modified": str(collection.get("modified") or ""),
                   "name": str(collection.get("name") or "")},
        "domain": "enterprise-attack",
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
    }


def render(table: dict) -> bytes:
    return (json.dumps(table, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("bundle", type=Path, help="enterprise-attack-19.x.json from mitre-attack/attack-stix-data")
    ap.add_argument("--url", default="", help="where the bundle was downloaded from (recorded in the table)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    raw = args.bundle.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    url = args.url or ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/"
                       + args.bundle.name)
    table = build(json.loads(raw), sha256=sha, url=url)
    args.out.write_bytes(render(table))
    live = sum(1 for t in table["techniques"].values() if not (t["revoked"] or t["deprecated"]))
    print(f"ATT&CK v{table['attack_version']}: {len(table['techniques'])} techniques ({live} current), "
          f"{len(table['tactics'])} tactics -> {args.out} (bundle sha256 {sha})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
