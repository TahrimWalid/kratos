#!/usr/bin/env python3
"""Build Kratos's vendored ComplianceAsCode CIS mapping (E.2 §5.1).

    build_compliance_vendor.py <ComplianceAsCode checkout> --commit <sha> [--check]

Reads the CIS control files of a pinned ComplianceAsCode/content checkout and writes
``src/kratos/compliance/vendor/cac_cis.json`` -- per product: the CIS section NUMBERS,
their levels, the ComplianceAsCode rule ids and variable assignments, and the automation
status. Nothing else: no titles, no notes, no descriptions. The CIS Benchmark texts are
licensed for non-commercial use only and must not ship; ComplianceAsCode's control-file
mapping (ids) is BSD-3-Clause.

Every string written is checked against a closed set of id shapes -- one with a space in
it (every CIS title has one) stops the build. ``--check`` rebuilds in memory and fails if
the vendored file differs (CI). Deterministic: sorted keys, stable order, no dates other
than the commit's own.

Needs PyYAML (a build-time tool only; Kratos itself reads the JSON with the standard library).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "src" / "kratos" / "compliance" / "vendor"
OUT = OUT_DIR / "cac_cis.json"

# product -> control file (relative to the checkout). Rocky / Alma / CentOS Stream use the
# RHEL product (stated in the report); almalinux9's own file is kept for reference only.
PRODUCTS: dict[str, str] = {
    "ubuntu2204": "controls/cis_ubuntu2204.yml",
    "ubuntu2404": "controls/cis_ubuntu2404.yml",
    "debian12": "controls/cis_debian12.yml",
    "debian13": "controls/cis_debian13.yml",
    "rhel8": "products/rhel8/controls/cis_rhel8.yml",
    "rhel9": "products/rhel9/controls/cis_rhel9.yml",
    "rhel10": "products/rhel10/controls/cis_rhel10.yml",
}

SECTION_RE = re.compile(r"^[0-9]{1,2}(\.[0-9]{1,3}){0,5}$")
RULE_RE = re.compile(r"^[a-z0-9][A-Za-z0-9_.-]{0,99}$")
VAR_RE = re.compile(r"^([a-z0-9][a-z0-9_-]{0,79})=([A-Za-z0-9_.:,-]{1,64})$")
LEVEL_RE = re.compile(r"^[lL][12]_(server|workstation)$")
VERSION_RE = re.compile(r"^[0-9]{1,2}(\.[0-9]{1,3}){0,3}$")
STATUSES = frozenset({"automated", "manual", "partial", "pending", "planned", "supported", "not applicable",
                      "inherently met", "unknown"})
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class VendorError(Exception):
    pass


def _str(value, pattern: re.Pattern[str], what: str) -> str:
    s = str(value).strip()
    if not pattern.fullmatch(s):
        raise VendorError(f"{what} {s[:60]!r} is not an id-shaped string -- refusing (no CIS text may ship)")
    return s


def _controls(raw: list, product: str) -> list[dict]:
    out: list[dict] = []

    def walk(items: list) -> None:
        for c in items or []:
            if not isinstance(c, dict):
                raise VendorError(f"{product}: a control is not a mapping")
            raw_id = str(c.get("id") or "").strip()
            if not SECTION_RE.fullmatch(raw_id) and RULE_RE.fullmatch(raw_id):
                # a helper entry (e.g. rhel8's "reload_dconf_db"), not a CIS section: not vendored
                walk(c.get("controls") or [])
                continue
            sid = _str(raw_id, SECTION_RE, f"{product} section")
            levels = sorted({_str(lv, LEVEL_RE, f"{product} {sid} level").lower() for lv in c.get("levels") or []})
            rules: list[str] = []
            variables: dict[str, str] = {}
            for r in c.get("rules") or []:
                m = VAR_RE.fullmatch(str(r).strip())
                if m:
                    variables[m.group(1)] = m.group(2)
                else:
                    rules.append(_str(r, RULE_RE, f"{product} {sid} rule"))
            status = str(c.get("status") or "unknown").strip().lower()
            if status not in STATUSES:
                raise VendorError(f"{product} {sid}: unknown status {status[:40]!r}")
            out.append({"id": sid, "levels": levels, "rules": sorted(set(rules)),
                        "vars": dict(sorted(variables.items())), "status": status})
            walk(c.get("controls") or [])

    walk(raw)
    seen: set[str] = set()
    for c in out:
        if c["id"] in seen:
            raise VendorError(f"{product}: section {c['id']} appears twice")
        seen.add(c["id"])

    def key(c: dict) -> tuple:
        return tuple(int(x) for x in c["id"].split("."))

    return sorted(out, key=key)


def build(checkout: Path, commit: str) -> dict:
    import yaml  # build-time only

    if not SHA_RE.fullmatch(commit):
        raise VendorError("--commit must be a full 40-character commit id")
    head = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    if head != commit:
        raise VendorError(f"the checkout is at {head}, not the pinned {commit}")
    date = subprocess.run(["git", "-C", str(checkout), "log", "-1", "--format=%cI", commit], capture_output=True,
                          text=True, check=True).stdout.strip()
    lic = (checkout / "LICENSE").read_text(encoding="utf-8", errors="replace")
    if "BSD-3-Clause" not in lic:
        raise VendorError("ComplianceAsCode's LICENSE no longer says BSD-3-Clause -- re-check before vendoring")
    products: dict[str, dict] = {}
    for product, rel in PRODUCTS.items():
        doc = yaml.safe_load((checkout / rel).read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or str(doc.get("product")) != product:
            raise VendorError(f"{rel}: not the {product} control file")
        levels: dict[str, list[str]] = {}
        for lv in doc.get("levels") or []:
            lid = _str(lv.get("id"), LEVEL_RE, f"{product} level").lower()
            levels[lid] = sorted(_str(p, LEVEL_RE, f"{product} level parent").lower()
                                 for p in lv.get("inherits_from") or [])
        products[product] = {
            "policy_id": _str(doc.get("id"), RULE_RE, f"{product} policy id"),
            "benchmark_version": _str(doc.get("version"), VERSION_RE, f"{product} benchmark version"),
            "levels": dict(sorted(levels.items())),
            "controls": _controls(doc.get("controls") or [], product),
        }
    return {"format": 1, "source": {"repository": "https://github.com/ComplianceAsCode/content", "commit": commit,
                                    "commit_date": date, "licence": "BSD-3-Clause"},
            "products": products}


def assert_ids_only(obj, path: str = "$") -> None:
    """Every string in the vendored file is a short id: no spaces outside the closed
    status words and the fixed source fields, nothing over 100 characters."""
    allowed_spaced = STATUSES | {"https://github.com/ComplianceAsCode/content"}
    if isinstance(obj, dict):
        for k, v in obj.items():
            assert_ids_only(k, f"{path}.{k}")
            assert_ids_only(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            assert_ids_only(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        if len(obj) > 100 or (" " in obj and obj not in allowed_spaced):
            raise VendorError(f"{path}: {obj[:60]!r} is not an id -- refusing (no CIS text may ship)")


def render(doc: dict) -> str:
    assert_ids_only(doc)
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


SOURCE_TEMPLATE = """ComplianceAsCode CIS control mapping vendored by Kratos (E.2)

Repository: https://github.com/ComplianceAsCode/content
Tag:        {tag}
Commit:     {commit}
Committed:  {date}
Licence:    BSD-3-Clause (see LICENSE.ComplianceAsCode beside this file)

What is vendored (cac_cis.json): for each product below, the CIS section numbers, their
levels, the ComplianceAsCode rule ids and variable assignments, and the automation status
-- from the product's CIS control file. Nothing else. The CIS Benchmark texts (titles,
descriptions, rationale, audit and remediation text) are licensed by the Center for
Internet Security for non-commercial use only (CC BY-NC-SA) and are NOT shipped; the
titles in Kratos's reports are Kratos's own descriptions of what its checks test.

Products and CIS benchmark versions (as named in each control file):
{products}

Kratos never runs ComplianceAsCode's OVAL or Bash content. A CIS section Kratos has no
check for is reported as "not checked by Kratos" with its ComplianceAsCode rule ids, so a
person can run OpenSCAP with the same content themselves.

Rebuild: scripts/dev/build_compliance_vendor.py <checkout at the commit above> --commit {commit}
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("checkout", type=Path)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--tag", default="")
    ap.add_argument("--check", action="store_true", help="fail if the vendored files differ from a fresh build")
    a = ap.parse_args(argv)
    try:
        doc = build(a.checkout, a.commit)
    except VendorError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    text = render(doc)
    lines = "\n".join(f"  {p:<11} CIS benchmark {d['benchmark_version']} ({d['policy_id']}, "
                      f"{len(d['controls'])} sections)" for p, d in doc["products"].items())
    source = SOURCE_TEMPLATE.format(tag=a.tag or "(none)", commit=a.commit, date=doc["source"]["commit_date"],
                                    products=lines)
    licence = (a.checkout / "LICENSE").read_text(encoding="utf-8")
    want = {OUT: text, OUT_DIR / "SOURCE.txt": source, OUT_DIR / "LICENSE.ComplianceAsCode": licence}
    if a.check:
        bad = [str(p.relative_to(ROOT)) for p, t in want.items() if not p.exists() or p.read_text() != t]
        if bad:
            print("vendored ComplianceAsCode files differ from a fresh build: " + ", ".join(bad), file=sys.stderr)
            return 1
        print("vendored ComplianceAsCode files match the pinned commit")
        return 0
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for p, t in want.items():
        p.write_text(t, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
