#!/usr/bin/env python3
"""Build Kratos's shipped Sigma rule pack from a pinned SigmaHQ checkout.

    python scripts/dev/build_sigma_pack.py <sigmahq-checkout> --pack-version N --drl <LICENSE.Detection.Rules.md>

<sigmahq-checkout> is a git checkout of https://github.com/SigmaHQ/sigma at the
commit to pin (its HEAD is recorded in the pack). The DRL text comes from
https://github.com/SigmaHQ/Detection-Rule-License. Needs pySigma (`pip install
'.[sigma]'`); Kratos itself never does at run time.

Every rule under rules/linux/ is compiled with the Kratos pipeline and backend
(kratos.detect.sigma_build); the ones that compile faithfully and pass the
selection policy (compile.not_shipped_reason) are shipped, each with a matching
and a non-matching sample proposed mechanically and checked by the evaluator;
every other rule is listed in the pack's `skipped` with its reason. It writes,
under src/kratos/detect/packs/ (package data):

    sigma-linux-<N>.json   the pack (deterministic: the same inputs give the same bytes)
    sigma/rules/linux/...  the shipped rules' source files, unmodified
    LICENSE.DRL            the Detection Rule License 1.1 text
    NOTICE                 where the rules come from, and every shipped rule's author

Remove the previous pack file yourself (git rm) when the version changes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from kratos.detect.sigma_build.compile import (  # noqa: E402
    SHIP_MIN_LEVEL, SHIP_STATUSES, Source, build_pack, compile_sources, select_for_shipping)
from kratos.detect.sigma_build.pipeline import PIPELINE_NAME  # noqa: E402
from kratos.detect.sigma_build.samples import add_samples  # noqa: E402

PACKS = REPO / "src" / "kratos" / "detect" / "packs"
PACK_ID = "sigma-linux"
UPSTREAM = "https://github.com/SigmaHQ/sigma"
DRL_URL = "https://github.com/SigmaHQ/Detection-Rule-License"


def _git(checkout: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(checkout), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def notice_text(pack: dict) -> str:
    src = pack["source"]
    lines = [
        "Kratos detection rules -- notice",
        "",
        f"The rules in {PACK_ID}-{pack['pack_version']}.json are compiled from the SigmaHQ project",
        f"({UPSTREAM}), commit {src['commit']} ({src['commit_date']}).",
        "They are released under the Detection Rule License (DRL) 1.1 -- full text in LICENSE.DRL",
        f"next to this file, and at {DRL_URL}. The source file of every shipped rule is in",
        "sigma/ next to this file, unmodified. Kratos compiled each into its own closed rule format",
        f"(pySigma {src['pysigma']}, pipeline \"{src['pipeline']}\"); a finding, an alert or a report entry",
        "raised by a rule names the rule's author, as the licence asks.",
        "",
        "Shipped rules (Kratos id -- title -- author -- source):",
        "",
    ]
    for r in pack["rules"]:
        lines.append(f"{r['id']} -- {r['title']} -- {r['author']} -- {r['source']['url']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("checkout", type=Path)
    ap.add_argument("--pack-version", type=int, required=True)
    ap.add_argument("--drl", type=Path, required=True, help="LICENSE.Detection.Rules.md from the DRL repository")
    ap.add_argument("--out", type=Path, default=PACKS)
    args = ap.parse_args(argv)

    checkout = args.checkout.resolve()
    commit = _git(checkout, "rev-parse", "HEAD")
    commit_date = _git(checkout, "log", "-1", "--format=%cI")
    drl = args.drl.read_text(encoding="utf-8")
    if not drl.startswith("# Detection Rule License (DRL) 1.1"):
        raise SystemExit(f"{args.drl}: not the Detection Rule License 1.1 text")
    paths = sorted((checkout / "rules" / "linux").rglob("*.yml"))
    if not paths:
        raise SystemExit(f"{checkout}: no rules/linux/*.yml -- is this a SigmaHQ checkout?")
    sources = []
    for p in paths:
        rel = p.relative_to(checkout).as_posix()
        sources.append(Source(path=rel, text=p.read_text(encoding="utf-8"), commit=commit,
                              url=f"{UPSTREAM}/blob/{commit}/{rel}"))
    compiled = compile_sources(sources)
    ship, left = select_for_shipping(compiled)
    for rule in ship:
        why = add_samples(rule)
        if why:
            raise SystemExit(f"{rule['id']} ({rule['source']['path']}): {why}")
    source = {
        "repository": UPSTREAM, "commit": commit, "commit_date": commit_date, "path": "rules/linux",
        "license": "DRL-1.1", "license_url": DRL_URL,
        "license_sha256": hashlib.sha256(drl.encode("utf-8")).hexdigest(),
        "pysigma": metadata.version("pysigma"), "pipeline": PIPELINE_NAME,
        "selection": {"statuses": list(SHIP_STATUSES), "min_level": SHIP_MIN_LEVEL,
                      "rule": "compiles faithfully; not ESXi tooling; level medium or above; a medium rule "
                              "is not only discovery/reconnaissance"},
        "candidates": len(paths), "attack_dropped": compiled.attack_dropped,
    }
    pack = build_pack(ship, compiled.skipped + left, pack_id=PACK_ID, pack_version=args.pack_version,
                      source=source, notice=f"Rules by their authors (see each rule), DRL 1.1: {DRL_URL}")

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{PACK_ID}-{args.pack_version}.json").write_text(
        json.dumps(pack, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    vendored = out / "sigma"
    if vendored.exists():
        shutil.rmtree(vendored)
    for rule in pack["rules"]:
        rel = rule["source"]["path"]
        dest = vendored / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(checkout / rel, dest)
    (out / "LICENSE.DRL").write_text(drl if drl.endswith("\n") else drl + "\n", encoding="utf-8")
    (out / "NOTICE").write_text(notice_text(pack), encoding="utf-8")
    by_kind: dict[str, int] = {}
    for s in pack["skipped"]:
        by_kind[s["kind"]] = by_kind.get(s["kind"], 0) + 1
    print(f"{len(paths)} candidate files, {len(pack['rules'])} rules shipped, {len(pack['skipped'])} not shipped "
          f"({', '.join(f'{k} {v}' for k, v in sorted(by_kind.items()))}); pack sha256 {pack['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
