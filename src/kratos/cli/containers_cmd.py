"""`kratos containers`: the containers on a machine, from its newest container read (D.5).

    kratos containers [--machine M] [--refresh] [--json]

The table shows each container's name, image (short id), user, published ports -- with
"reachable despite firewall" marks -- and its risky settings; stopped containers are
listed after the running ones. `--refresh` reads the machine now (through its sub-agent
when it has one, else over SSH as the SSH login). Read-only: nothing is changed on the
machine.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from kratos.untrusted import safe_print as print

RISK_WORDS = {"CONT-001": "privileged", "CONT-002": "engine socket", "CONT-003": "host namespace",
              "CONT-004": "reachable despite firewall", "CONT-005": "writable host folders",
              "CONT-006": "powerful capabilities", "CONT-007": "confinement off"}


def add_parser(sub: Any) -> None:
    p = sub.add_parser("containers", help="Docker / Podman containers on a machine: risky settings, ports reachable "
                                          "despite the firewall (read-only, never the docker group)")
    p.add_argument("--machine", default=None, help="Which machine (default: the active target)")
    p.add_argument("--refresh", action="store_true", help="Read the machine now instead of showing the newest read")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_containers)


def table_lines(doc: dict[str, Any]) -> list[str]:
    from kratos.containers import record

    out = [f"{doc.get('target')}: {record.summary_line(doc)}  (read {doc.get('checked_at')} via {doc.get('via')})"]
    if not doc.get("engines_found"):
        return out
    for r in doc.get("rows") or []:
        state = "" if r.get("running") else f"  [{r.get('state') or 'stopped'}]"
        risks = ", ".join(RISK_WORDS.get(x, x) for x in r.get("risks") or []) or "-"
        comp = r.get("compose") or {}
        where = f"  compose {comp.get('project')}/{comp.get('service')}" if comp else ""
        out.append(f"  {r.get('name')}{state}  image {r.get('image') or '?'} ({r.get('digest') or '-'})  "
                   f"user {r.get('user') or '?'}{where}")
        for port in r.get("ports") or []:
            out.append(f"      {port}")
        out.append(f"      risks: {risks}")
    for g in doc.get("coverage_gaps") or []:
        out.append(f"  not checked: {g}")
    return out


def cmd_containers(args: argparse.Namespace) -> int:
    from kratos import kratos_config
    from kratos.containers import record

    data_dir = Path(args.data_dir)
    machine = args.machine or kratos_config.get_active_target()
    if not machine:
        print("No machine: pass --machine or set a target first.")
        return 2
    if args.refresh:
        doc = record.run(data_dir, machine)
        if doc.get("status") != "ok":
            print(f"Could not read {machine}: {doc.get('observation')}")
            return 1
    else:
        doc = record.load(data_dir, machine)
        if doc is None:
            print(f"Kratos has no container read of {machine} yet -- run `kratos containers --refresh` "
                  "(or `kratos collect`).")
            return 1
    if args.json:
        print(json.dumps({k: doc.get(k) for k in ("target", "checked_at", "via", "engines_found", "engines",
                                                  "firewall_backend", "counts", "rows", "port_checks",
                                                  "coverage_gaps")}, indent=2, default=str))
        return 0
    for line in table_lines(doc):
        print(line)
    return 0
