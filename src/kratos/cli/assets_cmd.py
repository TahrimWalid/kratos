"""`kratos assets`: what you say about each machine (D.3 asset record).

    kratos assets list [--json]
    kratos assets set <MACHINE> [--criticality low|medium|high|critical|unset]
                                [--wellbeing minimal|material|irreversible]
                                [--exposure internet|private|unset]
                                [--role TEXT] [--groups A,B] [--owner-note TEXT]
    kratos assets history <MACHINE>

Criticality feeds CISA's SSVC tree (Mission & Well-being); exposure "internet" / "private"
tells Kratos what it can't measure (whether the machine is reachable from the internet).
Every change is recorded with who made it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from kratos.untrusted import safe_print as print


def add_parser(sub: Any) -> None:
    p = sub.add_parser("assets", help="The machines Kratos knows: how much each matters (criticality, used to rank "
                                      "vulnerabilities), whether it's reachable from the internet, groups, owner")
    asub = p.add_subparsers(dest="assets_action", required=True)
    ls = asub.add_parser("list", help="Every machine: criticality, exposure, groups, role, owner note")
    ls.add_argument("--json", action="store_true")
    st = asub.add_parser("set", help="Change what you say about a machine (recorded with your name)")
    st.add_argument("machine")
    st.add_argument("--criticality", choices=("low", "medium", "high", "critical", "unset"),
                    help="How much the machine matters (unset: Kratos assumes medium and says so)")
    st.add_argument("--wellbeing", choices=("minimal", "material", "irreversible"),
                    help="How badly a compromise could hurt people outside your organisation (default minimal)")
    st.add_argument("--exposure", choices=("internet", "private", "unset"),
                    help="internet: it is reachable from the internet; private: it isn't; unset: Kratos's "
                         "measurement only")
    st.add_argument("--role", default=None, help="A label for you (web, db, build ...); never sent to the model")
    st.add_argument("--groups", default=None, help="Comma-separated group names")
    st.add_argument("--owner-note", default=None, help="Who to call; never sent to the model")
    h = asub.add_parser("history", help="Every change to a machine's record, newest first")
    h.add_argument("machine")
    p.set_defaults(func=cmd_assets)


def _measured(data_dir: Path, target: str) -> str:
    """The machine's most exposed point from its newest running-process read."""
    from kratos.adapters.findings_engine import _load_recent_live, find_latest_inputs
    from kratos.ssvc.exposure import machine_highest

    try:
        live = _load_recent_live(find_latest_inputs(data_dir, target=target).get("live_response"))
    except Exception:  # noqa: BLE001
        live = None
    if live is None:
        return "not measured"
    return machine_highest(live).value


def _rows(data_dir: Path) -> list[dict[str, Any]]:
    from kratos.assets import store
    from kratos.kratos_config import get_active_target

    out = []
    for a in store.known_machines(data_dir, configured=get_active_target()):
        d = a.to_dict()
        d["measured_exposure"] = _measured(data_dir, a.target)
        d["seen_in"] = list(a.seen_in)
        out.append(d)
    return out


def cmd_assets(args: argparse.Namespace) -> int:
    from kratos.assets import store
    from kratos.lifecycle.decide import Actor

    data_dir = Path(args.data_dir)
    if args.assets_action == "list":
        rows = _rows(data_dir)
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
            return 0
        if not rows:
            print("[KRATOS] Kratos doesn't know any machine yet.")
            return 0
        print(f"{'MACHINE':<28} {'CRITICALITY':<22} {'EXPOSURE':<26} {'GROUPS':<16} ROLE / OWNER")
        for r in rows:
            crit = (r["criticality"] or "not set (assumed medium)") if r["set_up"] else "not set up"
            if r["set_up"] and r["wellbeing"] != "minimal":
                crit += f", well-being {r['wellbeing']}"
            exp = r["measured_exposure"] + (f" (you: {r['exposure_override']})" if r["exposure_override"] else "")
            who = " / ".join(x for x in (r["role"], r["owner_note"]) if x)
            print(f"{r['target'][:28]:<28} {crit[:22]:<22} {exp[:26]:<26} {', '.join(r['groups'])[:16]:<16} {who}")
        if any(not r["set_up"] for r in rows):
            print("\n[KRATOS] 'not set up': Kratos holds data for it, nobody has said how much it matters yet. "
                  "Set it with: kratos assets set <MACHINE> --criticality high")
        return 0
    if args.assets_action == "history":
        events = store.events(data_dir, args.machine)
        if not events:
            print(f"[KRATOS] No changes recorded for {args.machine}.")
            return 0
        from kratos.utils.timeutil import epoch_to_utc_iso

        for e in events:
            what = "asked how much it matters" if e["field"] == "asked" else \
                f"{e['field']}: {e['old_value'] or '(unset)'} -> {e['new_value'] or '(unset)'}"
            print(f"{epoch_to_utc_iso(e['at'])}  {e['actor']} ({e['interface']})  {what}")
        return 0
    changes: dict[str, Any] = {}
    for flag, field in (("criticality", "criticality"), ("wellbeing", "wellbeing"), ("exposure", "exposure_override"),
                        ("role", "role"), ("groups", "groups"), ("owner_note", "owner_note")):
        value = getattr(args, flag, None)
        if value is not None:
            changes[field] = value
    if not changes:
        print("[KRATOS] Nothing to change: give --criticality, --wellbeing, --exposure, --role, --groups or "
              "--owner-note.")
        return 1
    try:
        a = store.update(data_dir, args.machine, Actor.current("cli"), **changes)
    except store.AssetError as e:
        print(f"[KRATOS] Not changed: {e}")
        return 1
    print(f"[KRATOS] {a.target}: criticality {a.criticality or 'not set (assumed medium)'}, public well-being "
          f"impact {a.wellbeing}, exposure {a.exposure_override or 'as measured'}"
          + (f", groups {', '.join(a.groups)}" if a.groups else "") + f" -- recorded as {a.updated_by}.")
    print("[KRATOS] Vulnerability decisions use this from the next report on (`kratos findings`).")
    return 0
