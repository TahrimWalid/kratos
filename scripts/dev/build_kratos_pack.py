"""Build Kratos's own detection rule pack (kratos-linux): rules for the intrusion signs a
plain Linux machine logs without auditd -- SSH and sudo abuse, accounts created or given
privileged group membership. Same format, validator and evaluator as the Sigma pack
(kratos.subagent.detect), so the agent runs them live and Kratos runs them on schedule.

    python scripts/dev/build_kratos_pack.py [--check]

Writes src/kratos/detect/packs/kratos-linux-<PACK_VERSION>.json (deterministic: building
twice gives the same bytes). --check only verifies the committed file is current.
Phase C audit: the shipped Sigma pack has no counting rules and nothing for these
journal lines, so continuous watching was silent on the commonest intrusion signs.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from kratos.subagent import detect as D  # noqa: E402

PACK_ID = "kratos-linux"
PACK_VERSION = 1
OUT = ROOT / "src" / "kratos" / "detect" / "packs" / f"{PACK_ID}-{PACK_VERSION}.json"
DATE = "2026-10-26"
AUTH = ["kratos.auth"]

# Groups whose members can become root (the same idea as the privileged-accounts check).
PRIVILEGED_GROUPS = ["sudo", "wheel", "admin", "root", "docker", "lxd", "incus-admin", "libvirt", "disk", "shadow"]


def leaf(op: str, field: str, value: object, **kw: object) -> dict:
    key = "values" if op in ("in", "cidr") else ("pattern" if op == "wildcard" else "value")
    return {"op": op, "field": field, key: value, **kw}


def all_of(*args: dict) -> dict:
    return {"op": "all_of", "args": list(args)}


def any_of(*args: dict) -> dict:
    return {"op": "any_of", "args": list(args)}


def ev(i: str, **fields: object) -> dict:
    return {"event.dataset": "kratos.auth", "event.id": f"kratos-sample-{i}", **fields}


def rule(rid: str, title: str, level: str, description: str, match: dict, *, attack: list[str],
         tactics: list[str], samples: dict, count: dict | None = None, falsepositives: list[str]) -> dict:
    return {
        "id": rid, "title": title, "level": level, "author": "Kratos", "license": "MIT", "status": "stable",
        "description": description, "date": DATE, "modified": DATE,
        "source": {"path": f"src/kratos/detect/packs/{PACK_ID}-{PACK_VERSION}.json",
                   "builder": "scripts/dev/build_kratos_pack.py"},
        "tags": [f"attack.{t}" for t in tactics] + [f"attack.{a.lower()}" for a in attack],
        "attack": attack, "references": [], "falsepositives": falsepositives,
        "logsource": {"product": "linux", "service": "auth", "category": None},
        "scope": {"datasets": AUTH, "where": None},
        "match": match, "count": count, "samples": samples,
    }


UID_1000_UP = any_of(*(leaf("wildcard", "user.id", "?" * n) for n in range(4, 11)))   # 1000 and up: people

RULES = [
    rule("KRATOS-SSH-BRUTEFORCE", "SSH brute force from one address", "medium",
         "Ten or more failed SSH logins from the same address within five minutes. On a machine reachable "
         "from the internet this is constant background scanning; it matters most when the address later "
         "logs in, or when the machine is not meant to be reachable.",
         all_of(leaf("eq", "event.action", "ssh_failed_login", cased=True), leaf("exists", "source.ip", True)),
         count={"window_seconds": 300, "group_by": "source.ip", "op": "gte", "threshold": 10},
         attack=["T1110.001"], tactics=["credential-access"],
         falsepositives=["Internet-wide scanners on a public SSH port", "A person repeatedly mistyping a password"],
         samples={"match": [ev("bf-1", **{"event.action": "ssh_failed_login", "source.ip": "203.0.113.9",
                                          "user.name": "admin"})],
                  "no_match": [ev("bf-0", **{"event.action": "ssh_success_login", "source.ip": "203.0.113.9",
                                             "user.name": "admin"})]}),
    rule("KRATOS-SSH-ROOT-LOGIN", "Root logged in over SSH", "medium",
         "A successful SSH login straight to the root account. Many hardening guides disable this "
         "(PermitRootLogin no); where it is allowed on purpose, this is routine.",
         # The message is part of the rule so a live match carries the "Accepted ..." line: Kratos
         # recognises its own key's fingerprint in it and sets its own logins aside (detect/own.py).
         all_of(leaf("eq", "event.action", "ssh_success_login", cased=True), leaf("eq", "user.name", "root", cased=True),
                leaf("startswith", "message", "Accepted ")),
         attack=["T1078.003"], tactics=["initial-access"],
         falsepositives=["Administrators who log in as root by design"],
         samples={"match": [ev("rl-1", **{"event.action": "ssh_success_login", "user.name": "root",
                                          "source.ip": "198.51.100.7",
                                          "message": "Accepted publickey for root from 198.51.100.7 port 50022 ssh2"})],
                  "no_match": [ev("rl-0", **{"event.action": "ssh_success_login", "user.name": "alice",
                                             "source.ip": "198.51.100.7"})]}),
    rule("KRATOS-SUDO-NOT-IN-SUDOERS", "sudo refused: user not in sudoers", "medium",
         "Someone without sudo rights tried to run a command as root -- a mistake, or an intruder in an "
         "ordinary account probing for privileges.",
         all_of(leaf("eq", "event.provider", "sudo", cased=True), leaf("contains", "message", "user NOT in sudoers")),
         attack=["T1548.003"], tactics=["privilege-escalation"],
         falsepositives=["A user who forgot they are not an administrator"],
         samples={"match": [ev("ns-1", **{"event.provider": "sudo", "event.action": "sudo_other",
                                          "message": "bob : user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"})],
                  "no_match": [ev("ns-0", **{"event.provider": "sudo", "event.action": "sudo_command",
                                             "message": "bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls"})]}),
    rule("KRATOS-SUDO-PASSWORD-BURST", "Repeated wrong sudo passwords", "medium",
         "Three or more failed sudo password attempts by the same account within ten minutes.",
         leaf("in", "event.action", ["sudo_auth_failure", "sudo_pam_auth_failure"], cased=True),
         count={"window_seconds": 600, "group_by": "user.name", "op": "gte", "threshold": 3},
         attack=["T1110.001"], tactics=["credential-access"],
         falsepositives=["A person mistyping their own password"],
         samples={"match": [ev("sp-1", **{"event.action": "sudo_auth_failure", "user.name": "bob"})],
                  "no_match": [ev("sp-0", **{"event.action": "sudo_command", "user.name": "bob"})]}),
    rule("KRATOS-ACCOUNT-CREATED", "New login account created", "medium",
         "A new account with a user id of 1000 or more (a person's account, not a system service account) "
         "was created.",
         all_of(leaf("eq", "event.action", "account_created", cased=True), UID_1000_UP),
         attack=["T1136.001"], tactics=["persistence"],
         falsepositives=["An administrator adding a colleague"],
         samples={"match": [ev("ac-1", **{"event.action": "account_created", "user.name": "carol", "user.id": "1002"})],
                  "no_match": [ev("ac-0", **{"event.action": "account_created", "user.name": "_apt", "user.id": "105"})]}),
    rule("KRATOS-ACCOUNT-PRIVILEGED-GROUP", "Account added to a privileged group", "high",
         "An account was added to a group whose members can become root (sudo, wheel, admin, docker, lxd, "
         "libvirt, disk, shadow ...). Attackers do this to keep root access.",
         all_of(leaf("eq", "event.action", "account_added_to_group", cased=True),
                leaf("in", "group.name", PRIVILEGED_GROUPS, cased=True)),
         attack=["T1098"], tactics=["persistence", "privilege-escalation"],
         falsepositives=["An administrator granting admin rights on purpose"],
         samples={"match": [ev("pg-1", **{"event.action": "account_added_to_group", "user.name": "carol",
                                          "group.name": "sudo"})],
                  "no_match": [ev("pg-0", **{"event.action": "account_added_to_group", "user.name": "carol",
                                             "group.name": "audio"})]}),
    rule("KRATOS-ACCOUNT-UID0", "Account with user id 0 (root powers)", "critical",
         "An account was created with, or changed to, user id 0 -- a second root account, a classic backdoor.",
         all_of(leaf("in", "event.action", ["account_created", "account_changed"], cased=True),
                leaf("eq", "user.id", "0", cased=True)),
         attack=["T1136.001"], tactics=["persistence"],
         falsepositives=["Almost never legitimate"],
         samples={"match": [ev("u0-1", **{"event.action": "account_created", "user.name": "toor", "user.id": "0"})],
                  "no_match": [ev("u0-0", **{"event.action": "account_created", "user.name": "carol", "user.id": "1002"})]}),
]


def build() -> dict:
    pack = {
        "format": D.FORMAT, "format_version": D.FORMAT_VERSION, "pack_id": PACK_ID, "pack_version": PACK_VERSION,
        "source": {"author": "Kratos", "license": "MIT", "builder": "scripts/dev/build_kratos_pack.py",
                   "note": "Kratos's own rules for what a Linux machine logs without auditd"},
        "notice": "Kratos's own detection rules, under the same licence as Kratos (MIT).",
        "rules": RULES, "skipped": [],
    }
    pack["sha256"] = D.pack_digest(pack)
    return pack


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if the committed pack is not what this builds")
    args = ap.parse_args()
    pack = build()
    D.validate_pack(pack)
    problems = D.check_samples(D.Pack(pack))
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    text = json.dumps(pack, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(f"{OUT} is out of date: run scripts/dev/build_kratos_pack.py", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT} ({len(RULES)} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
