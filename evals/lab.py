"""The lab the live evaluations run against -- its names and addresses, from
config/lab.toml (point KRATOS_EVAL_LAB at another file for another lab).

The code that *changes* the lab for a scenario (a failed login, a planted file, a
stopped service) is deliberately NOT here: per Phase A's rule, offensive/attack
orchestration is never vendored into the repo. Live scenarios delegate their setup
and teardown to the durable external harness (evals.harness_bridge); replay scenarios
touch no machine at all. This module is pure configuration plus the recording-scan
allowlist, so it is safe to import anywhere.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

CONFIG = Path(__file__).resolve().parent / "config" / "lab.toml"


@dataclass(frozen=True)
class Lab:
    target: str
    target_user: str
    key: str
    target_incus: str
    attacker_incus: str
    attacker_ip: str
    allowed_public: dict[str, str] = field(default_factory=dict)


@lru_cache(maxsize=None)
def lab() -> Lab:
    path = Path(os.environ.get("KRATOS_EVAL_LAB") or CONFIG)
    d = tomllib.loads(path.read_text(encoding="utf-8"))
    t, a = d["target"], d["attacker"]
    return Lab(target=t["host"], target_user=t["user"], key=str(Path(t["key"]).expanduser()),
               target_incus=t["incus"], attacker_incus=a["incus"], attacker_ip=a["ip"],
               allowed_public=dict(d.get("recordings", {}).get("allowed_public_addresses", {})))


def lab_addresses() -> set[str]:
    """Addresses that are legitimately part of the lab, so a recording may mention them."""
    L = lab()
    return {L.target, L.attacker_ip}


def is_private_or_documentation(ip: str) -> bool:
    """True for an address a recording may hold without disclosing a real machine:
    private, loopback, link-local, or the documentation ranges (192.0.2/24, 198.51.100/24,
    203.0.113/24) the corpus uses for fake attacker hosts."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast:
        return True
    doc = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                             "2001:db8::/32")]
    return any(addr in n for n in doc)
