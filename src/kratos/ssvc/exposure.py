"""Is the vulnerable code exposed on this machine? (D.3 §5.3) -- measured, shown, used to order.

From the machine's newest running-process read (A.5's live snapshot) and the
finding's package names. Values, most exposed first:

- ``internet``    a process whose program or a loaded library comes from the package
                  listens on a non-loopback address, and the machine has a public
                  address there (the listener's own, or one of the machine's for a
                  wildcard listener) -- or a person marked the machine internet-facing;
- ``network``     the same, but the address is private / CGNAT / tailnet, or a person
                  marked the machine as not reachable from the internet;
- ``local``       a running program comes from the package, but nothing it owns listens
                  (or it listens on loopback only);
- ``not running`` installed, no running program comes from it and no listening program
                  loads it (libraries of programs that don't listen are not read);
- ``unknown``     the read couldn't see (another user's processes over SSH, an agent too
                  old to read loaded libraries, no read yet) -- it says so and how to fix it.

Exposure never changes CISA's outcome: it is Kratos's own measured fact beside it.
A firewall Kratos can see is mentioned, but its per-port rules are not read, so it
does not lower a measured exposure.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Iterable

INTERNET, NETWORK, LOCAL, NOT_RUNNING, UNKNOWN = "internet", "network", "local", "not running", "unknown"
VALUES = (INTERNET, NETWORK, LOCAL, NOT_RUNNING, UNKNOWN)
# Sort order within one decision: most exposed first, unknown between local and not running
# (it may be running -- the read just couldn't tell).
RANK = {INTERNET: 0, NETWORK: 1, LOCAL: 2, UNKNOWN: 3, NOT_RUNNING: 4}
AGENT_FIX = "read this machine through its sub-agent (it can see every process)"
UPDATE_AGENT = "update the agent to see loaded libraries (`g` in /subagent, select the machine)"


@dataclass(frozen=True)
class Exposure:
    value: str
    reason: str
    measured_at: str = ""
    via: str = ""                  # "agent" | "ssh" | "scan" | "person"
    fix: str = ""                  # what would let Kratos see more
    override: str = ""             # the person's setting that applied, if any

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "reason": self.reason, "measured_at": self.measured_at, "via": self.via,
                "fix": self.fix, "override": self.override}


def _bare(pkg: Any) -> str:
    """'libssl3:amd64' -> 'libssl3' (dpkg names multi-arch packages with their arch)."""
    return str(pkg or "").split(":", 1)[0].strip()


def _ip(text: Any) -> Any:
    try:
        ip = ipaddress.ip_address(str(text or "").split("%", 1)[0])
    except ValueError:
        return None
    return getattr(ip, "ipv4_mapped", None) or ip


def _public(ip: Any) -> bool:
    """Outside every local range -- the same rule as SSH reachability
    (adapters.ssh_guessing: private LAN, CGNAT/tailnet, link-local, loopback)."""
    from kratos.adapters.ssh_guessing import _is_local

    return ip is not None and not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or _is_local(ip))


def _wildcard(ip: Any) -> bool:
    return ip is not None and ip.is_unspecified


def _where(item: dict[str, Any]) -> str:
    addr = str(item.get("address") or "?")
    shown = f"[{addr}]" if ":" in addr else addr
    return f"{shown}:{item.get('port')}"


def _program(item: dict[str, Any]) -> str:
    return str(item.get("exe") or "a program")


def _loaded(item: dict[str, Any], wanted: set[str], label: str) -> str:
    """'libnghttp2-14 (from nghttp2)': the library package the process actually maps."""
    names = sorted(wanted & {_bare(p) for p in item.get("lib_packages") or []})
    if not names or names == [label]:
        return label
    return f"{', '.join(names[:2])} (from {label})"


def _scope(items: list[dict[str, Any]], local_addresses: Iterable[str]) -> tuple[str, str]:
    """(internet|network, why) for listeners on non-loopback addresses."""
    machine_public = [a for a in (_ip(x) for x in local_addresses or []) if _public(a)]
    for item in items:
        ip = _ip(item.get("address"))
        if _public(ip):
            return INTERNET, f"{_where(item)} is a public address"
        if _wildcard(ip) and machine_public:
            return INTERNET, f"it listens on all addresses and the machine has the public address {machine_public[0]}"
    return NETWORK, "the machine has no public address there (private, CGNAT or tailnet only)"


def _apply_override(value: str, why: str, override: str | None) -> tuple[str, str, str]:
    if override == "internet" and value == NETWORK:
        return INTERNET, why + "; you marked this machine as reachable from the internet", "internet"
    if override == "private" and value == INTERNET:
        return NETWORK, why + "; you marked this machine as not reachable from the internet", "private"
    return value, why, ""


def _firewall_note(firewall: dict[str, Any] | None) -> str:
    status = str((firewall or {}).get("status") or "").upper()
    if status == "PASS":
        return " (a firewall is active; Kratos didn't read its per-port rules, so it may limit who can reach this)"
    if status == "FAIL":
        return " (no firewall rules are active)"
    return ""


def for_packages(names: Iterable[str], live: dict[str, Any] | None, *, override: str | None = None,
                 firewall: dict[str, Any] | None = None, label: str = "") -> Exposure:
    """Exposure of the code in these binary packages (a PKG finding's installed names)."""
    wanted = {_bare(n) for n in names if _bare(n)}
    label = label or ", ".join(sorted(wanted)[:3]) or "the package"
    if not isinstance(live, dict):
        return Exposure(UNKNOWN, f"Kratos has no recent running-process read of this machine to tell whether "
                                 f"{label} is in use", fix="run a check of the machine (the running-process read)")
    when, via = str(live.get("checked_at") or ""), str(live.get("via") or "")
    listeners = [x for x in live.get("listeners") or [] if isinstance(x, dict)]
    maps_read = bool(live.get("maps_read"))
    by_program, by_library = [], []
    for item in listeners:
        if not item.get("seen"):
            continue
        if _bare(item.get("package")) in wanted:
            by_program.append(item)
        elif wanted & {_bare(p) for p in item.get("lib_packages") or []}:
            by_library.append(item)
    hits = by_program + by_library
    open_hits = [x for x in hits if not (_ip(x.get("address")) and _ip(x.get("address")).is_loopback)]
    if open_hits:
        value, why = _scope(open_hits, live.get("local_addresses") or [])
        first = open_hits[0]
        how = (f"{_program(first)}, from {label}, listens on {_where(first)}" if first in by_program
               else f"{_loaded(first, wanted, label)} is loaded by {_program(first)}, which listens on "
                    f"{_where(first)}")
        more = f" (and {len(open_hits) - 1} more listener(s))" if len(open_hits) > 1 else ""
        value, why, used = _apply_override(value, why, override)
        return Exposure(value, f"{how}{more}; {why}{_firewall_note(firewall)}", when, via, override=used)
    # A root read (the sub-agent) sees every process: a listening socket it can't tie to
    # one is the kernel's own (or its process just exited), never a hidden program.
    root = live.get("reader_uid") == 0
    unseen = [] if root else [x for x in listeners if not x.get("seen")]
    unreadable = [x for x in listeners if x.get("seen") and x.get("maps") == "unreadable"]
    running = wanted & {_bare(p) for p in live.get("running_packages") or []}
    if hits:      # listens on loopback only
        return Exposure(LOCAL, f"{_program(hits[0])} uses {label} but listens only on {_where(hits[0])}", when, via)
    if unseen or unreadable:
        what = (f"{len(unseen)} listening program(s) belong to another user and this login can't see them"
                if unseen else f"this login can't read which libraries {len(unreadable)} listening program(s) load")
        lead = f"a running program comes from {label}; " if running else ""
        return Exposure(UNKNOWN, f"{lead}{what}, so whether {label} is exposed is unknown", when, via, fix=AGENT_FIX)
    if not maps_read and listeners:
        lead = f"a running program comes from {label}, but " if running else ""
        fix = UPDATE_AGENT if via in ("agent", "subagent") else "read the machine again with this version of Kratos"
        return Exposure(UNKNOWN, f"{lead}this read didn't look at which libraries listening programs load "
                                 f"(only their programs) -- {fix}", when, via, fix=fix)
    if running:
        return Exposure(LOCAL, f"a running program comes from {label}; nothing from it listens on the network",
                        when, via)
    return Exposure(NOT_RUNNING, f"installed; no running program comes from {label} and no listening program loads "
                                 "it (libraries of programs that don't listen were not read)", when, via)


def machine_highest(live: dict[str, Any] | None, *, override: str | None = None,
                    firewall: dict[str, Any] | None = None) -> Exposure:
    """The machine's most exposed point, for the running kernel (PKG-003): whatever
    listens on the network exposes the kernel's network code."""
    if not isinstance(live, dict):
        return Exposure(UNKNOWN, "Kratos has no recent running-process read of this machine",
                        fix="run a check of the machine (the running-process read)")
    when, via = str(live.get("checked_at") or ""), str(live.get("via") or "")
    listeners = [x for x in live.get("listeners") or [] if isinstance(x, dict)]
    open_items = [x for x in listeners if not (_ip(x.get("address")) and _ip(x.get("address")).is_loopback)]
    if open_items:
        value, why = _scope(open_items, live.get("local_addresses") or [])
        value, why, used = _apply_override(value, why, override)
        return Exposure(value, f"the running kernel serves {len(open_items)} network listener(s), e.g. "
                               f"{_where(open_items[0])}; {why}{_firewall_note(firewall)}", when, via,
                        override=used)
    return Exposure(LOCAL, "nothing on this machine listens on the network", when, via)


def for_scanned_ports(ports: Iterable[Any], target: str, *, override: str | None = None,
                      scanned_at: str = "") -> Exposure:
    """VULN-001: the CVEs matched a service Kratos reached over the network itself."""
    shown = ", ".join(str(p) for p in list(ports)[:5]) or "?"
    ip = _ip(target)
    value, why = (INTERNET, f"{target} is a public address") if _public(ip) else (
        NETWORK, "Kratos reached it over the network (the address it scanned is not public)")
    value, why, used = _apply_override(value, why, override)
    return Exposure(value, f"the scan reached port(s) {shown} from the Kratos machine; {why}",
                    scanned_at, "scan", override=used)


def rank(value: Any) -> int:
    return RANK.get(str(value or ""), RANK[UNKNOWN])
