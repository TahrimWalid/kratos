"""
Work out which address a sub-agent should DIAL to reach this Kratos core.

The transport is agent-initiated: the target always dials out to core and core
opens the listener (see agent.py / core_server.py). So onboarding a target
needs one thing the operator often gets wrong -- *what address will the target
actually reach this core at?* That depends on where the target is:

- same LAN as core          -> core's LAN IP (routing-table lookup)
- across the internet, core  -> a Tailscale (or other overlay) IP, because a
  behind home NAT              home-lab core has no public inbound address
- core has a public address  -> that public IP/hostname (operator-supplied)

This module only *suggests* candidates (best-effort, never a guessed-wrong
value silently used); the operator confirms or types the real one. Nothing here
sends traffic: the LAN lookup is the standard UDP-``connect()`` routing trick
(no packet leaves the host), and the Tailscale lookup shells out to the local
``tailscale`` CLI read-only.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class HubAddressCandidate:
    kind: str  # "lan" | "tailscale" | "manual"
    address: str
    note: str


def detect_lan_ip(reference_host: str = "8.8.8.8") -> str | None:
    """Best-effort local IP the OS would route outbound through.

    A UDP ``connect()`` sends no packet (UDP has no handshake) -- this is a pure
    routing-table lookup. Returns ``None`` (never a wrong guess) on failure.
    ``reference_host`` only steers which route is chosen; it is never contacted.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((reference_host, 1))
            return sock.getsockname()[0]
    except OSError:
        return None


def detect_tailscale_ip() -> str | None:
    """This host's Tailscale IPv4, or ``None`` if Tailscale isn't installed/up.

    Read-only: runs ``tailscale ip -4`` and returns its first line. Any error
    (no CLI, not logged in, not up) resolves to ``None`` rather than a guess.
    """
    if shutil.which("tailscale") is None:
        return None
    try:
        out = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    first = out.stdout.strip().splitlines()
    return first[0].strip() if first and first[0].strip() else None


def candidate_hub_addresses() -> list[HubAddressCandidate]:
    """Ordered best-effort suggestions for the address a target should dial.

    Tailscale first when present (the right answer for a remote target reaching
    a behind-NAT core), then the LAN IP (right for a same-network target), then
    always a manual option. Deduplicated by address; the manual entry is always
    last so the operator can override with a public IP/hostname.
    """
    candidates: list[HubAddressCandidate] = []
    seen: set[str] = set()

    ts = detect_tailscale_ip()
    if ts and ts not in seen:
        candidates.append(
            HubAddressCandidate(
                kind="tailscale",
                address=ts,
                note="Tailscale IP -- use this if the target is on your tailnet (remote / behind NAT).",
            )
        )
        seen.add(ts)

    lan = detect_lan_ip()
    if lan and lan not in seen:
        candidates.append(
            HubAddressCandidate(
                kind="lan",
                address=lan,
                note="LAN IP -- use this if the target is on the same local network as this core.",
            )
        )
        seen.add(lan)

    candidates.append(
        HubAddressCandidate(
            kind="manual",
            address="",
            note="Enter a different address -- e.g. a public IP/hostname the target can reach.",
        )
    )
    return candidates
