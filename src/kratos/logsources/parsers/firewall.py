"""Firewall log lines from the kernel (ufw and plain nftables/iptables LOG rules).

    [UFW BLOCK] IN=enp5s0 OUT= MAC=... SRC=10.136.28.52 DST=10.136.28.102 ... PROTO=TCP SPT=59286 DPT=2222 ...

Only lines that carry a packet (IN=/OUT= and SRC=) are events; other kernel
lines are skipped.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

try:  # in the agent bundle (C.2): sibling modules
    from .parsers_base import Parsed, record_parts  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:
        from kratos.logsources.parsers import Parsed, record_parts
    except ImportError:  # run directly
        from parsers_base import Parsed, record_parts  # type: ignore[no-redef]

_UFW = re.compile(r"\[UFW (?P<act>[A-Z ]+?)\]")
_PACKET = re.compile(r"\bIN=\S* OUT=\S*.*?\bSRC=(?P<src>[0-9A-Fa-f:.]+) DST=(?P<dst>[0-9A-Fa-f:.]+)", re.DOTALL)
_PROTO = re.compile(r"\bPROTO=(?P<p>[A-Za-z0-9]+)")
_SPT = re.compile(r"\bSPT=(?P<p>\d{1,5})\b")
_DPT = re.compile(r"\bDPT=(?P<p>\d{1,5})\b")
_ACTIONS = {"BLOCK": "blocked", "LIMIT BLOCK": "blocked", "ALLOW": "allowed", "AUDIT": "audit",
            "AUDIT INVALID": "audit", "LIMIT": "audit"}


def _ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _port(rx: re.Pattern[str], text: str) -> int | None:
    m = rx.search(text)
    return int(m.group("p")) if m and int(m.group("p")) <= 65535 else None


def to_parsed(rec: Any) -> Parsed | None:
    _prog, _pid, msg, original, cursor = record_parts(rec)
    pm = _PACKET.search(msg)
    if not pm:
        return None
    um = _UFW.search(msg)
    action = _ACTIONS.get(um.group("act").strip(), "logged") if um else "logged"
    proto = _PROTO.search(msg)
    fields: dict[str, Any] = {
        "source_ip": _ip(pm.group("src")), "destination_ip": _ip(pm.group("dst")),
        "source_port": _port(_SPT, msg), "destination_port": _port(_DPT, msg),
        "network_transport": proto.group("p").lower() if proto else None,
    }
    return Parsed(ts=rec.ts, action=action, provider="ufw" if um else "kernel", message=msg, original=original,
                  fields={k: v for k, v in fields.items() if v not in (None, "")}, log_file_path=rec.path,
                  cursor=cursor, zone_assumed=rec.zone_assumed)


def parse(read: Any) -> list[Parsed]:
    return [p for p in (to_parsed(r) for r in read.records) if p is not None]
