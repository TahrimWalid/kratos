"""Can guessing passwords get into this machine over SSH? Judged from sshd's settings.

A brute force against SSH is constant on any machine reachable from the internet. What
decides how much it matters is whether a guess can ever succeed: on a key-only server it
can't, so it is background noise to note, not an alarm; with password (or PAM
keyboard-interactive) logins on, it can. CORR-SSH-001's severity follows this (owner
decision 2026-11-01): key-only -> low, password logins possible -> high, settings not
readable -> medium.

The facts come from the config audit (`run_config_audit`, both transports), saved per
machine as `context/config_audit_<ts>.json` by `save_snapshot`. Kratos judges:

- **closed** (guessing can't work): PasswordAuthentication no, keyboard-interactive off
  (or on without PAM), no Match block re-enabling either -- or AuthenticationMethods
  requires a key for every allowed sign-in and no Match block re-enables passwords;
- **open** (guessing can work): any of PasswordAuthentication yes, keyboard-interactive
  with PAM, a Match block turning them on, AuthenticationMethods allowing a sign-in
  without a key;
- **unknown**: any needed setting couldn't be read (no audit yet, an older agent without
  the new rows, sudo for `sshd -T` missing, sshd_config not readable).

Also: whether SSH is reachable, from the machine's own evidence -- failed logins coming
from other addresses prove it can be reached by them (from the internet when any of them
is outside the local-network ranges), and a running sshd listening on a network address shows it is
offered; an nmap scan is no longer required.
"""
from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SNAPSHOT_DIR = "context"
SNAPSHOT_PATTERN = "config_audit_*.json"
MAX_AGE_HOURS = 24

SEVERITY = {"open": "high", "unknown": "medium", "closed": "low"}

# The config audit rows that decide it (subagent/reads.py's script prints them).
_ROWS = ("ssh_password_auth", "ssh_kbd_interactive", "ssh_match_password")


@dataclass(frozen=True)
class Assessment:
    state: str                                   # "open" | "closed" | "unknown"
    reasons: tuple[str, ...] = ()                # plain lines, Kratos-written
    gaps: tuple[str, ...] = ()                   # what couldn't be read, with the fix

    @property
    def severity(self) -> str:
        return SEVERITY[self.state]


def save_snapshot(data_dir: Path | None, target: str, checks: list[dict[str, Any]], *,
                  via: str | None = None, now: float | None = None) -> Path | None:
    """Keep a config audit's result for the findings engine (one file per audit)."""
    if data_dir is None or not target or not isinstance(checks, list):
        return None
    now = time.time() if now is None else now
    out = Path(data_dir) / SNAPSHOT_DIR
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"config_audit_{datetime.fromtimestamp(now).strftime('%Y%m%d_%H%M%S_%f')}.json"
    doc = {"target": target, "collected_at": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds"),
           "collected_at_epoch": now, "via": via,
           "checks": [{k: str(c.get(k) or "") for k in ("check", "status", "detail")}
                      for c in checks if isinstance(c, dict)]}
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    tmp.replace(path)
    return path


def load_recent(path: Path | None, *, now: float | None = None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("checks"), list):
        return None
    now = time.time() if now is None else now
    if now - float(doc.get("collected_at_epoch") or 0) > MAX_AGE_HOURS * 3600:
        return None
    return doc


def assess(audit: dict[str, Any] | None) -> Assessment:
    if not audit:
        return Assessment("unknown", gaps=(
            "sshd's settings haven't been read for this machine in the last 24 hours, so Kratos can't tell "
            "whether password logins are possible (the configuration audit reads them)",))
    rows = {str(c.get("check")): c for c in audit.get("checks") or [] if isinstance(c, dict)}

    def status(name: str) -> str | None:
        row = rows.get(name)
        return str(row.get("status") or "").upper() if row else None

    reasons: list[str] = []
    opened = []
    if status("ssh_password_auth") == "WARN":
        opened.append("password logins are on (PasswordAuthentication yes)")
    if status("ssh_kbd_interactive") == "WARN":
        opened.append("keyboard-interactive logins go through PAM, which usually asks for a password")
    if status("ssh_match_password") == "WARN":
        opened.append("a Match block in sshd_config turns password logins on for some users or addresses")
    if status("ssh_auth_methods") == "WARN":
        opened.append("AuthenticationMethods allows a sign-in without a key")
    if opened:
        return Assessment("open", tuple("Guessing can succeed: " + r for r in opened))

    keys_required = status("ssh_auth_methods") == "PASS"
    needed = ("ssh_match_password",) if keys_required else _ROWS
    missing = [n for n in needed if status(n) not in ("PASS",)]
    if missing:
        gaps = []
        old_agent = audit.get("via") == "agent" and any(rows.get(n) is None for n in missing)
        for n in missing:
            row = rows.get(n)
            if row is None:
                gaps.append(f"{_LABEL[n]} wasn't reported"
                            + (" (this machine's agent is older -- update it with `g` in /subagent)" if old_agent else ""))
            else:
                gaps.append(f"{_LABEL[n]} couldn't be read: {str(row.get('detail') or '')[:160]}")
        return Assessment("unknown", gaps=tuple(gaps))
    if keys_required:
        reasons.append("Guessing can't succeed: every allowed sign-in needs a key (AuthenticationMethods)")
    else:
        reasons.append("Guessing can't succeed: password and keyboard-interactive logins are off")
    reasons.append("No Match block in sshd_config turns password logins back on")
    return Assessment("closed", tuple(reasons))


_LABEL = {"ssh_password_auth": "PasswordAuthentication", "ssh_kbd_interactive": "keyboard-interactive login",
          "ssh_match_password": "Match blocks in sshd_config", "ssh_auth_methods": "AuthenticationMethods"}


@dataclass
class Exposure:
    exposed: bool = False
    scope: str = ""                              # "internet" | "network" | ""
    lines: list[str] = field(default_factory=list)


# Addresses of a local network: private LAN, CGNAT / tailnet, link-local, loopback. Any
# other source address reached sshd from outside them -- "the internet".
_LOCAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
    "fc00::/7", "fe80::/10", "::1/128"))


def _is_local(ip: Any) -> bool:
    return any(ip.version == n.version and ip in n for n in _LOCAL_NETS)


def _addr(text: Any) -> Any:
    try:
        ip = ipaddress.ip_address(str(text or "").split("%", 1)[0])
    except ValueError:
        return None
    return getattr(ip, "ipv4_mapped", None) or ip


def exposure(source_ips: Iterable[Any], *, listeners: list[dict[str, Any]] | None = None,
             nmap_ssh: bool = False) -> Exposure:
    """SSH reachability from the machine's own evidence (see the module docstring)."""
    out = Exposure()
    remote = [a for a in (_addr(s) for s in source_ips) if a is not None and not a.is_loopback]
    public = [a for a in remote if not _is_local(a)]
    if public:
        out.exposed, out.scope = True, "internet"
        out.lines.append(f"SSH is reachable from the internet: failed logins came from {len(set(public))} public "
                         "address(es)")
    elif remote:
        out.exposed, out.scope = True, "network"
        out.lines.append(f"SSH is reachable from the network: failed logins came from {len(set(remote))} other "
                         "address(es) (none public)")
    sshd = [x for x in listeners or [] if isinstance(x, dict) and str(x.get("exe") or "").rsplit("/", 1)[-1]
            in ("sshd", "sshd-session") and (_addr(x.get("address")) is not None and not _addr(x.get("address")).is_loopback)]
    if sshd:
        out.exposed = True
        ports = sorted({int(x["port"]) for x in sshd if isinstance(x.get("port"), int)})
        out.lines.append(f"sshd listens on a network address (port {', '.join(map(str, ports))})")
    if nmap_ssh:
        out.exposed = True
        out.lines.append("the network scan found SSH open")
    return out
