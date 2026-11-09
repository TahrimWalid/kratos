"""Run the container read, judge it, and save what the rule engine reads (D.5).

One call: read (through the machine's sub-agent as root when it has one, else over SSH
as the SSH login -- ``ssh_remote.fetch_containers`` -- or, for Kratos's own machine, the
same script run locally as Kratos's own user), confirm each port the firewall model says
bypasses the firewall with ONE TCP connect from Kratos (no payload), judge
(``kratos.containers.judge``) and write ``data_dir/containers/containers_<machine>.json``
-- one file per machine, replaced in place (a file per run would push other machines'
snapshots out of the input lookup -- the Phase C lesson).

Nothing is written on the monitored machine, and nothing here calls a model.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from kratos.containers.judge import judge
from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso

FOLDER = "containers"
PATTERN = "containers_*.json"
CONNECT_TIMEOUT_SECONDS = 2.5
LOCAL_TIMEOUT_SECONDS = 60

Reader = Callable[[], Any]


def machine_hash(target: str) -> str:
    return hashlib.sha256(target_key(target).encode()).hexdigest()[:8]


def snapshot_path(data_dir: Path, target: str) -> Path:
    return Path(data_dir) / FOLDER / f"containers_{machine_hash(target)}.json"


def is_local(target: str) -> bool:
    from kratos.subagent import routing

    return routing.normalize_host(target) in routing._LOOPBACK


def _local_reader() -> Any:
    """Kratos's own machine: the SSH script run locally as Kratos's own user (never the
    engine API -- Kratos's login may be in the docker group, and must not use it)."""
    from kratos.adapters import containers

    try:
        p = subprocess.run(["sh", "-s"], input=containers.build_script(), capture_output=True, text=True,
                           errors="replace", timeout=LOCAL_TIMEOUT_SECONDS, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                                                                  "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as e:
        from kratos.adapters.ssh_remote import SSHResult

        return SSHResult(ok=False, returncode=-1, stdout="", stderr=f"local read failed: {e}", via="local")
    out = containers.parse_output(p.stdout)
    out["via"] = "local"
    out["truncated_output"] = not out["complete"]
    return out


def _default_reader(target: str) -> Reader:
    if is_local(target):
        return _local_reader

    def read() -> Any:
        from kratos import kratos_config
        from kratos.adapters.ssh_remote import fetch_containers

        with kratos_config.pinned_target(target):
            return fetch_containers()
    return read


def host_addresses(target: str) -> dict[int, str | None]:
    """The machine's address per family, as Kratos reaches it (the name resolved here)."""
    host = target_key(target)
    out: dict[int, str | None] = {4: None, 6: None}
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        out[ip.version] = str(ip)
        return out
    except ValueError:
        pass
    try:
        for fam, _t, _p, _c, sa in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
            v = 4 if fam == socket.AF_INET else 6
            out[v] = out[v] or sa[0]
    except OSError:
        pass
    return out


def vantage(addr: str | None) -> str:
    """Kratos's own address on the way to `addr` (a UDP connect sends nothing)."""
    if not addr:
        return "Kratos"
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    try:
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.connect((addr, 9))
            return f"Kratos at {s.getsockname()[0]}"
    except OSError:
        return "Kratos"


def tcp_connect(addr: str, port: int, timeout: float = CONNECT_TIMEOUT_SECONDS) -> bool:
    """One TCP connection attempt, closed at once: no byte is sent."""
    try:
        s = socket.create_connection((addr, int(port)), timeout=timeout)
    except OSError:
        return False
    s.close()
    return True


def _failure_text(result: Any) -> str:
    text = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
    return " ".join(text.split())[:300] or "the read failed"


def run(data_dir: Path, target: str, *, reader: Reader | None = None, now: float | None = None,
        connect: Callable[[str, int], bool] | None = None) -> dict[str, Any]:
    """Read, judge, save. Returns the saved document plus `file`, or
    `{"status": "error", ...}` when the read failed (nothing saved -- a failed read must
    never become "no containers")."""
    data_dir = Path(data_dir)
    when = time.time() if now is None else now
    result = (reader or _default_reader(target))()
    if not isinstance(result, dict):
        return {"status": "error", "target": target, "observation": _failure_text(result)}
    inv = result
    addrs = host_addresses(target)
    local = is_local(target)
    v4 = addrs.get(4)
    connector = connect or tcp_connect
    confirm = (lambda port: connector(v4, port)) if v4 and not local else None
    judged = judge(inv, host_addrs=addrs, confirm=confirm, vantage=vantage(v4), local_machine=local)
    infos = inv.get("infos") or {}
    doc: dict[str, Any] = {
        "target": target, "checked_at": epoch_to_utc_iso(when), "checked_at_epoch": when,
        "via": inv.get("via") or "ssh", "complete": bool(inv.get("complete")) and not inv.get("truncated_output"),
        "engines_found": judged.engines_found,
        "engines": [{"engine": e["engine"], "state": e["state"], "version": e["detail"] if e["state"] == "ok" else ""}
                    for e in inv.get("engines") or []],
        "firewall_backend": next((str(i.get("firewall_backend")) for i in infos.values() if i.get("firewall_backend")), ""),
        "firewall_read": {k: (v or {}).get("status") for k, v in (inv.get("firewall") or {}).items()},
        "counts": judged.counts, "rows": judged.rows, "port_checks": judged.port_checks,
        "coverage_gaps": judged.gaps, "signals": judged.signals,
        # what the per-image package read and SSVC exposure need: each running image and
        # the ports its containers publish
        "images": _images(inv),
        "agent_note": str(inv.get("agent_note") or "")[:300],
    }
    path = snapshot_path(data_dir, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)
    from kratos import evidence as _evidence

    _evidence.record(path, data_dir=data_dir, category="containers", machine=target, read="container_inventory",
                     transport=doc.get("via"))
    return {**doc, "status": "ok", "file": str(path)}


def _images(inv: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for c in (inv.get("containers") or {}).values():
        if not c.get("running") or not c.get("image_id"):
            continue
        it = out.setdefault(c["image_id"], {"image": c.get("image") or "", "digest": c.get("image_digest") or "",
                                            "containers": [], "ports": []})
        it["containers"].append(str(c.get("name") or c["id"][:12]))
        for p in c.get("ports") or []:
            it["ports"].append({"host_ip": p.get("host_ip"), "host_port": p.get("host_port"), "proto": p.get("proto")})
        if str(c.get("network_mode")) == "host":
            it["host_network"] = True
    return out


def load(data_dir: Path, target: str) -> dict[str, Any] | None:
    try:
        data = json.loads(snapshot_path(data_dir, target).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def summary_line(doc: dict[str, Any]) -> str:
    """The digest's one line, in Kratos's own words (no machine text: no names, no images)."""
    if not doc.get("engines_found"):
        return "no container engine found"
    c = doc.get("counts") or {}
    n = int(c.get("running") or 0)
    parts = [f"{n} running container(s)"]
    sigs = doc.get("signals") or []
    bypass = [s for s in sigs if s.get("rule") == "CONT-004"]
    if bypass:
        ports = sorted({f"{p['host_port']}/{p['proto']}" for s in bypass for p in s.get("ports") or []})
        conf = sum(1 for s in bypass if s.get("severity") == "high")
        parts.append(f"{len(ports)} port(s) reachable despite the firewall ({', '.join(ports[:4])}"
                     + (f", {conf} confirmed from Kratos" if conf else ", not confirmed from Kratos") + ")")
    words = {"CONT-001": "privileged", "CONT-002": "engine socket mounted", "CONT-003": "host namespace",
             "CONT-005": "writable host folders", "CONT-006": "powerful capabilities", "CONT-007": "confinement off"}
    risky = [f"{sum(1 for s in sigs if s.get('rule') == r)} {w}" for r, w in words.items()
             if any(s.get("rule") == r for s in sigs)]
    if risky:
        parts.append(", ".join(risky))
    elif not bypass:
        parts.append("no risky settings found")
    if doc.get("via") == "ssh":
        parts.append("engine settings not readable over SSH")
    return "; ".join(parts)
