from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from kratos.utils.latest_file import latest_file


def _env_label(system_context: dict[str, Any] | None) -> str:
    if not system_context:
        return "unknown"
    rel = ((system_context.get("os") or {}).get("release") or "")
    if "WSL" in rel or "microsoft" in rel.lower():
        return "wsl2"
    return "linux"


def _sudo_members(system_context: dict[str, Any] | None) -> list[str]:
    if not system_context:
        return []
    sudo_line = ((system_context.get("users") or {}).get("sudo_group") or "")
    # expected format: "sudo:x:27:walid000"
    parts = sudo_line.split(":")
    if len(parts) >= 4 and parts[3].strip():
        return [u.strip() for u in parts[3].split(",") if u.strip()]
    return []


def _active_services(system_context: dict[str, Any] | None) -> list[str]:
    if not system_context:
        return []
    services = system_context.get("services") or {}

    # Preferred if you later add structured units:
    units = services.get("units")
    if isinstance(units, list):
        out = []
        for u in units:
            if not isinstance(u, dict):
                continue
            unit_name = u.get("unit")
            active = u.get("active")
            if unit_name and active == "active":
                out.append(str(unit_name))
        return sorted(set(out))

    # Fallback: parse "raw" text lines
    raw = services.get("raw")
    if not isinstance(raw, list):
        return []
    out = []
    for line in raw:
        line = str(line).strip()
        if not line or line.startswith("UNIT") or line.startswith("Legend") or "loaded units listed" in line:
            continue
        # crude split: unit is first column
        unit = line.split()[0] if line.split() else None
        if unit and unit.endswith(".service"):
            out.append(unit)
    return sorted(set(out))


def _open_ports(nmap_parsed: dict[str, Any] | None) -> dict[str, list[str]]:
    """
    Return map host->["22/tcp ssh OpenSSH 8.9", ...] stable strings.
    """
    if not nmap_parsed:
        return {}
    hosts = nmap_parsed.get("hosts")
    if not isinstance(hosts, list):
        return {}

    result: dict[str, list[str]] = {}
    for h in hosts:
        if not isinstance(h, dict):
            continue
        host = str(h.get("host") or h.get("address") or "unknown")
        ports = h.get("open_ports") or []
        lines = []
        for p in ports:
            if not isinstance(p, dict):
                continue
            port = p.get("port")
            proto = p.get("protocol") or "tcp"
            svc = (p.get("service") or "").strip()
            product = (p.get("product") or "").strip()
            ver = (p.get("version") or "").strip()
            extra = " ".join([x for x in [svc, product, ver] if x]).strip()
            if port:
                lines.append(f"{port}/{proto} {extra}".strip())
        result[host] = sorted(set(lines))
    return result


def _services_state(system_context: dict[str, Any] | None) -> dict[str, dict[str, str]]:
    """
    Extract service state map: {unit: {active, sub, load}}
    """
    if not system_context:
        return {}
    services = system_context.get("services") or {}
    units = services.get("units") or []
    
    state_map: dict[str, dict[str, str]] = {}
    for u in units:
        if not isinstance(u, dict):
            continue
        unit = u.get("unit")
        if not unit:
            continue
        state_map[unit] = {
            "active": u.get("active") or "unknown",
            "sub": u.get("sub") or "unknown",
            "load": u.get("load") or "unknown",
        }
    return state_map


@dataclass
class BaselineSnapshot:
    created_at: str
    environment: str
    inputs: dict[str, str | None]
    sudo_members: list[str]
    active_services: list[str]
    open_ports: dict[str, list[str]]
    services_state: dict[str, dict[str, str]]


def build_current_snapshot(data_dir: Path) -> BaselineSnapshot:
    scans_dir = data_dir / "scans"
    ctx_dir = data_dir / "context"
    logs_dir = data_dir / "logs"

    nmap_parsed_path = latest_file(scans_dir, "parsed_*.json")
    system_context_path = latest_file(ctx_dir, "system_context_*.json")
    auth_stats_path = latest_file(logs_dir, "auth_stats_*.json")  # not required but good metadata

    nmap_parsed = json.loads(nmap_parsed_path.read_text()) if nmap_parsed_path else None
    system_context = json.loads(system_context_path.read_text()) if system_context_path else None

    snap = BaselineSnapshot(
        created_at=datetime.now().isoformat(timespec="seconds"),
        environment=_env_label(system_context),
        inputs={
            "nmap_parsed": nmap_parsed_path.name if nmap_parsed_path else None,
            "system_context": system_context_path.name if system_context_path else None,
            "auth_stats": auth_stats_path.name if auth_stats_path else None,
        },
        sudo_members=_sudo_members(system_context),
        active_services=_active_services(system_context),
        open_ports=_open_ports(nmap_parsed),
        services_state=_services_state(system_context),
    )
    return snap


def save_baseline(data_dir: Path, snapshot: BaselineSnapshot) -> Path:
    baseline_dir = data_dir / "baseline"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = baseline_dir / f"baseline_{ts}.json"
    out.write_text(json.dumps(asdict(snapshot), indent=2), encoding="utf-8")
    return out


def load_latest_baseline(data_dir: Path) -> tuple[Path | None, dict[str, Any] | None]:
    baseline_dir = data_dir / "baseline"
    path = latest_file(baseline_dir, "baseline_*.json")
    if not path:
        return None, None
    return path, json.loads(path.read_text(encoding="utf-8", errors="replace"))


def diff_baseline(baseline: dict[str, Any], current: BaselineSnapshot) -> dict[str, Any]:
    """
    Produce a compact diff object for reporting.
    """
    base_sudo = set(baseline.get("sudo_members") or [])
    cur_sudo = set(current.sudo_members)

    base_services = set(baseline.get("active_services") or [])
    cur_services = set(current.active_services)

    base_ports = baseline.get("open_ports") or {}
    cur_ports = current.open_ports

    ports_added: dict[str, list[str]] = {}
    ports_removed: dict[str, list[str]] = {}

    all_hosts = set(base_ports.keys()) | set(cur_ports.keys())
    for host in sorted(all_hosts):
        b = set(base_ports.get(host) or [])
        c = set(cur_ports.get(host) or [])
        added = sorted(c - b)
        removed = sorted(b - c)
        if added:
            ports_added[host] = added
        if removed:
            ports_removed[host] = removed

    # Count totals for baseline and current
    base_sudo_members = list(base_sudo)
    cur_sudo_members = list(cur_sudo)
    base_active_services = list(base_services)
    cur_active_services = list(cur_services)
    
    # Flatten open ports count
    base_open_ports = [p for ports in base_ports.values() for p in ports]
    cur_open_ports = [p for ports in cur_ports.values() for p in ports]

    # Service state changes
    base_services_state = baseline.get("services_state") or {}
    cur_services_state = current.services_state or {}
    
    service_state_changes: list[dict[str, Any]] = []
    common_units = set(base_services_state.keys()) & set(cur_services_state.keys())
    
    for unit in sorted(common_units):
        base_state = base_services_state[unit]
        cur_state = cur_services_state[unit]
        
        if base_state.get("active") != cur_state.get("active") or base_state.get("sub") != cur_state.get("sub"):
            service_state_changes.append({
                "unit": unit,
                "baseline": base_state,
                "current": cur_state,
            })

    return {
        "baseline_created_at": baseline.get("created_at"),
        "current_created_at": current.created_at,
        "environment": {"baseline": baseline.get("environment"), "current": current.environment},
        "counts": {
            "sudo_members": {"baseline": len(base_sudo_members), "current": len(cur_sudo_members)},
            "active_services": {"baseline": len(base_active_services), "current": len(cur_active_services)},
            "open_ports": {"baseline": len(base_open_ports), "current": len(cur_open_ports)},
        },
        "sudo_members": {
            "added": sorted(cur_sudo - base_sudo),
            "removed": sorted(base_sudo - cur_sudo),
        },
        "active_services": {
            "added": sorted(cur_services - base_services),
            "removed": sorted(base_services - cur_services),
        },
        "open_ports": {
            "added": ports_added,
            "removed": ports_removed,
        },
        "service_state_changes": service_state_changes,
    }
