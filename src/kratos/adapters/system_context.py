from __future__ import annotations

import json
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from kratos.adapters.context import parse_systemctl_units, detect_production_like_services


def _run(cmd: list[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        return out.strip()
    except Exception:
        return ""


def collect_system_context() -> dict[str, Any]:
    context: dict[str, Any] = {}

    # --- OS & kernel ---
    context["os"] = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
    }

    # --- uptime ---
    uptime = _run(["uptime", "-p"])
    context["uptime"] = uptime or None

    # --- users & groups ---
    users = _run(["cut", "-d:", "-f1", "/etc/passwd"]).splitlines()
    sudo_group = _run(["getent", "group", "sudo"])

    context["users"] = {
        "total_users": len(users),
        "usernames": users,
        "sudo_group": sudo_group,
    }

    # --- running services ---
    services_raw = _run(["systemctl", "list-units", "--type=service", "--state=running"])
    if services_raw:
        services_raw_lines = services_raw.splitlines()
        services_units = parse_systemctl_units(services_raw_lines)
        prod = detect_production_like_services(services_units)
        
        context["services"] = {
            "method": "systemctl",
            "raw": services_raw_lines,
            "units": services_units,
        }
        
        context["critical_services"] = {
            "detected": prod,
            "notes": (
                ["Production-like services detected; avoid restarts during peak hours."]
                if prod
                else []
            ),
        }
    else:
        # fallback (WSL / minimal systems)
        ps = _run(["ps", "-eo", "pid,comm"])
        context["services"] = {
            "method": "ps",
            "raw": ps.splitlines() if ps else [],
        }
        context["critical_services"] = {"detected": [], "notes": []}

    # --- network interfaces ---
    ip = _run(["ip", "-brief", "addr"])
    context["network"] = {
        "interfaces": ip.splitlines() if ip else [],
    }

    # --- SSH exposure detection ---
    ssh_info: dict[str, Any] = {
        "service_active": False,
        "listening_ports": [],
        "methods": []
    }
    
    # Check if SSH service is active
    ssh_active = _run(["systemctl", "is-active", "ssh"])
    if not ssh_active:
        ssh_active = _run(["systemctl", "is-active", "sshd"])
    
    if ssh_active in ("active", "activating"):
        ssh_info["service_active"] = True
        ssh_info["methods"].append("systemctl")
    
    # Check listening ports (works even without systemd)
    ss_output = _run(["ss", "-lntp"])
    if not ss_output:
        ss_output = _run(["netstat", "-lntp"])
        if ss_output:
            ssh_info["methods"].append("netstat")
    else:
        ssh_info["methods"].append("ss")
    
    # Parse listening ports for SSH (port 22 or sshd)
    if ss_output:
        for line in ss_output.splitlines():
            if ":22 " in line or "sshd" in line.lower():
                # Extract port number
                parts = line.split()
                for part in parts:
                    if ":22" in part or (":2" in part and "sshd" in line.lower()):
                        # Try to extract port
                        try:
                            if ":" in part:
                                port_str = part.split(":")[-1].split()[0]
                                port = int(port_str)
                                if port not in ssh_info["listening_ports"]:
                                    ssh_info["listening_ports"].append(port)
                        except (ValueError, IndexError):
                            pass
                # Default to 22 if we found sshd but couldn't parse port
                if "sshd" in line.lower() and 22 not in ssh_info["listening_ports"]:
                    ssh_info["listening_ports"].append(22)
    
    context["ssh"] = ssh_info

    context["collected_at"] = datetime.now().isoformat(timespec="seconds")
    return context


def write_system_context(data_dir: Path) -> Path:
    ctx = collect_system_context()

    ctx_dir = data_dir / "context"
    ctx_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = ctx_dir / f"system_context_{ts}.json"
    out.write_text(json.dumps(ctx, indent=2), encoding="utf-8")
    return out
