from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any


def find_latest_nmap_xml(data_dir: Path) -> Path | None:
    scans_dir = data_dir / "scans"
    xml_files = sorted(scans_dir.glob("nmap_*.xml"), reverse=True)
    return xml_files[0] if xml_files else None


def parse_nmap_xml_to_dict(xml_path: Path) -> dict[str, Any]:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        raise RuntimeError(f"Failed to parse XML: {xml_path}") from e

    parsed: dict[str, Any] = {
        "tool": "nmap",
        "source_file": xml_path.name,
        "parsed_at": datetime.now().isoformat(timespec="seconds"),
        "hosts": [],
    }

    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "unknown"

        status = host.find("status")
        host_state = status.get("state") if status is not None else "unknown"

        host_obj: dict[str, Any] = {
            "ip": ip,
            "state": host_state,
            "open_ports": [],
        }

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                proto = port.get("protocol", "unknown")
                portid_str = port.get("portid", "0")
                try:
                    portid: int | str = int(portid_str)
                except ValueError:
                    portid = portid_str

                service = port.find("service")
                svc_name = service.get("name") if service is not None else "unknown"
                product = service.get("product") if service is not None else None
                version = service.get("version") if service is not None else None
                extrainfo = service.get("extrainfo") if service is not None else None
                ostype = service.get("ostype") if service is not None else None
                tunnel = service.get("tunnel") if service is not None else None

                host_obj["open_ports"].append(
                    {
                        "protocol": proto,
                        "port": portid,
                        "service": svc_name,
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                        "ostype": ostype,
                        "tunnel": tunnel,
                    }
                )

        parsed["hosts"].append(host_obj)

    return parsed


def write_parsed_json(data_dir: Path, parsed: dict[str, Any]) -> Path:
    scans_dir = data_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = scans_dir / f"parsed_{ts}.json"
    out_json.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    return out_json
