"""Turns nmap's XML output into a normalized dict.

nmap writes XML; the rest of Kratos wants a plain {hosts, ports, services} shape.
This finds the most recent scan XML under `data_dir/scans/`, parses it, and
writes the normalized JSON that the finding rules and the baseline read. Isolating
the XML handling here means nothing downstream has to know nmap's schema.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from kratos.utils.timeutil import utc_now_iso
from pathlib import Path
from typing import Any


def find_latest_nmap_xml(data_dir: Path) -> Path | None:
    scans_dir = data_dir / "scans"
    # newest by modification time, NOT by name: a filename sort put 'nmap_kratos_<old>' above
    # 'nmap_10.136..._<new>' and scan-summary silently reported an August scan (regression check §2.2)
    xml_files = sorted(scans_dir.glob("nmap_*.xml"), key=lambda p: p.stat().st_mtime, reverse=True)
    return xml_files[0] if xml_files else None


_HTTP_REPLY = re.compile(r"HTTP/[12](?:\\?\.\d)?\\x20\d{3}")  # nmap escapes the dot: HTTP/1\.1\x20200
_SERVER_HEADER = re.compile(r"server:\\x20([^\\\r\n]{1,60})", re.IGNORECASE)


def _identify(svc_name: str, method: str | None, fingerprint: str) -> tuple[str, str | None, str | None]:
    """(service, product-from-fingerprint, port-table guess). nmap names a service it
    could NOT identify after the port number ('3000 -> ppp', method="table"); that
    guess was reported as fact ('8001 (vcom-tunnel)' for a web API). A table guess
    becomes 'http' when nmap's fingerprint shows an HTTP reply (with the Server
    header as the product), else 'unknown'; the guess is kept, labelled as one."""
    if method != "table":
        return svc_name, None, None
    if _HTTP_REPLY.search(fingerprint):
        m = _SERVER_HEADER.search(fingerprint)
        return "http", (m.group(1).strip() if m else None), svc_name
    return "unknown", None, svc_name


def parse_nmap_xml_to_dict(xml_path: Path) -> dict[str, Any]:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        raise RuntimeError(f"Failed to parse XML: {xml_path}") from e

    parsed: dict[str, Any] = {
        "tool": "nmap",
        "source_file": xml_path.name,
        "parsed_at": utc_now_iso(),
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
                method = service.get("method") if service is not None else None
                svc_name, fp_product, guess = _identify(
                    svc_name or "unknown", method, (service.get("servicefp") or "") if service is not None else "")

                entry = {
                    "protocol": proto,
                    "port": portid,
                    "service": svc_name,
                    "product": product or fp_product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "ostype": ostype,
                    "tunnel": tunnel,
                }
                if guess:
                    entry["port_usually_used_by"] = guess  # nmap's port-number guess, not a detection
                host_obj["open_ports"].append(entry)

        parsed["hosts"].append(host_obj)

    return parsed


def write_parsed_json(data_dir: Path, parsed: dict[str, Any]) -> Path:
    scans_dir = data_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = scans_dir / f"parsed_{ts}.json"
    out_json.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    return out_json
