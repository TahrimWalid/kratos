"""
Network Aggregator - Tier 2 Intelligence Layer
==============================================
Correlates Nmap device identity with actual network behavior from tcpdump.
Detects anomalies: Device doing something it shouldn't be doing.

Example:
  Nmap: 192.168.0.50 = Printer (port 9100 open)
  tcpdump: 192.168.0.50 opened SSH to 8.8.8.8
  → ANOMALY: Printer doing SSH (expected: only printing)
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from typing import Any, Optional
from kratos.utils.latest_file import latest_file


# Device type -> Expected behaviors (port numbers)
EXPECTED_BEHAVIORS = {
    "printer": {80, 443, 9100, 631},  # HTTP, HTTPS, LPD/JetDirect, CUPS
    "router": {22, 23, 80, 443},      # SSH, Telnet, HTTP, HTTPS
    "camera": {80, 443, 554, 8080},   # HTTP, HTTPS, RTSP, alt-HTTP
    "laptop": {22, 80, 443, 3306, 5432, 27017},  # SSH, HTTP, HTTPS, MySQL, PostgreSQL, MongoDB
    "phone": {80, 443, 5353},         # HTTP, HTTPS, mDNS
    "web_server": {80, 443, 22},      # HTTP, HTTPS, SSH
    "database": {3306, 5432, 27017, 1433},  # MySQL, PostgreSQL, MongoDB, MSSQL
    "unknown": set(),  # No restrictions for unknowns
}

SEVERITY_SCORES = {
    "internal_ssh": 8,        # Device doing SSH internally (lateral movement)
    "external_ssh": 9,        # Device doing SSH to external IP (C&C callback)
    "unexpected_port": 6,     # Device using port it shouldn't
    "data_exfil": 9,          # Large data transfer to external
    "random_ports": 7,        # Scanning behavior
}


def _extract_device_type_from_nmap(nmap_data: dict[str, Any]) -> dict[str, str]:
    """
    Extract device type mapping from Nmap parsed JSON.
    Returns: {ip_address: device_type, ...}
    """
    mapping = {}
    try:
        hosts = nmap_data.get("hosts", [])
        for host in hosts:
            ip = host.get("host") or host.get("address") or "unknown"
            os_type = host.get("osmatch", "").lower() or "unknown"
            
            # Heuristic: guess device type from OS and open ports
            if "windows" in os_type:
                device_type = "laptop"
            elif "linux" in os_type:
                device_type = "web_server"
            elif "printer" in os_type or any(p.get("port") == 9100 for p in host.get("open_ports", [])):
                device_type = "printer"
            elif "router" in os_type or "firmware" in os_type:
                device_type = "router"
            elif "camera" in os_type or "nvr" in os_type:
                device_type = "camera"
            else:
                device_type = "unknown"
            
            mapping[ip] = device_type
    except Exception:
        pass
    
    return mapping


def _score_connection(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    device_type: str,
    is_internal: bool,
) -> int:
    """
    Assign anomaly score to a connection.
    Higher score = more anomalous.
    """
    score = 0
    reasons = []
    
    # Check if port is expected for this device type
    expected_ports = EXPECTED_BEHAVIORS.get(device_type, set())
    if expected_ports and dst_port not in expected_ports:
        score += SEVERITY_SCORES.get("unexpected_port", 5)
        reasons.append(f"Port {dst_port} unexpected for {device_type}")
    
    # SSH behavior scoring
    if dst_port == 22 and protocol.upper() == "TCP":
        if not is_internal:
            score += SEVERITY_SCORES.get("external_ssh", 9)
            reasons.append("SSH to external IP (C&C risk)")
        else:
            score += SEVERITY_SCORES.get("internal_ssh", 7)
            reasons.append("SSH to internal IP (lateral movement)")
    
    # High ports to unknown external IPs (potential scan/callback)
    if dst_port > 1024 and not is_internal and is_private_ip(src_ip) and not is_private_ip(dst_ip):
        if device_type not in ["laptop", "web_server"]:
            score += 4
            reasons.append("High port to external (unusual for this device)")
    
    return score, reasons


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private range."""
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    
    first = int(octets[0])
    second_third = f"{octets[1]}.{octets[2]}"
    
    # 10.0.0.0/8
    if first == 10:
        return True
    # 192.168.0.0/16
    if first == 192 and octets[1] == "168":
        return True
    # 172.16.0.0/12
    if first == 172 and 16 <= int(octets[1]) <= 31:
        return True
    
    return False


# Alias for consistency
is_private_ip = _is_private_ip


def build_anomaly_report(
    data_dir: Path,
    nmap_file: Path | None = None,
    conn_summary_file: Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    """
    Correlate Nmap device info with tcpdump connections.
    Generate anomaly report JSON.
    
    Returns:
        (output_file_path, anomalies_dict)
    """
    logs_dir = data_dir / "logs"
    reports_dir = data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Find latest files if not provided
    if nmap_file is None:
        nmap_file = latest_file(data_dir / "scans", "parsed_*.json")
    if conn_summary_file is None:
        conn_summary_file = latest_file(logs_dir, "conn_summary_*.json")
    
    anomalies = []
    metadata = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "nmap_source": nmap_file.name if nmap_file else "none",
        "conn_source": conn_summary_file.name if conn_summary_file else "none",
        "anomaly_count": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0,
    }
    
    if not nmap_file or not nmap_file.exists():
        print(f"[KRATOS-NET] No Nmap file found. Run: kratos scan first", flush=True)
        return None, metadata
    
    if not conn_summary_file or not conn_summary_file.exists():
        print(f"[KRATOS-NET] No connection summary found. Run network capture first", flush=True)
        return None, metadata
    
    # Load data
    try:
        nmap_data = json.loads(nmap_file.read_text(encoding="utf-8", errors="replace"))
        connections = json.loads(conn_summary_file.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        print(f"[KRATOS-NET] Error reading files: {e}", flush=True)
        return None, metadata
    
    # Map IPs to device types
    device_map = _extract_device_type_from_nmap(nmap_data)
    
    # Score each connection
    for conn in connections:
        src_ip = conn.get("src_ip", "unknown")
        dst_ip = conn.get("dst_ip", "unknown")
        dst_port = conn.get("dst_port", 0)
        protocol = conn.get("protocol", "TCP")
        packets = conn.get("packets", 1)
        
        if src_ip == "unknown" or dst_ip == "unknown":
            continue
        
        device_type = device_map.get(src_ip, "unknown")
        is_internal = is_private_ip(dst_ip)
        
        score, reasons = _score_connection(
            src_ip, dst_ip, dst_port, protocol, device_type, is_internal
        )
        
        # Flag if score exceeds threshold
        if score >= 5:
            severity = "HIGH" if score >= 8 else ("MEDIUM" if score >= 6 else "LOW")
            
            anomalies.append({
                "src_ip": src_ip,
                "device_type": device_type,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "packets": packets,
                "severity": severity,
                "anomaly_score": score,
                "reasons": reasons,
                "recommendation": (
                    "Block immediately" if score >= 8 else
                    "Investigate and potentially isolate" if score >= 6 else
                    "Monitor and log"
                ),
            })
            
            # Update counters
            metadata["anomaly_count"] += 1
            if severity == "HIGH":
                metadata["high_severity"] += 1
            elif severity == "MEDIUM":
                metadata["medium_severity"] += 1
            else:
                metadata["low_severity"] += 1
    
    # Sort by score (highest first)
    anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
    
    # Write output
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = reports_dir / f"network_anomalies_{ts}.json"
    
    report = {
        "metadata": metadata,
        "anomalies": anomalies,
    }
    
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[KRATOS-NET] Anomaly report written -> {out_json}", flush=True)
    print(f"[KRATOS-NET] Found {metadata['anomaly_count']} anomalies ({metadata['high_severity']} HIGH)", flush=True)
    
    return out_json, report
