"""
Network Traffic Capture & Parsing
==================================
Lightweight tcpdump wrapper for passive network monitoring.
Captures connection metadata (src, dst, port, protocol, bytes).
Output: conn_summary JSON for aggregator to process.
"""

from __future__ import annotations

import json
import subprocess
import re
from pathlib import Path
from datetime import datetime
from typing import Any


def _parse_tcpdump_line(line: str) -> dict[str, Any] | None:
    """
    Parse a single tcpdump text output line.
    Expected format (with specific flags):
      IP src.port > dst.port: flags ...
    Example:
      192.168.1.100.54321 > 8.8.8.8.53: UDP, length 45
      192.168.1.50.22 > 192.168.1.1.54123: Flags [S], seq ...
    """
    try:
        # Regex: "SRC.PORT > DST.PORT:"
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+).*?(\w+)(,|:)', line)
        if not match:
            return None
        
        src_ip, src_port, dst_ip, dst_port, protocol, _ = match.groups()
        
        return {
            "src_ip": src_ip,
            "src_port": int(src_port),
            "dst_ip": dst_ip,
            "dst_port": int(dst_port),
            "protocol": protocol.upper(),  # TCP, UDP, ICMP, etc
        }
    except Exception:
        return None


def capture_traffic(
    duration_seconds: int = 60,
    interface: str = "any",
    output_file: Path | None = None,
) -> Path | None:
    """
    Run tcpdump for specified duration and save connection summary.
    
    Args:
        duration_seconds: How long to capture
        interface: Network interface (default: 'any' = all interfaces)
        output_file: Where to write JSON (default: data/logs/conn_summary_YYYYMMDD_HHMMSS.json)
    
    Returns:
        Path to output JSON file, or None if capture failed
    """
    from kratos.llm_config import DEFAULT_DATA_DIR
    
    # Default output location
    if output_file is None:
        logs_dir = DEFAULT_DATA_DIR / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = logs_dir / f"conn_summary_{ts}.json"
    
    print(f"[KRATOS-NET] Capturing traffic for {duration_seconds}s on {interface}...", flush=True)
    
    try:
        # Run tcpdump: capture packets, write to file instead of stdout
        # -nn: no DNS resolution, no port name resolution (faster)
        # -l: line-buffered output
        # -i interface: which interface to capture on
        # -w: write to binary pcap file first, then parse it
        temp_pcap = output_file.with_suffix('.pcap')
        
        cmd = [
            "sudo", "tcpdump",
            "-nn",
            "-l",
            "-i", interface,
            "-w", str(temp_pcap),
            "-G", str(duration_seconds),  # Rotate/quit after N seconds
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=duration_seconds + 10,
            text=True,
        )
        
        # If tcpdump not available or no permissions, return None gracefully
        if result.returncode != 0 and "command not found" in result.stderr.lower():
            print(f"[KRATOS-NET] Warning: tcpdump not found or permission denied", flush=True)
            print(f"[KRATOS-NET] Install with: sudo apt-get install tcpdump", flush=True)
            return None
        
        # Parse pcap file using tcpdump text output
        conn_summary = _parse_pcap_to_summary(temp_pcap)
        
        # Write summary JSON
        output_file.write_text(json.dumps(conn_summary, indent=2), encoding="utf-8")
        print(f"[KRATOS-NET] Connection summary written -> {output_file}", flush=True)
        
        # Clean up pcap file
        if temp_pcap.exists():
            temp_pcap.unlink()
        
        return output_file
    except subprocess.TimeoutExpired:
        print(f"[KRATOS-NET] tcpdump timeout (expected after {duration_seconds}s)", flush=True)
        return None
    except Exception as e:
        print(f"[KRATOS-NET] Error capturing traffic: {e}", flush=True)
        return None


def _parse_pcap_to_summary(pcap_file: Path) -> list[dict[str, Any]]:
    """
    Parse tcpdump pcap file to connection summary.
    Uses tcpdump text output parsing.
    """
    connections = {}
    
    try:
        # Read pcap with tcpdump and parse text output
        cmd = ["tcpdump", "-nn", "-r", str(pcap_file)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        for line in result.stdout.split("\n"):
            parsed = _parse_tcpdump_line(line)
            if parsed:
                # Use (src_ip, dst_ip, dst_port, protocol) as key to aggregate
                key = (parsed["src_ip"], parsed["dst_ip"], parsed["dst_port"], parsed["protocol"])
                if key not in connections:
                    connections[key] = {
                        "src_ip": parsed["src_ip"],
                        "dst_ip": parsed["dst_ip"],
                        "dst_port": parsed["dst_port"],
                        "protocol": parsed["protocol"],
                        "packets": 0,
                    }
                connections[key]["packets"] += 1
        
        return list(connections.values())
    except Exception:
        return []


def read_conn_summary(file_path: Path) -> list[dict[str, Any]]:
    """
    Read pre-saved connection summary JSON file.
    """
    if not file_path.exists():
        return []
    
    try:
        data = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, list) else []
    except Exception:
        return []
