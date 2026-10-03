"""Runs an nmap scan and saves the raw XML.

The thin wrapper around invoking nmap itself: scan a target, drop the XML under
`data_dir/scans/`, hand back the path. Parsing that XML into something usable is
`nmap_parse`'s job, kept separate so a re-parse never needs a re-scan.
"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime
from pathlib import Path


def run_nmap_scan(data_dir: Path, target: str) -> Path:
    """
    Run an Nmap scan against `target` and save XML output under data_dir/scans/.
    Returns the path to the created XML file.
    """
    scans_dir = data_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    out_xml = scans_dir / f"nmap_{safe_target}_{ts}.xml"

    # -Pn: skip host-discovery ping probes and treat the target as up. Without
    # this, a firewalled target that drops ICMP/discovery probes but has real
    # listening TCP ports (e.g. ufw default-deny-incoming with only 22/tcp
    # allowed) is reported as "0 hosts up" -- a false-negative empty scan,
    # not an accurate "nothing exposed" result. Harmless against a host that
    # does respond to discovery probes; -sV still probes exactly the same.
    cmd = ["nmap", "-sV", "-Pn", "-oX", str(out_xml), target]

    # nmap's human-readable report is captured, then re-printed to sys.stderr from
    # Python -- never left on an inherited file descriptor:
    #  * under the MCP stdio server (`kratos mcp-serve`) fd 1 IS the JSON-RPC channel,
    #    so an inherited stdout would interleave the report with protocol messages;
    #  * inside the full-screen TUI, Textual replaces sys.stderr with a capture
    #    object whose fileno() is -1, which subprocess reads as "don't redirect":
    #    the report then went straight to the real terminal, over the interface.
    # Printing through sys.stderr keeps it visible on the command line, on stderr
    # for MCP, and swallowed by the TUI. Only the -oX XML is consumed downstream.
    print(f"[KRATOS] Running: {' '.join(cmd)}", file=sys.stderr)
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True, errors="replace")
    except FileNotFoundError as e:
        raise RuntimeError("nmap not found. Install with: sudo apt install nmap") from e
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or "").strip().splitlines()[-1:] or [""]
        raise RuntimeError(f"nmap failed with exit code {e.returncode}" + (f": {detail[0]}" if detail[0] else "")) from e
    report = (proc.stdout or "") + (proc.stderr or "")
    if report.strip():
        print(report.rstrip(), file=sys.stderr)

    return out_xml
