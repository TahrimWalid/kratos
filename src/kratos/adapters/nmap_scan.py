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

    # The status line AND nmap's own human-readable report both go to STDERR,
    # never stdout. Under the MCP stdio server (`kratos mcp-serve`) the process's
    # stdout (fd 1) IS the JSON-RPC channel to the client, and a subprocess with
    # no `stdout=` inherits that fd directly -- so nmap's scan report (which is
    # NOT captured by `-oX`; that only writes the XML file) would be flushed onto
    # the protocol stream, interleaving with JSON-RPC responses (flooding the
    # client with parse errors and, worst case, hanging it). Only the -oX XML is
    # ever consumed downstream; the human-readable output is purely informational,
    # so routing it to stderr keeps it visible in the CLI/REPL while leaving fd 1
    # clean. stderr is safe -- it is never the protocol channel (FastMCP's own
    # logs already go there).
    print(f"[KRATOS] Running: {' '.join(cmd)}", file=sys.stderr)
    try:
        subprocess.run(cmd, check=True, stdout=sys.stderr)
    except FileNotFoundError as e:
        raise RuntimeError("nmap not found. Install with: sudo apt install nmap") from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"nmap failed with exit code {e.returncode}") from e

    return out_xml
