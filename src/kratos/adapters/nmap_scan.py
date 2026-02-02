from __future__ import annotations

import subprocess
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

    cmd = ["nmap", "-sV", "-oX", str(out_xml), target]

    print(f"[KRATOS] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError as e:
        raise RuntimeError("nmap not found. Install with: sudo apt install nmap") from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"nmap failed with exit code {e.returncode}") from e

    return out_xml
