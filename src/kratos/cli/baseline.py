from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from kratos.adapters.baseline import (
    build_current_snapshot,
    save_baseline,
    load_latest_baseline,
    diff_baseline,
)


def cmd_baseline_create(args) -> int:
    snap = build_current_snapshot(args.data_dir)
    out = save_baseline(args.data_dir, snap)
    print(f"[KRATOS] Baseline saved -> {out}")
    return 0


def cmd_baseline_compare(args) -> int:
    base_path, base = load_latest_baseline(args.data_dir)
    if not base_path or not base:
        print("[KRATOS] No baseline found. Create one first: kratos baseline-create")
        return 1

    cur = build_current_snapshot(args.data_dir)
    diff = diff_baseline(base, cur)

    reports_dir = args.data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    out_json = reports_dir / f"baseline_compare_{ts}.json"
    out_md = reports_dir / f"baseline_compare_{ts}.md"

    out_json.write_text(json.dumps({
        "baseline_file": base_path.name,
        "current_inputs": cur.inputs,
        "diff": diff
    }, indent=2), encoding="utf-8")

    # simple markdown
    md_lines = []
    md_lines.append("# Kratos Baseline Compare")
    md_lines.append("")
    md_lines.append(f"- Baseline file: {base_path.name}")
    md_lines.append(f"- Baseline created: {diff['baseline_created_at']}")
    md_lines.append(f"- Compared at: {diff['current_created_at']}")
    md_lines.append(f"- Environment: {diff['environment']['baseline']} -> {diff['environment']['current']}")
    md_lines.append("")
    md_lines.append("## Counts (baseline → current)")
    md_lines.append("")
    counts = diff.get("counts", {})
    sudo_counts = counts.get("sudo_members", {"baseline": 0, "current": 0})
    service_counts = counts.get("active_services", {"baseline": 0, "current": 0})
    port_counts = counts.get("open_ports", {"baseline": 0, "current": 0})
    
    md_lines.append(f"- Sudo members: {sudo_counts['baseline']} → {sudo_counts['current']}")
    md_lines.append(f"- Active services: {service_counts['baseline']} → {service_counts['current']}")
    md_lines.append(f"- Open ports: {port_counts['baseline']} → {port_counts['current']}")
    md_lines.append("")
    md_lines.append("## Changes")
    md_lines.append("")
    md_lines.append("### Sudo members")
    md_lines.append(f"- Added: {', '.join(diff['sudo_members']['added']) or 'None'}")
    md_lines.append(f"- Removed: {', '.join(diff['sudo_members']['removed']) or 'None'}")
    md_lines.append("")
    md_lines.append("### Active services")
    md_lines.append(f"- Added: {', '.join(diff['active_services']['added']) or 'None'}")
    md_lines.append(f"- Removed: {', '.join(diff['active_services']['removed']) or 'None'}")
    md_lines.append("")
    md_lines.append("### Open ports")
    added_ports = diff["open_ports"]["added"]
    removed_ports = diff["open_ports"]["removed"]

    if not added_ports and not removed_ports:
        md_lines.append("- No changes in open ports detected.")
    else:
        if added_ports:
            md_lines.append("**Added**")
            for host, ports in added_ports.items():
                md_lines.append(f"- {host}:")
                for p in ports:
                    md_lines.append(f"  - {p}")
        if removed_ports:
            md_lines.append("")
            md_lines.append("**Removed**")
            for host, ports in removed_ports.items():
                md_lines.append(f"- {host}:")
                for p in ports:
                    md_lines.append(f"  - {p}")

    md_lines.append("")
    md_lines.append("### Service state changes")
    service_state_changes = diff.get("service_state_changes", [])
    if not service_state_changes:
        md_lines.append("- None")
    else:
        for change in service_state_changes:
            unit = change["unit"]
            base = change["baseline"]
            cur = change["current"]
            base_str = f"{base.get('active', '?')}/{base.get('sub', '?')}"
            cur_str = f"{cur.get('active', '?')}/{cur.get('sub', '?')}"
            md_lines.append(f"- {unit}: {base_str} → {cur_str}")

    out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"[KRATOS] Baseline compared -> {out_json}")
    print(f"[KRATOS] Report written     -> {out_md}")
    return 0
