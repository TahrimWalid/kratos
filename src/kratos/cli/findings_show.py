from __future__ import annotations

import json
from pathlib import Path

from kratos.utils.latest_file import latest_file


def _fmt_list(lines: list[str]) -> str:
    if not lines:
        return "  (none)"
    return "\n".join([f"  - {x}" for x in lines])


def cmd_findings_show(args) -> int:
    reports_dir = args.data_dir / "reports"
    latest = latest_file(reports_dir, "findings_*.json")
    if not latest:
        print("[KRATOS] No findings file found. Run: kratos findings-generate")
        return 1

    data = json.loads(latest.read_text(encoding="utf-8", errors="replace"))
    findings = data.get("findings") or []

    print(f"[KRATOS] Latest findings file: {latest.name}")
    print(f"Generated at: {data.get('generated_at')}")
    
    # Show context snapshot for traceability
    ctx_file = data.get("inputs", {}).get("system_context")
    if ctx_file:
        print(f"Context snapshot: {ctx_file}")
    
    print("")

    fid = getattr(args, "finding_id", None)

    if not fid:
        # existing summary behavior
        for f in findings:
            sev = (f.get("severity") or "info").upper()
            print(f"[{sev}] {f.get('id')} — {f.get('title')}")
        return 0

    # filter by ID
    match = None
    for f in findings:
        if f.get("id") == fid:
            match = f
            break

    if not match:
        print(f"[KRATOS] Finding ID not found: {fid}")
        ids = [f.get("id") for f in findings if f.get("id")]
        if ids:
            print("Available IDs:")
            for i in ids:
                print(f" - {i}")
        return 1

    sev = (match.get("severity") or "info").upper()
    print(f"[{sev}] {match.get('id')} — {match.get('title')}")
    print("")
    print("Evidence:")
    print(_fmt_list(match.get("evidence") or []))
    print("")
    print("Recommendations:")
    print(_fmt_list(match.get("recommendation") or []))
    
    # Display playbooks if present
    playbooks = match.get("playbooks") or []
    if playbooks:
        print("")
        print("Playbooks:")
        for idx, pb in enumerate(playbooks, start=1):
            print(f"  [{idx}] {pb.get('title', 'Untitled')}")
            for cmd in pb.get('commands', []):
                print(f"    - {cmd}")
            for note in pb.get('notes', []):
                print(f"    note: {note}")
    
    return 0
