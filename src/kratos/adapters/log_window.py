from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _parse_dt(ts: str) -> datetime:
    """
    Parse timestamps produced by our pipeline.
    - ISO with timezone: 2026-02-01T18:54:52.363981+02:00
    - ISO without timezone (rare): 2026-02-01T18:54:52
    """
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def write_event_excerpt_from_events_file(
    data_dir: Path,
    events_file: Path,
    burst_event_type: str,
    burst_start: str,
    burst_end: str,
    minutes_before: int = 5,
    max_lines: int = 200,
) -> Path:
    """
    Uses normalized events (auth_events_*.json) and writes a raw-lines excerpt
    for the time window [start - minutes_before, end].
    """
    logs_dir = data_dir / "logs"
    excerpts_dir = logs_dir / "excerpts"
    excerpts_dir.mkdir(parents=True, exist_ok=True)

    events: list[dict[str, Any]] = json.loads(events_file.read_text(encoding="utf-8", errors="replace"))

    start_dt = _parse_dt(burst_start) - timedelta(minutes=minutes_before)
    end_dt = _parse_dt(burst_end)

    selected: list[str] = []
    for e in events:
        ts = e.get("timestamp")
        raw = e.get("raw")
        if not ts or not raw:
            continue
        try:
            dt = _parse_dt(ts)
        except Exception:
            continue
        if start_dt <= dt <= end_dt:
            selected.append(raw)

    if len(selected) > max_lines:
        selected = selected[-max_lines:]  # keep tail if too big

    safe_type = burst_event_type.replace("/", "_").replace(" ", "_")
    ts_out = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = excerpts_dir / f"excerpt_{safe_type}_{ts_out}.log"
    out_path.write_text("\n".join(selected) + ("\n" if selected else ""), encoding="utf-8")

    return out_path
