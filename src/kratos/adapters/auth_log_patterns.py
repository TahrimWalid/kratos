from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from kratos.adapters.log_window import write_event_excerpt_from_events_file


def find_latest_auth_events_json(data_dir: Path) -> Path | None:
    logs_dir = data_dir / "logs"
    files = sorted(logs_dir.glob("auth_events_*.json"), reverse=True)
    return files[0] if files else None


def _parse_iso(ts: str) -> datetime | None:
    """
    Parse timestamps like:
      - 2026-02-01T18:56:57.976846+02:00
      - 2026-02-01T18:56:57+02:00
      - 2026-02-01T18:56:57
    Returns datetime or None if unparseable.
    """
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _detect_bursts(
    events: list[dict[str, Any]],
    event_type: str,
    window: timedelta,
    threshold: int,
) -> list[dict[str, Any]]:
    """
    Sliding-window burst detection:
    - Consider only events of `event_type`
    - Sort by timestamp
    - A burst is any window with >= threshold events
    - Merge overlapping windows into a single burst range
    """
    # Filter and parse times
    filtered: list[tuple[datetime, dict[str, Any]]] = []
    for e in events:
        if e.get("event_type") != event_type:
            continue
        dt = _parse_iso(str(e.get("timestamp", "")))
        if dt is None:
            continue
        filtered.append((dt, e))

    filtered.sort(key=lambda x: x[0])
    times = [t for t, _ in filtered]

    bursts: list[dict[str, Any]] = []
    n = len(times)
    if n == 0:
        return bursts

    # Find candidate windows
    i = 0
    while i < n:
        j = i
        while j < n and (times[j] - times[i]) <= window:
            j += 1

        count = j - i
        if count >= threshold:
            start = times[i]
            end = times[j - 1]

            # Collect metadata in this window
            window_events = [filtered[k][1] for k in range(i, j)]
            users = [we.get("user") for we in window_events if we.get("user")]
            ips = [we.get("source_ip") for we in window_events if we.get("source_ip")]

            burst = {
                "event_type": event_type,
                "start": start.isoformat(),
                "end": end.isoformat(),
                "count": count,
                "top_users": [{"user": u, "count": c} for u, c in Counter(users).most_common(5)],
                "top_source_ips": [{"ip": ip, "count": c} for ip, c in Counter(ips).most_common(5)],
            }

            # Merge if overlaps with previous burst
            if bursts and bursts[-1]["event_type"] == event_type:
                prev_start = _parse_iso(bursts[-1]["start"])  # should parse
                prev_end = _parse_iso(bursts[-1]["end"])
                if prev_start and prev_end and start <= (prev_end + timedelta(seconds=1)):
                    # merge range + counts; recompute top lists by extending
                    bursts[-1]["end"] = max(prev_end, end).isoformat()
                    bursts[-1]["count"] = bursts[-1]["count"] + count

                    # Merge top users/ips approximately by combining counters
                    prev_users = {d["user"]: d["count"] for d in bursts[-1]["top_users"]}
                    prev_ips = {d["ip"]: d["count"] for d in bursts[-1]["top_source_ips"]}

                    for u, c in Counter(users).items():
                        prev_users[u] = prev_users.get(u, 0) + c
                    for ip, c in Counter(ips).items():
                        prev_ips[ip] = prev_ips.get(ip, 0) + c

                    bursts[-1]["top_users"] = [{"user": u, "count": c} for u, c in Counter(prev_users).most_common(5)]
                    bursts[-1]["top_source_ips"] = [{"ip": ip, "count": c} for ip, c in Counter(prev_ips).most_common(5)]
                else:
                    bursts.append(burst)
            else:
                bursts.append(burst)

            # Move i forward to avoid producing tons of overlapping bursts
            i = j
        else:
            i += 1

    return bursts


def analyze_auth_patterns(
    data_dir: Path,
    events_file: Path | None = None,
    event_types: list[str] | None = None,
    window_minutes: int = 5,
    threshold: int = 3,
) -> Path:
    """
    Loads auth events JSON and writes a patterns JSON:
      data/logs/auth_patterns_<ts>.json
    """
    if event_types is None:
        event_types = ["sudo_pam_auth_failure", "sudo_auth_failure", "ssh_failed_login"]

    if events_file is None:
        events_file = find_latest_auth_events_json(data_dir)

    if events_file is None or not events_file.exists():
        raise RuntimeError("No auth_events_*.json found. Run: kratos logs-parse")

    events = json.loads(events_file.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(events, list):
        raise RuntimeError(f"Invalid events JSON format: {events_file}")

    window = timedelta(minutes=window_minutes)

    bursts_all: list[dict[str, Any]] = []
    for et in event_types:
        bursts_all.extend(_detect_bursts(events, et, window, threshold))

    # Generate context excerpts for each burst
    for burst in bursts_all:
        # rolling window excerpt (previous N minutes)
        excerpt_path = write_event_excerpt_from_events_file(
            data_dir=data_dir,
            events_file=events_file,
            burst_event_type=burst["event_type"],
            burst_start=burst["start"],
            burst_end=burst["end"],
            minutes_before=window_minutes,
        )
        burst["context_minutes_before"] = window_minutes
        burst["context_excerpt_file"] = excerpt_path.name

    patterns = {
        "source_events_file": events_file.name,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "params": {
            "window_minutes": window_minutes,
            "threshold": threshold,
            "event_types": event_types,
        },
        "bursts": bursts_all,
    }

    logs_dir = data_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = logs_dir / f"auth_patterns_{ts}.json"
    out.write_text(json.dumps(patterns, indent=2), encoding="utf-8")
    return out
