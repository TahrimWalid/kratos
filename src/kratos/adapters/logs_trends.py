from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class TrendPoint:
    file: str
    generated_at: str | None
    auth_failure_total: int
    sudo_auth_failure: int
    sudo_pam_auth_failure: int
    ssh_failed_login: int


def _safe_int(x: Any) -> int:
    try:
        return int(x)
    except Exception:
        return 0


def _extract_counts(stats: dict[str, Any]) -> tuple[int, int, int]:
    """
    Returns: (sudo_auth_failure, sudo_pam_auth_failure, ssh_failed_login)
    """
    by_type = stats.get("events_by_type", {}) or {}
    sudo_auth_failure = _safe_int(by_type.get("sudo_auth_failure", 0))
    sudo_pam_auth_failure = _safe_int(by_type.get("sudo_pam_auth_failure", 0))
    ssh_failed_login = _safe_int(by_type.get("ssh_failed_login", 0))
    return sudo_auth_failure, sudo_pam_auth_failure, ssh_failed_login


def _direction(first: int, last: int) -> str:
    if last > first:
        return "increasing"
    if last < first:
        return "decreasing"
    return "stable"


def build_auth_trends_report(
    data_dir: Path,
    last_n: int = 5,
    min_delta: int = 2,
) -> tuple[Path, Path, dict[str, Any]]:
    logs_dir = data_dir / "logs"
    reports_dir = data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    stat_files = sorted(logs_dir.glob("auth_stats_*.json"))
    if len(stat_files) < 2:
        raise RuntimeError(f"Not enough auth_stats files for trends (found {len(stat_files)}). Run logs-parse a few times first.")

    chosen = stat_files[-last_n:]

    points: list[TrendPoint] = []
    for f in chosen:
        stats = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        sudo_auth, sudo_pam, ssh_fail = _extract_counts(stats)
        total = sudo_auth + sudo_pam + ssh_fail
        points.append(
            TrendPoint(
                file=f.name,
                generated_at=stats.get("generated_at"),  # may or may not exist
                auth_failure_total=total,
                sudo_auth_failure=sudo_auth,
                sudo_pam_auth_failure=sudo_pam,
                ssh_failed_login=ssh_fail,
            )
        )

    series = [p.auth_failure_total for p in points]
    first = series[0]
    last = series[-1]
    delta = last - first
    direction = _direction(first, last)

    # conservative trigger condition for your optional thesis finding
    trigger = bool(delta >= min_delta)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_json = reports_dir / f"auth_trends_{ts}.json"
    out_md = reports_dir / f"auth_trends_{ts}.md"

    report: dict[str, Any] = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "inputs": {
            "stats_files": [p.file for p in points],
            "last_n": last_n,
            "min_delta": min_delta,
        },
        "series": [asdict(p) for p in points],
        "summary": {
            "direction": direction,
            "first": first,
            "last": last,
            "delta": delta,
            "files_compared": len(points),
            "trigger_auth_trend_001": trigger,
        },
    }

    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    out_md.write_text(_render_md(report), encoding="utf-8")
    return out_json, out_md, report


def _render_md(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = []
    lines.append("# Kratos Auth Trends")
    lines.append("")
    lines.append(f"- Generated at: {report['generated_at']}")
    lines.append(f"- Files used: {len(report['inputs']['stats_files'])}")
    lines.append(f"- Direction: **{summary['direction']}**")
    lines.append(f"- Delta (last - first): **{summary['delta']}**")
    lines.append(f"- Trigger AUTH-TREND-001: **{summary['trigger_auth_trend_001']}**")
    lines.append("")
    lines.append("## Series (oldest → newest)")
    lines.append("")
    lines.append("| file | total | sudo_auth | sudo_pam | ssh_failed |")
    lines.append("|---|---:|---:|---:|---:|")
    for p in report["series"]:
        lines.append(
            f"| {p['file']} | {p['auth_failure_total']} | {p['sudo_auth_failure']} | {p['sudo_pam_auth_failure']} | {p['ssh_failed_login']} |"
        )
    lines.append("")
    return "\n".join(lines)
