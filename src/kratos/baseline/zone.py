"""The machine's time zone, for learning sign-in hours in machine time (E.3 §3.9).

No routine collection read tells Kratos a journald machine's zone: the sign-in measurement
prints it only in its classic-log part, journal sync never does, and the scripts that could
are shared with the agent bundle. Two Kratos-side reads do say it, in one row each:

- the SSH config audit, which Kratos runs with one fixed line appended for this
  (`ssh_remote.run_config_audit_checks`; every config audit, 6 h freshness), and
- the setup probe (onboarding, `/target verify`, `/doctor`; over SSH and through the
  sub-agent's `capabilities` probe), whose zone is saved here when it runs.

Both rows read "Target system timezone: <zone> (...)" or "Box timezone: <zone> (...)";
`parse_row` is the only place that text is read. The zone is accepted only when it names a
real IANA zone (or a +HHMM offset): text from the machine never becomes anything else.

Order (`for_hours`): the zone the measurement itself read; else the config audit's; else the
setup probe's; else UTC, labelled as assumed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any

from kratos.target_key import target_key

ASSUMED_UTC = "UTC (assumed)"
_UTC_NAMES = {"utc", "etc/utc", "etc/universal", "universal", "zulu", "etc/zulu", "gmt", "etc/gmt", "+0000",
              ASSUMED_UTC.lower()}
_ROW = re.compile(r"\b(?:Box|Target system) timezone:\s*(\S+)")
_OFFSET = re.compile(r"([+-])(\d\d)(\d\d)")
PROBE_FOLDER = "context"
PROBE_PATTERN = "machine_zone_*.json"
ROW_CHECK = "target_timezone"

# Appended by Kratos to the SSH config-audit script (not part of the shared script, so the
# agent bundle is unchanged). Same wording as the setup probe's row.
SSH_ROW_SH = ("tz_name=\"$( (timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || "
              "readlink /etc/localtime 2>/dev/null | sed 's|.*zoneinfo/||') | head -n 1)\"\n"
              "printf 'target_timezone\\tINFO\\tTarget system timezone: %s (journald log timestamps are stored as "
              "absolute UTC regardless)\\n' \"${tz_name:-unknown}\"\n")


@dataclass(frozen=True)
class Zone:
    tz: tzinfo
    name: str
    assumed: bool
    source: str                   # measurement | config_audit | setup_probe | assumed
    captured_at: float | None     # when the read that named it was taken


def same_zone(a: str | None, b: str | None) -> bool:
    """Two zone names that give the same hours: equal, or both UTC (the assumed UTC included)."""
    a, b = str(a or "").strip().lower(), str(b or "").strip().lower()
    return a == b or (a in _UTC_NAMES and b in _UTC_NAMES)


def resolve(name: Any) -> tzinfo | None:
    """A tzinfo for a real zone name or a +HHMM offset; None for anything else."""
    from kratos.utils.timeutil import zone_from_name

    text = str(name or "").strip()
    if not text or text.lower() == "unknown" or len(text) > 64:
        return None
    m = _OFFSET.fullmatch(text)
    if m:
        sign = -1 if m.group(1) == "-" else 1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
    return zone_from_name(text)


def parse_row(detail: Any) -> str | None:
    """The zone a target_timezone row names (either wording), or None for 'unknown', empty or
    anything that isn't a real zone."""
    m = _ROW.search(str(detail or ""))
    if not m:
        return None
    name = m.group(1).strip()
    return name if resolve(name) is not None else None


def zone_of_rows(rows: Any) -> str | None:
    for r in rows or []:
        if isinstance(r, dict) and r.get("check") == ROW_CHECK:
            return parse_row(r.get("detail"))
    return None


def probe_path(data_dir: Path | str, target: str) -> Path:
    return (Path(data_dir) / PROBE_FOLDER /
            f"machine_zone_{hashlib.sha256(target_key(target).encode()).hexdigest()[:8]}.json")


def save_probe_zone(data_dir: Path | str | None, target: str, rows: Any, *, now: float | None = None) -> Path | None:
    """Keep the zone the setup probe read (one small file per machine, replaced in place)."""
    if data_dir is None or not target:
        return None
    name = zone_of_rows(rows)
    if name is None:
        return None
    now = time.time() if now is None else now
    path = probe_path(data_dir, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"target": target_key(target), "zone": name, "source": "setup_probe",
                               "captured_at_epoch": now}), encoding="utf-8")
    os.replace(tmp, path)
    from kratos import evidence as _evidence

    _evidence.record(path, data_dir=Path(data_dir), category="machine_zone", machine=target, read="setup_probe",
                     transport=None)
    return path


def _read(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _from_measurement(inputs: dict[str, Any]) -> tuple[str, float | None] | None:
    doc = _read(inputs.get("auth_stats"))
    tz = (doc or {}).get("target_timezone")
    if not isinstance(tz, dict):
        return None
    for value in (tz.get("name"), tz.get("offset")):
        if resolve(value) is not None:
            return str(value).strip(), None
    return None


def _from_config_audit(inputs: dict[str, Any]) -> tuple[str, float | None] | None:
    doc = _read(inputs.get("config_audit"))
    if not doc:
        return None
    name = doc.get("zone") if resolve(doc.get("zone")) is not None else zone_of_rows(doc.get("checks"))
    if not name:
        return None
    return str(name), float(doc.get("collected_at_epoch") or 0) or None


def _from_probe(data_dir: Path, target: str) -> tuple[str, float | None] | None:
    doc = _read(probe_path(data_dir, target))
    if not doc or target_key(str(doc.get("target") or "")) != target_key(target) or resolve(doc.get("zone")) is None:
        return None
    return str(doc["zone"]), float(doc.get("captured_at_epoch") or 0) or None


def for_hours(data_dir: Path | str, target: str) -> Zone:
    """The zone sign-in hours are learned in (see the module doc for the order)."""
    from kratos.adapters.findings_engine import find_latest_inputs

    data_dir = Path(data_dir)
    inputs = find_latest_inputs(data_dir, target)
    for source, found in (("measurement", _from_measurement(inputs)), ("config_audit", _from_config_audit(inputs)),
                          ("setup_probe", _from_probe(data_dir, target))):
        if found is not None:
            tz = resolve(found[0])
            if tz is not None:
                return Zone(tz, found[0], False, source, found[1])
    return Zone(timezone.utc, ASSUMED_UTC, True, "assumed", None)
