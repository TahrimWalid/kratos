"""A6.3 -- saved schedules (run a preset / the standard audit on a cadence).

A schedule is a named, reusable "run X every <cadence>, deliver the report"
definition. It is CONFIG ONLY -- it references a safe unit of work (the built-in
standard audit, or a saved goal preset by name) and a delivery channel; it can
NEVER carry inline commands/steps that act (design doc §6 "schedule stores a
PRESET only, never actions"). The actual cadence is owned by systemd user timers
(the decided mechanism) generated from this definition (see schedule_units.py);
the headless run itself is scheduled_run.py.

Storage copies presets.py exactly (the doc's §3 "pattern to copy for any new
store"): one TOML file per schedule at ``<data_dir>/schedules/<name>.toml``, read
via stdlib ``tomllib`` and written by a round-trip-verified serializer, atomic
(``tempfile`` + ``os.replace``), tolerant listing (one corrupt file never wedges
the list), slug/validation (traversal-safe, reserved words). Run history is kept
separately as an append-only JSONL ledger (``<name>.runs.jsonl``) so a run never
rewrites -- and so can never corrupt -- the definition.

The ``kind`` field is the runnable-unit selector, kept small and closed:
  * ``kind="audit"``  -> run the deterministic standard audit (run_pipeline)
  * ``kind="preset"`` -> run the named goal preset through the agentic loop
Anything else is parsed, listed, and shown, but declined at run time (the same
forward-compat contract presets.py uses).
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from kratos.utils.timeutil import utc_now_iso

# Runnable kinds this build supports. Closed set; anything else is declined.
RUNNABLE_KINDS = {"audit", "preset"}

# Named cadences -> systemd OnCalendar expressions. A small, closed, honestly-
# validatable set for the first slice (a raw OnCalendar override is a later
# refinement -- validating arbitrary OnCalendar strings correctly is real work).
CADENCE_ONCALENDAR = {
    "hourly": "hourly",
    "daily": "daily",
    "weekly": "weekly",
    "monthly": "monthly",
}

# Delivery channels this slice supports. Email/SMTP is a deliberately deferred
# later slice (new secret + privacy surface), so it is not a valid value yet.
DELIVERY_CHANNELS = {"ntfy"}

_SEVERITIES = ("info", "low", "medium", "high", "critical")

_RESERVED_NAMES = {
    "run", "list", "ls", "new", "add", "create", "edit", "update", "delete",
    "del", "rm", "remove", "show", "view", "help", "schedule", "schedules",
    "install", "uninstall", "run-now",
}

_MAX_NAME_LEN = 64
_SLUG_STRIP_RE = re.compile(r"[^a-z0-9_-]+")
_SLUG_COLLAPSE_RE = re.compile(r"-{2,}")


class ScheduleError(Exception):
    """A schedule couldn't be saved/loaded (invalid name, corrupt file, bad
    field). The message is user-facing (surfaced verbatim in the TUI)."""


@dataclass
class Schedule:
    name: str
    kind: str
    preset: Optional[str]           # required when kind == "preset"
    target: Optional[str]           # None -> resolve the active target at run time
    cadence: str                    # a key of CADENCE_ONCALENDAR
    deliver: list[str]              # subset of DELIVERY_CHANNELS
    min_severity: Optional[str]     # notify only if a finding >= this (None -> always)
    created_at: Optional[str]
    path: Path
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_runnable(self) -> bool:
        if self.kind not in RUNNABLE_KINDS:
            return False
        if self.kind == "preset":
            return bool(self.preset and self.preset.strip())
        return True

    @property
    def unsupported_reason(self) -> Optional[str]:
        if self.is_runnable:
            return None
        if self.kind not in RUNNABLE_KINDS:
            return (f"'{self.name}' has an unsupported kind '{self.kind}'. "
                    "Supported: 'audit' (standard audit) or 'preset' (a saved goal preset).")
        return f"'{self.name}' is a preset schedule but names no preset to run."

    @property
    def oncalendar(self) -> str:
        return CADENCE_ONCALENDAR.get(self.cadence, "weekly")

    @property
    def unit_name(self) -> str:
        """The systemd unit stem (without .service/.timer)."""
        return f"kratos-{self.name}"


# --------------------------------------------------------------------------- #
# Name handling (identical rules to presets.slugify/validate)
# --------------------------------------------------------------------------- #
def slugify_schedule_name(raw: str) -> str:
    s = (raw or "").strip().lower().replace(" ", "-")
    s = _SLUG_STRIP_RE.sub("-", s)
    s = _SLUG_COLLAPSE_RE.sub("-", s)
    return s.strip("-_")


def validate_schedule_name(raw: str) -> tuple[bool, str, Optional[str]]:
    canonical = slugify_schedule_name(raw)
    if not canonical:
        return False, "", "A schedule name must contain letters or digits."
    if len(canonical) > _MAX_NAME_LEN:
        return False, canonical, f"Schedule name too long (max {_MAX_NAME_LEN} characters)."
    if canonical in _RESERVED_NAMES:
        return False, canonical, f"'{canonical}' is a reserved word — pick a different name."
    return True, canonical, None


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def schedules_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "schedules"


_TOML_ESCAPES = {
    "\\": "\\\\", '"': '\\"', "\b": "\\b", "\t": "\\t",
    "\n": "\\n", "\f": "\\f", "\r": "\\r",
}


def _toml_basic_string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _TOML_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _toml_string_array(items: list[str]) -> str:
    return "[" + ", ".join(_toml_basic_string(i) for i in items) + "]"


def _dump_schedule_toml(
    *, name: str, kind: str, preset: Optional[str], target: Optional[str],
    cadence: str, deliver: list[str], min_severity: Optional[str],
    created_at: Optional[str],
) -> str:
    lines = [
        "# Kratos schedule — a saved 'run X on a cadence, deliver the report'.",
        "# CONFIG ONLY: it references a preset/audit + delivery; it never carries commands.",
        f"name = {_toml_basic_string(name)}",
        f"kind = {_toml_basic_string(kind)}",
        f"cadence = {_toml_basic_string(cadence)}",
        f"deliver = {_toml_string_array(deliver)}",
    ]
    if preset:
        lines.append(f"preset = {_toml_basic_string(preset)}")
    if target:
        lines.append(f"target = {_toml_basic_string(target)}")
    if min_severity:
        lines.append(f"min_severity = {_toml_basic_string(min_severity)}")
    if created_at:
        lines.append(f"created_at = {_toml_basic_string(created_at)}")
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _schedule_from_dict(data: dict[str, Any], path: Path, stem: str) -> Schedule:
    """Build a Schedule tolerantly (listing must survive odd files): missing
    name -> stem, missing kind -> 'audit', deliver coerced to a clean str list."""
    name = str(data.get("name") or stem)
    kind = str(data.get("kind") or "audit").strip().lower() or "audit"
    preset = str(data["preset"]) if data.get("preset") else None
    target = str(data["target"]) if data.get("target") else None
    cadence = str(data.get("cadence") or "weekly").strip().lower() or "weekly"
    deliver_raw = data.get("deliver")
    if isinstance(deliver_raw, list):
        deliver = [str(x).strip().lower() for x in deliver_raw if str(x).strip()]
    elif deliver_raw:
        deliver = [str(deliver_raw).strip().lower()]
    else:
        deliver = ["ntfy"]
    min_sev = str(data["min_severity"]).strip().lower() if data.get("min_severity") else None
    created_at = str(data["created_at"]) if data.get("created_at") else None
    return Schedule(name=name, kind=kind, preset=preset, target=target,
                    cadence=cadence, deliver=deliver, min_severity=min_sev,
                    created_at=created_at, path=path, raw=dict(data))


def schedule_exists(data_dir: Path, name: str) -> bool:
    ok, canonical, _ = validate_schedule_name(name)
    if not ok:
        return False
    return (schedules_dir(data_dir) / f"{canonical}.toml").exists()


def load_schedule(data_dir: Path, name: str) -> Optional[Schedule]:
    ok, canonical, _ = validate_schedule_name(name)
    if not ok:
        return None
    path = schedules_dir(data_dir) / f"{canonical}.toml"
    if not path.exists():
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ScheduleError(f"Schedule '{canonical}' is corrupt and couldn't be read: {e}")
    return _schedule_from_dict(data, path, canonical)


def list_schedules(data_dir: Path) -> tuple[list[Schedule], list[tuple[str, str]]]:
    """(valid schedules sorted by name, [(filename, error)]). Never raises -- a
    corrupt file becomes an error entry, never wedges the listing."""
    d = schedules_dir(data_dir)
    schedules: list[Schedule] = []
    errors: list[tuple[str, str]] = []
    if not d.exists():
        return schedules, errors
    for path in sorted(d.glob("*.toml")):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            schedules.append(_schedule_from_dict(data, path, path.stem))
        except Exception as e:  # noqa: BLE001 -- one bad file must not kill the list
            errors.append((path.name, str(e)))
    schedules.sort(key=lambda s: s.name)
    return schedules, errors


def save_schedule(
    data_dir: Path,
    *,
    name: str,
    kind: str = "audit",
    preset: Optional[str] = None,
    target: Optional[str] = None,
    cadence: str = "weekly",
    deliver: Optional[list[str]] = None,
    min_severity: Optional[str] = None,
    created_at: Optional[str] = None,
) -> Schedule:
    """Validate and atomically write a schedule, returning the reloaded object.
    Raises ScheduleError on any invalid field (the TUI surfaces the message)."""
    ok, canonical, err = validate_schedule_name(name)
    if not ok:
        raise ScheduleError(err or "Invalid schedule name.")
    kind = (kind or "audit").strip().lower()
    if kind not in RUNNABLE_KINDS:
        raise ScheduleError(f"Unsupported kind '{kind}'. Use 'audit' or 'preset'.")
    if kind == "preset" and not (preset and preset.strip()):
        raise ScheduleError("A preset schedule needs the name of a saved preset to run.")
    cadence = (cadence or "weekly").strip().lower()
    if cadence not in CADENCE_ONCALENDAR:
        raise ScheduleError(
            f"Unknown cadence '{cadence}'. Use one of: {', '.join(sorted(CADENCE_ONCALENDAR))}.")
    deliver = [d.strip().lower() for d in (deliver or ["ntfy"]) if d.strip()]
    bad = [d for d in deliver if d not in DELIVERY_CHANNELS]
    if bad:
        raise ScheduleError(
            f"Unsupported delivery channel(s): {', '.join(bad)}. Supported: {', '.join(sorted(DELIVERY_CHANNELS))}.")
    if not deliver:
        deliver = ["ntfy"]
    if min_severity is not None:
        min_severity = min_severity.strip().lower()
        if min_severity not in _SEVERITIES:
            raise ScheduleError(f"Unknown severity '{min_severity}'. Use one of: {', '.join(_SEVERITIES)}.")

    d = schedules_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{canonical}.toml"
    if path.resolve().parent != d.resolve():
        raise ScheduleError("Refusing to write a schedule outside the schedules directory.")

    text = _dump_schedule_toml(
        name=canonical, kind=kind, preset=(preset.strip() if preset else None),
        target=(target or None), cadence=cadence, deliver=deliver,
        min_severity=min_severity, created_at=(created_at or utc_now_iso()),
    )
    _atomic_write(path, text)
    reloaded = load_schedule(data_dir, canonical)
    assert reloaded is not None
    return reloaded


def delete_schedule(data_dir: Path, name: str) -> bool:
    """Delete the schedule definition (and its run ledger). Returns True if a
    definition file was removed. Does NOT touch installed systemd units -- the
    caller surfaces the uninstall command, since Kratos never runs systemctl."""
    ok, canonical, _ = validate_schedule_name(name)
    if not ok:
        return False
    path = schedules_dir(data_dir) / f"{canonical}.toml"
    if not path.exists():
        return False
    try:
        path.unlink()
    except OSError:
        return False
    ledger = _runs_ledger_path(data_dir, canonical)
    if ledger.exists():
        try:
            ledger.unlink()
        except OSError:
            pass
    return True


# --------------------------------------------------------------------------- #
# Run history (append-only JSONL, never rewrites the definition)
# --------------------------------------------------------------------------- #
def _runs_ledger_path(data_dir: Path, name: str) -> Path:
    return schedules_dir(data_dir) / f"{name}.runs.jsonl"


def append_run_record(data_dir: Path, name: str, record: dict[str, Any]) -> None:
    """Append one run record. Best-effort: a ledger write must never crash a run
    (a scheduled run's value is the report + notification, not the ledger)."""
    ok, canonical, _ = validate_schedule_name(name)
    if not ok:
        return
    d = schedules_dir(data_dir)
    try:
        d.mkdir(parents=True, exist_ok=True)
        with open(_runs_ledger_path(data_dir, canonical), "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except OSError:
        pass


def read_run_records(data_dir: Path, name: str, limit: Optional[int] = None) -> list[dict[str, Any]]:
    """Return this schedule's run records, newest last. Tolerant: a malformed
    line is skipped, never crashes the read."""
    ok, canonical, _ = validate_schedule_name(name)
    if not ok:
        return []
    path = _runs_ledger_path(data_dir, canonical)
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    if limit is not None and limit >= 0:
        records = records[-limit:]
    return records


def last_run_record(data_dir: Path, name: str) -> Optional[dict[str, Any]]:
    recs = read_run_records(data_dir, name, limit=1)
    return recs[-1] if recs else None
