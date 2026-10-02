"""A6.4 -- triggers store (if condition X is detected, do action Y).

A trigger is a named rule evaluated against the STRUCTURED findings a run produces
(a scheduled run, or an interactive /run) -- NEVER a regex over attacker-influenced
raw text (design doc §7 "untrusted-data triggers"; the same separation A6.2's
playbooks enforce). Its condition keys on the deterministic findings engine's own
output: a severity threshold and/or a specific finding-ID. Its action is
recommend/notify/investigate ONLY -- never target execution (INVARIANT 1; the
"act temptation is highest here" hard-gate).

Decoupled from schedules (owner decision, 2026-09-10): triggers are their own
store, evaluated against ANY run's findings, with an optional target filter -- not
a sub-field of one schedule. The evaluation itself rides the existing scheduled-run
cadence (no new daemon); see trigger_eval.py.

Storage copies schedules.py / presets.py exactly (TOML file-per-item, atomic
write, tolerant listing, slug/validation). Fire history is an append-only JSONL
ledger (``<name>.fired.jsonl``) used for cooldown/dedupe -- it never rewrites the
definition.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: the same parser, from the tomli backport
    import tomli as tomllib  # type: ignore[no-redef]
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from kratos.utils.timeutil import utc_now_iso

# What a matched trigger DOES. All recommend/notify/read-only -- never execution.
#   notify      -> a sharp, condition-specific ntfy alert
#   playbook    -> the alert PLUS the A6.2 IR response plan for the matched finding
#   investigate -> launch a deeper READ-ONLY agentic investigation (headless,
#                  approval-gated tools excluded), then notify its conclusion
ACTIONS = {"notify", "playbook", "investigate"}

_SEVERITIES = ("info", "low", "medium", "high", "critical")

# Named cooldowns (minutes) -> keeps a persistent condition from paging every run
# (design doc §7 debounce/cooldown). A closed set for the guided UI; any int is
# accepted by save_trigger for hand-authored files.
COOLDOWN_CHOICES = {"15m": 15, "1h": 60, "6h": 360, "24h": 1440}
DEFAULT_COOLDOWN_MINUTES = 60

_RESERVED_NAMES = {
    "run", "list", "ls", "new", "add", "create", "edit", "update", "delete",
    "del", "rm", "remove", "show", "view", "help", "trigger", "triggers", "test",
}

_MAX_NAME_LEN = 64
_SLUG_STRIP_RE = re.compile(r"[^a-z0-9_-]+")
_SLUG_COLLAPSE_RE = re.compile(r"-{2,}")
# A finding-ID looks like NET-002 / CORR-SSH-001 -- letters/digits/dash only. Used
# only to reject obvious junk at save time, never to parse untrusted data.
_FINDING_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{1,39}$")


class TriggerError(Exception):
    """A trigger couldn't be saved/loaded (invalid name/condition/action). The
    message is user-facing."""


@dataclass
class Trigger:
    name: str
    min_severity: Optional[str]     # fire if any finding >= this
    finding_id: Optional[str]       # fire if a finding with this ID is present
    target: Optional[str]           # only evaluate for runs on this target (None = any)
    action: str                     # one of ACTIONS
    cooldown_minutes: int
    created_at: Optional[str]
    path: Path
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        if self.action not in ACTIONS:
            return False
        return bool(self.min_severity or self.finding_id)

    @property
    def condition_text(self) -> str:
        parts = []
        if self.finding_id:
            parts.append(f"finding {self.finding_id}")
        if self.min_severity:
            parts.append(f"severity ≥ {self.min_severity}")
        return " and ".join(parts) if parts else "(no condition — never fires)"


# --------------------------------------------------------------------------- #
# Name handling
# --------------------------------------------------------------------------- #
def slugify_trigger_name(raw: str) -> str:
    s = (raw or "").strip().lower().replace(" ", "-")
    s = _SLUG_STRIP_RE.sub("-", s)
    s = _SLUG_COLLAPSE_RE.sub("-", s)
    return s.strip("-_")


def validate_trigger_name(raw: str) -> tuple[bool, str, Optional[str]]:
    canonical = slugify_trigger_name(raw)
    if not canonical:
        return False, "", "A trigger name must contain letters or digits."
    if len(canonical) > _MAX_NAME_LEN:
        return False, canonical, f"Trigger name too long (max {_MAX_NAME_LEN} characters)."
    if canonical in _RESERVED_NAMES:
        return False, canonical, f"'{canonical}' is a reserved word — pick a different name."
    return True, canonical, None


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def triggers_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "triggers"


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


def _dump_trigger_toml(
    *, name: str, min_severity: Optional[str], finding_id: Optional[str],
    target: Optional[str], action: str, cooldown_minutes: int,
    created_at: Optional[str],
) -> str:
    lines = [
        "# Kratos trigger — 'if a matching finding is detected, do <action>'.",
        "# RECOMMEND/NOTIFY/READ-ONLY only. Keyed on structured findings, never raw text.",
        f"name = {_toml_basic_string(name)}",
        f"action = {_toml_basic_string(action)}",
        f"cooldown_minutes = {int(cooldown_minutes)}",
    ]
    if min_severity:
        lines.append(f"min_severity = {_toml_basic_string(min_severity)}")
    if finding_id:
        lines.append(f"finding_id = {_toml_basic_string(finding_id)}")
    if target:
        lines.append(f"target = {_toml_basic_string(target)}")
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


def _trigger_from_dict(data: dict[str, Any], path: Path, stem: str) -> Trigger:
    name = str(data.get("name") or stem)
    action = str(data.get("action") or "notify").strip().lower() or "notify"
    min_sev = str(data["min_severity"]).strip().lower() if data.get("min_severity") else None
    fid = str(data["finding_id"]).strip() if data.get("finding_id") else None
    target = str(data["target"]) if data.get("target") else None
    try:
        cooldown = int(data.get("cooldown_minutes", DEFAULT_COOLDOWN_MINUTES))
    except (TypeError, ValueError):
        cooldown = DEFAULT_COOLDOWN_MINUTES
    created_at = str(data["created_at"]) if data.get("created_at") else None
    return Trigger(name=name, min_severity=min_sev, finding_id=fid, target=target,
                   action=action, cooldown_minutes=max(0, cooldown),
                   created_at=created_at, path=path, raw=dict(data))


def trigger_exists(data_dir: Path, name: str) -> bool:
    ok, canonical, _ = validate_trigger_name(name)
    if not ok:
        return False
    return (triggers_dir(data_dir) / f"{canonical}.toml").exists()


def load_trigger(data_dir: Path, name: str) -> Optional[Trigger]:
    ok, canonical, _ = validate_trigger_name(name)
    if not ok:
        return None
    path = triggers_dir(data_dir) / f"{canonical}.toml"
    if not path.exists():
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise TriggerError(f"Trigger '{canonical}' is corrupt and couldn't be read: {e}")
    return _trigger_from_dict(data, path, canonical)


def list_triggers(data_dir: Path) -> tuple[list[Trigger], list[tuple[str, str]]]:
    """(valid triggers sorted by name, [(filename, error)]). Never raises."""
    d = triggers_dir(data_dir)
    triggers: list[Trigger] = []
    errors: list[tuple[str, str]] = []
    if not d.exists():
        return triggers, errors
    for path in sorted(d.glob("*.toml")):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            triggers.append(_trigger_from_dict(data, path, path.stem))
        except Exception as e:  # noqa: BLE001
            errors.append((path.name, str(e)))
    triggers.sort(key=lambda t: t.name)
    return triggers, errors


def save_trigger(
    data_dir: Path,
    *,
    name: str,
    action: str = "notify",
    min_severity: Optional[str] = None,
    finding_id: Optional[str] = None,
    target: Optional[str] = None,
    cooldown_minutes: int = DEFAULT_COOLDOWN_MINUTES,
    created_at: Optional[str] = None,
) -> Trigger:
    ok, canonical, err = validate_trigger_name(name)
    if not ok:
        raise TriggerError(err or "Invalid trigger name.")
    action = (action or "notify").strip().lower()
    if action not in ACTIONS:
        raise TriggerError(f"Unknown action '{action}'. Use one of: {', '.join(sorted(ACTIONS))}.")
    if min_severity is not None:
        min_severity = min_severity.strip().lower()
        if min_severity not in _SEVERITIES:
            raise TriggerError(f"Unknown severity '{min_severity}'. Use one of: {', '.join(_SEVERITIES)}.")
    if finding_id is not None:
        finding_id = finding_id.strip().upper()
        if not _FINDING_ID_RE.match(finding_id):
            raise TriggerError(
                "A finding-ID looks like 'CORR-SSH-001' or 'NET-002' (letters, digits, dashes).")
    if not (min_severity or finding_id):
        raise TriggerError("A trigger needs a condition: a severity threshold and/or a finding-ID.")
    try:
        cooldown_minutes = max(0, int(cooldown_minutes))
    except (TypeError, ValueError):
        raise TriggerError("Cooldown must be a whole number of minutes.")

    d = triggers_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{canonical}.toml"
    if path.resolve().parent != d.resolve():
        raise TriggerError("Refusing to write a trigger outside the triggers directory.")

    text = _dump_trigger_toml(
        name=canonical, min_severity=min_severity, finding_id=finding_id,
        target=(target or None), action=action, cooldown_minutes=cooldown_minutes,
        created_at=(created_at or utc_now_iso()),
    )
    _atomic_write(path, text)
    reloaded = load_trigger(data_dir, canonical)
    assert reloaded is not None
    return reloaded


def delete_trigger(data_dir: Path, name: str) -> bool:
    ok, canonical, _ = validate_trigger_name(name)
    if not ok:
        return False
    path = triggers_dir(data_dir) / f"{canonical}.toml"
    if not path.exists():
        return False
    try:
        path.unlink()
    except OSError:
        return False
    fired = _fired_ledger_path(data_dir, canonical)
    if fired.exists():
        try:
            fired.unlink()
        except OSError:
            pass
    return True


# --------------------------------------------------------------------------- #
# Fire history (append-only; drives cooldown/dedupe)
# --------------------------------------------------------------------------- #
def _fired_ledger_path(data_dir: Path, name: str) -> Path:
    return triggers_dir(data_dir) / f"{name}.fired.jsonl"


def append_fire_record(data_dir: Path, name: str, record: dict[str, Any]) -> None:
    ok, canonical, _ = validate_trigger_name(name)
    if not ok:
        return
    d = triggers_dir(data_dir)
    try:
        d.mkdir(parents=True, exist_ok=True)
        with open(_fired_ledger_path(data_dir, canonical), "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except OSError:
        pass


def read_fire_records(data_dir: Path, name: str, limit: Optional[int] = None) -> list[dict[str, Any]]:
    ok, canonical, _ = validate_trigger_name(name)
    if not ok:
        return []
    path = _fired_ledger_path(data_dir, canonical)
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


def last_fire_record(data_dir: Path, name: str) -> Optional[dict[str, Any]]:
    recs = read_fire_records(data_dir, name, limit=1)
    return recs[-1] if recs else None
