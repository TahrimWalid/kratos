"""Saved investigation presets (A2 Tier 1) + the forward-compatible schema.

A preset is a named, reusable, user-authored investigation. Tier 1 (this module)
stores **named natural-language goals** run through the agentic `run_agent()`
loop; the schema and every reader are built so comprehensive A2 Tier 2
(deterministic user pipelines run through `agent/pipeline.py`) slots in by adding
one branch, reusing all of the storage / validation / CRUD here. See
`docs/a2_custom_presets_and_pipelines.md` §4.1 for the locked schema contract.

Storage: one TOML file per preset at `<data_dir>/presets/<name>.toml`, read via
stdlib `tomllib` and written by a small round-trip-verified serializer (no new
dependency, no hand-rolled-escaping risk — the writer's output is re-parsed in
tests). Writes are atomic (`tempfile` + `os.replace`) so a crash mid-write never
corrupts a preset. Consistent with how Kratos stores `sessions/` and
`kratos_local_config.json` under `data_dir` (not a second home-dir config).

The `kind` field is the Tier-1→Tier-2 seam:
  * `kind="goal"`     -> run `goal` through `run_agent()`   (Tier 1, built)
  * `kind="pipeline"` -> run `steps` through `run_pipeline()` (Tier 2, NOT built)
  * anything else     -> treated like a not-yet-supported pipeline
A preset whose `kind` this build can't run is still parsed, listed, and shown
normally; only *running* it is declined with a clear message. Listing/loading
must never crash on such a preset (forward-compat invariant, tested).
"""
from __future__ import annotations

import os
import re
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from kratos.utils.timeutil import utc_now_iso

# Kinds this (Tier 1) build can actually run. Everything else is recognized but
# gracefully declined -- the forward-compat contract.
_RUNNABLE_KINDS = {"goal"}

# Names that would collide with a `/preset <sub>` subcommand or read confusingly
# as one. Rejected at validation time so a preset can never shadow the CRUD verbs
# (and so a future `/<name>` first-class command stays feasible).
_RESERVED_NAMES = {
    "run", "list", "ls", "new", "add", "create", "edit", "update", "delete",
    "del", "rm", "remove", "show", "view", "help", "preset", "presets",
}

_MAX_NAME_LEN = 64
_SLUG_STRIP_RE = re.compile(r"[^a-z0-9_-]+")
_SLUG_COLLAPSE_RE = re.compile(r"-{2,}")


class PresetError(Exception):
    """A preset couldn't be saved/loaded (invalid name, corrupt file, …). The
    message is user-facing (surfaced verbatim in the TUI)."""


@dataclass
class Preset:
    """A parsed preset. `raw` keeps the full parsed TOML so a Tier-2 preset's
    `steps` (which this build doesn't interpret) survive a round trip untouched."""

    name: str
    kind: str
    goal: Optional[str]
    target: Optional[str]
    created_at: Optional[str]
    path: Path
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_runnable_tier1(self) -> bool:
        return self.kind in _RUNNABLE_KINDS and bool(self.goal and self.goal.strip())

    @property
    def unsupported_reason(self) -> Optional[str]:
        """Why this preset can't run in a Tier-1 build, or None if it can."""
        if self.is_runnable_tier1:
            return None
        if self.kind not in _RUNNABLE_KINDS:
            return (
                f"'{self.name}' is a '{self.kind}' preset (a deterministic pipeline). "
                "Pipeline presets aren't runnable in this build yet — only saved "
                "goal presets are. The preset is kept; it just can't run here."
            )
        return f"'{self.name}' has no goal to run (the preset's goal is empty)."


# --------------------------------------------------------------------------- #
# Name handling
# --------------------------------------------------------------------------- #
def slugify_preset_name(raw: str) -> str:
    """Reduce a user-typed name to a safe, canonical, traversal-free slug:
    lowercased, only `[a-z0-9_-]`, collapsed/trimmed hyphens. Path separators,
    dots, and everything else become hyphens, so `../etc` -> `etc`, never a path
    escape."""
    s = (raw or "").strip().lower().replace(" ", "-")
    s = _SLUG_STRIP_RE.sub("-", s)
    s = _SLUG_COLLAPSE_RE.sub("-", s)
    return s.strip("-_")


def validate_preset_name(raw: str) -> tuple[bool, str, Optional[str]]:
    """Return (ok, canonical_slug, error_message). `canonical` is the slug even
    when invalid (useful for messages), `error` is None when ok."""
    canonical = slugify_preset_name(raw)
    if not canonical:
        return False, "", "A preset name must contain letters or digits."
    if len(canonical) > _MAX_NAME_LEN:
        return False, canonical, f"Preset name too long (max {_MAX_NAME_LEN} characters)."
    if canonical in _RESERVED_NAMES:
        return False, canonical, f"'{canonical}' is a reserved word — pick a different name."
    return True, canonical, None


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def presets_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "presets"


_TOML_ESCAPES = {
    "\\": "\\\\", '"': '\\"', "\b": "\\b", "\t": "\\t",
    "\n": "\\n", "\f": "\\f", "\r": "\\r",
}


def _toml_basic_string(s: str) -> str:
    """Serialize a Python str as a TOML single-line basic string, per the TOML
    spec: escape backslash/quote and the named control chars, and any other
    control char (U+0000–U+001F, U+007F) as \\uXXXX. Verified by round-tripping
    every write through tomllib in the tests, so this can never silently emit a
    file the stdlib parser won't read back identically."""
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


def _dump_preset_toml(
    *, name: str, kind: str, target: Optional[str], goal: Optional[str],
    created_at: Optional[str],
) -> str:
    lines = [
        "# Kratos preset — editable by hand or via /preset. `kind` selects how it runs.",
        f"name = {_toml_basic_string(name)}",
        f"kind = {_toml_basic_string(kind)}",
    ]
    if target:
        lines.append(f"target = {_toml_basic_string(target)}")
    if created_at:
        lines.append(f"created_at = {_toml_basic_string(created_at)}")
    if goal is not None:
        lines.append(f"goal = {_toml_basic_string(goal)}")
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, text: str) -> None:
    """Write text to `path` atomically (temp file in the same dir + os.replace,
    POSIX-atomic), so a crash/interrupt never leaves a torn or half-written
    preset -- same guarantee the kept-tools persistence uses."""
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


def _preset_from_dict(data: dict[str, Any], path: Path, stem: str) -> Preset:
    """Build a Preset from parsed TOML. Tolerant by design: a missing `name`
    falls back to the filename stem, a missing `kind` defaults to 'goal' (so a
    minimally hand-authored file works), and unexpected types are coerced to str
    rather than raising -- listing must survive odd files."""
    name = str(data.get("name") or stem)
    kind = str(data.get("kind") or "goal").strip().lower() or "goal"
    goal_val = data.get("goal")
    goal = str(goal_val) if goal_val is not None else None
    target_val = data.get("target")
    target = str(target_val) if target_val else None
    created_val = data.get("created_at")
    created_at = str(created_val) if created_val else None
    return Preset(name=name, kind=kind, goal=goal, target=target,
                  created_at=created_at, path=path, raw=dict(data))


def preset_exists(data_dir: Path, name: str) -> bool:
    ok, canonical, _ = validate_preset_name(name)
    if not ok:
        return False
    return (presets_dir(data_dir) / f"{canonical}.toml").exists()


def load_preset(data_dir: Path, name: str) -> Optional[Preset]:
    """Return the named preset, or None if the name is invalid or no such file
    exists. Raises PresetError if the file exists but is corrupt/unparseable
    (so a direct `/preset run <name>` can report *why*, vs. silently 'not
    found')."""
    ok, canonical, _ = validate_preset_name(name)
    if not ok:
        return None
    path = presets_dir(data_dir) / f"{canonical}.toml"
    if not path.exists():
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise PresetError(f"Preset '{canonical}' is corrupt and couldn't be read: {e}")
    return _preset_from_dict(data, path, canonical)


def list_presets(data_dir: Path) -> tuple[list[Preset], list[tuple[str, str]]]:
    """Return (valid presets sorted by name, [(filename, error) for unreadable
    files]). NEVER raises -- a single corrupt file becomes an entry in the error
    list, so `/preset list` always renders and surfaces the problem rather than
    dying. Both goal and pipeline (and unknown-kind) presets appear in the valid
    list; runnability is a per-preset property, not a listing filter."""
    d = presets_dir(data_dir)
    presets: list[Preset] = []
    errors: list[tuple[str, str]] = []
    if not d.exists():
        return presets, errors
    for path in sorted(d.glob("*.toml")):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            presets.append(_preset_from_dict(data, path, path.stem))
        except Exception as e:  # noqa: BLE001 -- one bad file must not kill the list
            errors.append((path.name, str(e)))
    presets.sort(key=lambda p: p.name)
    return presets, errors


def save_preset(
    data_dir: Path,
    *,
    name: str,
    goal: Optional[str],
    target: Optional[str] = None,
    kind: str = "goal",
    created_at: Optional[str] = None,
) -> Preset:
    """Validate and atomically write a preset, returning the reloaded Preset.
    Raises PresetError on an invalid name or an empty goal for a goal preset."""
    ok, canonical, err = validate_preset_name(name)
    if not ok:
        raise PresetError(err or "Invalid preset name.")
    if kind == "goal" and not (goal and goal.strip()):
        raise PresetError("A goal preset needs a non-empty goal.")

    d = presets_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{canonical}.toml"
    # Defense in depth on top of the slug: the written file must stay inside the
    # presets dir. (slugify already forbids separators; this catches any future
    # regression in the slug rules rather than trusting them alone.)
    if path.resolve().parent != d.resolve():
        raise PresetError("Refusing to write a preset outside the presets directory.")

    goal_clean = goal.strip() if goal else goal
    text = _dump_preset_toml(
        name=canonical, kind=kind, target=(target or None),
        goal=goal_clean, created_at=(created_at or utc_now_iso()),
    )
    _atomic_write(path, text)
    reloaded = load_preset(data_dir, canonical)
    assert reloaded is not None  # just written
    return reloaded


def delete_preset(data_dir: Path, name: str) -> bool:
    """Delete the named preset. Returns True if a file was removed, False if the
    name was invalid or no such preset existed."""
    ok, canonical, _ = validate_preset_name(name)
    if not ok:
        return False
    path = presets_dir(data_dir) / f"{canonical}.toml"
    if not path.exists():
        return False
    try:
        path.unlink()
    except OSError:
        return False
    return True
