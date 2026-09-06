"""
.env LLM-profile discovery/validation/editing for /model (2026-07-18).

Reference: .env's own documented structure (its header comment, confirmed
by reading the real file before writing this module, not assumed) --
LLM_BASE_URL/LLM_API_KEY/LLM_MODEL/KRATOS_LLM_BACKEND form ONE profile
"group", always adjacent in that exact order, each line either fully
commented (`# KEY=value`) or fully uncommented. Swapping a model means
swapping the WHOLE group, never just LLM_MODEL alone -- a partial swap
would leave LLM_BASE_URL pointed at the wrong backend, reproducing this
project's own documented 2026-07-15/16 LLM-backend consistency bug via a
different mechanism (see CLAUDE.md's "LLM backend refactor" section).

dotenv resolves a key repeated across multiple uncommented blocks by
LAST-ASSIGNMENT-WINS (confirmed against this repo's installed
python-dotenv, per .env's own header comment) -- "currently active" here
is resolved the same way (the last/lowest matching uncommented block),
not just "any" uncommented one, so this module's notion of "active" always
matches what the running process actually loaded.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

PROFILE_KEYS: tuple[str, ...] = ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL", "KRATOS_LLM_BACKEND")

_LINE_RE = re.compile(
    r"^(?P<comment>#\s?)?(?P<key>LLM_BASE_URL|LLM_API_KEY|LLM_MODEL|KRATOS_LLM_BACKEND)=(?P<value>.*)$"
)

# Optional 5th line a profile block MAY carry (written by the model-setup flow):
# the per-profile context window. Backward-compatible -- a classic 4-line block
# simply has no such line, and its absence changes nothing.
_CONTEXT_LINE_RE = re.compile(r"^(?P<comment>#\s?)?LLM_CONTEXT_WINDOW=(?P<value>.*)$")

# Literal placeholder strings this repo's own .env/.env.example templates
# use -- a profile whose value matches one of these has never actually
# been filled in by a human, regardless of whether all 4 keys are
# technically "present". Grounded in the real file content, not guessed.
_PLACEHOLDER_VALUES = {
    "your-model-name",
    "dummy-or-real-key",
    "your-real-gemini-key-here",
    "your-otx-api-key-here",
    "your-abuseipdb-api-key-here",
}
# .env's own template block: LLM_BASE_URL=http://127.0.0.1:PORT/v1 -- the
# literal, never-replaced "PORT" text.
_PLACEHOLDER_URL_MARKER = "PORT"


@dataclass
class EnvProfile:
    values: dict[str, str]
    line_indices: dict[str, int]
    active: bool

    @property
    def model(self) -> str:
        return self.values.get("LLM_MODEL", "")

    def is_template(self) -> bool:
        model = self.model.strip()
        return not model or model in _PLACEHOLDER_VALUES


def _parse_profiles(lines: list[str]) -> list[EnvProfile]:
    """Scans for consecutive LLM_BASE_URL -> LLM_API_KEY -> LLM_MODEL ->
    KRATOS_LLM_BACKEND runs, in that exact order (matching every real block
    in the file), regardless of whether individual lines are commented.
    `active` is True only if ALL 4 lines in the run are uncommented,
    matching .env's own documented invariant."""
    profiles: list[EnvProfile] = []
    i, n = 0, len(lines)
    while i < n:
        m = _LINE_RE.match(lines[i])
        if m and m.group("key") == PROFILE_KEYS[0]:
            block_values: dict[str, str] = {}
            block_indices: dict[str, int] = {}
            active_flags: list[bool] = []
            ok = True
            for offset, expected_key in enumerate(PROFILE_KEYS):
                if i + offset >= n:
                    ok = False
                    break
                lm = _LINE_RE.match(lines[i + offset])
                if not lm or lm.group("key") != expected_key:
                    ok = False
                    break
                block_values[expected_key] = lm.group("value")
                block_indices[expected_key] = i + offset
                active_flags.append(lm.group("comment") is None)
            if ok:
                consumed = len(PROFILE_KEYS)
                # Optional trailing LLM_CONTEXT_WINDOW line -- captured into the
                # SAME profile (values + line_indices) so it round-trips and
                # switch_profile toggles it together with the block. `active` is
                # still decided by the 4 required keys only, so a window line's
                # own comment state can't flip a profile's active status.
                if i + consumed < n:
                    cm = _CONTEXT_LINE_RE.match(lines[i + consumed])
                    if cm:
                        block_values["LLM_CONTEXT_WINDOW"] = cm.group("value")
                        block_indices["LLM_CONTEXT_WINDOW"] = i + consumed
                        consumed += 1
                profiles.append(
                    EnvProfile(values=block_values, line_indices=block_indices, active=all(active_flags))
                )
                i += consumed
                continue
        i += 1
    return profiles


def list_candidate_profiles(env_path: Path) -> tuple[list[EnvProfile], EnvProfile | None]:
    """Returns (deduplicated real candidates in file order, the currently-
    active one or None). Template/placeholder blocks (see is_template)
    are never offered as real candidates. Deduplicates by LLM_MODEL value,
    first occurrence wins for display order."""
    if not env_path.exists():
        return [], None
    lines = env_path.read_text(encoding="utf-8").split("\n")
    all_profiles = _parse_profiles(lines)
    real_profiles = [p for p in all_profiles if not p.is_template()]

    seen: dict[str, EnvProfile] = {}
    for p in real_profiles:
        if p.model not in seen:
            seen[p.model] = p
    candidates = list(seen.values())

    active_candidates = [p for p in real_profiles if p.active]
    current = active_candidates[-1] if active_candidates else None
    return candidates, current


def validate_profile(profile: EnvProfile) -> list[str]:
    """Returns human-readable problems (empty list = usable). Deliberately
    only catches concrete, literal templating gaps (empty values, this
    repo's own known placeholder strings/markers) -- never tries to verify
    a real-looking key/URL actually WORKS, which needs a live call and is
    out of scope here."""
    problems: list[str] = []
    for key in PROFILE_KEYS:
        value = profile.values.get(key, "").strip()
        if not value:
            problems.append(f"{key} is empty")
        elif value in _PLACEHOLDER_VALUES:
            problems.append(f"{key} is still a template placeholder ({value!r})")
    base_url = profile.values.get("LLM_BASE_URL", "")
    if _PLACEHOLDER_URL_MARKER in base_url:
        problems.append(
            f"LLM_BASE_URL still contains the unfilled {_PLACEHOLDER_URL_MARKER!r} placeholder ({base_url!r})"
        )
    return problems


def add_profile(env_path: Path, values: dict[str, str], make_active: bool = True) -> None:
    """Append a NEW profile block to `.env` from `values` (the 4 PROFILE_KEYS,
    plus an optional LLM_CONTEXT_WINDOW). Written in the exact block shape
    `_parse_profiles` reads back. When `make_active` (the default), the block is
    written uncommented AND the currently-active profile is commented out -- so
    adding a model also switches to it -- mirroring switch_profile's comment/
    uncomment discipline. Only appends + toggles the outgoing active block's own
    lines; every other line in the file is left byte-identical.

    Does NOT activate the profile in the running process -- the caller does that
    via llm_config.set_active_llm_profile(values), exactly as /model already
    does after a switch."""
    text = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    lines = text.split("\n") if text else []

    if make_active:
        active = [p for p in _parse_profiles(lines) if p.active]
        current = active[-1] if active else None
        if current is not None:
            for idx in current.line_indices.values():
                if not lines[idx].lstrip().startswith("#"):
                    lines[idx] = f"# {lines[idx]}"

    prefix = "" if make_active else "# "
    block = [f"{prefix}{key}={values.get(key, '')}" for key in PROFILE_KEYS]
    window = str(values.get("LLM_CONTEXT_WINDOW", "")).strip()
    if window:
        block.append(f"{prefix}LLM_CONTEXT_WINDOW={window}")

    # Separate the appended block from prior content with exactly one blank line.
    while lines and lines[-1].strip() == "":
        lines.pop()
    if lines:
        lines.append("")
    lines.extend(block)
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def set_profile_context_window(env_path: Path, model: str, window: int | None) -> bool:
    """Set (or clear, when `window` is None) the LLM_CONTEXT_WINDOW for the
    profile whose LLM_MODEL == `model`, editing ONLY that block's lines. Updates
    the line in place if present; inserts it right after the block's
    KRATOS_LLM_BACKEND (matching that block's comment state) if absent; removes
    it when clearing. Returns True iff a matching profile was found. Does not
    activate anything in-process -- the caller re-syncs set_active_llm_profile if
    it edited the active profile."""
    lines = env_path.read_text(encoding="utf-8").split("\n")
    target = next((p for p in _parse_profiles(lines) if p.model == model), None)
    if target is None:
        return False
    prefix = "" if target.active else "# "
    if "LLM_CONTEXT_WINDOW" in target.line_indices:
        idx = target.line_indices["LLM_CONTEXT_WINDOW"]
        if window is None:
            del lines[idx]
        else:
            lines[idx] = f"{prefix}LLM_CONTEXT_WINDOW={window}"
    elif window is not None:
        after = target.line_indices["KRATOS_LLM_BACKEND"]
        lines.insert(after + 1, f"{prefix}LLM_CONTEXT_WINDOW={window}")
    text = "\n".join(lines)
    env_path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return True


def delete_profile(env_path: Path, model: str) -> bool:
    """Remove the profile whose LLM_MODEL == `model` from `.env` entirely --
    deletes exactly that block's lines (the 4 PROFILE_KEYS plus an optional
    LLM_CONTEXT_WINDOW), leaving every other line intact. Returns True iff a
    matching profile was found. Callers MUST NOT delete the currently-active
    profile (that would leave the running process pointed at a model no longer
    in the file); the UI guards that -- this function just does the edit.

    Collapses any run of 3+ blank lines the deletion leaves behind back to a
    single separator, so repeated add/delete cycles don't accumulate blank
    lines."""
    lines = env_path.read_text(encoding="utf-8").split("\n")
    target = next((p for p in _parse_profiles(lines) if p.model == model), None)
    if target is None:
        return False
    for idx in sorted(target.line_indices.values(), reverse=True):
        del lines[idx]
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines))
    env_path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return True


def switch_profile(env_path: Path, target: EnvProfile, current: EnvProfile | None) -> None:
    """Comments out `current`'s 4 lines (if any, and if it's a different
    profile) and uncomments `target`'s 4 lines -- edits ONLY those specific
    line indices. Every other line (other inactive profiles, comments,
    blank lines) is left byte-identical. Re-selecting the already-active
    profile (current is target) is a safe no-op."""
    lines = env_path.read_text(encoding="utf-8").split("\n")

    if current is not None and current.model != target.model:
        for idx in current.line_indices.values():
            line = lines[idx]
            if not line.lstrip().startswith("#"):
                lines[idx] = f"# {line}"

    uncomment_re = re.compile(r"^#\s?(.*)$")
    for idx in target.line_indices.values():
        line = lines[idx]
        m = uncomment_re.match(line)
        if m:
            lines[idx] = m.group(1)

    env_path.write_text("\n".join(lines), encoding="utf-8")
