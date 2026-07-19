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
                profiles.append(
                    EnvProfile(values=block_values, line_indices=block_indices, active=all(active_flags))
                )
                i += len(PROFILE_KEYS)
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
