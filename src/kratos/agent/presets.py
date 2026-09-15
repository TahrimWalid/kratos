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
  * `kind="goal"`     -> run `goal` through `run_agent()`     (Tier 1)
  * `kind="pipeline"` -> run `steps` through `run_pipeline()` (Tier 2: an ordered,
                         deterministic list of read/observe tool steps, each step
                         optionally guarded by a bounded `when` condition)
  * anything else     -> treated like a not-yet-supported preset
A preset whose `kind` this build can't run (an unknown kind, or a pipeline with a
STRUCTURAL error — no steps, a bad tool entry, or an invalid `when`) is still
parsed, listed, and shown normally; only *running* it is declined with a clear
message. Listing and loading must never crash on such a preset (forward-compat
invariant, tested).

Tier-2 pipeline bodies (`[[steps]]`) are parsed here into normalized step dicts
(`{tool, args, label, required, when?}`) via `parse_pipeline()`, which is
deliberately TOLERANT (never raises) so `list_presets` survives a hand-broken
file, and reports structural errors/warnings separately so `save_preset` can
REJECT an unrunnable body while listing still shows it. A step's optional `when`
condition is a bounded, whitelisted predicate compiled by `agent/pipeline_when.py`
(never `eval()`): a VALID `when` is runnable, an INVALID one is a structural error
that makes the preset unrunnable (declined with a clear message, still listed and
shown). Step `args` carry tool-specific options only: `data_dir` is force-injected by
`execute_tool_call` and a non-loopback `target` is rejected there, so both are
stripped from step args at parse (with a recorded note), never persisted.
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

# Kinds a GOAL (Tier-1) run can execute. `is_runnable_tier1` keys off this;
# pipelines are handled separately in `is_runnable`/`unsupported_reason` so
# tier1-only call sites (goal editing, the agentic-cloud cost warning) keep
# meaning exactly "a natural-language goal preset".
_RUNNABLE_KINDS = {"goal"}
# Kinds this build RECOGNIZES (a real preset shape). Anything else is a
# not-yet-supported kind -- parsed and listed, but declined at run time.
_KNOWN_KINDS = {"goal", "pipeline"}

# The one target value a pipeline step may legitimately pin (Kratos self-
# monitoring), matching execute_tool_call's own _LOOPBACK_SELF_TARGETS exception.
# Every other explicit `target` in a step's args is rejected there, so it is
# stripped at parse time rather than persisted to fail later.
_LOOPBACK_STEP_TARGETS = {"127.0.0.1", "localhost", "::1"}

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


# --------------------------------------------------------------------------- #
# Tier-2 pipeline body parsing (Piece A)
# --------------------------------------------------------------------------- #
@dataclass
class PipelineParse:
    """Result of parsing a `[[steps]]` body. TOLERANT: `parse_pipeline` never
    raises, so listing survives a broken file. `errors` are STRUCTURAL problems
    that make the body unrunnable/unsavable (a step isn't a table, has no tool,
    `args` isn't a table, `when` isn't a string, or there are zero steps);
    `warnings` are advisory (an unknown tool name -- a kept tool may load later;
    a stripped `data_dir`/`target`; an arg that isn't one of the tool's
    parameters). `steps` is the normalized, ready-to-run step list (built from
    whatever parsed cleanly). `has_conditions` is True if any step declares a
    `when` -- informational only; a VALID `when` does not block running (an
    invalid one lands in `errors`). See `is_runnable_pipeline`.
    """

    steps: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    has_conditions: bool = False


def parse_pipeline(raw_steps: Any, *, registry: Optional[dict[str, Any]] = None) -> PipelineParse:
    """Parse a pipeline preset's `steps` value into normalized step dicts, never
    raising. Structural problems become `errors`; advisory ones become
    `warnings`. Pass `registry` (the live `TOOL_REGISTRY`) to additionally warn
    about unknown tool names and unknown arg names -- omitted at plain parse time
    (kept tools load at runtime; existence is a save/run concern), included at
    save time to catch typos early. `data_dir` (always) and a non-loopback
    `target` (rejected by execute_tool_call anyway) are stripped from each step's
    args with a recorded warning -- step args are tool-specific options only."""
    parse = PipelineParse()
    if not isinstance(raw_steps, list):
        parse.errors.append("a pipeline preset needs a [[steps]] list of steps")
        return parse
    if not raw_steps:
        parse.errors.append("a pipeline needs at least one step")
        return parse

    prior_steps: list[tuple[Optional[str], str]] = []  # (label, tool) of EARLIER steps (Piece C)
    for i, raw in enumerate(raw_steps, start=1):
        if not isinstance(raw, dict):
            parse.errors.append(f"step {i} is not a table (each step needs a `tool`)")
            continue
        tool = str(raw.get("tool") or "").strip()
        if not tool:
            parse.errors.append(f"step {i} has no `tool` name")
            continue

        # args: must be a table if present; strip auto-injected/rejected keys.
        args_raw = raw.get("args")
        if args_raw is None:
            args: dict[str, Any] = {}
        elif isinstance(args_raw, dict):
            args = dict(args_raw)
        else:
            parse.errors.append(f"step {i} ({tool}): `args` must be a table")
            continue
        if "data_dir" in args:
            args.pop("data_dir")
            parse.warnings.append(
                f"step {i} ({tool}): dropped `data_dir` from args — Kratos injects it automatically")
        if "target" in args:
            tv = str(args.get("target") or "")
            if tv.strip().lower() in _LOOPBACK_STEP_TARGETS:
                args["target"] = tv.strip().lower()
            else:
                args.pop("target")
                parse.warnings.append(
                    f"step {i} ({tool}): dropped `target` from args — steps run against the "
                    "preset's/active target; only a loopback self-target may be pinned per step")

        # when: an optional bounded, whitelisted predicate (slice 4). Must be a
        # string, and must compile against the whitelisted grammar
        # (agent/pipeline_when.py) -- an unrecognized predicate is a STRUCTURAL
        # error (reject at save), so a broken condition can never silently run.
        # Validation is registry-independent, so it belongs in errors stored on
        # the Preset. The step is KEPT (not dropped) so show/preview can display
        # the offending condition; the recorded error makes the preset unrunnable.
        when = raw.get("when")
        if when is not None and not isinstance(when, str):
            parse.errors.append(f"step {i} ({tool}): `when` must be a string predicate")
            continue
        when_clean = when.strip() if isinstance(when, str) else None
        if when_clean:
            parse.has_conditions = True
            from kratos.agent.pipeline_when import WhenError, compile_when
            try:
                compile_when(when_clean)  # validate only; the runner recompiles
            except WhenError as e:
                parse.errors.append(f"step {i} ({tool}): invalid condition ({e})")

        required = bool(raw.get("required", True))
        label_raw = raw.get("label")
        label = str(label_raw).strip() if label_raw else None

        # A2 Piece C: resolve step-output references in args (forward-only,
        # whitelisted, never eval). A malformed/invalid reference is a STRUCTURAL
        # error (reject at save); the normalized ref is stored so the step shows
        # its dependency. prior_steps carries (label, tool) of EARLIER steps only,
        # so a reference can never name a later/same step.
        from kratos.agent import pipeline_refs as _refs
        for arg_name, arg_val in list(args.items()):
            if not _refs.is_reference(arg_val):
                continue
            try:
                ref = _refs.normalize_reference(arg_val)
                _refs.validate_reference(
                    ref, prior_steps=prior_steps, consumer_tool=tool,
                    consumer_arg=arg_name, registry=registry)
                args[arg_name] = ref
            except _refs.RefError as e:
                parse.errors.append(f"step {i} ({tool}): {arg_name} — {e}")

        if registry is not None:
            reg_tool = registry.get(tool)
            if reg_tool is None:
                parse.warnings.append(
                    f"step {i}: '{tool}' isn't a currently-loaded tool — if it's a kept "
                    "tool it'll load at run time, otherwise this step will fail")
            else:
                known_params = set(getattr(reg_tool, "parameters", {}) or {})
                for arg_name in args:
                    if arg_name not in known_params:
                        parse.warnings.append(
                            f"step {i} ({tool}): '{arg_name}' isn't one of its parameters "
                            f"({', '.join(sorted(known_params - {'data_dir'})) or 'none'})")

        step: dict[str, Any] = {"tool": tool, "args": args, "required": required}
        if label:
            step["label"] = label
        if when_clean:
            step["when"] = when_clean
        parse.steps.append(step)
        prior_steps.append((label, tool))  # visible to LATER steps' references

    if not parse.steps and not parse.errors:
        parse.errors.append("a pipeline needs at least one valid step")
    # Piece G (determinism/reporting honesty): a pipeline SHOULD end in
    # correlate_findings so the run produces ranked findings for /report and
    # triggers. Advisory only -- some pipelines legitimately just gather data.
    if parse.steps and parse.steps[-1]["tool"] != "correlate_findings":
        parse.warnings.append(
            "this pipeline doesn't end in correlate_findings — add it as the last step so the "
            "run produces ranked findings for /report and triggers")
    return parse


@dataclass
class Preset:
    """A parsed preset. `raw` keeps the full parsed TOML so unknown/future fields
    survive a round trip. For a `kind="pipeline"` preset, `steps` holds the
    normalized step list and `pipeline_errors`/`has_conditions` capture the
    structural (registry-independent) parse verdict used by `is_runnable`."""

    name: str
    kind: str
    goal: Optional[str]
    target: Optional[str]
    created_at: Optional[str]
    path: Path
    raw: dict[str, Any] = field(default_factory=dict)
    steps: list[dict[str, Any]] = field(default_factory=list)
    pipeline_errors: list[str] = field(default_factory=list)
    has_conditions: bool = False
    # True for an AI-DRAFTED preset (A2 §5.6 /preset-describe). Informational +
    # used to gate running with a danger-confirm ("generated ≠ trusted-to-run").
    generated: bool = False

    @property
    def is_pipeline(self) -> bool:
        return self.kind == "pipeline"

    @property
    def is_runnable_tier1(self) -> bool:
        """A runnable natural-language GOAL preset (agentic). Deliberately does
        NOT include pipelines -- tier1-only call sites (goal editing, the
        agentic-cloud cost warning) mean exactly this."""
        return self.kind in _RUNNABLE_KINDS and bool(self.goal and self.goal.strip())

    @property
    def is_runnable_pipeline(self) -> bool:
        """A runnable deterministic PIPELINE preset: a well-formed, non-empty step
        list with no structural errors (registry-independent — an unknown tool
        name is only a warning here, caught hard at run time; an invalid `when`
        predicate IS a structural error and blocks running). A valid bounded
        `when` (slice 4) is runnable; `has_conditions` is informational only."""
        return self.is_pipeline and bool(self.steps) and not self.pipeline_errors

    @property
    def is_runnable(self) -> bool:
        """Can this preset run in this build at all (goal OR pipeline)?"""
        return self.is_runnable_tier1 or self.is_runnable_pipeline

    @property
    def unsupported_reason(self) -> Optional[str]:
        """Why this preset can't run in this build, or None if it can."""
        if self.is_runnable:
            return None
        if self.kind not in _KNOWN_KINDS:
            return (
                f"'{self.name}' is a '{self.kind}' preset, an unrecognized kind this build "
                "doesn't know how to run (it may come from a newer Kratos). The preset is "
                "kept and shown; it just can't run here."
            )
        if self.is_pipeline:
            if self.pipeline_errors:
                return (f"'{self.name}' has invalid pipeline steps: "
                        + "; ".join(self.pipeline_errors))
            if not self.steps:
                return f"'{self.name}' is a pipeline preset with no steps to run."
            return f"'{self.name}' can't run (unknown reason)."
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


def _toml_scalar(v: Any) -> str:
    """Serialize a scalar (or a flat list of scalars, or a nested table — a Piece
    C step-output reference `{from, field, select?}`) as TOML. Bools/ints/floats
    render natively; a dict becomes an inline table; everything else (incl.
    anything unexpected) falls back to a basic string, so the writer can never
    emit a value tomllib won't read back — round-trip-verified in tests."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_scalar(x) for x in v) + "]"
    if isinstance(v, dict):
        return _toml_inline_table(v)
    return _toml_basic_string(str(v))


def _toml_inline_table(d: dict[str, Any]) -> str:
    """Serialize a flat dict as a TOML inline table `{ k = v, ... }`. Keys are
    step arg names (already validated to a tool's parameter names / stripped of
    data_dir/target), values are scalars or flat lists."""
    if not d:
        return "{}"
    inner = ", ".join(f"{k} = {_toml_scalar(v)}" for k, v in d.items())
    return "{ " + inner + " }"


def _dump_preset_toml(
    *, name: str, kind: str, target: Optional[str], goal: Optional[str],
    created_at: Optional[str], steps: Optional[list[dict[str, Any]]] = None,
    generated: bool = False,
) -> str:
    lines = [
        "# Kratos preset — editable by hand or via /preset. `kind` selects how it runs.",
        f"name = {_toml_basic_string(name)}",
        f"kind = {_toml_basic_string(kind)}",
    ]
    if generated:
        lines.append("generated = true")
    if target:
        lines.append(f"target = {_toml_basic_string(target)}")
    if created_at:
        lines.append(f"created_at = {_toml_basic_string(created_at)}")
    if goal is not None:
        lines.append(f"goal = {_toml_basic_string(goal)}")
    for step in steps or []:
        lines.append("")
        lines.append("[[steps]]")
        lines.append(f"tool = {_toml_basic_string(str(step.get('tool', '')))}")
        if step.get("label"):
            lines.append(f"label = {_toml_basic_string(str(step['label']))}")
        # `required` is written explicitly (even the True default) so a
        # hand-editor sees the fail-fast/resilient choice, not a hidden default.
        lines.append(f"required = {_toml_scalar(bool(step.get('required', True)))}")
        args = step.get("args")
        if isinstance(args, dict) and args:
            lines.append(f"args = {_toml_inline_table(args)}")
        if step.get("when"):
            lines.append(f"when = {_toml_basic_string(str(step['when']))}")
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
    rather than raising -- listing must survive odd files. A `kind="pipeline"`
    body's `[[steps]]` are parsed here (registry-independent, so structural errors
    are captured without depending on which kept tools happen to be loaded)."""
    name = str(data.get("name") or stem)
    kind = str(data.get("kind") or "goal").strip().lower() or "goal"
    goal_val = data.get("goal")
    goal = str(goal_val) if goal_val is not None else None
    target_val = data.get("target")
    target = str(target_val) if target_val else None
    created_val = data.get("created_at")
    created_at = str(created_val) if created_val else None

    steps: list[dict[str, Any]] = []
    pipeline_errors: list[str] = []
    has_conditions = False
    if kind == "pipeline":
        parsed = parse_pipeline(data.get("steps"))
        steps, pipeline_errors, has_conditions = (
            parsed.steps, parsed.errors, parsed.has_conditions)

    return Preset(name=name, kind=kind, goal=goal, target=target,
                  created_at=created_at, path=path, raw=dict(data),
                  steps=steps, pipeline_errors=pipeline_errors,
                  has_conditions=has_conditions, generated=bool(data.get("generated", False)))


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
    goal: Optional[str] = None,
    target: Optional[str] = None,
    kind: str = "goal",
    created_at: Optional[str] = None,
    steps: Optional[list[dict[str, Any]]] = None,
    generated: bool = False,
) -> Preset:
    """Validate and atomically write a preset, returning the reloaded Preset.
    Raises PresetError on an invalid name, an empty goal for a goal preset, or a
    structurally-broken pipeline body. For a pipeline, save-time validation runs
    against the LIVE registry (unknown tool / arg-name warnings) but only
    STRUCTURAL errors block the write -- an unknown tool name is a warning, not a
    rejection, because a referenced kept tool may load only at run time. Any
    warnings are returned on the reloaded Preset via `save_preset_with_warnings`;
    this thin wrapper keeps the common (warning-free) call site simple."""
    preset, _warnings = save_preset_with_warnings(
        data_dir, name=name, goal=goal, target=target, kind=kind,
        created_at=created_at, steps=steps, generated=generated)
    return preset


def save_preset_with_warnings(
    data_dir: Path,
    *,
    name: str,
    goal: Optional[str] = None,
    target: Optional[str] = None,
    kind: str = "goal",
    created_at: Optional[str] = None,
    steps: Optional[list[dict[str, Any]]] = None,
    generated: bool = False,
) -> tuple[Preset, list[str]]:
    """Like `save_preset`, but also returns advisory warnings (unknown tool /
    unknown arg-name / stripped data_dir|target) so a UI can surface them. The
    write still succeeds despite warnings; only structural `errors` raise."""
    from kratos.agent.tools import TOOL_REGISTRY  # live registry for save-time checks

    ok, canonical, err = validate_preset_name(name)
    if not ok:
        raise PresetError(err or "Invalid preset name.")

    kind = (kind or "goal").strip().lower() or "goal"
    warnings: list[str] = []
    norm_steps: Optional[list[dict[str, Any]]] = None
    if kind == "goal":
        if not (goal and goal.strip()):
            raise PresetError("A goal preset needs a non-empty goal.")
    elif kind == "pipeline":
        parsed = parse_pipeline(steps, registry=TOOL_REGISTRY)
        if parsed.errors:
            raise PresetError("This pipeline can't be saved: " + "; ".join(parsed.errors))
        norm_steps = parsed.steps
        warnings = list(parsed.warnings)
    else:
        raise PresetError(
            f"Unknown preset kind '{kind}'. Use 'goal' (a natural-language "
            "investigation) or 'pipeline' (an ordered list of tool steps).")

    d = presets_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{canonical}.toml"
    # Defense in depth on top of the slug: the written file must stay inside the
    # presets dir. (slugify already forbids separators; this catches any future
    # regression in the slug rules rather than trusting them alone.)
    if path.resolve().parent != d.resolve():
        raise PresetError("Refusing to write a preset outside the presets directory.")

    goal_clean = goal.strip() if goal else None
    text = _dump_preset_toml(
        name=canonical, kind=kind, target=(target or None),
        goal=(goal_clean if kind == "goal" else None),
        created_at=(created_at or utc_now_iso()),
        steps=(norm_steps if kind == "pipeline" else None),
        generated=generated,
    )
    _atomic_write(path, text)
    reloaded = load_preset(data_dir, canonical)
    assert reloaded is not None  # just written
    return reloaded, warnings


# A valid, hand-editable starter pipeline (Piece F files-first bridge). Kept as
# a literal template (not _dump_preset_toml output) so it can carry teaching
# comments a programmatic dump wouldn't. It IS structurally valid — writing it
# then loading it must yield a runnable pipeline preset (asserted in tests).
_PIPELINE_SCAFFOLD = '''\
# Kratos pipeline preset — a deterministic, ordered list of tool steps (no LLM).
# Edit the [[steps]] below, then run it with /preset-run. Kratos validates this
# file on load and shows any problems. Steps run top-to-bottom.
name = {name}
kind = "pipeline"
# target = "10.0.0.5"   # optional — omit to use whatever target is active at run

[[steps]]
tool = "run_nmap_scan"        # a tool name from /tools (target-facing or Kratos-host)
required = true               # true = abort the run if this step fails; false = carry on
# args = {{ }}                #   tool-specific options only (never data_dir/target)

[[steps]]
tool = "correlate_findings"   # synthesize everything gathered above into ranked findings
required = true
# A pipeline should end in correlate_findings so /report and triggers see findings.

# Optional: a step can run conditionally with a bounded `when` predicate. The
# whitelist (no arbitrary code) is:
#   has_finding()  ·  has_finding(min_severity='high')  ·  no_findings()
#   finding_count >= 3   ·   finding_id == 'CORR-SSH-001'
# combine with  and / or / not. Conditions usually go on LATER steps (a first
# step runs before any findings exist). Example:
# [[steps]]
# tool = "run_vuln_scan"
# required = false
# when = "has_finding(min_severity='high')"
'''


def write_pipeline_scaffold(data_dir: Path, name: str) -> Path:
    """Write a commented, valid starter pipeline preset for hand-editing, and
    return its path. Raises PresetError on an invalid name / traversal. The
    written file is a real, runnable pipeline (nmap -> correlate), so a user who
    runs it before editing still gets a sensible audit."""
    ok, canonical, err = validate_preset_name(name)
    if not ok:
        raise PresetError(err or "Invalid preset name.")
    d = presets_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{canonical}.toml"
    if path.resolve().parent != d.resolve():
        raise PresetError("Refusing to write a preset outside the presets directory.")
    _atomic_write(path, _PIPELINE_SCAFFOLD.format(name=_toml_basic_string(canonical)))
    return path


def delete_preset(data_dir: Path, name: str) -> bool:
    """Delete the named preset. Returns True if a file was removed, False if the
    name was invalid or no such preset existed. Also prunes its run-history
    sidecar entry (best-effort)."""
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
    _prune_run_meta(data_dir, canonical)
    return True


# --------------------------------------------------------------------------- #
# Run-history metadata (Piece H) -- a sidecar, never the preset's own file, so a
# hand-edited preset's comments/layout are never rewritten by a run.
# --------------------------------------------------------------------------- #
_RUNS_FILENAME = ".runs.json"


def _runs_path(data_dir: Path) -> Path:
    return presets_dir(data_dir) / _RUNS_FILENAME


def _read_run_meta(data_dir: Path) -> dict[str, Any]:
    try:
        raw = _runs_path(data_dir).read_text(encoding="utf-8")
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def preset_run_meta(data_dir: Path) -> dict[str, dict[str, Any]]:
    """Return {name: {"last_run_at": iso, "last_status": str}} for presets that
    have been run. Never raises (a corrupt sidecar reads as empty)."""
    return {k: v for k, v in _read_run_meta(data_dir).items() if isinstance(v, dict)}


def record_preset_run(data_dir: Path, name: str, status: str = "ran") -> None:
    """Stamp a preset's last run (best-effort; a failure here never sinks a run).
    Keyed by canonical slug. Uses the same atomic write as preset files, so a
    concurrent run can't tear the sidecar into invalid JSON."""
    ok, canonical, _ = validate_preset_name(name)
    if not ok:
        return
    d = presets_dir(data_dir)
    try:
        d.mkdir(parents=True, exist_ok=True)
        data = _read_run_meta(data_dir)
        data[canonical] = {"last_run_at": utc_now_iso(), "last_status": str(status)}
        _atomic_write(_runs_path(data_dir), json.dumps(data, indent=2) + "\n")
    except OSError:
        pass


def _prune_run_meta(data_dir: Path, canonical: str) -> None:
    data = _read_run_meta(data_dir)
    if canonical in data:
        data.pop(canonical)
        try:
            _atomic_write(_runs_path(data_dir), json.dumps(data, indent=2) + "\n")
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Import (Piece H) -- pull a shared/foreign preset file into the presets dir,
# re-validated through the normal save path so a broken import is rejected.
# --------------------------------------------------------------------------- #
def import_preset_file(
    data_dir: Path, src_path: Any, *, overwrite: bool = False,
) -> tuple[Preset, list[str]]:
    """Import a preset TOML from `src_path` into this data_dir's presets. Returns
    (imported preset, warnings). Raises PresetError on a missing/unreadable file,
    an invalid name, an existing name without `overwrite`, a structurally broken
    body, or an unknown kind. Re-saved through the normal path so the imported
    file is normalized + validated (a malformed pipeline can't sneak in)."""
    src = Path(src_path).expanduser()
    if not src.is_file():
        raise PresetError(f"No file to import at {src}.")
    try:
        parsed = tomllib.loads(src.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise PresetError(f"Couldn't read {src.name} as a preset: {e}")

    raw_name = str(parsed.get("name") or src.stem)
    ok, canonical, err = validate_preset_name(raw_name)
    if not ok:
        raise PresetError(f"Can't import: {err}")
    if preset_exists(data_dir, canonical) and not overwrite:
        raise PresetError(
            f"A preset named '{canonical}' already exists — delete it first, or import with overwrite.")

    kind = str(parsed.get("kind") or "goal").strip().lower() or "goal"
    if kind == "pipeline":
        return save_preset_with_warnings(
            data_dir, name=canonical, kind="pipeline", steps=parsed.get("steps"),
            target=parsed.get("target"), created_at=parsed.get("created_at"))
    if kind == "goal":
        preset = save_preset(
            data_dir, name=canonical, goal=parsed.get("goal"),
            target=parsed.get("target"), created_at=parsed.get("created_at"))
        return preset, []
    raise PresetError(
        f"Can't import a '{kind}' preset — this build only understands 'goal' and 'pipeline'.")
