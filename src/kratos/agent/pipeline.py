"""Deterministic, rule-based investigation engine.

This is the modern replacement for the legacy ``cli/app.py::cmd_run`` pipeline
(see ``docs/DESIGN.md``'s "Presets and pipelines" section). It runs an ordered,
declarative list of steps over the live ``TOOL_REGISTRY`` by dispatching each
one through ``agent/loop.py::execute_tool_call`` -- so it inherits, for free and
without re-implementation:

* approval-gating (a step that runs a ``requires_approval`` tool still prompts),
* ``get_active_target()`` resolution and the target-vs-local dispatch guards,
* the ``run_linux_command`` host-confusion stamping / state-change rejection,
* the kept-tool dispatch gating.

Two properties that distinguish it from the agentic ``investigate`` loop, and
that are the whole reason a deterministic engine exists:

* **Guaranteed repeatability** -- the same steps, in the same order, every run,
  with ZERO LLM variance. (The *target* still varies day to day; determinism
  here means "same steps, same logic", never "byte-identical output" -- callers
  should say so in any UI.)
* **Target-correctness by construction** -- the default "standard audit" uses
  only target-facing tools for target claims and never folds a Kratos-host tool
  (``parse_auth_log`` / ``collect_system_context``) into "the target's findings".
  That silent local/target mixing was the core ``cmd_run`` bug; it cannot
  recur here because the local-only tools simply aren't in the default sequence.

Design intent: a *built-in* step below has the exact same shape a
*user-defined* step has, so a user-authored pipeline is just supplying its
own step list against this same engine, not a from-scratch workflow
engine of its own. The conditional
``when`` hook is a bounded, WHITELISTED predicate (``agent/pipeline_when.py`` --
never ``eval()``); a step whose predicate is falsey is SKIPPED, and one whose
predicate raises is fail-safe-SKIPPED with a recorded reason. The default audit
sets no ``when`` -- it is strictly linear (a branching DSL here would trade
predictability for flexibility nobody's asked for), and the conditional
stays a single bounded predicate, deliberately not a general expression
language.

The engine itself is UI-agnostic: it returns a structured ``PipelineOutcome`` and
emits per-step progress via an optional ``on_step`` callback (mirroring
``run_agent``'s own ``on_step``), so the mk2 TUI, the classic console, and tests
all drive the identical engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from kratos.agent.loop import execute_tool_call
from kratos.agent.pipeline_refs import resolve_step_args as _resolve_step_args

# A dispatcher has execute_tool_call's shape: (tool_name, args, data_dir) -> dict
# with {"status": "ok", "result": ...} or {"status": "error"|"not_approved",
# "observation": ...}. Injectable so tests can swap in a canned dispatcher
# without real SSH/LLM, exactly like test_execute_tool_call_guards.py swaps tool
# handlers.
Dispatch = Callable[[str, dict[str, Any], Path], dict[str, Any]]

# Tools that analyze/act on KRATOS'S OWN HOST, not the monitored target. The
# single source of truth for the target-correctness check: a user pipeline
# may legitimately include one, but the runner/builder
# must LABEL it as "Kratos host", never fold its output into "the target's
# findings" (the exact cmd_run bug). Everything else in the registry is
# target-facing (a network scan or an SSH-to-target probe) or host-agnostic
# (correlate_findings synthesizes collected data; send_notification/
# check_ip_reputation aren't about either host).
LOCAL_HOST_TOOLS = frozenset({
    "parse_auth_log", "collect_system_context", "capture_traffic", "run_linux_command",
})


def is_local_host_tool(tool: str) -> bool:
    """True if `tool` runs against Kratos's own host rather than the target."""
    return tool in LOCAL_HOST_TOOLS


def _condition_placeholder(_ctx: "PipelineContext") -> bool:  # pragma: no cover - preview fallback
    """A non-None `when` marker used ONLY so a preview can flag a step conditional
    when its predicate string couldn't be compiled (a broken-`when` preset, which
    is not runnable and so never reaches a real dispatch). Returns True defensively
    so that even if it were somehow reached, the step would run rather than vanish."""
    return True


def steps_from_specs(specs: list[dict[str, Any]]) -> list["PipelineStep"]:
    """Convert normalized preset step dicts (from
    `agent/presets.py::parse_pipeline`) into engine `PipelineStep`s. A spec's
    string `when` is COMPILED into a safe, whitelisted predicate
    (`agent/pipeline_when.compile_when` -- never eval()); a `when` that fails to
    compile falls back to the preview-only conditional marker (such a preset is
    not runnable, so this path is preview-only). Extra spec keys are ignored
    (forward-compat)."""
    from kratos.agent.pipeline_when import WhenError, compile_when

    out: list[PipelineStep] = []
    for spec in specs:
        when_str = spec.get("when")
        when_cb: Optional[Callable[["PipelineContext"], bool]] = None
        if when_str:
            try:
                when_cb = compile_when(str(when_str))
            except WhenError:
                when_cb = _condition_placeholder  # preview-only; unrunnable upstream
        out.append(PipelineStep(
            tool=str(spec.get("tool", "")),
            args=dict(spec.get("args") or {}),
            label=spec.get("label"),
            required=bool(spec.get("required", True)),
            when=when_cb,
        ))
    return out


@dataclass(frozen=True)
class PipelineStep:
    """One declarative step: run ``tool`` (a TOOL_REGISTRY key) with ``args``.

    ``data_dir`` and ``target`` are resolved by ``execute_tool_call`` itself
    (data_dir is force-injected; target defaults to the active target), so a
    step's ``args`` should carry only tool-specific options, never those two.

    ``required`` (default True) = fail-fast: if this step doesn't return ``ok``
    the run aborts (the one good lesson kept from ``cmd_run`` -- single
    transaction). Set ``required=False`` for resilient "nice to have" steps whose
    failure shouldn't sink the whole audit (e.g. an SSH hiccup on one probe).

    ``when`` is the Tier-2 conditional seam: an optional predicate over the
    accumulated ``PipelineContext``; when it returns falsey the step is SKIPPED
    (not failed). The default audit sets none -- it is strictly linear.
    """

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    label: Optional[str] = None
    required: bool = True
    when: Optional[Callable[["PipelineContext"], bool]] = None


@dataclass
class StepResult:
    """The outcome of one step. ``status`` is one of:
    ``ok`` (ran, tool returned ok), ``error`` (tool/dispatch error),
    ``not_approved`` (a gated tool the user declined), ``skipped`` (``when`` was
    falsey). ``result`` is the tool's own return dict on ``ok``; ``detail`` is
    the human-readable observation on any non-ok status.
    """

    step: PipelineStep
    status: str
    result: Optional[dict[str, Any]] = None
    detail: Optional[str] = None

    @property
    def tool(self) -> str:
        return self.step.tool

    @property
    def label(self) -> str:
        return self.step.label or self.step.tool


@dataclass
class PipelineContext:
    """What a ``when`` predicate (Tier 2) sees: the steps run so far and every
    finding produced up to this point. Read-only by convention -- a predicate
    inspects, it does not mutate."""

    data_dir: Path
    results: list[StepResult] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    def has_finding(self, *, min_severity: Optional[str] = None) -> bool:
        """Convenience predicate: any finding (optionally at/above a severity).
        Handy for Tier-2 'if a HIGH finding exists, run Z' steps later."""
        if not self.findings:
            return False
        if min_severity is None:
            return True
        floor = _SEVERITY_RANK.get(min_severity.lower(), 0)
        return any(_SEVERITY_RANK.get(str(f.get("severity", "info")).lower(), 0) >= floor
                   for f in self.findings)


@dataclass
class PipelineOutcome:
    """The whole run. ``status`` is ``completed`` (every required step ran) or
    ``aborted`` (a required step failed; ``aborted_on`` names its tool).
    ``findings`` is the synthesized finding list (from the last step that
    produced one -- i.e. ``correlate_findings`` in the standard audit)."""

    status: str
    steps: list[StepResult] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    aborted_on: Optional[str] = None

    @property
    def ran(self) -> int:
        return sum(1 for s in self.steps if s.status == "ok")

    @property
    def severity_tally(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for f in self.findings:
            sev = str(f.get("severity") or "info").lower()
            tally[sev] = tally.get(sev, 0) + 1
        return tally


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def run_pipeline(
    steps: list[PipelineStep],
    data_dir: Path,
    *,
    on_step: Optional[Callable[[StepResult], None]] = None,
    dispatch: Optional[Dispatch] = None,
) -> PipelineOutcome:
    """Run ``steps`` in order over the tool registry, threading accumulated
    results/findings into each step's ``when`` predicate, and stopping the whole
    run the moment a ``required`` step doesn't succeed (fail-fast, single
    transaction). ``on_step`` is called once per step with its ``StepResult``
    (after it runs, before the next begins) so a UI can render live."""
    data_dir = Path(data_dir)
    dispatch = dispatch or execute_tool_call
    ctx = PipelineContext(data_dir=data_dir)
    outcome = PipelineOutcome(status="completed")

    for step in steps:
        # A predicate that RAISES is fail-safe:
        # treat the condition as unknown and SKIP the step with a recorded reason,
        # never crash the whole run. A well-formed predicate
        # over not-yet-produced data just returns False (e.g. has_finding() on an
        # empty context) and skips cleanly.
        if step.when is not None:
            try:
                should_run = bool(step.when(ctx))
                skip_detail = "condition not met — step skipped"
            except Exception as e:  # noqa: BLE001 -- a predicate error must not sink the run
                should_run = False
                skip_detail = f"condition could not be evaluated ({e}) — step skipped (fail-safe)"
            if not should_run:
                sr = StepResult(step=step, status="skipped", detail=skip_detail)
                ctx.results.append(sr)
                outcome.steps.append(sr)
                if on_step is not None:
                    on_step(sr)
                continue

        # Resolve any step-output references in this step's args from
        # PRIOR results. If a referenced value wasn't produced (its producer step
        # was skipped/failed/excluded, or the field is empty), fail-safe SKIP this
        # step -- never dispatch it with a missing/garbage value.
        resolved_args, ref_skip = _resolve_step_args(dict(step.args), ctx.results)
        if ref_skip is not None:
            sr = StepResult(step=step, status="skipped", detail=f"{ref_skip} — step skipped")
            ctx.results.append(sr)
            outcome.steps.append(sr)
            if on_step is not None:
                on_step(sr)
            continue

        raw = dispatch(step.tool, resolved_args, data_dir)
        status = raw.get("status")
        if status == "ok":
            result = raw.get("result")
            result = result if isinstance(result, dict) else {"result": result}
            sr = StepResult(step=step, status="ok", result=result)
            # Thread any findings a step produced (correlate_findings is the
            # synthesis; the last one to produce them wins, so a later
            # correlate supersedes an earlier partial).
            found = result.get("findings")
            if isinstance(found, list) and found:
                ctx.findings = found
                outcome.findings = found
        else:
            sr = StepResult(step=step, status=str(status or "error"),
                            detail=str(raw.get("observation") or "").strip() or None)

        ctx.results.append(sr)
        outcome.steps.append(sr)
        if on_step is not None:
            on_step(sr)

        if sr.status != "ok" and step.required:
            outcome.status = "aborted"
            outcome.aborted_on = step.tool
            break

    return outcome


def standard_audit_steps() -> list[PipelineStep]:
    """The built-in "standard audit": a fixed, deterministic security sweep of
    the configured target. Target-correct by construction -- every step below is
    target-facing (network scan or SSH-to-target), so nothing about Kratos's own
    host is ever mixed into the target's findings (the ``cmd_run`` bug this
    replaces).

    Order and rationale:
      1. run_nmap_scan     — map the target's network attack surface. REQUIRED:
                             if the target is unreachable the rest is moot, so a
                             failure here fail-fasts the whole audit.
      2. run_vuln_scan     — known-CVE / misconfig sweep (network). Optional:
                             it's network-heavy and secondary; a hiccup here
                             shouldn't sink the audit.
      3. run_config_audit  — the target's hardening posture over SSH. Optional.
      4. read_journalctl   — pull the target's auth journal over SSH; this also
                             persists the auth-correlation inputs correlate_findings
                             reads. Optional (SSH may be restricted).
      5. correlate_findings— the rule engine synthesizes everything gathered above
                             into ranked findings. REQUIRED: it is the point of the
                             audit.

    Deliberately NOT included: ``parse_auth_log`` and ``collect_system_context``
    — both analyze KRATOS'S OWN host, not the target. ``cmd_run`` ran them and
    folded their output into "the target's findings", which is silently wrong for
    any real remote target. Omitting them is the fix, not an oversight. (They can
    be offered later as an explicit, clearly-labeled "audit this Kratos host"
    pipeline — a different recipe, never mixed into this one.)
    """
    return [
        PipelineStep("run_nmap_scan", required=True,
                     label="Map the target's open ports & services"),
        PipelineStep("run_vuln_scan", required=False,
                     label="Scan the target for known vulnerabilities"),
        PipelineStep("run_config_audit", required=False,
                     label="Audit the target's security configuration"),
        PipelineStep("read_journalctl", required=False,
                     label="Pull the target's auth journal (SSH)"),
        PipelineStep("correlate_findings", required=True,
                     label="Correlate everything into ranked findings"),
    ]
