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
    ``ok`` (ran, tool returned ok), ``error`` (dispatch error, or the tool's own
    result said ``status: error``),
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
    run_id: Optional[str] = None      # this run's record (kratos.trace), when one was written

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

    @property
    def lifecycle_line(self) -> Optional[str]:
        """'New 2 · Still open 3 · Fixed 1 · Hidden by your decisions 4' from the
        last correlation step, or None when no step correlated."""
        for s in reversed(self.steps):
            if s.tool == "correlate_findings" and isinstance(s.result, dict) and s.result.get("lifecycle"):
                return str(s.result["lifecycle"])
        return None


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def run_pipeline(
    steps: list[PipelineStep],
    data_dir: Path,
    *,
    on_step: Optional[Callable[[StepResult], None]] = None,
    dispatch: Optional[Dispatch] = None,
) -> PipelineOutcome:
    """A pipeline run, recorded as one run record (kratos.trace): each dispatched step
    is a tool-call span, a skipped one an instant span saying why."""
    from kratos.trace import recorder as _trace

    with _trace.run_trace("pipeline", data_dir, name="pipeline", steps=[s.tool for s in steps]) as tr:
        outcome = _pipeline_body(steps, data_dir, on_step=on_step, dispatch=dispatch)
        if tr is not None:
            outcome.run_id = tr.trace_id
            _trace.set_result(status=outcome.status, aborted_on=outcome.aborted_on,
                              finding_ids=[str(f.get("id")) for f in outcome.findings])
    return outcome


def _trace_skipped_step(sr: "StepResult") -> None:
    from kratos.trace import recorder as _trace

    _trace.event("tool_call", sr.step.tool, tool=sr.step.tool, skipped=True, detail=sr.detail)


def _pipeline_body(
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
                _trace_skipped_step(sr)
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
            _trace_skipped_step(sr)
            ctx.results.append(sr)
            outcome.steps.append(sr)
            if on_step is not None:
                on_step(sr)
            continue

        raw = dispatch(step.tool, resolved_args, data_dir)
        status = raw.get("status")
        result = raw.get("result") if status == "ok" else None
        if status == "ok" and not isinstance(result, dict):
            result = {"result": result}
        if status == "ok" and result.get("status") == "error":
            # The call went through but the tool itself reports failure (an SSH
            # read that failed, a scan that could check nothing): not a pass. A
            # deliberate refusal that names what wasn't checked (a network scan
            # of a box reached only through its sub-agent) is a skip, so the
            # rest of the audit still runs.
            detail = result.get("observation") or "; ".join(str(e) for e in result.get("errors") or [])
            sr = StepResult(step=step, status="skipped" if result.get("coverage_gap") else "error", result=result,
                            detail=str(detail).strip() or "the tool reported an error")
        elif status == "ok":
            sr = StepResult(step=step, status="ok", result=result)
            # Thread any findings a step produced (correlate_findings is the
            # synthesis; the last one to produce them wins, so a later
            # correlate supersedes an earlier partial). Only report-shaped
            # findings (id + severity): run_vuln_scan's raw matches also sit
            # under a "findings" key and must not stand in for them.
            found = [f for f in result.get("findings") or []
                     if isinstance(f, dict) and f.get("id") and f.get("severity")]
            if found:
                ctx.findings = found
                outcome.findings = found
        else:
            sr = StepResult(step=step, status=str(status or "error"),
                            detail=str(raw.get("observation") or "").strip() or None)

        ctx.results.append(sr)
        outcome.steps.append(sr)
        if on_step is not None:
            on_step(sr)

        if sr.status not in ("ok", "skipped") and step.required:
            outcome.status = "aborted"
            outcome.aborted_on = step.tool
            break

    return outcome


AUDIT_BUDGET_SECONDS = 480.0


def run_standard_audit(
    data_dir: Path,
    *,
    on_step: Optional[Callable[["StepResult"], None]] = None,
    dispatch: Optional[Dispatch] = None,
    skip_tools: frozenset[str] = frozenset(),
    target: Optional[str] = None,
    budget: float = AUDIT_BUDGET_SECONDS,
) -> PipelineOutcome:
    """The standard audit on the collection layer (kratos.collect): every check, quick and
    slow, re-run now (``force``) in parallel -- the SAME checks an investigation starts
    from -- then one ``correlate_findings`` over what they collected. One implementation
    of "look at the machine", not two. Each check is reported as a step (named by the tool
    it ran) so the screen, the CLI, schedules and reports read it like any pipeline.
    ``skip_tools``: tools an unattended run must not use (the approval-gated ones).
    Recorded as one run record (kratos.trace): each check a collection-check span."""
    from kratos.trace import recorder as _trace

    with _trace.run_trace("audit", data_dir, name="standard audit", skip_tools=sorted(skip_tools)) as tr:
        outcome = _standard_audit_body(data_dir, on_step=on_step, dispatch=dispatch, skip_tools=skip_tools,
                                      target=target, budget=budget)
        if tr is not None:
            outcome.run_id = tr.trace_id
            _trace.set_result(status=outcome.status, aborted_on=outcome.aborted_on,
                              finding_ids=[str(f.get("id")) for f in outcome.findings])
    return outcome


def _standard_audit_body(
    data_dir: Path,
    *,
    on_step: Optional[Callable[["StepResult"], None]] = None,
    dispatch: Optional[Dispatch] = None,
    skip_tools: frozenset[str] = frozenset(),
    target: Optional[str] = None,
    budget: float = AUDIT_BUDGET_SECONDS,
) -> PipelineOutcome:
    from kratos.collect import checks as _checks  # noqa: F401 -- registers the built-in checks
    from kratos.collect import registry as _registry
    from kratos.collect import runner as _runner

    data_dir = Path(data_dir)
    outcome = PipelineOutcome(status="completed")

    def to_step(o: Any) -> StepResult:
        tool = (o.tools[0] if o.tools else None) or (_CHECK_TOOLS.get(o.name) or (o.name,))[0]
        step = PipelineStep(tool, label=o.label, required=False)
        first = next((s for s in o.steps if s.get("tool") == tool), None)
        obs = (first or {}).get("observation") or {}
        result = obs.get("result") if isinstance(obs, dict) and isinstance(obs.get("result"), dict) else None
        if o.status in ("ok", "partial"):
            return StepResult(step=step, status="ok", result=result or {}, detail=o.summary)
        if o.status in ("not_supported", "skipped"):
            return StepResult(step=step, status="skipped", result=result, detail=o.reason or o.summary)
        return StepResult(step=step, status="error", result=result, detail=o.summary)

    def on_outcome(o: Any) -> None:
        sr = to_step(o)
        outcome.steps.append(sr)
        if on_step is not None:
            on_step(sr)

    chosen = tuple(c.name for c in _registry.checks()
                   if not (set(_tool_names(c)) & set(skip_tools)))
    report = _runner.prepare(target, data_dir, classes=("quick", "slow"), budget=budget, force=True,
                             only=chosen, dispatch=dispatch or execute_tool_call, correlate=True,
                             on_outcome=on_outcome)
    if report.disabled_reason:
        outcome.status = "aborted"
        outcome.aborted_on = "run_nmap_scan"
        return outcome
    # The port scan keeps its old role as the "is the target there at all" check: when it FAILS (not
    # "unavailable for this machine"), the audit is reported as aborted -- never a quiet partial pass.
    ports = next((c for c in report.checks if c.name == "ports"), None)
    if ports is not None and ports.status == "failed":
        outcome.status = "aborted"
        outcome.aborted_on = "run_nmap_scan"
    if report.correlation is not None:
        step = PipelineStep("correlate_findings", required=True, label="Correlate everything into ranked findings")
        sr = StepResult(step=step, status="ok", result=report.correlation)
        outcome.steps.append(sr)
        outcome.findings = [f for f in report.findings if isinstance(f, dict) and f.get("id") and f.get("severity")]
        if on_step is not None:
            on_step(sr)
    else:
        step = PipelineStep("correlate_findings", required=True)
        sr = StepResult(step=step, status="error", detail=report.correlation_error or "nothing was collected to correlate")
        outcome.steps.append(sr)
        outcome.status = "aborted"
        outcome.aborted_on = outcome.aborted_on or "correlate_findings"
        if on_step is not None:
            on_step(sr)
    return outcome


# The tools each check runs (to leave out the ones an unattended run may not use).
_CHECK_TOOLS = {
    "ports": ("run_nmap_scan",), "auth_activity": ("measure_auth_activity",), "log_integrity": ("check_log_integrity",),
    "privileged_accounts": ("list_privileged_accounts",), "config_audit": ("run_config_audit",),
    "vuln_scan": ("run_vuln_scan",), "yara_sweep": ("run_yara_scan",), "file_integrity": ("check_file_integrity",),
    "log_sync": (),
}


def _tool_names(check: Any) -> tuple[str, ...]:
    return _CHECK_TOOLS.get(check.name, ())


def standard_audit_steps() -> list[PipelineStep]:
    """The built-in "standard audit", as a plan: what it looks at, in the order it is
    shown. It RUNS through ``run_standard_audit`` (the collection layer: every check in
    parallel, then one correlation); this list is what previews, ``/plan`` and approval
    summaries describe, one entry per check plus the correlation.

    Target-correct by construction -- every step is target-facing (a network scan or an
    SSH/sub-agent read of the target), so nothing about Kratos's own host is ever mixed
    into the target's findings (the ``cmd_run`` bug this replaced). ``parse_auth_log`` and
    ``collect_system_context`` analyse KRATOS'S OWN host and are deliberately not here.
    """
    return [
        PipelineStep("run_nmap_scan", required=False,
                     label="Map the target's open ports & services"),
        PipelineStep("measure_auth_activity", {"window": {"kind": "rolling", "amount": 24, "unit": "hour"}},
                     required=False, label="Count the target's sign-in activity over the last 24 hours"),
        PipelineStep("check_log_integrity", required=False,
                     label="Check whether the target's logs were cleared or edited"),
        PipelineStep("list_privileged_accounts", required=False,
                     label="List who has privileged access on the target"),
        PipelineStep("run_config_audit", required=False,
                     label="Audit the target's security configuration"),
        PipelineStep("check_file_integrity", required=False,
                     label="Compare the target's critical files with their baseline"),
        PipelineStep("run_vuln_scan", required=False,
                     label="Scan the target for known vulnerabilities"),
        PipelineStep("run_yara_scan", required=False,
                     label="Sweep the target's usual drop locations for malware signatures"),
        PipelineStep("correlate_findings", required=True,
                     label="Correlate everything into ranked findings"),
    ]
