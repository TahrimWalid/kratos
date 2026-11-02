"""The answer checks (Guards 1-12) as pure functions over one machine's evidence.

Extracted from ``agent/loop.py::_run_agent_loop`` (D.2 §5.1) with no change in what
they decide or say: the loop builds a :class:`MachineEvidence` for its one machine and
calls :func:`evaluate`, :func:`rejections` and :func:`apply_notes`; a fleet answer
(``kratos/fleet/answer.py``) does the same once per machine, each time with THAT
machine's evidence only, so one machine's findings can never make another machine's
answer pass.

Why each check exists, and why each is deliberately narrow, is told where its
evidence is gathered in ``agent/loop.py``; the wording of every correction and NOTE
is the loop's, moved here verbatim.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from kratos import finding_facts as _finding_facts
from kratos.agent.answer_checks.patterns import (
    _CAPABILITY_GAP_RE,
    _HOST_AS_TARGET_RE,
    _KNOWN_COVERAGE_LIMIT_RE,
    _NO_RECORD_ACK_RE,
    _coverage_note,
    _gap_sentence,
    _names_finding,
    _plain_claim_problem,
    _ungrounded_ips,
    _unstated_coverage_gaps,
)
from kratos.timewin.agentwin import unqueried_goal_windows as _unqueried_goal_windows
from kratos.timewin.claims import is_time_scoped as _is_time_scoped, verify_claims as _verify_claims
from kratos.timewin.yes_no import yes_no_problem as _yes_no_problem

# Guard 1: the "explain and skip" bypass only counts an explanation that names the
# rule engine (and only when no data tool returned real data -- see the loop).
_CORRELATION_EXPLAINED_RE = re.compile(r"correlat|rule engine", re.IGNORECASE)
# Guard 5: a tool name preceded by a negation ("I did not run X") is not a claim.
_TOOL_NEGATION_RE = re.compile(
    r"(without|not|never|didn't|did not|no|couldn't|could not|unable to|skipped|instead of)\W+(?:\w+\W+){0,3}$",
    re.IGNORECASE,
)
# Guard 2: the answer says files/configs are unchanged.
_FILE_INTEGRITY_NO_CHANGE_CLAIM_RE = re.compile(
    r"(?:files?|configs?|configuration)\b[^.]{0,40}\bnot\s+(?:been\s+)?(?:tampered|modified|altered|changed)\b"
    r"|\bnot\s+(?:been\s+)?tampered\s+with\b"
    r"|\bno\s+(?:unauthorized\s+)?tampering\b"
    r"|\bintegrity\s+(?:is\s+|remains\s+|appears\s+)?(?:intact|verified|confirmed)\b"
    r"|(?:files?|configs?|configuration)\b[^.]{0,40}\bunchanged\b",
    re.IGNORECASE,
)
# Guard 3: a dismissive overall verdict.
_NO_SUSPICIOUS_ACTIVITY_CLAIM_RE = re.compile(
    r"no\s+suspicious\s+activity"
    r"|nothing\s+suspicious"
    r"|no\s+(?:signs?\s+of\s+)?(?:compromise|intrusion|attack)\b"
    r"|system\s+(?:appears?\s+|looks?\s+)?(?:to\s+be\s+)?(?:clean|fine|normal|secure|safe)\b"
    r"|no\s+(?:issues?|problems?|concerns?)\s+(?:were\s+|was\s+)?(?:found|detected|identified)\b",
    re.IGNORECASE,
)
# Guard 4: a specific recency window claimed in the answer.
_TIMEFRAME_CLAIM_RE = re.compile(
    r"\b(?:last|past|over\s+the\s+last|over\s+the\s+past|within\s+the\s+last|within\s+the\s+past)"
    r"\s+(?:\d+\s*)?(?:hours?|days?|weeks?|months?)\b",
    re.IGNORECASE,
)

# Check name -> (violation tag, how many times it may reject one investigation's answer).
MAX_REJECTIONS: dict[str, int] = {
    "guard1": 2, "guard2": 2, "guard3": 2, "guard12": 1, "guard4": 2, "guard5": 2,
    "guard6": 2, "guard7": 2, "guard8": 1, "guard9": 1, "guard10": 1, "guard11": 1,
}
VIOLATION_TAGS: dict[str, str] = {
    "guard1": "missing_correlation",
    "guard2": "file_integrity_contradiction",
    "guard3": "dismissive_verdict_contradiction",
    "guard12": "serious_finding_left_out",
    "guard4": "staleness_timeframe_contradiction",
    "guard5": "claims_uncalled_tool",
    "guard6": "time_scope_not_queried",
    "guard7": "claims_not_verified",
    "guard8": "unproposed_capability_gap",
    "guard9": "past_state_without_record",
    "guard10": "host_called_target",
    "guard11": "yes_no_contradicts_comparison",
}
# The order corrections are combined in (one rejection per iteration) and the order
# NOTEs are prepended in -- both exactly the loop's historical order.
CORRECTION_ORDER: tuple[str, ...] = (
    "guard11", "guard1", "guard2", "guard3", "guard12", "guard4", "guard5", "guard6",
    "guard7", "guard10", "guard9", "guard8",
)
_NOTE_ORDER: tuple[str, ...] = ("guard1", "guard2", "guard3", "guard4", "guard7", "guard11", "guard9",
                                "guard6", "guard5")


@dataclass
class MachineEvidence:
    """Everything the checks may hold an answer to -- for ONE machine.

    ``findings`` is the latest successful correlation (None: none succeeded);
    ``transcript`` is what grounds the addresses an answer may name (each entry's
    ``observation`` and ``digest``); ``known_tools`` are the names Guard 5 looks for.
    """

    machine: str | None
    goal: str
    findings: list[dict[str, Any]] | None = None
    correlate_called: bool = False
    correlate_error: str | None = None
    any_data_tool_ok: bool = False
    file_integrity_diff: dict[str, Any] | None = None
    staleness_warning: str | None = None
    tools_called: set[str] = field(default_factory=set)
    known_tools: Iterable[str] = ()
    tool_proposals_made: int = 0
    coverage_gaps: list[str] = field(default_factory=list)
    state_no_records: dict[str, str] = field(default_factory=dict)
    comparison_pairs: list[dict[str, Any]] = field(default_factory=list)
    time_ctx: Any = None
    host_mode: bool = False
    transcript: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class CheckResult:
    """One check on one answer: ``trigger`` -- it may send the answer back;
    ``noted`` -- it still tags a NOTE if the answer is accepted as it stands."""

    name: str
    trigger: bool
    noted: bool = False
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def violation(self) -> str:
        return VIOLATION_TAGS[self.name]


@dataclass
class Evaluation:
    results: dict[str, CheckResult]
    verified_claims: list[dict[str, Any]] | None   # None: not time-scoped (keep the previous list)

    def __getitem__(self, name: str) -> CheckResult:
        return self.results[name]


def evaluate(answer: str, ev: MachineEvidence, claims: Any = None) -> Evaluation:
    """Run every check on ``answer`` against ``ev`` (nothing is changed)."""
    findings = ev.findings
    r: dict[str, CheckResult] = {}

    # Guard 1: correlate_findings must have SUCCEEDED.
    never = not ev.correlate_called
    failed = ev.correlate_called and findings is None
    explains_skip = never and not ev.any_data_tool_ok and bool(_CORRELATION_EXPLAINED_RE.search(answer))
    g1 = (never or failed) and not explains_skip
    r["guard1"] = CheckResult("guard1", g1, g1, {"attempted_and_failed": failed})

    # Guard 2: file-integrity contradiction.
    diff = ev.file_integrity_diff
    real_changes = bool(diff and (diff.get("changed") or diff.get("added") or diff.get("removed")))
    g2 = real_changes and bool(_FILE_INTEGRITY_NO_CHANGE_CLAIM_RE.search(answer))
    r["guard2"] = CheckResult("guard2", g2, g2)

    # Guard 3: dismissive verdict vs a HIGH/CRITICAL finding (or a downplayed Act decision).
    high = [f for f in (findings or [])
            if isinstance(f, dict) and str(f.get("severity", "")).lower() in ("high", "critical")]
    unacknowledged = [f for f in high if not _names_finding(answer, f)]
    g3 = bool(unacknowledged) and bool(_NO_SUSPICIOUS_ACTIVITY_CLAIM_RE.search(answer))
    downplayed_act = [
        f for f in (findings or [])
        if isinstance(f, dict) and str((f.get("ssvc") or {}).get("outcome") or "") == "act"
        and str(f.get("state") or "") not in _finding_facts.DECIDED_STATES
        and _finding_facts.downplays(answer, f)
    ]
    if downplayed_act:
        g3 = True
        unacknowledged = unacknowledged + [
            {**f, "title": f"{f.get('title')} (CISA SSVC decision: Act -- remediate as soon as possible; "
                           "the answer calls it unimportant)"} for f in downplayed_act
            if f not in unacknowledged]
    r["guard3"] = CheckResult("guard3", g3, g3, {"unacknowledged": unacknowledged})

    # Guard 12: a serious finding the analysis leaves out (asked once; never a NOTE --
    # Kratos's own block lists it regardless).
    left = [(f, m) for f, m in _finding_facts.left_out(answer, findings) if _finding_facts.relevant_to(ev.goal, f)]
    r["guard12"] = CheckResult("guard12", bool(left), False, {"left_out": left})

    # Guard 4: a claimed timeframe while correlation's own staleness check flagged the inputs.
    g4 = bool(ev.staleness_warning) and bool(_TIMEFRAME_CLAIM_RE.search(answer))
    r["guard4"] = CheckResult("guard4", g4, g4)

    # Guard 5: a Kratos tool the answer names that never ran.
    uncalled = sorted(
        name for name in ev.known_tools
        if name not in ev.tools_called
        and any(not _TOOL_NEGATION_RE.search(answer[: m.start()])
                for m in re.finditer(rf"\b{re.escape(name)}\b", answer))
    )
    r["guard5"] = CheckResult("guard5", bool(uncalled), bool(uncalled), {"uncalled": uncalled})

    # Guard 6: the goal's time periods must have been queried.
    unqueried = _unqueried_goal_windows(ev.time_ctx)
    r["guard6"] = CheckResult("guard6", bool(unqueried), bool(unqueried), {"unqueried": unqueried})

    # Guard 7: structured claims against this run's measurements.
    problems: list[str] = []
    verified: list[dict[str, Any]] | None = None
    if _is_time_scoped(ev.time_ctx):
        problems, verified = _verify_claims(ev.time_ctx, answer, claims)
    r["guard7"] = CheckResult("guard7", bool(problems), bool(problems), {"problems": problems})

    # Guard 8: a capability gap in prose, never proposed (asked once; surfaced, never a NOTE).
    gap = None if ev.tool_proposals_made else _CAPABILITY_GAP_RE.search(answer)
    if gap is not None and ev.coverage_gaps and _KNOWN_COVERAGE_LIMIT_RE.search(_gap_sentence(answer, gap)):
        gap = None
    r["guard8"] = CheckResult("guard8", gap is not None, False, {"gap": gap})

    # Guard 9: a past state with no record must be said, not inferred.
    g9 = bool(ev.state_no_records) and not _NO_RECORD_ACK_RE.search(answer)
    r["guard9"] = CheckResult("guard9", g9, g9)

    # Guard 10: in host mode, Kratos's own machine is not "the target".
    r["guard10"] = CheckResult("guard10", ev.host_mode and bool(_HOST_AS_TARGET_RE.search(answer)), False)

    # Guard 11: a Yes/No to "more/fewer ... than ...?" must match the comparison.
    yes_no = (_yes_no_problem(ev.goal, answer, ev.comparison_pairs, getattr(ev.time_ctx, "windows", {}) or {})
              if ev.comparison_pairs else None)
    r["guard11"] = CheckResult("guard11", yes_no is not None, yes_no is not None, {"yes_no": yes_no})

    return Evaluation(r, verified)


def correction_text(res: CheckResult, ev: MachineEvidence) -> str:
    """The rejection the model reads for one triggered check (the loop's wording)."""
    d = res.data
    if res.name == "guard11":
        yn = d["yes_no"]
        return (
            f"REJECTED (yes/no contradicts the comparison): {yn['why']}, so the answer to the "
            f"question as asked is \"{yn['expected']}\", but your answer starts with "
            f"\"{yn['got']}\". Start the answer with \"{yn['expected']}\" and keep the same numbers."
        )
    if res.name == "guard1":
        if d["attempted_and_failed"]:
            return (
                "REJECTED (correlate_findings attempted but never succeeded): your "
                "correlate_findings call did not return a real result -- concluding on raw "
                "tool observations without a successful correlation pass risks missing "
                f"evidence you already collected. The real error was: "
                f"{ev.correlate_error!r}. If this was caused by a guessed file "
                "path, retry correlate_findings using the EXACT path string from a prior "
                "tool's own Observation in this conversation (e.g. run_nmap_scan's "
                "parsed_json_file, collect_system_context's context_file, parse_auth_log's "
                "stats_file) -- or omit the argument entirely to auto-discover the latest "
                "file. Do not guess a new path."
            )
        return (
            "REJECTED (correlate_findings not called): correlate_findings has not been "
            "called yet in this investigation. It is the deterministic rule engine that "
            "reliably classifies raw observations into real findings -- concluding without "
            "ever running it risks missing evidence you already collected. Either call "
            "correlate_findings now to synthesize what you've gathered, or if it genuinely "
            "cannot run (e.g. no collection tool succeeded that it could use as input), your "
            "final_answer text itself must explicitly say so (e.g. 'concluding without "
            "correlate_findings because ...') -- a reasoning field alone is not enough, and "
            "this cannot be omitted silently."
        )
    if res.name == "guard2":
        return (
            "REJECTED (file-integrity contradiction): this final_answer's "
            "characterization of file/config integrity conflicts with "
            "check_file_integrity's actual result from THIS investigation. The real diff "
            f"was: {json.dumps(ev.file_integrity_diff)}. Revise your final_answer so it "
            "accurately reflects this -- do not claim files are unchanged/not tampered "
            "with when this diff shows real changes."
        )
    if res.name == "guard3":
        summary = "; ".join(f"{f.get('id')}: {f.get('title')}" for f in d["unacknowledged"])
        return (
            "REJECTED (dismissive-verdict contradiction): this final_answer's overall "
            "verdict (e.g. 'no suspicious activity') contradicts real HIGH/CRITICAL "
            f"finding(s) correlate_findings just produced in THIS investigation: "
            f"{summary}. Revise your final_answer so its overall characterization "
            "is consistent with these findings -- do not describe the investigation as "
            "clean/unsuspicious while also citing evidence that contradicts that."
        )
    if res.name == "guard12":
        listed = "; ".join(f"{_finding_facts.model_line(f)} [missing from your answer: {', '.join(m)}]"
                           for f, m in d["left_out"])
        return (
            "REJECTED (serious finding left out): these HIGH/CRITICAL findings are open on this machine "
            f"and your final_answer does not cover them: {listed}. Rewrite your final_answer so it "
            "addresses each one -- what it means and what to do -- and names its facts (the source "
            "address, a known-malicious match, the process id or package). Keep everything else that is right."
        )
    if res.name == "guard4":
        return (
            "REJECTED (staleness-vs-timeframe contradiction): this final_answer states a "
            "specific recency window (e.g. 'in the last 24 hours'), but correlate_findings' "
            f"own staleness_warning from THIS investigation says: {ev.staleness_warning!r} "
            "-- the data you correlated is not actually known to be confined to that window. "
            "Revise your final_answer to either drop the specific timeframe claim, or "
            "explicitly caveat that the underlying data spans a wider/uncertain window than "
            "what was asked."
        )
    if res.name == "guard5":
        return (
            "REJECTED (claims a tool that was never run): this final_answer names "
            f"{', '.join(d['uncalled'])}, but that tool was NOT called in this investigation. "
            "Either call it now and use its real result, or remove the claim. If you are "
            "recommending it as a follow-up, say so explicitly (e.g. 'I did not run X')."
        )
    if res.name == "guard6":
        return (
            "REJECTED (time period not queried): the goal asks about "
            + "; ".join(f"\"{w.phrase}\" = {w.summary()}" for w in d["unqueried"])
            + ", but no tool has queried that window yet. Call a time-aware tool (e.g. "
            "read_journalctl) with \"window\": {\"id\": \"<id above>\"} before concluding. If no "
            "available tool can cover that period, say so explicitly in the answer."
        )
    if res.name == "guard7":
        return (
            "REJECTED (claims do not match what was measured):\n- " + "\n- ".join(d["problems"])
            + "\nFix the answer and its \"claims\" list: every count must equal the measured value, "
            "'none' needs 100% coverage of that window (otherwise say which part is unknown), and every "
            "period you mention must be a window you queried. If a period was not measured, run "
            "measure_auth_activity for it first."
        )
    if res.name == "guard10":
        return (
            "CHECK (wording): this investigation is about KRATOS'S OWN MACHINE, not a monitored "
            "target. Reword the answer to say \"this Kratos machine\" instead of \"the target\", "
            "and send it again (same facts)."
        )
    if res.name == "guard9":
        return (
            "REJECTED (past state without a record): state_as_of found NO saved record of "
            + "; ".join(ev.state_no_records.values())
            + ". Say plainly that Kratos has no record of that, and do not infer the past state "
            "from other data (login or sudo events say nothing about which ports were open). "
            "If useful, say what WOULD answer it next time (e.g. a scan saved at that time)."
        )
    if res.name == "guard8":
        return (
            "CHECK (capability gap not proposed): your answer says Kratos can't do something "
            f"(\"{d['gap'].group(0).strip()}\"). If that is a real gap for THIS goal, respond now with "
            'a tool_proposal ({"reasoning": "...", "tool_proposal": {"name": "...", "description": '
            '"..."}}) so a human can decide whether to build it -- it does not end the '
            "investigation -- and then send your final_answer again. If an existing tool already "
            "covers it, use that tool instead. If the gap isn't real, reword the answer."
        )
    raise KeyError(res.name)


def rejections(evaluation: Evaluation, ev: MachineEvidence, counts: dict[str, int], *,
               final_iteration: bool) -> tuple[list[str], list[str]]:
    """(violation tags, correction texts) for every triggered check that still has a
    rejection left -- one combined rejection per iteration. Bumps ``counts`` in place.
    Nothing is rejected on the final iteration (there is no next one to retry into)."""
    violations: list[str] = []
    corrections: list[str] = []
    if final_iteration:
        return violations, corrections
    for name in CORRECTION_ORDER:
        res = evaluation[name]
        if res.trigger and counts.get(name, 0) < MAX_REJECTIONS[name]:
            counts[name] = counts.get(name, 0) + 1
            violations.append(res.violation)
            corrections.append(correction_text(res, ev))
    return violations, corrections


@dataclass
class NotedAnswer:
    text: str
    unstated_gaps: list[str]
    invented_ips: list[str]

    def noted(self, evaluation: Evaluation) -> dict[str, bool]:
        """Which NOTEs the answer carries, by violation tag (for the run record)."""
        out = {VIOLATION_TAGS[n]: evaluation[n].noted for n in
               ("guard1", "guard2", "guard3", "guard4", "guard5", "guard6", "guard7", "guard9", "guard11")}
        out["unstated_coverage_gap"] = bool(self.unstated_gaps)
        out["ungrounded_ip"] = bool(self.invented_ips)
        return out


def note_text(res: CheckResult, ev: MachineEvidence) -> str:
    """The NOTE prepended for a check still violated when the answer is accepted."""
    d = res.data
    if res.name == "guard1":
        if d["attempted_and_failed"]:
            return (
                "[NOTE: correlate_findings (the deterministic rule engine) was attempted "
                "during this investigation but never returned a successful result (last "
                f"error: {ev.correlate_error!r}), and this conclusion does not "
                "explain why -- treat it as a lower-confidence, observation-only "
                "conclusion, not one corroborated by the rule engine.]\n\n"
            )
        return (
            "[NOTE: correlate_findings (the deterministic rule engine) was never run "
            "during this investigation, and this conclusion does not explain why -- "
            "treat it as a lower-confidence, observation-only conclusion, not one "
            "corroborated by the rule engine.]\n\n"
        )
    if res.name == "guard2":
        return (
            "[NOTE: this answer's characterization of file/config integrity conflicts "
            f"with check_file_integrity's actual result from this investigation: "
            f"{json.dumps(ev.file_integrity_diff)}. Treat the file-integrity portion of "
            "this answer as unreliable -- trust the diff above instead.]\n\n"
        )
    if res.name == "guard3":
        summary = "; ".join(f"{f.get('id')}: {f.get('title')}" for f in d["unacknowledged"])
        return (
            "[NOTE: this answer's overall verdict conflicts with real HIGH/CRITICAL "
            f"finding(s) from this investigation: {summary}. Treat the dismissive "
            "framing above as unreliable.]\n\n"
        )
    if res.name == "guard4":
        return (
            "[NOTE: this answer states a specific recency window, but correlate_findings' "
            f"own staleness_warning from this investigation says: {ev.staleness_warning!r} "
            "-- the underlying data is not actually confirmed to be confined to that window. "
            "Treat the claimed timeframe as unreliable.]\n\n"
        )
    if res.name == "guard7":
        problems = d["problems"]
        plain = [_plain_claim_problem(p, ev.time_ctx) for p in problems[:4]]
        return (
            "[NOTE: parts of this answer could not be verified against Kratos's own measurements: "
            + "; ".join(plain) + (" (and more)" if len(problems) > 4 else "")
            + " -- treat those statements as unverified.]\n\n"
        )
    if res.name == "guard11":
        yn = d["yes_no"]
        return f"[NOTE: {yn['why']}, so the answer to the question is {yn['expected']}.]\n\n"
    if res.name == "guard9":
        return (
            "[NOTE: Kratos has no saved record of " + "; ".join(ev.state_no_records.values())
            + " -- anything above about that past state is inferred from other data, not "
            "observed.]\n\n"
        )
    if res.name == "guard6":
        return (
            "[NOTE: the goal asked about "
            + "; ".join(f"\"{w.phrase}\" ({w.id})" for w in d["unqueried"])
            + ", but no data for that period was queried -- this answer is not scoped to it.]\n\n"
        )
    if res.name == "guard5":
        return (
            f"[NOTE: this answer refers to {', '.join(d['uncalled'])}, which was never run in "
            "this investigation -- anything attributed to it above is unverified.]\n\n"
        )
    raise KeyError(res.name)


def apply_notes(answer: str, evaluation: Evaluation, ev: MachineEvidence) -> NotedAnswer:
    """``answer`` with a NOTE in front for every check still violated, then the
    unstated-coverage-gap NOTE and the invented-address NOTE -- each a prefix, so the
    model's own text stays the tail of the result."""
    text = answer
    for name in _NOTE_ORDER:
        res = evaluation[name]
        if res.noted:
            text = note_text(res, ev) + text
    unstated = _unstated_coverage_gaps(ev.coverage_gaps, text)
    if unstated:
        text = _coverage_note(unstated) + text
    # An address the answer names that nothing Kratos read contains is the model's
    # invention (phase A audit: an answer blamed 10.136.28.1 for an attack from .52).
    invented = _ungrounded_ips(text, ev.goal, ev.transcript)
    if invented:
        text = (f"[NOTE: this answer mentions {', '.join(invented)}, which appears in nothing Kratos read "
                "in this investigation -- treat it as unverified.]\n\n" + text)
    return NotedAnswer(text, unstated, invented)
