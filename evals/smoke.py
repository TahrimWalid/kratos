"""The gate's harness, proven without a model key or a lab (the `eval-replay-smoke` CI job).

A scripted model (no network) runs a real investigation in replay against a tiny
synthetic recording, the answer is scored, and the gate rule is exercised on made-up
counts. This proves the plumbing -- replay, scoring, the gate -- not answer quality.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from evals import gate, replay, score

TARGET = "10.136.28.168"
ATTACKER = "10.136.28.52"

_FINDING = {"id": "CORR-SSH-001", "severity": "high", "title": "SSH brute-force burst",
            "evidence": [f"burst from {ATTACKER}"], "source_ips": [ATTACKER]}

# A recording the scripted model's one correlate_findings call will hit.
_RECORDING = {
    "format": replay.RECORDING_FORMAT, "scenario": "A1", "goal": score.SCENARIOS["A1"].goal,
    "target": TARGET, "collection": None,
    "calls": [{"tool": "correlate_findings", "args": {},
               "result": {"status": "ok", "result": {"findings": [_FINDING], "count": 1,
                                                      "staleness_warning": None, "missing_inputs": [],
                                                      "input_errors": {}, "inputs_used": {}}}}],
}

_ANSWER = (f"The system is under an active SSH brute-force attack from {ATTACKER} (CORR-SSH-001, HIGH). "
           "I recommend blocking that address and reviewing fail2ban.")

_SCRIPT = [json.dumps({"reasoning": "correlate", "tool": "correlate_findings", "args": {}}),
           json.dumps({"reasoning": "done", "final_answer": _ANSWER})]


def _scripted_model():
    replies = list(_SCRIPT)

    def agent_chat(system_prompt: str, user_prompt: str, max_tokens=None, **kw):  # noqa: ANN001
        return replies.pop(0) if replies else json.dumps({"reasoning": "stop", "final_answer": _ANSWER})

    return agent_chat


def _replay_a_recorded_run() -> dict:
    from kratos import kratos_config
    from kratos.agent import loop
    from kratos.run_context import run_scope

    orig = loop.agent_chat
    loop.agent_chat = _scripted_model()
    try:
        with tempfile.TemporaryDirectory(prefix="kratos-smoke-") as d:
            dd = Path(d)
            kratos_config.set_active_data_dir(dd)
            kratos_config.set_active_target(TARGET)
            with replay.install(_RECORDING) as tracker, run_scope("cli"):
                payload = loop.run_agent(score.SCENARIOS["A1"].goal, dd, max_iters=4)
            payload["_replay"] = {"hits": tracker.hits, "left_recording": tracker.left_recording}
            return payload
    finally:
        loop.agent_chat = orig


def _check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def run() -> int:
    # 1. replay a run with the scripted model, score it
    payload = _replay_a_recorded_run()
    _check(payload.get("status") == "final_answer", f"run did not finish: {payload.get('status')}")
    _check(payload["_replay"]["hits"] >= 1 and not payload["_replay"]["left_recording"],
           "the correlate_findings call did not hit the recording")
    scored = score.score_payload(score.SCENARIOS["A1"], payload)
    _check("correlate_findings" in [e.get("tool") for e in payload.get("transcript") or [] if e.get("tool")],
           "no tool call recorded")
    _check(scored["person_sees"] == "pass", f"A1 should pass on the scripted answer: {scored}")
    _check((payload.get("final_answer") or "").startswith("Kratos found"),
           "Kratos's findings block should lead the answer")

    # 2. the scorer tells a clean answer from a dismissive one and reads the analysis alone
    _check(not score.dismissive(score.P({"final_answer": _ANSWER})), "a real-threat answer is not dismissive")
    _check(score.dismissive(score.P({"final_answer": "No suspicious activity; the system is clean."})),
           "a clean verdict is dismissive")
    _check(score.analysis_only("Kratos found (checked by Kratos itself)\n\nThe model's text.") == "The model's text.",
           "analysis_only did not strip Kratos's block")

    # 3. the gate rule: a hard failure, a scored regression after re-run, a clean pass
    kinds = {"F1": "hard", "A1": "scored"}
    hard_fail = gate.decide([gate.ScenarioResult("F1", "hard", person_pass=4, person_fail=1)],
                            {"scenarios": {"F1": {"person_pass": 5, "n": 5}}})
    _check(not hard_fail.passed and hard_fail.hard_failures, "a hard-scenario failure must fail the gate")
    base = {"scenarios": {"A1": {"person_pass": 5, "n": 5}}}
    drop = gate.decide([gate.ScenarioResult("A1", "scored", person_pass=2, person_fail=3)], base)
    _check("A1" in drop.needs_rerun, "a 3-run drop should trigger a re-run")
    reran = gate.decide([gate.ScenarioResult("A1", "scored", person_pass=2, person_fail=8)], base, reran=True)
    _check(not reran.passed, "a 40-point drop after re-run must fail the gate")
    ok = gate.decide([gate.ScenarioResult("A1", "scored", person_pass=5, person_fail=0)], base)
    _check(ok.passed and not ok.needs_rerun, "an at-baseline scenario must pass quietly")

    # 4. a recording that leaves the lab is caught
    bad = dict(_RECORDING, calls=_RECORDING["calls"] + [{"tool": "x", "args": {},
               "result": {"note": "reached 8.8.8.8 with key sk-abcdefghijklmnopqrstuvwxyz"}}])
    probs = replay.scan_recording(bad)
    _check(any("8.8.8.8" in p for p in probs) and any("key" in p.lower() for p in probs),
           f"scan_recording should flag the public IP and the key: {probs}")

    print("eval smoke: replay, scoring and the gate rule all work (scripted model, no lab).")
    return 0


if __name__ == "__main__":
    sys.exit(run())
