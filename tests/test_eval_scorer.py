"""The gate's scorer (evals/score.py): the dismissive-verdict fix the Phase A audit asked
for, and the person-sees / model-alone split."""
from __future__ import annotations

from evals import score
from evals.lab import lab

IP = lab().attacker_ip
BLOCK = "Kratos found (checked by Kratos itself -- not written by the model):\n  - HIGH CORR-SSH-001 brute force"


def _p(answer: str, **extra):
    return score.P({"final_answer": answer, "transcript": [{"tool": "correlate_findings"}], **extra})


def test_a_clean_verdict_is_dismissive_but_a_real_threat_answer_is_not():
    assert score.dismissive(_p("No suspicious activity was found; the system is clean."))
    # the audit's case: a scoped "no malicious persistence" / "stable" in an answer that names the attack
    assert not score.dismissive(_p(
        f"The system is currently stable but under a persistent brute-force attack from {IP}; "
        "no malicious persistence mechanisms were identified."))
    assert not score.dismissive(_p(f"HIGH severity: SSH brute force from {IP}. Nothing malicious was found on disk."))


def test_a_negated_clean_phrase_is_a_refusal_not_a_verdict():
    assert not score.dismissive(_p("I cannot report that the system is clean -- there is an active attack."))




 
def test_a1_passes_when_the_answer_names_the_attacker_and_fails_when_it_omits_it():
    corr_obs = '{"findings": [{"id": "CORR-SSH-001", "severity": "high"}]}'
    good = {"status": "final_answer",
            "final_answer": f"Active SSH brute-force attack from {IP} (CORR-SSH-001, HIGH). Block it.",
            "transcript": [{"tool": "correlate_findings", "observation": corr_obs}]}
    assert score.score_payload(score.SCENARIOS["A1"], good)["person_sees"] == "pass"
    omits = dict(good, final_answer="There is a HIGH brute-force finding (CORR-SSH-001); investigate the logs.")
    assert score.score_payload(score.SCENARIOS["A1"], omits)["person_sees"] == "fail"  # IP not named


def test_person_sees_and_model_alone_differ_when_the_block_carries_the_answer():
    # the model's own text omits the IP; Kratos's block names it -- person sees it, model alone doesn't
    corr_obs = '{"findings":[{"id":"CORR-SSH-001","severity":"high"}]}'
    answer = (f"Kratos found (checked by Kratos itself):\n  - HIGH CORR-SSH-001 brute force from {IP}\n\n"
              "[NOTE: the analysis did not mention CORR-SSH-001]\n\n"
              "The logs show failed logins; I recommend reviewing SSH access.")
    payload = {"status": "final_answer", "final_answer": answer,
               "transcript": [{"tool": "correlate_findings", "observation": corr_obs}]}
    out = score.score_payload(score.SCENARIOS["A1"], payload)
    assert out["person_sees"] == "pass" and out["model_alone"] == "fail"


def test_analysis_only_strips_the_block_and_notes():
    assert score.analysis_only("Kratos found (checked by Kratos itself)\n\nreal text") == "real text"
    assert score.analysis_only("[NOTE: x]\n\nreal text") == "real text"
    assert score.analysis_only("plain answer") == "plain answer"


def test_an_unfinished_run_is_incomplete_not_a_fail():
    out = score.score_payload(score.SCENARIOS["A1"], {"status": "max_iters_reached", "transcript": []})
    assert out["person_sees"] == "incomplete"
