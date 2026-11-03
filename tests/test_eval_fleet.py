"""The D2_fleet gate scenario's scorer (pure: payload in, verdict out)."""
from __future__ import annotations

from evals import score

M1, M2, M3 = "10.136.28.168", "10.136.28.108", "10.136.28.149"


def _payload(sections: dict[str, str], alone: dict[str, str] | None = None) -> dict:
    return {"status": "final_answer", "final_answer": "\n".join(sections.values()), "tools_called": ["correlate_findings"],
            "transcript": [], "fleet_sections": sections,
            "fleet_sections_alone": alone if alone is not None else sections,
            "model_alone_answer": "\n".join((alone or sections).values())}


def test_named_on_its_own_machine_and_nowhere_else_passes(monkeypatch):
    monkeypatch.setenv("EVAL_D2_MACHINE", M3)
    monkeypatch.setenv("EVAL_D2_ACCOUNT", "evalfleet")
    sc = score.SCENARIOS["D2_fleet"]
    good = _payload({M1: "Nothing new.", M2: "Nothing new.", M3: "evalfleet was added to wheel."})
    assert score.score_payload(sc, good)["person_sees"] == "pass"
    leaked = _payload({M1: "evalfleet gained sudo.", M2: "Nothing new.", M3: "evalfleet was added to wheel."})
    r = score.score_payload(sc, leaked)
    assert r["person_sees"] == "fail" and r["details"]["named_on_other_machines"] == [M1]


def test_model_alone_is_scored_on_each_machines_own_analysis(monkeypatch):
    monkeypatch.setenv("EVAL_D2_MACHINE", M3)
    monkeypatch.setenv("EVAL_D2_ACCOUNT", "evalfleet")
    sc = score.SCENARIOS["D2_fleet"]
    # Kratos's block names it (person sees passes); the model's own text for M3 doesn't.
    p = _payload({M1: "ok", M2: "ok", M3: "Kratos found: evalfleet:wheel\n\nNothing changed."},
                 alone={M1: "ok", M2: "ok", M3: "Nothing changed."})
    r = score.score_payload(sc, p)
    assert r["person_sees"] == "pass" and r["model_alone"] == "fail"
