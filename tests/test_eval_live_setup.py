"""D.3 follow-up: the live gate gives every run the configured vulnerability index, and a
package scenario without one is reported incomplete with the reason -- never a fail that
looks like the model's (V1_pkg used to fail 5/5 on every branch through the gate)."""
from __future__ import annotations

from evals import lab as L
from evals import run as R
from evals import score


def test_the_index_is_linked_into_a_live_runs_data_folder(tmp_path, monkeypatch):
    src = tmp_path / "vulndb.sqlite"
    src.write_bytes(b"SQLite format 3\x00 test")
    monkeypatch.setenv("EVAL_VULNDB", str(src))
    dd = tmp_path / "run"
    assert R._link_vulndb(dd) is True
    assert (dd / "vulndb" / "vulndb.sqlite").read_bytes() == src.read_bytes()


def test_without_an_index_v1_is_incomplete_with_the_reason(tmp_path, monkeypatch):
    monkeypatch.setenv("EVAL_VULNDB", str(tmp_path / "missing.sqlite"))
    monkeypatch.setattr(L, "lab", lambda: L.Lab(target="10.0.0.5", target_user="u", key="k", target_incus="t",
                                                attacker_incus="a", attacker_ip="10.0.0.6", vulndb=""))
    payload = R._run_once(score.SCENARIOS["V1_pkg"], mode="live", data_dir=tmp_path / "run")
    assert payload["status"] == "no_vulndb"
    scored = score.score_payload(score.SCENARIOS["V1_pkg"], payload)
    assert scored["person_sees"] == "incomplete" and "EVAL_VULNDB" in scored["details"]["reason"]


def test_v1_expectations_come_from_the_lab_config_unless_overridden(monkeypatch):
    monkeypatch.delenv("EVAL_V1_PKG", raising=False)
    assert L.expected("V1_pkg", "package", "EVAL_V1_PKG") == "nghttp2"
    assert L.expected("V1_pkg", "cve", "EVAL_V1_CVE") == "CVE-2023-44487"
    monkeypatch.setenv("EVAL_V1_PKG", "openssl")
    assert L.expected("V1_pkg", "package", "EVAL_V1_PKG") == "openssl"


def test_v1_scores_the_planted_package_without_any_environment(monkeypatch):
    for k in ("EVAL_V1_PKG", "EVAL_V1_CVE"):
        monkeypatch.delenv(k, raising=False)
    p = score.P({"final_answer": "Upgrade nghttp2 now: CVE-2023-44487 is exploited in the wild.",
                 "transcript": [{"tool": "correlate_findings", "observation": "PKG-001 nghttp2 act now"}]})
    assert score.SCENARIOS["V1_pkg"].score(p)[0] == "pass"
