"""
Self-diagnostic (agent/doctor.py, feature A1).

The network/SSH sections (LLM endpoint, target probe) aren't exercised for real
here -- run_diagnostics's RESILIENCE and aggregation are tested by swapping the
section list, and the filesystem-only kept-tools check is tested directly. The
pure helpers (_is_local_url, summarize) are unit-tested.
"""
from __future__ import annotations

import json

from kratos.agent import doctor


def test_is_local_url():
    assert doctor._is_local_url("http://127.0.0.1:11434/v1")
    assert doctor._is_local_url("http://localhost:8080")
    assert not doctor._is_local_url("https://api.openai.com/v1")


def test_summarize_counts_status():
    checks = [
        {"check": "a", "status": "pass", "detail": ""},
        {"check": "b", "status": "warn", "detail": ""},
        {"check": "c", "status": "fail", "detail": ""},
        {"check": "d", "status": "info", "detail": ""},  # not counted either way
        {"check": "e", "status": "pass", "detail": ""},
    ]
    assert doctor.summarize(checks) == (2, 1, 1)


def test_run_diagnostics_isolates_a_failing_section(monkeypatch):
    def _good(out):
        out.append(doctor._row("good", "pass", "ok"))

    def _boom(out):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(doctor, "_SECTIONS", (("good", _good), ("bad", _boom)))
    checks = doctor.run_diagnostics()
    # the good section still ran; the broken one reported itself as a fail row
    assert {"check": "good", "status": "pass", "detail": "ok"} in checks
    bad = [c for c in checks if c["check"] == "bad"]
    assert bad and bad[0]["status"] == "fail" and "kaboom" in bad[0]["detail"]


def _seed_kept(tmp_path, monkeypatch, metadata, files):
    from kratos.agent import self_write_loop as swl

    monkeypatch.setattr(swl, "KEPT_TOOLS_DIR", tmp_path)
    (tmp_path / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    for f in files:
        (tmp_path / f).write_text("# tool\n", encoding="utf-8")


def test_kept_tools_all_present_passes(tmp_path, monkeypatch):
    _seed_kept(tmp_path, monkeypatch,
               {"foo": {"source_file": "foo.py"}, "bar": {"source_file": "bar.py"}},
               ["foo.py", "bar.py"])
    out: list = []
    doctor._check_kept_tools(out)
    assert out[0]["status"] == "pass" and "2 kept" in out[0]["detail"]


def test_kept_tools_missing_file_fails(tmp_path, monkeypatch):
    _seed_kept(tmp_path, monkeypatch,
               {"foo": {"source_file": "foo.py"}, "gone": {"source_file": "gone.py"}},
               ["foo.py"])  # gone.py deliberately absent
    out: list = []
    doctor._check_kept_tools(out)
    assert out[0]["status"] == "fail" and "gone" in out[0]["detail"]


def test_kept_tools_none_is_info(tmp_path, monkeypatch):
    _seed_kept(tmp_path, monkeypatch, {}, [])
    out: list = []
    doctor._check_kept_tools(out)
    assert out[0]["status"] == "info" and "none kept" in out[0]["detail"]


def test_failing_rows_carry_an_actionable_fix(tmp_path, monkeypatch):
    # P2.2: every FAIL/WARN a user can act on names the next step inline. Info/pass
    # rows never need one.
    _seed_kept(tmp_path, monkeypatch,
               {"foo": {"source_file": "foo.py"}, "gone": {"source_file": "gone.py"}},
               ["foo.py"])
    out: list = []
    doctor._check_kept_tools(out)
    assert out[0]["status"] == "fail" and out[0].get("fix")   # missing-file → how to fix

    # .env with no active profile is a warn the user can resolve.
    from kratos.adapters import llm_profiles
    monkeypatch.setattr(llm_profiles, "list_candidate_profiles", lambda _p: ([], None))
    out = []
    doctor._check_env_profile(out)
    assert out[0]["status"] == "warn" and "/model" in out[0].get("fix", "")


def test_row_omits_fix_when_none():
    r = doctor._row("x", "pass", "all good")
    assert "fix" not in r                                       # clean pass rows stay uncluttered
