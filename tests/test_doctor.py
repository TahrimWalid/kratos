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


def _render_doctor(checks):
    from rich.console import Console
    import io
    from kratos.tui_mk2 import render as R
    buf = io.StringIO()
    Console(file=buf, width=92).print(R.doctor_table(checks))
    return buf.getvalue()


def test_doctor_verdict_leads_the_output():
    # The "is my setup OK?" verdict is a headline ABOVE the detail rows, and it
    # reads in plain language (with correct singular/plural verb agreement).
    fail = _render_doctor([
        {"check": "a", "status": "pass", "detail": "the endpoint responded normally"},
        {"check": "b", "status": "fail", "detail": "the target could not be reached over ssh"},
    ])
    first_line = next(ln for ln in fail.splitlines() if ln.strip())
    assert "1 check needs attention" in first_line          # verdict is the very first line
    assert first_line.index("needs attention") < fail.index("self-diagnostic")  # before the table

    warn = _render_doctor([{"check": "a", "status": "warn", "detail": "x"}])
    assert "1 warning to review" in warn

    healthy = _render_doctor([{"check": "a", "status": "pass", "detail": ""}])
    assert "Everything looks healthy" in healthy


def test_target_info_rows_are_facts_not_warnings(monkeypatch):
    """Found in the P2.5 snapshots: the target's timezone (an INFO probe row) was shown as a
    warning and counted in the '1 warning to review' verdict."""
    monkeypatch.setattr("kratos.kratos_config.SSH_TARGET_HOST", "10.0.0.5")
    monkeypatch.setattr("kratos.adapters.ssh_remote.run_target_probe_checks", lambda: [
        {"check": "ssh_reachable", "status": "PASS", "detail": "ok"},
        {"check": "target_timezone", "status": "INFO", "detail": "Etc/UTC"},
        {"check": "lsof_installed", "status": "UNKNOWN", "detail": "?"},
    ])
    rows: list = []
    doctor._check_target(rows)
    by = {r["check"]: r["status"] for r in rows}
    assert by["target · target_timezone"] == "info"
    assert by["target · ssh_reachable"] == "pass" and by["target · lsof_installed"] == "warn"


def test_doctor_details_are_folded_not_cut_off():
    """A detail can be a value to copy (the suggested ntfy topic, a URL); it must never end
    in an ellipsis at a narrow width."""
    import io

    from rich.console import Console

    from kratos.tui_mk2.render import doctor_table

    value = "KRATOS_NTFY_TOPIC=kratos-1e2a29b3ed51ca9a8d7f00112233"
    buf = io.StringIO()
    Console(file=buf, width=60).print(doctor_table([{"check": "notifications", "status": "info",
                                                     "detail": f"not configured. Suggested: {value}"}]))
    text = buf.getvalue()
    assert "…" not in text and value in "".join(text.split())


def test_fix_hints_use_the_accent_only_where_something_needs_doing():
    from rich.console import Group

    from kratos.tui_mk2 import theme as T
    from kratos.tui_mk2.render import doctor_table

    rows = [{"check": "notifications", "status": "info", "detail": "off", "fix": "add a topic"},
            {"check": "target", "status": "fail", "detail": "down", "fix": "check port 22"},
            {"check": "history", "status": "warn", "detail": "old", "fix": "re-run"}]
    group = doctor_table(rows)
    table = [r for r in group.renderables if hasattr(r, "columns")][0]
    fix_cells = [cell for cell in table.columns[2]._cells if str(cell).startswith("→")]
    styles = {str(c)[2:]: str(c.style) for c in fix_cells}
    assert styles == {"add a topic": T.TEXT_MUTED, "check port 22": T.ACCENT, "re-run": T.ACCENT}
    assert isinstance(group, Group)
