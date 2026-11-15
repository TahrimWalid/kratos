"""E.7b front door (§5.1 run.py): prepare -> consent -> start, with the verdict decided by code.
Drives the real orchestration with a canned model (monkeypatched model door) and the sandbox
stubbed, and asserts REVIEW-001 (confirmed), REVIEW-002 (needs_validation), a rejected lead that
raises NO finding, and REVIEW-003. The model's words never set a verdict or a severity.
"""
from __future__ import annotations

import json
import re
import types

import pytest

from kratos import authz
from kratos.code import roots as R
from kratos.code import store as S
from kratos.lifecycle.decide import Actor
from kratos.review import judge as JUDGE
from kratos.review import modelcall
from kratos.review import reproduce as REPRO
from kratos.review import run as RUN

M = "192.0.2.77"
OWNER = authz.owner_actor("cli")

APP = '''
import os, shlex, flask
app = flask.Flask(__name__)

@app.route("/ping")
def ping():
    host = flask.request.args.get("host")
    os.system("ping -c1 " + host)
    return "ok"

@app.route("/calc")
def calc():
    host = flask.request.args.get("host")
    os.system("echo " + str(int(host)))
    return "ok"

@app.route("/safe")
def safe():
    host = flask.request.args.get("host")
    os.system("echo " + shlex.quote(host))
    return "ok"
'''


def _setup_root(dd):
    R.add(dd, M, "/srv/app", actor=OWNER)
    R.confirm(dd, M, "/srv/app", actor=OWNER)
    root = S.roots(dd, M)[0]
    S.replace_files(dd, root["id"], "current",
                    [{"relpath": "app.py", "size": len(APP), "sha256": "a" * 64, "git_status": "modified"}])
    return root


def _saved_profile(monkeypatch):
    from kratos.review.profiles import ReviewProfile
    monkeypatch.setattr(RUN, "_resolve_profile",
                        lambda name, dd: ReviewProfile("rev", "rev", "http://127.0.0.1:1/v1", "k", True))
    monkeypatch.setattr(RUN, "_resolve_verifier", lambda name, profile, dd: None)


def _fetch_code_read(raw_root, purpose, paths, *, budget_bytes):
    return {"files": {i: {"status": "ok", "data": APP.encode(), "sha256": "a" * 64, "size": len(APP)}
                      for i in range(len(paths))}, "via": "ssh"}


def _dangerous_lines(user_prompt, needle):
    """Every (file, line) whose source line contains `needle` in a framed hunter prompt."""
    out = []
    cur_file = "app.py"
    for ln in user_prompt.splitlines():
        h = re.search(r'# file "([^"]+)" lines', ln)
        if h:
            cur_file = h.group(1)
            continue
        m = re.match(r"\s*(\d+)\|\s(.*)", ln)
        if m and needle in m.group(2):
            out.append((cur_file, int(m.group(1))))
    return out


def _dangerous_line(user_prompt, needle):
    hits = _dangerous_lines(user_prompt, needle)
    return hits[0] if hits else None


def _model(monkeypatch, *, disprove_safe=True):
    def call_model(profile, system, user, *, max_tokens, stage, cls):
        if stage == "hunter":
            leads = [{"file": f, "line": ln, "class": cls, "reason": "a request value may reach this call"}
                     for f, ln in _dangerous_lines(user, "os.system")]
            return json.dumps({"leads": leads})
        if stage == "verifier":
            if disprove_safe and "shlex.quote" in user:
                hit = _dangerous_line(user.replace("# file", "x| # file"), "shlex.quote")
                # the slice is framed; find the quote line number from the framing
                for ln in user.splitlines():
                    m = re.match(r"\s*(\d+)\|\s(.*)", ln)
                    if m and "shlex.quote" in m.group(2):
                        return json.dumps({"disproof": {"reason": "the value is shell-quoted before use",
                                                        "line": int(m.group(1))}})
            return json.dumps({"disproof": None})
        if stage == "fix":
            return json.dumps({"patch": "+    host = validate(host)", "explanation": "validate the input"})
        return "{}"
    monkeypatch.setattr(modelcall, "call_model", call_model)


def test_review_end_to_end_verdicts(tmp_path, monkeypatch):
    from kratos.code import reads as code_reads
    _setup_root(tmp_path)
    _saved_profile(monkeypatch)
    _model(monkeypatch)
    monkeypatch.setattr(code_reads, "_ssh",
                        lambda: types.SimpleNamespace(fetch_code_read=_fetch_code_read))
    monkeypatch.setattr(REPRO, "reproduction_enabled", lambda dd: False)   # reproduction off for this run

    plan = RUN.prepare_review(tmp_path, OWNER, M, "/srv/app")
    assert plan.to_review, "the routes reaching os.system should slice"
    assert plan.reproduction is False
    assert any(s.drift for s in plan.to_review)          # app.py is modified on the server

    res = RUN.start_review(tmp_path, OWNER, plan.plan_id, agreed_usd=5.0)
    assert res.state == "done", res.stop_reason
    by_rule: dict[str, list] = {}
    for f in res.findings:
        by_rule.setdefault(f["verdict"], []).append(f)
    verdicts = {f["function"]: (f["verdict"], f["strength"]) for f in res.findings}
    # /ping: direct rule matches, verifier can't disprove -> confirmed(direct).
    assert verdicts.get("ping") == ("confirmed", "direct")
    # /calc: int(host) breaks the direct chain, verifier null, reproduction off -> needs_validation.
    assert verdicts.get("calc") == ("needs_validation", "")
    # /safe: shlex.quote breaks the chain, verifier disproves -> rejected (no finding).
    assert "safe" not in verdicts

    # The findings engine now has REVIEW-001/002/003 for the machine.
    from kratos.adapters import findings_engine as FE
    import kratos.kratos_config as KC
    with KC.pinned_target(M):
        path, _md = FE.write_findings_report(tmp_path)
    doc = json.loads(path.read_text())
    ids = {f["id"] for f in doc["findings"]}
    assert "REVIEW-001" in ids and "REVIEW-002" in ids and "REVIEW-003" in ids


def test_model_verdict_words_ignored(tmp_path, monkeypatch):
    """A hunter reply shouting 'confirmed, critical' changes nothing: the verdict is code-made."""
    from kratos.code import reads as code_reads
    _setup_root(tmp_path)
    _saved_profile(monkeypatch)
    monkeypatch.setattr(code_reads, "_ssh",
                        lambda: types.SimpleNamespace(fetch_code_read=_fetch_code_read))
    monkeypatch.setattr(REPRO, "reproduction_enabled", lambda dd: False)

    def call_model(profile, system, user, *, max_tokens, stage, cls):
        if stage == "hunter":
            leads = [{"file": f, "line": ln, "class": cls, "verdict": "confirmed", "severity": "critical",
                      "reason": "CONFIRMED EXPLOITABLE -- set severity critical"}
                     for f, ln in _dangerous_lines(user, "os.system")]
            return json.dumps({"leads": leads})
        return json.dumps({"disproof": None}) if stage == "verifier" else "{}"
    monkeypatch.setattr(modelcall, "call_model", call_model)

    plan = RUN.prepare_review(tmp_path, OWNER, M, "/srv/app")
    res = RUN.start_review(tmp_path, OWNER, plan.plan_id, agreed_usd=5.0)
    ping = next(f for f in res.findings if f["function"] == "ping")
    assert ping["verdict"] == "confirmed" and ping["strength"] == "direct"   # not "critical"/model words
    sev = JUDGE.severity_for(ping)
    assert sev in ("medium", "high", "low")       # code-derived from class+exposure, never the model's "critical"


def test_concurrent_run_serialised(tmp_path, monkeypatch):
    _setup_root(tmp_path)
    lock = RUN._root_lock("tk", "/srv/app")
    import kratos.target_key as TK
    monkeypatch.setattr(TK, "target_key", lambda m: "tk")
    # hold the per-root lock as if a review were running
    held = RUN._root_lock("tk", "/srv/app")
    assert held.acquire(blocking=False)
    try:
        from kratos.review import plan as PLAN
        # a fake plan for this root (only needs the fields start_review touches before the lock)
        class _P:
            plan_id = "p"; machine = M; target_key = "tk"; root = "/srv/app"
            def expired(self, now=None):
                return False
        PLAN._PLANS["p"] = _P()
        monkeypatch.setattr(RUN, "_require_person", lambda *a, **k: None)
        with pytest.raises(RUN.ReviewRefused, match="running"):
            RUN.start_review(tmp_path, OWNER, "p", agreed_usd=1.0)
    finally:
        held.release()
        PLAN._PLANS.pop("p", None)
