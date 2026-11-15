"""E.7b model door (profiles, prompts parsers, hunt, verify, fix): tool-less calls, framed
slices with secrets removed, leads validated/capped, the model's class/verdict words ignored.
Driven with injected fake callers -- no real model. Fails on old code."""
from __future__ import annotations

import json

from kratos.review import fix as FIX
from kratos.review import hunt as H
from kratos.review import prompts as P
from kratos.review import profiles as PR
from kratos.review import slice as S
from kratos.review import verify as VE

FLASK = '''\
from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/ping", methods=["POST"])
def ping():
    key = "AKIAIOSFODNN7EXAMPLE"
    host = request.form["host"]
    subprocess.run("ping " + host, shell=True)
    return "ok"
'''


def _exec_slice():
    slices, _s, idx = S.slice_root("/srv/app", {"app.py": FLASK}, file_hashes={}, all_sizes={})
    sl = next(s for s in slices if s.cls == "exec")
    return sl, idx


# --------------------------------------------------------------------------- profiles
ENV = """\
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_API_KEY=ollama
LLM_MODEL=qwen2.5:7b
KRATOS_LLM_BACKEND=openai_compatible

LLM_BASE_URL=https://api.example.com/v1
LLM_API_KEY=sk-secret
LLM_MODEL=gemini-3.1-pro-preview
KRATOS_LLM_BACKEND=openai_compatible
"""


def test_profile_resolution_local_and_hosted(tmp_path):
    env = tmp_path / ".env"
    env.write_text(ENV)
    local = PR.resolve("qwen2.5:7b", env_path=env)
    assert local.local and local.destination == "local" and "your own network" in local.destination_text
    hosted = PR.resolve("gemini-3.1-pro-preview", env_path=env)
    assert not hosted.local and hosted.destination == "hosted" and "outside your network" in hosted.destination_text
    assert set(PR.saved_names(env_path=env)) == {"qwen2.5:7b", "gemini-3.1-pro-preview"}


def test_unsaved_or_empty_profile_refused(tmp_path):
    env = tmp_path / ".env"
    env.write_text(ENV)
    for bad in ("", "not-a-saved-model"):
        try:
            PR.resolve(bad, env_path=env)
            assert False, "expected refusal"
        except PR.UnknownProfile as e:
            assert "qwen2.5:7b" in str(e)   # the saved names are listed, none pre-selected as active


def test_consent_line_names_destination_and_secret_removal(tmp_path):
    env = tmp_path / ".env"
    env.write_text(ENV)
    line = PR.consent_line(PR.resolve("gemini-3.1-pro-preview", env_path=env), None, "standard")
    assert "outside your network" in line and "Secrets are always removed" in line and "Masking: standard" in line


# --------------------------------------------------------------------------- parsers
def test_parse_leads_validates_and_ignores_model_class():
    allowed = {"app.py"}
    spans = {"app.py": [(5, 12)]}
    reply = json.dumps({"leads": [
        {"file": "app.py", "line": 9, "class": "sql", "reason": "flows to run"},   # class ignored -> exec
        {"file": "app.py", "line": 999, "class": "exec", "reason": "outside"},      # dropped
        {"file": "other.py", "line": 9, "class": "exec", "reason": "not sent"},      # dropped
    ]})
    leads, drops = P.parse_leads(reply, allowed_files=allowed, spans=spans, batch_class="exec", max_per_call=20)
    assert len(leads) == 1 and leads[0]["class"] == "exec" and leads[0]["line"] == 9
    assert drops["outside"] == 2


def test_parse_leads_dedup_and_cap():
    spans = {"app.py": [(1, 50)]}
    items = [{"file": "app.py", "line": 9, "class": "exec", "reason": "a"},
             {"file": "app.py", "line": 9, "class": "exec", "reason": "dup"}]      # merged
    items += [{"file": "app.py", "line": 10 + i, "class": "exec", "reason": "x"} for i in range(5)]
    leads, drops = P.parse_leads(json.dumps({"leads": items}), allowed_files={"app.py"}, spans=spans,
                                 batch_class="exec", max_per_call=3)
    assert len(leads) == 3 and drops["over_cap"] == 3   # 6 distinct, cap 3


def test_parse_disproof_needs_a_line():
    assert P.parse_disproof(json.dumps({"disproof": {"reason": "quoted at 6", "line": 6}})) == {"reason": "quoted at 6", "line": 6}
    assert P.parse_disproof(json.dumps({"disproof": {"reason": "looks safe"}})) is None
    assert P.parse_disproof(json.dumps({"disproof": None})) is None
    assert P.parse_disproof("not json at all") is None


def test_parse_patch_keeps_only_added_lines():
    reply = json.dumps({"patch": "--- a\n+++ b\n-    bad = x\n+    good = shlex.quote(x)\n+    run(good)",
                        "explanation": "quote the input"})
    out = P.parse_patch(reply)
    assert out["added"] == "    good = shlex.quote(x)\n    run(good)"
    assert "+++ b" not in out["added"] and "bad = x" not in out["added"]
    assert out["explanation"] == "quote the input"


# --------------------------------------------------------------------------- hunt / verify / fix
def test_hunt_maps_lead_to_slice_and_counts_drops():
    sl, _ = _exec_slice()
    line = sl.calls[0].line
    prof = PR.ReviewProfile("m", "m", "http://127.0.0.1/v1", "k", True)
    batches = H.build_batches([sl], run_id="r", window_tokens=32000)

    def caller(system, user, *, stage, cls):
        assert stage == "hunter" and cls == "exec"
        return json.dumps({"leads": [{"file": sl.rel, "line": line, "class": "sql", "reason": "flows"},
                                     {"file": sl.rel, "line": 100000, "class": "exec", "reason": "nope"}]})

    res = H.hunt(prof, batches, max_leads_per_call=20, max_leads=200, call=caller)
    assert len(res.leads) == 1 and res.leads[0].cls == "exec" and res.leads[0].slice_sha == sl.sha256
    assert res.drops["outside"] == 1 and res.calls == 1


def test_hunt_removes_secrets_before_sending():
    sl, _ = _exec_slice()
    assert "AKIAIOSFODNN7EXAMPLE" in sl.text          # the secret is in the slice...
    batches = H.build_batches([sl], run_id="r", window_tokens=32000)
    assert "AKIAIOSFODNN7EXAMPLE" not in batches[0].user_prompt   # ...but never in what would be sent
    assert "[REDACTED]" in batches[0].user_prompt


def test_build_batches_split_by_window():
    body = "".join(f"    v{i} = {i}\n" for i in range(500))      # a large function body
    big = ("from flask import Flask, request\nimport subprocess\napp = Flask(__name__)\n\n"
           '@app.route("/x", methods=["POST"])\ndef x():\n' + body
           + '    subprocess.run(request.form["c"], shell=True)\n    return "ok"\n')
    slices, _s, _i = S.slice_root("/srv/app", {"a.py": big}, file_hashes={}, all_sizes={}, max_slice_bytes=10 ** 7)
    exec_slices = [s for s in slices if s.cls == "exec"]
    batches = H.build_batches(exec_slices * 3, run_id="r", window_tokens=2000)   # each big slice ~ its own batch
    assert len(batches) > 1 and all(b.cls == "exec" for b in batches)


def test_verify_requires_a_line_in_the_slice():
    sl, _ = _exec_slice()
    line = sl.calls[0].line
    prof = PR.ReviewProfile("m", "m", "http://127.0.0.1/v1", "k", True)
    lead = P.Lead(file=sl.rel, line=line, cls="exec", reason="x", slice_sha=sl.sha256)

    good = VE.verify(prof, lead, sl, run_id="r",
                     call=lambda s, u, **k: json.dumps({"disproof": {"reason": "quoted", "line": line}}))
    assert good is not None and good.line == line

    outside = VE.verify(prof, lead, sl, run_id="r",
                        call=lambda s, u, **k: json.dumps({"disproof": {"reason": "quoted", "line": 999999}}))
    assert outside is None            # a disproof that cites a line outside the slice is "could not disprove"

    none = VE.verify(prof, lead, sl, run_id="r", call=lambda s, u, **k: json.dumps({"disproof": None}))
    assert none is None


def test_fix_keeps_only_added_lines():
    sl, _ = _exec_slice()
    prof = PR.ReviewProfile("m", "m", "http://127.0.0.1/v1", "k", True)
    reply = json.dumps({"patch": "+    safe = shlex.quote(host)\n-    bad", "explanation": "quote host"})
    out = FIX.propose(prof, sl, "exec", run_id="r", call=lambda s, u, **k: reply)
    assert out.added == "    safe = shlex.quote(host)" and out.words == "quote host"
    assert "bad" not in out.added
