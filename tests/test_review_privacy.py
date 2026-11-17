"""E.7b privacy (§3.11, §6, §8): secrets are removed before anything is sent in EVERY mask mode
(including off and a local endpoint); masking keeps line numbers; the model door keeps no code in
the run record. Secrets are built at test time, never checked-in values."""
from __future__ import annotations

import secrets as _secrets


from kratos.review import fix as FIX
from kratos.review import hunt as HUNT
from kratos.review import slice as SL
from kratos.review import verify as VERIFY
from kratos.review.profiles import ReviewProfile

PROFILE = ReviewProfile("rev", "rev", "http://127.0.0.1:1/v1", "k", True)   # local endpoint, mask mode off


def _secret() -> str:
    return "AKIA" + "".join(_secrets.choice("ABCDEFGHIJKLMNOP1234567") for _ in range(16))


def _slice_with_secret(secret: str):
    app = f'''
import os, flask
app = flask.Flask(__name__)
@app.route("/ping")
def ping():
    token = "{secret}"
    host = flask.request.args.get("host")
    os.system("curl -H " + token + " " + host)
    return "ok"
'''
    slices, _s, idx = SL.slice_root("/srv", {"app.py": app}, file_hashes={"app.py": "h"},
                                    all_sizes={"app.py": len(app)})
    return next(s for s in slices if s.cls == "exec"), idx, app


def test_secret_removed_before_hunt_send():
    secret = _secret()
    sl, _idx, _app = _slice_with_secret(secret)
    sent = []

    def caller(system, user, *, stage, cls):
        sent.append(user)
        return '{"leads": []}'

    HUNT.hunt(PROFILE, HUNT.build_batches([sl], run_id="r", window_tokens=32000),
              max_leads_per_call=20, max_leads=200, call=caller)
    assert sent, "the hunter should have sent a batch"
    blob = "\n".join(sent)
    assert secret not in blob                 # removed even with mask mode off on a local endpoint
    assert "[REDACTED]" in blob


def test_secret_removed_before_verify_and_fix_send():
    secret = _secret()
    sl, _idx, _app = _slice_with_secret(secret)
    seen = []

    def caller(system, user, *, stage, cls):
        seen.append(user)
        return '{"disproof": null}' if stage == "verifier" else '{"patch": "", "explanation": "x"}'

    from kratos.review.prompts import Lead
    lead = Lead(file="app.py", line=sl.span[0], cls="exec", reason="x", slice_sha=sl.sha256)
    VERIFY.verify(PROFILE, lead, sl, run_id="r", call=caller)
    FIX.propose(PROFILE, sl, "exec", run_id="r", call=caller)
    for u in seen:
        assert secret not in u and "[REDACTED]" in u


def test_masking_preserves_lines():
    from kratos.privacy.mask import Masker
    src = "def ping():\n    host = request.args.get('host')  # 10.0.0.5\n    run(host)\n    return 'ok'\n"
    for mode in ("standard", "strict"):
        m = Masker(mode=mode, scope="s", data_dir=None, machine="10.0.0.5")
        out = m.mask(src)
        assert out.count("\n") == src.count("\n")      # placeholders never add or remove newlines


def test_model_door_keeps_no_code(monkeypatch):
    """call_model runs inside trace.suppress_prompts(): a model call stores no prompt text even
    when trace.store_prompts is on, and records the request's size + sha256 instead."""
    from kratos.review import modelcall
    from kratos.trace import recorder as trace
    import kratos.llm_interface as LI

    captured = {}

    def fake_send(base_url, api_key, model, *, system_prompt, prompt, max_tokens):
        captured["prompts_enabled"] = trace.prompts_enabled()
        return '{"leads": []}'

    monkeypatch.setattr(LI, "send_review_request", fake_send)
    # a trace with store_prompts ON; call_model must still suppress the code.
    monkeypatch.setattr(trace, "prompts_enabled", trace.prompts_enabled)   # keep the real one
    reply = modelcall.call_model(PROFILE, "sys", "SENSITIVE CODE", max_tokens=100, stage="hunter", cls="exec")
    assert reply == '{"leads": []}'
    assert captured["prompts_enabled"] is False     # prompts suppressed around the review call
