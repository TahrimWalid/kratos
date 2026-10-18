"""B.2 at the investigation level: a scripted investigation through the real HTTP
layer. What is sent carries no real value; what the person reads, what the tools get
and what the guards check are all real values. Neutral fixtures only."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("requests")

from kratos import kratos_config, llm_interface, settings_store
from kratos.agent import loop as agent_loop
from kratos.agent.tools import TOOL_REGISTRY
from kratos.privacy import mode as M
from kratos.run_context import run_scope

TARGET = "192.0.2.10"
ATTACKER = "203.0.113.7"
USER = "alice"
SECRET = "AKIA" + "X" * 16
HIGH = {"id": "CORR-SSH-001", "title": "SSH exposed with failed-login burst activity observed", "severity": "high",
        "entities": [ATTACKER], "evidence": [f"burst of 12 failed logins from {ATTACKER} for {USER}"],
        "recommendation": ["restrict ssh"]}
GOOD = (f"A HIGH-severity finding (CORR-SSH-001: SSH exposed with failed-login burst activity) shows {ATTACKER} "
        f"guessing the password of {USER}. Restrict SSH access.")
DISMISSIVE = "No suspicious activity was detected on this system; overall the system appears secure."


def _tool(name, args=None):
    return json.dumps({"reasoning": "next", "tool": name, "args": args or {}})


def _final(text, **extra):
    return json.dumps({"reasoning": "done", "final_answer": text, **extra})


class _Resp:
    def __init__(self, content):
        self._body = {"choices": [{"message": {"content": content}}],
                      "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


@pytest.fixture
def run(tmp_path, monkeypatch):
    """`run(replies, mode)` -> (result, sent bodies, tool calls seen). Each reply is written
    with real values; the fake model turns them into the placeholders it was sent (a model
    that uses placeholders as told)."""
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target(TARGET)
    monkeypatch.setattr(llm_interface, "_running_backend", lambda: "openai_compatible")
    monkeypatch.setattr(llm_interface, "get_active_llm_base_url", lambda: "https://api.example.com/v1")
    monkeypatch.setattr(llm_interface, "get_active_llm_api_key", lambda: "k")
    monkeypatch.setattr(llm_interface, "get_active_llm_model", lambda: "m")
    (tmp_path / "context").mkdir()
    (tmp_path / "context" / "privileged_accounts_20260101_000000_000000.json").write_text(json.dumps(
        {"target": f"ubuntu@{TARGET}", "accounts": {}, "local_accounts": {USER: 1001, "root": 0}}))
    seen: dict[str, list] = {"tools": []}
    monkeypatch.setattr(TOOL_REGISTRY["read_journalctl"], "handler", lambda **kw: {
        "status": "ok", "entries": [f"sshd: Failed password for {USER} from {ATTACKER} port 50022",
                                    f"cron: export KEY={SECRET}"], "user": USER})
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", lambda **kw: {
        "findings": [HIGH], "count": 1, "staleness_warning": None, "missing_inputs": [], "input_errors": {},
        "inputs_used": {}})
    monkeypatch.setattr(TOOL_REGISTRY["check_ip_reputation"], "handler",
                        lambda ip: seen["tools"].append(("check_ip_reputation", ip)) or
                        {"status": "ok", "ip": ip, "source": "none"})

    def go(replies, mode="standard"):
        settings_store.set(M.MODE_KEY, mode, data_dir=tmp_path, actor="test")
        script, bodies = list(replies), []

        def post(url, headers=None, json=None, timeout=None):  # noqa: A002
            from kratos.privacy.mask import request_masker

            bodies.append(json)
            reply = script.pop(0)
            return _Resp(request_masker(base_url="https://api.example.com/v1").mask(reply))

        monkeypatch.setattr(llm_interface.requests, "post", post)
        with run_scope("cli", session_id=f"s-{mode}"):
            result = agent_loop.run_agent("who is trying to log in?", tmp_path, max_iters=8)
        return result, bodies, seen["tools"]

    return go


SCRIPT = [_tool("read_journalctl", {"since": "24 hours ago"}), _tool("check_ip_reputation", {"ip": ATTACKER}),
          _tool("correlate_findings"), _final(DISMISSIVE), _final(GOOD, recommended_commands=[
              {"command": f"sudo ufw deny from {ATTACKER}", "explanation": "block it", "run_on": "target"}])]


def _sent_text(bodies) -> str:
    return "\n".join(m["content"] for b in bodies for m in b["messages"])


def test_nothing_real_is_sent_and_the_person_reads_real_values(run):
    result, bodies, tools = run(SCRIPT)
    sent = _sent_text(bodies)
    for value in (TARGET, ATTACKER, SECRET):
        assert value not in sent
    assert f" {USER} " not in sent and f'"{USER}"' not in sent
    answer = result["final_answer"]
    assert ATTACKER in answer and USER in answer                 # restored for the person
    assert tools == [("check_ip_reputation", ATTACKER)]          # restored before dispatch
    cmd = result["recommended_commands"][0]["command"]
    # the shown command is real, and A.4's catalogue rebuilt it from the restored value
    assert cmd.startswith(f"sudo ufw deny from {ATTACKER}")


def test_guards_and_answer_are_identical_with_masking_on_and_off(run):
    on, _b, _t = run(SCRIPT, "standard")
    off, _b, _t = run(SCRIPT, "off")
    assert on["final_answer"] == off["final_answer"]
    assert on["status"] == off["status"]
    def steps(result):
        return [json.dumps({k: v for k, v in step.items() if k not in ("timestamp", "duration_s", "elapsed_s", "run_id")},
                           sort_keys=True, default=str) for step in result["transcript"]]

    assert steps(on) == steps(off)
    # the dismissive first answer was sent back by the same guard either way (Guard 3)
    assert sum(DISMISSIVE in s for s in steps(on)) == 1 and len(steps(on)) == len(SCRIPT)


def test_the_findings_block_shows_real_values_and_never_came_from_the_model(run):
    result, bodies, _t = run(SCRIPT)
    answer = result["final_answer"]
    if "Kratos found" in answer:
        block = answer.split("Kratos found", 1)[1][:400]
        assert ATTACKER in block
    assert "Kratos found" not in _sent_text(bodies[:1])


def test_an_invented_placeholder_in_a_tool_call_is_refused(run, monkeypatch):
    from kratos.privacy import mask as PM

    real_mask = PM.Masker.mask

    def mask_and_invent(self, text):          # the model makes up a label it was never given
        out = real_mask(self, text)
        return out.replace("INVENT_ME", f"PUBLIC_IP_9_{self.tag}")

    monkeypatch.setattr(PM.Masker, "mask", mask_and_invent)
    result, _b, tools = run([_tool("check_ip_reputation", {"ip": "INVENT_ME"}), _tool("correlate_findings"),
                             _final(GOOD)])
    assert tools == []
    obs = json.dumps(result["transcript"])
    assert "not a value Kratos gave you" in obs


def test_nothing_stored_is_masked(run, tmp_path):
    result, _b, _t = run(SCRIPT)
    stored = json.dumps(result["transcript"])
    assert ATTACKER in stored and "_IP_" not in stored and "USER_" not in stored
    traces = list((tmp_path / "traces").rglob("*.json"))
    assert traces and ATTACKER in traces[0].read_text()


STRAY = "198.51.100.77"


@pytest.mark.parametrize("case", ["ungrounded_ip", "time_claim"])
def test_the_note_guards_fire_the_same_with_masking_on_and_off(run, monkeypatch, case):
    if case == "time_claim":
        monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", lambda **kw: {
            "findings": [HIGH], "count": 1, "missing_inputs": [], "input_errors": {}, "inputs_used": {},
            "staleness_warning": "inputs span 101.3 hours apart"})
        text = GOOD + " This happened in the last 24 hours."
    else:
        text = GOOD + f" It may also involve {STRAY}."
    # Guard 4 sends a time claim back (twice) before it adds its NOTE; the IP NOTE is added at once
    repeats = 3 if case == "time_claim" else 1
    script = [_tool("read_journalctl"), _tool("correlate_findings")] + [_final(text)] * repeats
    on, bodies, _t = run(script, "standard")
    off, _b, _t = run(script, "off")
    assert on["final_answer"] == off["final_answer"]
    assert "[NOTE" in on["final_answer"] or "NOTE:" in on["final_answer"]
    if case == "ungrounded_ip":
        assert STRAY in on["final_answer"] and STRAY not in _sent_text(bodies)
