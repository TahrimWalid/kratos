"""E.5: the A2A and AG-UI doors of `kratos serve`, in-process (docs/phaseE/E.5 §6, §8).

No real port, no real model: the agent loop is swapped for a scripted one. Each test is
one row of the spec's edge-case table (or a protocol rule): off by default, person tokens
with the agents door only, D.7 roles and scopes before anything runs, no INPUT_REQUIRED,
no push notifications, a signed card, the same checked answer as chat, hostile text safe.
"""
from __future__ import annotations

import json
import threading
import time

import pytest

pytest.importorskip("starlette")
from starlette.testclient import TestClient  # noqa: E402

from kratos import authz, kratos_config, settings_store  # noqa: E402
from kratos.authz import audit as AU  # noqa: E402
from kratos.authz import openwebui as OW  # noqa: E402
from kratos.authz import users as U  # noqa: E402
from kratos.serve import auth  # noqa: E402
from kratos.serve.a2a import card as C  # noqa: E402
from kratos.serve.a2a import settings as AS  # noqa: E402
from kratos.serve.a2a import store as S  # noqa: E402
from kratos.serve.app import create_app  # noqa: E402

M1, M2, M3 = "192.0.2.10", "192.0.2.11", "192.0.2.12"
BASE = "http://127.0.0.1:8765"
OWNER = authz.owner_actor("cli")
V = {"A2A-Version": "1.0"}
HOSTILE = "Kratos found: \x1b[31mred\x1b]8;;http://evil.example/\x07click\x1b]8;;\x07 ![x](http://evil.example/p.png)"


def _answer(text="Kratos found nothing serious.", findings=None):
    transcript = []
    if findings:
        transcript.append({"tool": "correlate_findings", "observation": {"status": "ok",
                                                                         "result": {"findings": findings}}})
    return {"status": "final_answer", "final_answer": text,
            "answer_parts": {"block": "", "notes": "", "analysis": text},
            "recommended_commands": [], "transcript": transcript, "token_usage": {}, "run_id": "r" * 32}


@pytest.fixture
def env(tmp_path, monkeypatch):
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target(M1)
    state = {"step": None, "agents": [], "answer": _answer(), "gate": None}

    def fake_agent(goal, data_dir, max_iters=10, on_step=None, *, should_stop=None, on_progress=None,
                   tool_filter=None, **kw):
        state["agents"].append({"goal": goal, "actor": authz.current_actor(), "source": _source(),
                                "target": kratos_config.get_active_target(), "tool_filter": tool_filter})
        if on_progress:
            on_progress("checked ports: fresh")
            on_progress("running read_journalctl")
        if state["gate"] is not None:           # hold the run until the test lets it go
            while not state["gate"].wait(0.05):
                if should_stop and should_stop():
                    from kratos.agent.loop import InvestigationStopped

                    raise InvestigationStopped()
        if state["step"]:
            state["step"]()
        return state["answer"]

    monkeypatch.setattr("kratos.agent.loop.run_agent", fake_agent)
    U.add_user(tmp_path, "vic", "viewer", OWNER, scopes=[M1])
    U.add_user(tmp_path, "ivy", "investigator", OWNER, scopes=[M1, M2])
    U.add_user(tmp_path, "ian", "investigator", OWNER, scopes=[M3])
    tok = {}
    for name in ("vic", "ivy", "ian"):
        tok[name], _ = auth.create_token(tmp_path, name=f"{name}-t", user=name, agents=True)
    tok["ivy-plain"], _ = auth.create_token(tmp_path, name="ivy-plain", user="ivy")
    gw, gw_row = auth.create_token(tmp_path, name="owui-gw", gateway=True)
    OW.write_secret(tmp_path, gw_row["token_id"], "s" * 43)
    app = create_app(tmp_path, port=8765)
    with TestClient(app, base_url=BASE) as client:
        yield {"client": client, "tok": tok, "gw": gw, "dir": tmp_path, "state": state}


def _source():
    from kratos import run_context

    ctx = run_context.current()
    return ctx.source if ctx else None


def _on(env, a2a=True, agui=True):
    if a2a:
        settings_store.set(AS.A2A_ENABLED, True, data_dir=env["dir"], actor="test")
    if agui:
        settings_store.set(AS.AGUI_ENABLED, True, data_dir=env["dir"], actor="test")


def _h(token, **extra):
    return {"Authorization": f"Bearer {token}", **V, **extra}


def _msg(data=None, text=None, **extra):
    parts = []
    if text is not None:
        parts.append({"text": text})
    if data is not None:
        parts.append({"data": data})
    return {"message": {"messageId": "m-1", "role": "ROLE_USER", "parts": parts, **extra}}


def _send(env, who, body, *, path="/a2a/v1/message:send"):
    return env["client"].post(path, headers=_h(env["tok"][who]), json=body)


def _inv(machine=M1, question="anything suspicious?"):
    return {"skill": "investigate_machine", "machine": machine, "question": question}


def _sse(text):
    return [json.loads(line[6:]) for line in text.splitlines() if line.startswith("data: ")]


# ------------------------------------------------------------------ off by default, the door rules
def test_doors_off_by_default(env):
    c = env["client"]
    assert settings_store.get(AS.A2A_ENABLED, data_dir=env["dir"]) is False
    assert settings_store.get(AS.AGUI_ENABLED, data_dir=env["dir"]) is False
    assert c.get(C.WELL_KNOWN_PATH).status_code == 404
    assert c.get(C.KEYS_PATH).status_code == 404
    assert c.post("/a2a/v1/message:send", headers=_h(env["tok"]["ivy"]), json=_msg(_inv())).status_code == 404
    assert c.post("/ag-ui/run", headers=_h(env["tok"]["ivy"]), json={}).status_code == 404
    assert env["state"]["agents"] == []


def test_public_card_names_no_machine_and_is_signed(env):
    _on(env)
    r = env["client"].get(C.WELL_KNOWN_PATH)
    assert r.status_code == 200
    card = r.json()
    text = json.dumps(card)
    for m in (M1, M2, M3, "ivy", "vic"):
        assert m not in text
    assert [s["id"] for s in card["skills"]] == list(C.SKILL_IDS)
    assert card["capabilities"]["pushNotifications"] is False
    assert card["supportedInterfaces"][0]["url"] == BASE + "/a2a/v1"
    keys = env["client"].get(C.KEYS_PATH).json()["keys"]
    assert C.verify(card, keys)


def test_card_signature(env):
    _on(env)
    card = env["client"].get(C.WELL_KNOWN_PATH).json()
    keys = env["client"].get(C.KEYS_PATH).json()["keys"]
    assert C.verify(card, keys)
    for field in ("description", "name"):
        bad = json.loads(json.dumps(card))
        bad[field] = bad[field][:-1] + ("X" if bad[field][-1] != "X" else "Y")
        assert C.verify(bad, keys) is None
    bad = json.loads(json.dumps(card))
    bad["capabilities"]["pushNotifications"] = True
    assert C.verify(bad, keys) is None
    # a key rotation keeps cards signed by the retired key verifiable
    from kratos import signing

    with authz.acting_as(OWNER):
        signing.rotate(env["dir"])
    keys2 = env["client"].get(C.KEYS_PATH).json()["keys"]
    assert len(keys2) == 2 and keys2[1].get("kratos_retired") is True
    assert C.verify(card, keys2)                                   # the old card, the retired key
    new = env["client"].get(C.WELL_KNOWN_PATH).json()
    assert C.verify(new, keys2) == keys2[0]["kid"] != C.verify(card, keys2)


def test_jcs_matches_rfc8785_examples():
    from kratos.serve.a2a import jcs

    assert jcs.canonicalize({"b": 1, "a": [True, None, "x"]}) == '{"a":[true,null,"x"],"b":1}'
    assert jcs.canonicalize("€\n\x01\"\\") == '"€\\n\\u0001\\"\\\\"'
    # UTF-16 code-unit order: U+1F600 (surrogates D83D...) sorts before U+FB33
    assert jcs.canonicalize({"דּ": 1, "\U0001f600": 2}).index("\U0001f600") < \
        jcs.canonicalize({"דּ": 1, "\U0001f600": 2}).index("דּ")
    with pytest.raises(jcs.CanonicalizationError):
        jcs.canonicalize({"a": 1.5})
    with pytest.raises(jcs.CanonicalizationError):
        jcs.canonicalize("\ud800")
    assert jcs.clean_empty({"a": "", "b": [], "c": {"d": ""}, "e": False, "f": 0}) == {"e": False, "f": 0}


def test_a2a_auth_failures(env):
    _on(env)
    c = env["client"]
    r = c.post("/a2a/v1/message:send", headers=V, json=_msg(_inv()))
    assert r.status_code == 401
    assert c.get("/a2a/v1/extendedAgentCard", headers=_h("krt_000000000000_" + "x" * 43)).status_code == 401
    # revoked
    row = next(t for t in auth._store.list_tokens(env["dir"]) if t["name"] == "ian-t")
    with authz.acting_as(OWNER):
        auth.revoke(env["dir"], row["token_id"])
    assert _send(env, "ian", _msg(_inv(M3))).status_code == 401
    # disabled user
    with authz.acting_as(OWNER):
        U.set_disabled(env["dir"], "vic", True, OWNER)
    r = c.get("/a2a/v1/extendedAgentCard", headers=_h(env["tok"]["vic"]))
    assert r.status_code == 403 and "disabled" in r.json()["error"]["message"]
    assert env["state"]["agents"] == []
    assert any(x["result"] == "refused" and "disabled" in (x["reason"] or "") for x in AU.query(env["dir"]))


def test_gateway_token_refused(env):
    _on(env)
    for path, body in (("/a2a/v1/message:send", _msg(_inv())), ("/ag-ui/run", {})):
        r = env["client"].post(path, headers=_h(env["gw"]), json=body)
        assert r.status_code == 403
        assert "person token" in r.json()["error"]["message"]
    with pytest.raises(auth.TokenError):
        with authz.acting_as(OWNER):
            auth.create_token(env["dir"], name="gw2", gateway=True, agents=True)
    refused = [x for x in AU.query(env["dir"], result="refused") if "gateway" in (x["credential"] or "")]
    assert refused and all(x["credential"].endswith(("+a2a", "+agui")) for x in refused)


def test_token_without_agents_door_refused(env):
    _on(env)
    r = _send(env, "ivy-plain", _msg(_inv()))
    assert r.status_code == 403 and "--agents" in r.json()["error"]["message"]
    assert env["state"]["agents"] == []


def test_bad_version_refused(env):
    _on(env)
    r = env["client"].post("/a2a/v1/message:send", headers={"Authorization": f"Bearer {env['tok']['ivy']}"},
                           json=_msg(_inv()))
    assert r.status_code == 400
    assert r.json()["error"]["details"][0]["reason"] == "VERSION_NOT_SUPPORTED"
    r = env["client"].post("/a2a/v1/message:send", headers=_h(env["tok"]["ivy"], **{"A2A-Version": "0.3"}),
                           json=_msg(_inv()))
    assert r.json()["error"]["details"][0]["reason"] == "VERSION_NOT_SUPPORTED"


# ------------------------------------------------------------------ roles and scopes
def test_viewer_rejected(env):
    _on(env)
    r = _send(env, "vic", _msg(_inv()))
    assert r.status_code == 200
    task = r.json()["task"]
    assert task["status"]["state"] == "TASK_STATE_REJECTED"
    assert "viewers can't start investigations" in task["status"]["message"]["parts"][0]["text"]
    assert env["state"]["agents"] == []
    # a viewer may still use the read-only skills
    r = _send(env, "vic", _msg({"skill": "list_machines"}))
    t = r.json()["task"]
    assert t["status"]["state"] == "TASK_STATE_COMPLETED"
    data = t["artifacts"][0]["parts"][1]["data"]
    assert data["machines"] == [M1] and data["groups"] == []
    r = _send(env, "vic", _msg({"skill": "finding_states"}))
    assert r.json()["task"]["status"]["state"] == "TASK_STATE_COMPLETED"
    # hunting from another agent is a task: investigators and up
    r = _send(env, "vic", _msg({"skill": "hunt_indicator", "indicators": "203.0.113.7"}))
    assert r.json()["task"]["status"]["state"] == "TASK_STATE_REJECTED"


def test_out_of_scope(env):
    _on(env)
    r = _send(env, "ivy", _msg(_inv(M3)))
    task = r.json()["task"]
    assert task["status"]["state"] == "TASK_STATE_REJECTED"
    assert M3 not in json.dumps(task)
    assert env["state"]["agents"] == []
    card = env["client"].get("/a2a/v1/extendedAgentCard", headers=_h(env["tok"]["ivy"])).json()
    ext = card["capabilities"]["extensions"][0]["params"]
    assert sorted(ext["machines"]) == [M1, M2] and M3 not in json.dumps(card)
    assert C.verify(card, env["client"].get(C.KEYS_PATH).json()["keys"])
    assert any(x["result"] == "refused" for x in AU.query(env["dir"], user="ivy"))


def test_group_scope(env, monkeypatch):
    _on(env)
    seen = {}

    class _Out:
        status, run_id, answer, text, token_usage, results = "final_answer", "f" * 32, None, "per-machine text", {}, []
        group_label = "@lab"

    def fake_fleet(req):
        seen["scope"], seen["group"], seen["source"] = list(req.scope), req.group, req.source
        return _Out()

    monkeypatch.setattr("kratos.fleet.run.run_fleet", fake_fleet)
    monkeypatch.setattr("kratos.serve.openai_routes.group_models_for", lambda client, dd: [("kratos/@lab", "@lab")])
    r = _send(env, "ivy", _msg({"skill": "ask_group", "group": "@lab", "question": "who gained sudo?"}))
    t = r.json()["task"]
    assert t["status"]["state"] == "TASK_STATE_COMPLETED", t
    assert sorted(seen["scope"]) == [M1, M2] and seen["group"] == "@lab" and seen["source"] == "a2a"
    assert "per-machine text" in t["artifacts"][0]["parts"][0]["text"]
    r = _send(env, "ivy", _msg({"skill": "ask_group", "group": "@nope", "question": "x"}))
    assert r.json()["task"]["status"]["state"] == "TASK_STATE_REJECTED"
    monkeypatch.setattr("kratos.serve.openai_routes.group_models_for", lambda client, dd: [])
    r = _send(env, "ivy", _msg({"skill": "ask_group", "group": "@lab", "question": "x"}))
    assert r.json()["task"]["status"]["state"] == "TASK_STATE_REJECTED"


# ------------------------------------------------------------------ tasks
def test_investigation_round_trip_same_answer_as_chat(env):
    _on(env)
    finding = {"id": "AUTH-004", "title": "SSH guessing burst", "severity": "medium", "finding_key": "a" * 64}
    env["state"]["answer"] = _answer("Kratos found an SSH guessing burst.", [finding])
    r = _send(env, "ivy", _msg(_inv()))
    t = r.json()["task"]
    assert t["status"]["state"] == "TASK_STATE_COMPLETED"
    text, data = t["artifacts"][0]["parts"][0], t["artifacts"][0]["parts"][1]
    from kratos.serve import render as R

    a = env["state"]["answer"]
    assert text["text"] == R.answer_markdown(a["final_answer"], a["answer_parts"], [])      # byte-equal to chat
    assert data["data"]["findings"][0]["rule"] == "AUTH-004" and data["data"]["findings"][0]["machine"] == M1
    run = env["state"]["agents"][0]
    assert run["source"] == "a2a" and run["target"] == M1 and run["actor"].user == "ivy"
    assert run["tool_filter"] is not None                       # the headless filter: no approval-reaching tool
    # GetTask after it finished, from the store
    g = env["client"].get(f"/a2a/v1/tasks/{t['id']}", headers=_h(env["tok"]["ivy"]))
    assert g.status_code == 200 and g.json()["artifacts"][0]["parts"][0]["text"] == text["text"]
    row = S.get(env["dir"], t["id"], *_ivy(env))
    assert row["state"] == "TASK_STATE_COMPLETED" and row["door"] == "a2a" and row["target"] == M1


def test_findings_listed_once_across_correlations(env):
    _on(env)
    note = {"id": "BASE-007", "title": "still learning", "severity": "info"}
    a = _answer("done", [note, {"id": "AUTH-004", "title": "b", "severity": "medium", "finding_key": "d" * 64}])
    a["transcript"] = a["transcript"] * 3                     # re-correlated twice
    env["state"]["answer"] = a
    data = _send(env, "ivy", _msg(_inv())).json()["task"]["artifacts"][0]["parts"][1]["data"]
    assert sorted(f["rule"] for f in data["findings"]) == ["AUTH-004", "BASE-007"]


def test_text_only_message_needs_a_single_machine(env):
    _on(env)
    r = _send(env, "ian", {"message": {"messageId": "m-2", "role": "ROLE_USER", "parts": [{"text": "check it"}]}})
    assert r.json()["task"]["status"]["state"] == "TASK_STATE_COMPLETED"
    assert env["state"]["agents"][0]["target"] == M3
    r = _send(env, "ivy", {"message": {"messageId": "m-3", "role": "ROLE_USER", "parts": [{"text": "check it"}]}})
    assert r.status_code == 400 and r.json()["error"]["details"][0]["reason"] == "INVALID_PARAMS"


def test_bad_inputs_refused(env):
    _on(env)
    for body, reason in (
            (_msg({"skill": "investigate_machine", "machine": M1, "question": "x", "cmd": "rm -rf /"}), "INVALID_PARAMS"),
            (_msg({"skill": "run_command"}), "INVALID_PARAMS"),
            ({"message": {"messageId": "m", "parts": [{"url": "http://169.254.169.254/"}]}},
             "CONTENT_TYPE_NOT_SUPPORTED"),
            ({"message": {"messageId": "m", "parts": [{"raw": "AAAA"}]}}, "CONTENT_TYPE_NOT_SUPPORTED"),
            (_msg({"skill": "investigate_machine", "machine": M1, "question": "x" * 5000}), "INVALID_PARAMS"),
            ({"message": {"parts": [{"text": "x"}]}}, "INVALID_PARAMS")):
        r = _send(env, "ivy", body)
        assert r.status_code == 400, body
        assert r.json()["error"]["details"][0]["reason"] == reason
    assert env["state"]["agents"] == []


def test_foreign_task_id(env):
    _on(env)
    t = _send(env, "ivy", _msg(_inv())).json()["task"]
    for who in ("ian", "vic"):
        h = _h(env["tok"][who])
        assert env["client"].get(f"/a2a/v1/tasks/{t['id']}", headers=h).json()["error"]["details"][0]["reason"] \
            == "TASK_NOT_FOUND"
        assert env["client"].post(f"/a2a/v1/tasks/{t['id']}:cancel", headers=h).status_code == 404
        assert env["client"].get("/a2a/v1/tasks", headers=h).json()["tasks"] == [] or \
            all(x["id"] != t["id"] for x in env["client"].get("/a2a/v1/tasks", headers=h).json()["tasks"])
    nonexistent = env["client"].get("/a2a/v1/tasks/task-doesnotexist", headers=_h(env["tok"]["ian"])).json()
    foreign = env["client"].get(f"/a2a/v1/tasks/{t['id']}", headers=_h(env["tok"]["ian"])).json()
    assert nonexistent["error"]["message"] == foreign["error"]["message"]          # no existence leak


def test_push_unsupported(env, monkeypatch):
    _on(env)
    calls = []
    import httpx
    import urllib.request

    monkeypatch.setattr(httpx, "post", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: calls.append(a))
    body = _msg(_inv())
    body["configuration"] = {"taskPushNotificationConfig": {"url": "http://198.51.100.9/hook", "token": "x"}}
    r = _send(env, "ivy", body)
    assert r.status_code == 400 and r.json()["error"]["details"][0]["reason"] == "PUSH_NOTIFICATION_NOT_SUPPORTED"
    assert S.list_for(env["dir"], U.find(env["dir"], "ivy").user_id)[1] == 0      # nothing stored
    for method, path in (("post", "/a2a/v1/tasks/task-x/pushNotificationConfigs"),
                         ("get", "/a2a/v1/tasks/task-x/pushNotificationConfigs"),
                         ("get", "/a2a/v1/tasks/task-x/pushNotificationConfigs/c1"),
                         ("delete", "/a2a/v1/tasks/task-x/pushNotificationConfigs/c1")):
        r = getattr(env["client"], method)(path, headers=_h(env["tok"]["ivy"]))
        assert r.json()["error"]["details"][0]["reason"] == "PUSH_NOTIFICATION_NOT_SUPPORTED"
    card = env["client"].get(C.WELL_KNOWN_PATH).json()
    assert card["capabilities"]["pushNotifications"] is False
    assert calls == [] and env["state"]["agents"] == []


def test_size_limits(env):
    _on(env)
    big = _msg(_inv(question="x" * 10))
    big["message"]["metadata"] = {"pad": "y" * 400_000}
    r = env["client"].post("/a2a/v1/message:send", headers=_h(env["tok"]["ivy"]), content=json.dumps(big))
    assert r.status_code == 413
    deep = "[" * 5000 + "]" * 5000
    r = env["client"].post("/a2a/v1/message:send", headers=_h(env["tok"]["ivy"], **{"content-type": "application/json"}),
                           content=deep)
    assert r.status_code == 400
    nested = {"message": {"messageId": "m", "parts": [{"data": {"skill": "list_machines"}}],
                          "metadata": json.loads("[" * 40 + "1" + "]" * 40)}}
    r = _send(env, "ivy", nested)
    assert r.status_code == 400 and "nested" in r.json()["error"]["message"]
    assert env["state"]["agents"] == []


def test_cancel_stops_reads(env):
    _on(env)
    env["state"]["gate"] = threading.Event()
    body = _msg(_inv())
    body["configuration"] = {"returnImmediately": True}
    t = _send(env, "ivy", body).json()["task"]
    assert t["status"]["state"] in ("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING")
    for _ in range(100):
        if env["state"]["agents"]:
            break
        time.sleep(0.02)
    r = env["client"].post(f"/a2a/v1/tasks/{t['id']}:cancel", headers=_h(env["tok"]["ivy"]))
    assert r.status_code == 200 and r.json()["status"]["state"] == "TASK_STATE_CANCELED"
    # the run sees should_stop at its next check and ends; nothing later overwrites CANCELED
    state = env["client"].app.app.state.kratos
    live = state.a2a_tasks.live(t["id"], *_ivy(env))
    assert live.ended.wait(5)                              # the run stopped at its next check
    reads_after_cancel = len(env["state"]["agents"])
    env["state"]["gate"].set()
    g = env["client"].get(f"/a2a/v1/tasks/{t['id']}", headers=_h(env["tok"]["ivy"])).json()
    assert g["status"]["state"] == "TASK_STATE_CANCELED" and "artifacts" not in g
    assert len(env["state"]["agents"]) == reads_after_cancel == 1
    row = S.get(env["dir"], t["id"], *_ivy(env))
    assert row["state"] == "TASK_STATE_CANCELED" and row["session_id"]        # still linked to its session


def test_cancel_terminal(env):
    _on(env)
    t = _send(env, "ivy", _msg(_inv())).json()["task"]
    r = env["client"].post(f"/a2a/v1/tasks/{t['id']}:cancel", headers=_h(env["tok"]["ivy"]))
    assert r.status_code == 400 and r.json()["error"]["details"][0]["reason"] == "TASK_NOT_CANCELABLE"
    # a message to a finished (or any) task is refused: nothing restarted
    n = len(env["state"]["agents"])
    r = _send(env, "ivy", _msg(_inv(), taskId=t["id"]))
    assert r.status_code == 400 and r.json()["error"]["details"][0]["reason"] == "UNSUPPORTED_OPERATION"
    r = _send(env, "ivy", _msg(_inv(), taskId="task-not-mine"))
    assert r.json()["error"]["details"][0]["reason"] == "TASK_NOT_FOUND"
    assert len(env["state"]["agents"]) == n


def test_busy_and_open_task_cap(env):
    _on(env)
    settings_store.set(AS.MAX_OPEN_TASKS, 1, data_dir=env["dir"], actor="test")
    env["state"]["gate"] = threading.Event()
    body = _msg(_inv())
    body["configuration"] = {"returnImmediately": True}
    first = _send(env, "ivy", body).json()["task"]
    second = _send(env, "ivy", body).json()["task"]
    assert second["status"]["state"] == "TASK_STATE_REJECTED"
    assert "unfinished tasks" in second["status"]["message"]["parts"][0]["text"]
    env["state"]["gate"].set()
    for _ in range(200):
        if S.get(env["dir"], first["id"], *_ivy(env))["finished"]:
            break
        time.sleep(0.02)
    # the server's open turns are shared with chat: none left -> rejected "busy", not queued
    state = env["client"].app.app.state.kratos
    settings_store.set(AS.MAX_OPEN_TASKS, 4, data_dir=env["dir"], actor="test")
    taken = 0
    while state.open_turn():
        taken += 1
    try:
        t = _send(env, "ivy", _msg(_inv())).json()["task"]
        assert t["status"]["state"] == "TASK_STATE_REJECTED" and "busy" in t["status"]["message"]["parts"][0]["text"]
    finally:
        for _ in range(taken):
            state.close_turn()


def test_hourly_limit_shared(env):
    from kratos.serve import settings as SS

    _on(env)
    settings_store.set(SS.REQUESTS_PER_HOUR, 1, data_dir=env["dir"], actor="test")
    assert _send(env, "ivy", _msg(_inv())).json()["task"]["status"]["state"] == "TASK_STATE_COMPLETED"
    t = _send(env, "ivy", _msg(_inv())).json()["task"]
    assert t["status"]["state"] == "TASK_STATE_REJECTED" and "this hour" in t["status"]["message"]["parts"][0]["text"]


def test_budget_stop(env):
    _on(env)
    a = _answer("Stopped by the budget: Kratos's findings so far ...")
    a["status"] = "stopped_by_budget"
    env["state"]["answer"] = a
    t = _send(env, "ivy", _msg(_inv())).json()["task"]
    assert t["status"]["state"] == "TASK_STATE_COMPLETED"
    assert "Stopped by the budget" in t["artifacts"][0]["parts"][0]["text"]


def test_budget_refused_before_start(env, monkeypatch):
    _on(env)
    from kratos.budget import guard

    class _R:
        def user_message(self):
            return "Model use is paused: today's limit is reached."

        def as_dict(self):
            return {}

    monkeypatch.setattr(guard, "precheck", lambda source, **kw: _R())
    t = _send(env, "ivy", _msg(_inv())).json()["task"]
    assert t["status"]["state"] == "TASK_STATE_REJECTED" and "limit" in t["status"]["message"]["parts"][0]["text"]
    assert env["state"]["agents"] == []


def test_stream(env):
    _on(env)
    with env["client"].stream("POST", "/a2a/v1/message:stream", headers=_h(env["tok"]["ivy"]),
                              json=_msg(_inv())) as r:
        events = _sse("".join(r.iter_text()))
    assert "task" in events[0]
    kinds = [next(iter(e)) for e in events]
    assert "artifactUpdate" in kinds and kinds[-1] == "statusUpdate"
    assert events[-1]["statusUpdate"]["status"]["state"] == "TASK_STATE_COMPLETED"
    working = [e for e in events if "statusUpdate" in e and e["statusUpdate"]["status"]["state"] == "TASK_STATE_WORKING"]
    assert any("read_journalctl" in json.dumps(e) for e in working)


class _GoneRequest:
    """A request whose client has already gone (Starlette's TestClient never says so)."""

    async def is_disconnected(self):
        return True


def test_stream_drop(env):
    """A client that drops an A2A stream only stops listening: the run continues and
    GetTask returns the result."""
    import asyncio

    from kratos.serve.a2a import routes as RT

    _on(env)
    env["state"]["gate"] = threading.Event()
    body = _msg(_inv())
    body["configuration"] = {"returnImmediately": True}
    t = _send(env, "ivy", body).json()["task"]
    state = env["client"].app.app.state.kratos
    live = state.a2a_tasks.live(t["id"], *_ivy(env))

    async def drop():
        q = live.subscribe(asyncio.get_running_loop())
        got = [x async for x in RT.stream_task(live, q, _GoneRequest())]
        return got

    got = asyncio.run(drop())
    assert '"task"' in got[0] and "TASK_STATE_COMPLETED" not in "".join(got)   # it ended before the result
    assert not live.stop.is_set()                         # a dropped A2A stream does not stop the run
    env["state"]["gate"].set()
    assert live.ended.wait(5)
    g = env["client"].get(f"/a2a/v1/tasks/{t['id']}", headers=_h(env["tok"]["ivy"])).json()
    assert g["status"]["state"] == "TASK_STATE_COMPLETED" and g["artifacts"]


def test_subscribe(env):
    _on(env)
    env["state"]["gate"] = threading.Event()
    body = _msg(_inv())
    body["configuration"] = {"returnImmediately": True}
    t = _send(env, "ivy", body).json()["task"]
    threading.Timer(0.3, env["state"]["gate"].set).start()
    with env["client"].stream("POST", f"/a2a/v1/tasks/{t['id']}:subscribe", headers=_h(env["tok"]["ivy"])) as r:
        events = _sse("".join(r.iter_text()))
    assert events[0]["task"]["id"] == t["id"]
    assert events[-1]["statusUpdate"]["status"]["state"] == "TASK_STATE_COMPLETED"
    r = env["client"].post(f"/a2a/v1/tasks/{t['id']}:subscribe", headers=_h(env["tok"]["ivy"]))
    assert r.json()["error"]["details"][0]["reason"] == "UNSUPPORTED_OPERATION"


def test_restart_mid_task(env, tmp_path):
    uid = U.find(env["dir"], "ivy").user_id
    S.insert(env["dir"], task_id="task-left", context_id="ctx-1", door="a2a", user_id=uid,
             token_id=_token_id(env, "ivy-t"), skill="x",
             target=M1, state="TASK_STATE_WORKING")
    app = create_app(env["dir"], port=8766)
    with TestClient(app, base_url="http://127.0.0.1:8766") as c2:
        settings_store.set(AS.A2A_ENABLED, True, data_dir=env["dir"], actor="test")
        g = c2.get("/a2a/v1/tasks/task-left", headers=_h(env["tok"]["ivy"])).json()
    assert g["status"]["state"] == "TASK_STATE_FAILED"
    assert "restarted" in g["status"]["message"]["parts"][0]["text"]


def test_hostile_text_in_parts(env):
    _on(env)
    finding = {"id": "PERSIST-001", "title": "cron entry \x1b[2J‮evil", "severity": "high", "finding_key": "b" * 64}
    env["state"]["answer"] = _answer(HOSTILE, [finding])
    t = _send(env, "ivy", _msg(_inv())).json()["task"]
    body = json.dumps(t)
    assert "\\u001b" not in body and "\x1b" not in body and "‮" not in body
    text = t["artifacts"][0]["parts"][0]["text"]
    assert "http://evil.example" not in text and "(image removed: x)" in text
    assert t["artifacts"][0]["parts"][1]["data"]["findings"][0]["title"].startswith("cron entry")


def test_no_approvals_reachable(env):
    from kratos.agent.tools import TOOL_REGISTRY, tool_reaches_approval

    _on(env)
    _send(env, "ivy", _msg(_inv()))
    flt = env["state"]["agents"][0]["tool_filter"]
    for name in TOOL_REGISTRY:
        if tool_reaches_approval(TOOL_REGISTRY[name]):
            assert not flt(name), name
    card = env["client"].get(C.WELL_KNOWN_PATH).json()
    assert "INPUT_REQUIRED" not in json.dumps(card)
    rows = [r["state"] for r in S.list_for(env["dir"], U.find(env["dir"], "ivy").user_id)[0]]
    assert all(s not in ("TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED") for s in rows)


def test_audit_names_person_door_and_token(env):
    _on(env)
    _send(env, "ivy", _msg(_inv()))
    _send(env, "vic", _msg(_inv()))
    rows = AU.query(env["dir"])
    ivy = [r for r in rows if r["user_name"] == "ivy" and r["action"] == "investigate.start"]
    assert ivy and ivy[0]["credential"].endswith("+a2a") and ivy[0]["machine"] == M1
    vic = [r for r in rows if r["user_name"] == "vic" and r["result"] == "refused"]
    assert vic and "viewers" in vic[0]["reason"]
    from kratos.serve import store as SS

    http = [r for r in SS.recent_audit(env["dir"], 50) if r["door"] == "a2a"]
    assert any(r["metered"] for r in http) and all(r["user_id"] for r in http if r["token_id"])


def test_list_tasks_paging(env):
    _on(env)
    for _ in range(3):
        _send(env, "ivy", _msg({"skill": "list_machines"}))
    r = env["client"].get("/a2a/v1/tasks?pageSize=2", headers=_h(env["tok"]["ivy"])).json()
    assert len(r["tasks"]) == 2 and r["totalSize"] == 3 and r["nextPageToken"] == "2"
    r2 = env["client"].get("/a2a/v1/tasks?pageSize=2&pageToken=2", headers=_h(env["tok"]["ivy"])).json()
    assert len(r2["tasks"]) == 1 and r2["nextPageToken"] == ""


# ------------------------------------------------------------------ AG-UI
def _agui(env, who, machine=M1, question="anything odd?", **extra):
    body = {"threadId": "th-1", "runId": "run-1", "messages": [{"id": "u1", "role": "user", "content": question}],
            "tools": [], "context": [], "state": {}, "forwardedProps": {"kratos": {"machine": machine}}, **extra}
    with env["client"].stream("POST", "/ag-ui/run", headers=_h(env["tok"][who]), json=body) as r:
        return r.status_code, _sse("".join(r.iter_text())) if r.status_code == 200 else r.read()


def test_agui_event_order_and_only_checked_text(env):
    _on(env)
    env["state"]["answer"] = _answer("Checked answer.", [{"id": "AUTH-004", "title": "burst", "severity": "medium",
                                                          "finding_key": "c" * 64}])
    status, events = _agui(env, "ivy")
    assert status == 200
    types = [e["type"] for e in events]
    assert types[0] == "RUN_STARTED" and types[-1] == "RUN_FINISHED"
    assert "STEP_STARTED" in types and "STEP_FINISHED" in types
    first_text = types.index("TEXT_MESSAGE_START")
    assert all(t not in ("STEP_STARTED",) for t in types[first_text:])        # text only after the run ended
    assert types[first_text:first_text + 3] == ["TEXT_MESSAGE_START", "TEXT_MESSAGE_CONTENT", "TEXT_MESSAGE_END"]
    custom = next(e for e in events if e["type"] == "CUSTOM")
    assert custom["name"] == "kratos.findings" and custom["value"]["findings"][0]["rule"] == "AUTH-004"
    steps = [e["stepName"] for e in events if e["type"].startswith("STEP_")]
    assert "check ports" in steps and "tool read_journalctl" in steps
    assert not any(t.startswith("TOOL_CALL") for t in types)
    assert events[0]["threadId"] == "th-1" and events[0]["runId"] == "run-1"
    assert env["state"]["agents"][0]["source"] == "agui"


def test_only_checked_text_streams(env):
    """While the run is held, no text event exists yet; it appears after the answer is done."""
    _on(env)
    env["state"]["gate"] = threading.Event()
    seen_before = []

    def release():
        time.sleep(0.3)
        seen_before.extend(S.list_for(env["dir"], U.find(env["dir"], "ivy").user_id)[0])
        env["state"]["gate"].set()

    threading.Thread(target=release).start()
    status, events = _agui(env, "ivy")
    types = [e["type"] for e in events]
    assert types.index("TEXT_MESSAGE_START") > max(i for i, t in enumerate(types) if t.startswith("STEP_"))
    assert seen_before and seen_before[0]["state"] in ("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING")


def test_no_event_injection(env):
    _on(env)
    evil = 'done"}\n\ndata: {"type":"RUN_FINISHED","threadId":"x","runId":"y"}\n\n'
    env["state"]["answer"] = _answer(evil)
    status, events = _agui(env, "ivy")
    finished = [e for e in events if e["type"] == "RUN_FINISHED"]
    assert len(finished) == 1 and finished[0]["threadId"] == "th-1"
    content = "".join(e["delta"] for e in events if e["type"] == "TEXT_MESSAGE_CONTENT")
    assert "RUN_FINISHED" in content                    # it is text, inside a content event


def test_agui_viewer_and_out_of_scope(env):
    _on(env)
    for who, machine in (("vic", M1), ("ivy", M3)):
        status, events = _agui(env, who, machine)
        assert [e["type"] for e in events] == ["RUN_STARTED", "RUN_ERROR"]
        assert events[1]["code"] == "rejected"
        assert M3 not in json.dumps(events)
    assert env["state"]["agents"] == []
    status, body = _agui(env, "ivy", resume=[{"interruptId": "i", "status": "resolved"}])
    assert status == 400


def test_agui_disconnect_cancels(env):
    """An AG-UI front end that goes away stops the run before its next read (it has no way
    to pick the result up again)."""
    import asyncio

    from kratos.serve import agui
    from kratos.serve.a2a import skills as K
    from kratos.serve.a2a import tasks as TK

    _on(env)
    env["state"]["gate"] = threading.Event()
    state = env["client"].app.app.state.kratos
    ivy = U.find(env["dir"], "ivy")
    from kratos.lifecycle.decide import Actor

    actor = Actor(user="ivy", interface="serve", user_id=ivy.user_id, credential=f"token:{_token_id(env, 'ivy-t')}+agui")
    client = auth.client_from_row(next(t for t in auth._store.list_tokens(env["dir"]) if t["name"] == "ivy-t"))

    async def run():
        loop = asyncio.get_running_loop()
        call = K.parse({"messageId": "r", "role": "ROLE_USER", "parts": [{"data": _inv()}]})
        started = await asyncio.to_thread(TK.start_task, state, actor=actor, client=client, door="agui", call=call,
                                          loop=loop)
        gen = agui._stream(state, started.task, started.queue, _GoneRequest(), "th", "run", set(), set())
        first = await gen.__anext__()
        assert "RUN_STARTED" in first
        for _ in range(200):                              # the run is reading the machine
            if env["state"]["agents"]:
                break
            await asyncio.sleep(0.02)
        await gen.aclose()                                # the front end went away
        await asyncio.sleep(0.3)
        return started.task

    t = asyncio.run(run())
    assert t.stop.is_set()
    assert t.ended.wait(5)
    env["state"]["gate"].set()
    row = S.get(env["dir"], t.task_id, ivy.user_id, t.token_id)
    assert row["state"] == "TASK_STATE_CANCELED" and row["door"] == "agui"
    assert len(env["state"]["agents"]) == 1


def _ivy(env):
    return U.find(env["dir"], "ivy").user_id, _token_id(env, "ivy-t")


def test_a_narrowed_token_never_reads_the_same_persons_other_tasks(env):
    """D.7: a token can narrow a person's machines. A task belongs to the person AND the
    token that started it, so a token narrowed to M1 can't read what the same person's
    broader token found on M2 (MCP binds its investigations the same way)."""
    _on(env)
    with authz.acting_as(OWNER):
        narrow, _ = auth.create_token(env["dir"], name="ivy-m1", user="ivy", targets=[M1], agents=True)
    t = _send(env, "ivy", _msg(_inv(M2))).json()["task"]
    assert t["status"]["state"] == "TASK_STATE_COMPLETED"
    h = _h(narrow)
    assert env["client"].get(f"/a2a/v1/tasks/{t['id']}", headers=h).json()["error"]["details"][0]["reason"] \
        == "TASK_NOT_FOUND"
    assert env["client"].post(f"/a2a/v1/tasks/{t['id']}:subscribe", headers=h).status_code == 404
    assert env["client"].post(f"/a2a/v1/tasks/{t['id']}:cancel", headers=h).status_code == 404
    assert env["client"].get("/a2a/v1/tasks", headers=h).json()["tasks"] == []
    r = env["client"].post("/a2a/v1/message:send", headers=h, json=_msg(_inv(M2)))
    assert r.json()["task"]["status"]["state"] == "TASK_STATE_REJECTED"          # and it can't start one there


def _token_id(env, name):
    return next(t for t in auth._store.list_tokens(env["dir"]) if t["name"] == name)["token_id"]


def test_an_extra_read_with_no_tool_named_reads_plainly():
    """A fleet model may ask for an extra read without naming the tool or machine: the
    line says so instead of 'Extra reads:  on  (not run: ...)' (seen in the E.5 lab run)."""
    from kratos.fleet.answer import FleetAnswer
    from kratos.serve import render as R

    a = FleetAnswer(status="final_answer", summary="2 machines")
    a.extra_reads.append({"tool": "", "machine": None, "ran": False, "why": "(none) is not a machine in this question"})
    text = R.fleet_markdown(a)
    assert "(no read named) on (no machine named)" in text and "  on  " not in text
    assert "(no read named) on (no machine named)" in a.render()


_BAD_CHARS = [chr(c) for c in range(0x20) if chr(c) not in "\n\t"] + ["\x7f"] + \
    [chr(c) for c in range(0x80, 0xA0)] + [chr(c) for c in range(0x202A, 0x202F)] + \
    [chr(c) for c in range(0x2066, 0x206A)] + ["​", "‍", "﻿", " ", " "]


def test_hostile_corpus_through_both_doors(env):
    """Every A.4 corpus entry, as a finding title and in the model's analysis: what reaches
    the other agent (the A2A task JSON, the AG-UI events) carries no escape sequence,
    hidden or direction-changing character, live link, image or raw HTML."""
    import pathlib

    from kratos.serve import settings as SS

    pytest.importorskip("markdown_it")
    from _untrusted_corpus import assert_screen_safe
    from test_untrusted_markdown import _assert_inert

    corpus = json.loads((pathlib.Path(__file__).parent / "fixtures/untrusted/corpus.json").read_text())
    _on(env)
    settings_store.set(SS.REQUESTS_PER_HOUR, 1000, data_dir=env["dir"], actor="test")
    for i, (name, value) in enumerate(corpus.items()):
        env["state"]["answer"] = _answer(f"Finding: {value}", [{"id": "PERSIST-001", "title": value,
                                                                "severity": "high", "finding_key": f"{i:064x}"}])
        t = _send(env, "ivy", _msg(_inv())).json()["task"]
        decoded = json.loads(json.dumps(t))
        text = decoded["artifacts"][0]["parts"][0]["text"]
        title = decoded["artifacts"][0]["parts"][1]["data"]["findings"][0]["title"]
        for out in (text, title):
            bad = [c for c in out if c in _BAD_CHARS or 0xE0000 <= ord(c) <= 0xE007F or 0xD800 <= ord(c) <= 0xDFFF]
            assert not bad, (name, bad[:3])
            assert_screen_safe(out, where=name)
        _assert_inert(text)                     # rendered by a CommonMark parser: no image, live link or raw tag
    status, events = _agui(env, "ivy")
    blob = json.dumps(events, ensure_ascii=False)
    assert not [c for c in blob if c in _BAD_CHARS and c not in "\n"], "AG-UI events"
