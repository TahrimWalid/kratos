"""`kratos serve` (docs/phaseB/B.3 §7), all in-process -- no real port.

The OpenAI-compatible door and MCP over HTTP: tokens, target scope, Host/Origin checks,
the unreachable-tools rule, the answer contract (the reply is the checked answer, never a
draft), streaming (progress only in the reasoning channel, keep-alives, [DONE]), stop on
disconnect, sessions, budget, the audit log, and masking of what reaches the model.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from starlette.testclient import TestClient  # noqa: E402

from kratos import kratos_config, settings_store  # noqa: E402
from kratos.agent.tools import TOOL_REGISTRY  # noqa: E402
from kratos.serve import auth, render  # noqa: E402
from kratos.serve import settings as SS  # noqa: E402
from kratos.serve import store as S  # noqa: E402
from kratos.serve.app import create_app  # noqa: E402

T1, T2, OTHER = "192.0.2.10", "192.0.2.11", "192.0.2.99"
BASE = "http://127.0.0.1:8765"


def _answer(block="Kratos found (open, serious):\n  - HIGH CORR-SSH-001 x\n\n", notes="[NOTE: n.]\n\n",
            analysis="The analysis."):
    return {"status": "final_answer", "final_answer": block + notes + analysis,
            "answer_parts": {"block": block, "notes": notes, "analysis": analysis},
            "recommended_commands": [], "transcript": [], "token_usage": {"prompt_tokens": 3, "completion_tokens": 2},
            "run_id": "r" * 32}


@pytest.fixture
def env(tmp_path, monkeypatch):
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target(T1)
    calls = {"route": [], "agent": []}

    def route(message, context="", *, capture_stderr=True):
        calls["route"].append((message, context, capture_stderr))
        if message.lower().startswith("hello"):
            return False, "Hi -- ask me about the machine."
        return True, None

    from kratos.cli import repl as _repl

    real_route = _repl._route_input
    monkeypatch.setattr("kratos.cli.repl._route_input", route)
    state = {"result": _answer(), "sleep": 0.0, "raise": None, "step": None}

    def fake_agent(goal, data_dir, max_iters=10, on_step=None, *, tool_filter=None, on_progress=None,
                   should_stop=None, **kw):
        calls["agent"].append({"goal": goal, "target": kratos_config.get_active_target(), "filter": tool_filter,
                               "prior": kw.get("prior_context"), "session_id": kw.get("session_id")})
        if on_progress:
            on_progress("checked ports: ok")
        if on_step:
            on_step({"tool": "run_nmap_scan"})
        end = time.monotonic() + state["sleep"]
        while time.monotonic() < end:
            if should_stop and should_stop():
                from kratos.agent.loop import InvestigationStopped

                raise InvestigationStopped()
            time.sleep(0.02)
        if state["step"]:
            state["step"]()
        if state["raise"]:
            raise state["raise"]
        return dict(state["result"])

    import kratos.agent.loop as agent_loop

    real_agent = agent_loop.run_agent
    monkeypatch.setattr("kratos.agent.loop.run_agent", fake_agent)
    token, _row = auth.create_token(tmp_path, name="owui", targets=[T1, T2], mcp=True)
    plain, _ = auth.create_token(tmp_path, name="plain")          # default machine only, no MCP
    app = create_app(tmp_path, port=8765)
    with TestClient(app, base_url=BASE) as client:
        yield {"client": client, "token": token, "plain": plain, "dir": tmp_path, "calls": calls,
               "state": state, "app": app, "real_agent": real_agent, "real_route": real_route}


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _chat(env, content="has anyone been trying to log in?", *, model=f"kratos/{T1}", token=None, stream=False,
          headers=None, messages=None):
    body = {"model": model, "stream": stream, "messages": messages or [{"role": "user", "content": content}]}
    return env["client"].post("/v1/chat/completions", json=body, headers={**_h(token or env["token"]), **(headers or {})})


def _audit_rows(d):
    conn = sqlite3.connect(Path(d) / "kratos.db")
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM serve_audit ORDER BY id")]
    finally:
        conn.close()


def _sse_events(text):
    out = []
    for line in text.splitlines():
        if line.startswith("data: ") and line != "data: [DONE]":
            out.append(json.loads(line[6:]))
    return out


# --------------------------------------------------------------------------- auth
def test_no_wrong_or_revoked_token_is_401(env):
    c = env["client"]
    assert c.get("/v1/models").status_code == 401
    assert c.get("/v1/models", headers=_h("krt_000000000000_" + "x" * 43)).status_code == 401
    assert c.get("/v1/models", headers=_h(env["token"][:-1] + ("A" if env["token"][-1] != "A" else "B"))).status_code == 401
    assert c.get("/v1/models", headers=_h(env["token"])).status_code == 200
    auth.revoke(env["dir"], "owui")
    assert c.get("/v1/models", headers=_h(env["token"])).status_code == 401   # revoked: next request, cached or not
    assert "error" in c.get("/v1/models").json()


def test_repeated_failures_from_one_address_are_throttled(env):
    from kratos.subagent.core_server import AUTH_FAILURE_LIMIT

    c = env["client"]
    for _ in range(AUTH_FAILURE_LIMIT):
        assert c.get("/v1/models", headers=_h("wrong")).status_code == 401
    r = c.get("/v1/models", headers=_h(env["token"]))     # even the right token waits now
    assert r.status_code == 429


def test_only_an_scrypt_hash_is_stored_never_the_token(env):
    raw = (Path(env["dir"]) / "kratos.db").read_bytes()
    for tok in (env["token"], env["plain"]):
        secret = tok.split("_", 2)[2]
        assert secret.encode() not in raw and tok.encode() not in raw
    row = S.get_token(env["dir"], env["token"].split("_")[1])
    assert row["kdf"]["name"] == "scrypt" and row["kdf"]["n"] >= 2 ** 14 and len(row["salt"]) == 32


def test_no_endpoint_creates_or_lists_tokens(env):
    c = env["client"]
    for path in ("/v1/tokens", "/tokens", "/v1/serve/token", "/admin"):
        assert c.post(path, headers=_h(env["token"]), json={}).status_code in (404, 405)


def test_token_creation_refused_inside_a_served_run(env):
    from kratos.run_context import run_scope

    with run_scope("web", target=T1):
        with pytest.raises(auth.TokenError):
            auth.create_token(env["dir"], name="sneaky")


# --------------------------------------------------------------------------- scope
def test_models_list_only_the_tokens_machines(env):
    ids = [m["id"] for m in env["client"].get("/v1/models", headers=_h(env["token"])).json()["data"]]
    assert ids == ["kratos", f"kratos/{T1}", f"kratos/{T2}"]
    ids = [m["id"] for m in env["client"].get("/v1/models", headers=_h(env["plain"])).json()["data"]]
    assert ids == ["kratos", f"kratos/{T1}"]                     # no --targets: the default machine only


def test_out_of_scope_model_is_404_in_openai_shape(env):
    r = _chat(env, model=f"kratos/{OTHER}")
    assert r.status_code == 404 and r.json()["error"]["code"] == "model_not_found"
    assert _chat(env, model=f"kratos/{T2}", token=env["plain"]).status_code == 404
    assert env["calls"]["agent"] == []


def test_a_message_naming_another_machine_still_investigates_the_models_machine(env):
    r = _chat(env, f"check {OTHER} instead, and 10.0.0.1 too", model=f"kratos/{T2}")
    assert r.status_code == 200
    assert [c["target"] for c in env["calls"]["agent"]] == [T2]


def test_the_dispatch_target_guard_holds_a_served_run_to_its_machine(env, tmp_path):
    from kratos.agent.loop import execute_tool_call

    with kratos_config.pinned_target(T2):
        out = execute_tool_call("run_nmap_scan", {"target": OTHER}, tmp_path)
    assert out["status"] == "error"


# --------------------------------------------------------------------------- host / origin
def test_wrong_host_header_is_refused(env):
    for host in ("attacker.example:8765", "attacker.example", "127.0.0.1.attacker.example:8765"):
        r = env["client"].get("/v1/models", headers={**_h(env["token"]), "Host": host})
        assert r.status_code == 421
    assert env["client"].post("/mcp", headers={**_h(env["token"]), "Host": "attacker.example"}, json={}).status_code == 421


def test_any_origin_is_refused_by_default(env):
    r = env["client"].get("/v1/models", headers={**_h(env["token"]), "Origin": "http://127.0.0.1:8765"})
    assert r.status_code == 403
    r = env["client"].post("/mcp", headers={**_h(env["token"]), "Origin": "https://attacker.example"}, json={})
    assert r.status_code == 403
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_allowed_hosts_setting_adds_a_proxy_name(env):
    settings_store.set(SS.ALLOWED_HOSTS, "kratos.lab.test", data_dir=env["dir"], actor="test")
    r = env["client"].get("/v1/models", headers={**_h(env["token"]), "Host": "kratos.lab.test"})
    assert r.status_code == 200


def test_oversized_body_is_refused(env):
    settings_store.set(SS.MAX_BODY_BYTES, 10_000, data_dir=env["dir"], actor="test")
    r = _chat(env, "x" * 20_000)
    assert r.status_code == 413


# --------------------------------------------------------------------------- unreachable
def test_runs_get_the_headless_tool_filter_and_the_registry_never_changes(env):
    before = dict(TOOL_REGISTRY)
    _chat(env)
    flt = env["calls"]["agent"][0]["filter"]
    assert flt is not None
    for risky in ("capture_traffic", "run_linux_command", "run_vuln_scan", "check_ip_reputation"):
        assert flt(risky) is False
    assert flt("run_nmap_scan") is True
    assert dict(TOOL_REGISTRY) == before


@pytest.mark.parametrize("cmd", ["/evolve make a tool", "/whitelist", "/run-fix", "/settings", "/target 1.2.3.4",
                                 "/accept abc", "/preset run x", "/delete"])
def test_app_only_commands_are_refused_without_a_model_call(env, cmd):
    r = _chat(env, cmd)
    text = r.json()["choices"][0]["message"]["content"]
    assert "not available from a chat client" in text
    assert env["calls"]["route"] == [] and env["calls"]["agent"] == []


def test_help_and_findings_work_without_a_model_call(env):
    assert "Commands that work here" in _chat(env, "/help").json()["choices"][0]["message"]["content"]
    assert "No open findings" in _chat(env, "/findings").json()["choices"][0]["message"]["content"]
    assert env["calls"]["route"] == []


def test_client_background_tasks_are_answered_without_the_model(env):
    task = ("### Task:\nGenerate a concise title summarizing the chat history.\n### Output:\n"
            'JSON format: { "title": "your concise title here" }\n### Chat History:\n<chat_history>\nUSER: hi\n'
            "</chat_history>")
    r = _chat(env, task)
    assert json.loads(r.json()["choices"][0]["message"]["content"]) == {"title": "Kratos investigation"}
    assert env["calls"]["route"] == [] and env["calls"]["agent"] == []
    assert _audit_rows(env["dir"])[-1]["status"] == "task"


# --------------------------------------------------------------------------- answer contract
def test_reply_is_exactly_the_rendered_checked_answer(env):
    result = env["state"]["result"]
    r = _chat(env)
    content = r.json()["choices"][0]["message"]["content"]
    assert content == render.answer_markdown(result["final_answer"], result["answer_parts"], [])
    assert r.json()["usage"]["total_tokens"] == 5 and r.json()["model"] == f"kratos/{T1}"


def test_a_guard_rejected_draft_never_reaches_the_client(env, monkeypatch, tmp_path):
    """Through the REAL loop: the model's first answer is dismissive while a HIGH finding is
    open, Guard 3 sends it back, the stream carries only the checked answer."""
    from kratos.agent import loop as agent_loop

    monkeypatch.setattr("kratos.agent.loop.run_agent", env["real_agent"])
    high = {"id": "CORR-SSH-001", "title": "SSH exposed with failed-login burst", "severity": "high",
            "entities": ["203.0.113.7"], "evidence": ["burst from 203.0.113.7"]}
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", lambda **kw: {
        "findings": [high], "count": 1, "staleness_warning": None, "missing_inputs": [], "input_errors": {},
        "inputs_used": {}})
    replies = iter([json.dumps({"reasoning": "r", "tool": "correlate_findings", "args": {}}),
                    json.dumps({"reasoning": "r", "final_answer": "DRAFT_ONE: no suspicious activity, the system appears secure."}),
                    json.dumps({"reasoning": "r", "final_answer": "FINAL: CORR-SSH-001 -- a burst from 203.0.113.7. Act on it."})])
    monkeypatch.setattr(agent_loop, "agent_chat", lambda *a, **k: next(replies))
    r = _chat(env, stream=True)
    assert "DRAFT_ONE" not in r.text
    events = _sse_events(r.text)
    content = "".join(e["choices"][0]["delta"].get("content") or "" for e in events)
    assert "FINAL: CORR-SSH-001" in content and "Kratos found" in content


# --------------------------------------------------------------------------- stream
def test_stream_progress_only_in_reasoning_then_the_answer_then_done(env):
    r = _chat(env, stream=True)
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.text.rstrip().endswith("data: [DONE]")
    events = _sse_events(r.text)
    deltas = [e["choices"][0]["delta"] for e in events]
    assert deltas[0]["role"] == "assistant"
    reasoning = [d["reasoning_content"] for d in deltas if "reasoning_content" in d]
    contents = [d["content"] for d in deltas if d.get("content")]
    assert any("checked ports" in x for x in reasoning) and any("run_nmap_scan" in x for x in reasoning)
    assert len(contents) == 1 and "The analysis." in contents[0]
    assert all("checked ports" not in c for c in contents)
    assert events[-1]["choices"][0]["finish_reason"] == "stop" and events[-1]["usage"]["total_tokens"] == 5


def test_stream_sends_keepalive_comments_while_quiet(env, monkeypatch):
    from kratos.serve import openai_routes

    monkeypatch.setattr(openai_routes, "KEEPALIVE_SECONDS", 0.2)
    env["state"]["sleep"] = 1.6
    r = _chat(env, stream=True)
    assert ": keep-alive" in r.text


def test_an_error_after_streaming_started_is_a_plain_final_chunk(env):
    env["state"]["raise"] = RuntimeError("disk full")
    r = _chat(env, stream=True)
    content = "".join(e["choices"][0]["delta"].get("content") or "" for e in _sse_events(r.text))
    assert "could not finish" in content and "disk full" in content
    assert "Traceback" not in content and 'File "' not in content
    assert r.text.rstrip().endswith("data: [DONE]")


# --------------------------------------------------------------------------- stop
def test_disconnect_mid_run_stops_before_another_tool_dispatch(env, monkeypatch):
    """A raw ASGI call whose client goes away mid-run: should_stop turns true, the run ends
    (InvestigationStopped) before its next dispatch, the turn is recorded stopped."""
    dispatched_after_stop = []
    env["state"]["sleep"] = 3.0

    def after():                        # would run only if the stop didn't land
        dispatched_after_stop.append(True)

    env["state"]["step"] = after
    app = env["app"]
    body = json.dumps({"model": f"kratos/{T1}", "stream": True,
                       "messages": [{"role": "user", "content": "scan it"}]}).encode()
    scope = {"type": "http", "http_version": "1.1", "method": "POST", "path": "/v1/chat/completions",
             "raw_path": b"/v1/chat/completions", "query_string": b"", "root_path": "", "scheme": "http",
             "server": ("127.0.0.1", 8765), "client": ("127.0.0.1", 50000),
             "headers": [(b"host", b"127.0.0.1:8765"), (b"content-type", b"application/json"),
                         (b"content-length", str(len(body)).encode()),
                         (b"authorization", f"Bearer {env['token']}".encode())]}
    sent: list[dict] = []
    t_start = time.monotonic()

    async def drive():
        got_body = {"done": False}
        start = time.monotonic()

        async def receive():
            if not got_body["done"]:
                got_body["done"] = True
                return {"type": "http.request", "body": body, "more_body": False}
            while time.monotonic() - start < 0.6:          # the client stays 0.6 s, then leaves
                await asyncio.sleep(0.05)
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        # the server's loop keeps running after a disconnect (uvicorn); so does this one,
        # until the stopped run has wound down and been audited
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            found = [r for r in _audit_rows(env["dir"]) if r["endpoint"] == "/v1/chat/completions"]
            if found:
                return found
            await asyncio.sleep(0.1)
        return []

    rows = asyncio.run(drive())
    assert time.monotonic() - t_start < 3.0           # stopped well before the 3 s run would have ended
    assert dispatched_after_stop == []
    assert rows and rows[-1]["status"] == "stopped"
    from kratos.storage.session_store import SessionStore

    store = SessionStore(Path(env["dir"]) / "kratos.db")
    sid = env["calls"]["agent"][0]["session_id"]
    assert store.get_goal_history(sid)[-1]["status"] == "cancelled"


# --------------------------------------------------------------------------- concurrency
def test_max_parallel_makes_a_third_wait(tmp_path):
    from kratos.serve.runs import RunSlots

    settings_store.set(SS.MAX_PARALLEL, 2, data_dir=tmp_path, actor="test")
    slots = RunSlots(tmp_path)
    assert slots.acquire() and slots.acquire()
    waited = []
    got = threading.Event()

    def third():
        slots.acquire(on_wait=lambda: waited.append(True))
        got.set()

    t = threading.Thread(target=third)
    t.start()
    time.sleep(0.3)
    assert waited == [True] and not got.is_set() and slots.waiting == 1
    slots.release()
    assert got.wait(2)
    t.join()


def test_a_waiting_run_tells_the_client_and_can_be_stopped(tmp_path):
    from kratos.serve.runs import RunSlots

    settings_store.set(SS.MAX_PARALLEL, 1, data_dir=tmp_path, actor="test")
    slots = RunSlots(tmp_path)
    assert slots.acquire()
    stop = threading.Event()
    threading.Timer(0.3, stop.set).start()
    assert slots.acquire(should_stop=stop.is_set) is False


# --------------------------------------------------------------------------- budget
def test_a_paused_source_is_refused_before_starting_with_the_reason(env, monkeypatch):
    from kratos.budget import guard

    class Refusal:
        def user_message(self):
            return "Kratos paused this source: three failures in a row."

    monkeypatch.setattr(guard, "precheck", lambda source, **kw: Refusal() if source == "web" else None)
    r = _chat(env)
    assert "paused this source" in r.json()["choices"][0]["message"]["content"]
    assert env["calls"]["agent"] == [] and env["calls"]["route"] == []
    assert _audit_rows(env["dir"])[-1]["status"] == "budget"


def test_hourly_request_limit_per_token(env):
    settings_store.set(SS.REQUESTS_PER_HOUR, 2, data_dir=env["dir"], actor="test")
    assert _chat(env).status_code == 200 and _chat(env).status_code == 200
    r = _chat(env)
    assert r.status_code == 429 and r.json()["error"]["code"] == "rate_limit_exceeded"
    assert _chat(env, "/help").status_code == 200                       # commands use no model: not counted


def test_served_runs_are_web_runs(env, monkeypatch):
    from kratos.run_context import current

    seen = {}
    env["state"]["step"] = lambda: seen.setdefault("ctx", current())
    _chat(env)
    assert seen["ctx"].source == "web" and seen["ctx"].unattended


# --------------------------------------------------------------------------- sessions
def test_same_client_chat_same_session_new_chat_new_session(env):
    h1 = {"X-OpenWebUI-Chat-Id": "chat-aaa", "X-OpenWebUI-User-Name": "Alice Example",
          "X-OpenWebUI-User-Email": "alice@example.com"}
    _chat(env, "first?", headers=h1)
    _chat(env, "second?", headers=h1, messages=[{"role": "user", "content": "first?"},
                                                {"role": "assistant", "content": "answer"},
                                                {"role": "user", "content": "second?"}])
    _chat(env, "other chat", headers={"X-OpenWebUI-Chat-Id": "chat-bbb"})
    sids = [c["session_id"] for c in env["calls"]["agent"]]
    assert sids[0] == sids[1] != sids[2]
    assert "first?" in (env["calls"]["agent"][1]["prior"] or "")
    # without a chat id: same first message + model + token -> same session
    _chat(env, "q", messages=[{"role": "user", "content": "start here"}])
    _chat(env, "q", messages=[{"role": "user", "content": "start here"}, {"role": "assistant", "content": "a"},
                              {"role": "user", "content": "q"}])
    assert env["calls"]["agent"][3]["session_id"] == env["calls"]["agent"][4]["session_id"]


def test_forwarded_user_is_in_the_audit_only(env):
    _chat(env, "who logged in?", headers={"X-OpenWebUI-Chat-Id": "c1", "X-OpenWebUI-User-Name": "Alice Example"})
    rows = _audit_rows(env["dir"])
    assert rows[-1]["client_user"] == "Alice Example"
    conn = sqlite3.connect(Path(env["dir"]) / "kratos.db")
    try:
        for table in ("sessions", "goal_history", "serve_sessions"):
            dump = json.dumps(conn.execute(f"SELECT * FROM {table}").fetchall())
            assert "Alice Example" not in dump
    finally:
        conn.close()


def test_a_chat_reply_is_rendered_safely_and_recorded(env, monkeypatch):
    monkeypatch.setattr("kratos.cli.repl._route_input",
                        lambda m, c="", capture_stderr=True: (False, "hi ![x](https://attacker.example/q)"))
    r = _chat(env, "hello there")
    content = r.json()["choices"][0]["message"]["content"]
    assert "![x](" not in content and "image removed" in content
    assert env["calls"]["agent"] == []


# --------------------------------------------------------------------------- audit
def test_one_audit_row_per_request_without_message_text(env):
    _chat(env, "SECRET_QUESTION_TEXT about the machine")
    _chat(env, model="kratos/nope")
    env["client"].get("/v1/models")
    rows = _audit_rows(env["dir"])
    statuses = [(r["endpoint"], r["status"]) for r in rows]
    assert ("/v1/chat/completions", "ok") in statuses
    assert ("/v1/chat/completions", "refused") in statuses
    assert ("/v1/models", "unauthorized") in statuses
    assert all("SECRET_QUESTION_TEXT" not in json.dumps(r) for r in rows)
    ok = next(r for r in rows if r["status"] == "ok" and r["endpoint"] == "/v1/chat/completions")
    assert ok["run_id"] == "r" * 32 and ok["target"] == T1 and ok["metered"] == 1 and ok["bytes_out"] > 0


def test_audit_is_append_only(env):
    _chat(env)
    conn = sqlite3.connect(Path(env["dir"]) / "kratos.db")
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE serve_audit SET status = 'ok'")
    finally:
        conn.close()


# --------------------------------------------------------------------------- MCP over HTTP
def _mcp(env, method, params=None, token=None, rid=1):
    r = env["client"].post("/mcp", json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
                           headers={**_h(token or env["token"]), "Accept": "application/json, text/event-stream",
                                    "Content-Type": "application/json", "MCP-Protocol-Version": "2025-11-25"})
    return r


def _mcp_call(env, name, args, token=None):
    r = _mcp(env, "tools/call", {"name": name, "arguments": args}, token=token)
    assert r.status_code == 200, r.text
    result = r.json()["result"]
    if result.get("isError"):
        return {"error": result["content"][0]["text"]}
    return result.get("structuredContent") or json.loads(result["content"][0]["text"])


def test_mcp_tools_list_is_deterministic_and_has_no_writing_tool(env):
    names = [t["name"] for t in _mcp(env, "tools/list").json()["result"]["tools"]]
    assert names == ["kratos_start_investigation", "kratos_get_investigation", "kratos_get_findings",
                     "kratos_list_sessions", "kratos_finding_states"]
    assert names == [t["name"] for t in _mcp(env, "tools/list").json()["result"]["tools"]]


def test_mcp_needs_a_token_with_the_mcp_door(env):
    assert _mcp(env, "tools/list", token="nope").status_code == 401
    assert _mcp(env, "tools/list", token=env["plain"]).status_code == 403


def test_mcp_start_returns_at_once_then_poll_gives_progress_and_the_answer(env):
    env["state"]["sleep"] = 0.8
    t0 = time.monotonic()
    started = _mcp_call(env, "kratos_start_investigation", {"goal": "anyone logging in?", "target": T1})
    assert time.monotonic() - t0 < 0.6
    inv = started["investigation_id"]
    deadline = time.monotonic() + 10
    got = {}
    while time.monotonic() < deadline:
        got = _mcp_call(env, "kratos_get_investigation", {"investigation_id": inv})
        if got["status"] == "done":
            break
        time.sleep(0.1)
    assert got["status"] == "done" and "The analysis." in got["final_answer"]
    assert any("checked ports" in p for p in got["progress"])
    # another token can't see it
    other, _ = auth.create_token(env["dir"], name="other", targets=[T1], mcp=True)
    assert "no investigation" in _mcp_call(env, "kratos_get_investigation", {"investigation_id": inv},
                                           token=other)["error"]


def test_mcp_start_refuses_a_machine_outside_the_tokens_scope(env):
    out = _mcp_call(env, "kratos_start_investigation", {"goal": "x", "target": OTHER})
    assert "may not investigate" in out["error"]
    assert env["calls"]["agent"] == []


def test_stdio_mcp_server_still_uses_the_shared_runner(env):
    from kratos import mcp_server

    out = mcp_server._mcp_investigation("goal", T1, 3, env["dir"])
    assert out["status"] == "final_answer" and env["calls"]["agent"][-1]["filter"] is not None


# --------------------------------------------------------------------------- doctor / status
def test_status_file_says_running_while_served(env):
    from kratos.serve import status

    st = status.read(env["dir"])
    assert st["running"] and st["port"] == 8765
    assert "running on 127.0.0.1:8765" in status.summary(env["dir"]) and "3 tokens" not in status.summary(env["dir"])


# --------------------------------------------------------------------------- masking (B.2) over a served run
def test_a_served_investigation_sends_no_real_values_to_the_model(env, monkeypatch):
    """The router call and every investigation call of a chat-started run go through the
    masked choke point: the captured request bodies carry none of the fixture's real
    values, while the reply the chat client gets has them back."""
    pytest.importorskip("requests")
    from kratos import llm_interface
    from kratos.privacy import mode as M

    attacker, user, secret = "203.0.113.7", "alice", "AKIA" + "X" * 16
    d = env["dir"]
    monkeypatch.setattr("kratos.agent.loop.run_agent", env["real_agent"])
    monkeypatch.setattr("kratos.cli.repl._route_input", env["real_route"])
    monkeypatch.setattr(llm_interface, "_running_backend", lambda: "openai_compatible")
    monkeypatch.setattr(llm_interface, "get_active_llm_base_url", lambda: "https://api.example.com/v1")
    monkeypatch.setattr(llm_interface, "get_active_llm_api_key", lambda: "k")
    monkeypatch.setattr(llm_interface, "get_active_llm_model", lambda: "m")
    settings_store.set(M.MODE_KEY, "standard", data_dir=d, actor="test")
    (d / "context").mkdir(exist_ok=True)
    (d / "context" / "privileged_accounts_20260101_000000_000000.json").write_text(json.dumps(
        {"target": f"ubuntu@{T1}", "accounts": {}, "local_accounts": {user: 1001, "root": 0}}))
    high = {"id": "CORR-SSH-001", "title": "SSH exposed with failed-login burst activity observed", "severity": "high",
            "entities": [attacker], "evidence": [f"burst of 12 failed logins from {attacker} for {user}"]}
    monkeypatch.setattr(TOOL_REGISTRY["read_journalctl"], "handler", lambda **kw: {
        "status": "ok", "entries": [f"sshd: Failed password for {user} from {attacker} port 50022",
                                    f"cron: export KEY={secret}"], "user": user})
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", lambda **kw: {
        "findings": [high], "count": 1, "staleness_warning": None, "missing_inputs": [], "input_errors": {},
        "inputs_used": {}})
    script = ["INVESTIGATE",
              json.dumps({"reasoning": "r", "tool": "read_journalctl", "args": {"since": "24 hours ago"}}),
              json.dumps({"reasoning": "r", "tool": "correlate_findings", "args": {}}),
              json.dumps({"reasoning": "r", "final_answer": f"CORR-SSH-001: {attacker} is guessing the password "
                                                              f"of {user}. Restrict SSH."})]
    bodies = []

    class _Resp:
        def __init__(self, content):
            self._b = {"choices": [{"message": {"content": content}}],
                       "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}

        def raise_for_status(self):
            return None

        def json(self):
            return self._b

    def post(url, headers=None, json=None, timeout=None):  # noqa: A002
        from kratos.privacy.mask import request_masker

        bodies.append(json)
        return _Resp(request_masker(base_url="https://api.example.com/v1").mask(script.pop(0)))

    monkeypatch.setattr(llm_interface.requests, "post", post)
    r = _chat(env, f"did {attacker} get in as {user}? my key is {secret}", headers={"X-OpenWebUI-Chat-Id": "m1"})
    sent = "\n".join(m["content"] for b in bodies for m in b["messages"])
    assert len(bodies) >= 3                                   # the router call + the investigation's calls
    for value in (T1, attacker, secret):
        assert value not in sent
    assert f" {user} " not in sent and f"{user}?" not in sent
    content = r.json()["choices"][0]["message"]["content"]
    assert attacker in content and user in content            # the person reads real values
    # the ledger recorded the calls under source "web"
    conn = sqlite3.connect(d / "kratos.db")
    try:
        sources = {row[0] for row in conn.execute("SELECT DISTINCT source FROM budget_ledger")}
    finally:
        conn.close()
    assert "web" in sources


def test_doctor_reports_the_chat_server(env):
    from kratos.agent import doctor

    assert any(name == "chat server" for name, _fn in _doctor_sections(doctor, env["dir"]))
    rows = []
    doctor._check_chat_server(rows, env["dir"])
    assert rows and "running on 127.0.0.1:8765" in rows[0]["detail"] and rows[0]["status"] == "info"


def _doctor_sections(doctor, data_dir):
    import inspect

    src = inspect.getsource(doctor.run_diagnostics)
    return [("chat server", None)] if '("chat server", lambda o: _check_chat_server(o' in src else []


def test_doctor_when_never_run(tmp_path):
    from kratos.agent.doctor import _check_chat_server

    out = []
    _check_chat_server(out, tmp_path)
    assert out[0]["detail"].startswith("chat server: not running")
