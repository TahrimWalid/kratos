"""D.7 through `kratos serve` (in-process, no real port): who is calling, what they may
see and do, a shared Open WebUI with signed identity, per-person sessions and limits,
and an investigation stopped at its next read when its person's access is removed."""
from __future__ import annotations

import json
import sqlite3
import time

import pytest

pytest.importorskip("starlette")
from starlette.testclient import TestClient  # noqa: E402

from kratos import authz, kratos_config  # noqa: E402
from kratos.authz import audit as AU  # noqa: E402
from kratos.authz import openwebui as OW  # noqa: E402
from kratos.authz import users as U  # noqa: E402
from kratos.serve import auth  # noqa: E402
from kratos.serve.app import create_app  # noqa: E402

M1, M2, M3 = "192.0.2.10", "192.0.2.11", "192.0.2.12"
BASE = "http://127.0.0.1:8765"
OWNER = authz.owner_actor("cli")


def _answer(text="Kratos found nothing serious."):
    return {"status": "final_answer", "final_answer": text, "answer_parts": {"block": "", "notes": "",
                                                                              "analysis": text},
            "recommended_commands": [], "transcript": [], "token_usage": {}, "run_id": "r" * 32}


@pytest.fixture
def env(tmp_path, monkeypatch):
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target(M1)
    from kratos.tui_mk2 import command_intent as _ci

    def route(message, context="", *, capture_stderr=True):
        if message.lower().startswith("hello"):
            return _ci.RouteResult(kind="chat", reply="Hi.")
        return _ci.RouteResult(kind="investigate")

    monkeypatch.setattr("kratos.tui_mk2.command_intent.route_message", route)
    state = {"step": None, "agents": []}

    def fake_agent(goal, data_dir, max_iters=10, on_step=None, *, should_stop=None, **kw):
        state["agents"].append({"goal": goal, "actor": authz.current_actor(),
                                "target": kratos_config.get_active_target()})
        if state["step"]:
            state["step"]()
        return _answer()

    monkeypatch.setattr("kratos.agent.loop.run_agent", fake_agent)
    U.add_user(tmp_path, "vic", "viewer", OWNER, scopes=[M1])
    U.add_user(tmp_path, "ivy", "investigator", OWNER, scopes=[M1, M2])
    tok = {}
    for name in ("vic", "ivy"):
        tok[name], _ = auth.create_token(tmp_path, name=f"{name}-t", user=name, mcp=True)
    tok["owner"], _ = auth.create_token(tmp_path, name="own", targets=[M1, M2, M3], mcp=True)
    gw, gw_row = auth.create_token(tmp_path, name="owui-gw", gateway=True)
    secret = "s" * 43
    OW.write_secret(tmp_path, gw_row["token_id"], secret)
    U.map_gateway(tmp_path, "openwebui", "owui-vic", "vic", OWNER, email="vic@example.com")
    U.map_gateway(tmp_path, "openwebui", "owui-ivy", "ivy", OWNER, email="ivy@example.com")
    app = create_app(tmp_path, port=8765)
    with TestClient(app, base_url=BASE) as client:
        yield {"client": client, "tok": tok, "gw": gw, "secret": secret, "dir": tmp_path, "state": state}


def _jwt(env, sub, *, secret=None, exp_in=300, iat_shift=0, iss="open-webui"):
    now = int(time.time()) + iat_shift
    return OW.mint_for_tests({"sub": sub, "email": f"{sub}@example.com", "name": sub, "role": "user", "iss": iss,
                              "iat": now, "exp": now + exp_in}, secret or env["secret"])


def _h(token, jwt=None, extra=None):
    h = {"Authorization": f"Bearer {token}"}
    if jwt:
        h["X-OpenWebUI-User-Jwt"] = jwt
    return {**h, **(extra or {})}


def _models(env, headers):
    r = env["client"].get("/v1/models", headers=headers)
    return r.status_code, ([m["id"] for m in r.json().get("data", [])] if r.status_code == 200 else r.json())


def _chat(env, headers, content, model=f"kratos/{M1}"):
    r = env["client"].post("/v1/chat/completions", headers=headers,
                           json={"model": model, "messages": [{"role": "user", "content": content}]})
    return r.status_code, (r.json()["choices"][0]["message"]["content"] if r.status_code == 200 else r.json())


def _mcp(env, headers, name, args):
    r = env["client"].post("/mcp", headers={**headers, "Accept": "application/json, text/event-stream",
                                             "Content-Type": "application/json", "MCP-Protocol-Version": "2025-11-25"},
                           json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                 "params": {"name": name, "arguments": args}})
    res = r.json()["result"]
    if res.get("isError"):
        return {"error": res["content"][0]["text"]}
    out = res.get("structuredContent") or json.loads(res["content"][0]["text"])
    return out["result"] if isinstance(out, dict) and set(out) == {"result"} else out


# --- person tokens ------------------------------------------------------------------
def test_a_viewer_sees_only_their_machines_and_cannot_investigate(env):
    code, models = _models(env, _h(env["tok"]["vic"]))
    assert code == 200 and models == ["kratos", f"kratos/{M1}"]
    code, text = _chat(env, _h(env["tok"]["vic"]), "check this machine for anything suspicious")
    assert code == 200 and "viewers can't start investigations" in text and "investigator access" in text
    assert env["state"]["agents"] == []
    code, _ = _chat(env, _h(env["tok"]["vic"]), "hi", model=f"kratos/{M2}")
    assert code == 404                                            # M2 doesn't exist for vic
    code, text = _chat(env, _h(env["tok"]["vic"]), "/findings")
    assert code == 200 and "findings" in text.lower()


def test_an_investigator_investigates_as_themselves(env):
    code, text = _chat(env, _h(env["tok"]["ivy"]), "anyone logging in?", model=f"kratos/{M2}")
    assert code == 200 and "nothing serious" in text
    run = env["state"]["agents"][-1]
    assert run["actor"].user == "ivy" and run["target"] == M2
    rows = AU.query(env["dir"], action="investigate.start")
    assert rows[0]["user_name"] == "ivy" and rows[0]["result"] == "allowed" and rows[0]["machine"] == M2


def test_a_disabled_user_is_refused_at_the_door(env):
    U.set_disabled(env["dir"], "ivy", True, OWNER)
    code, body = _models(env, _h(env["tok"]["ivy"]))
    assert code == 403 and "disabled" in body["error"]["message"]
    assert AU.query(env["dir"], result="refused")[0]["reason"].startswith("your Kratos account is disabled")


def test_an_expired_token_is_refused_with_its_date(env):
    row = next(t for t in auth._store.list_tokens(env["dir"]) if t["name"] == "ivy-t")
    with sqlite3.connect(env["dir"] / "kratos.db") as c:
        c.execute("UPDATE serve_tokens SET expires_at = ? WHERE token_id = ?", (time.time() - 5, row["token_id"]))
    r = env["client"].get("/v1/models", headers=_h(env["tok"]["ivy"]))
    assert r.status_code == 401 and "expired on" in r.json()["error"]["message"]


def test_unsigned_forwarded_headers_change_nothing(env):
    spoof = {"X-OpenWebUI-User-Id": "owui-ivy", "X-OpenWebUI-User-Email": "ivy@example.com"}
    code, text = _chat(env, _h(env["tok"]["vic"], extra=spoof), "check this machine")
    assert code == 200 and "viewers can't" in text             # still vic
    assert _models(env, _h(env["gw"], extra=spoof)) == (200, ["kratos-no-access"])   # gateway + plain headers
    code, body = _chat(env, _h(env["gw"], extra=spoof), "hello")
    assert code == 403 and "signed identity" in body["error"]["message"]


# --- the shared Open WebUI ------------------------------------------------------------
def test_a_mapped_open_webui_user_gets_exactly_their_scope(env):
    code, models = _models(env, _h(env["gw"], _jwt(env, "owui-ivy")))
    assert code == 200 and models == ["kratos", f"kratos/{M1}", f"kratos/{M2}"]
    code, models = _models(env, _h(env["gw"], _jwt(env, "owui-vic")))
    assert models == ["kratos", f"kratos/{M1}"]
    code, text = _chat(env, _h(env["gw"], _jwt(env, "owui-ivy")), "anyone logging in?", model=f"kratos/{M2}")
    assert code == 200 and env["state"]["agents"][-1]["actor"].user == "ivy"
    row = AU.query(env["dir"], action="investigate.start")[0]
    assert row["credential"].startswith("gateway:") and row["credential"].endswith("+openwebui:owui-ivy")


@pytest.mark.parametrize("why, make", [
    ("wrong secret", lambda env: _jwt(env, "owui-ivy", secret="x" * 43)),
    ("expired", lambda env: _jwt(env, "owui-ivy", exp_in=10, iat_shift=-400)),
    ("too long-lived", lambda env: _jwt(env, "owui-ivy", exp_in=86400)),
    ("other issuer", lambda env: _jwt(env, "owui-ivy", iss="someone-else")),
    ("unmapped", lambda env: _jwt(env, "owui-stranger")),
    ("none", lambda env: None),
    ("alg none", lambda env: _jwt(env, "owui-ivy").split(".")[0][:0] + "eyJhbGciOiJub25lIn0."
     + _jwt(env, "owui-ivy").split(".")[1] + "."),
])
def test_a_gateway_request_without_a_valid_mapped_jwt_is_refused(env, why, make):
    # the model list: one placeholder (a shared Open WebUI would otherwise show another person's list)
    assert _models(env, _h(env["gw"], make(env))) == (200, ["kratos-no-access"]), why
    code, body = _chat(env, _h(env["gw"], make(env)), "hello", model="kratos-no-access")
    assert code == 403, why
    if why == "unmapped":
        assert "ask the Kratos owner to add you" in body["error"]["message"]
    assert AU.query(env["dir"], result="refused")[0]["credential"].startswith("gateway:")


def test_gateway_users_have_their_own_sessions_and_hourly_limits(env):
    from kratos import settings_store
    from kratos.serve import settings as SS

    with authz.acting_as(OWNER):
        settings_store.set(SS.REQUESTS_PER_HOUR, 1, data_dir=env["dir"], actor="test")
    hdr = {"X-OpenWebUI-Chat-Id": "chat-1"}
    assert _chat(env, _h(env["gw"], _jwt(env, "owui-ivy"), hdr), "hello")[0] == 200
    code, _ = _chat(env, _h(env["gw"], _jwt(env, "owui-ivy"), hdr), "hello")
    assert code == 429                                            # ivy used her hour...
    assert _chat(env, _h(env["gw"], _jwt(env, "owui-vic"), hdr), "hello")[0] == 200   # ...vic didn't
    from kratos.storage.session_store import SessionStore

    owners = {s["owner_user_id"] for s in SessionStore(env["dir"] / "kratos.db").list_recent_sessions(limit=50)}
    assert owners == {U.find(env["dir"], "ivy").user_id, U.find(env["dir"], "vic").user_id}


def test_removing_the_jwt_secret_refuses_every_gateway_request(env):
    row = next(t for t in auth._store.list_tokens(env["dir"]) if t["kind"] == "gateway")
    OW.secret_path(env["dir"], row["token_id"]).unlink()
    assert _models(env, _h(env["gw"], _jwt(env, "owui-ivy"))) == (200, ["kratos-no-access"])
    assert _chat(env, _h(env["gw"], _jwt(env, "owui-ivy")), "hello")[0] == 403


# --- MCP over HTTP ----------------------------------------------------------------------
def test_mcp_viewer_cannot_start_and_sees_only_their_sessions(env):
    out = _mcp(env, _h(env["tok"]["vic"]), "kratos_start_investigation", {"goal": "x", "target": M1})
    assert "viewers can't start investigations" in out["error"]
    _mcp(env, _h(env["tok"]["ivy"]), "kratos_start_investigation", {"goal": "x", "target": M1, "wait_seconds": 5})
    assert _mcp(env, _h(env["tok"]["vic"]), "kratos_list_sessions", {}) == []
    mine = _mcp(env, _h(env["tok"]["ivy"]), "kratos_list_sessions", {})
    assert len(mine) == 1
    out = _mcp(env, _h(env["tok"]["vic"]), "kratos_finding_states", {"target": M2})
    assert "error" in out                                          # not visible to vic


def test_mcp_investigation_stops_at_its_next_read_when_scope_is_narrowed(env):
    from kratos.agent import loop as L
    from kratos.agent.tools import TOOL_REGISTRY, Tool

    TOOL_REGISTRY["authz_probe"] = Tool(name="authz_probe", description="x", parameters={},
                                        handler=lambda: {"ok": 1})

    def step():
        L.execute_tool_call("authz_probe", {}, env["dir"])
        U.set_scopes(env["dir"], "ivy", [M1], OWNER)                # the owner narrows ivy now
        L.execute_tool_call("authz_probe", {}, env["dir"])           # next read

    env["state"]["step"] = step
    try:
        out = _mcp(env, _h(env["tok"]["ivy"]), "kratos_start_investigation",
                   {"goal": "x", "target": M2, "wait_seconds": 10})
    finally:
        TOOL_REGISTRY.pop("authz_probe", None)
    assert out["status"] == "stopped"
    assert f"stopped: your access to {M2} was removed" in out["final_answer"]


# --- chat decisions ---------------------------------------------------------------------
def _seed_finding(dd, target):
    import uuid

    from kratos.lifecycle import apply as A
    from kratos.lifecycle.coverage import nothing
    from kratos.lifecycle.keys import finding_key
    from kratos.run_context import RunContext

    r = RunContext(run_id=uuid.uuid4().hex, source="cli", target=target, session_id=None, started_at=time.time())
    A.apply_run([{"id": "NET-002", "title": "t", "severity": "medium", "entities": ["22/tcp"]}],
                target=target, coverage=nothing(), run=r, data_dir=dd)
    return finding_key("NET-002", target, "")


def test_investigators_decide_findings_in_the_chat_and_viewers_cannot(env):
    key = _seed_finding(env["dir"], M1)
    code, text = _chat(env, _h(env["tok"]["vic"]), f"/decide {key[:12]} false-positive lab noise")
    assert "Not recorded" in text and "viewers can't decide" in text
    code, text = _chat(env, _h(env["tok"]["ivy"]), f"/decide {key[:12]} false-positive lab noise")
    assert "Recorded" in text and "(by ivy)" in text
    from kratos.lifecycle import store as S

    with S.opened(env["dir"]) as conn:
        ev = conn.execute("SELECT actor, interface FROM finding_events WHERE kind = 'state_changed' "
                          "ORDER BY rowid DESC LIMIT 1").fetchone()
    assert tuple(ev) == ("ivy", "serve")


def test_a_group_model_chat_reaches_the_fleet_run_as_the_person(env, monkeypatch):
    """Regression (lab): the door checked "@lab" as if it were a machine and refused every group chat."""
    from kratos.fleet import groups as G
    from kratos.fleet import run as FR

    G.create_group(env["dir"], "lab", OWNER, members=[M1, M2, M3])
    seen = {}

    def fake_run(req):
        seen.update(actor=req.actor, scope=req.scope)
        return FR.FleetOutcome("final_answer", "summary", group_label="@lab")

    monkeypatch.setattr(FR, "run_fleet", fake_run)
    code, models = _models(env, _h(env["tok"]["ivy"]))
    assert "kratos/@lab" in models
    assert "kratos/@lab" not in _models(env, _h(env["tok"]["vic"]))[1]      # viewers: no group models
    code, text = _chat(env, _h(env["tok"]["ivy"]), "who gained sudo?", model="kratos/@lab")
    assert code == 200 and seen["actor"].user == "ivy" and seen["scope"] == [M1, M2]


def test_a_refusal_by_the_doors_own_lookup_is_recorded_too(env):
    _chat(env, _h(env["tok"]["vic"]), "hi", model=f"kratos/{M2}")
    _mcp(env, _h(env["tok"]["ivy"]), "kratos_start_investigation", {"goal": "x", "target": M3})
    _mcp(env, _h(env["tok"]["ivy"]), "kratos_hunt", {"indicators": "198.51.100.7", "machine": M3})
    rows = AU.query(env["dir"], result="refused")
    who = [(r["user_name"], r["action"]) for r in rows]
    assert ("vic", "read") in who and ("ivy", "read") in who and ("ivy", "hunt") in who


@pytest.mark.parametrize("claim", [{"exp": float("nan")}, {"iat": float("nan")}, {"exp": float("inf")},
                                   {"exp": True}])
def test_a_forwarded_identity_with_a_non_number_time_is_refused(claim):
    """Audit D: NaN compares false with everything, so an `exp` of NaN passed every time check
    (only a holder of the shared secret could sign one -- defence in depth)."""
    now = int(time.time())
    claims = {"sub": "vic", "iss": "open-webui", "iat": now, "exp": now + 300, **claim}
    with pytest.raises(OW.JWTError, match="no valid time"):
        OW.verify(OW.mint_for_tests(claims, "s" * 43), "s" * 43)


# --- E.2: compliance reports through the chat and MCP doors (read-only, scoped) -------
def _seed_compliance(d):
    import copy

    from kratos.compliance import record
    from tests.test_compliance import good_hardening

    h = good_hardening()
    bad = copy.deepcopy(h)
    bad["stat"]["/etc/crontab"]["mode"] = 0o666
    record.run(d, M1, fetch=lambda: dict(bad, via="ssh"), now=time.time())
    record.run(d, M2, fetch=lambda: dict(bad, via="ssh"), now=time.time())


def test_a_viewer_reads_compliance_for_their_machine_only(env):
    _seed_compliance(env["dir"])
    code, text = _chat(env, _h(env["tok"]["vic"]), "/compliance iso27001")
    assert code == 200 and M1 in text and M2 not in text and "not a certification" in text
    assert "8.3" in text and "fail" in text
    out = _mcp(env, _h(env["tok"]["vic"]), "kratos_compliance", {"framework": "cis", "target": M1})
    assert out["machines"][0]["machine"] == M1
    assert any(c["control"] == "2.4.1.2" and c["status"] == "fail" for c in out["machines"][0]["controls"])
    refused = _mcp(env, _h(env["tok"]["vic"]), "kratos_compliance", {"target": M2})
    assert "error" in refused
    every = _mcp(env, _h(env["tok"]["vic"]), "kratos_compliance", {"framework": "nis2"})
    assert [m["machine"] for m in every["machines"]] == [M1]


def test_compliance_decisions_have_no_network_door(env):
    names = [t["name"] for t in env["client"].post(
        "/mcp", headers={**_h(env["tok"]["owner"]), "Accept": "application/json, text/event-stream",
                         "Content-Type": "application/json", "MCP-Protocol-Version": "2025-11-25"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).json()["result"]["tools"]]
    assert "kratos_compliance" in names and not [n for n in names if "owner" in n or "na_" in n]
    from kratos.compliance import owners as O
    from kratos.lifecycle.decide import Actor

    with pytest.raises(O.ComplianceError):
        O.set_owner(env["dir"], Actor("ivy", "serve", user_id="ivy", credential="token:x"), "iso27001", "8.9",
                    "all", "ivy")
