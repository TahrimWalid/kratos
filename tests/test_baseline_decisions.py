"""E.3 people's decisions, scope and the never-lowers rule (spec §3.7, §3.8, §3.10, §8)."""
from __future__ import annotations

import ast
import inspect
import json
import sqlite3
from pathlib import Path

import pytest

from _baseline_history import END, add_logins, machine, normal_days, raised, run, write
from kratos.baseline import decide as BD
from kratos.lifecycle.decide import Actor

OWNER = Actor("owner", "cli", user_id="owner")


def _ready(tmp_path, plants=()):
    m = machine(0)
    normal_days(m)
    for p in plants:
        m.plant(p, END)
    return m, write(tmp_path / "home", [m])


def _findings(data: Path, target: str) -> list[dict]:
    """The findings report for this machine: correlation over its snapshots, lifecycle applied."""
    import kratos.collect.checks  # noqa: F401
    from kratos import kratos_config
    from kratos.adapters import findings_engine as FE

    with kratos_config.pinned_target(target):
        path, _md = FE.write_findings_report(data)
    return json.loads(Path(path).read_text()).get("findings") or []


# ---------------------------------------------------------------- people only
def test_decisions_people_only(tmp_path):
    from kratos import settings_store

    m, data = _ready(tmp_path, ("new_source",))
    run(data, m.target)
    for actor in (Actor("bot", "mcp"), Actor("bot", "serve", credential="token:x"), Actor("s", "schedule")):
        with pytest.raises(BD.BaselineError):
            BD.accept(data, m.target, "login_source", "deploy", "192.0.2.0/24", actor=actor)
        with pytest.raises(BD.BaselineError):
            BD.freeze(data, m.target, actor=actor)
        with pytest.raises(BD.BaselineError):
            BD.reset(data, m.target, actor=actor)
        with pytest.raises(BD.BaselineError):
            BD.forget(data, m.target, "login_source", "deploy", "10.20.0.0/24", actor=actor)
    token = settings_store._IN_TOOL.set("correlate_findings")
    try:
        with pytest.raises(BD.BaselineError, match="agent tools"):
            BD.accept(data, m.target, "login_source", "deploy", "192.0.2.0/24", actor=OWNER)
    finally:
        settings_store._IN_TOOL.reset(token)
    con = sqlite3.connect(data / "kratos.db")
    assert con.execute("SELECT COUNT(*) FROM baseline_decisions").fetchone()[0] == 0


def _refs(source: str) -> list[str]:
    hits = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("kratos.baseline"):
            names = {a.name for a in node.names}
            if node.module == "kratos.baseline.decide" or "decide" in names:
                hits.append(f"line {node.lineno}")
        elif isinstance(node, ast.Import) and any(a.name == "kratos.baseline.decide" for a in node.names):
            hits.append(f"line {node.lineno}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and "baseline.decide" in node.value:
            hits.append(f"line {node.lineno}")
    return hits


def test_no_tool_mcp_or_chat_module_reaches_baseline_decisions():
    import kratos.mcp_server as mcp_server
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos.serve import mcp_http, openai_routes

    files = {inspect.getsourcefile(t.handler) for t in TOOL_REGISTRY.values()}
    files |= {inspect.getsourcefile(mcp_server), inspect.getsourcefile(mcp_http), inspect.getsourcefile(openai_routes)}
    offenders = {f: h for f in files if (h := _refs(Path(f).read_text(encoding="utf-8")))}
    assert offenders == {}
    assert _refs("from kratos.baseline import decide\n") and _refs("from kratos.baseline.decide import accept\n")


def test_mcp_has_only_a_read_tool_for_baselines():
    import asyncio

    import kratos.mcp_server as mcp_server

    names = {t.name for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert "kratos_baseline" in names
    assert not [n for n in names if "baseline" in n and n != "kratos_baseline"]


# ---------------------------------------------------------------- accept, forget, freeze, reset
def test_accept_is_never_raised_again_and_marks_the_finding(tmp_path):
    m, data = _ready(tmp_path, ("new_source",))
    run(data, m.target)
    rows = _findings(data, m.target)
    base = [f for f in rows if f["id"] == "BASE-001"]
    assert base and base[0]["state"] == "open"
    res = BD.accept(data, m.target, "login_source", "deploy", "192.0.2.0/24", actor=OWNER, reason="new office VPN")
    assert res["finding"] == "false_positive"
    from kratos.lifecycle import store as LS

    with LS.opened(data) as conn:
        rec = LS.get_record(conn, res["finding_key"])
        exc = LS.applicable_exception(conn, key=res["finding_key"], rule_id="BASE-001", target=m.target,
                                      now=END.timestamp() + 1e6)
    assert rec["state"] == "false_positive" and "expected behaviour" in exc["reason"]
    con = sqlite3.connect(data / "kratos.db")
    d = con.execute("SELECT actor, interface, kind, reason FROM baseline_decisions").fetchone()
    assert d == ("owner", "cli", "accept", "new office VPN")
    # a week later the same place again: not raised
    add_logins(data, m.target, [(END.timestamp() + 7 * 86400, "deploy", "192.0.2.80", "publickey")])
    doc = run(data, m.target, now=END.timestamp() + 7 * 86400 + 60)
    assert ("BASE-001", "deploy", "192.0.2.0/24") not in raised(doc)


def test_a_false_positive_in_findings_teaches_the_baseline(tmp_path):
    m, data = _ready(tmp_path, ("listener",))
    run(data, m.target)
    rows = _findings(data, m.target)
    fk = [f for f in rows if f["id"] == "BASE-005"][0]["finding_key"]
    from kratos.lifecycle import decide as LD

    LD.mark_false_positive(fk, actor=OWNER, reason="our new service", data_dir=data)
    doc = run(data, m.target, now=END.timestamp() + 60)
    assert doc["accepted_from_findings"] == 1
    con = sqlite3.connect(data / "kratos.db")
    acc = con.execute("SELECT accepted_by FROM baseline_entries WHERE dim = 'listener' AND key = 'tcp/4444'"
                      ).fetchone()
    assert acc == ("owner",)
    kinds = [r[0] for r in con.execute("SELECT kind FROM baseline_decisions")]
    assert kinds == ["accept_from_finding"]
    run(data, m.target, now=END.timestamp() + 120)            # absorbed once only
    assert [r[0] for r in con.execute("SELECT kind FROM baseline_decisions")] == ["accept_from_finding"]


def test_forget_makes_it_new_again(tmp_path):
    m, data = _ready(tmp_path)
    run(data, m.target)
    BD.forget(data, m.target, "login_source", "deploy", "10.20.0.0/24", actor=OWNER)
    add_logins(data, m.target, [(END.timestamp() + 600, "deploy", "10.20.0.9", "publickey")])
    doc = run(data, m.target, now=END.timestamp() + 900)
    assert ("BASE-001", "deploy", "10.20.0.0/24") in raised(doc)
    con = sqlite3.connect(data / "kratos.db")
    assert con.execute("SELECT kind FROM baseline_decisions").fetchone() == ("forget",)


def test_freeze_reset(tmp_path):
    m, data = _ready(tmp_path)
    run(data, m.target)
    BD.freeze(data, m.target, actor=OWNER, reason="incident 42")
    add_logins(data, m.target, [(END.timestamp() + 600, "deploy", "192.0.2.10", "publickey")])
    doc = run(data, m.target, now=END.timestamp() + 900)
    assert ("BASE-001", "deploy", "192.0.2.0/24") in raised(doc)       # frozen: still raised
    con = sqlite3.connect(data / "kratos.db")
    assert con.execute("SELECT COUNT(*) FROM baseline_entries WHERE key = '192.0.2.0/24'").fetchone()[0] == 0
    BD.unfreeze(data, m.target, actor=OWNER)
    BD.reset(data, m.target, actor=OWNER, reason="rebuilt after incident 42")
    doc = run(data, m.target, now=END.timestamp() + 1800)
    assert all(s["status"] in ("learning", "not_learnable") for s in doc["dims"].values())
    assert {s["generation"] for n, s in doc["dims"].items()} == {2}
    old = con.execute("SELECT COUNT(*) FROM baseline_entries WHERE generation = 1").fetchone()[0]
    assert old > 0                                                      # the old profile is kept
    kinds = [r[0] for r in con.execute("SELECT kind FROM baseline_decisions ORDER BY id")]
    assert kinds == ["freeze", "unfreeze", "reset"]
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("DELETE FROM baseline_decisions")
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("UPDATE baseline_decisions SET actor = 'x'")


def test_unknown_kind_and_empty_key_are_refused(tmp_path):
    m, data = _ready(tmp_path)
    run(data, m.target)
    with pytest.raises(BD.BaselineError):
        BD.accept(data, m.target, "dns", "deploy", "x", actor=OWNER)
    with pytest.raises(BD.BaselineError):
        BD.accept(data, m.target, "login_source", "", "", actor=OWNER)
    with pytest.raises(BD.BaselineError):
        BD.accept(data, m.target, "login_source", "deploy", "x", actor=OWNER, reason="bad\x1b[31m")


# ---------------------------------------------------------------- never lowers other rules
def _non_base_rules():
    from kratos.lifecycle.rules import RULES

    return sorted(r for r in RULES if not r.startswith("BASE-"))


@pytest.mark.parametrize("rule_id", _non_base_rules())
def test_baseline_never_lowers_other_rules(rule_id):
    """No baseline state can close, lower or decide another rule's finding: a baseline run is
    never a covering input of a non-BASE rule, so its completeness never marks one mitigated
    or inactive, and nothing in kratos.baseline writes another rule's severity."""
    from kratos.lifecycle.rules import RULES

    info = RULES[rule_id]
    assert "baseline" not in info.inputs and "baseline" not in info.covering_inputs


def test_baseline_findings_only_carry_base_ids(tmp_path):
    m, data = _ready(tmp_path, ("new_source", "listener"))
    doc = run(data, m.target)
    from kratos.baseline import findings

    assert {f.id[:5] for f in findings.build(doc)} == {"BASE-"}


def test_a_baseline_beside_a_serious_finding_changes_nothing_about_it(tmp_path):
    """End to end: CORR-SSH-002 (critical) on the same machine is unchanged by a baseline that
    knows the address, accepts it as normal, or is frozen."""
    m, data = _ready(tmp_path, ("new_source",))
    out = data / "sshguess"
    out.mkdir(parents=True, exist_ok=True)
    import hashlib
    import time

    hit = {"ip": "192.0.2.77", "user": "deploy", "login_ts": END.timestamp() - 3600, "method": "password",
           "failures": 9, "first_failure_ts": END.timestamp() - 7200, "last_failure_ts": END.timestamp() - 3700,
           "users_tried": ["deploy"], "login_event_id": "x", "severity": "critical"}
    (out / f"sshguess_{hashlib.sha256(m.target.encode()).hexdigest()[:8]}.json").write_text(json.dumps(
        {"target": m.target, "checked_at_epoch": time.time(), "complete": True, "coverage_gaps": [], "hits": [hit]}))

    def ssh002():
        return [(f["severity"], f["state"]) for f in _findings(data, m.target) if f["id"] == "CORR-SSH-002"]

    before = ssh002()
    assert before == [("critical", "open")]
    run(data, m.target, now=time.time())
    assert ssh002() == before
    BD.accept(data, m.target, "login_source", "deploy", "192.0.2.0/24", actor=OWNER)
    BD.freeze(data, m.target, actor=OWNER)
    run(data, m.target, now=time.time() + 60)
    assert ssh002() == before


# ---------------------------------------------------------------- scope and group context
def test_group_context_never_suppresses(tmp_path):
    from kratos.fleet import groups as G

    a, b = machine(0, target="10.200.0.41"), machine(1, target="10.200.0.42")
    normal_days(a)
    normal_days(b)
    # deploy normally signs in on b from 192.0.2.0/24 ...
    b.logins = [(ts, u, "192.0.2.15" if u == "deploy" else ip, meth) for ts, u, ip, meth in b.logins]
    a.logins.append((END.timestamp() - 3600, "deploy", "192.0.2.15", "publickey"))   # ... first time on a
    data = write(tmp_path / "home", [a, b])
    G.create_group(data, "lab", OWNER, members=[a.target, b.target])
    run(data, b.target)
    doc = run(data, a.target)
    d = [d for d in doc["deviations"] if d["rule"] == "BASE-001" and d["subject"] == "deploy"]
    assert d, "a key normal elsewhere in the group is still raised here"
    assert d[0]["severity"] == "low" and d[0]["detail"]["usual_elsewhere"] == {"group": "lab", "machines": 1}
    from kratos.baseline import findings, present

    f = [f for f in findings.build(doc) if f.id == "BASE-001"][0]
    text = " ".join(f.evidence)
    assert "first time HERE" in text and b.target not in text            # the finding never names the machine
    owner_view = present.view(data, a.target, scope=None)
    mine = [x for x in owner_view["deviations"] if x["rule"] == "BASE-001" and x["subject"] == "deploy"][0]
    assert mine["usual_on"] == {"machines": [b.target], "outside_your_access": 0}
    from kratos.authz.scope import Scope

    narrow = present.view(data, a.target, scope=Scope(names=(a.target,)))
    u = [x for x in narrow["deviations"] if x["rule"] == "BASE-001" and x["subject"] == "deploy"][0]["usual_on"]
    assert u == {"machines": [], "outside_your_access": 1}
    assert "outside your access" in present.to_text(narrow) and b.target not in present.to_text(narrow)


def test_a_viewer_reads_only_machines_in_scope(tmp_path):
    from kratos.authz import users
    from kratos.baseline import present

    m, data = _ready(tmp_path)
    run(data, m.target)
    from kratos.serve import auth

    vic = users.add_user(data, "vic", "viewer", OWNER, scopes=[m.target])
    _token, row = auth.create_token(data, name="vic-t", user="vic", targets=[m.target], mcp=True)
    viewer = Actor("vic", "serve", user_id=vic.user_id, credential=f"token:{row['token_id']}")
    tk, scope = present.resolve(data, viewer, m.target)
    assert tk == m.target and scope.allows(m.target) and not scope.allows("10.9.9.9")
    with pytest.raises(present.ViewError):
        present.resolve(data, viewer, "10.9.9.9")
    with pytest.raises(BD.BaselineError):
        BD.accept(data, m.target, "login_source", "deploy", "10.20.0.0/24", actor=viewer)


def test_forget_reopens_an_accepted_finding_and_raises_again_despite_the_cooldown(tmp_path):
    m, data = _ready(tmp_path, ("new_source",))
    run(data, m.target, now=END.timestamp())
    _findings(data, m.target)
    res = BD.accept(data, m.target, "login_source", "deploy", "192.0.2.0/24", actor=OWNER)
    assert res["finding"] == "false_positive"
    out = BD.forget(data, m.target, "login_source", "deploy", "192.0.2.0/24", actor=OWNER, reason="test")
    assert out["finding"] == "reopened"
    add_logins(data, m.target, [(END.timestamp() + 300, "deploy", "192.0.2.78", "publickey")])
    doc = run(data, m.target, now=END.timestamp() + 600)          # well inside the 24 h cooldown
    again = [d for d in doc["deviations"] if d["rule"] == "BASE-001" and d["raised_at"] == END.timestamp() + 600]
    assert again and again[0]["key"] == "192.0.2.0/24"
    rows = _findings(data, m.target)
    assert [f["state"] for f in rows if f["id"] == "BASE-001"] == ["open"]
