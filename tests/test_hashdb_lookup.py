"""E.4 §3.10: a hash leaves this computer only when a person at the Kratos computer asks,
with `hashdb.online` on, after a plain yes -- never from a model tool, MCP, the chat
server or a schedule; and a reputation check sends nothing anywhere."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from kratos import settings_store
from kratos.hashdb import lookup as L
from kratos.hashdb import record

SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"
SHA = hashlib.sha256(b"kratos-test-lookup").hexdigest()


class Spy:
    def __init__(self):
        self.calls = []

    def get(self, *a, **k):
        self.calls.append(("GET", a, k))
        raise AssertionError("nothing may be sent")

    post = head = get


def _on(tmp_path):
    from kratos.hashdb import settings as S

    settings_store.set(S.ONLINE, "on", data_dir=tmp_path, actor="test")


def test_online_off_sends_nothing(tmp_path):
    spy = Spy()
    with pytest.raises(L.LookupRefused, match="online lookups are off"):
        L.online(tmp_path, SHA, confirm=lambda q: True, session=spy)
    assert not spy.calls


def test_a_no_sends_nothing(tmp_path):
    _on(tmp_path)
    spy, asked = Spy(), []
    with pytest.raises(L.LookupRefused, match="not sent"):
        L.online(tmp_path, SHA, confirm=lambda q: asked.append(q) or False, session=spy)
    assert not spy.calls and "This sends the hash" in asked[0] and "circl.lu" in asked[0]


@pytest.mark.parametrize("interface", ["mcp", "schedule", "web"])
def test_online_lookup_unreachable_from_doors_at_runtime(tmp_path, interface, monkeypatch):
    from kratos.authz import check

    _on(tmp_path)
    spy = Spy()
    if interface == "web":            # the chat server's process: no actor is ever the owner
        monkeypatch.setattr(check, "_network_process", True)
        actor = None
    else:
        actor = check.owner_actor(interface)
    with pytest.raises(L.LookupRefused, match="a person's action at the Kratos computer"):
        L.online(tmp_path, SHA, confirm=lambda q: True, session=spy, actor=actor)
    assert not spy.calls


def test_online_lookup_refused_inside_an_agent_tool(tmp_path):
    from kratos.authz import check

    _on(tmp_path)
    spy = Spy()
    with settings_store.tool_call_scope("run_linux_command"):
        with pytest.raises(L.LookupRefused):
            L.online(tmp_path, SHA, confirm=lambda q: True, session=spy, actor=check.owner_actor("tui"))
    assert not spy.calls


def test_online_lookup_unreachable_from_doors_by_source_scan():
    """No module behind a door (model tools, MCP, the chat server, schedules, triggers, the
    agent loop) may import the online lookup."""
    doors = ["agent/tools.py", "agent/loop.py", "mcp_server.py", "agent/scheduled_run.py", "agent/triggers.py",
             "agent/trigger_eval.py"] + [str(p.relative_to(SRC)) for p in (SRC / "serve").rglob("*.py")]
    pat = re.compile(r"hashdb\.lookup|hashdb import lookup|lookup\.online|\bonline\(")
    hits = {d: pat.findall((SRC / d).read_text()) for d in doors if (SRC / d).exists()}
    assert not {d: h for d, h in hits.items() if h}, hits
    assert not any("hash" in name for name in __import__("kratos.agent.tools", fromlist=["TOOL_REGISTRY"])
                   .TOOL_REGISTRY), "Phase E adds no model tool"


def test_a_person_at_the_cli_can_look_up_with_consent(tmp_path):
    from kratos.authz import check
    from kratos.hashdb import store

    _on(tmp_path)

    class Resp:
        def __init__(self, status, body):
            self.status_code, self._b = status, body

        def json(self):
            return self._b

    class Sess:
        def __init__(self):
            self.urls = []

        def get(self, url, **k):
            self.urls.append(url)
            return Resp(200, {"hashlookup:trust": 90, "source": ["NSRL"], "FileName": "x"})

    s = Sess()
    out = L.online(tmp_path, SHA, confirm=lambda q: True, session=s, actor=check.owner_actor("cli"))
    assert s.urls == [f"https://hashlookup.circl.lu/lookup/sha256/{SHA}"]
    assert out["verdict"] == "known_good" and out["circl"]["trust"] == 90
    row = [r for r in store.lookup(tmp_path, SHA) if r["target_key"] == ""][0]
    assert row["sources"][0]["source"] == "online" and row["sources"][0]["date"]


def test_a_reputation_check_sends_nothing_anywhere(tmp_path, monkeypatch):
    """The capture test: a whole check with every outbound HTTP call failing loudly."""
    import requests

    def boom(*a, **k):
        raise AssertionError("a reputation check sent something")

    monkeypatch.setattr(requests.Session, "request", boom)
    monkeypatch.setattr(requests, "get", boom)
    monkeypatch.setattr(requests, "post", boom)
    docs = {"persistence": {"hash_candidates": [{"path": "/tmp/x", "uses": ["u"]}]}, "live_response": None}
    doc = record.run(tmp_path, "m", docs=docs, fetch=lambda paths, **k: {
        "complete": True, "via": "ssh", "files": {0: {"status": "ok", "sha256": SHA, "sha1": "a" * 40}}})
    assert doc["status"] == "ok"


def test_offline_lookup(tmp_path):
    info = L.offline(tmp_path, SHA)
    assert info["kind"] == "sha256" and not info["malwarebazaar_installed"] and not info["machines"]
    with pytest.raises(ValueError):
        L.offline(tmp_path, "d41d8cd98f00b204e9800998ecf8427e")       # MD5 is not looked up
