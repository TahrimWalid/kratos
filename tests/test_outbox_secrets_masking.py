"""D.4: secrets never in the database, the run records, the logs, /doctor or the CLI's
listings; secrets inside a payload are removed before it is stored; per-channel masking
replaces values and never restores them; channel edits are people-only; alert filters."""
from __future__ import annotations

import json
import logging

import pytest

from kratos import kratos_config as kc
from kratos import settings_store
from kratos.lifecycle.decide import Actor
from kratos.outbox import alerts as A
from kratos.outbox import config as C
from kratos.outbox import store as S
from kratos.outbox import worker as W
from kratos.outbox.store import Outcome

ACTOR = Actor(user="tester", interface="cli")


@pytest.fixture
def dd(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "NTFY_TOPIC", None)
    return tmp_path


def _all_rows(dd) -> str:
    with S.opened(dd) as conn:
        return "\n".join(str(tuple(r)) for t in ("outbox", "outbox_attempts", "channels", "channel_events",
                                                  "forward_cursors")
                         for r in conn.execute(f"SELECT * FROM {t}"))


def test_channel_secrets_live_outside_the_database_owner_only(dd):
    pw = "pw-" + "x" * 20                      # built at test time, never a real secret
    auth = "Bearer " + "t" * 30
    C.add_channel(dd, name="mail", kind="email", config={"host": "mail.example", "from": "k@example.com",
                                                         "to": "o@example.com", "username": "kratos"},
                  scopes=["alerts"], secrets={"password": pw}, actor=ACTOR)
    sec = C.new_webhook_secret()
    C.add_channel(dd, name="soc", kind="webhook", config={"url": "https://soc.example/in", "auth_header":
                                                          "Authorization"},
                  scopes=["alerts"], secrets={"signing_secret": sec, "auth_value": auth}, actor=ACTOR)
    dump = _all_rows(dd)
    for v in (pw, auth, sec, sec[6:]):
        assert v not in dump
    folder = C.secrets_dir(dd)
    assert oct(folder.stat().st_mode & 0o777) == "0o700"
    for f in folder.iterdir():
        assert oct(f.stat().st_mode & 0o777) == "0o600"
    assert C.read_secrets(dd, "soc") == {"signing_secret": sec, "auth_value": auth}


def test_secrets_never_reach_doctor_logs_or_listings(dd, monkeypatch, caplog, capsys):
    sec = C.new_webhook_secret()
    C.add_channel(dd, name="soc", kind="webhook", config={"url": "https://soc.example/in"}, scopes=["alerts"],
                  secrets={"signing_secret": sec}, actor=ACTOR)
    monkeypatch.setattr(W, "sender_for", lambda kind: lambda d, ch, s, dd_: Outcome(False, True,
                                                                                   f"refused {s['signing_secret']}"))
    caplog.set_level(logging.DEBUG, logger="kratos")
    A.enqueue_alert("x", deliver=["soc"], data_dir=dd)
    W.flush(dd, label="t")
    from kratos.agent.doctor import run_diagnostics
    from kratos.cli import outbox_cmd

    rows = json.dumps(run_diagnostics(dd))
    import argparse

    outbox_cmd.cmd_outbox(argparse.Namespace(data_dir=dd, outbox_action="list", status=None, channel=None,
                                             limit=30, json=False))
    outbox_cmd.cmd_channels(argparse.Namespace(data_dir=dd, channels_action="show", name="soc"))
    out = capsys.readouterr().out
    # a sender that echoed its secret back still had it removed from the stored error
    for text in (rows, out, caplog.text, _all_rows(dd)):
        assert sec not in text and sec[6:] not in text


def test_secrets_inside_a_payload_are_removed_before_it_is_stored(dd):
    C.add_channel(dd, name="soc", kind="webhook", config={"url": "https://soc.example/in"}, scopes=["alerts"],
                  actor=ACTOR)
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn" + "A" * 40 + "\n-----END OPENSSH PRIVATE KEY-----"
    A.enqueue_alert(f"leaked {key} and password: hunter2-{'z' * 8}\n{pem}", deliver=["soc"], data_dir=dd)
    dump = _all_rows(dd)
    assert key not in dump and "hunter2" not in dump and "b3Blbn" not in dump and "[REDACTED]" in dump


def test_masking_replaces_values_and_the_receiver_never_gets_them_back(dd, monkeypatch):
    C.add_channel(dd, name="soc", kind="webhook", config={"url": "https://soc.example/in"}, scopes=["alerts"],
                  mask_values=True, actor=ACTOR)
    sent = []
    monkeypatch.setattr(W, "sender_for", lambda kind: lambda d, ch, s, dd_: sent.append(d.payload["body"]) or
                        Outcome(True, False))
    A.enqueue_alert("Failed password for alice from 203.0.113.9 on web-01", deliver=["soc"], data_dir=dd,
                    machine="198.51.100.7")
    W.flush(dd, label="t")
    (body,) = sent
    assert "203.0.113.9" not in body and json.loads(body)["type"] == "kratos.alert"
    assert "IP_" in body


def test_an_agent_tool_can_never_change_a_channel(dd):
    C.add_channel(dd, name="soc", kind="webhook", config={"url": "https://soc.example/in"}, scopes=["alerts"],
                  actor=ACTOR)
    with settings_store.tool_call_scope("some_tool"):
        for call in (lambda: C.set_enabled(dd, "soc", False, actor=ACTOR),
                     lambda: C.edit_channel(dd, "soc", actor=ACTOR, max_per_minute=5),
                     lambda: C.add_channel(dd, name="x", kind="webhook", config={"url": "https://x.example"},
                                           scopes=["alerts"], actor=ACTOR),
                     lambda: C.remove_channel(dd, "soc", actor=ACTOR),
                     lambda: C.set_secret(dd, "soc", "signing_secret", C.new_webhook_secret(), actor=ACTOR)):
            with pytest.raises(C.ChannelError, match="agent tools may not"):
                call()
    with pytest.raises(C.ChannelError, match="needs a person"):
        C.set_enabled(dd, "soc", False, actor=Actor(user="x", interface="schedule"))


def test_no_registered_tool_module_imports_channel_editing():
    from kratos.agent.tools import TOOL_REGISTRY
    import inspect

    for name, tool in TOOL_REGISTRY.items():
        mod = inspect.getmodule(tool.handler)
        if mod is None or not mod.__name__.startswith("kratos."):
            continue                                  # a tool another test registered
        src = inspect.getsource(mod)
        for forbidden in ("add_channel(", "edit_channel(", "remove_channel(", "set_secret(", "retry_now("):
            assert forbidden not in src, (name, forbidden)


@pytest.mark.parametrize("filters,kw,expect", [
    ({"min_severity": "high"}, {"worst": "medium"}, "filtered (below high)"),
    ({"min_severity": "high"}, {"worst": "critical"}, "queued"),
    ({"machines": ["198.51.100.7"]}, {"machine": "198.51.100.8"}, "filtered (other machines)"),
    ({"machines": ["198.51.100.7"]}, {"machine": "198.51.100.7"}, "queued"),
    ({"machines": ["198.51.100.7"]}, {}, "filtered (other machines)"),
    ({"rule_prefixes": ["PKG-"]}, {"findings": [{"id": "CORR-SSH-001"}]}, "filtered (no matching rule)"),
    ({"min_ssvc": "act"}, {"findings": [{"id": "PKG-001", "ssvc": {"outcome": "attend"}}]},
     "filtered (no decision act or above)"),
])
def test_alert_filters(dd, filters, kw, expect):
    C.add_channel(dd, name="soc", kind="webhook", config={"url": "https://soc.example/in"}, scopes=["alerts"],
                  filters=filters, actor=ACTOR)
    res = A.enqueue_alert("x", deliver=["soc"], data_dir=dd, **kw)
    assert res["channels"]["soc"] == expect


def test_notices_about_kratos_itself_ignore_filters(dd):
    C.add_channel(dd, name="soc", kind="webhook", config={"url": "https://soc.example/in"}, scopes=["alerts"],
                  filters={"min_severity": "critical", "machines": ["198.51.100.7"]}, actor=ACTOR)
    assert A.enqueue_alert("budget used up", "warning", data_dir=dd, kind="notice")["channels"]["soc"] == "queued"
