"""ntfy topic privacy: Kratos ships no default topic (one written in public source would be
readable by anyone -- ntfy topics are unauthenticated), notifications stay off until the
install sets its own, and a topic that was ever public is refused. No network: requests.post
is replaced and asserted on."""
from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest
import requests

from kratos import kratos_config as kc
from kratos.agent import notify


@pytest.fixture
def posts(monkeypatch):
    calls: list = []

    class _Resp:
        status_code = 200
        text = "ok"

    def fake_post(url, **kw):
        calls.append((url, kw))
        return _Resp()

    monkeypatch.setattr(requests, "post", fake_post)
    return calls


def _config(monkeypatch, *, topic=None, base="https://ntfy.sh", token=None):
    monkeypatch.setattr(kc, "NTFY_TOPIC", topic)
    monkeypatch.setattr(kc, "NTFY_BASE_URL", base)
    monkeypatch.setattr(kc, "NTFY_TOKEN", token)


def test_the_shipped_default_is_no_topic_at_all(monkeypatch):
    monkeypatch.delenv("KRATOS_NTFY_TOPIC", raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)  # ignore the developer's own .env
    try:
        fresh = importlib.reload(kc)
        assert fresh.NTFY_TOPIC is None
    finally:
        importlib.reload(kc)
    src = Path(kc.__file__).read_text()
    m = re.search(r'os\.environ\.get\("KRATOS_NTFY_TOPIC",\s*"([^"]*)"\)', src)
    assert m and m.group(1) == "", "a default topic in source would be public knowledge"


def test_nothing_is_sent_until_a_topic_is_set(monkeypatch, posts):
    _config(monkeypatch, topic=None)
    r = notify.send_notification("CORR-SSH-001 high", "critical")
    assert r["status"] == "not_configured" and "KRATOS_NTFY_TOPIC" in r["observation"] and posts == []


def test_a_topic_that_was_ever_in_public_source_is_refused(monkeypatch, posts):
    leaked = "kratos-alerts-" + "n4qk9zxp2v7m"  # split so the full string isn't grep-able here
    _config(monkeypatch, topic=leaked)
    r = notify.send_notification("x", "info")
    assert r["status"] == "refused" and posts == []
    assert notify.notify_config_status()[0] == "bad"


@pytest.mark.parametrize("bad", ["has space", "a/b", "x" * 65, "../etc"])
def test_malformed_topics_are_refused(monkeypatch, posts, bad):
    _config(monkeypatch, topic=bad)
    assert notify.send_notification("x")["status"] == "refused" and posts == []


def test_sends_to_this_installs_topic_with_optional_token(monkeypatch, posts):
    _config(monkeypatch, topic="kratos-0123456789abcdef01234567", base="https://ntfy.example.org/", token="tk_secret")
    r = notify.send_notification("hello", "warning")
    assert r["status"] == "sent"
    url, kw = posts[0]
    assert url == "https://ntfy.example.org/kratos-0123456789abcdef01234567"
    assert kw["headers"]["Authorization"] == "Bearer tk_secret" and kw["headers"]["Priority"] == "high"


def test_delivery_errors_never_echo_the_token(monkeypatch):
    _config(monkeypatch, topic="kratos-0123456789abcdef01234567", token="tk_secret")

    def boom(url, **kw):
        raise requests.ConnectionError("proxy said tk_secret is bad")

    monkeypatch.setattr(requests, "post", boom)
    r = notify.send_notification("x")
    assert r["status"] == "failed" and "tk_secret" not in r["observation"]


def test_suggested_topics_are_random_and_valid():
    a, b = notify.suggest_topic(), notify.suggest_topic()
    assert a != b and notify.topic_problem(a) is None and len(a) >= 24


def test_config_status_explains_the_public_server_caveat(monkeypatch):
    _config(monkeypatch, topic=None)
    status, detail = notify.notify_config_status()
    assert status == "off" and "KRATOS_NTFY_TOPIC=kratos-" in detail
    _config(monkeypatch, topic="short")
    status, detail = notify.notify_config_status()
    assert status == "warn" and "anyone who knows the topic name" in detail and "guess" in detail
    _config(monkeypatch, topic="kratos-0123456789abcdef01234567", token="tk")
    assert notify.notify_config_status()[0] == "ok"
    _config(monkeypatch, topic="kratos-0123456789abcdef01234567", base="https://ntfy.internal.lan")
    assert notify.notify_config_status()[0] == "ok"


def test_doctor_reports_notifications(monkeypatch):
    from kratos.agent import doctor

    _config(monkeypatch, topic=None)
    rows: list = []
    doctor._check_notifications(rows)
    assert rows[-1]["check"] == "notifications" and rows[-1]["status"] == "info" and rows[-1]["fix"]


def test_the_send_notification_tool_and_mcp_path_still_go_through_notify(monkeypatch, posts):
    from kratos.agent import tools

    _config(monkeypatch, topic=None)
    assert tools.tool_send_notification("x")["status"] == "not_configured"
    _config(monkeypatch, topic="kratos-0123456789abcdef01234567")
    assert tools.tool_send_notification("x", "info")["status"] == "sent" and len(posts) == 1
