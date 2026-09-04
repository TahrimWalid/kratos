"""
Scripted tests for real token accounting (feature 7c) in llm_interface.py.

No real LLM: requests.post is monkeypatched with a fake response carrying a
`usage` block, matching the project's convention for pure-logic coverage.
The point under test is that usage is captured from the response (it used to
be thrown away) and exposed via the accessors WITHOUT changing agent_chat's
`Optional[str]` return contract.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from kratos import llm_interface as L


class _FakeResp:
    status_code = 200

    def __init__(self, body: dict):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


@pytest.fixture(autouse=True)
def _reset_usage():
    L.reset_session_token_usage()
    yield
    L.reset_session_token_usage()


def test_record_usage_basic():
    L._record_usage({"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120})
    lu = L.get_last_token_usage()
    assert (lu.prompt_tokens, lu.completion_tokens, lu.total_tokens) == (100, 20, 120)


def test_record_usage_derives_total_when_missing():
    L._record_usage({"prompt_tokens": 10, "completion_tokens": 5})
    assert L.get_last_token_usage().total_tokens == 15


def test_record_usage_tolerates_garbage():
    L._record_usage(None)
    L._record_usage("nonsense")
    L._record_usage({"prompt_tokens": "bad"})
    # Nothing recorded from any of the above -> still no usage.
    assert L.get_last_token_usage() is None
    assert L.get_session_token_usage().total_tokens == 0


def test_session_usage_accumulates_last_is_latest():
    L._record_usage({"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110})
    L._record_usage({"prompt_tokens": 200, "completion_tokens": 20, "total_tokens": 220})
    assert L.get_session_token_usage().total_tokens == 330
    # last usage reflects only the most recent call (the context-fill numerator)
    assert L.get_last_token_usage().prompt_tokens == 200


def test_reset_clears_both():
    L._record_usage({"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10})
    L.reset_session_token_usage()
    assert L.get_last_token_usage() is None
    assert L.get_session_token_usage().total_tokens == 0


def test_get_last_returns_a_copy_not_live_reference():
    L._record_usage({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})
    snap = L.get_last_token_usage()
    snap.prompt_tokens = 999  # mutating the snapshot must not corrupt internal state
    assert L.get_last_token_usage().prompt_tokens == 1


def test_query_openai_compatible_captures_usage():
    body = {
        "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1234, "completion_tokens": 56, "total_tokens": 1290},
    }
    with patch.object(L, "requests") as rq:
        rq.post.return_value = _FakeResp(body)
        out = L._query_openai_compatible("prompt", "system", 100)
    assert out == "hi"
    assert L.get_last_token_usage().as_dict() == {
        "prompt_tokens": 1234,
        "completion_tokens": 56,
        "total_tokens": 1290,
    }


def test_query_openai_compatible_records_usage_even_when_content_truncated():
    # A reasoning model can burn the whole budget on hidden tokens: HTTP 200,
    # finish_reason="length", no content -- but real tokens were still spent
    # and must show in the meter.
    body = {
        "choices": [{"message": {}, "finish_reason": "length"}],
        "usage": {"prompt_tokens": 4096, "completion_tokens": 0, "total_tokens": 4096},
    }
    with patch.object(L, "requests") as rq:
        rq.post.return_value = _FakeResp(body)
        out = L._query_openai_compatible("prompt", "system", 4096)
    assert out is None  # no content
    assert L.get_last_token_usage().prompt_tokens == 4096  # usage still captured


def test_query_openai_compatible_missing_usage_block_is_fine():
    body = {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    with patch.object(L, "requests") as rq:
        rq.post.return_value = _FakeResp(body)
        out = L._query_openai_compatible("p", "s", 50)
    assert out == "ok"
    assert L.get_last_token_usage() is None  # nothing to record, no crash


def test_context_window_is_positive_int():
    assert isinstance(L.get_context_window_tokens(), int)
    assert L.get_context_window_tokens() > 0
