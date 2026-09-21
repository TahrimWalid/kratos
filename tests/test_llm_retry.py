"""
Mocked tests for llm_interface.py::_query_openai_compatible's retry/backoff
logic -- see docs/DESIGN.md's "LLM backend" section for why this exists:
large system prompts hit transient 503s from a hosted backend far more
often than small ones, and a single 503 used to kill the whole call with
zero retry.

requests.post is mocked throughout (via side_effect lists mixing fake
Response objects and raised exceptions) so these are fast, deterministic,
and don't depend on a real backend's live state. time.sleep is also mocked
so tests don't actually wait out the real 1s/2s backoff. Backoff timing and
retry-note rendering were separately verified against a live hosted
endpoint -- these tests exist for durable regression coverage of the
retryable/non-retryable classification and attempt-budget bookkeeping, not
to re-prove that live finding.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

pytest.importorskip("requests")
import requests

from kratos import llm_interface


class _FakeResponse:
    def __init__(self, status_code: int, json_data: dict | None = None):
        self.status_code = status_code
        self._json = json_data or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code} error", response=self)

    def json(self) -> dict:
        return self._json


def _ok_response(content: str = "hello") -> _FakeResponse:
    return _FakeResponse(200, {"choices": [{"message": {"content": content}}]})


def _truncated_response() -> _FakeResponse:
    return _FakeResponse(200, {"choices": [{"message": {}, "finish_reason": "length"}]})


@patch("kratos.llm_interface.time.sleep")
@patch("kratos.llm_interface.requests.post")
def test_retries_on_503_then_succeeds(mock_post, mock_sleep):
    mock_post.side_effect = [
        _FakeResponse(503),
        _FakeResponse(503),
        _ok_response("recovered"),
    ]
    result = llm_interface._query_openai_compatible("prompt", "system", 100)
    assert result == "recovered"
    assert mock_post.call_count == 3
    assert mock_sleep.call_args_list == [((1,),), ((2,),)]


@patch("kratos.llm_interface._render_retry_note")
@patch("kratos.llm_interface.time.sleep")
@patch("kratos.llm_interface.requests.post")
def test_exhausted_retries_on_persistent_503_falls_through_to_failure(mock_post, mock_sleep, mock_render):
    mock_post.side_effect = [_FakeResponse(503), _FakeResponse(503), _FakeResponse(503)]
    result = llm_interface._query_openai_compatible("prompt", "system", 100)
    assert result is None
    # 3 total attempts (initial + 2 retries), never more.
    assert mock_post.call_count == 3
    # A retry note fires before attempts 2 and 3, never after the final
    # exhausted attempt (that one falls through to the existing stderr
    # failure print instead).
    assert mock_render.call_count == 2


@patch("kratos.llm_interface.time.sleep")
@patch("kratos.llm_interface.requests.post")
def test_429_is_retried_same_as_503(mock_post, mock_sleep):
    mock_post.side_effect = [_FakeResponse(429), _ok_response("ok")]
    result = llm_interface._query_openai_compatible("prompt", "system", 100)
    assert result == "ok"
    assert mock_post.call_count == 2


@patch("kratos.llm_interface.time.sleep")
@patch("kratos.llm_interface.requests.post")
def test_connection_error_is_retried(mock_post, mock_sleep):
    mock_post.side_effect = [requests.exceptions.ConnectionError("refused"), _ok_response("ok")]
    result = llm_interface._query_openai_compatible("prompt", "system", 100)
    assert result == "ok"
    assert mock_post.call_count == 2


@patch("kratos.llm_interface.time.sleep")
@patch("kratos.llm_interface.requests.post")
def test_timeout_is_retried(mock_post, mock_sleep):
    mock_post.side_effect = [requests.exceptions.Timeout("timed out"), _ok_response("ok")]
    result = llm_interface._query_openai_compatible("prompt", "system", 100)
    assert result == "ok"
    assert mock_post.call_count == 2


@patch("kratos.llm_interface.time.sleep")
@patch("kratos.llm_interface.requests.post")
def test_401_fails_immediately_no_retry(mock_post, mock_sleep):
    """A bad API key is a non-transient client error -- retrying it can
    never succeed, so it must fail on the first attempt, same as before
    this change."""
    mock_post.side_effect = [_FakeResponse(401)]
    result = llm_interface._query_openai_compatible("prompt", "system", 100)
    assert result is None
    assert mock_post.call_count == 1
    mock_sleep.assert_not_called()


@patch("kratos.llm_interface.time.sleep")
@patch("kratos.llm_interface.requests.post")
def test_400_fails_immediately_no_retry(mock_post, mock_sleep):
    mock_post.side_effect = [_FakeResponse(400)]
    result = llm_interface._query_openai_compatible("prompt", "system", 100)
    assert result is None
    assert mock_post.call_count == 1
    mock_sleep.assert_not_called()


@patch("kratos.llm_interface.time.sleep")
@patch("kratos.llm_interface.requests.post")
def test_content_none_not_retried(mock_post, mock_sleep):
    """A real HTTP 200 with no content (reasoning tokens burned the whole
    max_tokens budget) is a real response, not a transient failure --
    retrying the identical request would very likely burn the budget the
    same way again, so this must not be retried."""
    mock_post.side_effect = [_truncated_response()]
    result = llm_interface._query_openai_compatible("prompt", "system", 100)
    assert result is None
    assert mock_post.call_count == 1
    mock_sleep.assert_not_called()


@patch("kratos.agent.console.render_note")
@patch("kratos.agent.console.get_console")
@patch("kratos.llm_interface.time.sleep")
@patch("kratos.llm_interface.requests.post")
def test_retry_note_rendered_visibly_via_console(mock_post, mock_sleep, mock_get_console, mock_render_note):
    # _render_retry_note does `from kratos.agent import console as _console`
    # lazily, then calls _console.render_note(...) / _console.get_console()
    # -- these are attribute lookups on the real, cached module object at
    # call time, so patching the real module's attributes directly (not
    # sys.modules) is what actually gets seen, regardless of import timing.
    mock_post.side_effect = [_FakeResponse(503), _ok_response("ok")]
    result = llm_interface._query_openai_compatible("prompt", "system", 100)
    assert result == "ok"
    mock_render_note.assert_called_once()
    rendered_text = mock_render_note.call_args[0][1]
    assert "retrying" in rendered_text
    assert "HTTP 503" in rendered_text
    # Attempt 1 (of 3) just failed and is about to be retried -- the note
    # names the attempt that failed, not the one about to run.
    assert "(1/3)" in rendered_text
