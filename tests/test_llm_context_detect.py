"""
Tests for adapters/llm_context_detect.detect_context_window -- the multi-provider
context-window detection behind the model-setup UI. HTTP is mocked with realistic
per-framework response shapes (the OpenRouter path is additionally verified live
in the build session against the real active endpoint). Asserts each framework's
parsing, the Ollama loaded-vs-max distinction, and that an unreadable endpoint
degrades to a clean "enter manually" rather than raising.
"""
from __future__ import annotations

import pytest
import requests

from kratos.adapters import llm_context_detect as D


class _Resp:
    def __init__(self, status: int, payload: dict):
        self.status_code = status
        self._payload = payload

    def json(self) -> dict:
        return self._payload


def _install(monkeypatch, routes: dict):
    """routes: url-fragment -> _Resp, or an Exception to raise (simulating a
    provider that isn't there). Any unmatched URL raises RequestException."""
    def _match(url: str):
        for frag, resp in routes.items():
            if frag in url:
                if isinstance(resp, Exception):
                    raise resp
                return resp
        raise requests.RequestException(f"no route: {url}")

    monkeypatch.setattr(D.requests, "get", lambda url, **kw: _match(url))
    monkeypatch.setattr(D.requests, "post", lambda url, **kw: _match(url))


# --- Ollama: max from /api/show, loaded (< max) from /api/ps ----------------
def test_ollama_reports_max_and_loaded(monkeypatch):
    _install(monkeypatch, {
        "/api/show": _Resp(200, {"model_info": {"general.architecture": "qwen3",
                                                "qwen3.context_length": 262144}}),
        "/api/ps": _Resp(200, {"models": [{"name": "qwen3:27b", "model": "qwen3:27b",
                                           "context_length": 32768}]}),
    })
    d = D.detect_context_window("http://127.0.0.1:11434/v1", "", "qwen3:27b")
    assert d.source == "ollama"
    assert d.max_context == 262144           # hard ceiling (architecture)
    assert d.loaded_context == 32768         # current runtime (the beefy-rig headroom case)
    assert "supports up to 262,144" in d.detail and "loaded at 32,768" in d.detail


def test_ollama_show_without_ps_still_detects_max(monkeypatch):
    _install(monkeypatch, {
        "/api/show": _Resp(200, {"model_info": {"llama.context_length": 131072}}),
        "/api/ps": requests.RequestException("ps unavailable"),   # bonus endpoint absent
    })
    d = D.detect_context_window("http://localhost:11434/v1", "", "llama3:8b")
    assert d.source == "ollama" and d.max_context == 131072 and d.loaded_context is None


# --- vLLM / OpenRouter / generic /models ------------------------------------
def test_vllm_max_model_len(monkeypatch):
    _install(monkeypatch, {
        "/api/show": requests.RequestException("not ollama"),
        "/models": _Resp(200, {"data": [{"id": "my-served-model", "max_model_len": 32768}]}),
    })
    d = D.detect_context_window("http://127.0.0.1:8000/v1", "", "my-served-model")
    assert d.source == "vllm"
    assert d.max_context == 32768 and d.loaded_context == 32768   # served endpoint: max == operative


def test_openrouter_context_length(monkeypatch):
    _install(monkeypatch, {
        "/models": _Resp(200, {"data": [{"id": "qwen/qwen3.6-27b", "context_length": 262144}]}),
    })
    d = D.detect_context_window("https://openrouter.ai/api/v1", "sk-x", "qwen/qwen3.6-27b")
    assert d.source == "openrouter" and d.max_context == 262144


def test_models_endpoint_matches_provider_prefixed_id(monkeypatch):
    # bare model string vs provider-prefixed id in the listing
    _install(monkeypatch, {
        "/models": _Resp(200, {"data": [{"id": "vendor/cool-model", "context_length": 40960}]}),
    })
    d = D.detect_context_window("https://api.cloud.example/v1", "k", "cool-model")
    assert d.max_context == 40960


# --- HF TGI /info -----------------------------------------------------------
def test_tgi_info(monkeypatch):
    _install(monkeypatch, {
        "/api/show": requests.RequestException("not ollama"),
        "/models": _Resp(404, {}),                       # TGI has no /models
        "/info": _Resp(200, {"max_total_tokens": 32768, "max_input_tokens": 32000}),
    })
    d = D.detect_context_window("http://127.0.0.1:8080/v1", "", "tgi-model")
    assert d.source == "tgi" and d.max_context == 32768


# --- undetectable degrades cleanly ------------------------------------------
def test_bare_endpoint_undetectable_is_clean_not_an_error(monkeypatch):
    _install(monkeypatch, {
        "/models": _Resp(200, {"data": [{"id": "mystery-model"}]}),   # no window field anywhere
    })
    d = D.detect_context_window("https://api.mystery.example/v1", "k", "mystery-model")
    assert d.detectable is False
    assert d.source == "none"
    assert "manually" in d.detail


def test_all_probes_fail_returns_none_not_raises(monkeypatch):
    _install(monkeypatch, {})   # every URL raises RequestException
    d = D.detect_context_window("https://dead.example/v1", "k", "m")
    assert d.detectable is False and d.source == "none"


def test_empty_inputs_short_circuit():
    assert D.detect_context_window("", "", "").detectable is False
    assert D.detect_context_window("http://x/v1", "", "").detectable is False
