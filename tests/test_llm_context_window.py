"""
Tests for the model-aware context window (llm_config.get_active_llm_context_window
+ llm_interface.get_context_window_tokens).

The window is the denominator for the 7c fill meter and the trigger budget for
agent/loop.py's compaction, so getting it right per active model is what makes
"switch to a bigger model -> more room / less compaction; switch to a smaller
one -> compaction adapts to fit" actually happen. Key invariants asserted:
  * local (loopback / llama_cpp) stays at the deliberate LLAMA_N_CTX budget --
    the project runs its local model at 6144, not its theoretical max;
  * a cloud model with a SAVED window (per-profile LLM_CONTEXT_WINDOW, detected-
    and-saved or user-typed) uses it -- there is deliberately NO name->size table;
  * a cloud model with NOTHING saved underclaims to LLAMA_N_CTX -- never
    optimistically guesses large, because overclaiming risks a real overflow;
  * an explicit value (per-profile LLM_CONTEXT_WINDOW / global env) always wins;
  * switching profiles changes the window (the whole point).
"""
from __future__ import annotations

import pytest

from kratos import llm_config as C
from kratos import llm_interface
from kratos.llm_config import LLAMA_N_CTX


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch):
    """Reset the live-active profile and the global env override around each
    test (set_active_llm_profile mutates a module global)."""
    monkeypatch.setattr(C, "_active_llm_override", None)
    monkeypatch.delenv("KRATOS_LLM_CONTEXT_WINDOW", raising=False)
    yield
    C._active_llm_override = None


def _use(model: str, base_url: str = "https://api.example.com/v1", backend: str = "openai_compatible", **extra):
    C.set_active_llm_profile({"LLM_BASE_URL": base_url, "LLM_API_KEY": "x",
                              "LLM_MODEL": model, "KRATOS_LLM_BACKEND": backend, **extra})


# --- local stays at the deliberate budget ----------------------------------
@pytest.mark.parametrize("base_url", [
    "http://127.0.0.1:11434/v1", "http://localhost:11434/v1", "http://127.0.0.5:8080/v1",
])
def test_local_loopback_uses_local_budget(base_url):
    _use("qwen2.5:7b", base_url=base_url)
    assert C.get_active_llm_context_window() == LLAMA_N_CTX


def test_llama_cpp_backend_uses_local_budget():
    _use("whatever", base_url="https://not-loopback.example/v1", backend="llama_cpp")
    assert C.get_active_llm_context_window() == LLAMA_N_CTX


# --- a cloud model with NO saved window underclaims (no name->size table) ---
@pytest.mark.parametrize("model", [
    "gemini-3.1-pro", "claude-opus-5", "gpt-4o", "deepseek-chat",
    "qwen/qwen3.6-27b", "meta-llama/llama-3.3-70b", "some-brand-new-model-x",
])
def test_cloud_model_without_saved_window_underclaims(model):
    # No saved LLM_CONTEXT_WINDOW -> the safe local budget, NOT a guess from the
    # model name (the old name->size table was removed on purpose).
    _use(model)
    assert C.get_active_llm_context_window() == LLAMA_N_CTX


# --- unknown cloud underclaims (safety) ------------------------------------
def test_unknown_cloud_model_underclaims_to_local_budget():
    _use("some-brand-new-frontier-model-x")
    # never optimistically large -- overclaiming risks a real overflow
    assert C.get_active_llm_context_window() == LLAMA_N_CTX


# --- explicit values always win --------------------------------------------
def test_per_profile_explicit_window_wins_over_map():
    _use("gemini-3.1-pro", LLM_CONTEXT_WINDOW="8000")   # a saved window is used verbatim
    assert C.get_active_llm_context_window() == 8000


def test_global_env_override_wins(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KRATOS_LLM_CONTEXT_WINDOW", "12345")
    _use("qwen2.5:7b", base_url="http://127.0.0.1:11434/v1")   # local would be 6144
    assert C.get_active_llm_context_window() == 12345


def test_non_numeric_explicit_is_ignored():
    _use("gemini-3.1-pro", LLM_CONTEXT_WINDOW="lots")   # garbage window -> safe default
    assert C.get_active_llm_context_window() == LLAMA_N_CTX


# --- the core property: switching model changes the window -----------------
def test_switching_model_changes_window_live():
    _use("qwen2.5:7b", base_url="http://127.0.0.1:11434/v1")
    assert C.get_active_llm_context_window() == LLAMA_N_CTX          # local budget
    _use("gemini-3.1-pro", LLM_CONTEXT_WINDOW="1000000")           # switch to a model with a saved window
    assert C.get_active_llm_context_window() == 1_000_000           # budget grew, no other wiring


# --- get_context_window_tokens delegates -----------------------------------
def test_interface_delegates_to_resolver():
    _use("deepseek-chat", LLM_CONTEXT_WINDOW="65536")
    assert llm_interface.get_context_window_tokens() == C.get_active_llm_context_window() == 65_536
