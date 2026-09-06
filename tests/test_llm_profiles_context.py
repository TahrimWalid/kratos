"""
Tests for the per-profile context window plumbing (Piece 2 of model management):
adapters/llm_profiles.add_profile + the optional trailing LLM_CONTEXT_WINDOW line
that _parse_profiles/switch_profile now round-trip, and llm_config's reading of
the active profile's window at startup. Backward compatibility with classic
4-line blocks is asserted explicitly.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from kratos.adapters import llm_profiles as P
from kratos import llm_config as C


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / ".env"
    p.write_text(text, encoding="utf-8")
    return p


_TWO_PROFILES = (
    "# header\n"
    "LLM_BASE_URL=https://api.gemini.example/v1\n"
    "LLM_API_KEY=gkey\n"
    "LLM_MODEL=gemini-3.1-pro\n"
    "KRATOS_LLM_BACKEND=openai_compatible\n"
    "\n"
    "# LLM_BASE_URL=http://127.0.0.1:11434/v1\n"
    "# LLM_API_KEY=ollama\n"
    "# LLM_MODEL=qwen2.5:7b\n"
    "# KRATOS_LLM_BACKEND=openai_compatible\n"
)


# --- backward compatibility: 4-line blocks parse exactly as before ----------
def test_classic_four_line_blocks_unchanged(tmp_path):
    env = _write(tmp_path, _TWO_PROFILES)
    candidates, current = P.list_candidate_profiles(env)
    assert {c.model for c in candidates} == {"gemini-3.1-pro", "qwen2.5:7b"}
    assert current is not None and current.model == "gemini-3.1-pro"
    assert "LLM_CONTEXT_WINDOW" not in current.values   # no 5th line -> absent, not error


# --- add_profile writes a 5-line block that round-trips ---------------------
def test_add_profile_with_window_roundtrips_and_activates(tmp_path):
    env = _write(tmp_path, _TWO_PROFILES)
    P.add_profile(env, {
        "LLM_BASE_URL": "https://openrouter.ai/api/v1",
        "LLM_API_KEY": "sk-or",
        "LLM_MODEL": "qwen/qwen3.6-27b",
        "KRATOS_LLM_BACKEND": "openai_compatible",
        "LLM_CONTEXT_WINDOW": "262144",
    })
    candidates, current = P.list_candidate_profiles(env)
    # new profile is now the active one, and its window round-tripped
    assert current is not None and current.model == "qwen/qwen3.6-27b"
    assert current.values["LLM_CONTEXT_WINDOW"] == "262144"
    # the previously-active gemini profile was deactivated (commented)
    assert "qwen/qwen3.6-27b" in {c.model for c in candidates}
    text = env.read_text()
    assert "# LLM_MODEL=gemini-3.1-pro" in text       # gemini commented out
    assert "LLM_CONTEXT_WINDOW=262144" in text        # written uncommented


def test_add_profile_without_window_writes_four_lines(tmp_path):
    env = _write(tmp_path, _TWO_PROFILES)
    P.add_profile(env, {
        "LLM_BASE_URL": "https://api.deepseek.com/v1", "LLM_API_KEY": "k",
        "LLM_MODEL": "deepseek-chat", "KRATOS_LLM_BACKEND": "openai_compatible",
    })
    _, current = P.list_candidate_profiles(env)
    assert current.model == "deepseek-chat"
    assert "LLM_CONTEXT_WINDOW" not in current.values
    assert "LLM_CONTEXT_WINDOW" not in env.read_text()


# --- switch_profile toggles the window line together with the block ---------
def test_switch_toggles_window_line_with_its_block(tmp_path):
    env = _write(tmp_path, _TWO_PROFILES)
    P.add_profile(env, {
        "LLM_BASE_URL": "https://openrouter.ai/api/v1", "LLM_API_KEY": "sk",
        "LLM_MODEL": "qwen/qwen3.6-27b", "KRATOS_LLM_BACKEND": "openai_compatible",
        "LLM_CONTEXT_WINDOW": "262144",
    })
    # now switch back to gemini -> the openrouter block (incl. its window line) must be commented
    candidates, current = P.list_candidate_profiles(env)
    gemini = next(c for c in candidates if c.model == "gemini-3.1-pro")
    P.switch_profile(env, target=gemini, current=current)

    text = env.read_text()
    assert "# LLM_CONTEXT_WINDOW=262144" in text       # window line commented with its block
    _, now_active = P.list_candidate_profiles(env)
    assert now_active.model == "gemini-3.1-pro"

    # and switching back to openrouter re-activates the window line
    candidates2, cur2 = P.list_candidate_profiles(env)
    openrouter = next(c for c in candidates2 if c.model == "qwen/qwen3.6-27b")
    P.switch_profile(env, target=openrouter, current=cur2)
    text2 = env.read_text()
    assert "\nLLM_CONTEXT_WINDOW=262144" in text2       # uncommented again


# --- llm_config reads the active profile's window at startup ----------------
def test_resolver_reads_profile_window_from_env_at_startup(monkeypatch):
    # No live /model switch (override is None) -> the active profile's
    # LLM_CONTEXT_WINDOW, as load_dotenv would have put it in os.environ.
    monkeypatch.setattr(C, "_active_llm_override", None)
    monkeypatch.delenv("KRATOS_LLM_CONTEXT_WINDOW", raising=False)
    monkeypatch.setenv("LLM_CONTEXT_WINDOW", "196000")
    assert C.get_active_llm_context_window() == 196000


def test_set_profile_context_window_insert_update_clear(tmp_path):
    env = _write(tmp_path, _TWO_PROFILES)
    # insert on a profile that had none
    assert P.set_profile_context_window(env, "gemini-3.1-pro", 200000) is True
    _, current = P.list_candidate_profiles(env)
    assert current.values["LLM_CONTEXT_WINDOW"] == "200000"
    # update it
    assert P.set_profile_context_window(env, "gemini-3.1-pro", 128000) is True
    _, current = P.list_candidate_profiles(env)
    assert current.values["LLM_CONTEXT_WINDOW"] == "128000"
    # clear it (back to auto) -> line removed
    assert P.set_profile_context_window(env, "gemini-3.1-pro", None) is True
    _, current = P.list_candidate_profiles(env)
    assert "LLM_CONTEXT_WINDOW" not in current.values
    # the 4-key block is still intact and active
    assert current.model == "gemini-3.1-pro" and current.active


def test_set_profile_context_window_unknown_model_returns_false(tmp_path):
    env = _write(tmp_path, _TWO_PROFILES)
    assert P.set_profile_context_window(env, "no-such-model", 100000) is False


def test_set_profile_context_window_on_inactive_profile_keeps_it_commented(tmp_path):
    env = _write(tmp_path, _TWO_PROFILES)
    # qwen2.5:7b is the commented (inactive) block -> its new window line must
    # also be commented, so it doesn't leak active.
    P.set_profile_context_window(env, "qwen2.5:7b", 40960)
    assert "# LLM_CONTEXT_WINDOW=40960" in env.read_text()
    _, current = P.list_candidate_profiles(env)
    assert current.model == "gemini-3.1-pro"   # active unchanged


def test_delete_profile_removes_block_and_keeps_others(tmp_path):
    env = _write(tmp_path, _TWO_PROFILES)
    # qwen2.5:7b is the inactive (commented) block -> deletable.
    assert P.delete_profile(env, "qwen2.5:7b") is True
    text = env.read_text()
    assert "qwen2.5:7b" not in text
    # the active gemini profile is untouched and still the current one
    candidates, current = P.list_candidate_profiles(env)
    assert {c.model for c in candidates} == {"gemini-3.1-pro"}
    assert current is not None and current.model == "gemini-3.1-pro" and current.active


def test_delete_profile_removes_its_window_line_too(tmp_path):
    env = _write(tmp_path, _TWO_PROFILES)
    P.add_profile(env, {
        "LLM_BASE_URL": "https://openrouter.ai/api/v1", "LLM_API_KEY": "sk",
        "LLM_MODEL": "qwen/qwen3.6-27b", "KRATOS_LLM_BACKEND": "openai_compatible",
        "LLM_CONTEXT_WINDOW": "262144",
    })
    # switch back to gemini so the openrouter block (with its window line) is inactive, then delete it
    candidates, current = P.list_candidate_profiles(env)
    gemini = next(c for c in candidates if c.model == "gemini-3.1-pro")
    P.switch_profile(env, target=gemini, current=current)
    assert P.delete_profile(env, "qwen/qwen3.6-27b") is True
    text = env.read_text()
    assert "qwen/qwen3.6-27b" not in text
    assert "262144" not in text          # its trailing LLM_CONTEXT_WINDOW line went with it
    assert "\n\n\n" not in text          # no accumulated blank-line runs


def test_delete_profile_unknown_returns_false(tmp_path):
    env = _write(tmp_path, _TWO_PROFILES)
    assert P.delete_profile(env, "no-such-model") is False
    # nothing removed
    assert {c.model for c in P.list_candidate_profiles(env)[0]} == {"gemini-3.1-pro", "qwen2.5:7b"}


def test_after_switch_absent_window_does_not_use_stale_env(monkeypatch):
    # A profile switch happened whose profile has NO window -> must NOT fall back
    # to a stale os.environ LLM_CONTEXT_WINDOW from a different profile.
    monkeypatch.setenv("LLM_CONTEXT_WINDOW", "196000")          # stale, from a prior profile
    monkeypatch.delenv("KRATOS_LLM_CONTEXT_WINDOW", raising=False)
    C.set_active_llm_profile({"LLM_BASE_URL": "https://api.example.com/v1", "LLM_API_KEY": "k",
                              "LLM_MODEL": "gpt-4o", "KRATOS_LLM_BACKEND": "openai_compatible"})
    try:
        # gpt-4o (cloud, known) -> 128k from the map, NOT the stale 196000
        assert C.get_active_llm_context_window() == 128_000
    finally:
        C._active_llm_override = None
