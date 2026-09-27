"""
Tests for detect-once-and-save (adapters/llm_context_autofill.py) and the
LLM_CONTEXT_SOURCE provenance line it relies on (adapters/llm_profiles.py).

Invariants asserted:
  * a detected window is saved to the profile WITH its source (provider/catalog),
    and `values` is updated in place so the caller can re-sync the live profile;
  * a window that's already saved -- user-typed or detected -- is never
    overwritten by autofill;
  * local endpoints are never autofilled (their deliberate budget stays);
  * an undetectable model writes nothing (runtime then uses the safe default);
  * the source line round-trips, follows its block on switch, is removed on
    clear/delete, and is dropped when the user types their own number.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from kratos.adapters import llm_profiles as P
from kratos.adapters.llm_context_autofill import autofill_context_window, describe, needs_autofill
from kratos.adapters.llm_context_detect import DetectedContext

_ENV = (
    "LLM_BASE_URL=https://api.cloud.example/v1\nLLM_API_KEY=k\n"
    "LLM_MODEL=cloud-model\nKRATOS_LLM_BACKEND=openai_compatible\n\n"
    "# LLM_BASE_URL=https://api.other.example/v1\n# LLM_API_KEY=k2\n"
    "# LLM_MODEL=other-model\n# KRATOS_LLM_BACKEND=openai_compatible\n"
    "# LLM_CONTEXT_WINDOW=8000\n\n"
    "# LLM_BASE_URL=http://127.0.0.1:11434/v1\n# LLM_API_KEY=ollama\n"
    "# LLM_MODEL=qwen2.5:7b\n# KRATOS_LLM_BACKEND=openai_compatible\n"
)


def _env(tmp_path: Path) -> Path:
    p = tmp_path / ".env"
    p.write_text(_ENV, encoding="utf-8")
    return p


def _profile(env: Path, model: str) -> P.EnvProfile:
    lines = env.read_text(encoding="utf-8").split("\n")
    return next(p for p in P._parse_profiles(lines) if p.model == model)


def _detector(value, authority, calls=None):
    def _detect(base_url, api_key="", model=""):
        if calls is not None:
            calls.append(model)
        if value is None:
            return DetectedContext(None, None, "none", "couldn't read it -- enter it manually")
        if authority == "catalog":
            return DetectedContext(None, value, "catalog", "public catalog: ...", authority="catalog")
        return DetectedContext(value, value, "provider", "host reports ...", authority="provider")
    return _detect


# --- the source line itself ---------------------------------------------------
def test_source_line_roundtrips_with_window(tmp_path):
    env = _env(tmp_path)
    assert P.set_profile_context_window(env, "cloud-model", 262144, source="provider")
    prof = _profile(env, "cloud-model")
    assert prof.values["LLM_CONTEXT_WINDOW"] == "262144"
    assert prof.values["LLM_CONTEXT_SOURCE"] == "provider"
    assert prof.active   # adding lines must not flip active status
    text = env.read_text(encoding="utf-8")
    assert "LLM_CONTEXT_WINDOW=262144\nLLM_CONTEXT_SOURCE=provider\n" in text


def test_inactive_block_gets_commented_source_line(tmp_path):
    env = _env(tmp_path)
    P.set_profile_context_window(env, "other-model", 131072, source="catalog")
    assert "# LLM_CONTEXT_WINDOW=131072\n# LLM_CONTEXT_SOURCE=catalog\n" in env.read_text(encoding="utf-8")
    assert not _profile(env, "other-model").active


def test_user_number_drops_the_source_line(tmp_path):
    env = _env(tmp_path)
    P.set_profile_context_window(env, "cloud-model", 262144, source="catalog")
    P.set_profile_context_window(env, "cloud-model", 100000)          # user types their own
    prof = _profile(env, "cloud-model")
    assert prof.values["LLM_CONTEXT_WINDOW"] == "100000"
    assert "LLM_CONTEXT_SOURCE" not in prof.values                   # absent = user-set
    assert "LLM_CONTEXT_SOURCE" not in env.read_text(encoding="utf-8")


def test_clear_removes_window_and_source(tmp_path):
    env = _env(tmp_path)
    P.set_profile_context_window(env, "cloud-model", 262144, source="provider")
    P.set_profile_context_window(env, "cloud-model", None)
    text = env.read_text(encoding="utf-8")
    assert "LLM_CONTEXT_SOURCE" not in text
    assert "LLM_CONTEXT_WINDOW=262144" not in text
    assert "# LLM_CONTEXT_WINDOW=8000" in text                       # the other profile untouched


def test_unknown_source_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        P.set_profile_context_window(_env(tmp_path), "cloud-model", 1, source="guess")


def test_switch_moves_source_line_with_its_block(tmp_path):
    env = _env(tmp_path)
    P.set_profile_context_window(env, "other-model", 131072, source="catalog")
    lines = env.read_text(encoding="utf-8").split("\n")
    profiles = P._parse_profiles(lines)
    current = next(p for p in profiles if p.active)
    target = next(p for p in profiles if p.model == "other-model")
    P.switch_profile(env, target, current)
    text = env.read_text(encoding="utf-8")
    assert "\nLLM_CONTEXT_WINDOW=131072\nLLM_CONTEXT_SOURCE=catalog\n" in text   # uncommented together
    assert _profile(env, "other-model").active
    assert not _profile(env, "cloud-model").active


def test_delete_removes_source_line(tmp_path):
    env = _env(tmp_path)
    P.set_profile_context_window(env, "other-model", 131072, source="catalog")
    P.delete_profile(env, "other-model")
    text = env.read_text(encoding="utf-8")
    assert "other-model" not in text and "LLM_CONTEXT_SOURCE" not in text


def test_add_profile_writes_detected_source(tmp_path):
    env = _env(tmp_path)
    P.add_profile(env, {"LLM_BASE_URL": "https://x.example/v1", "LLM_API_KEY": "k", "LLM_MODEL": "new",
                        "KRATOS_LLM_BACKEND": "openai_compatible", "LLM_CONTEXT_WINDOW": "65536",
                        "LLM_CONTEXT_SOURCE": "provider"})
    assert _profile(env, "new").values["LLM_CONTEXT_SOURCE"] == "provider"


# --- autofill -------------------------------------------------------------------
def test_autofill_saves_detected_window_and_updates_values(tmp_path):
    env = _env(tmp_path)
    values = dict(_profile(env, "cloud-model").values)
    r = autofill_context_window(env, values, detect=_detector(262144, "provider"))
    assert r.saved and r.window == 262144 and r.source == "provider"
    assert values["LLM_CONTEXT_WINDOW"] == "262144" and values["LLM_CONTEXT_SOURCE"] == "provider"
    assert _profile(env, "cloud-model").values["LLM_CONTEXT_SOURCE"] == "provider"
    assert "reported by the provider" in describe(r, "cloud-model")


def test_autofill_catalog_is_labelled_less_certain(tmp_path):
    env = _env(tmp_path)
    values = dict(_profile(env, "cloud-model").values)
    r = autofill_context_window(env, values, detect=_detector(1048576, "catalog"))
    assert r.saved and r.source == "catalog"
    assert "may allow less" in describe(r, "cloud-model")


def test_autofill_never_overwrites_a_saved_window(tmp_path):
    env = _env(tmp_path)
    before = env.read_text(encoding="utf-8")
    calls: list[str] = []
    values = dict(_profile(env, "other-model").values)                 # has a user-set 8000
    r = autofill_context_window(env, values, detect=_detector(999999, "provider", calls))
    assert not r.saved and calls == []                                 # didn't even probe
    assert env.read_text(encoding="utf-8") == before
    assert describe(r, "other-model") is None


def test_autofill_skips_local_models(tmp_path):
    env = _env(tmp_path)
    calls: list[str] = []
    values = dict(_profile(env, "qwen2.5:7b").values)
    assert not needs_autofill(values)
    r = autofill_context_window(env, values, detect=_detector(32768, "provider", calls))
    assert not r.saved and calls == []


def test_autofill_undetectable_writes_nothing_and_says_so(tmp_path):
    env = _env(tmp_path)
    before = env.read_text(encoding="utf-8")
    values = dict(_profile(env, "cloud-model").values)
    r = autofill_context_window(env, values, detect=_detector(None, None))
    assert not r.saved and r.window is None
    assert env.read_text(encoding="utf-8") == before
    assert "safe default" in describe(r, "cloud-model")


def test_autofill_survives_a_crashing_detector(tmp_path):
    env = _env(tmp_path)

    def _boom(*a, **k):
        raise RuntimeError("network exploded")

    r = autofill_context_window(env, dict(_profile(env, "cloud-model").values), detect=_boom)
    assert not r.saved and "RuntimeError" in r.detail