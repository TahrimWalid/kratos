"""
Detect-once-and-save for a profile's context window.

The context window is read constantly during an investigation (agent/loop.py
re-checks it every step to decide when to compact), so that read must be instant
and offline -- it only ever reads the number saved in the profile. This module is
how that number gets there without the user typing it: when a model is added or
switched to (or the TUI starts) and its profile has NO saved window, detect it
once (provider first, then the public catalog -- adapters/llm_context_detect.py)
and write it to .env with its source.

Rules:
  * Never overwrites an existing window. A saved number -- user-typed or earlier
    detected -- is left alone; the user refreshes it deliberately via Settings
    (Ctrl+D), which is also how a catalog figure gets upgraded to a provider one.
  * Never runs for a LOCAL endpoint. Local models run at the deliberate
    LLAMA_N_CTX budget (llm_config), and a detected architecture max would be
    larger than what the local server actually has loaded -- sending prompts that
    big gets them silently truncated. Local users set a larger number themselves.
  * Undetectable is a normal outcome: nothing is written, and the runtime falls
    back to the safe default, which the UI states plainly.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from kratos.adapters import llm_profiles
from kratos.adapters.llm_context_detect import DetectedContext, detect_context_window

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


@dataclass
class AutofillResult:
    window: int | None     # the number now saved; None if nothing was saved
    source: str | None     # "provider" | "catalog" | None
    detail: str            # human-readable outcome for a status line
    saved: bool            # True iff this call wrote a new window to .env


def _is_local(values: dict[str, str]) -> bool:
    if values.get("KRATOS_LLM_BACKEND") == "llama_cpp":
        return True
    host = (urlparse(values.get("LLM_BASE_URL", "")).hostname or "").lower()
    return host in _LOCAL_HOSTS or host.startswith("127.")


def needs_autofill(values: dict[str, str]) -> bool:
    """True iff this profile has no usable saved window and is a cloud endpoint."""
    saved = str(values.get("LLM_CONTEXT_WINDOW", "")).strip()
    return not saved.isdigit() and not _is_local(values)


def autofill_context_window(
    env_path: Path,
    values: dict[str, str],
    *,
    detect: Callable[..., DetectedContext] = detect_context_window,
) -> AutofillResult:
    """If `values` (one profile) needs it, detect its window and save it to
    `env_path`, updating `values` in place with LLM_CONTEXT_WINDOW /
    LLM_CONTEXT_SOURCE so a caller can re-sync set_active_llm_profile(values).
    Never raises."""
    try:
        return _autofill(env_path, values, detect)
    except Exception as e:  # noqa: BLE001 -- best-effort; never break startup/switch/add
        return AutofillResult(None, None, f"context detection failed ({type(e).__name__}: {e})", False)


def _autofill(env_path: Path, values: dict[str, str], detect: Callable[..., DetectedContext]) -> AutofillResult:
    model = values.get("LLM_MODEL", "")
    if not needs_autofill(values):
        return AutofillResult(None, None, "context window already set (or local model)", False)
    d = detect(values.get("LLM_BASE_URL", ""), values.get("LLM_API_KEY", ""), model)
    if not d.detectable or d.value is None or d.authority not in llm_profiles.CONTEXT_SOURCES:
        return AutofillResult(None, None, d.detail, False)
    try:
        written = llm_profiles.set_profile_context_window(env_path, model, d.value, source=d.authority)
    except OSError as e:
        return AutofillResult(None, None, f"couldn't save the detected window ({e})", False)
    if not written:
        return AutofillResult(None, None, "profile not found in .env", False)
    values["LLM_CONTEXT_WINDOW"] = str(d.value)
    values["LLM_CONTEXT_SOURCE"] = d.authority
    return AutofillResult(d.value, d.authority, d.detail, True)


def describe(result: AutofillResult, model: str) -> str | None:
    """One status line for the UI, or None when nothing worth saying happened."""
    if result.saved:
        how = "reported by the provider" if result.source == "provider" else \
              "from the public catalog (the provider may allow less)"
        return f"Context window for {model}: {result.window:,}, {how} — saved."
    if result.window is None and "already set" not in result.detail:
        return (f"Couldn't detect the context window for {model} — using the safe default. "
                "Set it in Settings → Models.")
    return None
