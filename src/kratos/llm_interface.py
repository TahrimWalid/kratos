"""
LLM Interface - Offline Qwen2.5-Coder 7B Integration
"""
from __future__ import annotations
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from kratos.llm_config import (
    MODEL_PATH,
    LLAMA_SERVER_HOST,
    LLAMA_SERVER_PORT,
    LLAMA_SERVER_URL,
    LLAMA_N_CTX,
    get_active_llm_context_window,
    LLAMA_N_GPU_LAYERS,
    LLAMA_TEMP,
    LLAMA_SEED,
    LLAMA_N_THREADS,
    LLAMA_TOP_P,
    LLAMA_TOP_K,
    REQUEST_TIMEOUT_SECONDS,
    MAX_TOKENS,
    MAX_TOKENS_QUESTION,
    FALLBACK_TO_DIRECT_LOAD,
    STARTUP_TIMEOUT_SECONDS,
    SYSTEM_PROMPT_ANALYST,
    PROMPT_SUMMARIZE_FINDINGS,
    PROMPT_DEEP_ANALYSIS,
    MSG_LOADING,
    MSG_READY,
    MSG_THINKING,
    MSG_NO_MODEL,
    get_active_llm_base_url,
    get_active_llm_api_key,
    get_active_llm_model,
    get_active_llm_backend,
)
from kratos.utils.redact import redact_secrets


# ---------------------------------------------------------------------------
# Real token accounting (feature 7c). Every OpenAI-compatible / llama.cpp
# response carries a `usage` block ({prompt_tokens, completion_tokens,
# total_tokens}); the query functions used to read only the message content
# and throw usage away, so a UI context/token meter had nothing real to show
# and fell back to a char-based approximation.
#
# Exposed WITHOUT changing agent_chat()/analyze_findings()'s return contract
# (still `Optional[str]`) -- every existing caller (REPL routing, MCP,
# `kratos chat`, self_write, the ReAct loop) keeps working unchanged. New
# consumers read usage via the accessors below instead:
#   - get_last_token_usage()   : the most recent call -- for a context-fill
#                                meter (prompt_tokens vs get_context_window_tokens()).
#   - get_session_token_usage(): cumulative since the last reset -- for a
#                                running session-total meter.
#   - reset_session_token_usage(): front-ends call this at a boundary they own
#                                (e.g. session start / per turn).
# Serial-execution safe as module state, the same basis kratos_config's
# active-target override relies on: one `kratos` process runs one session at a
# time, and the MCP server serializes tool calls on a connection.
# ---------------------------------------------------------------------------
@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def add(self, other: "TokenUsage") -> None:
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.total_tokens += other.total_tokens

    def copy(self) -> "TokenUsage":
        return TokenUsage(self.prompt_tokens, self.completion_tokens, self.total_tokens)

    def as_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


_last_usage: Optional[TokenUsage] = None
_session_usage = TokenUsage()


def _record_usage(raw: Any) -> None:
    """Capture a response's `usage` block. Tolerant of a missing/partial/
    malformed block (some endpoints omit it) -- records nothing rather than
    raising into a query path. total_tokens is derived when the endpoint
    reports the two components but not the sum."""
    global _last_usage
    if not isinstance(raw, dict):
        return
    try:
        prompt = int(raw.get("prompt_tokens") or 0)
        completion = int(raw.get("completion_tokens") or 0)
        total = int(raw.get("total_tokens") or 0)
    except (TypeError, ValueError):
        return
    if total == 0 and (prompt or completion):
        total = prompt + completion
    usage = TokenUsage(prompt_tokens=prompt, completion_tokens=completion, total_tokens=total)
    _last_usage = usage
    _session_usage.add(usage)


def get_last_token_usage() -> Optional[TokenUsage]:
    """The most recent LLM call's real token usage, or None if no call has
    reported usage yet. Its `prompt_tokens` is the meaningful numerator for a
    context-fill meter (how much context was actually sent)."""
    return _last_usage.copy() if _last_usage is not None else None


def get_session_token_usage() -> TokenUsage:
    """Cumulative token usage since the last reset_session_token_usage()."""
    return _session_usage.copy()


def reset_session_token_usage() -> None:
    global _last_usage, _session_usage
    _last_usage = None
    _session_usage = TokenUsage()


def get_context_window_tokens() -> int:
    """The active model's context window -- the denominator for the fill meter
    (7c) and the trigger budget for agent/loop.py's compaction (14b). MODEL-AWARE
    (delegates to llm_config.get_active_llm_context_window()): it reads the
    live-active profile, so a /model switch changes it automatically -- a
    bigger-window model raises the budget (less/no compaction), a smaller one
    lowers it (compaction adapts to fit on the next loop iteration). Local stays
    at the deliberate LLAMA_N_CTX budget; an unknown cloud model underclaims to
    that same budget rather than risk overflow. See that resolver for the full
    order (explicit per-profile/env value > local budget > known cloud window >
    safe default)."""
    return get_active_llm_context_window()


def _is_llama_server_running() -> bool:
    """Check if the llama.cpp server is up AND the model is loaded."""
    if requests is None:
        return False
    try:
        resp = requests.get(f"{LLAMA_SERVER_URL}/v1/models", timeout=1)
        return resp.status_code == 200
    except Exception:
        return False


def _running_backend() -> Optional[str]:
    if _is_llama_server_running():
        return "llama_cpp"
    if _is_openai_compatible_running():
        return "openai_compatible"
    return None


def check_endpoint_reachable(base_url: str, api_key: str, timeout: float = 3) -> tuple[bool, Optional[str]]:
    """Real reachability probe for an OpenAI-compatible /models endpoint --
    generalized (2026-07-18) from what used to be _is_openai_compatible_running's
    own inline logic, so cli/repl.py's /model can probe a CANDIDATE profile
    BEFORE switching to it, not just whatever's already active. Returns
    (reachable, detail) -- detail is None on success, a short human-
    readable reason on failure (status code / timeout / connection error),
    never a raw exception dump (redacted the same way
    _query_openai_compatible's own error path already is, since a raw dump
    could otherwise embed the key).

    Sends the same Authorization header _query_openai_compatible's real
    call uses -- real bug, not hypothetical (found live, 2026-07-16): a
    profile pointed at Gemini with a real, working key (confirmed directly
    via curl: an authenticated GET to this exact endpoint returns 200) still
    failed here, because this probe sent no auth header at all and Gemini's
    endpoint returns 404 (not a timeout, not 401/403) for an unauthenticated
    /models request -- so agent_chat/analyze_findings concluded "unreachable"
    and never even attempted the real, would-have-succeeded query. Harmless
    for local Ollama (no auth required there), which is why this went
    unnoticed until a real cloud profile was actually exercised end-to-end.
    """
    if requests is None:
        return False, "the `requests` package is not installed"
    try:
        resp = requests.get(
            f"{base_url.rstrip('/')}/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return True, None
        return False, f"HTTP {resp.status_code}"
    except requests.exceptions.Timeout:
        return False, f"timed out after {timeout}s"
    except requests.exceptions.ConnectionError:
        return False, "connection refused/unreachable"
    except Exception as e:
        return False, redact_secrets(str(e), api_key)


def _is_openai_compatible_running() -> bool:
    """Same check as _is_llama_server_running, generalized to whatever
    endpoint LLM_BASE_URL points at (local Ollama by default, or anything
    else) -- Ollama, like llama.cpp's own server, implements the OpenAI
    /models list endpoint alongside its native API. Thin wrapper around
    check_endpoint_reachable, always against the CURRENTLY ACTIVE profile
    -- see that function's own docstring for the real-bug history behind
    the auth header."""
    reachable, _ = check_endpoint_reachable(get_active_llm_base_url(), get_active_llm_api_key())
    return reachable


def _local_model_ready() -> bool:
    return MODEL_PATH.exists() and MODEL_PATH.stat().st_size > 0


def _resolved_backend() -> str:
    backend = (get_active_llm_backend() or "auto").strip().lower()
    if backend in {"llama_cpp", "openai_compatible"}:
        return backend
    if _local_model_ready():
        return "llama_cpp"
    return "openai_compatible"


def _query_server(prompt: str, system_prompt: str, max_tokens: int) -> Optional[str]:
    """Send a chat completions request to the running llama-cpp-python server."""
    if requests is None:
        return None
    try:
        resp = requests.post(
            f"{LLAMA_SERVER_URL}/v1/chat/completions",
            json={
                "model": MODEL_PATH.stem,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": LLAMA_TEMP,
                "top_p": LLAMA_TOP_P,
                "seed": LLAMA_SEED,
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        body = resp.json()
        _record_usage(body.get("usage"))
        return body["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[KRATOS-LLM] Server query error: {e}", file=sys.stderr)
        return None


# Retry/backoff for transient failures only (2026-07-16, real A/B test
# finding -- see docs/history for the interleaved-payload-size test that
# found this): a single 503/429/connection blip used to kill the entire
# call with zero resilience, and large system prompts (e.g. the ~4,200-token
# investigate prompt vs. a ~170-token routing prompt) were confirmed
# empirically far more likely to hit one -- consistent with provider-side
# load-shedding of the more expensive request, not random flakiness. This
# is NOT backend-specific: the same one-shot-no-retry gap exists for the
# local Ollama path too, it's just far less likely to hit a transient
# connection error there in practice.
#
# 3 total attempts (initial + 2 retries): matches this project's existing
# retry-budget convention elsewhere (self_write_loop's MAX_ATTEMPTS=3,
# agent/loop.py's guard retries ~2x) rather than picking a new number --
# enough to ride out a single transient blip without materially extending
# a genuinely-down backend's failure latency. Short fixed backoff (1s, 2s)
# between attempts -- long enough to not hammer an already-loaded endpoint,
# short enough not to meaningfully add to real per-call latency (already
# tens of seconds) on the common single-retry-then-succeeds case.
_MAX_LLM_ATTEMPTS = 3
_LLM_RETRY_BACKOFF_SECONDS = (1, 2)
_RETRYABLE_HTTP_STATUS_CODES = {429, 503}


def _describe_retryable_error(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.HTTPError) and exc.response is not None:
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection error"
    return type(exc).__name__


def _is_retryable_llm_error(exc: Exception) -> bool:
    if isinstance(exc, requests.exceptions.HTTPError):
        status = exc.response.status_code if exc.response is not None else None
        return status in _RETRYABLE_HTTP_STATUS_CODES
    # Connection-level errors (refused/reset/DNS) and timeouts are always
    # transient by nature -- retrying is the whole point. Anything else
    # (JSON decode errors, KeyError on a malformed 200 body, etc.) is left
    # non-retryable: a malformed response isn't fixed by asking again, and
    # retrying it would just add latency to a real error, same as a 4xx.
    return isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))


def _render_retry_note(attempt: int, exc: Exception) -> None:
    """Visible, dim retry status via the shared console renderer -- retries
    must never be silent (2026-07-16 requirement). Lazy import: avoids any
    module-load-order assumption between llm_interface.py and agent/console.py,
    and this path only runs on the (uncommon) retry case."""
    try:
        from kratos.agent import console as _console

        _console.render_note(
            _console.get_console(),
            f"LLM call failed ({_describe_retryable_error(exc)}) -- "
            f"retrying ({attempt + 1}/{_MAX_LLM_ATTEMPTS})...",
        )
    except Exception:
        pass


def _query_openai_compatible(prompt: str, system_prompt: str, max_tokens: int) -> Optional[str]:
    """
    Query LLM_OPENAI_BASE_URL, the one real query mechanism (2026-07-15) --
    any OpenAI-chat-completions-compatible endpoint: local Ollama (the
    default), a local llama.cpp/vLLM server, or a cloud provider. This
    replaced a separate Ollama-native /api/chat code path -- Ollama already
    speaks this same OpenAI-compatible API, so there is now exactly one
    query mechanism regardless of which endpoint LLM_BASE_URL points at.

    Retries transient failures (HTTP 429/503, connection errors, timeouts)
    up to _MAX_LLM_ATTEMPTS total attempts with a short fixed backoff --
    see _MAX_LLM_ATTEMPTS's own comment for why. Non-transient errors (4xx
    other than 429, a malformed response body) fail on the first attempt,
    unchanged from before.
    """
    if requests is None:
        return None
    base_url = get_active_llm_base_url()
    api_key = get_active_llm_api_key()
    model = get_active_llm_model()
    if not (base_url and api_key and model):
        print(
            "[KRATOS-LLM] LLM_BASE_URL/LLM_API_KEY/LLM_MODEL are not all set (check .env) -- "
            "these have defaults pointing at a local Ollama server, so this normally only "
            "happens if one was explicitly set to an empty value.",
            file=sys.stderr,
        )
        return None

    for attempt in range(_MAX_LLM_ATTEMPTS):
        try:
            resp = requests.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                },
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            body = resp.json()
            # Record real usage regardless of whether content came back --
            # a length-truncated reasoning response (content is None, below)
            # still consumed real tokens worth reflecting in a meter.
            _record_usage(body.get("usage"))
            choice = body["choices"][0]
            content = choice.get("message", {}).get("content")
            if content is None:
                # Confirmed real failure mode (Phase 3b.3, originally found
                # against Gemini 2.5 Pro but applies to any reasoning-capable
                # model behind this same endpoint): a reasoning model can spend
                # its entire max_tokens budget on hidden "thinking" tokens
                # before producing any visible output -- HTTP 200,
                # finish_reason="length", completion_tokens=0, and a message
                # dict with no "content" key at all. Left unhandled, the
                # dict-index access above raised a bare `KeyError: 'content'`
                # that gave no indication WHY -- indistinguishable from a real
                # network/API failure. Surface the actual cause instead.
                # Not retried -- a real 200 response, retrying the identical
                # request would very likely burn the budget the same way again.
                finish_reason = choice.get("finish_reason")
                if finish_reason == "length":
                    print(
                        "[KRATOS-LLM] openai_compatible query error: generation truncated by "
                        f"max_tokens (max_tokens={max_tokens}) -- no output produced, likely because "
                        "hidden reasoning tokens consumed the entire budget. Consider raising "
                        "KRATOS_LLM_MAX_TOKENS.",
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"[KRATOS-LLM] openai_compatible query error: response had no content "
                        f"(finish_reason={finish_reason!r}) -- raw message: {choice.get('message')}",
                        file=sys.stderr,
                    )
                return None
            return content.strip()
        except Exception as e:
            if _is_retryable_llm_error(e) and attempt < _MAX_LLM_ATTEMPTS - 1:
                _render_retry_note(attempt, e)
                time.sleep(_LLM_RETRY_BACKOFF_SECONDS[attempt])
                continue
            # Explicit redaction guard, not a reaction to a confirmed leak --
            # real testing (ConnectionError/HTTPError/Timeout/JSONDecodeError,
            # the realistic failure modes here) found requests's own exception
            # __str__ methods don't currently embed the Authorization header.
            # Applied anyway so a future exception type or a raw
            # request/response dump can't silently reintroduce a real one.
            print(f"[KRATOS-LLM] openai_compatible query error: {redact_secrets(str(e), api_key)}", file=sys.stderr)
            return None
    return None


class LLMServer:
    """Manages Qwen2.5-Coder local inference via llama-cpp-python."""

    def __init__(self):
        self._llama = None
        self.is_ready = False

    def start(self) -> bool:
        """Load the model. Returns True if successful."""
        backend = _resolved_backend()

        if backend == "openai_compatible":
            # Nothing to load in-process for an HTTP endpoint -- if
            # _running_backend() didn't already detect it as reachable
            # (agent_chat/analyze_findings only reach here when it didn't),
            # there is no cold-start fallback available the way there is
            # for a local GGUF file. Surface a clear, actionable error
            # instead of silently trying something else.
            print(
                f"[KRATOS-LLM] No OpenAI-compatible endpoint reachable at {get_active_llm_base_url()}. "
                "If this should be a local Ollama server, start it with `kratos llm-serve` "
                "(or `ollama serve` directly) and check LLM_BASE_URL matches where it's "
                "listening.",
                file=sys.stderr,
            )
            return False

        if not _local_model_ready():
            print(MSG_NO_MODEL.format(path=MODEL_PATH), file=sys.stderr)
            return False

        print(MSG_LOADING, file=sys.stderr)
        try:
            from llama_cpp import Llama
            self._llama = Llama(
                model_path=str(MODEL_PATH),
                n_ctx=LLAMA_N_CTX,
                n_gpu_layers=LLAMA_N_GPU_LAYERS,
                n_threads=LLAMA_N_THREADS,
                seed=LLAMA_SEED,
                verbose=False,
            )
            print(MSG_READY, file=sys.stderr)
            self.is_ready = True
            return True
        except Exception as e:
            print(f"[KRATOS-LLM] Failed to load model: {e}", file=sys.stderr)
            return False

    def infer(
        self,
        prompt: str,
        system_prompt: str = SYSTEM_PROMPT_ANALYST,
        max_tokens: int = MAX_TOKENS,
    ) -> Optional[str]:
        """Submit prompt and get response."""
        backend = _resolved_backend()

        if backend == "openai_compatible":
            # Defensive, not reachable in practice: start() above already
            # returns False for this backend, so callers' own
            # `if not self.is_ready and not server.start(): return None`
            # guard means infer() is never actually called here. Kept
            # explicit rather than silently falling through to the
            # llama_cpp-specific code below, which would be actively wrong
            # (no model_path was ever validated or loaded for this backend).
            return None

        if not self.is_ready or self._llama is None:
            return None

        print(MSG_THINKING, file=sys.stderr)

        # Qwen2.5 chat format
        full_prompt = (
            f"<|im_start|>system\n{system_prompt}<|im_end|>\n"
            f"<|im_start|>user\n{prompt}<|im_end|>\n"
            f"<|im_start|>assistant\n"
        )

        try:
            response = self._llama(
                full_prompt,
                max_tokens=max_tokens,
                temperature=LLAMA_TEMP,
                top_p=LLAMA_TOP_P,
                top_k=LLAMA_TOP_K,
                stop=["<|im_end|>", "<|im_start|>"],
            )
            _record_usage(response.get("usage"))
            return response["choices"][0]["text"].strip()
        except Exception as e:
            print(f"[KRATOS-LLM] Inference error: {e}", file=sys.stderr)
            return None

    def shutdown(self):
        """Free model resources."""
        self._llama = None
        self.is_ready = False


_llm_server: Optional[LLMServer] = None


def get_llm_server() -> LLMServer:
    global _llm_server
    if _llm_server is None:
        _llm_server = LLMServer()
    return _llm_server


def agent_chat(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = MAX_TOKENS,
) -> Optional[str]:
    """
    Raw single-turn chat completion for the ReAct agent loop.

    Unlike analyze_findings, this sends system_prompt/user_prompt as-is with no
    summarize/deep-analysis templating, so callers (e.g. agent/loop.py) can
    manage their own evolving conversation text turn by turn.
    """
    running_backend = _running_backend()
    if running_backend is not None:
        # Sprint 3 UI polish (2026-07-16): this used to print
        # "[KRATOS-LLM] Using running LLM server (fast path)..." on every
        # single call -- redundant noise once per investigate-loop iteration
        # (cmd_investigate's own "Kratos is working..." spinner already
        # signals this) and equally redundant for self_write.py's write
        # step (an internal "which code path" detail, not something a
        # human reviewing a self-write run needs repeated). Removed here
        # only -- analyze_findings's identical line (used by `kratos chat`,
        # out of Sprint 3's CLI-overhaul scope) is untouched.
        if running_backend == "openai_compatible":
            # Reasoning-capable models behind this endpoint (e.g. Gemini 2.5
            # Pro) spend hidden "thinking" tokens out of the same max_tokens
            # budget before any visible output -- a trivial one-word reply
            # already used ~120 total tokens in testing. The caller's
            # max_tokens is tuned for a non-reasoning local model and would
            # starve a reasoning model into returning empty content. Boost
            # the floor here only; harmless for local Ollama too (just a
            # higher output ceiling, not a behavior change).
            result = _query_openai_compatible(user_prompt, system_prompt, max(max_tokens, 4096))
        else:
            result = _query_server(user_prompt, system_prompt, max_tokens)
        if result is not None:
            return result
        if not FALLBACK_TO_DIRECT_LOAD:
            print(
                "[KRATOS-LLM] Server query failed and direct fallback is disabled. "
                "Increase KRATOS_LLM_REQUEST_TIMEOUT_SECONDS or reduce max tokens.",
                file=sys.stderr,
            )
            return None
        if running_backend == "llama_cpp":
            print("[KRATOS-LLM] Server query failed — falling back to direct load.", file=sys.stderr)

    server = get_llm_server()
    if not server.is_ready and not server.start():
        return None

    return server.infer(user_prompt, system_prompt, max_tokens)


def analyze_findings(
    bundle_text: str,
    mode: str = "summary",
    system_prompt: str = SYSTEM_PROMPT_ANALYST,
    max_tokens: int = MAX_TOKENS,
    is_custom_question: bool = False,
) -> Optional[str]:
    """
    Analyze Kratos findings bundle with Qwen2.5-Coder.

    Args:
        bundle_text: Prepared bundle from kratos prepare-bundle, or custom question+data
        mode: "summary" (executive) or "deep" (attack chains + blind spots)
        system_prompt: Override default system prompt if needed
        is_custom_question: If True, use bundle_text as-is (don't apply template)

    Returns:
        LLM analysis text, or None if failed
    """
    if is_custom_question:
        # Use the question directly without templating
        prompt = bundle_text
    elif mode == "deep":
        prompt = PROMPT_DEEP_ANALYSIS.format(bundle_text=bundle_text)
    else:
        prompt = PROMPT_SUMMARIZE_FINDINGS.format(bundle_text=bundle_text)

    # Fast path: use running llm-serve server (model already loaded)
    running_backend = _running_backend()
    if running_backend is not None:
        print("[KRATOS-LLM] Using running LLM server (fast path)...", file=sys.stderr)
        if running_backend == "openai_compatible":
            # See agent_chat's identical comment: boosts the floor for
            # reasoning-capable models behind this endpoint, harmless for
            # local Ollama.
            result = _query_openai_compatible(prompt, system_prompt, max(max_tokens, 4096))
        else:
            result = _query_server(prompt, system_prompt, max_tokens)
        if result is not None:
            return result
        if not FALLBACK_TO_DIRECT_LOAD:
            print(
                "[KRATOS-LLM] Server query failed and direct fallback is disabled. "
                "Increase KRATOS_LLM_REQUEST_TIMEOUT_SECONDS or reduce max tokens.",
                file=sys.stderr,
            )
            return None
        if running_backend == "llama_cpp":
            print("[KRATOS-LLM] Server query failed — falling back to direct load.", file=sys.stderr)

    # Slow path: load model directly (cold start ~2 min)
    server = get_llm_server()
    if not server.is_ready and not server.start():
        return None

    return server.infer(prompt, system_prompt, max_tokens)


def shutdown_llm():
    """Shutdown and free model memory."""
    global _llm_server
    if _llm_server:
        _llm_server.shutdown()
        _llm_server = None
