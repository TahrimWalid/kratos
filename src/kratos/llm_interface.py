"""
LLM Interface - Offline Qwen2.5-Coder 7B Integration
"""
from __future__ import annotations
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from kratos.llm_config import (
    MODEL_PATH,
    LLM_BACKEND,
    LLAMA_SERVER_HOST,
    LLAMA_SERVER_PORT,
    LLAMA_SERVER_URL,
    LLAMA_N_CTX,
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
    LLM_OPENAI_BASE_URL,
    LLM_OPENAI_API_KEY,
    LLM_OPENAI_MODEL,
)
from kratos.utils.redact import redact_secrets


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


def _is_openai_compatible_running() -> bool:
    """Same check as _is_llama_server_running, generalized to whatever
    endpoint LLM_BASE_URL points at (local Ollama by default, or anything
    else) -- Ollama, like llama.cpp's own server, implements the OpenAI
    /models list endpoint alongside its native API."""
    if requests is None:
        return False
    try:
        resp = requests.get(f"{LLM_OPENAI_BASE_URL.rstrip('/')}/models", timeout=1)
        return resp.status_code == 200
    except Exception:
        return False


def _local_model_ready() -> bool:
    return MODEL_PATH.exists() and MODEL_PATH.stat().st_size > 0


def _resolved_backend() -> str:
    backend = (LLM_BACKEND or "auto").strip().lower()
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
                "model": "qwen2.5-coder",
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
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[KRATOS-LLM] Server query error: {e}", file=sys.stderr)
        return None


def _query_openai_compatible(prompt: str, system_prompt: str, max_tokens: int) -> Optional[str]:
    """
    Query LLM_OPENAI_BASE_URL, the one real query mechanism (2026-07-15) --
    any OpenAI-chat-completions-compatible endpoint: local Ollama (the
    default), a local llama.cpp/vLLM server, or a cloud provider. This
    replaced a separate Ollama-native /api/chat code path -- Ollama already
    speaks this same OpenAI-compatible API, so there is now exactly one
    query mechanism regardless of which endpoint LLM_BASE_URL points at.
    """
    if requests is None:
        return None
    if not (LLM_OPENAI_BASE_URL and LLM_OPENAI_API_KEY and LLM_OPENAI_MODEL):
        print(
            "[KRATOS-LLM] LLM_BASE_URL/LLM_API_KEY/LLM_MODEL are not all set (check .env) -- "
            "these have defaults pointing at a local Ollama server, so this normally only "
            "happens if one was explicitly set to an empty value.",
            file=sys.stderr,
        )
        return None
    try:
        resp = requests.post(
            f"{LLM_OPENAI_BASE_URL.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {LLM_OPENAI_API_KEY}"},
            json={
                "model": LLM_OPENAI_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        choice = resp.json()["choices"][0]
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
        # Explicit redaction guard, not a reaction to a confirmed leak --
        # real testing (ConnectionError/HTTPError/Timeout/JSONDecodeError,
        # the realistic failure modes here) found requests's own exception
        # __str__ methods don't currently embed the Authorization header.
        # Applied anyway so a future exception type or a raw
        # request/response dump can't silently reintroduce a real one.
        print(f"[KRATOS-LLM] openai_compatible query error: {redact_secrets(str(e), LLM_OPENAI_API_KEY)}", file=sys.stderr)
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
                f"[KRATOS-LLM] No OpenAI-compatible endpoint reachable at {LLM_OPENAI_BASE_URL}. "
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
        print("[KRATOS-LLM] Using running LLM server (fast path)...", file=sys.stderr)
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
