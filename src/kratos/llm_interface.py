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
    STARTUP_TIMEOUT_SECONDS,
    SYSTEM_PROMPT_ANALYST,
    PROMPT_SUMMARIZE_FINDINGS,
    PROMPT_DEEP_ANALYSIS,
    MSG_LOADING,
    MSG_READY,
    MSG_THINKING,
    MSG_NO_MODEL,
    MSG_NO_SERVER,
    MSG_TIMEOUT,
)


class LLMServer:
    """Manages Qwen2.5-Coder local inference via llama-cpp-python."""

    def __init__(self):
        self._llama = None
        self.is_ready = False

    def start(self) -> bool:
        """Load the model. Returns True if successful."""
        if not MODEL_PATH.exists():
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


def analyze_findings(
    bundle_text: str,
    mode: str = "summary",
    system_prompt: str = SYSTEM_PROMPT_ANALYST,
    max_tokens: int = MAX_TOKENS,
) -> Optional[str]:
    """
    Analyze Kratos findings bundle with Qwen2.5-Coder.

    Args:
        bundle_text: Prepared bundle from kratos prepare-bundle
        mode: "summary" (executive) or "deep" (attack chains + blind spots)
        system_prompt: Override default system prompt if needed

    Returns:
        LLM analysis text, or None if failed
    """
    server = get_llm_server()
    if not server.is_ready and not server.start():
        return None

    if mode == "deep":
        prompt = PROMPT_DEEP_ANALYSIS.format(bundle_text=bundle_text)
    else:
        prompt = PROMPT_SUMMARIZE_FINDINGS.format(bundle_text=bundle_text)

    return server.infer(prompt, system_prompt, max_tokens)


def shutdown_llm():
    """Shutdown and free model memory."""
    global _llm_server
    if _llm_server:
        _llm_server.shutdown()
        _llm_server = None
