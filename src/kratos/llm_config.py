"""
LLM Configuration for Kratos
=============================
Offline security analysis using either Qwen2.5-Coder 7B GGUF or Ollama.

SETUP INSTRUCTIONS:
===================
1. Download model (4.5 GB, ~5 min on fast connection):
   wget -O llm/models/qwen2.5-coder-7b-q4_k_m.gguf \\
        https://huggingface.co/Qwen/Qwen2.5-Coder-7B-GGUF/resolve/main/qwen2.5-coder-7b-q4_k_m.gguf

2. Or set a custom path:
   export KRATOS_LLM_MODEL_PATH=/path/to/your/model.gguf

3. Or use any OpenAI-chat-completions-compatible endpoint -- this is also
   the default with NO configuration at all, pointed at a local Ollama
   server (`ollama serve`, which speaks this same API):
    export LLM_BASE_URL=http://127.0.0.1:11434/v1   # default if unset
    export LLM_API_KEY=ollama                        # default if unset -- Ollama ignores the value
    export LLM_MODEL=qwen2.5:7b                       # default if unset
   Swapping to a different local server or a cloud provider (Gemini, etc.)
   is just swapping these same 3 values -- no other config changes needed.
   Explicitly select this backend (skipping local-GGUF auto-detection) with:
    export KRATOS_LLM_BACKEND=openai_compatible

4. Once configured, `kratos chat` will automatically use it.

WHY QWEN2.5-CODER:
- Purpose-built for technical reasoning (logs, configs, code)
- Superior to Llama for security analysis
- 7B parameters = good accuracy without massive overhead
- Q4 GGUF quantization = ~4.5 GB (suitable for 8+ GB RAM systems)
"""

from __future__ import annotations

import os
import os as _os
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

# Exported (not just inline) so adapters/llm_profiles.py's /model
# implementation reads/writes the exact same .env file this module loads
# from, rather than independently recomputing the repo-root path and
# risking drift if the directory layout ever changes.
ENV_FILE_PATH = Path(__file__).parent.parent.parent / ".env"

# Load .env (repo root) if present -- real secrets (e.g. LLM_API_KEY below)
# live there, gitignored, never in tracked config files. Safe to call even
# if .env doesn't exist or the vars are already set in the real environment
# (load_dotenv does not override existing env vars by default).
load_dotenv(ENV_FILE_PATH)

# ---------------------------------------------------------------------------
# Model path — portable, no hardcoded user/hostname
# Priority: KRATOS_LLM_MODEL_PATH env var → relative path next to package root
# ---------------------------------------------------------------------------
MODEL_NAME = "qwen2.5-coder-7b-q4_k_m.gguf"
_env_model = _os.environ.get("KRATOS_LLM_MODEL_PATH")
MODEL_PATH = (
    Path(_env_model)
    if _env_model
    else Path(__file__).parent.parent.parent / "llm" / "models" / MODEL_NAME
)

LLM_BACKEND = _os.environ.get("KRATOS_LLM_BACKEND", "auto").strip().lower()

# 2026-07-15 refactor: querying now always goes through ONE mechanism
# (LLM_BASE_URL/LLM_API_KEY/LLM_MODEL below, OpenAI-chat-completions-
# compatible) regardless of whether that endpoint happens to be a local
# Ollama server or a cloud provider -- there is no more Ollama-specific
# query wiring (no separate host/port/model env vars, no native /api/chat
# call). What remains here is ONLY process-management config for `kratos
# llm-serve` actually spawning/finding a local Ollama binary -- a genuinely
# different concern (starting a local process) from "what URL do I send
# chat requests to" (which cli/app.py's cmd_llm_serve derives from
# LLM_BASE_URL itself, so there's one source of truth, not two configs that
# could silently drift out of sync).
OLLAMA_BIN = _os.environ.get(
    "KRATOS_OLLAMA_BIN",
    str(Path.home() / ".local" / "ollama" / "bin" / "ollama"),
)

# When true, Kratos will start Ollama with its stdout/stderr redirected
# to log files to keep the calling terminal quiet. Set to "0" to keep
# Ollama output attached to the terminal (useful for debugging).
OLLAMA_QUIET = os.environ.get("KRATOS_OLLAMA_QUIET", "1") == "1"
# When True, Kratos will start Ollama as a detached background process.
# Default is False: Ollama runs in the foreground so the terminal remains
# attached and the user can Ctrl+C to stop it. Set to "1" to detach.
OLLAMA_DETACH = os.environ.get("KRATOS_OLLAMA_DETACH", "0") == "1"

# Server Configuration (llama-cpp-python or llamafile)
LLAMA_SERVER_HOST = "127.0.0.1"
LLAMA_SERVER_PORT = 8686
LLAMA_SERVER_URL = f"http://{LLAMA_SERVER_HOST}:{LLAMA_SERVER_PORT}"

# ---------------------------------------------------------------------------
# Inference Parameters
# LLAMA_TEMP = 0.1  (low) → near-deterministic output, reproducible for thesis
# LLAMA_SEED = 42   → fixed seed ensures same input → same output every run
#
# LLAMA_N_CTX default: measured real usage (agent/loop.py's ReAct investigation
# loop) hit ~4095 tokens by iteration 8 of 10 with the old 2048/4096 defaults --
# essentially no headroom, which correlated with the small model losing track
# of its own response format and hallucinating tool names near the end of a
# run. 6144 was verified (2026-07-11) to comfortably cover a full investigation
# with real headroom to spare -- see agent/loop.py's wrap-up nudge comments.
# ---------------------------------------------------------------------------
LLAMA_N_CTX = int(os.environ.get("KRATOS_LLM_N_CTX", "6144"))
LLAMA_N_GPU_LAYERS = 0       # 0 = CPU-only (no GPU required)
LLAMA_N_THREADS = min(os.cpu_count() or 4, 8)  # Use all vCPUs (capped at 8)
LLAMA_TEMP = 0.1             # Low: reproducible outputs (thesis requirement)
LLAMA_SEED = 42              # Fixed seed for determinism
LLAMA_TOP_P = 0.9
LLAMA_TOP_K = 40

# Timeouts and Limits
REQUEST_TIMEOUT_SECONDS = int(os.environ.get("KRATOS_LLM_REQUEST_TIMEOUT_SECONDS", "900"))
# 8192, not 1024: confirmed via Phase 3b.3/3b.4 real testing that 1024 makes
# every openai_fallback call (the name at the time -- see the openai_compatible
# backend section above; same code path today) against Gemini 2.5 Pro --
# including fully benign ones,
# not just long/complex prompts -- fail outright. Gemini's hidden reasoning
# tokens are drawn from this SAME budget before any visible output exists;
# a real write-step prompt (full system prompt + harness file, ~1500+ tokens
# of input alone) reliably exhausted 1024 with finish_reason="length" and
# ZERO completion tokens. This is the caller-supplied default only -- it's a
# ceiling, not a target, so it has no effect on local Ollama (which doesn't
# consume hidden reasoning tokens the same way) or on calls that already
# complete well under the old limit (e.g. agent/loop.py's tool-selection
# calls, which use MAX_TOKENS_QUESTION below, not this constant, and were
# never affected by this bug). See llm_interface.py::agent_chat's own
# max(max_tokens, 4096) floor, applied whenever the openai_compatible
# backend is in use (any reasoning-capable model behind it, not just
# Gemini specifically, since 2026-07-15's backend-wiring refactor unified
# what used to be a Gemini-only "openai_fallback" path), for the other half
# of this mitigation, and _query_openai_compatible's finish_reason="length"
# check for making a future recurrence self-diagnosing instead of a bare
# KeyError.
MAX_TOKENS = int(os.environ.get("KRATOS_LLM_MAX_TOKENS", "8192"))
MAX_TOKENS_QUESTION = int(os.environ.get("KRATOS_LLM_MAX_TOKENS_QUESTION", "512"))
STARTUP_TIMEOUT_SECONDS = 30

# If True, when server fast-path fails, Kratos tries loading model directly in-process.
# On low-power hardware this can look like a hang. Set to 0 to disable fallback.
FALLBACK_TO_DIRECT_LOAD = os.environ.get("KRATOS_LLM_FALLBACK_TO_DIRECT_LOAD", "1") == "1"

# ---------------------------------------------------------------------------
# OpenAI-compatible backend -- the one real query mechanism (2026-07-15)
#
# Points at any OpenAI-chat-completions-compatible endpoint: local Ollama
# (the default, see below), a local llama.cpp/vLLM server, or a cloud
# provider (Gemini, etc.) -- swapping model/backend is just swapping these
# 3 values, nothing else. This used to be a separate "openai_fallback"
# debugging-only path (Gemini specifically, opt-in via
# KRATOS_LLM_BACKEND=openai_fallback) layered on top of Ollama's own
# native-API query code; that native path is gone -- this is now the only
# way Kratos ever sends a chat completion once a server is reachable.
# Configure via .env (gitignored), not tracked config files.
#
# Defaults point at a local Ollama server with no configuration needed at
# all (Ollama has spoken this same OpenAI-compatible API for a while now,
# in addition to its own native one) -- "ollama" as the API key is a
# conventional non-empty placeholder Ollama itself documents; it never
# checks the value.
# ---------------------------------------------------------------------------
LLM_OPENAI_BASE_URL = os.environ.get("LLM_BASE_URL", "http://127.0.0.1:11434/v1")
LLM_OPENAI_API_KEY = os.environ.get("LLM_API_KEY", "ollama")
LLM_OPENAI_MODEL = os.environ.get("LLM_MODEL", "qwen2.5:7b")

# ---------------------------------------------------------------------------
# Live LLM-profile override (/model, 2026-07-18) -- same pattern as
# get_active_target()/set_active_target() in kratos_config.py (/target's
# live-switch mechanism), applied to the LLM backend instead of the SSH
# target. The LLM_OPENAI_*/LLM_BACKEND constants above stay frozen at their
# .env-load-time values (still correct as "what this process started
# with"); every ACTUAL query call site must read through the get_active_*
# functions below instead, so a mid-session /model switch takes effect on
# the very next LLM call, not just at the next process launch.
#
# Real bug this deliberately avoids reproducing (the exact failure class
# this task's own prompt named): llm_interface.py's from-import bindings
# (`from kratos.llm_config import LLM_OPENAI_MODEL`) are independent names
# in llm_interface's OWN module namespace -- reassigning llm_config's
# module-level constant would NOT be seen by llm_interface's already-bound
# copy. Function-based getters (called fresh on every use, not imported as
# frozen values) are the only correct fix -- confirmed by how /target's own
# earlier real bug ("investigations silently kept hitting the global
# default" -- see CLAUDE.md) was actually fixed, not a new pattern invented
# here.
_active_llm_override: dict[str, str] | None = None


def get_active_llm_base_url() -> str:
    return (_active_llm_override or {}).get("LLM_BASE_URL") or LLM_OPENAI_BASE_URL


def get_active_llm_api_key() -> str:
    return (_active_llm_override or {}).get("LLM_API_KEY") or LLM_OPENAI_API_KEY


def get_active_llm_model() -> str:
    return (_active_llm_override or {}).get("LLM_MODEL") or LLM_OPENAI_MODEL


def get_active_llm_backend() -> str:
    return (_active_llm_override or {}).get("KRATOS_LLM_BACKEND") or LLM_BACKEND


def set_active_llm_profile(values: dict[str, str]) -> None:
    """`values` keyed exactly like adapters/llm_profiles.py's EnvProfile.values
    (LLM_BASE_URL/LLM_API_KEY/LLM_MODEL/KRATOS_LLM_BACKEND, and optionally
    LLM_CONTEXT_WINDOW once the model-setup UI sets it) -- no re-keying needed
    between parsing a .env profile and activating it."""
    global _active_llm_override
    _active_llm_override = dict(values)


# ---------------------------------------------------------------------------
# Model-aware context window (the denominator for the 7c fill meter and the
# trigger budget for agent/loop.py's compaction). Because every getter here
# reads the LIVE-active profile, a /model switch changes the window
# automatically -- bigger model -> bigger budget -> less/no compaction;
# smaller model -> compaction adapts to fit on the next iteration (agent/loop
# re-reads this every step).
#
# Best-effort context windows for common cloud model families -- DEFAULTS only,
# deliberately CONSERVATIVE. The asymmetry matters: overclaiming a window risks
# a real overflow (the backend rejects/truncates an over-long prompt), while
# underclaiming only compacts a little early, which is harmless -- so on any
# uncertainty this map underclaims, and an unknown cloud model falls back to the
# small local budget rather than an optimistic guess. Substring-matched against
# the active model id; not exhaustive and WILL age, so an explicit value always
# wins (per-profile LLM_CONTEXT_WINDOW, e.g. from the model-setup UI, or a global
# KRATOS_LLM_CONTEXT_WINDOW env var).
_KNOWN_CLOUD_MODEL_WINDOWS: tuple[tuple[str, int], ...] = (
    ("gemini", 1_000_000),
    ("claude", 200_000),
    ("gpt-4.1", 1_000_000),
    ("gpt-4o", 128_000),
    ("gpt-4", 128_000),
    ("o1", 128_000),
    ("o3", 128_000),
    ("llama-3", 131_072),
    ("deepseek", 65_536),
    ("qwen3", 32_768),
    ("qwen2.5", 32_768),
    ("qwq", 32_768),
    ("mixtral", 32_768),
    ("mistral", 32_768),
)

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _active_backend_is_local() -> bool:
    """Local inference = the in-process llama.cpp path, or an OpenAI-compatible
    endpoint on loopback (a local Ollama / llama.cpp server). For local we use
    the deliberate LOCAL BUDGET (LLAMA_N_CTX), not a model's theoretical max --
    the project runs its local model at a measured 6144 on modest hardware, not
    32k+."""
    if get_active_llm_backend() == "llama_cpp":
        return True
    host = (urlparse(get_active_llm_base_url()).hostname or "").lower()
    return host in _LOCAL_HOSTS or host.startswith("127.")


def get_active_llm_context_window() -> int:
    """The active model's context window in tokens. Resolution order:
      1. an explicit value -- per-profile `LLM_CONTEXT_WINDOW` or the global
         `KRATOS_LLM_CONTEXT_WINDOW` env var -- the user / setup-UI always wins;
      2. local backend -> LLAMA_N_CTX, the deliberate local budget;
      3. cloud + a known model family -> its (conservative) real window;
      4. cloud + unknown -> LLAMA_N_CTX (safe: underclaiming only compacts early,
         overclaiming would risk a real overflow)."""
    if _active_llm_override is not None:
        # A live /model switch happened -> the switched profile's own value is
        # authoritative. Its ABSENCE must NOT fall back to os.environ's
        # LLM_CONTEXT_WINDOW, which was loaded from a DIFFERENT profile at
        # startup and is now stale.
        explicit = _active_llm_override.get("LLM_CONTEXT_WINDOW")
    else:
        # Fresh process, no switch yet -> the active profile's LLM_CONTEXT_WINDOW
        # as load_dotenv loaded it from .env.
        explicit = os.environ.get("LLM_CONTEXT_WINDOW")
    explicit = explicit or os.environ.get("KRATOS_LLM_CONTEXT_WINDOW")  # global manual override (fallback)
    if explicit and str(explicit).strip().isdigit():
        return int(str(explicit).strip())
    if _active_backend_is_local():
        return LLAMA_N_CTX
    model = get_active_llm_model().lower()
    for needle, window in _KNOWN_CLOUD_MODEL_WINDOWS:
        if needle in model:
            return window
    return LLAMA_N_CTX


# ---------------------------------------------------------------------------
# System Prompt
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_ANALYST = """You are Kratos, an offline AI security analyst.

CORE RULES:
1. Use ONLY data provided in the bundle — never invent IPs, ports, usernames, or counts.
2. Prioritize findings by actual risk, not just severity tags.
3. Show connections between findings (e.g. SSH exposure + brute-force = elevated risk).
4. Explain findings in plain language for junior administrators.
5. Every action step must be specific to this system's data.
6. If data is missing for a point, write: "Not available in bundle."

NEVER: invent statistics, claim certainty without evidence, recommend autonomous actions."""

# ---------------------------------------------------------------------------
# Prompts
# Summary uses structured Observation→Evidence→Risk→Action format to prevent
# generic ("educate users", "keep software updated") responses.
# ---------------------------------------------------------------------------
PROMPT_SUMMARIZE_FINDINGS = """Analyze this Kratos security bundle using the structure below.

**SYSTEM STATE** (1-2 sentences using exact values from the bundle)

**TOP FINDINGS** — repeat this block for each of the top 3 risks:

Finding [N]: <one-line label>
- Observation: <what the data shows — use exact numbers, IPs, or usernames from the bundle>
- Evidence: <quote the specific metric or value from the bundle>
- Risk: <why this matters for this specific system>
- Action: <one specific command or config step — not generic advice>

**OVERALL RISK LEVEL**: LOW / MEDIUM / HIGH
Rationale: <one sentence citing specific bundle values>

RULES:
- Every claim must reference a value from the bundle.
- Do NOT write generic advice like "educate users" or "keep software updated".
- If data is missing for a point, write: "Not available in bundle."

Bundle:
{bundle_text}"""

PROMPT_DEEP_ANALYSIS = """Perform a deep security analysis using only bundle data.

1. **Attack Chains**: What sequences of findings could lead to compromise?
2. **Blind Spots**: What is NOT being monitored (if evident from bundle)?
3. **Hardening Priorities**: Top 3 highest-impact changes with specific commands.
4. **Confidence Notes**: What assumptions did you make from incomplete data?

Data:
{bundle_text}

Be explicit about what data was and was not available."""

# ---------------------------------------------------------------------------
# UI Messages
# ---------------------------------------------------------------------------
MSG_LOADING = "[KRATOS-LLM] Starting offline LLM (Qwen2.5-Coder 7B)..."
MSG_READY = "[KRATOS-LLM] LLM ready."
MSG_THINKING = "[KRATOS-LLM] Analyzing security data..."
MSG_NO_MODEL = (
    "[KRATOS-LLM] Model not found: {path}\n\n"
    "Download (4.5 GB):\n"
    "  wget -O {path} \\\n"
    "    https://huggingface.co/Qwen/Qwen2.5-Coder-7B-GGUF/resolve/main/qwen2.5-coder-7b-q4_k_m.gguf\n\n"
    "Or use a custom path:\n"
    "  export KRATOS_LLM_MODEL_PATH=/path/to/your/model.gguf\n\n"
    "Or skip Hugging Face entirely and use a local Ollama server (the "
    "default -- no config needed if Ollama is already running on the "
    "default port):\n"
    "  ollama serve\n"
    "  export LLM_MODEL=qwen2.5:7b   # only if you want a model other than the default"
)
MSG_NO_FINDINGS = "[KRATOS-LLM] No findings to analyze. Run: kratos findings-generate"
