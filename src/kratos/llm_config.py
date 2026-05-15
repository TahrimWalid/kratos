"""
LLM Configuration for Kratos
=============================
Offline security analysis using Qwen2.5-Coder 7B (GGUF quantized).

SETUP INSTRUCTIONS:
===================
1. Download model (4.5 GB, ~5 min on fast connection):
   wget -O llm/models/qwen2.5-coder-7b-q4_k_m.gguf \\
        https://huggingface.co/Qwen/Qwen2.5-Coder-7B-GGUF/resolve/main/qwen2.5-coder-7b-q4_k_m.gguf

2. Or set a custom path:
   export KRATOS_LLM_MODEL_PATH=/path/to/your/model.gguf

3. Once placed, kratos chat will automatically use it.

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

# Server Configuration (llama-cpp-python or llamafile)
LLAMA_SERVER_HOST = "127.0.0.1"
LLAMA_SERVER_PORT = 8686
LLAMA_SERVER_URL = f"http://{LLAMA_SERVER_HOST}:{LLAMA_SERVER_PORT}"

# ---------------------------------------------------------------------------
# Inference Parameters
# LLAMA_TEMP = 0.1  (low) → near-deterministic output, reproducible for thesis
# LLAMA_SEED = 42   → fixed seed ensures same input → same output every run
# ---------------------------------------------------------------------------
<<<<<<< HEAD
LLAMA_N_CTX = 2048          # Context window (2048 needed for full bundle + prompt)
=======
LLAMA_N_CTX = int(os.environ.get("KRATOS_LLM_N_CTX", "2048"))
>>>>>>> 41c3549 (Initialize Blade 3 feature branch with edge-optimized config)
LLAMA_N_GPU_LAYERS = 0       # 0 = CPU-only (no GPU required)
LLAMA_N_THREADS = min(os.cpu_count() or 4, 8)  # Use all vCPUs (capped at 8)
LLAMA_TEMP = 0.1             # Low: reproducible outputs (thesis requirement)
LLAMA_SEED = 42              # Fixed seed for determinism
LLAMA_TOP_P = 0.9
LLAMA_TOP_K = 40

# Timeouts and Limits
<<<<<<< HEAD
REQUEST_TIMEOUT_SECONDS = 120   # CPU inference is slower
MAX_TOKENS = 1024
MAX_TOKENS_QUESTION = 512  # Shorter answers for -q mode
STARTUP_TIMEOUT_SECONDS = 30

=======
REQUEST_TIMEOUT_SECONDS = int(os.environ.get("KRATOS_LLM_REQUEST_TIMEOUT_SECONDS", "120"))
MAX_TOKENS = int(os.environ.get("KRATOS_LLM_MAX_TOKENS", "1024"))
MAX_TOKENS_QUESTION = int(os.environ.get("KRATOS_LLM_MAX_TOKENS_QUESTION", "512"))
STARTUP_TIMEOUT_SECONDS = 30

# If True, when server fast-path fails, Kratos tries loading model directly in-process.
# On low-power hardware this can look like a hang. Set to 0 to disable fallback.
FALLBACK_TO_DIRECT_LOAD = os.environ.get("KRATOS_LLM_FALLBACK_TO_DIRECT_LOAD", "1") == "1"

>>>>>>> 41c3549 (Initialize Blade 3 feature branch with edge-optimized config)
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
    "  export KRATOS_LLM_MODEL_PATH=/path/to/your/model.gguf"
)
MSG_NO_SERVER = "[KRATOS-LLM] Failed to start LLM. Check: disk space (5 GB+ free), port 8686 not in use."
MSG_TIMEOUT = "[KRATOS-LLM] LLM timed out (CPU inference is slow). Retry."
MSG_NO_FINDINGS = "[KRATOS-LLM] No findings to analyze. Run: kratos findings-generate"
