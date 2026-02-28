"""
LLM Configuration for Kratos - Offline Qwen2.5-Coder 7B
"""
from __future__ import annotations
from pathlib import Path

MODEL_NAME = "qwen2.5-coder-7b-q4_k_m.gguf"
MODEL_PATH = Path("/home/ubuntu/kratos/llm/models") / MODEL_NAME

LLAMA_SERVER_HOST = "127.0.0.1"
LLAMA_SERVER_PORT = 8686
LLAMA_SERVER_URL = f"http://{LLAMA_SERVER_HOST}:{LLAMA_SERVER_PORT}"

LLAMA_N_CTX = 2048
LLAMA_N_GPU_LAYERS = 0
LLAMA_TEMP = 0.7
LLAMA_TOP_P = 0.9
LLAMA_TOP_K = 40
REQUEST_TIMEOUT_SECONDS = 120
MAX_TOKENS = 1024
STARTUP_TIMEOUT_SECONDS = 30

SYSTEM_PROMPT_ANALYST = """You are Kratos, an offline AI security analyst.

CORE RULES:
1. Use ONLY data in the bundle - never invent IPs, ports, usernames, or counts.
2. Prioritize findings by actual risk, not just severity tags.
3. Show connections between findings (e.g. SSH exposure + brute-force = elevated risk).
4. Explain findings in plain language for junior admins.
5. End with numbered, prioritized action steps.
6. If data is missing, say "Not available in provided data".

NEVER: invent statistics, claim certainty without evidence, recommend autonomous actions."""

PROMPT_SUMMARIZE_FINDINGS = """Analyze this Kratos security bundle and provide:

1. **Current State** (2 sentences): What is the security situation?
2. **Top 3 Risks** (one paragraph each): What matters most and why?
3. **Immediate Actions** (5 numbered steps): What to do right now?
4. **Overall Risk Level**: LOW / MEDIUM / HIGH - explain your reasoning.

Bundle:
{bundle_text}

Use actual values from the bundle. Be concise and actionable."""

PROMPT_DEEP_ANALYSIS = """Perform a deep security analysis:

1. **Attack Chains**: What sequences of findings could lead to compromise?
2. **Blind Spots**: What is NOT being monitored (if evident)?
3. **Hardening Priorities**: Top 3 highest-impact changes.
4. **Confidence Notes**: What assumptions did you make from incomplete data?

Data:
{bundle_text}"""

MSG_LOADING = "[KRATOS-LLM] Starting offline LLM (Qwen2.5-Coder 7B)..."
MSG_READY = "[KRATOS-LLM] LLM ready."
MSG_THINKING = "[KRATOS-LLM] Analyzing security data..."
MSG_NO_MODEL = "[KRATOS-LLM] Model not found: {path}\n\nDownload: wget -O /home/ubuntu/kratos/llm/models/qwen2.5-coder-7b-q4_k_m.gguf https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF/resolve/main/qwen2.5-coder-7b-instruct-q4_k_m.gguf"
MSG_NO_SERVER = "[KRATOS-LLM] Failed to start LLM. Check: disk space (5GB+ free), port 8686 not in use."
MSG_TIMEOUT = "[KRATOS-LLM] LLM timed out (CPU inference is slow). Retry."
MSG_NO_FINDINGS = "[KRATOS-LLM] No findings to analyze. Run: kratos findings-generate"
