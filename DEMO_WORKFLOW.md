# Kratos Security Tool — Presentation Demo Workflow

## Complete presentation workflow

**Terminal A — keep open the whole time**
```bash
cd /home/ubuntu/kratos
source venv/bin/activate
set -a; source .env; set +a
set -a; source /home/ubuntu/kratos/.env; set +a
kratos llm-serve
```
Wait until you see: `Uvicorn running on http://127.0.0.1:8686`

---

**Terminal B — run the demo**

### Default behavior (uses latest artifacts)
```bash
cd /home/ubuntu/kratos
source venv/bin/activate
set -a; source .env; set +a

# Step 1 — full pipeline (scan + logs + context + findings)
kratos run --target 127.0.0.1

# Step 2 — show findings report
kratos findings-show

# Step 3 — AI summary of all findings
kratos chat --mode summary

# Step 4 — 3 specific questions to the LLM
kratos chat -q "What is the most urgent thing to fix?"
kratos chat -q "Explain the SSH risk in simple terms"
kratos chat -q "What attacker could do if SSH is compromised?"
```

---

### NEW: Date-filtered commands (demonstrate historical analysis)

#### Show February 2026 trends & findings
```bash
# View February auth failure trends
kratos logs-trends --since 20260201 --until 20260228

# Create a bundle from February data only
kratos prepare-bundle --since 20260201 --until 20260228 --max-words 1000

# Analyze February findings with AI
kratos chat --since 20260201 --until 20260228 -q "What were the main security issues in February?"
```

#### Show March 2026 trends & findings
```bash
# View March auth failure trends
kratos logs-trends --since 20260301 --until 20260331

# Create a bundle from March data only
kratos prepare-bundle --since 20260301 --until 20260331 --max-words 1000

# Analyze March findings with AI
kratos chat --since 20260301 --until 20260331 -q "What were the main security issues in March?"
```

#### Historical comparison — what improved/changed?
```bash
# February baseline
kratos chat --since 20260201 --until 20260228 -q "List the top 3 security findings from February"

# March current state
kratos chat --since 20260301 --until 20260331 -q "List the top 3 security findings from March"

# Direct comparison question
kratos chat --since 20260201 --until 20260331 -q "What security improvements happened between February and March?"

# Trend analysis question
kratos logs-trends --since 20260201 --until 20260331 && \
kratos chat --since 20260201 --until 20260331 -q "Are auth failures increasing or decreasing over the 2-month period?"
```

---

## Demo Flow Narrative

**Part 1: Current Security State (Latest)**
- Run full pipeline → show current findings
- Ask LLM 3 tactical questions
- *Message:* "Kratos can continuously monitor and answer questions about your security posture."

**Part 2: Multi-Month Historical Analysis (NEW)**
- Show February trends
- Show March trends
- Ask comparison questions
- *Message:* "Kratos tracks improvements over time. Here's what got better in March vs February..."

---

## Key Points for Presentation

- **Fully offline** — No cloud API calls, runs on Mixtile Blade 3 (weak ARM SBC)
- **Real-time AI** — Qwen2.5-Coder 7B provides instant security analysis
- **Date filtering** — Isolate findings by time period for multi-month deployments (no context explosion)
- **Backward compatible** — Date filter args are optional; default behavior unchanged
- **Thesis ready** — Demonstrates correlation finding types (10+), baseline drift, auth trends, BitNet optimization study

---

## Quick Reference: Command Patterns

```bash
# Latest (default)
kratos logs-trends --last 5
kratos prepare-bundle --max-words 500
kratos chat -q "Question?"

# Specific date range (new)
kratos logs-trends --since YYYYMMDD --until YYYYMMDD
kratos prepare-bundle --since YYYYMMDD --until YYYYMMDD
kratos chat --since YYYYMMDD --until YYYYMMDD -q "Question?"

# Examples
kratos prepare-bundle --since 20260101 --until 20260131  # January only
kratos chat --since 20260201 --until 20260228 -q "What happened in February?"
```

---

**That's the full demo — two terminals, zero cloud, fully offline.**
