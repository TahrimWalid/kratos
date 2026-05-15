# Kratos — Offline AI Security Assistant

> Bachelor's thesis prototype · v0.1 · February 2026

Kratos is a fully offline Linux security analysis tool that collects,
correlates, and explains security findings using a local LLM — no cloud,
no internet, no external APIs required.

It is designed for administrators and security-conscious developers who need
meaningful, explainable security insights on systems that cannot or should
not phone home. The LLM layer bridges the gap between raw machine findings
and plain-language recommendations that a junior administrator can act on.

---

## Why Kratos

**Explainability** — All findings come from transparent, rule-based correlation.
Every security alert cites specific evidence: which ports are exposed, which
files show the patterns, what changed since baseline. No ML black boxes.

**Offline-First** — Zero external API calls. Works on air-gapped networks,
privacy-critical environments, and systems where data leaving the machine is
a compliance violation. Model and all dependencies are local.

**Edge Deployment** — Runs on resource-constrained hardware (8 GB RAM, CPU-only).
Successfully tested on Mixtile Blade 3 (ARM64, 16 GB). Suitable for edge
security, IoT gateways, and embedded threat detection.

**Reproducible** — Deterministic output. Same input + same seed = same findings.
Built for security audits, compliance reviews, and malware analysis where
repeatability matters.

**Full Audit Trail** — All artifacts timestamped and stored in `data/` directory.
Every report is traceable to the specific scan, logs, and context snapshots
used to generate it. No hidden derivations.

---

## Use Cases

- **Periodic security reviews** on infrastructure where manual log analysis is
  too slow or error-prone
- **Edge device monitoring** — SSH monitoring and breach detection on remote
  hardware without shipping logs to a central server
- **Compliance audits** — Generate timestamped, reproducible security reports
  with full evidence chain
- **Air-gapped systems** — Security analysis that never touches the internet or
  external APIs
- **Security awareness training** — Learn how correlation rules work by running
  them on synthetic or lab scenarios

---
=======
>>>>>>> 41c3549 (Initialize Blade 3 feature branch with edge-optimized config)
## How It Works

Kratos runs a five-stage pipeline entirely on the local machine:

```
[Scan]──►[Logs]──►[Context]──►[Findings]──►[LLM Chat]
  nmap     auth.log   OS/users    correlate    Qwen2.5-Coder 7B
  XML      parsing    services    + baseline   explains in plain English
```

1. **Scan** — Runs `nmap -sV` against a target IP and saves structured output
2. **Logs** — Parses `/var/log/auth.log` into structured events + detects
   burst patterns (e.g. 22 failed SSH logins in 4 minutes)
3. **Context** — Snapshots the system: OS, kernel, active services, sudo
   users, network interfaces, environment type (native/WSL/VM)
4. **Findings** — Correlates data across all sources using built-in rules
   and generates a severity-ranked report (JSON + Markdown)
5. **Chat** — Loads the findings into a local Qwen2.5-Coder 7B model and
   produces structured, grounded analysis in plain language

All outputs are timestamped and stored in `data/` for full traceability.

---

## Correlation Rules

Kratos detects the following finding types automatically:

| ID | Severity | What it detects |
|----|----------|----------------|
| `CORR-SSH-001` | HIGH | SSH exposed on network + active failed-login burst |
| `CORR-001` | MEDIUM | SSH in latest scan correlated with auth burst activity |
| `CORR-002` | MEDIUM | Privileged auth bursts concentrated on a single sudo user |
| `OBS-001` | MEDIUM | Auth failures present but logging services appear inactive |
| `AUTH-TREND-001` | MEDIUM | Failed login count increasing across recent runs |
| `AUTH-001` | LOW | Sudo authentication failures observed |
| `NET-002` | varies | Open ports detected (attack surface enumeration) |
| `AUTH-003` | INFO | Sudo session activity observed |
| `AUTH-004` | INFO | Burst activity present in auth failure events |
| `CTX-001` | INFO | Sudo-capable users identified on system |

Baseline drift detection runs separately and flags changes in:
- sudo group membership
- service additions / removals
- service state changes (active ↔ inactive)
- open port additions / removals

---

## Requirements

**System:**
- Linux (tested: Ubuntu 22.04+, WSL2)
- Python 3.10+
- `nmap` installed (`sudo apt install nmap`)
- Read access to `/var/log/auth.log`

**Hardware (for LLM chat):**
- 8 GB RAM minimum (16 GB recommended for comfortable operation)
- ~5 GB free disk space (model file)
- CPU-only — no GPU required

**Python dependencies** (installed automatically via `pip install -e .`):
- `llama-cpp-python` — local LLM inference
- `requests` — HTTP client for daemon mode

---

## Installation

```bash
git clone https://github.com/TahrimWalid/kratos.git
cd kratos

python3 -m venv venv
source venv/bin/activate
pip install -e .
pip install llama-cpp-python requests
```

**Download the LLM model** (~4.5 GB, required for `kratos chat`):

```bash
mkdir -p llm/models
wget -O llm/models/qwen2.5-coder-7b-q4_k_m.gguf \
  https://huggingface.co/Qwen/Qwen2.5-Coder-7B-GGUF/resolve/main/qwen2.5-coder-7b-q4_k_m.gguf
```

Or point to a custom model path:

```bash
export KRATOS_LLM_MODEL_PATH=/path/to/your/model.gguf
```

---

## Quick Start

**Run the full pipeline in one command:**

```bash
kratos run --target 127.0.0.1
```

This scans the target, parses auth logs, collects system context, and
generates a correlated findings report. Then ask the AI to explain it:

```bash
kratos chat --mode summary
```

That's it. Two commands from zero to plain-language security analysis.

---

## Full Workflow

### Option A — One-shot (simple)

```bash
kratos run --target <IP>      # full pipeline
kratos chat --mode summary    # AI explains findings (~2 min cold start)
kratos chat --mode deep       # attack chains + blind spots
kratos chat -q "why is SSH high risk here?"   # ask a specific question
```

### Option B — With daemon mode (fast repeated queries)

Run the LLM server once in a dedicated terminal — the model loads into RAM
and stays there. All subsequent `kratos chat` calls respond in ~10-20s
instead of ~2 minutes.

```bash
# Terminal 1 — leave running
kratos llm-serve

# Terminal 2 — instant responses
kratos run --target <IP>
kratos chat --mode summary
kratos chat -q "what is the most urgent thing to fix?"
kratos chat --mode deep
```

`kratos chat` automatically detects whether the server is running and uses
it if available — no configuration needed. If the server is stopped, it
falls back to direct model loading.

---

## All Commands

| Command | Description |
|---------|-------------|
| `kratos run` | Full pipeline: scan → logs → context → findings |
| `kratos scan --target <IP>` | Run nmap scan |
| `kratos scan-parse` | Parse latest nmap XML to JSON |
| `kratos scan-summary` | Summarise latest scan |
| `kratos logs-parse` | Parse auth.log into structured events |
| `kratos logs-patterns` | Detect burst patterns in auth events |
| `kratos logs-patterns-show` | Display latest pattern analysis |
| `kratos logs-trends` | Compare auth stats across recent runs |
| `kratos context-collect` | Snapshot OS, users, services, network |
| `kratos findings-generate` | Run correlation rules, write report |
| `kratos findings-show` | Display latest findings |
| `kratos findings-show --id CORR-SSH-001` | Filter by finding ID |
| `kratos baseline-create` | Save a baseline configuration snapshot |
| `kratos baseline-compare` | Detect drift from baseline |
| `kratos prepare-bundle` | Build compact LLM-ready text bundle |
| `kratos chat --mode summary` | AI executive summary of findings |
| `kratos chat --mode deep` | AI deep analysis: attack chains + blind spots |
| `kratos chat -q "<question>"` | Ask a specific question about findings |
| `kratos llm-serve` | Start LLM server (keeps model in RAM) |

---

## Example Output

### Findings report (`kratos findings-show`)

```
[HIGH] CORR-SSH-001: SSH exposed with failed-login burst activity observed
  evidence: ssh exposed (nmap + context), ports: [22]

[MEDIUM] CORR-001: SSH exposure correlated with failed-login burst activity
  evidence: SSH detected on port 22, burst of 22 failures in 4 min window

[MEDIUM] OBS-001: Auth failures detected but logging services appear inactive
  evidence: auth failure events = 2, rsyslog.service = inactive
```

### AI chat output (`kratos chat --mode summary`)

```
SYSTEM STATE
The system has SSH exposed on port 22 with an active brute-force pattern
(22 failed logins in a 4-minute window from external IPs).

Finding 1: Active SSH brute-force
- Observation: 22 failed ssh_failed_login events in a 4-minute burst
- Evidence: "ssh_failed_login: 22 (11:13:33 → 11:17:56)"
- Risk: Ongoing credential stuffing attack — successful login possible if
  passwords are weak
- Action: sudo ufw deny from <attacker-IP> to any port 22

OVERALL RISK LEVEL: HIGH
Rationale: Active brute-force (22 events/4 min) on externally exposed SSH.
```

---

## Project Structure

```
kratos/
├── src/kratos/
│   ├── cli/
│   │   ├── app.py              # All CLI commands
│   │   └── bundle.py           # LLM bundle generator
│   ├── adapters/
│   │   ├── findings_engine.py  # Correlation rules engine
│   │   ├── auth_log_patterns.py# Burst detection (sliding window)
│   │   ├── baseline.py         # Drift detection
│   │   ├── nmap_parser.py      # Scan XML → JSON
│   │   └── system_context.py   # OS/service/user snapshot
│   ├── llm_config.py           # Model path, inference params, prompts
│   └── llm_interface.py        # LLM server client + direct inference
├── llm/
│   └── models/                 # Place model file here
├── data/
│   ├── scans/                  # nmap XML + parsed JSON
│   ├── logs/                   # auth events, stats, patterns
│   ├── context/                # system context snapshots
│   ├── baseline/               # baseline snapshots
│   └── reports/                # findings, bundles
└── pyproject.toml
```

---

## Design Decisions

**Why offline?**
Security tools sending data to external APIs create their own attack
surface. Kratos is designed for air-gapped or privacy-sensitive environments
where no data leaves the machine.

**Why Qwen2.5-Coder 7B?**
Purpose-built for technical reasoning over structured data (logs, configs,
code). Outperforms general-purpose models on security-adjacent tasks.
Q4_K_M quantisation keeps it at ~4.5 GB — usable on edge hardware.

**Why not real-time?**
Continuous monitoring with autonomous response is a different threat model.
Kratos targets the "periodic review" use case: run it, understand what
happened, decide what to do. No automated changes, no false confidence.

**Why structured output format?**
The `Observation → Evidence → Risk → Action` format forces the LLM to cite
actual bundle values rather than producing generic advice. Every claim is
traceable to the source data.

---

## Known Limitations

- **Cold start**: Loading the 7B model takes ~2 minutes on CPU. Use
  `kratos llm-serve` for repeated queries to avoid reloading.
- **Single host**: Kratos analyses one target at a time. Multi-host
  correlation is out of scope for v0.1.
- **Log coverage**: Currently parses `/var/log/auth.log` only.
  Application logs, syslog, and journald are not yet supported.
- **No real-time monitoring**: Designed for periodic analysis, not
  continuous alerting.
- **Development environment**: Primary development on CSC OpenStack VM
  (Ubuntu 22.04, 8 vCPU, 77 GB). Target deployment: Mixtile Blade 3
  (Ubuntu, 16 GB RAM, 128 GB storage). Performance numbers from target
  hardware will be recorded in the thesis appendix.

---

## Thesis Context

Developed as a Bachelor's thesis prototype (February 2026).

The research question: *Can meaningful, explainable security insights be
generated entirely locally on resource-constrained hardware, without cloud
services or internet connectivity?*

Kratos demonstrates that the answer is yes — by combining lightweight
rule-based correlation with a quantised local LLM, a system can move from
raw telemetry to plain-language actionable advice with no external
dependencies.

All design decisions prioritise traceability, reproducibility, and
evaluability over feature completeness.

---

## Status

- **Version**: v0.1 (February 2026)
- **Correlation rules**: 10 active finding types
- **LLM integration**: Qwen2.5-Coder 7B, fully offline, daemon mode supported
- **Baseline drift**: sudo / services / ports
