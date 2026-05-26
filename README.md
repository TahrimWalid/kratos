# Kratos — Offline AI Security Analysis for Edge Devices

> Bachelor's thesis prototype · v0.1 · Deployed on Mixtile Blade 3 (ARM64, RK3588, 16 GB RAM)

Kratos is a fully offline Linux security analysis system that collects, correlates, and interprets security findings using a locally hosted LLM — no cloud, no internet, no external APIs. It was designed and evaluated as part of a Bachelor's thesis in Software Engineering (Tampere University of Applied Sciences, May 2026).

The core thesis: *can a quantized LLM running entirely on ARM edge hardware produce meaningful, explainable security analysis without ever sending data outside the machine?* The answer, empirically, is yes.

---

## Why This Exists

Traditional SIEM tools assume either constant cloud connectivity or significant compute budgets. That leaves a real gap: air-gapped networks, edge-deployed infrastructure, IoT gateways, and privacy-sensitive environments where sending authentication logs to a third-party API is a non-starter.

Kratos fills that gap by combining two layers that complement each other:

- **Deterministic rule-based correlation** — fast, transparent, reproducible. Fires the right alerts on known patterns.
- **Offline LLM interpretation** — turns those alerts into coherent analysis. Reasons across events. Infers intent that rules cannot.

The LLM advises. It never acts. All mitigation decisions stay with the human operator.

---

## Architecture

```
[Scan] ──► [Logs] ──► [Context] ──► [Findings] ──► [LLM Chat]
  nmap      auth.log    OS/users      correlate       Qwen2.5-Coder 7B
  XML       parsing     services      + baseline      plain-English analysis
```

Five stages, all local:

1. **Scan** — `nmap -sV` against a target IP, saved as structured XML → JSON
2. **Logs** — Parses `/var/log/auth.log` into typed events; detects burst patterns via sliding window (5-minute windows, ≥5 events = burst)
3. **Context** — Snapshots OS, kernel, active services, sudo group members, network interfaces
4. **Findings** — Correlates across all sources using fixed rules; outputs severity-ranked report
5. **Chat** — Loads findings into a quantized local LLM; produces structured, grounded analysis with evidence citations

All artifacts are timestamped and stored in `data/` — every report is fully traceable to the scan, log snapshot, and context file that produced it.

---

## Correlation Rules

| ID | Severity | What it detects |
|----|----------|----------------|
| `CORR-SSH-001` | HIGH | SSH exposed (nmap + context) + active failed-login burst |
| `CORR-001` | MEDIUM | SSH in latest scan correlated with auth burst activity |
| `CORR-002` | MEDIUM | Sudo failure bursts concentrated on a single sudo user |
| `OBS-001` | MEDIUM | Auth failures present but logging services appear inactive |
| `AUTH-TREND-001` | MEDIUM | Failed login count escalating across runs |
| `AUTH-001` | LOW | Sudo authentication failures observed |
| `NET-002` | varies | Open ports detected (attack surface enumeration) |
| `AUTH-003` | INFO | Sudo session activity observed |
| `AUTH-004` | INFO | Burst activity in auth failure events |
| `CTX-001` | INFO | Sudo-capable users identified |

Baseline drift detection flags changes in sudo group membership, service additions/removals, service state transitions, and open port changes between runs.

---

## Benchmarking: Adversarial Simulation Results

Kratos was evaluated across three adversarial runs against a **Zyxel VMG3625-T50B** gateway on a physical home lab. The Mixtile Blade 3 was connected via LAN (ethernet, not Wi-Fi) to monitor syslog traffic forwarded from the router.

### What was simulated

- **Run 1 (MEDIUM):** Baseline SSH exposure scan. 5 failed logins detected, 12 open ports enumerated (FTP, SSH, Telnet, HTTP, HTTPS, SMB, Zebra, 802-11-iapp, UPnP). LLM recommended rate-limiting and key-based auth.
- **Run 2 (MEDIUM → escalation):** Repeated failed SSH attempts leading to account lockout observed by the gateway syslog. LLM escalated from hygiene advice to "stop the service immediately."
- **Run 3 (HIGH):** After gateway lockout, internal authentication bursts appeared on the node itself. LLM connected these two events — gateway lockout followed by internal auth spikes — and inferred a **lateral movement / pivot attempt**. This is the key result: a rule-based system would have generated two separate alerts with no connection between them.

The gateway syslog capture confirmed the attack vector — `zHttpd` logging repeated invalid password attempts for `admin` from `192.168.1.37`, forwarded over UDP syslog to the Kratos node via `enP2p36s0`.

### Real benchmark outputs

**Run 1 — findings:**
```
[HIGH] CORR-SSH-001 — SSH exposed with failed-login burst activity observed
[MEDIUM] NET-002 — Open ports detected (attack surface present)
[MEDIUM] CORR-001 — SSH exposure correlated with failed-login burst activity
[INFO] CTX-001 — Sudo-capable users identified
[INFO] AUTH-003 — Sudo session activity observed
[INFO] AUTH-004 — Burst activity detected in authentication failures
```

**Run 1 — LLM summary (`kratos chat --mode summary`):**
```
SYSTEM STATE: The system has SSH exposed on port 22 with an active
failed-login burst pattern.

Finding 1: SSH exposed with failed-login burst activity observed
- Evidence: ssh exposed (nmap + context), ports: [22]
- Risk: Ongoing credential stuffing — successful login possible if
  passwords are weak
- Action: Disable SSH if not needed, or restrict via iptables

Finding 2: SSH exposure correlated with failed-login burst activity
- Evidence: SSH detected on port 22, burst activity confirmed
- Action: Implement fail2ban or equivalent rate-limiting

Finding 3: Open ports detected (attack surface present)
- Evidence: 12 open ports — FTP/21, SSH/22, Telnet/23, DNS/53,
  HTTP/80, SMB/139+445, HTTPS/443, Zebra/2601, UPnP/49152-49153
- Action: Close unnecessary ports via ufw

OVERALL RISK LEVEL: MEDIUM
```

**Run 3 — pivot inference query:**
```
kratos chat -q "Analyze the internal authentication bursts.
                Do they suggest a pivot from the gateway?"

→ "It is reasonable to infer that there may be a pivot from the
   gateway — the gateway lockout and subsequent internal auth_other
   burst (34 events) are temporally correlated. A traditional alert
   system would surface these as separate findings."

OVERALL RISK LEVEL: HIGH
```

This is what the LLM layer adds that rules cannot.

### Performance metrics (Mixtile Blade 3, CPU-only)

| Metric | Value |
|--------|-------|
| Average LLM inference latency | 4 min 3 sec |
| Latency range | 2 min 53 sec – 5 min 14 sec |
| CPU time (parsing + correlation) | < 0.3 sec (negligible) |
| RAM at idle | ~320–480 MB (2–3% of 16 GB) |
| RAM during LLM inference | ~1.9–2.0 GB (12% of 16 GB) |
| Model disk size (Q4_K_M) | ~4.2 GB |
| Swap usage | 0% across all runs |
| Hallucinations observed (12 queries) | 0 |
| LLM temperature | 0.3 (deterministic) |
| Seed | 42 (reproducible) |

The non-LLM pipeline (log parsing, burst detection, correlation, context collection) accounts for under 0.3 seconds total. 99.9% of execution time is LLM inference. This is a deliberate trade-off: 3–5 minutes is unacceptable for real-time intrusion prevention, and entirely acceptable for periodic security audits on air-gapped hardware where cloud upload is impossible.

---

## Quick Start

```bash
git clone https://github.com/TahrimWalid/kratos.git
cd kratos
python3 -m venv venv
source venv/bin/activate
pip install -e .
pip install llama-cpp-python requests
```

Download the model (~4.5 GB):

```bash
mkdir -p llm/models
wget -O llm/models/qwen2.5-coder-7b-q4_k_m.gguf \
  https://huggingface.co/Qwen/Qwen2.5-Coder-7B-GGUF/resolve/main/qwen2.5-coder-7b-q4_k_m.gguf
```

Run it:

```bash
kratos run --target 192.168.1.1   # full pipeline
kratos findings-show               # inspect correlated findings
kratos chat --mode summary         # LLM executive summary
kratos chat --mode deep            # attack chains + blind spots
kratos chat -q "is this a pivot attempt?"  # freeform query
```

### Daemon mode (recommended for repeated queries)

Cold-starting the 7B model takes ~2 minutes. Keep it loaded in RAM:

```bash
# Terminal 1 — leave running
kratos llm-serve
# [KRATOS-LLM] Host: 127.0.0.1:8686 — model stays in RAM

# Terminal 2 — responses in ~10–20s instead of ~2 min
kratos run --target <IP>
kratos chat --mode summary
kratos chat -q "what is the most urgent thing to fix?"
```

`kratos chat` auto-detects the running server and uses it if available.

---

## All Commands

| Command | Description |
|---------|-------------|
| `kratos run` | Full pipeline: scan → logs → context → findings |
| `kratos scan --target <IP>` | Run nmap scan |
| `kratos scan-parse` | Parse latest nmap XML to JSON |
| `kratos scan-summary` | Summarise latest scan |
| `kratos logs-parse` | Parse auth.log into structured events |
| `kratos logs-patterns` | Detect burst patterns (sliding window) |
| `kratos logs-patterns-show` | Display latest pattern analysis |
| `kratos logs-trends` | Compare auth stats across recent runs |
| `kratos context-collect` | Snapshot OS, users, services, network |
| `kratos findings-generate` | Run correlation rules, write report |
| `kratos findings-show` | Display latest findings |
| `kratos findings-show --id CORR-SSH-001` | Filter by finding ID |
| `kratos baseline-create` | Save a baseline configuration snapshot |
| `kratos baseline-compare` | Detect drift from baseline |
| `kratos prepare-bundle` | Build compact LLM-ready text bundle |
| `kratos chat --mode summary` | AI executive summary |
| `kratos chat --mode deep` | AI deep analysis: attack chains + blind spots |
| `kratos chat -q "<question>"` | Ask the LLM a specific question |
| `kratos llm-serve` | Start LLM server daemon (keeps model in RAM) |

---

## Requirements

**System:**
- Linux (tested: Ubuntu 22.04, WSL2, ARM64)
- Python 3.10+
- `nmap` installed (`sudo apt install nmap`)
- Read access to `/var/log/auth.log`

**Hardware (for LLM chat):**
- 8 GB RAM minimum (16 GB recommended)
- ~5 GB free disk space (model file)
- CPU-only — no GPU required
- Tested on: Mixtile Blade 3 (RK3588, 16 GB), CSC OpenStack VM (Ubuntu 22.04, 8 vCPU, 77 GB), WSL2

---

## Project Structure

```
kratos/
├── src/kratos/
│   ├── cli/
│   │   ├── app.py               # All CLI commands
│   │   └── bundle.py            # LLM bundle generator
│   ├── adapters/
│   │   ├── findings_engine.py   # Correlation rules engine
│   │   ├── auth_log_patterns.py # Burst detection (sliding window)
│   │   ├── baseline.py          # Drift detection
│   │   ├── nmap_parser.py       # Scan XML → JSON
│   │   └── system_context.py    # OS/service/user snapshot
│   ├── llm_config.py            # Model path, inference params, prompts
│   └── llm_interface.py         # LLM server client + direct inference
├── llm/
│   └── models/                  # Place model file here
├── data/
│   ├── scans/                   # nmap XML + parsed JSON
│   ├── logs/                    # auth events, stats, patterns
│   ├── context/                 # system context snapshots
│   ├── baseline/                # baseline snapshots
│   └── reports/                 # findings, bundles
└── pyproject.toml
```

---

## Design Decisions

**Why offline?**
Security tools that send data to external APIs create their own attack surface. Auth logs contain IP addresses, usernames, and timestamps — exactly the data an adversary wants. Kratos is designed for environments where data leaving the machine is a compliance violation or an operational risk.

**Why Qwen2.5-Coder 7B?**
Purpose-built for technical reasoning over structured data: logs, configs, code. Outperforms general-purpose models on security-adjacent tasks at the same parameter count. Q4_K_M quantization keeps it at ~4.5 GB and CPU-only viable on 16 GB ARM hardware.

**Why not real-time?**
Continuous autonomous response is a different — and much riskier — threat model. A 4-minute LLM inference latency is unacceptable for an IPS that must drop packets in milliseconds. It is entirely acceptable for periodic security audits and post-incident forensics, which is what Kratos targets. The controlled execution philosophy (LLM advises, human decides) keeps hallucinations from becoming operational failures.

**Why structured output?**
The `Observation → Evidence → Risk → Action` format forces the LLM to cite actual bundle values rather than producing generic advice. Across 12 benchmark queries, zero factual hallucinations were observed — no invented IPs, no fabricated port numbers, no evidence misattribution.

---

## Known Limitations

- **Cold start:** Model loading takes ~2 minutes on CPU. Use `kratos llm-serve` to keep it resident.
- **Single host:** Analyses one target at a time. Multi-host correlation is out of scope for v0.1.
- **Log coverage:** Parses `/var/log/auth.log` only. Journald, syslog, and application logs are not yet supported.
- **Context window:** 2048-token limit requires aggressive log summarization. The Prepared Bundle caps at ~1000 words.
- **No real-time monitoring:** Periodic analysis only — not continuous alerting.
- **NPU unused:** The RK3588 has a 6 TOPS NPU that was not usable at development time due to missing llama-cpp-python NPU backend support. Porting to the NPU is the highest-impact future optimization.

---

## Thesis

Developed as a Bachelor's thesis prototype at Tampere University of Applied Sciences (Software Engineering, May 2026).

**Research questions answered:**
1. *How effectively can an offline LLM interpret correlated security logs compared to traditional rule-based alerts?* — Significantly better for tasks requiring synthesis. The LLM integrated isolated rule alerts into a coherent attack narrative, including identifying a gateway-to-node pivot attempt that rules alone cannot surface.
2. *What are the performance trade-offs when running quantized models on edge-equivalent hardware?* — 4-minute average inference latency, zero swap, 12% RAM peak on 16 GB. The trade-off is speed for data sovereignty.
3. *Can a controlled execution philosophy mitigate LLM hallucinations in security reporting?* — Yes. Structural output validation, evidence citation requirements, fixed seed, and human-in-the-loop review produced zero factual hallucinations across all benchmark runs.

**Full thesis:** [URN:NBN:fi:amk-2026051813153](https://urn.fi/URN:NBN:fi:amk-2026051813153)

---

## Status

- **Version:** v0.1 (May 2026)
- **Correlation rules:** 10 active finding types
- **LLM integration:** Qwen2.5-Coder 7B, fully offline, daemon mode
- **Baseline drift:** sudo / services / ports
- **Tested hardware:** Mixtile Blade 3 (RK3588 ARM64), CSC OpenStack VM, WSL2
