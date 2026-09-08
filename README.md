# Kratos — Offline AI Security Assistant

> Local-first, **observe-and-recommend** security analysis. A deterministic rule engine paired with an agentic LLM loop, running fully offline on modest hardware. Kratos investigates a host, explains what it finds in plain language, and **recommends** actions to a human — it never executes changes on the monitored target.

Kratos started as a Bachelor's thesis prototype (Tampere University of Applied Sciences, Software Engineering, 2026) answering one question: *can a quantized LLM running entirely on ARM edge hardware produce meaningful, explainable security analysis without ever sending data outside the machine?* The answer, empirically, was yes.

Since then it has grown from a fixed five-stage pipeline into an **agentic assistant** that reasons about a goal, chooses its own read-only tools, correlates findings through a rule engine, and can even **write and keep new tools for itself** under human review — all without giving up the offline, safe-by-construction design.

---

## What Kratos is (and isn't)

- **Offline / local-first.** Primary analysis runs on a local model (default: `qwen2.5:7b` via Ollama). No cloud, no internet, no third-party API required. The *inference layer* is fully local; the only optional online piece is threat-intel enrichment, disabled by default (see below).
- **Observe-and-recommend, not autonomous.** Kratos reads and investigates; it recommends remediation to a human via findings and its final answer. **It never executes state-changing actions on the monitored target.** This boundary is foundational, not a limitation (a narrow, opt-in, whitelisted sub-agent for direct execution is *designed but not built* — see the boundary note below).
- **Two analysis modes.** A **deterministic pipeline** (fast, reproducible, zero LLM variance) *and* an **agentic ReAct loop** (the LLM picks tools based on what it finds). Use whichever fits the job.
- **Backend-flexible.** The same OpenAI-compatible client drives a local Ollama server, a local llama.cpp/vLLM server, or a **cloud provider via API key** — swapping is just changing three env vars (`LLM_BASE_URL`/`LLM_API_KEY`/`LLM_MODEL`). Local ships unconditionally; **cloud LLMs are supported and have been used through the development phase** (for faster iteration), but they're a dev/testing convenience — never required, and never the shipped default.

Kratos is a **defensive** assistant for blue-teamers, homelabbers, and small teams who need explainable security analysis on infrastructure where sending logs to a cloud API is a non-starter — not an autonomous offensive/pentest agent.

---

## Capabilities at a glance

- **`kratos investigate "<goal>"`** — an agentic ReAct loop: the LLM reasons about your goal, selects read-only tools, correlates the evidence, and answers with cited findings. Structural guards keep it honest (it can't conclude "all clear" over a real HIGH finding, can't claim a timeframe the data doesn't cover, etc.).
- **`kratos run`** — the original deterministic pipeline (scan → logs → context → findings → report), preserved for reproducible/audit use.
- **15 built-in tools**, all read/observe-only on the target: `run_nmap_scan`, `read_journalctl`, `list_open_files`, `list_processes`, `check_file_integrity`, `run_yara_scan`, `run_vuln_scan`, `check_ip_reputation`, `run_config_audit`, `correlate_findings`, plus local-host self-monitoring tools (`parse_auth_log`, `collect_system_context`, `capture_traffic`, `run_linux_command` — the last two approval-gated, local-host only).
- **Self-writing tools ("evo-loop").** Kratos can draft a new Python tool for a capability gap, **sandbox-test it** (no-network Incus container), and **keep it only after a human approves** — no force-accept, ever. Kept tools require approval to run until you trust them.
- **Textual TUI (`kratos-mk2`).** A full-screen terminal UI: session picker with search + date buckets, live investigation rendering, chat, findings/reports, self-diagnostics, a searchable tool runner, and in-app settings — all keyboard-first.
- **MCP server (`kratos mcp-serve`).** A read/investigate-only Model Context Protocol surface (3–4 high-level tools) so an external MCP client can drive an investigation through Kratos's own agent loop — approval-reaching tools are excluded by construction.
- **SSH read-only target model.** Kratos runs on its own host and reaches one monitored target over SSH using fixed, read-only commands (journalctl, `sshd -T`, firewall status, `lsof`, `ps`, YARA, config audit). A setup checklist + probe verify a new target.
- **Threat-intel (optional, off by default).** Offline OTX cache by default; opt-in, approval-gated live AbuseIPDB escalation. Disabled out of the box — Kratos works fully offline without it.
- **Session persistence** (SQLite), tiered resume (light summary vs full transcript replay), C7-safe context compaction, real token accounting, and per-session usage/cost visibility.

---

## The boundary (read this)

**Kratos never executes state-changing actions on the monitored target, by default.** Every target-facing tool is read/observe-only. When an investigation finds something that warrants action, Kratos's job ends at *recommending* it to a human — never doing it. `run_linux_command` runs on **Kratos's own host only**, is approval-gated, and is structurally blocked from touching the target or making state changes during an investigation.

A **narrow, per-target opt-in** for direct execution — a signed, **whitelisted** action set dispatched to a sub-agent on the target over Tailscale — is *designed* (`docs/subagent_architecture.md`) but **not built**: there is no sub-agent, no Tailscale integration, and no execution toggle anywhere in the code yet. Until then, and for every target by default, Kratos observes and recommends.

---

## Architecture

```
                         Kratos host (local)
  ┌───────────────────────────────────────────────────────────┐
  │  kratos investigate "<goal>"        kratos run             │
  │        │  agentic ReAct loop              │  fixed pipeline│
  │        ▼                                  ▼                │
  │   pick read-only tool ──► observe ──► correlate_findings   │
  │        ▲            │                     │   (rule engine)│
  │        └── reason ──┘                     ▼                │
  │                                    severity-ranked report  │
  │                                           │                │
  │                              local LLM (Ollama / llama.cpp)│
  │                              plain-language, cited analysis│
  └───────────────────────────────────────────────────────────┘
                  │  SSH (read-only: journalctl, sshd -T,
                  │  lsof, ps, yara, config audit …)
                  ▼
        Monitored target (never modified by Kratos)
```

The non-LLM layer (parsing, burst detection, correlation, context) is milliseconds; effectively all wall-clock time is LLM inference. That's the deliberate trade: minutes-scale analysis for **data sovereignty**, aimed at periodic audits and post-incident forensics, not millisecond intrusion prevention.

---

## Correlation rules (the deterministic layer)

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

Threat-intel enrichment runs an **offline** OTX-cache lookup on suspicious source IPs and, on a known-malicious hit, corroborates and raises severity — no network, no approval. Baseline drift detection flags changes in sudo group membership, service add/remove, service state, and open ports between runs.

---

## Thesis evaluation (v0.1 — the empirical grounding)

The original prototype was evaluated across three adversarial runs against a **Zyxel VMG3625-T50B** gateway on a physical home lab (a Mixtile Blade 3 monitoring forwarded syslog), using **`qwen2.5-coder-7b` (Q4_K_M) as the reference offline model**. These results are from that thesis-era evaluation and remain the empirical backbone of the "an offline LLM adds real synthesis over rules" claim. *(The agentic loop, evo-loop, TUI, and MCP surfaces below were built after the thesis and are lab-tested against a live Incus target, not part of these published benchmarks.)*

- **Run 1 (MEDIUM):** SSH exposure + 5 failed logins, 12 open ports enumerated. LLM recommended rate-limiting and key-based auth.
- **Run 2 (MEDIUM → escalation):** Repeated failed SSH → account lockout observed. LLM escalated from hygiene advice to "stop the service immediately."
- **Run 3 (HIGH):** After gateway lockout, internal auth bursts appeared on the node itself. The LLM connected the two — gateway lockout followed by internal auth spikes — and inferred a **lateral-movement / pivot attempt**. A rule-only system would have produced two disconnected alerts. This is the key result.

**Run 3 — pivot inference:**
```
kratos chat -q "Analyze the internal authentication bursts. Do they suggest a pivot from the gateway?"

→ "It is reasonable to infer that there may be a pivot from the gateway — the gateway lockout and
   subsequent internal auth_other burst (34 events) are temporally correlated. A traditional alert
   system would surface these as separate findings."   OVERALL RISK LEVEL: HIGH
```

**Performance (Mixtile Blade 3, RK3588 ARM64, CPU-only):**

| Metric | Value |
|--------|-------|
| Average LLM inference latency | ~4 min (range 2m53s–5m14s) |
| Non-LLM pipeline (parse + correlate + context) | < 0.3 sec |
| RAM at idle / during inference | ~320–480 MB / ~1.9–2.0 GB (12% of 16 GB) |
| Model disk size (Q4_K_M) | ~4.2 GB · Swap: 0% |
| Hallucinations across 12 queries | 0 (temp 0.3, seed 42, structured output) |

**Full thesis:** [URN:NBN:fi:amk-2026051813153](https://urn.fi/URN:NBN:fi:amk-2026051813153)

---

## Quick start

```bash
git clone https://github.com/TahrimWalid/kratos.git
cd kratos
python3 -m venv venv && source venv/bin/activate
pip install -e .
pip install requests            # + llama-cpp-python only if using the in-process GGUF path
```

**Pick a model backend.** The zero-config default is local Ollama:

```bash
ollama serve
ollama pull qwen2.5:7b
```

To point at a different local server or a cloud provider instead, set `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL` in `.env` (see `.env.example`) — no other code changes. (Local ships unconditionally; cloud is dev/testing only, never left active in `.env`.)

**Run it:**

```bash
# Agentic: reason about a goal, pick tools, correlate, answer
kratos investigate "check this host for signs of an SSH brute-force"

# Deterministic pipeline (reproducible)
kratos run --target 192.168.1.1
kratos findings-show

# Full-screen Textual UI (session picker, live investigation, chat, settings)
kratos-mk2

# Interactive REPL (bare command → session chooser)
kratos

# Expose a read/investigate-only MCP surface to an external client
kratos mcp-serve
```

**Keep the model warm** (cold start is ~2 min on CPU):

```bash
kratos llm-serve      # leave running; kratos auto-detects it → ~10–20s responses
```

---

## Commands (selection)

| Command | Description |
|---------|-------------|
| `kratos investigate "<goal>"` | Agentic ReAct investigation — the LLM picks read-only tools |
| `kratos run [--target IP]` | Deterministic full pipeline: scan → logs → context → findings |
| `kratos` | Interactive REPL / session chooser |
| `kratos-mk2` | Textual full-screen TUI |
| `kratos mcp-serve` | Read/investigate-only MCP server (stdio) |
| `kratos llm-serve` | Keep the local model resident (daemon) |
| `kratos findings-show [--id ID]` | Display / filter correlated findings |
| `kratos scan / logs-parse / context-collect / findings-generate` | Individual pipeline stages |
| `kratos baseline-create / baseline-compare` | Snapshot config and detect drift |
| `kratos chat --mode summary|deep -q "<question>"` | LLM analysis over the latest findings |

Inside the TUI/REPL, slash commands include `/investigate-host`, `/doctor` (self-diagnostic), `/usage` & `/context`, `/use <tool>` (deterministic single-tool run), `/evolve` (write a new tool), `/tools`, `/report`, `/model`, `/settings`, `/target`, `/compact`, and more — type `?` for help.

---

## Requirements

**Kratos host:**
- Linux (tested: Ubuntu 22.04, WSL2, ARM64), Python 3.10+
- `nmap` (`sudo apt install nmap`)
- A model backend: local **Ollama** (recommended) or a llama.cpp GGUF, or any OpenAI-compatible endpoint
- Optional, for `run_vuln_scan`: `nuclei` (prebuilt release binary on PATH; templates auto-download) + a local vulscan CVE database at `vulscan/scripts/vulscan/{vulscan.nse,cve.csv}` (gitignored — see `vulscan/README.md`)

**On the monitored target** (reached read-only over SSH — not installed on the Kratos host):
- SSH key access; passwordless sudo (or `systemd-journal` group) for journal reads; `lsof`; and `yara` for `run_yara_scan` (a starter ruleset ships in `yara_rules/`). `kratos-mk2`'s target setup checklist + probe verify all of this.

**Hardware (for local LLM chat):**
- 8 GB RAM minimum (16 GB recommended), ~5 GB disk (model), CPU-only — no GPU required.
- Tested on: Mixtile Blade 3 (RK3588 ARM64), CSC OpenStack VM (Ubuntu 22.04), WSL2, and an Incus lab target.

---

## Design decisions

**Why offline?** Auth logs contain IPs, usernames, timestamps — exactly what an adversary wants. Kratos is for environments where data leaving the machine is a compliance violation or operational risk. The offline inference layer is the moat.

**Why observe-and-recommend?** Autonomous response on production infrastructure is a much riskier threat model. Kratos keeps the human in the loop for every state change, which is also what makes it *trustable* to run on real hosts. Approval-gating and no-force-accept (especially on keeping a self-written tool) are non-negotiable.

**Why both a pipeline and an agentic loop?** The pipeline gives reproducible, zero-variance audits; the agentic loop gives synthesis and adaptive tool selection. They serve different needs, so Kratos keeps both.

**Why structured, evidence-cited output?** Forcing the LLM to cite actual observed values (not generic advice) is what kept factual hallucinations at zero across the thesis benchmarks — and the investigation loop adds structural guards on top so a conclusion can't contradict the evidence.

---

## Known limitations

- **Cold start:** ~2 min to load a local 7B on CPU — use `kratos llm-serve`.
- **Single target:** one monitored host at a time; multi-target correlation is deliberately deferred.
- **Local model ceiling:** the local-first moat trades some capability away — tool-selection and reasoning are weaker than a frontier model (a stronger cloud model can be swapped in for dev, but shipping stays local).
- **Not real-time:** periodic analysis and forensics, not continuous alerting.
- **Self-written tools:** evo-loop sandbox-tests against *mocked* network I/O (the sandbox has no network by design), so a tool can pass tests yet still hit a live-only issue (e.g. a permission it lacks) — human review is the gate, and improving this is on the roadmap.
- **OT/ICS coverage:** the scanners are HTTP/host-focused; a clean result is not evidence an OT/ICS device is safe.

---

## Status

- Evolved from the **v0.1 thesis prototype** (May 2026) into an agentic, tool-using, self-extending assistant.
- **Deterministic pipeline** + **agentic `investigate`** + **Textual TUI** + **MCP** + **self-writing tools**, all offline-first.
- **Boundary:** observe-and-recommend; never executes on the target (direct-execution sub-agent designed, not built).
- Active development on the `sprint2-tool-expansion-and-llm-refactor` branch.

---

*Developed as a Bachelor's thesis prototype at Tampere University of Applied Sciences (Software Engineering, 2026) and extended since.*
