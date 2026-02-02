Kratos

Kratos is an offline security analysis assistant developed as a Bachelor’s thesis prototype.
It is designed to run fully locally on Linux systems (including edge devices) and focuses on collecting, normalizing, and correlating security-relevant data without any cloud dependency.

This repository represents **v0.1** (February 2026 milestone) of the thesis implementation.

## Why Kratos?

**Unlike traditional security tools that dump raw alerts**, Kratos correlates findings across multiple data sources:

- **CORR-001**: Detects SSH exposure combined with authentication bursts
- **CORR-002**: Identifies single-user sudo abuse patterns (concentrated privilege escalation attempts)
- **OBS-001**: Flags authentication failures when logging services are inactive (blind spots)
- **Baseline mode**: Tracks configuration drift over time (sudo membership, service state, open ports)

**Air-gapped ready**: No cloud APIs, no external dependencies, full audit trail with timestamped outputs.

**Thesis-driven design**: Prioritizes traceability, explainability, and reproducibility over feature completeness.

Project goals (current scope)

Kratos aims to demonstrate that meaningful security insights can be generated locally by combining:

Network scan results

Authentication and system logs

System context (users, services, environment state)

The project intentionally avoids:

Real-time intrusion prevention

Signature-based malware detection

Cloud-hosted AI or external APIs

Instead, the focus is on traceability, explainability, and offline operation, which are evaluated in the thesis.

Current capabilities (v0.1)
Data collection

Run safe Nmap scans and store results locally

Parse Linux authentication logs (auth.log)

Collect system context:

OS and kernel

active services

sudo users

network interfaces

environment type (e.g. WSL vs native Linux)

Data processing

Normalize raw outputs into structured JSON

Detect authentication event bursts using a rolling time window

Extract contextual log excerpts for detected patterns

Correlation & findings

Generate structured security findings with:

- **severity** (critical, high, medium, low, info)
- **evidence** (timestamped, traceable)
- **recommendations** (actionable next steps)

**Active correlation rules**:

- **CORR-001**: SSH exposure + authentication bursts
- **CORR-002**: Single-user sudo abuse patterns
- **OBS-001**: Auth failures with inactive logging services
- **Baseline drift detection**: sudo membership, service state, open ports

Each finding includes the tool version and environment context (production vs development)

Reporting & usability

Human-readable Markdown reports

CLI helpers for viewing latest results

LLM-ready “clean room” text bundles (optional, offline)

Project structure (simplified)
src/kratos/
  cli/          # CLI commands and argument parsing
  adapters/     # Parsers, collectors, findings engine
  core/         # Shared logic and utilities

data/
  scans/        # Nmap XML + parsed scan JSON
  logs/         # Auth events, stats, patterns, excerpts
  context/      # System context snapshots
  baseline/     # Baseline snapshots
  reports/      # Findings, baseline compare, bundles


All outputs are timestamped to preserve traceability.

Installation (development)

Create and activate a virtual environment, then install dependencies:

python3 -m venv .venv
source .venv/bin/activate
pip install -e .


Ensure required system tools are available:

nmap

systemctl (or compatible service manager)

Access to /var/log/auth.log (read permissions)

## Example Output

Kratos generates actionable, correlated findings with evidence and recommendations:

```
[MEDIUM] OBS-001 — Authentication failures detected but log collection services appear inactive

Evidence:
  - auth failure events = 2
  - rsyslog.service active = false
  - systemd-journald.service active = false
  - context snapshot = 2026-02-02T04:14:42

Recommendations:
  - Verify that system logging is enabled (rsyslog or journald) so security-relevant events are recorded.
  - If this is an embedded/stripped environment, document logging limitations.
```

```
[MEDIUM] CORR-002 — Privileged authentication bursts observed on a single sudo user

Evidence:
  - sudo user: admin
  - sudo failure events: 5
  - time window: 30 seconds

Recommendations:
  - Investigate whether this user's credentials are compromised.
  - Consider enforcing MFA for privileged access.
```

Quick start (recommended demo)

Run the full analysis pipeline with one command:

kratos run --target 127.0.0.1 --threshold 1


This performs, in order:

Network scan

Scan parsing

Log parsing

Pattern detection

System context collection

Findings generation

View results:

kratos findings-show
kratos findings-show --id CORR-002
kratos logs-patterns-show

Manual step-by-step usage (advanced)
Network scanning
kratos scan --target <host-or-ip>
kratos scan-summary
kratos scan-parse

Log analysis
kratos logs-parse
kratos logs-patterns --threshold 1
kratos logs-patterns-show

System context
kratos context-collect

Findings
kratos findings-generate
kratos findings-show
kratos findings-show --id <FINDING_ID>

Baseline mode (configuration drift)

Create a baseline snapshot:

kratos baseline-create


Later, compare current state to baseline:

kratos baseline-compare


This detects:

sudo membership changes

service additions/removals

service state changes (active ↔ inactive)

open-port drift

LLM-ready summary (optional)

Generate a compact, noise-free summary (offline):

kratos prepare-bundle


This produces a single text file under 500 words, suitable for:

manual review

future local LLM integration

appendix material in the thesis

Limitations (intentional)

No real-time monitoring

No automatic remediation

No cloud connectivity

No SSH exposure detection yet (planned for next phase)

These constraints are by design and are discussed explicitly in the thesis.

## Status

- **Version**: v0.1 (February 2026 milestone)
- **State**: Feature-complete for Phase 1 — all core correlation rules implemented
- **Correlation engine**: 3 active rules (CORR-001, CORR-002, OBS-001)
- **Next phase**: SSH configuration analysis on real network hosts (March 2026)

Thesis context

This project is developed as part of a Bachelor’s thesis in software / systems engineering.
All design decisions prioritize clarity, reproducibility, and evaluability over production completeness.