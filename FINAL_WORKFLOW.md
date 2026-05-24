# Kratos — Complete 3-Tier NDR System
## Production Workflow for Thesis Demonstration

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│ TIER 1: SENSORS (Active + Passive)                      │
├─────────────────────────────────────────────────────────┤
│ ├─ Nmap scan (active)      → nmap_snapshot.xml          │
│ ├─ tcpdump (passive)       → conn_summary.json          │
│ └─ Auth logs (local)       → auth_events.json           │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│ TIER 2: AGGREGATION (Intelligent Correlation)          │
├─────────────────────────────────────────────────────────┤
│ ├─ Device fingerprinting (Nmap)                         │
│ ├─ Behavior analysis (tcpdump)                          │
│ ├─ Anomaly scoring                                      │
│ └─ OUTPUT: network_anomalies.json (high-confidence)    │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│ TIER 3: INTELLIGENCE (AI + Persistence)                │
├─────────────────────────────────────────────────────────┤
│ ├─ Time-series database (SQLite)                        │
│ ├─ Historical trending                                  │
│ ├─ LLM reasoning (Qwen2.5-Coder 7B)                    │
│ └─ OUTPUT: daily_report.html, weekly_report.html      │
└─────────────────────────────────────────────────────────┘
```

---

## Complete Workflow (Bash Script)

### Terminal A — LLM Server (Keep Running)

```bash
#!/bin/bash
# Run once at start of session, keep in background

cd /home/ubuntu/kratos
source venv/bin/activate
set -a; source .env; set +a

# Start LLM server (loads model once, daemon mode)
kratos llm-serve
```

Wait for: `Uvicorn running on http://127.0.0.1:8686`

---

### Terminal B — Complete Analysis Pipeline

```bash
#!/bin/bash

cd /home/ubuntu/kratos
source venv/bin/activate
set -a; source .env; set +a

# ========================================
# HOUR 0: Initial Baseline Scan
# ========================================

echo "=== PHASE 1: TIER 1 - Active Scan ==="
kratos scan --target 127.0.0.1
kratos scan-parse

echo "=== PHASE 1: TIER 1 - Parse Logs ==="
kratos logs-parse
kratos logs-patterns

echo "=== PHASE 1: Collect Context ==="
kratos context-collect

echo "=== PHASE 1: Generate Findings (LLM) ==="
kratos findings-generate


# ========================================
# CONTINUOUS: Passive Traffic Monitoring
# ========================================

echo "=== PHASE 2: TIER 1 - Passive Capture (60s sample) ==="
# In production: run continuously in background
# For demo: capture once
kratos network-capture --duration 60 --interface any


# ========================================
# PERIODIC (e.g., every hour): Correlation
# ========================================

echo "=== PHASE 2: TIER 2 - Correlate & Score Anomalies ==="
kratos network-anomalies

echo "=== PHASE 3: Store in Database ==="
kratos store-anomalies


# ========================================
# REPORTS: Daily/Weekly
# ========================================

echo "=== PHASE 3: TIER 3 - Daily Report ==="
kratos daily-report

echo "=== PHASE 3: TIER 3 - Weekly Report ==="
kratos weekly-report


# ========================================
# HISTORICAL ANALYSIS (using date filtering)
# ========================================

echo "=== PHASE 1: Date-Filtered Analysis (February) ==="
kratos logs-trends --since 20260201 --until 20260228
kratos prepare-bundle --since 20260201 --until 20260228
kratos chat --since 20260201 --until 20260228 -q "What were the main risks in February?"

echo "=== PHASE 1: Date-Filtered Analysis (March) ==="
kratos logs-trends --since 20260301 --until 20260331
kratos prepare-bundle --since 20260301 --until 20260331
kratos chat --since 20260301 --until 20260331 -q "What were the main risks in March?"

echo "=== PHASE 1: Trend Analysis ==="
kratos chat --since 20260201 --until 20260331 -q "Did security improve from February to March? Why/why not?"


# ========================================
# LLM Chat Examples (Questions Based on Anomalies)
# ========================================

echo "=== PHASE 3: Ask LLM about Network Behavior ==="
kratos chat -q "Which device has the most anomalies today?"
kratos chat -q "Is there evidence of lateral movement in the network?"
kratos chat -q "Which ports shouldn't be open on these devices?"


# ========================================
# Output Summary
# ========================================

echo ""
echo "=== ANALYSIS COMPLETE ==="
echo ""
echo "Generated Artifacts:"
ls -lh data/reports/      | tail -10
ls -lh data/logs/         | tail -10
echo ""
echo "Database:"
ls -lh data/kratos.db
echo ""
echo "Reports are HTML — open in browser:"
echo "  file://$(pwd)/data/reports/daily_report_*.html"
echo "  file://$(pwd)/data/reports/weekly_report_*.html"
```

---

## Individual Command Reference

### PHASE 1 — Active Scanning & Findings

```bash
# Nmap scanning
kratos scan --target 127.0.0.1           # Active port scan
kratos scan-parse                         # Parse XML → JSON

# Auth log analysis
kratos logs-parse                         # Extract failure events
kratos logs-patterns                      # Detect burst patterns

# System profiling
kratos context-collect                    # Gather system metadata

# Security findings (uses LLM)
kratos findings-generate                  # Correlate all data

# Show findings
kratos findings-show
kratos findings-show --id CORR-001       # Filter by ID

# Auth trending
kratos logs-trends --last 5              # Last 5 auth_stats files
kratos logs-trends --since 20260201 --until 20260228  # Date range
```

### PHASE 2 — Passive Network Monitoring & Anomaly Detection

```bash
# Capture network connections (requires tcpdump + sudo)
kratos network-capture --duration 60 --interface any
# Output: data/logs/conn_summary_YYYYMMDD_HHMMSS.json

# Correlate Nmap + tcpdump → find anomalies
kratos network-anomalies
# Output: data/reports/network_anomalies_YYYYMMDD_HHMMSS.json
# Example findings:
#   - Printer doing SSH to 8.8.8.8 (C&C callback?)
#   - Camera using RDP to external IP (compromised?)
#   - Laptop connecting to database (expected behavior ✓)
```

### PHASE 3 — Persistence & Reporting

```bash
# Store anomalies in time-series DB (SQLite)
kratos store-anomalies
# Saves to: data/kratos.db

# Generate reports
kratos daily-report    # HTML: daily_report_*.html
kratos weekly-report   # HTML: weekly_report_*.html

# View reports in browser:
firefox data/reports/daily_report_*.html &
firefox data/reports/weekly_report_*.html &
```

### Multi-Month Historical Analysis (Phase 1 Enhancement)

```bash
# Prepare bundle from specific date range
kratos prepare-bundle --since 20260201 --until 20260228 --max-words 1000

# Ask LLM questions about specific periods
kratos chat --since 20260201 --until 20260228 -q "What changed this month?"
kratos chat --since 20260301 --until 20260331 -q "Compare to last month?"

# Ask about the full historical period
kratos chat --since 20260101 --until 20260331 -q "What's the overall security trend?"
```

### LLM Chat Examples (Using Phase 1 + 3 Together)

```bash
# AI summarizes latest findings (template mode)
kratos chat --mode summary

# Deep analysis: attack chains + blind spots
kratos chat --mode deep

# Specific questions (triggers custom question mode, no template)
kratos chat -q "What's the most urgent security fix?"
kratos chat -q "Explain this in simple terms for non-technical users"
kratos chat -q "What would an attacker do with these vulnerabilities?"
```

---

## Data Directory Layout (After Full Workflow)

```
data/
├── scans/
│   ├── nmap_127.0.0.1_YYYYMMDD_HHMMSS.xml
│   ├── nmap_127.0.0.1_YYYYMMDD_HHMMSS.json
│   └── parsed_YYYYMMDD_HHMMSS.json
│
├── logs/
│   ├── auth_events_YYYYMMDD_HHMMSS.json
│   ├── auth_stats_YYYYMMDD_HHMMSS.json
│   ├── auth_patterns_YYYYMMDD_HHMMSS.json
│   ├── conn_summary_YYYYMMDD_HHMMSS.json        ← PHASE 2
│   └── excerpts/
│
├── context/
│   └── system_context_YYYYMMDD_HHMMSS.json
│
├── baseline/
│   └── baseline_YYYYMMDD_HHMMSS.json
│
├── reports/
│   ├── findings_YYYYMMDD_HHMMSS.json
│   ├── findings_YYYYMMDD_HHMMSS.md
│   ├── auth_trends_YYYYMMDD_HHMMSS.json
│   ├── auth_trends_YYYYMMDD_HHMMSS.md
│   ├── network_anomalies_YYYYMMDD_HHMMSS.json  ← PHASE 2
│   ├── bundle_YYYYMMDD_HHMMSS.txt
│   ├── daily_report_YYYYMMDD_HHMMSS.html        ← PHASE 3
│   └── weekly_report_YYYYMMDD_HHMMSS.html       ← PHASE 3
│
└── kratos.db                                    ← PHASE 3 (SQLite)
```

---

## Thesis Presentation Talking Points

### "3-Tier Network Detection & Response on Edge Hardware"

1. **Tier 1 — Sensor Layer** (Active + Passive)
   - Nmap for device discovery and fingerprinting
   - tcpdump for behavioral monitoring (low CPU)
   - Auth logs for login attempt analysis
   - Advantage: Continuous low-overhead collection

2. **Tier 2 — Aggregation Layer** (The Innovation)
   - Correlates device *identity* (Nmap) with device *behavior* (tcpdump)
   - Anomaly scoring: Expected ports vs actual connections
   - Example: "Printer should only use port 9100, but it's using SSH"
   - Result: High-signal findings (no noise)

3. **Tier 3 — Intelligence Layer** (AI + Persistence)
   - Time-series database tracks anomalies over time
   - Trend analysis: "Are intrusions increasing?"
   - Qwen2.5-Coder 7B LLM reasons about findings
   - Executive reports for non-technical stakeholders
   - Advantage: Scales to multi-month deployments without context explosion

### Why This Matters

- **Enterprise equivalents:** Darktrace, Vectra AI (both use similar 3-tier approach)
- **Edge advantage:** Runs on $200 Mixtile Blade 3 (no cloud required)
- **Thesis contribution:** Open-source NDR designed for resource-constrained devices
- **Real-world validation:** Tested on home network with dates Feb-Mar 2026

---

## Hardware Requirements (Blade 3 Verified)

| Component | Requirement | Blade 3 Status |
|-----------|-------------|--------|
| CPU | 4+ cores for tcpdump/Nmap | ✅ 8-core RK3588 |
| RAM | 8+ GB (LLM needs 6GB) | ✅ 16GB |
| Disk | 100+ GB for logs | ✅ NVMe SSD |
| Network | 1Gbps Ethernet | ✅ Gigabit LAN |
| OS | Linux | ✅ Ubuntu 22.04 |

---

## Timeline (Estimated)

### Cold Start (First Run)
- Nmap scan: ~2 min
- Log parsing: ~1 min
- LLM findings (load model): ~3 min
- **Total: ~6 minutes**

### Subsequent Runs (LLM already loaded)
- Nmap scan: 2 min
- Network capture: 1 min (configurable)
- tcpdump → anomalies: ~1 min
- Reports: ~30 sec
- **Total: ~4 minutes**

### Daemon Mode (Continuous)
- tcpdump (background): ~2% CPU
- Periodic checks: ~5% CPU intermittent
- LLM queries on-demand: ~90% CPU for 2-5 min

---

## Thesis Deliverables Checklist

- ✅ **Architecture:** 3-Tier NDR design document (PROJECT_PHASES.md)
- ✅ **Implementation:** All phases working on Blade 3
- ✅ **Code:** ~1,500 LOC of Python, fully modular
- ✅ **Database:** SQLite for time-series anomaly storage
- ✅ **Reporting:** HTML reports (daily/weekly)
- ✅ **LLM Integration:** Qwen2.5-Coder 7B for reasoning
- ✅ **Date Filtering:** Multi-month historical analysis (Phase 1)
- ✅ **Testing:** Validated on home network (Feb-Mar 2026 data)
- ⏳ **BitNet Optional:** Quantization study for future work

---

## Next Steps After Presentation

1. **Deploy to real network:** Use SPAN port on router
2. **Optimize for production:** Background service + cron jobs for periodic runs
3. **BitNet quantization:** Test 1.58-bit model for even lower CPU usage
4. **Mobile dashboard:** Web UI for remote monitoring
5. **Threat intelligence:** Integrate IP reputation feeds

