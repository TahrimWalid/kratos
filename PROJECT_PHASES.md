# Kratos Development — 3-Phase Roadmap

## PHASE 1: ✅ COMPLETE — Date-Filtered Queries (DONE)
**Status:** Ready for presentation demo

### Deliverables:
- ✅ Date-range filtering (`--since YYYYMMDD --until YYYYMMDD`)
- ✅ Works on: `logs-trends`, `prepare-bundle`, `chat`
- ✅ Backward compatible (old commands still work)
- ✅ LLM question fix: `-q` questions now get unique answers (not template)
- ✅ Demo workflow documented: `DEMO_WORKFLOW.md`

### Key Files Modified:
- `src/kratos/utils/latest_file.py` — Added `files_in_date_range()`
- `src/kratos/adapters/logs_trends.py` — Date filtering logic
- `src/kratos/cli/bundle.py` — Date filtering for bundles
- `src/kratos/cli/app.py` — CLI args + `is_custom_question` flag
- `src/kratos/llm_interface.py` — `is_custom_question` parameter

### How to Resume:
If context tokens end, and you need Phase 1 fixes:
```bash
cd /home/ubuntu/kratos
git log --oneline feature/blade3-edge | grep -E "date|filter"
```

---

## PHASE 2: 🟡 IN PROGRESS — Tier 2 Aggregator (Network correlation)
**Parent Task:** Build anomaly detector that correlates Nmap + passive traffic

### Deliverables:
- tcpdump integration (capture connections)
- Aggregator adapter (correlate device identity + behavior)
- Lightweight JSON output (fits in LLM tokens)
- Integration into `kratos run` pipeline

### Sub-tasks:
1. **tcpdump wrapper** (`src/kratos/adapters/network_capture.py`)
   - Parse tcpdump/conn.log
   - Extract: src_ip, dst_ip, dst_port, protocol, bytes_sent
   - Output: `conn_summary_YYYYMMDD_HHMMSS.json`

2. **Aggregator logic** (`src/kratos/adapters/network_aggregator.py`)
   - Input: Latest Nmap XML + latest conn_summary.json
   - Correlate: Nmap device_type vs actual_behavior
   - Flag: Mismatches as anomalies
   - Output: `network_anomalies_YYYYMMDD_HHMMSS.json`
   ```json
   [
     {
       "device": "192.168.0.50",
       "identity": "Printer (Nmap)",
       "anomaly": "SSH connection to 8.8.8.8",
       "severity": "HIGH",
       "recommendation": "Isolate device"
     }
   ]
   ```

3. **CLI integration** (`src/kratos/cli/app.py`)
   - Add `--capture-traffic` flag to `kratos run`
   - Or add `kratos network-capture` subcommand
   - Passes anomalies to LLM

### Key Decision Points:
- Use **tcpdump** (simple, ~50 lines parse logic) OR **Zeek** (structured, more powerful)?
  - **Recommended:** tcpdump for MVP, Zeek for thesis final
- How to handle **home router without SPAN port**?
  - tcpdump on Blade 3 only sees: broadcast, device's own traffic, ARP
  - Trade-off: Limited but still valid for proof-of-concept

### Testing Checklist:
- [ ] tcpdump running in background (2% CPU)
- [ ] Nmap identifies 3+ devices
- [ ] Aggregator detects 1 real anomaly (e.g., device using unexpected port)
- [ ] LLM analyzes anomaly correctly
- [ ] Entire pipeline < 5 min per cycle

### Estimated Time: **5-7 days**

### How to Resume Phase 2:
```bash
cd /home/ubuntu/kratos
git checkout feature/blade3-edge
git log --oneline | head -20  # Check latest commits
ls src/kratos/adapters/ | grep -E "capture|aggregator"
```
If files exist, check: `git diff HEAD~5 src/kratos/adapters/`

---

## PHASE 3: 🔴 NOT STARTED — Thesis-Ready System
**Parent Task:** End-to-end NDR system with persistence, reporting, BitNet exploration

### Deliverables:
1. **Persistence Layer** (`src/kratos/storage/anomaly_store.py`)
   - Store anomalies in SQLite (time-series)
   - Query: "Show me all HIGH severity anomalies from last 7 days"
   - Enable trend analysis: "Are intrusions increasing?"

2. **Report Generation** (`src/kratos/adapters/security_report.py`)
   - Daily/weekly security reports
   - Format: Executive summary + detailed findings
   - Output: HTML or PDF for stakeholders

3. **BitNet 1.58-bit Quantization** (optional, for thesis innovation section)
   - Test Qwen model with BitNet quantization
   - Measure: Inference speed vs accuracy trade-off
   - Document: Why/when BitNet makes sense for edge

4. **Final Thesis Artifacts**
   - Architecture diagram (Tier 1-2-3)
   - Performance benchmarks (Blade 3 specific)
   - Real-world test results (home network data)
   - Comparison table: Kratos vs enterprise NDR

### Testing Checklist:
- [ ] 7-day continuous operation without errors
- [ ] SQLite database shows 100+ anomalies
- [ ] Weekly report generated automatically
- [ ] LLM reasoning on multi-day trends works
- [ ] BitNet model loads and infers (if attempted)

### Estimated Time: **2-3 weeks** (includes writing, testing, thesis prep)

### How to Resume Phase 3:
```bash
cd /home/ubuntu/kratos
ls src/kratos/storage/ src/kratos/adapters/security_report.py
# If these don't exist, Phase 3 hasn't started
```

---

## Quick Context Recovery Commands

**If I lose context, use these to brief me:**

```bash
# Show current branch status
git branch -v

# Show what was done recently
git log --oneline -20

# List all adapters (Phase 1 & 2 progress)
ls -lah src/kratos/adapters/

# Show Phase 1 test results
kratos chat -q "Test question" | head -20

# Check if Phase 2 has been started
[ -f src/kratos/adapters/network_aggregator.py ] && echo "Phase 2 started" || echo "Phase 2 not started"
```

---

## Current Status (as of March 27, 2026)

**Completed:**
- Phase 1: ✅ Date filtering works, LLM question fix ready
- DEMO_WORKFLOW.md: ✅ Created with Feb/Mar examples

**Next Priority:**
- Phase 2: Start tcpdump wrapper (beginning of network aggregator)

**Branch:** `feature/blade3-edge`

---

## Notes for Quick Resume

If context ends:
1. **Always check:** `DEMO_WORKFLOW.md` and this file
2. **Always verify:** `git log --oneline` to see latest work
3. **Ask user:** "Which phase are we in?" if unclear
4. **Use:** Phase headers as checklist items
