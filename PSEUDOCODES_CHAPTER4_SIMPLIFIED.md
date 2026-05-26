# Kratos Implementation — Simplified Pseudocodes for Thesis (Chapter 4)

## 4.2 Auth Log Processing Pipeline

```
PIPELINE AuthLogProcessing(auth_log_path, data_dir):
    INPUT: /var/log/auth.log, output directory
    OUTPUT: Events, statistics, burst patterns (JSON files)
    
    STEP 1: Parse Events
    ├─ Input: Raw auth log file
    ├─ Process: Apply regex patterns for 6 event types
    └─ Output: auth_events_*.json (normalized event list)
    
    STEP 2: Compute Statistics
    ├─ Input: Parsed events
    ├─ Process: Aggregate counts by event_type, user, source_ip
    └─ Output: auth_stats_*.json (summary statistics)
    
    STEP 3: Detect Bursts
    ├─ Input: Parsed events
    ├─ Process: Sliding window (5-min window, threshold=5 events)
    ├─ Event types checked: ssh_failed_login, sudo_pam_auth_failure, sudo_auth_failure
    └─ Output: auth_patterns_*.json (burst list with metadata)
    
    RETURNS: Dictionary with events, stats, patterns
```

---

## 4.3 Findings Engine Orchestration

```
ALGORITHM RunFindingsEngine(data_dir):
    INPUT: Data directory with latest analysis files
    OUTPUT: findings_*.json (prioritized security findings)
    
    STEP 1: Locate Latest Input Files
    ├─ Search for most recent: nmap_parsed, auth_stats, auth_patterns, system_context
    └─ Load all JSON files (skip if missing)
    
    STEP 2: Execute Correlation Rules
    ├─ Call generate_findings() with all loaded data
    ├─ Rules check for:
    │  ├─ Network exposure + auth activity patterns
    │  ├─ Privilege context (sudo users)
    │  └─ Service state anomalies
    └─ Output: List of Finding objects
    
    STEP 3: Prioritize by Severity
    ├─ Sort findings: HIGH → MEDIUM → LOW → INFO
    └─ Maintain order for LLM analysis
    
    STEP 4: Persist Results
    ├─ Serialize findings to JSON
    ├─ Save: findings_*.json
    └─ RETURNS: Findings list
```

---

## 4.4 LLM Server Integration

```
CLASS LLMServer:
    
    OPERATION Initialize():
    ├─ Check if model file exists at MODEL_PATH
    ├─ Allocate resources: 2GB memory minimum
    └─ Set state: not_ready
    
    OPERATION LoadModel():
    ├─ Load Qwen2.5-Coder 7B (Q4_K_M quantization)
    ├─ Initialize with:
    │  ├─ Context window: 2048 tokens (empirically tested stable)
    │  ├─ Threads: 8 (ARM CPU threads)
    │  └─ GPU layers: 0 (CPU-only, no GPU)
    ├─ Set state: ready
    └─ RETURNS: Success/Failure
    
    OPERATION SendPrompt(user_message, system_message):
    ├─ Check if model is ready
    ├─ Format as chat completion request:
    │  ├─ System role: "You are a security analyst..."
    │  ├─ User role: Formatted findings
    │  └─ Max tokens: 2048
    ├─ Send to LLM inference engine
    ├─ Wait for response (timeout: 900s)
    └─ RETURNS: LLM analysis text

PIPELINE AnalyzeWithLLM(findings_list):
    STEP 1: Format Findings
    ├─ Sort by severity
    ├─ Group by risk level
    └─ Create readable prompt
    
    STEP 2: Initialize LLM
    ├─ Create LLMServer instance
    ├─ Load model (takes ~30 seconds first time)
    └─ Verify: ready state = true
    
    STEP 3: Send to LLM
    ├─ Combine system prompt + findings prompt
    ├─ Send via chat completion API
    ├─ Collect response
    └─ RETURNS: Analysis text from LLM
```

---

## Summary

| Section | Component | Input | Process | Output |
|---------|-----------|-------|---------|--------|
| 4.2 | Auth Pipeline | auth.log | Parse → Stats → Bursts | 3 JSON files |
| 4.3 | Findings Engine | 5 data sources | Correlation rules | findings.json |
| 4.4 | LLM Integration | Findings | Format + Inference | Analysis text |

**Use these high-level pseudocodes in your thesis Chapter 4 (Implementation Methodology).**
