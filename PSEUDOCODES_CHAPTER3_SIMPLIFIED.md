# Kratos System Design — Simplified Pseudocodes for Thesis (Chapter 3)

## 3.2.1 Nmap XML Parsing

```
ALGORITHM ParseNmapXML(xml_file):
    INPUT: Nmap XML scan output
    OUTPUT: Structured dictionary with hosts and open ports
    
    1. Load XML file and extract root element
    2. For each host in XML:
       a. Extract IP address and host state
       b. For each port with state='open':
          - Record: port number, protocol, service name, version
       c. Aggregate all open ports for this host
    3. Return structured data: {hosts: [{ip, state, open_ports}]}
```

---

## 3.2.2 Authentication Log Parsing

```
ALGORITHM ParseAuthLog(log_file, log_year):
    INPUT: /var/log/auth.log (syslog format)
    OUTPUT: List of normalized security events
    
    1. Read log file line by line
    2. For each line:
       a. Extract timestamp (ISO or classic syslog format)
       b. Extract program name (sshd, sudo, etc.)
       c. Match message against known patterns:
          - SSH failed login → event_type='ssh_failed_login'
          - SSH success login → event_type='ssh_success_login'
          - Sudo auth failure → event_type='sudo_pam_auth_failure'
          - Sudo session open → event_type='sudo_session_open'
       d. Extract relevant fields (user, source IP if available)
    3. Return list of normalized AuthEvent objects
```

---

## 3.3.1 Burst Detection (Sliding Window)

```
ALGORITHM DetectBursts(events, event_type, time_window, threshold):
    INPUT: List of security events, event type filter, time window (5 min), threshold (≥5)
    OUTPUT: List of detected burst periods
    
    1. Filter events by type and sort chronologically
    2. Use sliding window approach:
       a. For each starting event i:
          - Count all events within time_window after event i
          - If count ≥ threshold, this is a burst
       b. Merge overlapping bursts into single burst record
    3. For each burst, collect metadata:
       - Start/end timestamps
       - Event count
       - Top users and source IPs involved
    4. Return list of bursts with metadata
```

---

## 3.3.2 Correlation Rules (Fixed Ruleset)

```
ALGORITHM GenerateFindings(nmap_data, auth_stats, burst_patterns, system_context):
    INPUT: Nmap scan results, auth statistics, detected bursts, system state
    OUTPUT: List of security findings with severity and recommendations
    
    1. Apply fixed correlation rules:
    
       RULE CORR-001: SSH Exposed + Failed Login Burst
       - IF (SSH port 22 open in nmap) AND (SSH failed-login bursts detected)
       - THEN severity = MEDIUM
       - Recommendation: Disable password auth, implement rate limiting
    
       RULE CORR-002: Sudo Failures + Single User
       - IF (sudo auth failure bursts) AND (only 1 user in sudo group)
       - THEN severity = MEDIUM
       - Recommendation: Verify if expected or investigate
    
       RULE CORR-SSH-001: SSH Exposed (Confirmed) + Active Attacks
       - IF (SSH exposed in both nmap scan AND system context) 
         AND (multiple SSH failed-login bursts)
       - THEN severity = HIGH (escalated)
       - Recommendation: Immediate review, IP restrictions
    
    2. For each triggered rule, create finding object with:
       - Finding ID, title, severity level
       - Evidence (what triggered it)
       - Recommended actions
    
    3. Sort findings by severity (HIGH → MEDIUM → LOW → INFO)
    4. Return prioritized findings list
```

---

## 3.3.3 Event Statistics & Trending

```
ALGORITHM ComputeAuthStatistics(events):
    INPUT: List of parsed auth events
    OUTPUT: Aggregated statistics by type, user, source IP
    
    1. Initialize counters: events_by_type, by_user, by_source_ip
    2. For each event:
       - Increment counter for event.event_type
       - Increment counter for event.user (if present)
       - Increment counter for event.source_ip (if present)
    3. Return statistics dictionary with all counts

ALGORITHM DetectTrendChanges(current_stats, previous_stats):
    INPUT: Current auth statistics, previous auth statistics
    OUTPUT: Trend assessment (escalating / stable / improving)
    
    1. Extract total failure counts from both snapshots
    2. Calculate percent change:
       - If change > 50% → ESCALATING
       - If change < -30% → IMPROVING
       - Else → STABLE
    3. Return trend assessment with change percentage
```

---

## 3.4 Findings to LLM Prompt Formatting

```
ALGORITHM FormatFindingsForLLM(findings_list):
    INPUT: List of generated security findings
    OUTPUT: Structured prompt text for LLM analysis
    
    1. Sort findings by severity rank (HIGH → MEDIUM → LOW → INFO)
    2. Group findings by severity level
    3. For each severity group, format as prompt section:
       [HIGH SEVERITY]
       - CORR-SSH-001: SSH exposure correlated with active attacks
         Evidence: [list of evidence items]
         Recommendations: [list of actions]
    
    4. Include metadata (finding count, analysis timestamp)
    5. Return complete formatted prompt

ALGORITHM ConstructSystemPrompt():
    INPUT: None
    OUTPUT: System prompt that guides LLM analysis
    
    1. Define LLM role:
       - Explain findings in plain English to non-expert administrator
       - Prioritize next steps
       - Distinguish hygiene (best practices) from threats
    
    2. Provide constraints:
       - Be concise, cite evidence
       - No speculation beyond data
       - Assume reader is junior sysadmin/engineer
    
    3. Return system prompt instructions
```

---

## Summary

| Section | Complexity | Purpose |
|---------|-----------|---------|
| 3.2.1 - Nmap Parsing | Parse XML | Extract network inventory |
| 3.2.2 - Auth Log Parsing | Pattern matching | Normalize system events |
| 3.3.1 - Burst Detection | Sliding window | Identify attack patterns |
| 3.3.2 - Correlation Rules | Fixed ruleset | Generate findings |
| 3.3.3 - Statistics | Aggregation + comparison | Track trends over time |
| 3.4 - LLM Prompt Formatting | Text composition | Prepare findings for AI analysis |

**Use these high-level pseudocodes in your thesis Chapter 3. Keep the detailed implementation versions in `PSEUDOCODES.md` for the appendix.**
