# Kratos Pseudocodes for Thesis

## Section 3: System Design

### 3.2.1 Nmap Scan Parsing (XML → Structured Dict)

```
FUNCTION parse_nmap_xml_to_dict(xml_path):
    // From: kratos/adapters/nmap_parse.py
    
    TRY:
        tree ← ParseXML(xml_path)
        root ← tree.getroot()
    CATCH ParseError:
        RAISE RuntimeError("Failed to parse XML")
    END TRY
    
    parsed ← {
        'tool': 'nmap',
        'source_file': xml_path.name,
        'parsed_at': CurrentTimestamp(),
        'hosts': []
    }
    
    FOR EACH host IN root.findall('host'):
        addr ← host.find('address')
        ip ← addr.get('addr') IF addr ELSE 'unknown'
        
        status ← host.find('status')
        host_state ← status.get('state') IF status ELSE 'unknown'
        
        host_obj ← {
            'ip': ip,
            'state': host_state,
            'open_ports': []
        }
        
        ports ← host.find('ports')
        IF ports IS NOT NULL THEN:
            FOR EACH port IN ports.findall('port'):
                state ← port.find('state')
                
                // Only include open ports
                IF state IS NOT NULL AND state.get('state') == 'open' THEN:
                    proto ← port.get('protocol', 'unknown')
                    port_num ← port.get('portid', 'unknown')
                    service ← ExtractServiceInfo(port)
                    
                    portData ← {
                        'port': port_num,
                        'protocol': proto,
                        'service': service.name,
                        'version': service.version
                    }
                    host_obj['open_ports'].APPEND(portData)
                END IF
            END FOR
        END IF
        
        parsed['hosts'].APPEND(host_obj)
    END FOR
    
    RETURN parsed
END FUNCTION
```

### 3.2.2 Authentication Log Parsing (Regex-Based Event Extraction)

```
FUNCTION parse_auth_log(log_file_path, log_year):
    // From: kratos/adapters/auth_log_parse.py
    
    events ← []
    lines ← ReadFile(log_file_path)
    
    FOR EACH line IN lines:
        // Step 1: Extract log prefix (timestamp + hostname + program)
        IF line matches ISO_PREFIX_REGEX THEN:
            iso_time ← ExtractGroup('iso')
            hostname ← ExtractGroup('host')
            rest ← ExtractGroup('rest')
            
        ELSE IF line matches SYSLOG_PREFIX_REGEX THEN:
            // Classic format: Feb  2 00:18:01 OPTIMUS sudo: ...
            month, day, time ← ExtractGroups(month, day, time)
            hostname ← ExtractGroup('host')
            rest ← ExtractGroup('rest')
            // Infer year from context
            iso_time ← ConvertSyslogToISO(month, day, time, log_year)
            
        ELSE:
            CONTINUE  // Skip unparseable lines
        END IF
        
        // Step 2: Extract program name and message
        IF rest matches PROGRAM_PREFIX_REGEX THEN:
            program ← ExtractGroup('program')  // sshd, sudo, etc.
            pid ← ExtractGroup('pid')          // optional
            message ← ExtractGroup('msg')
        ELSE:
            CONTINUE
        END IF
        
        // Step 3: Pattern matching for specific events
        
        // SSH failed password
        IF message matches SSH_FAILED_PASSWORD_REGEX THEN:
            user ← ExtractGroup('user')
            source_ip ← ExtractGroup('ip')
            event ← AuthEvent(
                timestamp=iso_time,
                program='sshd',
                event_type='ssh_failed_login',
                user=user,
                source_ip=source_ip,
                raw=line
            )
            events.APPEND(event)
            
        // SSH successful login
        ELSE IF message matches SSH_ACCEPTED_PASSWORD_REGEX THEN:
            user ← ExtractGroup('user')
            source_ip ← ExtractGroup('ip')
            event ← AuthEvent(
                timestamp=iso_time,
                program='sshd',
                event_type='ssh_success_login',
                user=user,
                source_ip=source_ip,
                raw=line
            )
            events.APPEND(event)
            
        // Sudo authentication failure
        ELSE IF message matches SUDO_AUTH_FAILURE_REGEX THEN:
            user ← ExtractGroup('user')
            event ← AuthEvent(
                timestamp=iso_time,
                program='sudo',
                event_type='sudo_pam_auth_failure',
                user=user,
                source_ip=NULL,
                raw=line
            )
            events.APPEND(event)
            
        // Sudo session opened
        ELSE IF message matches SUDO_SESSION_OPEN_REGEX THEN:
            user ← ExtractGroup('user')
            event ← AuthEvent(
                timestamp=iso_time,
                program='sudo',
                event_type='sudo_session_open',
                user=user,
                source_ip=NULL,
                raw=line
            )
            events.APPEND(event)
            
        END IF
    END FOR
    
    RETURN events
END FUNCTION
```

### 3.3.1 Burst Detection (Sliding Window)

```
FUNCTION detect_bursts(events, event_type, time_window, threshold):
    // From: kratos/adapters/auth_log_patterns.py
    // Sliding-window burst detection with merging
    
    // Step 1: Filter events by type and parse timestamps
    filtered_events ← []
    
    FOR EACH event IN events:
        IF event.event_type == event_type THEN:
            dt ← ParseISOTimestamp(event.timestamp)
            IF dt IS NOT NULL THEN:
                filtered_events.APPEND((dt, event))
            END IF
        END IF
    END FOR
    
    filtered_events.SORT_BY(datetime ascending)
    times ← [dt FOR EACH (dt, event) IN filtered_events]
    
    bursts ← []
    n ← filtered_events.LENGTH
    IF n == 0 THEN:
        RETURN bursts
    END IF
    
    // Step 2: Sliding window detection
    i ← 0
    WHILE i < n:
        j ← i
        
        // Find end of window: times[j] - times[i] <= time_window
        WHILE j < n AND (times[j] - times[i]) <= time_window:
            j ← j + 1
        END WHILE
        
        count ← j - i
        
        // If window has >= threshold events, it's a burst
        IF count >= threshold THEN:
            start ← times[i]
            end ← times[j - 1]
            
            // Collect metadata in this window
            window_events ← filtered_events[i:j]
            users ← ExtractField(window_events, 'user')
            source_ips ← ExtractField(window_events, 'source_ip')
            
            burst ← {
                'event_type': event_type,
                'start': start.toISO(),
                'end': end.toISO(),
                'count': count,
                'top_users': CounterMostCommon(users, top_k=5),
                'top_source_ips': CounterMostCommon(source_ips, top_k=5)
            }
            
            // Step 3: Merge overlapping bursts
            IF bursts.LENGTH > 0 AND bursts[-1].event_type == event_type THEN:
                prev_burst ← bursts[-1]
                prev_start ← ParseISO(prev_burst.start)
                prev_end ← ParseISO(prev_burst.end)
                
                // If current burst overlaps with previous (within 1 second), merge
                IF start <= (prev_end + 1 second) THEN:
                    prev_burst.end ← max(prev_end, end).toISO()
                    prev_burst.count ← prev_burst.count + count
                    // Merge top users/ips into previous burst record
                ELSE:
                    bursts.APPEND(burst)
                END IF
            ELSE:
                bursts.APPEND(burst)
            END IF
        END IF
        
        i ← i + 1
    END WHILE
    
    RETURN bursts
END FUNCTION
```

### 3.3.2 Correlation Rules (Fixed Set)

```
FUNCTION generate_findings(nmap_parsed, auth_stats, auth_patterns, system_context, auth_trends):
    // From: kratos/adapters/findings_engine.py
    // Generates findings based on fixed correlation rules
    
    findings ← []
    
    // RULE CORR-001: SSH exposed (nmap) + SSH failed-login burst
    IF _nmap_has_ssh_exposed(nmap_parsed) AND _has_bursts(auth_patterns, 'ssh_failed_login') THEN:
        ssh_bursts ← _bursts_of(auth_patterns, ['ssh_failed_login'])
        
        finding ← {
            'id': 'CORR-001',
            'title': 'SSH exposure correlated with failed-login burst activity',
            'severity': 'medium',
            'evidence': [
                'SSH appears exposed in latest scan (port 22 detected)',
                'SSH failed-login bursts detected = ' + ssh_bursts.LENGTH,
                ... (burst details)
            ],
            'recommendation': [
                'Disable password auth, use key-based auth',
                'Implement rate-limiting or fail2ban',
                'Monitor authentication logs'
            ]
        }
        findings.APPEND(finding)
    END IF
    
    // RULE CORR-002: Sudo failure burst + single sudo user
    sudo_fail_bursts ← _bursts_of(auth_patterns, ['sudo_pam_auth_failure', 'sudo_auth_failure'])
    sudo_members ← ExtractSudoMembers(system_context)
    
    IF sudo_fail_bursts.LENGTH > 0 AND sudo_members.LENGTH == 1 THEN:
        finding ← {
            'id': 'CORR-002',
            'title': 'Privileged auth bursts on single sudo user',
            'severity': 'medium',
            'evidence': [
                'sudo group members = ' + sudo_members.JOIN(','),
                'Sudo failure bursts detected = ' + sudo_fail_bursts.LENGTH,
                ... (burst details)
            ],
            'recommendation': [
                'Verify if failures match expected admin activity',
                'If unexpected, review local user activity'
            ]
        }
        findings.APPEND(finding)
    END IF
    
    // RULE CORR-SSH-001: SSH open (nmap or context) + SSH failed bursts => HIGH
    ssh_from_nmap ← _nmap_has_ssh_exposed(nmap_parsed)
    ssh_from_context ← CheckSSHInContext(system_context)
    ssh_exposed ← ssh_from_nmap OR ssh_from_context
    ssh_failed_bursts ← _bursts_of(auth_patterns, ['ssh_failed_login'])
    
    IF ssh_exposed AND ssh_failed_bursts.LENGTH > 0 THEN:
        evidence ← ['SSH exposure detected (nmap/context)']
        
        IF ssh_from_nmap AND ssh_from_context THEN:
            evidence.APPEND('Confirmed both by scan and running service')
        END IF
        
        evidence.APPEND('SSH failed-login bursts = ' + ssh_failed_bursts.LENGTH)
        
        finding ← {
            'id': 'CORR-SSH-001',
            'title': 'SSH exposure correlated with active exploitation attempts',
            'severity': 'high',  // Elevated from CORR-001
            'evidence': evidence,
            'recommendation': [
                'Immediate: Review failed login attempts and source IPs',
                'Implement IP whitelisting or restrict SSH to VPN/bastion',
                'Disable password auth, enable key-only',
                'Monitor for successful compromises'
            ]
        }
        findings.APPEND(finding)
    END IF
    
    // Additional findings (NET-002, AUTH-001, AUTH-003, AUTH-004, OBS-001, CTX-001)
    // ... (similar pattern, but hardcoded rules, not generic)
    
    RETURN findings
END FUNCTION

FUNCTION _nmap_has_ssh_exposed(nmap_parsed):
    IF NOT nmap_parsed THEN:
        RETURN FALSE
    END IF
    
    FOR EACH host IN nmap_parsed.hosts:
        FOR EACH port IN host.open_ports:
            IF port.port == 22 OR port.service.contains('ssh') THEN:
                RETURN TRUE
            END IF
        END FOR
    END FOR
    
    RETURN FALSE
END FUNCTION

FUNCTION _has_bursts(auth_patterns, event_type):
    IF NOT auth_patterns OR NOT auth_patterns.bursts THEN:
        RETURN FALSE
    END IF
    
    FOR EACH burst IN auth_patterns.bursts:
        IF burst.event_type == event_type THEN:
            RETURN TRUE
        END IF
    END FOR
    
    RETURN FALSE
END FUNCTION
```

### 3.3.3 Event Statistics and Trending

```
FUNCTION compute_auth_stats(events):
    // From: kratos/adapters/auth_log_parse.py
    // Summarize event counts by type
    
    stats ← {
        'total_events': events.LENGTH,
        'events_by_type': {},
        'by_user': {},
        'by_source_ip': {}
    }
    
    FOR EACH event IN events:
        // Count by event type
        event_type ← event.event_type
        stats['events_by_type'][event_type] ← 
            stats['events_by_type'].get(event_type, 0) + 1
        
        // Count by user
        IF event.user THEN:
            stats['by_user'][event.user] ← 
                stats['by_user'].get(event.user, 0) + 1
        END IF
        
        // Count by source IP
        IF event.source_ip THEN:
            stats['by_source_ip'][event.source_ip] ← 
                stats['by_source_ip'].get(event.source_ip, 0) + 1
        END IF
    END FOR
    
    RETURN stats
END FUNCTION

FUNCTION detect_auth_trend_changes(auth_stats_current, auth_stats_previous):
    // From: kratos/adapters/logs_trends.py
    // Detect if auth failure trend is increasing
    
    trend ← {
        'period': 'current_vs_previous',
        'current_failures': 0,
        'previous_failures': 0,
        'trend': 'stable',
        'change_percent': 0.0
    }
    
    // Extract failure counts
    current_failures ← (
        auth_stats_current.events_by_type.get('ssh_failed_login', 0) +
        auth_stats_current.events_by_type.get('sudo_pam_auth_failure', 0) +
        auth_stats_current.events_by_type.get('sudo_auth_failure', 0)
    )
    
    previous_failures ← (
        auth_stats_previous.events_by_type.get('ssh_failed_login', 0) +
        auth_stats_previous.events_by_type.get('sudo_pam_auth_failure', 0) +
        auth_stats_previous.events_by_type.get('sudo_auth_failure', 0)
    )
    
    trend['current_failures'] ← current_failures
    trend['previous_failures'] ← previous_failures
    
    // Calculate trend
    IF previous_failures == 0 THEN:
        IF current_failures > 0 THEN:
            trend['trend'] ← 'new_activity'
            trend['change_percent'] ← 100.0
        END IF
    ELSE:
        change ← (current_failures - previous_failures) / previous_failures
        trend['change_percent'] ← change * 100
        
        IF change > 0.5 THEN:
            trend['trend'] ← 'escalating'
        ELSE IF change < -0.3 THEN:
            trend['trend'] ← 'improving'
        ELSE:
            trend['trend'] ← 'stable'
        END IF
    END IF
    
    RETURN trend
END FUNCTION
```

### 3.4 Findings to Prompt Formatting (Chain-of-Thought)

```
FUNCTION format_findings_for_llm(findings_list):
    // From: kratos/llm_config.py
    // Convert findings into a structured prompt for LLM analysis
    
    // Step 1: Sort findings by severity
    sorted_findings ← Sort(findings_list, BY: severity_rank DESC)
    
    prompt ← ""
    prompt ← prompt + "=== SECURITY FINDINGS ===\n\n"
    
    // Step 2: Group by severity level
    severity_groups ← {
        'high': Filter(sorted_findings, severity='high'),
        'medium': Filter(sorted_findings, severity='medium'),
        'low': Filter(sorted_findings, severity='low'),
        'info': Filter(sorted_findings, severity='info')
    }
    
    FOR EACH severity, group IN severity_groups:
        IF group.LENGTH == 0 THEN:
            CONTINUE
        END IF
        
        prompt ← prompt + "\n[" + severity.UPPER() + " SEVERITY]\n"
        
        FOR EACH finding IN group:
            prompt ← prompt + "\n" + finding.id + ": " + finding.title + "\n"
            
            // Evidence (what we detected)
            prompt ← prompt + "Evidence:\n"
            FOR EACH evidence_item IN finding.evidence:
                prompt ← prompt + "  - " + evidence_item + "\n"
            END FOR
            
            // Recommendation (what to do about it)
            prompt ← prompt + "Current Recommendations:\n"
            FOR EACH rec IN finding.recommendation:
                prompt ← prompt + "  - " + rec + "\n"
            END FOR
            
            // If there are playbooks (detailed remediation steps)
            IF finding.playbooks.LENGTH > 0 THEN:
                prompt ← prompt + "Reference Playbooks:\n"
                FOR EACH playbook IN finding.playbooks:
                    prompt ← prompt + "  " + playbook.title + "\n"
                END FOR
            END IF
        END FOR
    END FOR
    
    RETURN prompt
END FUNCTION

FUNCTION construct_system_prompt():
    // From: kratos/llm_config.py
    // System message that guides the LLM's analysis
    
    system_prompt ← """
You are a security analysis AI that explains findings in plain English.

Your role:
1. Summarize the findings in plain language (avoid jargon when possible)
2. Explain the risk to an administrator who may not be deeply technical
3. Suggest prioritized next steps (what to do first)
4. Distinguish between hygiene (best practices) vs. active threats
5. Ask clarifying questions if the context is ambiguous

Always:
- Be concise and direct
- Cite evidence from the findings
- Avoid speculation beyond what data supports
- Assume the reader is a junior administrator or systems engineer
"""
    
    RETURN system_prompt
END FUNCTION
```

---

## Section 4: Implementation

### 4.2 Auth Log Parsing Pipeline

```
FUNCTION pipeline_auth_log_to_findings(auth_log_path, log_year, data_dir):
    // Full pipeline: read → parse → detect bursts → statistics
    
    // 1. Parse auth log into events
    events ← parse_auth_log(auth_log_path, log_year)
    
    // 2. Save events as JSON
    events_json_path ← data_dir / 'auth_events_' + CurrentTimestamp() + '.json'
    WriteJSON(events_json_path, [AsDict(e) FOR e IN events])
    
    // 3. Compute statistics
    stats ← compute_auth_stats(events)
    stats_path ← data_dir / 'auth_stats_' + CurrentTimestamp() + '.json'
    WriteJSON(stats_path, stats)
    
    // 4. Detect burst patterns (sliding window algorithm)
    bursts ← []
    FOR EACH event_type IN ['ssh_failed_login', 'sudo_pam_auth_failure', 'sudo_auth_failure']:
        window_bursts ← detect_bursts(
            events, 
            event_type, 
            time_window=timedelta(seconds=300),  // 5-minute window
            threshold=5                           // 5+ events = burst
        )
        bursts.EXTEND(window_bursts)
    END FOR
    
    patterns ← {
        'bursts': bursts,
        'source_events_file': events_json_path
    }
    patterns_path ← data_dir / 'auth_patterns_' + CurrentTimestamp() + '.json'
    WriteJSON(patterns_path, patterns)
    
    RETURN { 'events': events, 'stats': stats, 'patterns': patterns }
END FUNCTION
```

### 4.3 Findings Engine Execution

```
FUNCTION run_findings_engine(data_dir):
    // Orchestrate finding generation by loading latest data files
    
    // 1. Load latest input files
    inputs ← find_latest_inputs(data_dir)
    
    nmap_parsed ← NULL
    IF inputs['nmap_parsed'] THEN:
        nmap_parsed ← ReadJSON(inputs['nmap_parsed'])
    END IF
    
    auth_stats ← NULL
    IF inputs['auth_stats'] THEN:
        auth_stats ← ReadJSON(inputs['auth_stats'])
    END IF
    
    auth_patterns ← NULL
    IF inputs['auth_patterns'] THEN:
        auth_patterns ← ReadJSON(inputs['auth_patterns'])
    END IF
    
    system_context ← NULL
    IF inputs['system_context'] THEN:
        system_context ← ReadJSON(inputs['system_context'])
    END IF
    
    auth_trends ← NULL
    IF inputs['auth_trends'] THEN:
        auth_trends ← ReadJSON(inputs['auth_trends'])
    END IF
    
    // 2. Execute correlation rules (generates findings)
    findings ← generate_findings(
        nmap_parsed,
        auth_stats,
        auth_patterns,
        system_context,
        auth_trends
    )
    
    // 3. Sort by severity
    findings.SORT_BY(lambda f: _severity_rank(f.severity), reverse=TRUE)
    
    // 4. Save findings
    findings_path ← data_dir / 'findings_' + CurrentTimestamp() + '.json'
    findings_json ← [AsDict(f) FOR f IN findings]
    WriteJSON(findings_path, findings_json)
    
    RETURN findings
END FUNCTION
```

### 4.4 LLM Server Integration (llama-cpp-python)

```
CLASS LLMServer:
    
    FUNCTION __init__():
        this._llama ← NULL
        this.is_ready ← FALSE
    END FUNCTION
    
    FUNCTION start():
        // Load Qwen2.5-Coder 7B model into memory
        
        IF NOT MODEL_PATH.exists() THEN:
            PrintError('Model file not found at: ' + MODEL_PATH)
            RETURN FALSE
        END IF
        
        PrintStatus('Loading LLM model...')
        
        TRY:
            FROM llama_cpp IMPORT Llama
            
            this._llama ← Llama(
                model_path=MODEL_PATH,
                n_ctx=2048,              // Context window (empirically tested)
                n_gpu_layers=0,          // CPU-only (no GPU available on ARM)
                n_threads=8,
                verbose=FALSE
            )
            
            this.is_ready ← TRUE
            PrintStatus('LLM model loaded successfully')
            RETURN TRUE
            
        CATCH error:
            PrintError('Failed to load model: ' + error)
            RETURN FALSE
        END TRY
    END FUNCTION
    
    FUNCTION chat(user_message, system_message, max_tokens=1024):
        // Send message to loaded model, return response
        
        IF NOT this.is_ready THEN:
            RAISE RuntimeError('LLM server not ready')
        END IF
        
        TRY:
            response ← this._llama.create_chat_completion(
                messages=[
                    {'role': 'system', 'content': system_message},
                    {'role': 'user', 'content': user_message}
                ],
                max_tokens=max_tokens,
                temperature=0.3,           // Lower = more deterministic
                top_p=0.95,
                seed=42                    // Reproducible output
            )
            
            RETURN response['choices'][0]['message']['content']
            
        CATCH timeout_error:
            RAISE RuntimeError('LLM inference timeout (default 900s)')
        CATCH error:
            RAISE RuntimeError('LLM inference error: ' + error)
        END TRY
    END FUNCTION
END CLASS

FUNCTION analyze_findings_with_llm(findings_list):
    // Full LLM analysis pipeline
    
    // 1. Format findings into prompt
    findings_prompt ← format_findings_for_llm(findings_list)
    system_prompt ← construct_system_prompt()
    
    // 2. Initialize LLM server
    llm ← LLMServer()
    IF NOT llm.start() THEN:
        RAISE RuntimeError('Failed to start LLM server')
    END IF
    
    // 3. Send to LLM
    TRY:
        analysis ← llm.chat(
            findings_prompt,
            system_prompt,
            max_tokens=2048
        )
        
        RETURN {
            'success': TRUE,
            'analysis': analysis,
            'findings_count': findings_list.LENGTH
        }
        
    CATCH error:
        RETURN {
            'success': FALSE,
            'error': error.message,
            'findings_count': findings_list.LENGTH
        }
    END TRY
END FUNCTION
```
