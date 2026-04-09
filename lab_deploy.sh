#!/bin/bash
# KRATOS LAB DEPLOYMENT — FULLY AUTOMATED 5-DAY MONITORING
# This script handles all automated tasks for the university lab network study

set -e  # Exit on any error

# ============================================================================
# CONFIGURATION
# ============================================================================

LAB_SUBNET="192.168.1.0/24"          # CHANGE THIS to your lab subnet
LAB_INTERFACE="eth0"                 # Network interface connected to SPAN port
DATA_DIR="/home/ubuntu/kratos/lab_data"
VENV_PATH="/home/ubuntu/kratos/venv"
KRATOS_SRC="/home/ubuntu/kratos/src"
LOG_DIR="${DATA_DIR}/logs"
BACKUP_DIR="${DATA_DIR}/backups"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} INFO: $1"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ✓ $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ⚠ $1"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ✗ $1" >&2
}

# ============================================================================
# PHASE 1: INITIAL SETUP (Day 1 Morning)
# ============================================================================

setup_lab_environment() {
    log_info "=== PHASE 1: LAB ENVIRONMENT SETUP ==="
    
    # Create directories
    log_info "Creating data directories..."
    mkdir -p "$DATA_DIR"/{captures,anomalies,reports,logs,database}
    mkdir -p "$BACKUP_DIR"
    mkdir -p "${LOG_DIR}/daily"
    
    log_success "Directories created: $DATA_DIR"
    
    # Verify network interface
    log_info "Checking network interface: $LAB_INTERFACE"
    if ! ip link show "$LAB_INTERFACE" &>/dev/null; then
        log_error "Interface $LAB_INTERFACE not found!"
        log_error "Available interfaces:"
        ip link show | grep "^[0-9]"
        return 1
    fi
    log_success "Network interface $LAB_INTERFACE is UP"
    
    # Verify tcpdump is available
    log_info "Checking tcpdump..."
    if ! command -v tcpdump &>/dev/null; then
        log_error "tcpdump not installed. Run: sudo apt install tcpdump"
        return 1
    fi
    log_success "tcpdump found"
    
    # Verify venv
    log_info "Checking Python venv..."
    if [ ! -f "$VENV_PATH/bin/activate" ]; then
        log_error "Venv not found at $VENV_PATH"
        return 1
    fi
    log_success "Venv is ready"
    
    # Create initialization marker
    echo "LAB_START_DATE=$(date +%Y%m%d)" > "$DATA_DIR/.lab_info"
    echo "LAB_SUBNET=$LAB_SUBNET" >> "$DATA_DIR/.lab_info"
    echo "LAB_INTERFACE=$LAB_INTERFACE" >> "$DATA_DIR/.lab_info"
    
    log_success "Environment setup complete!"
    return 0
}

# ============================================================================
# PHASE 2: BASELINE SCAN & DISCOVERY (Day 1 - ~8:30 AM)
# ============================================================================

run_baseline_scan() {
    log_info "=== PHASE 2: BASELINE NETWORK SCAN ==="
    
    source "$VENV_PATH/bin/activate"
    export PYTHONPATH="$KRATOS_SRC"
    
    local day1_dir="${DATA_DIR}/logs/day1"
    mkdir -p "$day1_dir"
    
    log_info "Scanning lab network: $LAB_SUBNET"
    PYTHONPATH="$KRATOS_SRC" python3 -m kratos scan --target "$LAB_SUBNET" \
        > "$day1_dir/scan.log" 2>&1
    
    log_info "Parsing scan results..."
    PYTHONPATH="$KRATOS_SRC" python3 -m kratos scan-parse \
        > "$day1_dir/scan_parse.log" 2>&1
    
    log_info "Getting scan summary..."
    PYTHONPATH="$KRATOS_SRC" python3 -m kratos scan-summary \
        > "$day1_dir/scan_summary.txt" 2>&1
    
    log_success "Baseline scan complete"
    cat "$day1_dir/scan_summary.txt"
    
    return 0
}

# ============================================================================
# PHASE 3: CONTINUOUS MONITORING (Days 1-5, 24/7)
# ============================================================================

start_continuous_capture() {
    log_info "=== PHASE 3: STARTING CONTINUOUS CAPTURE (24/7) ==="
    
    local capture_file="${DATA_DIR}/captures/continuous_capture_$(date +%Y%m%d_%H%M%S).pcap"
    
    log_info "Starting tcpdump capture to: $capture_file"
    log_info "This will run continuously... Let network traffic flow!"
    
    # Start tcpdump in background, logged to file
    sudo tcpdump -i "$LAB_INTERFACE" -w "$capture_file" -C 500 -W 10 \
        > "${LOG_DIR}/tcpdump.log" 2>&1 &
    
    local tcpdump_pid=$!
    echo $tcpdump_pid > "${DATA_DIR}/.tcpdump_pid"
    
    log_success "tcpdump started (PID: $tcpdump_pid)"
    log_info "Capture file: $capture_file"
    log_warning "This will run continuously. To stop: sudo kill $tcpdump_pid"
    
    return 0
}

# ============================================================================
# PHASE 4: PERIODIC ANALYSIS (Runs on schedule: 9 AM, 3 PM daily)
# ============================================================================

periodic_analysis() {
    local cycle_num=$1
    local day_number=$(date +%d)
    
    log_info "=== PERIODIC ANALYSIS CYCLE $cycle_num (Day $day_number) ==="
    
    source "$VENV_PATH/bin/activate"
    export PYTHONPATH="$KRATOS_SRC"
    
    local analysis_dir="${DATA_DIR}/logs/day${day_number}/cycle_$cycle_num"
    mkdir -p "$analysis_dir"
    
    # 1. Capture recent traffic (5-minute sample)
    log_info "Capturing 5-minute traffic sample..."
    PYTHONPATH="$KRATOS_SRC" python3 -m kratos network-capture \
        --duration 300 --interface "$LAB_INTERFACE" \
        > "$analysis_dir/capture.log" 2>&1
    
    # 2. Run anomaly detection
    log_info "Running anomaly detection..."
    PYTHONPATH="$KRATOS_SRC" python3 -m kratos network-anomalies \
        > "$analysis_dir/anomalies.log" 2>&1
    
    # 3. Store anomalies in database
    log_info "Storing anomalies in database..."
    PYTHONPATH="$KRATOS_SRC" python3 -m kratos store-anomalies \
        > "$analysis_dir/store.log" 2>&1
    
    # 4. Generate daily report (once per day at 3 PM)
    if [ "$(date +%H)" -eq "15" ]; then
        log_info "Generating daily report..."
        PYTHONPATH="$KRATOS_SRC" python3 -m kratos daily-report \
            > "$analysis_dir/daily_report.log" 2>&1
    fi
    
    log_success "Analysis cycle complete"
    
    # 5. Check for anomalies and log summary
    local anomaly_count=$(grep -c "\"severity\": \"HIGH\"" "$analysis_dir/anomalies.log" 2>/dev/null || echo "0")
    log_info "High-severity anomalies found: $anomaly_count"
    
    return 0
}

# ============================================================================
# PHASE 5: HEALTH CHECK (Manual check on Day 3)
# ============================================================================

health_check() {
    log_info "=== HEALTH CHECK ==="
    
    # Check tcpdump is running
    if [ -f "${DATA_DIR}/.tcpdump_pid" ]; then
        local pid=$(cat "${DATA_DIR}/.tcpdump_pid")
        if ps -p "$pid" > /dev/null; then
            log_success "tcpdump is running (PID: $pid)"
        else
            log_error "tcpdump crashed! PID: $pid not found"
            return 1
        fi
    fi
    
    # Check disk space
    local available_gb=$(df "$DATA_DIR" | tail -1 | awk '{print $4/1024/1024}')
    log_info "Available disk space: ${available_gb:.1f} GB"
    if (( $(echo "$available_gb < 1" | bc -l) )); then
        log_warning "Low disk space! Consider archiving old captures."
    fi
    
    # Check database exists
    if [ -f "$DATA_DIR/database/kratos.db" ]; then
        local db_size=$(du -h "$DATA_DIR/database/kratos.db" | awk '{print $1}')
        log_success "Database exists (size: $db_size)"
    else
        log_warning "Database not yet created"
    fi
    
    # Check log files
    local daily_logs=$(find "$DATA_DIR/logs" -name "*.log" | wc -l)
    log_info "Log files collected: $daily_logs"
    
    # Check captures
    local capture_files=$(find "$DATA_DIR/captures" -name "*.pcap" | wc -l)
    log_success "PCAP files captured: $capture_files"
    
    # Show last analysis
    local latest_analysis=$(find "$DATA_DIR/logs" -name "anomalies.log" -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
    if [ -n "$latest_analysis" ]; then
        log_info "Latest anomaly detection:"
        tail -20 "$latest_analysis"
    fi
    
    log_success "Health check complete. System appears to be running normally."
    
    return 0
}

# ============================================================================
# PHASE 6: FINAL ANALYSIS & CLEANUP (Day 5 Afternoon)
# ============================================================================

finalize_lab_study() {
    log_info "=== PHASE 6: FINALIZING LAB STUDY ==="
    
    source "$VENV_PATH/bin/activate"
    export PYTHONPATH="$KRATOS_SRC"
    
    # 1. Stop continuous capture
    if [ -f "${DATA_DIR}/.tcpdump_pid" ]; then
        local pid=$(cat "${DATA_DIR}/.tcpdump_pid")
        log_info "Stopping tcpdump (PID: $pid)..."
        sudo kill $pid 2>/dev/null || true
        sleep 2
        log_success "tcpdump stopped"
    fi
    
    # 2. Generate final weekly report
    log_info "Generating final weekly report..."
    PYTHONPATH="$KRATOS_SRC" python3 -m kratos weekly-report \
        > "${DATA_DIR}/logs/final_weekly_report.log" 2>&1
    
    # 3. Generate summary analysis
    log_info "Generating lab summary..."
    python3 - << 'SUMMARY_EOF'
import os
import json
from pathlib import Path

data_dir = "/home/ubuntu/kratos/lab_data"

# Count files
captures = list(Path(f"{data_dir}/captures").glob("*.pcap"))
reports = list(Path(f"{data_dir}/reports").glob("*.html"))
logs = list(Path(f"{data_dir}/logs").glob("**/*.log"))

summary = {
    "total_pcap_files": len(captures),
    "total_reports": len(reports),
    "total_log_entries": len(logs),
    "data_directory": data_dir,
    "study_duration": "5 days",
    "lab_subnet": "192.168.1.0/24"
}

summary_file = f"{data_dir}/LAB_STUDY_SUMMARY.json"
with open(summary_file, 'w') as f:
    json.dump(summary, f, indent=2)

print(f"✓ Summary saved to: {summary_file}")
print(json.dumps(summary, indent=2))
SUMMARY_EOF
    
    # 4. Create backup
    log_info "Creating backup of lab data..."
    local backup_file="$BACKUP_DIR/lab_data_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "$backup_file" -C "$DATA_DIR" . --exclude='*.pcap' 2>/dev/null
    log_success "Backup created: $backup_file"
    
    # 5. Cleanup
    log_info "Cleaning up temporary files..."
    rm -f "${DATA_DIR}/.tcpdump_pid"
    
    log_success "Lab study finalized!"
    log_info "All data available in: $DATA_DIR"
    
    return 0
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

main() {
    local command=${1:-help}
    
    case "$command" in
        init)
            # Day 1 morning setup
            setup_lab_environment
            run_baseline_scan
            start_continuous_capture
            log_success "Day 1 initialization complete!"
            ;;
        
        periodic)
            # Run on schedule (9 AM and 3 PM daily)
            cycle_num=${2:-1}
            periodic_analysis "$cycle_num"
            ;;
        
        health)
            # Day 3 manual check
            health_check
            ;;
        
        finalize)
            # Day 5 afternoon
            finalize_lab_study
            log_success "Lab study complete! Ready for analysis."
            ;;
        
        cleanup)
            # Emergency stop
            log_warning "Cleaning up and stopping all monitoring..."
            if [ -f "${DATA_DIR}/.tcpdump_pid" ]; then
                sudo kill $(cat "${DATA_DIR}/.tcpdump_pid") 2>/dev/null || true
            fi
            log_success "Cleanup complete"
            ;;
        
        *)
            echo "KRATOS Lab Deployment Script"
            echo "Usage: $0 {init|periodic|health|finalize|cleanup}"
            echo ""
            echo "Commands:"
            echo "  init       - Initialize (Day 1, 8:30 AM)"
            echo "  periodic   - Run analysis cycle (9 AM & 3 PM)"
            echo "  health     - Check system status (Day 3)"
            echo "  finalize   - Finalize study (Day 5, 2:00 PM)"
            echo "  cleanup    - Emergency stop"
            echo ""
            echo "Example cron jobs:"
            echo "  0 8 * * 1 /home/ubuntu/kratos/lab_deploy.sh init"
            echo "  0 9 * * 2-5 /home/ubuntu/kratos/lab_deploy.sh periodic 1"
            echo "  0 15 * * 2-5 /home/ubuntu/kratos/lab_deploy.sh periodic 2"
            echo "  0 14 * * 5 /home/ubuntu/kratos/lab_deploy.sh finalize"
            ;;
    esac
}

main "$@"
