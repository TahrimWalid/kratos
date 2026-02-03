#!/bin/bash
# Quick test script for CORR-SSH-001 on CSC VM
# Run this ON the CSC VM after generating failed SSH attempts

set -e

echo "=================================================="
echo "CORR-SSH-001 Test Script for CSC VM"
echo "=================================================="
echo ""

# 1. Check SSH detection
echo "[1/5] Checking SSH detection in context..."
python -m kratos context-collect > /dev/null 2>&1
LATEST_CTX=$(ls -t data/context/system_context_*.json | head -1)
python3 << EOF
import json
ctx = json.load(open('$LATEST_CTX'))
ssh = ctx.get('ssh', {})
print(f"  Service active: {ssh.get('service_active')}")
print(f"  Listening ports: {ssh.get('listening_ports')}")
print(f"  Detection methods: {ssh.get('methods')}")
if ssh.get('service_active') or 22 in ssh.get('listening_ports', []):
    print("  ✓ SSH DETECTED!")
else:
    print("  ✗ SSH NOT DETECTED (CORR-SSH-001 won't trigger)")
EOF
echo ""

# 2. Check recent SSH failures
echo "[2/5] Checking recent SSH failures in logs..."
python3 << EOF
import json, glob
try:
    latest = max(glob.glob('data/logs/auth_stats_*.json'), key=lambda x: x)
    stats = json.load(open(latest))
    ssh_fails = stats.get('events_by_type', {}).get('ssh_failed_login', 0)
    print(f"  SSH failed login events: {ssh_fails}")
    if ssh_fails > 0:
        print("  ✓ SSH FAILURES FOUND!")
    else:
        print("  ✗ No SSH failures (generate some from your local machine)")
except:
    print("  ✗ No auth stats found (run kratos logs-parse first)")
EOF
echo ""

# 3. Run full pipeline
echo "[3/5] Running Kratos pipeline..."
python -m kratos run --threshold 3 --window-minutes 5 > /dev/null 2>&1
echo "  ✓ Pipeline complete!"
echo ""

# 4. Check for bursts
echo "[4/5] Checking for SSH bursts..."
python3 << EOF
import json, glob
try:
    latest = max(glob.glob('data/logs/auth_patterns_*.json'), key=lambda x: x)
    patterns = json.load(open(latest))
    ssh_bursts = [b for b in patterns.get('bursts', []) if b.get('event_type') == 'ssh_failed_login']
    print(f"  SSH bursts detected: {len(ssh_bursts)}")
    for b in ssh_bursts:
        print(f"    - {b['count']} events from {b['start']} to {b['end']}")
    if ssh_bursts:
        print("  ✓ BURSTS FOUND!")
    else:
        print("  ✗ No bursts (need 3+ failures within 5 minutes)")
except:
    print("  ✗ No patterns file found")
EOF
echo ""

# 5. Check for CORR-SSH-001
echo "[5/5] Checking for CORR-SSH-001 finding..."
python3 << EOF
import json, glob
try:
    latest = max(glob.glob('data/reports/findings_*.json'), key=lambda x: x)
    report = json.load(open(latest))
    findings = report.get('findings', [])
    corr_ssh = [f for f in findings if f.get('id') == 'CORR-SSH-001']
    
    if corr_ssh:
        f = corr_ssh[0]
        print(f"  ✓✓✓ CORR-SSH-001 TRIGGERED! ✓✓✓")
        print(f"  Severity: {f['severity'].upper()}")
        print(f"  Title: {f['title']}")
        print(f"  Evidence:")
        for e in f['evidence'][:3]:
            print(f"    - {e}")
    else:
        print("  ✗ CORR-SSH-001 not found")
        print(f"  Other findings: {[f.get('id') for f in findings]}")
except Exception as e:
    print(f"  ✗ Error reading findings: {e}")
EOF
echo ""

echo "=================================================="
echo "To view full findings:"
echo "  python -m kratos findings-show"
echo ""
echo "To view bundle:"
echo "  python -m kratos prepare-bundle"
echo "  cat data/reports/bundle_*.txt | head -50"
echo "=================================================="
