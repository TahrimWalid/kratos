#!/bin/bash
# Test script for Kratos on CSC VM
# This script will help you test CORR-SSH-001 detection

set -e

echo "==================================================================="
echo "Kratos CSC VM Testing Script"
echo "==================================================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Step 1: Check if we're on the CSC VM
echo -e "${YELLOW}Step 1: Environment Check${NC}"
echo "Hostname: $(hostname)"
echo "User: $(whoami)"
echo ""

# Step 2: Test SSH detection
echo -e "${YELLOW}Step 2: Test SSH Detection in Context${NC}"
echo "Running: kratos context-collect"
python -m kratos context-collect

LATEST_CTX=$(ls -t data/context/system_context_*.json | head -1)
echo "Latest context: $LATEST_CTX"
echo ""
echo "SSH section from context:"
python -c "import json; ctx = json.load(open('$LATEST_CTX')); ssh = ctx.get('ssh', {}); print('  service_active:', ssh.get('service_active')); print('  listening_ports:', ssh.get('listening_ports')); print('  methods:', ssh.get('methods'))"
echo ""

# Check if SSH is detected
SSH_DETECTED=$(python -c "import json; ctx = json.load(open('$LATEST_CTX')); ssh = ctx.get('ssh', {}); print('yes' if ssh.get('listening_ports') else 'no')")

if [ "$SSH_DETECTED" = "yes" ]; then
    echo -e "${GREEN}✓ SSH detected in context!${NC}"
else
    echo -e "${RED}✗ SSH not detected in context${NC}"
    echo "This is expected if SSH is not running."
fi
echo ""

# Step 3: Instructions for generating SSH failures
echo -e "${YELLOW}Step 3: Generate SSH Failed Login Attempts${NC}"
echo "From your LOCAL machine (laptop), run these commands:"
echo ""
echo -e "${GREEN}# Option 1: Wrong username (will create 'Invalid user' logs)${NC}"
echo "  ssh nonexistentuser@YOUR_VM_IP"
echo ""
echo -e "${GREEN}# Option 2: Wrong key / no key (will create 'Failed publickey' logs)${NC}"
echo "  ssh -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -i /tmp/fake_key ubuntu@YOUR_VM_IP"
echo ""
echo -e "${GREEN}# Repeat 4-5 times within 5 minutes to create a burst${NC}"
echo ""
echo "Press ENTER when you've generated some failed logins..."
read

# Step 4: Parse auth logs
echo -e "${YELLOW}Step 4: Parse Authentication Logs${NC}"
echo "Running: kratos logs-parse"
python -m kratos logs-parse

LATEST_STATS=$(ls -t data/logs/auth_stats_*.json | head -1)
echo "Latest stats: $LATEST_STATS"
echo ""
echo "SSH failed login events:"
python -c "import json; stats = json.load(open('$LATEST_STATS')); events = stats.get('events_by_type', {}); print('  ssh_failed_login:', events.get('ssh_failed_login', 0)); print('  ssh_invalid_user:', events.get('ssh_invalid_user', 0))"
echo ""

# Step 5: Detect patterns/bursts
echo -e "${YELLOW}Step 5: Detect Authentication Patterns/Bursts${NC}"
LATEST_EVENTS=$(ls -t data/logs/auth_events_*.json | head -1)
echo "Running: kratos logs-patterns --events-file $LATEST_EVENTS --threshold 3"
python -m kratos logs-patterns --events-file "$LATEST_EVENTS" --threshold 3

LATEST_PATTERNS=$(ls -t data/logs/auth_patterns_*.json | head -1)
echo "Latest patterns: $LATEST_PATTERNS"
echo ""
echo "SSH bursts detected:"
python -c "import json; patterns = json.load(open('$LATEST_PATTERNS')); bursts = [b for b in patterns.get('bursts', []) if b.get('event_type') == 'ssh_failed_login']; print(f'  Count: {len(bursts)}'); [print(f'  - {b[\"count\"]} events from {b[\"start\"]} to {b[\"end\"]}') for b in bursts]"
echo ""

# Step 6: Run full pipeline
echo -e "${YELLOW}Step 6: Run Full Kratos Pipeline${NC}"
echo "Running: kratos run"
python -m kratos run
echo ""

# Step 7: Check for CORR-SSH-001
echo -e "${YELLOW}Step 7: Check for CORR-SSH-001 Finding${NC}"
echo "Running: kratos findings-show"
python -m kratos findings-show | head -30
echo ""

# Check if CORR-SSH-001 exists
CORR_SSH_FOUND=$(python -c "import json; findings = json.load(open('$(ls -t data/reports/findings_*.json | head -1)')); found = any(f['id'] == 'CORR-SSH-001' for f in findings.get('findings', [])); print('yes' if found else 'no')")

if [ "$CORR_SSH_FOUND" = "yes" ]; then
    echo -e "${GREEN}✓✓✓ SUCCESS! CORR-SSH-001 detected!${NC}"
    echo ""
    echo "Showing CORR-SSH-001 details:"
    python -c "import json; findings = json.load(open('$(ls -t data/reports/findings_*.json | head -1)')); corr = [f for f in findings.get('findings', []) if f['id'] == 'CORR-SSH-001'][0]; print('ID:', corr['id']); print('Severity:', corr['severity'].upper()); print('Evidence:'); [print(f'  - {e}') for e in corr['evidence']]; print('Playbooks:', len(corr.get('playbooks', [])))"
else
    echo -e "${RED}✗ CORR-SSH-001 not found${NC}"
    echo "Possible reasons:"
    echo "  - SSH not detected as exposed"
    echo "  - No SSH failed login bursts detected"
    echo "  - Threshold too high (try --threshold 2)"
fi
echo ""

# Step 8: Generate bundle
echo -e "${YELLOW}Step 8: Generate LLM-Ready Bundle${NC}"
echo "Running: kratos prepare-bundle"
python -m kratos prepare-bundle
LATEST_BUNDLE=$(ls -t data/reports/bundle_*.txt | head -1)
echo "Bundle: $LATEST_BUNDLE"
echo ""
echo "Top 5 findings in bundle:"
grep -A 1 "^\- \[" "$LATEST_BUNDLE" | head -10
echo ""

echo "==================================================================="
echo -e "${GREEN}Testing Complete!${NC}"
echo "==================================================================="
echo ""
echo "Next steps:"
echo "  1. Review findings: kratos findings-show"
echo "  2. Check bundle: cat $LATEST_BUNDLE"
echo "  3. Run playbook commands from CORR-SSH-001"
