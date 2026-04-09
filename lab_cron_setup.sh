#!/bin/bash
# KRATOS LAB DEPLOYMENT — CRON JOB SETUP
# Run this script once to setup all automated monitoring tasks

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}KRATOS Lab Deployment — Cron Setup${NC}"
echo -e "${BLUE}========================================${NC}"

# Make main script executable
chmod +x /home/ubuntu/kratos/lab_deploy.sh
echo -e "${GREEN}✓${NC} Made lab_deploy.sh executable"

# Create crontab entries
cat > /tmp/kratos_crontab << 'CRON_EOF'
# KRATOS Lab Deployment - Automated 5-Day Monitoring
# These jobs run automatically during the lab study week

# DAY 1 (MONDAY) - 8:30 AM: Initialize setup
30 8 * * 1 /home/ubuntu/kratos/lab_deploy.sh init >> /home/ubuntu/kratos/lab_data/logs/cron.log 2>&1

# DAYS 2-5 (TUESDAY-FRIDAY) - 9:00 AM: First analysis cycle
0 9 * * 2-5 /home/ubuntu/kratos/lab_deploy.sh periodic 1 >> /home/ubuntu/kratos/lab_data/logs/cron.log 2>&1

# DAYS 2-5 (TUESDAY-FRIDAY) - 3:00 PM: Second analysis cycle (includes daily report)
0 15 * * 2-5 /home/ubuntu/kratos/lab_deploy.sh periodic 2 >> /home/ubuntu/kratos/lab_data/logs/cron.log 2>&1

# DAY 5 (FRIDAY) - 2:00 PM: Finalize study & cleanup
0 14 * * 5 /home/ubuntu/kratos/lab_deploy.sh finalize >> /home/ubuntu/kratos/lab_data/logs/cron.log 2>&1

CRON_EOF

echo ""
echo -e "${BLUE}Proposed cron jobs:${NC}"
echo "=================================================="
cat /tmp/kratos_crontab | grep -v "^#" | grep -v "^$"
echo "=================================================="
echo ""

# Get current crontab (if exists)
current_crontab=$(crontab -l 2>/dev/null || echo "")

# Merge with new jobs (avoiding duplicates)
if [ -z "$current_crontab" ]; then
    cat /tmp/kratos_crontab | crontab -
    echo -e "${GREEN}✓${NC} Cron jobs installed"
else
    # User already has crontab, show instructions
    echo -e "${BLUE}You already have a crontab. Please add these lines manually:${NC}"
    echo ""
    cat /tmp/kratos_crontab | grep -v "^#" | grep -v "^$"
    echo ""
    echo "To edit your crontab:"
    echo "  crontab -e"
    echo ""
fi

# Verify cron installation
echo ""
echo -e "${BLUE}Current crontab entries:${NC}"
crontab -l | grep kratos || echo "No kratos entries found (will be added on execution)"

echo ""
echo -e "${GREEN}✓ Setup complete!${NC}"
echo ""
echo "=== TIMELINE ==="
echo "Monday 8:30 AM     → Initialization (baseline scan + start capture)"
echo "Tue-Fri 9:00 AM    → Analysis cycle 1"
echo "Tue-Fri 3:00 PM    → Analysis cycle 2 (+ daily report)"
echo "Friday 2:00 PM     → Finalize & generate weekly report"
echo ""
echo "=== WHAT YOU DO ==="
echo "• Day 1 (8:00 AM):  Physically plug in Blade 3 to SPAN port"
echo "• Day 3 (optional): SSH into Blade 3 and run: lab_deploy.sh health"
echo "• Day 5 (2:30 PM):  Physically unplug Blade 3"
echo ""

rm /tmp/kratos_crontab
