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
# KRATOS Lab Deployment - Automated 3-Day Intensive Monitoring
# Wednesday 10:30 AM - Friday 5:00 PM (3 days)

# WEDNESDAY 4:20 PM: Initialize setup
20 16 * * 3 /home/ubuntu/kratos/lab_deploy.sh init >> /home/ubuntu/kratos/lab_data/logs/cron.log 2>&1

# WED-THU 1:00 PM: First analysis cycle
0 13 * * 3-4 /home/ubuntu/kratos/lab_deploy.sh periodic 1 >> /home/ubuntu/kratos/lab_data/logs/cron.log 2>&1

# WED-THU 3:00 PM: Second analysis cycle
0 15 * * 3-4 /home/ubuntu/kratos/lab_deploy.sh periodic 2 >> /home/ubuntu/kratos/lab_data/logs/cron.log 2>&1

# WED-THU 8:00 PM: Third analysis cycle (covers evening activity)
0 20 * * 3-4 /home/ubuntu/kratos/lab_deploy.sh periodic 3 >> /home/ubuntu/kratos/lab_data/logs/cron.log 2>&1

# FRIDAY 10:00 AM: Fourth analysis cycle (morning of last day)
0 10 * * 5 /home/ubuntu/kratos/lab_deploy.sh periodic 4 >> /home/ubuntu/kratos/lab_data/logs/cron.log 2>&1

# FRIDAY 4:00 PM: Finalize study & cleanup (completes before 5 PM)
0 16 * * 5 /home/ubuntu/kratos/lab_deploy.sh finalize >> /home/ubuntu/kratos/lab_data/logs/cron.log 2>&1

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
echo "=== TIMELINE (WED 10:30 AM - FRI 5:00 PM) ==="
echo "Wednesday 10:30 AM  → Initialization (baseline scan + start capture)"
echo "Wed-Thu 1:00 PM     → Analysis cycle 1"
echo "Wed-Thu 3:00 PM     → Analysis cycle 2"
echo "Wed-Thu 8:00 PM     → Analysis cycle 3 (evening patterns)"
echo "Friday 10:00 AM     → Analysis cycle 4 (final morning)"
echo "Friday 4:00 PM      → Finalize & generate final report"
echo ""
echo "=== WHAT YOU DO ==="
echo "• Wednesday 10:00 AM:   Physically plug in Blade 3 to lab switch port"
echo "• Thursday (optional):  SSH to 10.6.0.123 and run: lab_deploy.sh health"
echo "• Friday 5:00 PM:       Physically unplug Blade 3"
echo ""
echo -e "${BLUE}=== 4X DAILY SAMPLING (INTENSIVE - 3 DAYS) ===${NC}"
echo "High-frequency sampling compensates for shorter window:"
echo "  • 1:00 PM:  Early analysis - catch morning activity"
echo "  • 3:00 PM:  Mid-afternoon patterns"
echo "  • 8:00 PM:  Evening/after-hours behavior"
echo "  • 10:00 AM (Fri): Final morning snapshot before finalize"
echo ""

rm /tmp/kratos_crontab
