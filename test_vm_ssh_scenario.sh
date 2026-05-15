#!/bin/bash
# Kratos CORR-SSH-001 Test Scenario for CSC VM
# This script sets up and tests the SSH exposure + failed login detection

set -e

echo "========================================"
echo "Kratos CORR-SSH-001 Test Scenario"
echo "========================================"
echo ""

# 1. Check SSH is running
echo "[1/6] Checking SSH service status..."
if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
    echo "✓ SSH service is running"
else
    echo "⚠ SSH service not running. Starting would require sudo."
    echo "   On your VM, run: sudo systemctl start ssh"
fi
echo ""

# 2. Check SSH port 22 is listening
echo "[2/6] Checking if SSH port 22 is listening..."
if ss -tuln | grep -q ':22 '; then
    echo "✓ SSH is listening on port 22"
else
    echo "⚠ SSH not listening on port 22"
fi
echo ""

# 3. Generate some failed SSH login attempts (safe local test)
echo "[3/6] Generating SSH failed login attempts (10 attempts)..."
echo "   This will create ~10 failed login events in auth logs"
for i in {1..10}; do
    # Try to SSH with wrong password (will fail immediately with publickey-only)
    # Or use ssh with wrong user - both generate auth failures
    ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no fakeuser@localhost 2>/dev/null || true
done
echo "✓ Failed login attempts generated"
echo ""

# 4. Wait a moment for logs to flush
echo "[4/6] Waiting 3 seconds for logs to flush..."
sleep 3
echo "✓ Done"
echo ""

# 5. Run Kratos full pipeline
echo "[5/6] Running Kratos pipeline..."
python -m kratos run
echo "✓ Pipeline complete"
echo ""

# 6. Show findings
echo "[6/6] Displaying findings..."
echo ""
python -m kratos findings-show
echo ""

echo "========================================"
echo "Test complete!"
echo ""
echo "Expected Results:"
echo "  - If SSH is exposed: CORR-SSH-001 (HIGH) should appear"
echo "  - Evidence should show tcp/22 open + ssh_failed_login bursts"
echo "  - Playbooks should be available for investigation"
echo ""
echo "To see detailed findings:"
echo "  python -m kratos findings-show | less"
echo ""
echo "To generate a bundle for LLM analysis:"
echo "  python -m kratos prepare-bundle"
echo "  cat data/reports/bundle_*.txt"
echo "========================================"
