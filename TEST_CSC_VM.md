# Testing CORR-SSH-001 on CSC VM (86.50.169.179)

## Prerequisites
- SSH access to your CSC VM: `ssh ubuntu@86.50.169.179`
- Kratos installed on the VM

## Step 1: Verify SSH Detection

SSH into your VM and run:
```bash
cd ~/kratos  # or wherever you have Kratos
python -m kratos context-collect
```

Check the SSH detection:
```bash
python -c "import json; ctx = json.load(open('data/context/system_context_*.json' | sort | tail -1)); print('SSH Info:', json.dumps(ctx.get('ssh', {}), indent=2))"
```

**Expected output:**
```json
{
  "service_active": true,
  "listening_ports": [22],
  "methods": ["systemctl", "ss"]
}
```

If `service_active` is true OR `listening_ports` contains 22, SSH detection is working! ✓

## Step 2: Generate SSH Failed Login Attempts

**From your LOCAL machine** (not the VM), generate some failed SSH attempts:

### Option A: Wrong username
```bash
ssh wronguser@86.50.169.179
# Enter any password when prompted, or Ctrl+C
# Repeat 3-5 times within 5 minutes
```

### Option B: Wrong key (publickey failure)
```bash
# This will fail publickey auth
ssh -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -i /tmp/fake_key ubuntu@86.50.169.179
# Repeat 3-5 times within 5 minutes
```

### Option C: Multiple wrong passwords
```bash
# Use correct username but wrong password
ssh ubuntu@86.50.169.179
# Enter wrong password 3-5 times within 5 minutes
```

⚠️ **Important:** Don't spam too many attempts! Just 3-5 times is enough to trigger the burst detection.

## Step 3: Run Kratos Pipeline

**Back on the CSC VM**, run the full pipeline:
```bash
cd ~/kratos
python -m kratos run --target 86.50.169.179 --threshold 3 --window-minutes 5
```

This will:
1. Scan 86.50.169.179 (might not find SSH if firewall blocks external scans)
2. Parse auth logs (will find your failed login attempts)
3. Detect SSH bursts
4. Generate findings including CORR-SSH-001

## Step 4: Check for CORR-SSH-001

View all findings:
```bash
python -m kratos findings-show
```

Look for:
```
[HIGH] CORR-SSH-001 — SSH exposed with failed-login burst activity observed
```

Or check specifically:
```bash
python -m kratos findings-show | grep -A 20 "CORR-SSH-001"
```

## Step 5: Verify Evidence

The finding should show:
- **Evidence:**
  - `ssh exposed (context: listening on ports [22])` or similar
  - `ssh_failed_login bursts detected = 1` (or more)
  - `example burst: X events between TIMESTAMP and TIMESTAMP`

- **Playbooks:** 2 playbooks with commands to investigate

## Troubleshooting

### If CORR-SSH-001 doesn't trigger:

**Check 1: Was SSH detected?**
```bash
python -c "import json; ctx = json.load(open(max(glob.glob('data/context/*.json')))); print(ctx.get('ssh'))"
```
- Should show `service_active: true` or `listening_ports: [22]`

**Check 2: Were failures parsed?**
```bash
python -c "import json; stats = json.load(open(max(glob.glob('data/logs/auth_stats_*.json')))); print('SSH failures:', stats['events_by_type'].get('ssh_failed_login', 0))"
```
- Should show count > 0

**Check 3: Were bursts detected?**
```bash
cat data/logs/auth_patterns_*.json | grep -A 5 "ssh_failed_login"
```
- Should show at least one burst with `event_type: ssh_failed_login`

**Check 4: Look at raw logs**
```bash
# Check what sshd logged
journalctl -u ssh --since "10 minutes ago" | grep -i "failed\|invalid\|disconnect"
# or
tail -100 /var/log/auth.log | grep sshd
```

## What Success Looks Like

When working correctly, you'll see:
1. ✅ SSH detected in context (service_active OR listening_ports)
2. ✅ SSH failed login events parsed from auth logs
3. ✅ Burst detected in patterns (3+ events in 5-minute window)
4. ✅ CORR-SSH-001 finding with HIGH severity
5. ✅ Finding appears at top of bundle (due to HIGH priority)

## Safe Testing Tips

- Test during off-hours if possible
- Don't exceed 5-10 failed attempts (avoid triggering fail2ban)
- Use your own IP so you recognize it in logs
- If the VM has fail2ban, you might get temporarily blocked (wait 10-15 minutes)

## Example Bundle Output

After running `python -m kratos prepare-bundle`, you should see:
```
TOP FINDINGS (ordered by severity)
- [HIGH] CORR-SSH-001: SSH exposed with failed-login burst activity observed
  evidence: ssh exposed (context: listening on ports [22])
```

---

**Ready to test?** SSH into `ubuntu@86.50.169.179` and follow the steps!
