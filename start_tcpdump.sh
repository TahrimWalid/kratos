#!/bin/bash
# Persistent tcpdump startup script
CAPTURE_DIR="/home/ubuntu/kratos/lab_data/captures"
LOG_FILE="/home/ubuntu/kratos/lab_data/logs/tcpdump.log"

# Ensure directory has right permissions
sudo chmod 777 "$CAPTURE_DIR"

# Kill any existing tcpdump
sudo pkill -f "tcpdump.*enP2p36s0" 2>/dev/null || true

# Start tcpdump with full path, absolutely detached
exec sudo -n tcpdump -i enP2p36s0 -w "$CAPTURE_DIR/lab_capture.pcap" -C 100 -W 5 >> "$LOG_FILE" 2>&1 &
