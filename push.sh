#!/bin/bash
# Quick sync to CSC VM for testing

rsync -avz --exclude='venv/' --exclude='.venv/' --exclude='__pycache__/' --exclude='*.pyc' --exclude='.git/' \
  /home/walid000/kratos/ ubuntu@86.50.169.179:~/kratos/

echo "[PUSH] Synced to CSC VM"
