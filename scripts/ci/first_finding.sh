#!/bin/sh
# The 10-minute test (docs/phaseB/B.4 §5.4): from a bare distro, follow the README
# literally to a first finding about a real machine, and time it. Every command here
# is one the README gives; a step the README omits is a README bug to fix.
#
#   first_finding.sh <image> <wheel> <target-host> <ssh-user> <ssh-key>
#
# It runs in a throwaway container of <image> (ubuntu:24.04, debian:12, fedora:latest),
# stands in the built <wheel> for the not-yet-published PyPI package, points Kratos at
# <target-host> over SSH, runs one investigation, and prints the wall-clock time to the
# first finding line. The model key comes from LLM_BASE_URL/LLM_API_KEY/LLM_MODEL in the
# environment (never baked into the image). Nothing is written on the target.
set -eu
IMAGE=${1:?image}; WHEEL=${2:?wheel}; THOST=${3:?target host}; TUSER=${4:?ssh user}; TKEY=${5:?ssh key}
wheel_name=$(basename "$WHEEL")

docker run --rm --network host \
  -e LLM_BASE_URL -e LLM_API_KEY -e LLM_MODEL -e KRATOS_LLM_BACKEND \
  -e KRATOS_SSH_HOST="$THOST" -e KRATOS_SSH_USER="$TUSER" \
  -v "$WHEEL:/tmp/$wheel_name:ro" -v "$TKEY:/tmp/kratos_key:ro" \
  "$IMAGE" sh -eu -c '
    # package manager varies by distro; the README names each.
    if command -v apt-get >/dev/null; then
      apt-get update -qq >/dev/null && apt-get install -y -qq python3 python3-venv python3-pip nmap openssh-client >/dev/null 2>&1
    else
      (dnf install -y -q python3 python3-pip nmap openssh-clients >/dev/null 2>&1 || yum install -y -q python3 python3-pip nmap openssh-clients >/dev/null 2>&1)
    fi
    install -d -m700 ~/.ssh && cp /tmp/kratos_key ~/.ssh/id_ed25519 && chmod 600 ~/.ssh/id_ed25519
    python3 -m venv /venv && . /venv/bin/activate
    pip install -q "/tmp/'"$wheel_name"'"
    kratos init >/dev/null
    echo "=== doctor ==="; kratos doctor || true
    echo "=== first investigation ==="
    start=$(date +%s)
    kratos investigate "check this system for suspicious login activity" 2>/dev/null | tee /tmp/out.txt
    end=$(date +%s)
    echo "=== time to answer: $((end-start))s ==="
  '
