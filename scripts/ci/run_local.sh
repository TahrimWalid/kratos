#!/bin/sh
# Run the CI jobs here, each in a fresh container -- the same jobs as .github/workflows/ci.yml
# (both come from scripts/ci/jobs.toml). Usage: scripts/ci/run_local.sh [-j N] [job ...]
set -e
cd "$(dirname "$0")/../.."
exec python3 scripts/ci/ci.py local "$@"
