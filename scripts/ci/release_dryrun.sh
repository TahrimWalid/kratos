#!/bin/sh
# A local dry run of .github/workflows/release.yml -- everything up to, but NOT including,
# the PyPI upload (the repo isn't pushed; the owner runs the real release after the review).
# Builds the wheel + sdist, checks them, checks the version gate, and shows what the
# attestation step would sign. Nothing leaves this machine.
set -e
cd "$(dirname "$0")/../.."
out=$(mktemp -d)
echo ":: build"
python -m build -o "$out"
echo ":: twine check"
python -m twine check --strict "$out"/*
echo ":: package-data check"
python scripts/ci/package_check.py contents "$out"/*.whl
ver=$(python -c 'import pathlib,sys
try: import tomllib
except ImportError: import tomli as tomllib
print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')
echo ":: version gate -> $ver (workflow_dispatch input must match this)"
echo ":: attestation would sign these subjects:"
ls -1 "$out"
echo ":: STOP before upload (Trusted Publishing runs only on GitHub, on the protected pypi environment)"
rm -rf "$out"
echo "release dry run OK"
