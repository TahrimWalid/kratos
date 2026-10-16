"""scripts/ci/agent_bundle.py builds the sub-agent bundle for the Python 3.8 CI job
without importing kratos (it reads installer.py's source text). These tests keep
that copy of the file list identical to the installer's real one, and prove the
job's import step catches a bundle file that needs a non-stdlib module."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from kratos.subagent import installer

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("agent_bundle", REPO / "scripts" / "ci" / "agent_bundle.py")
ab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ab)


def test_the_ci_bundle_is_the_installers_bundle():
    ci = ab.bundle_sources()
    real = installer.read_bundle_files()
    assert set(ci) == set(real)
    for name, path in ci.items():
        assert path.read_text(encoding="utf-8") == real[name], name


def test_the_built_bundle_imports_with_the_standard_library_only(tmp_path):
    ab.build(tmp_path)
    assert ab.import_check(tmp_path) == 0


def test_a_bundle_file_importing_a_third_party_module_fails(tmp_path):
    pkg = ab.build(tmp_path)
    reads = pkg / "reads.py"
    reads.write_text("import requests  # not in the standard library\n" + reads.read_text())
    import requests  # noqa: F401 -- installed here, so only the isolation can make the import fail

    assert ab.import_check(tmp_path, python=sys.executable) == 1
