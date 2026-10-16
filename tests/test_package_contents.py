"""The built wheel holds every file the code opens at runtime, and the install check
catches a wheel that can't run (docs/phaseB/B.4 §5.1).

The required set is found by reading the source (scripts/ci/package_check.py), never
from a hand-written list -- so these tests prove the scanner, and the CI `package`
job runs the same check against a freshly built wheel."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("package_check", REPO / "scripts" / "ci" / "package_check.py")
pc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pc)


def test_every_runtime_path_resolves_and_the_data_files_are_found():
    required, problems = pc.required_files()
    assert problems == []
    refs = pc.referenced_paths()
    # each kind of reference the code uses today is followed by the scanner
    assert any(where.startswith("kratos/attack/table.py") for ws in refs.values() for where in ws)       # files().joinpath
    assert any(where.startswith("kratos/agent/tools.py") for ws in refs.values() for where in ws)        # parents[1] / "x"
    assert any(where.startswith("kratos/cli/app.py") for ws in refs.values() for where in ws)            # files("kratos")
    data = {r for r in required if not r.endswith(".py")}
    for ref in refs:
        p = REPO / "src" / ref
        if p.is_file() and p.suffix != ".py":
            assert ref in data
        elif p.is_dir():
            assert any(r.startswith(ref + "/") for r in required), ref


def test_a_removed_data_file_fails_the_check():
    required, _ = pc.required_files()
    data = sorted(r for r in required if not r.endswith(".py"))
    assert data
    for gone in data:
        wheel = set(required) - {gone}
        assert pc.missing_from_wheel(wheel, required) == [gone]


def _fake_src(tmp_path: Path, code: str, files: dict[str, str]) -> Path:
    src = tmp_path / "src"
    pkg = src / "kratos"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "mod.py").write_text(code)
    for rel, body in files.items():
        f = src / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    return src


@pytest.mark.parametrize("code", [
    'from importlib import resources\nT = "t.json"\nX = resources.files("kratos.data").joinpath(T)\n',
    'from pathlib import Path\nD = Path(__file__).resolve().parent / "data"\n',
    'import os\nD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "t.json")\n',
])
def test_the_scanner_follows_each_way_code_opens_a_file(tmp_path, code):
    src = _fake_src(tmp_path, code, {"kratos/data/t.json": "{}", "kratos/data/__init__.py": ""})
    required, problems = pc.required_files(src)
    assert problems == [] and "kratos/data/t.json" in required
    assert pc.missing_from_wheel({"kratos/__init__.py", "kratos/mod.py"}, required) == \
        sorted(r for r in required if r.startswith("kratos/data/"))


def test_a_path_that_doesnt_exist_is_a_problem_not_silence(tmp_path):
    src = _fake_src(tmp_path, 'from pathlib import Path\nR = Path(__file__).parent / "rules"\n', {})
    _, problems = pc.required_files(src)
    assert len(problems) == 1 and "kratos/rules" in problems[0] and "kratos/mod.py:2" in problems[0]


def test_a_data_file_the_scanner_cant_follow_is_still_required(tmp_path):
    src = _fake_src(tmp_path, "NAME = 'x'\n", {"kratos/extra/blob.bin": "x"})
    required, _ = pc.required_files(src)
    assert "kratos/extra/blob.bin" in required


def test_a_missing_dependency_fails_the_import_step():
    """The install check imports every module; a dependency the wheel forgot to declare
    (here `univers`, blocked) fails it -- the user would have hit it on first use."""
    code = pc.import_all_modules_code()
    blocked = subprocess.run([sys.executable, "-c", "import sys; sys.modules['univers'] = None\n" + code],
                             capture_output=True, text=True, timeout=300, cwd=REPO)
    assert blocked.returncode == 1
    assert "IMPORT FAILED kratos.pkgvuln.versions" in blocked.stdout


def test_the_import_step_passes_with_every_dependency():
    r = subprocess.run([sys.executable, "-c", pc.import_all_modules_code()], capture_output=True, text=True,
                       timeout=300, cwd=REPO)
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_version_is_the_same_in_pyproject_and_the_package():
    import kratos

    meta = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["version"] == kratos.__version__


def _can_build() -> bool:
    try:
        import setuptools
    except ImportError:
        return False
    return int(setuptools.__version__.split(".")[0]) >= 77


@pytest.mark.skipif(not _can_build(), reason="setuptools>=77 not installed (the CI package job builds the wheel)")
def test_the_real_wheel_holds_every_required_file(tmp_path):
    r = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "-q",
                        "-w", str(tmp_path), str(REPO)], capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr[-2000:]
    wheel = next(tmp_path.glob("kratos_security_assistant-*.whl"))
    required, _ = pc.required_files()
    with zipfile.ZipFile(wheel) as z:
        assert pc.missing_from_wheel(z.namelist(), required) == []
