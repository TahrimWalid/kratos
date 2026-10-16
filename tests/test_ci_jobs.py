"""CI is one job list (scripts/ci/jobs.toml) run two ways: the GitHub workflow is
generated from it, and scripts/ci/run_local.sh runs it here in containers. These
tests keep the two from drifting and hold the list to what the package promises."""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("kratos_ci", REPO / "scripts" / "ci" / "ci.py")
ci = importlib.util.module_from_spec(_spec)
sys.modules["kratos_ci"] = ci   # dataclasses look their module up here
_spec.loader.exec_module(ci)

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib


def test_the_committed_workflow_is_generated_from_the_job_list():
    assert ci.WORKFLOW.read_text(encoding="utf-8") == ci.render_workflow(ci.load_jobs()), \
        "run: python scripts/ci/ci.py workflow --write"


def test_every_supported_python_has_a_test_job_and_a_classifier():
    meta = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    classified = {c.rsplit(" ", 1)[-1] for c in meta["classifiers"] if re.fullmatch(r".*:: 3\.\d+", c)}
    jobs = {j.name: j for j in ci.load_jobs()}
    tested = {n.split("-", 1)[1] for n in jobs if re.fullmatch(r"test-3\.\d+", n)}
    assert tested == classified == {"3.10", "3.11", "3.12", "3.13"}
    floor = meta["requires-python"].removeprefix(">=")
    assert min(tested, key=lambda v: tuple(map(int, v.split(".")))) == floor
    for v in tested:
        assert jobs[f"test-{v}"].image == f"python:{v}-slim"


def test_the_jobs_the_spec_asks_for_exist():
    names = {j.name for j in ci.load_jobs()}
    assert {"lint", "test-tz", "agent-bundle", "awk", "eval-replay-smoke"} <= names
    assert {"package-3.10", "package-3.13"} <= names
    bundle = next(j for j in ci.load_jobs() if j.name == "agent-bundle")
    assert bundle.image == "python:3.8-slim" and bundle.setup == []   # nothing installed for the agent
    tz = next(j for j in ci.load_jobs() if j.name == "test-tz")
    assert tz.env["TZ"] == "Europe/Helsinki" and "tzdata" in tz.apt


def test_every_action_is_pinned_by_commit():
    for wf in (REPO / ".github" / "workflows").glob("*.yml"):
        for line in wf.read_text(encoding="utf-8").splitlines():
            m = re.search(r"uses:\s*(\S+)", line)
            if m:
                assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", m.group(1)), f"{wf.name}: {line.strip()}"
                assert "#" in line, f"{wf.name}: name the release next to the pin: {line.strip()}"


def test_ci_sends_nothing_anywhere():
    """No secrets, no model keys in CI (B.4 decision 3)."""
    text = (REPO / "scripts" / "ci" / "jobs.toml").read_text(encoding="utf-8") + ci.WORKFLOW.read_text(encoding="utf-8")
    for word in ("secrets.", "LLM_API_KEY", "OTX_API_KEY", "ABUSEIPDB_API_KEY", "id-token"):
        assert word not in text


def test_a_local_job_unpacks_the_tree_and_runs_every_step():
    job = ci.Job(name="x", image="python:3.12-slim", apt=["gawk"], setup=["pip install a"], run=["echo 1", "echo 2"])
    script = ci.job_script(job)
    assert script.startswith("set -e\n")
    order = [script.index(s) for s in ("tar -xf /ci/src.tar", "apt-get install", "pip install a", "echo 1", "echo 2")]
    assert order == sorted(order)
