"""E.7b reproduction (§3.7): the real dangerous call is never run (the recorder is the only
callee), a request value that reaches it is `reproduced`, a guarded look-alike is not, a route
that needs a real dependency is `needs_validation`, reproduction is off without the sandbox, and
a fix re-check runs the same harness. Runs the code-authored harness through a LOCAL isolated
pytest subprocess (no Incus), standing in for the sandbox runner.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


import kratos
from kratos.review import reproduce as R
from kratos.review import slice as SL
from kratos.review.verdict import R_NOT_ATTEMPTED, R_NOT_REPRODUCED, R_OFF, R_REPRODUCED

_SRC = str(Path(kratos.__file__).resolve().parents[1])


class _Res:
    def __init__(self, cp: subprocess.CompletedProcess):
        self.passed = cp.returncode == 0
        self.timed_out = cp.returncode == 124
        self.infra_error = None
        self.stdout = cp.stdout
        self.stderr = cp.stderr


def _local_runner(candidate: Path, harness: Path):
    cp = subprocess.run([sys.executable, "-I", "-m", "pytest", str(harness), "-q"],
                        capture_output=True, text=True, timeout=90,
                        env={"PYTHONPATH": _SRC, "PATH": os.environ.get("PATH", "")})
    return _Res(cp)


def _slice(app_src: str, func: str, cls: str):
    slices, _stats, idx = SL.slice_root("/srv/app", {"app.py": app_src}, file_hashes={"app.py": "h"},
                                        all_sizes={"app.py": len(app_src)})
    sl = next(s for s in slices if s.function == func and s.cls == cls)
    return sl, idx


VULN = '''
import os, flask
app = flask.Flask(__name__)
@app.route("/ping")
def ping():
    host = flask.request.args.get("host")
    os.system("ping -c1 " + host)
    return "ok"
@app.route("/safe")
def safe():
    host = flask.request.args.get("host")
    if host not in ("a", "b"):
        flask.abort(400)
    os.system("ping -c1 " + host)
    return "ok"
'''


def test_selfcontained_confirmed(tmp_path):
    sl, idx = _slice(VULN, "ping", "exec")
    rep = R.reproduce(sl, idx, data_dir=tmp_path, run_id="r1", enabled=True, runner=_local_runner)
    assert rep.status == R_REPRODUCED
    assert "os.system" in rep.evidence


def test_guarded_lookalike_not_reproduced(tmp_path):
    sl, idx = _slice(VULN, "safe", "exec")
    rep = R.reproduce(sl, idx, data_dir=tmp_path, run_id="r2", enabled=True, runner=_local_runner)
    assert rep.status == R_NOT_REPRODUCED


def test_real_call_never_runs(tmp_path):
    """The recorder is the only callee: the harness replaces os.system, so even a reproduced
    flow spawns no real process. Proven by a runner that fails if the subprocess ever forked a
    `ping` (it records the child's own process tree would show it) -- here we assert the harness
    itself swaps the call: a sentinel file the real os.system WOULD create never appears."""
    sentinel = tmp_path / "SHOULD_NOT_EXIST"
    app = f'''
import os, flask
app = flask.Flask(__name__)
@app.route("/x")
def x():
    v = flask.request.args.get("v")
    os.system("touch {sentinel} # " + v)
    return "ok"
'''
    sl, idx = _slice(app, "x", "exec")
    rep = R.reproduce(sl, idx, data_dir=tmp_path, run_id="r3", enabled=True, runner=_local_runner)
    assert rep.status == R_REPRODUCED
    assert not sentinel.exists()        # the real os.system was never executed


def test_needs_app_needs_validation(tmp_path):
    app = '''
import flask, psycopg2
app = flask.Flask(__name__)
@app.route("/u")
def u():
    name = flask.request.args.get("name")
    conn = psycopg2.connect("x")
    conn.cursor().execute("select * from t where n = '%s'" % name)
    return "ok"
'''
    sl, idx = _slice(app, "u", "sql")
    ok, reason = R.self_contained(sl, idx)
    assert not ok and "psycopg2" in reason


def test_reproduction_off(tmp_path):
    sl, idx = _slice(VULN, "ping", "exec")
    rep = R.reproduce(sl, idx, data_dir=tmp_path, run_id="r4", enabled=False, runner=_local_runner)
    assert rep.status == R_OFF


def test_non_reproducible_class_not_attempted(tmp_path):
    app = '''
import flask
app = flask.Flask(__name__)
@app.route("/q", methods=["POST"])
def q():
    name = flask.request.form.get("name")
    db.execute("select * from t where n = '%s'" % name)
    return "ok"
'''
    slices, _s, idx = SL.slice_root("/srv", {"app.py": app}, file_hashes={"app.py": "h"},
                                    all_sizes={"app.py": len(app)})
    sl = next(s for s in slices if s.cls == "sql")
    rep = R.reproduce(sl, idx, data_dir=tmp_path, run_id="r5", enabled=True, runner=_local_runner)
    assert rep.status == R_NOT_ATTEMPTED        # sql is not in REPRODUCIBLE


def test_scratch_swept(tmp_path):
    work = tmp_path / R.WORK_DIRNAME / "leftover"
    work.mkdir(parents=True)
    (work / "x.py").write_text("stale")
    R.sweep(tmp_path)
    assert not (tmp_path / R.WORK_DIRNAME).exists()


def test_fix_checked_in_sandbox(tmp_path):
    sl, idx = _slice(VULN, "ping", "exec")
    # A real fix: validate the value against an allow-list so it never reaches the call. The
    # canary isn't in the list, so the sandbox sees it no longer reach os.system -> "checked".
    fixed = (
        "def ping():\n"
        "    host = flask.request.args.get('host')\n"
        "    if host not in ('a', 'b'):\n"
        "        return 'rejected'\n"
        "    os.system('ping -c1 ' + host)\n"
        "    return 'ok'\n"
    )
    check = R.fix_recheck(sl, idx, fixed, data_dir=tmp_path, run_id="r6", enabled=True, runner=_local_runner)
    assert check == "checked"

    # A non-fix (still reaches the call) reads as not_confirmed.
    nonfix = (
        "def ping():\n"
        "    host = flask.request.args.get('host')\n"
        "    os.system('ping -c1 ' + str(host))\n"
        "    return 'ok'\n"
    )
    assert R.fix_recheck(sl, idx, nonfix, data_dir=tmp_path, run_id="r6b", enabled=True,
                         runner=_local_runner) == "not_confirmed"


def test_fix_not_checked_when_unparseable(tmp_path):
    sl, idx = _slice(VULN, "ping", "exec")
    assert R.fix_recheck(sl, idx, "def ping(:\n  broken", data_dir=tmp_path, run_id="r7",
                         enabled=True, runner=_local_runner) == "not_checked"
    assert R.fix_recheck(sl, idx, "x = 1", data_dir=tmp_path, run_id="r7b", enabled=False,
                         runner=_local_runner) == "not_checked"
