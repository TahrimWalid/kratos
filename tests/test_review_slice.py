"""E.7b slicer (kratos.review.slice): surfaces, sink disambiguation, cross-file reach,
stable hashes, measured reduction, oversize split, unparsable files.

Every fixture here is a SOURCE STRING parsed by ``ast`` only; nothing is imported or run.
Fails on old code: ``kratos.review`` does not exist before this feature.
"""
from __future__ import annotations

import hashlib

from kratos.review import slice as S


def _hashes(files):
    return {rel: hashlib.sha256(text.encode()).hexdigest() for rel, text in files.items()}


def _sizes(files):
    return {rel: len(text.encode()) for rel, text in files.items()}


def _slice(files, **kw):
    return S.slice_root("/srv/app", files, file_hashes=_hashes(files), all_sizes=_sizes(files), **kw)


FLASK = '''\
from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/ping", methods=["POST"])
def ping():
    host = request.form["host"]
    subprocess.run("ping " + host, shell=True)
    return "ok"


@app.route("/safe", methods=["GET"])
def safe():
    return "hello"
'''


def test_flask_command_injection_route_sliced_as_exec():
    slices, stats, _ = _slice({"app.py": FLASK})
    classes = {sl.cls for sl in slices}
    assert "exec" in classes
    exec_sl = next(sl for sl in slices if sl.cls == "exec")
    assert exec_sl.rel == "app.py"
    assert exec_sl.function == "ping"
    assert exec_sl.route == "/ping"
    assert exec_sl.surface_kind == "flask"
    assert exec_sl.methods == ("post",)
    # The dangerous call is recorded with its qualified name, never executed.
    assert any(c.qualified == "subprocess.run" for c in exec_sl.calls)
    assert stats.surfaces == 2  # ping + safe
    # The GET /safe route has no sink and no state change -> no slice of its own.
    assert not any(sl.function == "safe" for sl in slices)


def test_mutating_route_without_auth_is_noauth():
    slices, _, _ = _slice({"app.py": FLASK})
    noauth = [sl for sl in slices if sl.cls == "noauth"]
    assert len(noauth) == 1
    assert noauth[0].function == "ping"  # POST with no login check


GUARDED = '''\
from flask import Flask, request
from flask_login import login_required
import subprocess

app = Flask(__name__)


@app.route("/run", methods=["POST"])
@login_required
def run_cmd():
    host = request.form["host"]
    subprocess.run("ping " + host, shell=True)
    return "ok"
'''


def test_auth_decorator_suppresses_noauth_but_not_sink():
    slices, _, _ = _slice({"app.py": GUARDED})
    classes = {sl.cls for sl in slices}
    assert "exec" in classes        # the sink is still a slice (verifier/rule decides later)
    assert "noauth" not in classes  # login_required is recognised on the path


CROSS_FILE = {
    "views.py": '''\
from flask import Flask, request
from app.helpers import shell_out

app = Flask(__name__)


@app.get("/x")
def x():
    return shell_out(request.args["cmd"])
''',
    "app/__init__.py": "",
    "app/helpers.py": '''\
import os


def shell_out(cmd):
    return os.system(cmd)
''',
}


def test_reach_follows_calls_into_root_functions():
    slices, _, _ = _slice(CROSS_FILE, depth=4)
    exec_sl = next(sl for sl in slices if sl.cls == "exec")
    # The slice touches both the route file and the helper it calls.
    assert "views.py" in exec_sl.touched
    assert "app/helpers.py" in exec_sl.touched
    assert any(c.qualified == "os.system" for c in exec_sl.calls)


def test_depth_zero_does_not_cross_into_helper():
    slices, _, _ = _slice(CROSS_FILE, depth=0)
    assert not any(sl.cls == "exec" for sl in slices)


SQL_UPLOAD = '''\
from flask import Flask, request

app = Flask(__name__)


@app.route("/q", methods=["POST"])
def q(db):
    cur = db.cursor()
    cur.execute("select * from t where x = '%s'" % request.form["x"])
    return "ok"


@app.route("/u", methods=["POST"])
def u():
    f = request.files["f"]
    f.save("/tmp/" + f.filename)
    return "ok"


@app.route("/noop", methods=["POST"])
def noop(obj):
    obj.execute()       # no args -> not a SQL sink
    other.save()        # not request.files -> not an upload sink
    return "ok"
'''


def test_method_sink_disambiguation():
    slices, _, _ = _slice({"app.py": SQL_UPLOAD})
    by_fn = {}
    for sl in slices:
        by_fn.setdefault(sl.function, set()).add(sl.cls)
    assert "sql" in by_fn.get("q", set())
    assert "upload" in by_fn.get("u", set())
    # noop: execute() with no args and save() off a non-files receiver are not sinks.
    assert "sql" not in by_fn.get("noop", set())
    assert "upload" not in by_fn.get("noop", set())


def test_slice_sha_stable_across_unrelated_line_shifts():
    base = FLASK
    shifted = "# a comment added far above\n# another\n" + FLASK
    a = next(sl for sl in _slice({"app.py": base})[0] if sl.cls == "exec")
    b = next(sl for sl in _slice({"app.py": shifted})[0] if sl.cls == "exec")
    assert a.sha256 == b.sha256           # same function body -> same slice hash
    assert a.entity() == b.entity()       # entity is by function name, not line


def test_context_hash_changes_when_a_touched_file_changes():
    files = dict(CROSS_FILE)
    a = next(sl for sl in _slice(files)[0] if sl.cls == "exec")
    files2 = dict(files)
    files2["app/helpers.py"] = files2["app/helpers.py"] + "\n# changed helper\n"
    b = next(sl for sl in _slice(files2)[0] if sl.cls == "exec")
    assert a.context_sha256 != b.context_sha256


def test_reduction_measured():
    noise = "\n".join(f"X_{i} = {i}" for i in range(5000))
    files = {"app.py": FLASK, "big_data.py": noise}
    slices, stats, _ = _slice(files)
    assert stats.root_bytes > 0
    assert stats.sliced_bytes > 0
    assert stats.sliced_bytes < stats.root_bytes       # slices are a fraction of the root


def test_unparsable_file_recorded_not_fatal():
    files = {"app.py": FLASK, "broken.py": "def (:::\n"}
    slices, stats, _ = _slice(files)
    assert "broken.py" in stats.not_parsed
    assert any(sl.cls == "exec" for sl in slices)      # the good file still slices


def test_oversize_function_split_or_skipped():
    # A single function body far above the slice-byte cap is skipped and counted.
    big_body = "\n".join(f"    y_{i} = {i}" for i in range(2000))
    src = (
        "from flask import Flask, request\nimport subprocess\napp = Flask(__name__)\n\n"
        '@app.route("/big", methods=["POST"])\n'
        "def big():\n"
        f"{big_body}\n"
        '    subprocess.run(request.form["c"], shell=True)\n'
        "    return 'ok'\n"
    )
    slices, stats, _ = _slice({"app.py": src}, max_slice_bytes=512)
    exec_slices = [sl for sl in slices if sl.cls == "exec"]
    assert exec_slices == [] and stats.too_large >= 1
