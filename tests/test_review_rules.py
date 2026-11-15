"""E.7b direct rules (kratos.review.rules §3.6): a request value reaching a dangerous call in
one function through string building only, with no check Kratos recognises. Conservative for
precision -- any unrecognised call breaks the chain. Fails on old code."""
from __future__ import annotations

from kratos.review import rules as RU
from kratos.review import slice as S


def _prep(files, **kw):
    slices, _stats, idx = S.slice_root("/srv/app", files, file_hashes={}, all_sizes={}, **kw)
    return slices, idx


def _pick(slices, function, cls):
    return next(sl for sl in slices if sl.function == function and sl.cls == cls)


def _flask(body, decorator='@app.route("/x", methods=["POST"])', fn="h"):
    return (
        "from flask import Flask, request\n"
        "import subprocess, os, shlex\n"
        "app = Flask(__name__)\n\n"
        f"{decorator}\n"
        f"def {fn}():\n"
        + "".join(f"    {line}\n" for line in body)
    )


def _direct(files, function, cls, **kw):
    slices, idx = _prep(files, **kw)
    return RU.direct(idx, _pick(slices, function, cls))


def test_shell_concat_is_direct():
    src = _flask(['subprocess.run("ping " + request.form["host"], shell=True)', "return 'ok'"])
    m = _direct({"a.py": src}, "h", "exec")
    assert m.matched
    assert "subprocess.run()" in m.evidence and "line" in m.evidence


def test_taint_through_assignment_and_fstring():
    src = _flask(['host = request.form["host"]', 'subprocess.run(f"ping {host}", shell=True)', "return 'ok'"])
    assert _direct({"a.py": src}, "h", "exec").matched


def test_shlex_quote_breaks_the_chain():
    src = _flask(['host = shlex.quote(request.form["host"])',
                  'subprocess.run("ping " + host, shell=True)', "return 'ok'"])
    assert not _direct({"a.py": src}, "h", "exec").matched


def test_int_cast_breaks_the_chain():
    src = _flask(['n = int(request.args["n"])', 'os.system("sleep " + str(n))', "return 'ok'"])
    assert not _direct({"a.py": src}, "h", "exec").matched


def test_list_form_subprocess_without_shell_is_not_direct():
    src = _flask(['subprocess.run(["ping", request.form["host"]])', "return 'ok'"])
    # The slice still exists (subprocess.run is a sink), but there is no shell context.
    assert not _direct({"a.py": src}, "h", "exec").matched


def test_eval_of_request_is_direct():
    src = _flask(['return eval(request.args["x"])'])
    assert _direct({"a.py": src}, "h", "exec").matched


SQL_FORMAT = '''\
from flask import Flask, request

app = Flask(__name__)


@app.route("/x", methods=["POST"])
def h(db):
    cur = db.cursor()
    cur.execute("select * from t where x = " + request.args["x"])
    return "ok"
'''

SQL_PARAM = '''\
from flask import Flask, request

app = Flask(__name__)


@app.route("/x", methods=["POST"])
def h(db):
    cur = db.cursor()
    cur.execute("select * from t where x = ?", (request.args["x"],))
    return "ok"
'''


def test_sql_string_format_is_direct_but_parameters_are_not():
    assert _direct({"a.py": SQL_FORMAT}, "h", "sql").matched
    assert not _direct({"a.py": SQL_PARAM}, "h", "sql").matched


def test_path_direct_but_basename_breaks_it():
    raw = _flask(['return open(request.args["f"]).read()'])
    assert _direct({"a.py": raw}, "h", "path").matched
    safe = _flask(['import os.path', 'return open(os.path.basename(request.args["f"])).read()'])
    assert not _direct({"a.py": safe}, "h", "path").matched


def test_template_from_request_is_direct():
    src = (
        "from flask import Flask, request, render_template_string\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/x", methods=["POST"])\n'
        "def h():\n"
        '    return render_template_string("<p>" + request.args["name"] + "</p>")\n'
    )
    assert _direct({"a.py": src}, "h", "template").matched


def test_upload_saved_under_client_name_is_direct():
    src = (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/u", methods=["POST"])\n'
        "def u():\n"
        '    f = request.files["f"]\n'
        '    f.save("/up/" + f.filename)\n'
        "    return 'ok'\n"
    )
    assert _direct({"a.py": src}, "u", "upload").matched


def test_cross_function_flow_is_not_direct():
    files = {
        "views.py": (
            "from flask import Flask, request\n"
            "from app.helpers import shell_out\n"
            "app = Flask(__name__)\n\n"
            '@app.get("/x")\n'
            "def x():\n"
            '    return shell_out(request.args["cmd"])\n'
        ),
        "app/__init__.py": "",
        "app/helpers.py": "import os\n\n\ndef shell_out(cmd):\n    return os.system(cmd)\n",
    }
    # The sink is in the helper, not the surface function: no direct (intraprocedural) match.
    assert not _direct(files, "x", "exec").matched


def test_wsgi_environ_param_is_a_request_root():
    src = (
        "import os\n\n\n"
        "def application(environ, start_response):\n"
        '    os.system(environ["QUERY_STRING"])\n'
        '    start_response("200 OK", [])\n'
        "    return [b'']\n"
    )
    assert _direct({"a.py": src}, "application", "exec").matched


def test_noauth_route_matches_structurally():
    src = _flask(["return 'changed'"])   # POST route, no auth, no sink -> a noauth slice
    m = _direct({"a.py": src}, "h", "noauth")
    assert m.matched and "no login check" in m.evidence
