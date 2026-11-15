"""E.7b dependency reachability for CODE-003 (§3.9): reached from a route > imported by served
code > not seen; it only annotates/orders, never lowers a CODE finding."""
from __future__ import annotations

from kratos.review import deps as D
from kratos.review import slice as SL


def _slice_importing(app_src: str):
    slices, _s, idx = SL.slice_root("/srv", {"app.py": app_src}, file_hashes={"app.py": "h"},
                                    all_sizes={"app.py": len(app_src)})
    return slices


def test_reached_from_a_route():
    app = '''
import yaml, flask
app = flask.Flask(__name__)
@app.route("/c", methods=["POST"])
def c():
    data = flask.request.data
    return str(yaml.load(data))
'''
    slices = _slice_importing(app)
    r = D.reachability([{"package": "PyYAML", "ecosystem": "PyPI",
                         "advisories": [{"osv_id": "GHSA-x", "cves": ["CVE-1"]}]}], slices)
    assert r[0].package == "PyYAML" and r[0].status == D.REACHED
    assert "reached from a network route" in r[0].note
    assert r[0].advisories == ("GHSA-x",)


def test_unseen_when_not_imported():
    app = '''
import flask
app = flask.Flask(__name__)
@app.route("/c")
def c():
    return "ok"
'''
    slices = _slice_importing(app)
    r = D.reachability([{"package": "requests", "ecosystem": "PyPI", "advisories": []}], slices)
    assert r[0].status == D.UNSEEN
    assert "not seen in served code" in r[0].note


def test_import_name_aliases():
    assert "yaml" in D._import_names("PyYAML")
    assert "bs4" in D._import_names("beautifulsoup4")
    assert "dateutil" in D._import_names("python-dateutil")


def test_order_reached_first():
    app = '''
import yaml, os, flask
app = flask.Flask(__name__)
@app.route("/c", methods=["POST"])
def c():
    return str(yaml.load(flask.request.data))
'''
    slices = _slice_importing(app)
    out = D.reachability([
        {"package": "requests", "ecosystem": "PyPI", "advisories": []},
        {"package": "PyYAML", "ecosystem": "PyPI", "advisories": []},
    ], slices)
    assert out[0].package == "PyYAML" and out[0].status == D.REACHED
    assert out[1].package == "requests" and out[1].status == D.UNSEEN
