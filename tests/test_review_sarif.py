"""E.7b SARIF 2.1.0 out (§3.14): valid against the official schema, rule ids / relative paths /
line regions / severity / verdict in properties, and NO code text or `snippet` anywhere."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kratos.review import sarif as S

_SCHEMA = Path(__file__).parent / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"

REVIEW_FINDINGS = [
    {"verdict": "confirmed", "strength": "reproduced", "rel": "app/views.py", "function": "ping", "cls": "exec",
     "line": 7, "exposure": "internet", "evidence": "the canary reached os.system() in the sandbox",
     "question": "", "drift": True, "slice_sha": "abc"},
    {"verdict": "needs_validation", "strength": "", "rel": "app/views.py", "function": "calc", "cls": "exec",
     "line": 12, "exposure": "network", "evidence": "", "question": "is the value checked first?", "drift": False},
    {"verdict": "rejected", "strength": "", "rel": "app/views.py", "function": "safe", "cls": "exec", "line": 18},
]


def _schema():
    return json.loads(_SCHEMA.read_text())


def test_sarif_valid_no_code():
    jsonschema = pytest.importorskip("jsonschema")
    doc = S.build_sarif(REVIEW_FINDINGS)
    jsonschema.validate(doc, _schema())
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    # the rejected finding is not a result.
    assert {r["ruleId"] for r in results} == {"REVIEW-001", "REVIEW-002"}
    first = next(r for r in results if r["ruleId"] == "REVIEW-001")
    assert first["level"] == "error"            # reproduced + exec + internet -> high -> error
    loc = first["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/views.py"
    assert loc["region"]["startLine"] == 7
    assert first["properties"]["verdict"] == "confirmed" and first["properties"]["strength"] == "reproduced"
    # no code text / snippet anywhere.
    blob = json.dumps(doc)
    assert "snippet" not in blob
    assert "def ping" not in blob and "request.args" not in blob


def test_sarif_needs_validation_is_warning_or_note():
    doc = S.build_sarif(REVIEW_FINDINGS)
    r2 = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "REVIEW-002")
    assert r2["level"] in ("warning", "note")
    assert r2["properties"]["openQuestion"] == "is the value checked first?"


def test_sarif_with_code_findings():
    jsonschema = pytest.importorskip("jsonschema")
    doc = S.build_sarif(REVIEW_FINDINGS,
                        code_findings=[{"id": "CODE-002", "title": "modified file app/views.py",
                                        "severity": "medium", "entities": ["app/views.py"]}])
    jsonschema.validate(doc, _schema())
    ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "CODE-002" in ids


def test_write_sarif_from_snapshots(tmp_path):
    from kratos.review import judge as J
    doc = {"target": "192.0.2.1", "machine": "192.0.2.1", "root": "/srv/app",
           "checked_at_epoch": 9e9, "findings": REVIEW_FINDINGS, "complete": True, "state": "done",
           "profile": "p", "destination": "local", "mask_mode": "off", "reproduction": True,
           "counts": {}, "reachability": []}
    J.write_snapshot(tmp_path, "192.0.2.1", doc)
    out = S.write_sarif(tmp_path, tmp_path / "out.sarif", machine="192.0.2.1")
    loaded = json.loads(out.read_text())
    assert {r["ruleId"] for r in loaded["runs"][0]["results"]} == {"REVIEW-001", "REVIEW-002"}
