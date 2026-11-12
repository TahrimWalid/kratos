"""E.2 in incident bundles (D.6): each machine's compliance reports go in as generated files,
hashed in SHA256SUMS like everything else; the redacted variant masks the machine."""
from __future__ import annotations

import json
import re
import time

import _export_fixture as FX
from kratos.compliance import record
from kratos.export import create as C
from kratos.export.scope import ExportRequest
from kratos.lifecycle.decide import Actor

from tests.test_compliance import good_hardening

ME = Actor(user="alice", interface="cli")


def _bundle(tmp_path, variant):
    d = tmp_path / "data"
    info = FX.build(d)
    h = good_hardening()
    h["stat"]["/etc/crontab"]["mode"] = 0o666
    record.run(d, FX.M1, fetch=lambda: dict(h, via="ssh"), now=time.time())
    now = info["now"]
    return C.create(d, ExportRequest(machines=[FX.M1], start=now - 86400, end=time.time() + 60, variant=variant), ME)


def test_export_includes_report(tmp_path):
    r = _bundle(tmp_path, "full")
    files = {p.relative_to(r.bundle).as_posix() for p in r.bundle.rglob("*") if p.is_file()}
    reports = sorted(f for f in files if "/compliance_" in f)
    assert len(reports) == 6 and any(f.endswith("compliance_cis.md") for f in reports)
    sums = (r.bundle / "SHA256SUMS").read_text()
    assert all(f in sums for f in reports)
    cis = json.loads((r.bundle / next(f for f in reports if f.endswith("compliance_cis.json"))).read_text())
    ctl = {c["control"]: c for c in cis["machines"][0]["controls"]}
    assert ctl["2.4.1.2"]["status"] == "fail"
    assert any("compliance/facts/" in f or "compliance/results/" in f for f in files)   # the facts as evidence


def test_redacted_bundle_masks_the_machine_in_reports(tmp_path):
    r = _bundle(tmp_path, "redacted")
    text = "\n".join(p.read_text(errors="replace") for p in r.bundle.rglob("compliance_*"))
    assert text and not re.search(rf"(?<![\w.-]){re.escape(FX.M1)}(?![\w-])", text)


def test_redacted_bundle_leaves_control_owner_names_out(tmp_path):
    from kratos.compliance import owners as O

    d = tmp_path / "data"
    info = FX.build(d)
    h = good_hardening()
    h["stat"]["/etc/crontab"]["mode"] = 0o666
    record.run(d, FX.M1, fetch=lambda: dict(h, via="ssh"), now=time.time())
    O.set_owner(d, Actor("owner", "cli"), "cis", "2.4.1.2", "all", "Mälli Örnek")
    full = C.create(d, ExportRequest(machines=[FX.M1], start=info["now"] - 86400, end=time.time() + 60,
                                     variant="full"), ME)
    assert "Mälli Örnek" in "\n".join(p.read_text() for p in full.bundle.rglob("compliance_cis.*"))
    red = C.create(d, ExportRequest(machines=[FX.M1], start=info["now"] - 86400, end=time.time() + 60,
                                    variant="redacted"), ME)
    text = "\n".join(p.read_text(errors="replace") for p in red.bundle.rglob("compliance_*"))
    assert "Mälli" not in text and "\\u00e4" not in text and "an owner is set" in text
