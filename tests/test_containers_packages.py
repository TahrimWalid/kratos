"""Packages inside running containers (D.5 §3.5): matched like the machine's, named after
the image, exposed through the container's published ports, kept apart from the
machine's own package findings in the lifecycle."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kratos.containers import packages as CP
from kratos.containers import record as R
from kratos.pkgvuln import inventory_store

from test_containers_judge import PUBLISHED, ctr, inv
from test_pkgvuln import DEB12_PACKAGES, build

IMG = "sha256:" + "c" * 64
IMG2 = "sha256:" + "7" * 64
T = "192.0.2.10"


@pytest.fixture()
def data(tmp_path):
    assert build(tmp_path).ok
    return tmp_path


def _image_inv():
    return {"header": True, "complete": True, "os": {"ID": "debian", "VERSION_ID": "12", "PRETTY_NAME": "Debian 12"},
            "packages": list(DEB12_PACKAGES), "managers": {"dpkg": "ok"}, "dropped": 0,
            "origins": {}, "origin_lists": {"lists": 0, "known": 0}}


def _reader(images):
    return lambda: {"complete": True, "header": True, "via": "subagent", "truncated": {}, "gaps": [], "images": images}


def _containers(data_dir, target=T, names=("web",), ports=PUBLISHED):
    cs = [ctr(n, image="shop/web:2", image_id=IMG, ports=ports if i == 0 else []) for i, n in enumerate(names)]
    cs.append(ctr("pause", image="registry.example/pause:3.9", image_id=IMG2))
    R.run(data_dir, target, reader=lambda: inv(*cs), connect=lambda a, p: True)


def test_image_packages_are_matched_and_named_after_the_image(data):
    _containers(data, names=("web", "web-2"))
    doc = CP.run(data, T, reader=_reader({IMG: {"pid": 1, "status": "ok", "inventory": _image_inv()},
                                          IMG2: {"pid": 2, "status": "no_db", "inventory": None}}))
    by = {(s["rule"], s["subject"]): s for s in doc["signals"]}
    ssh = by[("PKG-001", "shop/web:2:openssh")]
    assert "CVE-2024-6387" in ssh["entities"] and {"container:web", "container:web-2"} <= set(ssh["entities"])
    assert "shop/web" not in ssh["title"] and ssh["title"].startswith("In a container image:")
    assert ssh["evidence"][0].startswith("Inside container image shop/web:2")
    assert not any("apt-get" in r for r in ssh["recommendation"])
    assert any("docker compose pull" in r for r in ssh["recommendation"])
    assert ("PKG-002", "shop/web:2") in by
    rows = {r["image"]: r for r in doc["images"]}
    assert rows["registry.example/pause:3.9"]["note"].startswith("no package database (distroless or static image)")
    assert rows["shop/web:2"]["vulnerable"] >= 1
    assert inventory_store.latest(data, T, scope=inventory_store.image_scope(IMG)) is not None
    assert inventory_store.latest(data, T) is None                         # the machine's own list is untouched
    assert inventory_store.machines(data) == []


def test_over_ssh_it_is_a_stated_gap_and_no_engine_is_nothing(tmp_path):
    _containers(tmp_path)
    doc = CP.run(tmp_path, T, reader=lambda: {"unsupported": "not readable over SSH", "via": "ssh"})
    assert [s["rule"] for s in doc["signals"]] == ["CONT-008"] and "sub-agent" in doc["coverage_gaps"][0]
    R.run(tmp_path, "192.0.2.20", reader=lambda: {"via": "ssh", "complete": True, "engines": [], "containers": {},
                                                    "procs": {}, "firewall": {}})
    doc = CP.run(tmp_path, "192.0.2.20", reader=lambda: {"unsupported": "x", "via": "ssh"})
    assert doc["signals"] == [] and CP.summary_line(doc) == "no container engine found"


def test_an_old_rpm_database_and_an_unreadable_image_are_gaps(data):
    _containers(data)
    doc = CP.run(data, T, reader=_reader({IMG: {"pid": 1, "status": "old_rpmdb", "inventory": None},
                                          IMG2: {"pid": 2, "status": "gone", "inventory": None}}))
    gaps = " ".join(doc["coverage_gaps"])
    assert "old rpm database format" in gaps and "could not be read (gone)" in gaps
    assert doc["complete"] is False


def _correlate(data_dir, target=T):
    from kratos import kratos_config, run_context
    from kratos.adapters import findings_engine as FE

    kratos_config.set_active_target(target)
    with run_context.run_scope("cli"):
        out_json, _md = FE.write_findings_report(data_dir)
    return json.loads(Path(out_json).read_text())


def _records(data_dir):
    from kratos.lifecycle import store

    with store.opened(data_dir) as conn:
        return {(r["rule_id"], r["target"], r["subject"]): dict(r) for r in conn.execute("SELECT * FROM finding_records")}


def test_identity_lifecycle_and_exposure(data):
    from test_pkgvuln import _deb_inv
    from kratos.pkgvuln import record as PR

    reader = _reader({IMG: {"pid": 1, "status": "ok", "inventory": _image_inv()}})
    _containers(data)
    CP.run(data, T, reader=reader)
    rep = _correlate(data)
    f = next(x for x in rep["findings"] if x["id"] == "PKG-001" and x["subject"] == "shop/web:2:openssh")
    ex = f["ssvc"]["exposure"]
    assert ex["value"] in ("network", "internet") and "container web publishes" in ex["reason"]
    assert "pull or rebuild" in f["ssvc"]["fix"]
    # the same image on a second machine is a second finding
    _containers(data, target="192.0.2.11")
    CP.run(data, "192.0.2.11", reader=reader)
    _correlate(data, "192.0.2.11")
    recs = _records(data)
    assert ("PKG-001", T, "shop/web:2:openssh") in recs and ("PKG-001", "192.0.2.11", "shop/web:2:openssh") in recs
    # a new container from the same image adds an entity, not a finding
    _containers(data, names=("web", "web-new"))
    CP.run(data, T, reader=reader)
    _correlate(data)
    recs = _records(data)
    assert "container:web-new" in json.loads(recs[("PKG-001", T, "shop/web:2:openssh")]["entities"])
    assert sum(1 for k in recs if k[1] == T and k[2] == "shop/web:2:openssh") == 1
    # a fresh, complete package check of the MACHINE does not close the image's finding
    PR.run(data, T, reader=lambda: _deb_inv(packages=[]))
    _correlate(data)
    assert _records(data)[("PKG-001", T, "shop/web:2:openssh")]["state"] == "open"
    # ... a fresh container package read that no longer sees it does
    patched = _image_inv()
    patched["packages"] = [p for p in patched["packages"] if p["name"] != "openssh-server" and p["source"] != "openssh"]
    CP.run(data, T, reader=_reader({IMG: {"pid": 1, "status": "ok", "inventory": patched}}))
    _correlate(data)
    assert _records(data)[("PKG-001", T, "shop/web:2:openssh")]["state"] == "mitigated"


def test_an_image_whose_containers_publish_nothing_is_local(data):
    _containers(data, ports=[])
    CP.run(data, T, reader=_reader({IMG: {"pid": 1, "status": "ok", "inventory": _image_inv()}}))
    f = next(x for x in _correlate(data)["findings"] if x["id"] == "PKG-001" and x["subject"].startswith("shop/web:2:"))
    assert f["ssvc"]["exposure"]["value"] == "local" and "publishes no port" in f["ssvc"]["exposure"]["reason"]


@pytest.mark.parametrize("name,ref", [("nginx", "nginx:latest"), ("nginx:1.27", "nginx:1.27"),
                                      ("registry:5000/app", "registry:5000/app:latest"),
                                      ("app@sha256:" + "a" * 64, "app@sha256:" + "a" * 64),
                                      ("", "image@sha256:cccccccccccc")])
def test_image_refs_always_carry_a_tag_or_digest(name, ref):
    assert CP.image_ref(name, IMG) == ref and CP.is_image_subject(ref)


def test_host_package_names_are_never_image_subjects():
    assert not any(CP.is_image_subject(p["name"]) for p in DEB12_PACKAGES)
