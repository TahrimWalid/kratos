"""E.1 attack-path build, end to end over seeded stored evidence (no machine is read).

The README §5.1 scenario: a group with one internet-facing vulnerable service, a reused SSH
key, a docker-group user and a critical crown jewel -> the top path names entry -> hop ->
crown jewel with each edge's evidence; the chokepoint fix is listed first; the reused key is
a PATH-004 bridge; coverage is always numbers.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from kratos import authz
from kratos.attackpaths import build as B
from kratos.attackpaths import graph as G
from kratos.lifecycle import apply as lc_apply
from kratos.lifecycle.coverage import Coverage
from kratos.lifecycle import query as lc_query
from kratos.persist import baseline as persist_baseline
from kratos.run_context import RunContext


def _owner():
    return authz.owner_actor("cli")


def _run():
    return RunContext(run_id=uuid.uuid4().hex, source="interactive", target=None, session_id=None,
                      started_at=1_000_000.0)


def _write_live(data_dir: Path, target: str, *, listeners, outbound=(), local_addresses=(), via="agent",
                reader_uid=0, epoch=2_000_000_000.0):
    d = data_dir / "live"
    d.mkdir(parents=True, exist_ok=True)
    doc = {"target": target, "checked_at_epoch": epoch, "via": via, "reader_uid": reader_uid, "complete": True,
           "listeners": list(listeners), "outbound": list(outbound), "local_addresses": list(local_addresses),
           "maps_read": True}
    (d / f"live_response_{target}_{int(epoch)}.json").write_text(json.dumps(doc), encoding="utf-8")


def _seed_keys(data_dir: Path, target: str, keys):
    inv = {"items": {}, "keys": [{"user": u, "fingerprint": f} for u, f in keys], "modules": {},
           "reader_uid": 0, "via": "agent", "gaps": []}
    persist_baseline.save_first_look(data_dir, target, inv, areas=("ssh",), now=2_000_000_000.0)


def _seed_privileged(data_dir: Path, target: str, accounts, epoch="2033-05-18T03:33:20+00:00"):
    d = data_dir / "context"
    d.mkdir(parents=True, exist_ok=True)
    doc = {"target": target, "checked_at": epoch, "accounts": accounts,
           "local_accounts": {u: a.get("uid") for u, a in accounts.items()}}
    (d / f"privileged_accounts_{target}_x.json").write_text(json.dumps(doc), encoding="utf-8")


def _seed_finding(data_dir: Path, target: str, finding: dict):
    lc_apply.apply_run([finding], target=target, coverage=Coverage(inputs={}), run=_run(), data_dir=data_dir)


def _pkg_act(port=443):
    return {"id": "PKG-001", "title": "vulnerable nginx", "severity": "high", "evidence": ["x"],
            "subject": "nginx", "entities": ["CVE-2024-9999"], "recommendation": ["upgrade"],
            "ssvc": {"outcome": "act", "label": "Act", "exposure": {"value": "internet",
                     "reason": f"nginx, from nginx, listens on 0.0.0.0:{port}"}}}


@pytest.fixture()
def lab(tmp_path):
    data_dir = tmp_path
    owner = _owner()
    from kratos.assets import store as assets
    from kratos.fleet import groups as fleet_groups

    # web: internet entry (PKG-001 act), reused key
    _write_live(data_dir, "web", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0", "exe": "nginx",
                                             "seen": True, "package": "nginx"}], local_addresses=["203.0.113.5"])
    _seed_keys(data_dir, "web", [("deploy", "SHA256:AAAA")])
    _seed_finding(data_dir, "web", _pkg_act())
    assets.update(data_dir, "web", owner, exposure_override="internet")

    # db: critical crown jewel, same reused key
    _write_live(data_dir, "db", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0", "exe": "sshd",
                                           "seen": True, "package": "openssh-server"}], local_addresses=["10.0.0.9"])
    _seed_keys(data_dir, "db", [("deploy", "SHA256:AAAA")])
    assets.update(data_dir, "db", owner, criticality="critical")

    # app: docker-group user (reaches root), part of the group
    _write_live(data_dir, "app", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0", "exe": "sshd",
                                            "seen": True, "package": "openssh-server"}], local_addresses=["10.0.0.8"])
    _seed_privileged(data_dir, "app", {"ci": {"user": "ci", "uid": 1001, "via": ["member of 'docker' "
                                      "(root-equivalent group)"], "login_shell": True}})
    assets.update(data_dir, "app", owner, criticality="medium")

    fleet_groups.create_group(data_dir, "lab", owner, members=["web", "db", "app"])
    return data_dir, owner


def test_scenario_top_path_and_chokepoint(lab):
    data_dir, owner = lab
    out = B.run_path_build(data_dir=data_dir, group="lab", actor=owner, source="interactive")
    assert out.status == "done"
    assert out.coverage.machines_read == 3
    # a path reaches the critical crown jewel (db), fully observed
    db_paths = [p for p in out.paths if p.crown_jewel == "db"]
    assert db_paths, "a path should reach the critical crown jewel"
    top = db_paths[0]
    kinds = [e.kind for e in top.edges]
    assert kinds[0] == G.EXPOSES and G.KEY_REUSE in kinds
    assert top.fully_observed
    # every edge cites evidence
    assert all(e.evidence for e in top.edges)
    # chokepoint listed with a path count and a shown fix
    assert out.chokepoints and out.chokepoints[0].count >= 1 and out.chokepoints[0].fix_title


def test_findings_emitted_through_lifecycle(lab):
    data_dir, owner = lab
    B.run_path_build(data_dir=data_dir, group="lab", actor=owner, source="interactive")
    db = lc_query.list_findings(data_dir, target="db", state="open_verified")
    ids = {f["rule_id"] for f in db}
    assert "PATH-002" in ids                       # a path to the crown jewel
    # PATH-002 severity capped at high (critical crown jewel, fully observed)
    p2 = next(f for f in db if f["rule_id"] == "PATH-002")
    assert p2["severity"] == "high"
    # PATH-004 reused-key bridge somewhere in the group
    allf = []
    for mk in ("web", "db", "app"):
        allf += lc_query.list_findings(data_dir, target=mk, state="open_verified")
    assert any(f["rule_id"] == "PATH-004" for f in allf)
    assert any(f["rule_id"] == "PATH-001" for f in allf)


def test_build_reads_no_machine(lab, monkeypatch):
    """A build must only read stored data -- never SSH or the agent."""
    data_dir, owner = lab
    import kratos.adapters.ssh_remote as ssh

    def _boom(*a, **k):
        raise AssertionError("a path build must not read a machine")

    for name in ("run_remote_command", "run_remote_script", "fetch_live_response"):
        if hasattr(ssh, name):
            monkeypatch.setattr(ssh, name, _boom, raising=False)
    out = B.run_path_build(data_dir=data_dir, group="lab", actor=owner, source="interactive")
    assert out.status == "done"


def test_determinism_two_builds_identical_graph(lab):
    data_dir, owner = lab
    from kratos.attackpaths import construct, inputs as IN
    mi = IN.load_group(data_dir, ["web", "db", "app"])
    g1 = construct.build_graph(mi)
    g2 = construct.build_graph(mi)
    assert [e.edge_key for e in g1.all_edges()] == [e.edge_key for e in g2.all_edges()]
    assert sorted(g1.nodes) == sorted(g2.nodes)


def test_stale_machine_excluded_not_assumed_safe(tmp_path):
    import time as _t

    owner = _owner()
    from kratos.fleet import groups as fleet_groups
    from kratos.assets import store as assets
    # current machine
    _write_live(tmp_path, "cur", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0", "exe": "nginx",
                                            "seen": True, "package": "nginx"}], local_addresses=["203.0.113.5"])
    assets.update(tmp_path, "cur", owner, exposure_override="internet")
    # stale machine: only an old live snapshot (> 72 h)
    _write_live(tmp_path, "old", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0", "exe": "sshd",
                                           "seen": True}], local_addresses=["10.0.0.9"],
                epoch=_t.time() - 200 * 3600)
    assets.update(tmp_path, "old", owner, criticality="high")
    fleet_groups.create_group(tmp_path, "lab", owner, members=["cur", "old"])
    out = B.run_path_build(data_dir=tmp_path, group="lab", actor=owner, source="interactive")
    assert out.coverage.machines_stale == 1 and out.coverage.machines_read == 1
    # the crown jewel 'old' has no path drawn to it, and it is NOT assumed safe
    assert not any(p.crown_jewel == "old" for p in out.paths)
    # PATH-005 (a run note) carries the coverage in plain words -- "too old", never "safe"
    p5 = next(f for f in out.findings if f["id"] == "PATH-005")
    ev = " ".join(p5.get("evidence") or []).lower()
    assert "too old" in ev and "never 'safe'" in ev


def test_severity_cap_pinned_at_high(lab):
    data_dir, owner = lab
    B.run_path_build(data_dir=data_dir, group="lab", actor=owner, source="interactive")
    for f in _all_findings(data_dir):
        if f["rule_id"].startswith("PATH-"):
            assert f["severity"] in ("info", "low", "medium", "high")   # never critical


def test_build_refused_from_chat_mcp(lab):
    data_dir, owner = lab
    from kratos.lifecycle.decide import Actor
    # a chat/MCP caller is an interface build.py won't accept (fleet door, person-run)
    bad = Actor(user="token:abc", interface="mcp")
    try:
        B.run_path_build(data_dir=data_dir, group="lab", actor=bad, source="mcp")
        assert False, "a build from MCP should be refused"
    except B.PathBuildError:
        pass


def test_read_scoped_viewer_never_leaks(lab):
    data_dir, owner = lab
    B.run_path_build(data_dir=data_dir, group="lab", actor=owner, source="interactive")
    doc, visible = B.read_scoped(data_dir, owner, "lab")
    assert doc is not None and visible is None       # owner sees all
    # a scoped reader would be narrowed; here we assert the scoped_view contract directly
    from kratos.attackpaths import scope as SC
    only_web = SC.scoped_view(doc, {"web"})
    assert all(p.get("crown_jewel") == "web" for p in only_web["paths"])
    assert "db" not in str(only_web["entries"])


def test_no_model_call_in_a_build(lab, monkeypatch):
    data_dir, owner = lab
    import kratos.llm_interface as LI
    if hasattr(LI, "_metered_call"):
        monkeypatch.setattr(LI, "_metered_call",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("a build must not call a model")))
    out = B.run_path_build(data_dir=data_dir, group="lab", actor=owner, source="interactive")
    assert out.status == "done"


def _all_findings(data_dir):
    out = []
    for mk in ("web", "db", "app"):
        out += lc_query.list_findings(data_dir, target=mk, state="open_verified")
    return out


def test_no_data_group_says_coverage_not_safe(tmp_path):
    owner = _owner()
    from kratos.fleet import groups as fleet_groups
    from kratos.assets import store as assets
    assets.update(tmp_path, "empty1", owner, criticality="low")
    fleet_groups.create_group(tmp_path, "void", owner, members=["empty1"])
    out = B.run_path_build(data_dir=tmp_path, group="void", actor=owner, source="interactive")
    assert out.status == "no_data"
    assert "coverage" in out.summary.lower() and "clean bill of health" in out.summary.lower()
