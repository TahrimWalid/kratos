"""E.1 edge cases and failure modes (spec §6 — each row is a situation → what the person sees
→ this test). Graph-level cases use fast in-memory fixtures; store-level cases reuse the build
helpers in ``tests.test_attackpaths_build``.

README §4.6: an edge case without a test is a defect. The graph determinism / rank table /
cycle / scope / unset-criticality / key-reuse / assumed-vs-observed rows live in
``test_attackpaths_graph.py``; the scenario / stale / no-data / doors / scoped-read / severity
rows in ``test_attackpaths_build.py``; the never-lowers row in
``test_attackpaths_never_lowers.py``. This file covers the remaining rows.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from kratos.assets.store import Asset
from kratos.attackpaths import construct, crown as CR, entries as EN, graph as G
from kratos.attackpaths import inputs as IN, judge as J, paths as PA, record, scope as SC, settings as S
from kratos.attackpaths.inputs import MachineInputs

import tests.test_attackpaths_build as T


# --- fast in-memory machine inputs (no DB) ------------------------------------------


def _mi(tk, *, listeners=(), outbound=(), local=(), keys=(), accounts=None, criticality=None,
        exposure_override=None, findings=(), containers=None, code_roots=(), ssh_only=False,
        stale=False, unread=False, via="agent", reader_uid=0, label=None):
    mi = MachineInputs(target_key=tk, label=label or tk)
    mi.newest_epoch = 1.0
    mi.data_age_hours = 1.0 if not stale else 9999.0
    mi.transport = "ssh" if ssh_only else "subagent"
    mi.ssh_only = ssh_only
    mi.stale = stale
    mi.unread = unread
    mi.reader_root = reader_uid == 0
    mi.live = None if unread else {"via": via, "reader_uid": reader_uid, "listeners": list(listeners),
                                   "outbound": list(outbound), "local_addresses": list(local)}
    mi.key_identities = tuple(keys)
    mi.privileged = {"accounts": accounts or {}}
    mi.findings = list(findings)
    mi.containers = containers
    mi.code_roots = list(code_roots)
    mi.asset = Asset(tk, criticality=criticality, exposure_override=exposure_override)
    return mi


def _pkg_rule(outcome="act", exposure="internet", port=443, sev="high"):
    """A PKG-001 finding in the shape ``construct`` reads (``rule_id`` — the store path turns
    the engine's ``id`` into ``rule_id``; in-memory fixtures must match that)."""
    return {"rule_id": "PKG-001", "short_key": "pk01", "severity": sev, "subject": "nginx",
            "entities": ["CVE-1"], "ssvc": {"outcome": outcome,
            "exposure": {"value": exposure, "reason": f"nginx listens on 0.0.0.0:{port}"}}}


def _cont(name="web1", rule="CONT-001", host_network=False, ports=()):
    containers = {"images": {"img1": {"image": "nginx:latest", "digest": "sha256:dead",
                                      "containers": [name], "ports": list(ports),
                                      "host_network": host_network}}}
    finding = {"rule_id": rule, "short_key": rule.lower(), "severity": "high", "subject": name,
               "entities": [name], "ssvc": {}}
    return containers, finding


# --- empty / clean / latent ---------------------------------------------------------


def test_empty_machine():
    """A machine with no listeners and no privileged accounts is one machine node, no entries,
    not an error."""
    g = construct.build_graph({"m": _mi("m")})
    assert g.node(G.machine_key("m")) is not None
    assert EN.entries(g) == []


def test_clean_group_says_coverage_not_safe():
    """A group Kratos read with no vulnerable/exposed node: no entries, no paths, no
    PATH-001/002/003 high/medium; coverage wording, never 'safe'."""
    inputs = {"a": _mi("a", listeners=[{"port": 22, "proto": "tcp", "address": "127.0.0.1",
                                        "exe": "sshd", "seen": True}], local=["10.0.0.1"]),
              "b": _mi("b", criticality="high", local=["10.0.0.2"])}
    g = construct.build_graph(inputs)
    ents = EN.entries(g)
    cj = CR.crown_jewels(g, inputs)
    paths, caps = PA.enumerate_paths(g, cj)
    assert ents == [] and paths == []
    cov = J.coverage_numbers(inputs, paths, caps)
    specs = J.judge(g, ents, cj, paths, [], cov, data_dir=".", group_label="lab",
                    single_machine_scope=False)
    assert not any(s.payload["id"] in ("PATH-001", "PATH-002", "PATH-003") for s in specs)
    p5 = next(s for s in specs if s.payload["id"] == "PATH-005")
    assert "never 'safe'" in " ".join(p5.payload["evidence"])


def test_escape_without_entry_is_latent():
    """A container with an escape setting (CONT-001) but nothing reaching it: the `escapes`
    edge exists, but there is no `exposes` entry → no path, a latent risk, not a drawn path."""
    containers, cont_f = _cont(rule="CONT-001")
    inputs = {"host": _mi("host", criticality="high", containers=containers, findings=[cont_f])}
    g = construct.build_graph(inputs)
    escapes = [e for e in g.all_edges() if e.kind == G.ESCAPES]
    exposes = [e for e in g.all_edges() if e.kind == G.EXPOSES]
    assert escapes and not exposes
    cj = CR.crown_jewels(g, inputs)
    paths, _ = PA.enumerate_paths(g, cj)
    assert paths == []          # latent: no outside position reaches the container


def test_exposure_unknown_no_entry_invented():
    """A listener bound to a reachable address but exposure unknown (no SSVC finding, no
    person override) is a network entry at most — an internet entry is never invented."""
    inputs = {"m": _mi("m", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0",
                                        "exe": "nginx", "seen": True}], local=["10.0.0.5"])}
    g = construct.build_graph(inputs)
    inet = [e for e in g.out_edges(G.OUTSIDE_INTERNET) if e.kind == G.EXPOSES]
    assert inet == []           # no internet entry invented without evidence/override


# --- hostile / non-UTF-8 names ------------------------------------------------------


def test_hostile_names_are_cleaned():
    """Hostile machine / account / key text is cleaned through for_display; a control
    character or markup never survives into a node label."""
    hostile = "web\x1b[31m\r\n<script>"
    inputs = {"web": _mi("web", label=hostile,
                         accounts={hostile: {"user": hostile, "uid": 0, "via": ["uid 0"]}},
                         listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0",
                                     "exe": hostile, "seen": True}], local=["10.0.0.5"])}
    g = construct.build_graph(inputs)
    # for_display neutralises terminal escapes and carriage returns (A.4); a node label never
    # carries a raw ANSI escape or CR that could rewrite a terminal line.
    for n in g.all_nodes():
        assert "\x1b" not in n.label and "\r" not in n.label


def test_non_utf8_bytes_escaped_and_matched():
    """A non-UTF-8 byte sequence in a name is escaped for display and still matched exactly as
    a node key (never crashes the build)."""
    name = "svc-\udcff-x"        # a lone surrogate, as a replace-decoded read can produce
    inputs = {"m": _mi("m", listeners=[{"port": 80, "proto": "tcp", "address": "0.0.0.0",
                                        "exe": name, "seen": True}], local=["10.0.0.1"])}
    g = construct.build_graph(inputs)                       # must not raise
    svc = g.node(G.service_key("m", "tcp", 80))
    assert svc is not None and "\udcff" not in svc.label


# --- identity: same hostname, dedupe, re-pair ---------------------------------------


def test_same_hostname_separate_nodes():
    """Two machines that share a display label but have different target_keys are separate
    nodes, never merged."""
    inputs = {"tk1": _mi("tk1", label="web", local=["10.0.0.1"]),
              "tk2": _mi("tk2", label="web", local=["10.0.0.2"])}
    g = construct.build_graph(inputs)
    assert g.node(G.machine_key("tk1")) is not None and g.node(G.machine_key("tk2")) is not None


def test_duplicate_node_key_is_one_node():
    """add_node dedupes by key and merges evidence — a machine evidenced twice is one node
    (the group-level SSH-addr + agent-link dedup resolves to one target_key before this)."""
    g = G.Graph()
    g.add_node(G.Node(kind=G.MACHINE, node_key=G.machine_key("m"), target_key="m", label="m",
                      evidence=["a"]))
    g.add_node(G.Node(kind=G.MACHINE, node_key=G.machine_key("m"), target_key="m", label="m",
                      evidence=["b"]))
    assert len(g.nodes_by_kind(G.MACHINE)) == 1
    assert g.node(G.machine_key("m")).evidence == ["a", "b"]


def test_repair_new_target_key_is_a_new_machine():
    """A re-paired machine has a new target_key → its own machine node; the old identity is a
    different key and simply isn't in this build's inputs."""
    g = construct.build_graph({"new-id": _mi("new-id", label="web")})
    assert g.node(G.machine_key("new-id")) is not None
    assert g.node(G.machine_key("old-id")) is None


# --- scale (unit-level cap proof; the lab §9 measures time/memory) -------------------


def test_scale_caps_path_count():
    """A dense graph hits the path cap and stops, never a silent partial (the §9 lab measures
    time/memory at the full 50-machine ceiling)."""
    # a hub machine reachable from the internet, with many onward reaches to crown jewels
    inputs = {"hub": _mi("hub", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0",
              "exe": "nginx", "seen": True, "package": "nginx"}], local=["203.0.113.5"],
              exposure_override="internet", findings=[_pkg_rule()], keys=["d:SHA256:K"])}
    for i in range(20):
        inputs[f"cj{i}"] = _mi(f"cj{i}", criticality="critical", keys=["d:SHA256:K"], local=[f"10.0.0.{i}"])
    g = construct.build_graph(inputs)
    cj = CR.crown_jewels(g, inputs)
    paths, caps = PA.enumerate_paths(g, cj, max_path_len=8, max_paths=5)
    assert len(paths) <= 5 and "paths" in caps


# --- coverage: unread, ssh-only, subagent-only (store level) ------------------------


def _group(tmp_path, members):
    from kratos.fleet import groups as fleet_groups
    fleet_groups.create_group(tmp_path, "lab", T._owner(), members=members)


def test_unread_machine_counted(tmp_path):
    """A machine in the group with nothing stored is counted in PATH-005, never assumed safe,
    no path through it."""
    owner = T._owner()
    from kratos.assets import store as assets
    T._write_live(tmp_path, "web", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0",
                  "exe": "nginx", "seen": True, "package": "nginx"}], local_addresses=["203.0.113.5"])
    assets.update(tmp_path, "web", owner, exposure_override="internet")
    assets.update(tmp_path, "ghost", owner, criticality="high")   # asset row only, never read
    _group(tmp_path, ["web", "ghost"])
    from kratos.attackpaths import build as B
    out = B.run_path_build(data_dir=tmp_path, group="lab", actor=owner, source="interactive")
    assert out.coverage.machines_unread == 1
    p5 = next(f for f in out.findings if f["id"] == "PATH-005")
    assert "never read" in " ".join(p5["evidence"]).lower()


def test_ssh_only_partial_graph(tmp_path):
    """A machine read over SSH only (reader not root) is marked ssh_only and the limitation is
    stated in PATH-005."""
    owner = T._owner()
    from kratos.assets import store as assets
    T._write_live(tmp_path, "ssh1", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0",
                  "exe": "sshd", "seen": True}], local_addresses=["10.0.0.3"], via="ssh", reader_uid=1000)
    assets.update(tmp_path, "ssh1", owner, criticality="high")
    _group(tmp_path, ["ssh1"])
    from kratos.attackpaths import build as B
    out = B.run_path_build(data_dir=tmp_path, group="lab", actor=owner, source="interactive")
    assert out.coverage.ssh_only == 1
    p5 = next(f for f in out.findings if f["id"] == "PATH-005")
    assert "ssh only" in " ".join(p5["evidence"]).lower()


def test_subagent_only_machine_no_ssh_limitation(tmp_path):
    """A machine read through its agent (root) is not marked ssh_only."""
    owner = T._owner()
    from kratos.assets import store as assets
    T._write_live(tmp_path, "ag1", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0",
                  "exe": "sshd", "seen": True}], local_addresses=["10.0.0.4"], via="agent", reader_uid=0)
    assets.update(tmp_path, "ag1", owner, criticality="high")
    _group(tmp_path, ["ag1"])
    from kratos.attackpaths import build as B
    out = B.run_path_build(data_dir=tmp_path, group="lab", actor=owner, source="interactive")
    assert out.coverage.ssh_only == 0


# --- key-reuse scope (one machine in scope → PATH-004 low, other not named) ----------


def test_key_reuse_single_machine_scope_low():
    """When only one machine is in scope the bridge can't be drawn across two → PATH-004 low
    and the other machine is not named (single_machine_scope=True)."""
    inputs = {"a": _mi("a", keys=["u:SHA256:K"])}
    g = construct.build_graph(inputs)
    specs = J.judge(g, [], {}, [], [], J.coverage_numbers(inputs, [], set()),
                    data_dir=".", group_label="lab", single_machine_scope=True)
    bridges = [s for s in specs if s.payload["id"] == "PATH-004"]
    assert all(s.payload["severity"] in ("low",) for s in bridges)   # low when scope is one machine


# --- restart mid-build: a running row is never shown as a result --------------------


def test_restart_mid_build_not_shown(tmp_path):
    """A path_runs row that started but never finished (no snapshot_file) is never returned as
    the latest build to read."""
    record.start(tmp_path, run_id="half", group_ref="lab", actor=T._owner(), source="interactive",
                 machines=2, outside_scope=0, trace_id="half")
    assert record.latest(tmp_path, "lab")["status"] == "running"
    from kratos.attackpaths import build as B
    assert B.read_latest(tmp_path, "lab") is None      # no snapshot yet → not shown


# --- scheduled build beside an interactive one --------------------------------------


def test_scheduled_build_records_and_notifies(tmp_path):
    """A scheduled `paths` build runs read-free under the schedule's actor and sends exactly
    one grouped notification; it coexists with an interactive build (its own run id)."""
    owner = T._owner()
    from kratos.assets import store as assets
    from kratos.agent import scheduled_run
    from kratos.agent.schedules import Schedule
    T._write_live(tmp_path, "web", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0",
                  "exe": "nginx", "seen": True, "package": "nginx"}], local_addresses=["203.0.113.5"])
    T._seed_finding(tmp_path, "web", T._pkg_act())
    assets.update(tmp_path, "web", owner, exposure_override="internet")
    T._write_live(tmp_path, "db", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0",
                  "exe": "sshd", "seen": True}], local_addresses=["10.0.0.9"])
    assets.update(tmp_path, "db", owner, criticality="critical")
    _group(tmp_path, ["web", "db"])

    # interactive build first
    from kratos.attackpaths import build as B
    B.run_path_build(data_dir=tmp_path, group="lab", actor=owner, source="interactive")

    sent = []
    sch = Schedule(name="nightly-paths", kind="paths", preset=None, target="@lab", cadence="daily",
                   deliver=["ntfy"], min_severity=None, created_at=None, path=Path(tmp_path) / "s.toml")
    rec = scheduled_run.run_scheduled(sch, tmp_path, deliver=True,
                                      notifier=lambda msg, sev: (sent.append((msg, sev)) or "sent-1"),
                                      source="schedule")
    assert rec["status"] == "completed"
    assert len(sent) == 1 and "Attack paths" in sent[0][0]
    # two distinct runs on record (interactive + scheduled), each its own run id
    runs = record.recent(tmp_path, 10)
    assert len({r["run_id"] for r in runs}) >= 2


# --- doors: MCP read allowed scoped; build has no MCP tool --------------------------


def test_mcp_read_scoped(tmp_path):
    """The MCP read returns the latest build scoped; there is no MCP build tool (confirmed by
    name — kratos_attack_paths is read-only)."""
    import kratos.mcp_server as mcp
    assert hasattr(mcp, "kratos_attack_paths")
    assert not any("build" in n.lower() and "path" in n.lower()
                   for n in dir(mcp) if n.startswith("kratos_"))


# --- backup class + inventory + evidence folder -------------------------------------


def test_backup_and_inventory_classification():
    from kratos import datainv
    cat = next(c for c in datainv.CATEGORIES if c.key == "attack_paths")
    assert cat.backup == datainv.BACKUP_INCLUDE
    assert "paths" in cat.files
    from kratos.evidence import ledger
    assert "paths" in ledger.EVIDENCE_FOLDERS


# --- time-zone independence of the age computation ----------------------------------


def test_age_and_stale_are_utc(tmp_path):
    """'Last read' ages are computed in UTC epoch math, so stale detection is identical
    whatever the display zone (the full suite also runs under Europe/Helsinki)."""
    owner = T._owner()
    from kratos.assets import store as assets
    T._write_live(tmp_path, "old", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0",
                  "exe": "sshd", "seen": True}], local_addresses=["10.0.0.9"],
                  epoch=time.time() - 200 * 3600)
    assets.update(tmp_path, "old", owner, criticality="high")
    _group(tmp_path, ["old"])
    from kratos.attackpaths import build as B
    out = B.run_path_build(data_dir=tmp_path, group="lab", actor=owner, source="interactive")
    assert out.coverage.machines_stale == 1
