"""E.1 graph / rank / crown / paths / chokepoint / scope unit tests (fixtures only, no DB).

Covers the §8 areas: the graph is built from fixture snapshots with stable keys and holds its
caps; the rank table row by row; bounded cycle-safe DFS; observed above assumed; scope never
leaks an out-of-scope node; severity is never lowered by a path annotation.
"""
from __future__ import annotations

from kratos.attackpaths import chokepoint as CH
from kratos.attackpaths import construct
from kratos.attackpaths import crown as CR
from kratos.attackpaths import entries as EN
from kratos.attackpaths import graph as G
from kratos.attackpaths import paths as PA
from kratos.attackpaths import rank as R
from kratos.attackpaths import scope as SC
from kratos.attackpaths.inputs import MachineInputs


def _mi(tk, *, listeners=(), outbound=(), local=(), keys=(), accounts=None, criticality=None,
        exposure_override=None, findings=(), containers=None, code_roots=(), ssh_only=False):
    mi = MachineInputs(target_key=tk, label=tk)
    mi.newest_epoch = 1.0
    mi.data_age_hours = 1.0
    mi.transport = "subagent"
    mi.ssh_only = ssh_only
    mi.live = {"via": "agent", "reader_uid": 0, "listeners": list(listeners), "outbound": list(outbound),
               "local_addresses": list(local)}
    mi.key_identities = tuple(keys)
    mi.privileged = {"accounts": accounts or {}}
    mi.findings = list(findings)
    mi.containers = containers
    mi.code_roots = list(code_roots)
    from kratos.assets.store import Asset
    mi.asset = Asset(tk, criticality=criticality, exposure_override=exposure_override)
    return mi


def _pkg(outcome="act", exposure="internet", port=443, sev="high"):
    return {"rule_id": "PKG-001", "short_key": "pk01", "severity": sev, "subject": "nginx", "entities": ["CVE-1"],
            "ssvc": {"outcome": outcome, "exposure": {"value": exposure, "reason": f"nginx listens on 0.0.0.0:{port}"}}}


# --- rank table (decision 3) --------------------------------------------------------


def test_rank_table_row_by_row():
    def edge(rule="", outcome="", tier="network", no_weakness=False):
        return G.Edge(kind=G.EXPOSES, src=G.OUTSIDE_INTERNET, dst="x", confidence=G.OBSERVED,
                      attrs={"entry_rule": rule, "ssvc_outcome": outcome, "exposure_tier": tier,
                             "no_known_weakness": no_weakness})
    assert R.entry_strength(edge("PKG-001", "act", "internet")).rank_index == R.ACTIVE_EXPLOIT
    assert R.entry_strength(edge("PKG-001", "act", "internet")).severity == "high"
    assert R.entry_strength(edge("PKG-001", "attend", "internet")).rank_index == R.ATTEND
    assert R.entry_strength(edge("PKG-001", "attend", "internet")).severity == "high"
    assert R.entry_strength(edge("CONT-004", "", "network")).rank_index == R.CONTAINER_BYPASS
    assert R.entry_strength(edge("CODE-005", "", "internet")).rank_index == R.WEB_SHELL
    assert R.entry_strength(edge("CODE-001", "", "internet")).rank_index == R.WEB_SHELL
    assert R.entry_strength(edge("", "", "internet", no_weakness=True)).rank_index == R.NO_WEAKNESS
    assert R.entry_strength(edge("", "", "internet", no_weakness=True)).severity == "low"


# --- graph determinism, stable keys -------------------------------------------------


def test_graph_deterministic_and_stable_keys():
    inputs = {"web": _mi("web", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0", "exe": "nginx",
                                            "seen": True, "package": "nginx"}], local=["203.0.113.5"],
                         findings=[_pkg()], exposure_override="internet", keys=["deploy:SHA256:A"]),
              "db": _mi("db", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0", "exe": "sshd",
                                         "seen": True}], local=["10.0.0.9"], criticality="critical",
                        keys=["deploy:SHA256:A"])}
    g1 = construct.build_graph(inputs)
    g2 = construct.build_graph(inputs)
    assert [e.edge_key for e in g1.all_edges()] == [e.edge_key for e in g2.all_edges()]
    assert G.machine_key("web") in g1.nodes and G.service_key("web", "tcp", 443) in g1.nodes


# --- caps (decision 2) --------------------------------------------------------------


def test_caps_hold():
    inputs = {f"m{i}": _mi(f"m{i}", listeners=[{"port": 80 + i, "proto": "tcp", "address": "0.0.0.0",
                                               "exe": "x", "seen": True}]) for i in range(10)}
    g = construct.build_graph(inputs, caps=G.Caps(max_nodes=5, max_machines=50))
    assert "nodes" in g.caps_hit and len(g.nodes) <= 5


def test_max_machines_cap():
    inputs = {f"m{i}": _mi(f"m{i}") for i in range(10)}
    g = construct.build_graph(inputs, caps=G.Caps(max_machines=3))
    assert "machines" in g.caps_hit


# --- cycle-safe enumeration ---------------------------------------------------------


def test_graph_cycle_is_safe():
    # A <-> B reused key (a cycle), both crown jewels -> paths still enumerate, no hang
    inputs = {"a": _mi("a", criticality="high", keys=["u:SHA256:K"]),
              "b": _mi("b", criticality="high", keys=["u:SHA256:K"])}
    g = construct.build_graph(inputs)
    cj = CR.crown_jewels(g, inputs)
    paths, caps = PA.enumerate_paths(g, cj, max_path_len=8, max_paths=100)
    # no entry, so no path from outside -> but the key-reuse cycle must not loop forever
    assert isinstance(paths, list)


def test_assumed_ranked_below_observed_and_flagged():
    # one path fully observed, one with an assumed same-network hop
    inputs = {
        "web": _mi("web", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0", "exe": "nginx",
                                     "seen": True, "package": "nginx"}], local=["203.0.113.5"],
                   findings=[_pkg()], exposure_override="internet", keys=["d:SHA256:A"]),
        "cj": _mi("cj", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0", "exe": "nginx",
                                   "seen": True, "package": "nginx"}], local=["10.0.0.9"],
                  findings=[_pkg()], criticality="critical", keys=["d:SHA256:A"]),
    }
    g = construct.build_graph(inputs, assume_same_network=True)
    cj = CR.crown_jewels(g, inputs)
    paths, _ = PA.enumerate_paths(g, cj)
    # the top path to cj should be fully observed (via key-reuse), above any assumed one
    cj_paths = [p for p in paths if p.crown_jewel == "cj"]
    assert cj_paths and cj_paths[0].fully_observed
    assert all(p.assumed_hops == 0 for p in paths[:1])


# --- scope (decision 9) -------------------------------------------------------------


def test_scope_never_leaks_out_of_scope_node():
    inputs = {
        "web": _mi("web", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0", "exe": "nginx",
                                     "seen": True, "package": "nginx"}], local=["203.0.113.5"],
                   findings=[_pkg()], exposure_override="internet", keys=["d:SHA256:A"]),
        "secret": _mi("secret", criticality="critical", keys=["d:SHA256:A"]),
    }
    g = construct.build_graph(inputs)
    cj = CR.crown_jewels(g, inputs)
    paths, _ = PA.enumerate_paths(g, cj)
    ents = EN.entries(g)
    chokes = CH.chokepoints(g, paths)
    doc = {
        "nodes": [n.to_dict() for n in g.all_nodes()],
        "edges": [e.to_dict() for e in g.all_edges()],
        "entries": [{"target_key": e.target_key, "node_key": e.target_node_key, "label": e.target_label,
                     "tier": e.tier, "severity": e.severity, "grants_foothold": e.grants_foothold, "reason": ""}
                    for e in ents],
        "paths": [{"crown_jewel": p.crown_jewel, "criticality": p.crown_criticality, "length": p.length,
                   "assumed_hops": p.assumed_hops, "fully_observed": p.fully_observed,
                   "hops": [{"kind": e.kind, "src": e.src, "dst": e.dst, "confidence": e.confidence,
                             "reason": e.reason} for e in p.edges]} for p in paths],
        "chokepoints": [c.__dict__ for c in chokes],
    }
    scoped = SC.scoped_view(doc, {"web"})       # viewer sees only web, not 'secret'
    blob = str(scoped)
    assert "secret" not in blob                  # the out-of-scope machine is never named
    # a path whose crown jewel is out of scope is dropped
    assert all(p["crown_jewel"] == "web" for p in scoped["paths"])


# --- unset criticality assumed medium (decision 4) ----------------------------------


def test_unset_criticality_assumed_medium():
    inputs = {"m": _mi("m")}
    g = construct.build_graph(inputs)
    node = g.node(G.machine_key("m"))
    assert node.attrs["criticality"] == "medium" and node.attrs["criticality_assumed"] is True


# --- exposed, no known weakness, is still an entry (decision 3) ----------------------


def test_exposed_no_weakness_still_entry():
    inputs = {"m": _mi("m", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0", "exe": "nginx",
                                       "seen": True, "package": "nginx"}], local=["203.0.113.5"],
                       exposure_override="internet")}
    g = construct.build_graph(inputs)
    ents = EN.entries(g)
    assert ents and ents[-1].strength.rank_index == R.NO_WEAKNESS and ents[-1].severity == "low"


# --- key-reuse is undirected (gate decision) ----------------------------------------


def test_key_reuse_undirected():
    inputs = {"a": _mi("a", keys=["u:SHA256:K"]), "b": _mi("b", keys=["u:SHA256:K"])}
    g = construct.build_graph(inputs)
    reuse = [e for e in g.all_edges() if e.kind == G.KEY_REUSE]
    # drawn both ways (undirected), with the shared fingerprint as evidence
    assert {(e.src, e.dst) for e in reuse} == {(G.machine_key("a"), G.machine_key("b")),
                                               (G.machine_key("b"), G.machine_key("a"))}
    assert all(e.attrs.get("directed") is False for e in reuse)


# --- reputation never lowers a placement finding (decision 8 / README §6) ------------


def test_reputation_annotation_is_not_on_the_graph():
    # a known-good hash on a node that carries PERSIST-003 must not lower the path weight:
    # E.1 reads findings, it never rewrites their severity. The construct carries the finding's
    # own severity; a reputation tag never changes it.
    persist = {"rule_id": "PERSIST-003", "short_key": "ps03", "severity": "high", "subject": "/tmp/bash",
               "entities": ["/tmp/bash"], "reputation": [{"verdict": "known_good", "path": "/tmp/bash"}]}
    inputs = {"m": _mi("m", findings=[persist], accounts={"ci": {"user": "ci", "uid": 1001,
              "via": ["member of 'docker' (root-equivalent group)"]}})}
    g = construct.build_graph(inputs)
    # the SUID backdoor is recorded as a standing escalation on the machine; its finding stays high
    assert persist["severity"] == "high"
    assert g.node(G.machine_key("m")).attrs.get("suid_backdoor") is True
