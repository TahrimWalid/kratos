"""The typed, directed, bounded, deterministic attack-path graph (E.1 decision 2).

A graph is built entirely from evidence Kratos already stored (no machine is read). Every
node carries a ``target_key`` (empty only for the two synthetic ``outside`` start nodes),
a stable ``node_key`` and the finding ids / snapshot fields that evidence it. Every edge
is directed, carries the evidence that justifies it and a ``confidence`` -- ``observed``
(a fact Kratos saw) or ``assumed`` (a structural guess, always labelled) -- never a guess
dressed as a fact.

Nodes and edges are stored in insertion order and the graph is deterministic: the same
stored data builds a byte-identical graph (ids are stable, iteration is sorted where a
choice would otherwise depend on dict order). Caps (``paths.*``) bound every dimension; a
cap hit stops that dimension and is reported in PATH-005 (never a silent partial).

Edge model (decision 2, with one documented addition -- ``foothold``):

- ``exposes``       outside:{tier} -> service | container | code_root (an entry)
- ``foothold``      service | code_root | container -> machine (ADDED, E.1 Handoff): the
                    entry grants code execution / access on its machine (a web shell, an
                    SSVC-Act remote-code CVE on the serving package, a reachable container)
- ``serves``        service -> code_root
- ``authenticates`` key -> account (display/evidence; the traversable lateral edge is
                    ``key_reuse`` between machines)
- ``escalates``     account | service -> machine (reaching root on that machine)
- ``escapes``       container -> machine (reaching root via a container escape)
- ``reaches``       machine -> service on another machine (observed outbound, or assumed
                    same-network)
- ``key_reuse``     machine <-> machine (a public key authorises an account on both; one
                    stolen private half reaches both -- undirected, drawn both ways)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# --- node and edge kinds ------------------------------------------------------------

MACHINE = "machine"
SERVICE = "service"
ACCOUNT = "account"
KEY = "key"
CONTAINER = "container"
CODE_ROOT = "code_root"
OUTSIDE = "outside"
NODE_KINDS = (OUTSIDE, MACHINE, SERVICE, ACCOUNT, KEY, CONTAINER, CODE_ROOT)

EXPOSES = "exposes"
FOOTHOLD = "foothold"
SERVES = "serves"
AUTHENTICATES = "authenticates"
ESCALATES = "escalates"
ESCAPES = "escapes"
REACHES = "reaches"
KEY_REUSE = "key_reuse"
EDGE_KINDS = (EXPOSES, FOOTHOLD, SERVES, AUTHENTICATES, ESCALATES, ESCAPES, REACHES, KEY_REUSE)

# Edges along which the attacker advances during enumeration (decision 5). ``serves`` and
# ``authenticates`` are display/evidence edges and are not traversed on their own.
TRAVERSABLE = frozenset({EXPOSES, FOOTHOLD, ESCALATES, ESCAPES, REACHES, KEY_REUSE})

OBSERVED = "observed"
ASSUMED = "assumed"
CONFIDENCES = (OBSERVED, ASSUMED)

# The two synthetic start positions (decision 3): an attacker on the internet, or one
# already inside the group's network.
INTERNET = "internet"
NETWORK = "network"
OUTSIDE_INTERNET = f"{OUTSIDE}:{INTERNET}"
OUTSIDE_NETWORK = f"{OUTSIDE}:{NETWORK}"


@dataclass
class Node:
    kind: str
    node_key: str
    target_key: str                       # "" only for the two outside start nodes
    label: str                            # cleaned, for display (never a raw machine string)
    attrs: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)   # finding short-keys / snapshot references

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "node_key": self.node_key, "target_key": self.target_key,
                "label": self.label, "attrs": self.attrs, "evidence": list(self.evidence)}


@dataclass
class Edge:
    kind: str
    src: str                              # node_key
    dst: str                              # node_key
    confidence: str                       # observed | assumed
    reason: str = ""
    evidence: list[str] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def edge_key(self) -> str:
        return f"{self.kind}|{self.src}|{self.dst}"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "src": self.src, "dst": self.dst, "confidence": self.confidence,
                "reason": self.reason, "evidence": list(self.evidence), "attrs": self.attrs}


@dataclass
class Caps:
    max_nodes: int = 5000
    max_edges: int = 20000
    max_path_len: int = 8
    max_paths: int = 2000
    max_machines: int = 50


class Graph:
    """A bounded, deterministic directed graph. ``add_node``/``add_edge`` dedupe by key and
    enforce the node/edge caps; a cap hit sets a flag (reported in PATH-005), never raises."""

    def __init__(self, caps: Caps | None = None) -> None:
        self.caps = caps or Caps()
        self.nodes: dict[str, Node] = {}
        self.edges: dict[str, Edge] = {}
        self.caps_hit: set[str] = set()     # "nodes" / "edges" / "machines" / "paths" / "path_len"
        self._out: dict[str, list[str]] = {}   # node_key -> edge_keys out of it

    # -- building ---------------------------------------------------------------------

    def add_node(self, node: Node) -> Node | None:
        existing = self.nodes.get(node.node_key)
        if existing is not None:
            # Merge evidence deterministically (a machine may be evidenced by several reads).
            for e in node.evidence:
                if e not in existing.evidence:
                    existing.evidence.append(e)
            existing.attrs.update({k: v for k, v in node.attrs.items() if k not in existing.attrs})
            return existing
        if len(self.nodes) >= self.caps.max_nodes:
            self.caps_hit.add("nodes")
            return None
        self.nodes[node.node_key] = node
        self._out.setdefault(node.node_key, [])
        return node

    def add_edge(self, edge: Edge) -> Edge | None:
        if edge.src not in self.nodes or edge.dst not in self.nodes:
            return None
        if edge.edge_key in self.edges:
            existing = self.edges[edge.edge_key]
            for e in edge.evidence:
                if e not in existing.evidence:
                    existing.evidence.append(e)
            # observed beats assumed if a stronger justification turned up
            if existing.confidence == ASSUMED and edge.confidence == OBSERVED:
                existing.confidence = OBSERVED
                existing.reason = edge.reason or existing.reason
            return existing
        if len(self.edges) >= self.caps.max_edges:
            self.caps_hit.add("edges")
            return None
        self.edges[edge.edge_key] = edge
        self._out.setdefault(edge.src, []).append(edge.edge_key)
        return edge

    # -- reads ------------------------------------------------------------------------

    def node(self, node_key: str) -> Node | None:
        return self.nodes.get(node_key)

    def out_edges(self, node_key: str) -> list[Edge]:
        """Out-edges of a node, in a deterministic order (by edge key)."""
        keys = sorted(self._out.get(node_key, []))
        return [self.edges[k] for k in keys]

    def nodes_by_kind(self, kind: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def machine_of(self, node_key: str) -> str:
        n = self.nodes.get(node_key)
        return n.target_key if n is not None else ""

    def all_nodes(self) -> Iterable[Node]:
        return self.nodes.values()

    def all_edges(self) -> Iterable[Edge]:
        return self.edges.values()


# --- stable node keys ---------------------------------------------------------------


def machine_key(target_key: str) -> str:
    return f"{MACHINE}:{target_key}"


def service_key(target_key: str, proto: str, port: Any) -> str:
    return f"{SERVICE}:{target_key}:{str(proto).lower()}:{port}"


def account_key(target_key: str, name: str) -> str:
    return f"{ACCOUNT}:{target_key}:{name}"


def key_node_key(target_key: str, account: str, fingerprint: str) -> str:
    return f"{KEY}:{target_key}:{account}:{fingerprint}"


def container_key(target_key: str, ident: str) -> str:
    return f"{CONTAINER}:{target_key}:{ident}"


def code_root_key(target_key: str, path: str) -> str:
    return f"{CODE_ROOT}:{target_key}:{path}"
