"""Build the typed attack-path graph from stored evidence (E.1 decision 2).

``build_graph`` turns the per-machine :class:`~kratos.attackpaths.inputs.MachineInputs` (loaded
read-free) into a :class:`~kratos.attackpaths.graph.Graph`. Every node and edge cites the finding
ids / snapshot fields that justify it, from the machine it is about -- one machine's evidence
never supports a claim about another (the one exception, ``key_reuse``, pairs two machines'
own ``authorized_keys`` fingerprints). An unread or stale machine contributes only its
``machine`` node (marked), never services, accounts or keys it was never read for.

(``build_graph`` lives here rather than in ``graph.py`` so the typed-graph module stays free
of input-shape knowledge; ``graph.py`` holds the node/edge/Graph types and the stable keys.)
"""
from __future__ import annotations

import re
from typing import Any

from kratos.attackpaths import graph as G
from kratos.attackpaths.inputs import MachineInputs

# A listener/published address:port out of an SSVC exposure reason ("... listens on
# 10.0.0.5:443", "... publishes [::]:8080"). Used to tie a vulnerability finding to the
# service node it is exposed through.
_ADDR_PORT = re.compile(r"(\[[0-9A-Fa-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]+):(\d{1,5})\b")

# SSVC outcomes that make an exposed service a foothold-granting entry.
_ACT = "act"
_ATTEND = "attend"
_EXPOSED = frozenset({"internet", "network"})

# CONT-* settings that let a container escape to its host (T1611).
_ESCAPE_RULES = frozenset({"CONT-001", "CONT-002", "CONT-003", "CONT-005", "CONT-006"})


def _clean(text: Any) -> str:
    from kratos.untrusted import for_display

    return for_display(str(text or ""))


def _fid(f: dict[str, Any]) -> str:
    """A short, stable reference to a finding, for an edge's evidence list."""
    return str(f.get("short_key") or f.get("finding_key") or f.get("rule_id") or "")


def _ssvc(f: dict[str, Any]) -> dict[str, Any]:
    s = f.get("ssvc")
    return s if isinstance(s, dict) else {}


def _outcome(f: dict[str, Any]) -> str:
    return str(_ssvc(f).get("outcome") or "")


def _exposure(f: dict[str, Any]) -> str:
    return str((_ssvc(f).get("exposure") or {}).get("value") or "")


def _by_rule(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        out.setdefault(str(f.get("rule_id") or ""), []).append(f)
    return out


def _addr_port(reason: str) -> tuple[str, int] | None:
    m = _ADDR_PORT.search(str(reason or ""))
    if not m:
        return None
    addr = m.group(1).strip("[]")
    try:
        return addr, int(m.group(2))
    except ValueError:
        return None


# --- machine nodes ------------------------------------------------------------------


def _criticality(mi: MachineInputs) -> tuple[str, bool]:
    """(criticality, assumed). Unset is assumed 'medium' and labelled (D.3's rule)."""
    crit = getattr(mi.asset, "criticality", None) if mi.asset is not None else None
    if crit in ("low", "medium", "high", "critical"):
        return crit, False
    return "medium", True


def _add_machine(graph: G.Graph, mi: MachineInputs) -> G.Node | None:
    crit, assumed = _criticality(mi)
    node = G.Node(
        kind=G.MACHINE, node_key=G.machine_key(mi.target_key), target_key=mi.target_key,
        label=_clean(mi.label or mi.target_key),
        attrs={
            "criticality": crit, "criticality_assumed": assumed,
            "exposure_override": getattr(mi.asset, "exposure_override", None) if mi.asset else None,
            "transport": mi.transport, "ssh_only": mi.ssh_only, "reader_root": mi.reader_root,
            "data_age_hours": None if mi.data_age_hours is None else round(mi.data_age_hours, 1),
            "stale": mi.stale, "unread": mi.unread, "has_data": mi.has_data(),
        },
        evidence=[],
    )
    return graph.add_node(node)


# --- service nodes and entries ------------------------------------------------------


def _public_bound(address: Any) -> bool:
    """A listener bound somewhere another host could reach it (not loopback)."""
    a = str(address or "").strip()
    if not a or a.startswith("127.") or a in ("::1",):
        return False
    return True


def _add_services(graph: G.Graph, mi: MachineInputs) -> dict[tuple[str, int], str]:
    """A service node per listener; returns (proto, port) -> node_key for later linking."""
    by_port: dict[tuple[str, int], str] = {}
    for it in (mi.live or {}).get("listeners") or []:
        if not isinstance(it, dict) or not isinstance(it.get("port"), int):
            continue
        proto = str(it.get("proto") or "tcp").lower()
        port = int(it["port"])
        nk = G.service_key(mi.target_key, proto, port)
        prog = _clean(it.get("exe") or it.get("comm") or "a program")
        node = G.Node(kind=G.SERVICE, node_key=nk, target_key=mi.target_key,
                      label=f"{proto}/{port} ({prog})",
                      attrs={"proto": proto, "port": port, "address": str(it.get("address") or ""),
                             "program": prog, "package": it.get("package"), "seen": bool(it.get("seen")),
                             "public": _public_bound(it.get("address"))},
                      evidence=["live listeners"])
        if graph.add_node(node) is not None:
            by_port[(proto, port)] = nk
    return by_port


def _entry_findings(mi: MachineInputs) -> list[dict[str, Any]]:
    """Open findings that make a service or code folder an entry: an exposed vulnerable
    package / reached service (SSVC attend/act and internet/network exposure), a web shell,
    an untracked executed script, a vulnerable served dependency, a firewall-bypass port."""
    out: list[dict[str, Any]] = []
    for f in mi.findings:
        rid = str(f.get("rule_id") or "")
        if rid in ("PKG-001", "PKG-002", "PKG-003", "VULN-001", "VULN-002"):
            if _outcome(f) in (_ACT, _ATTEND) and _exposure(f) in _EXPOSED:
                out.append(f)
        elif rid in ("CODE-001", "CODE-003", "CODE-005", "CONT-004"):
            out.append(f)
    return out


def _outside_for(exposure: str, override: Any) -> str:
    """Which outside start node an exposure is reachable from. internet (or a person's
    internet override) -> the internet; network -> inside the group only."""
    if exposure == "internet" or override == "internet":
        return G.OUTSIDE_INTERNET
    return G.OUTSIDE_NETWORK


def _ensure_outside(graph: G.Graph) -> None:
    for nk, label in ((G.OUTSIDE_INTERNET, "an attacker on the internet"),
                      (G.OUTSIDE_NETWORK, "an attacker already inside your network")):
        graph.add_node(G.Node(kind=G.OUTSIDE, node_key=nk, target_key="", label=label))


def _foothold_confidence(f: dict[str, Any]) -> str:
    """A web shell or an actively-exploited (SSVC act) exposed service is a foothold we can
    stand on (observed weakness); an 'attend' vulnerability is a plausible, not proven,
    foothold (assumed)."""
    rid = str(f.get("rule_id") or "")
    if rid in ("CODE-001", "CODE-005", "CONT-004"):
        return G.OBSERVED
    return G.OBSERVED if _outcome(f) == _ACT else G.ASSUMED


# --- accounts -----------------------------------------------------------------------

_ROOT_WORDS = ("sudo group", "root-equivalent group", "uid 0", "granted sudo", "sudoers grant",
               "primary group is 'root'")


def _reaches_root(via: list[str]) -> tuple[bool, str]:
    for reason in via:
        low = str(reason).lower()
        if any(w in low for w in _ROOT_WORDS):
            return True, str(reason)
    return False, ""


def _add_accounts(graph: G.Graph, mi: MachineInputs) -> dict[str, str]:
    """An account node per privileged/local account; returns user -> node_key."""
    by_user: dict[str, str] = {}
    accounts = (mi.privileged or {}).get("accounts") or {}
    priv_ev = ["privileged-accounts read"]
    # PRIV findings as extra evidence per the accounts they name
    for user, acct in accounts.items():
        if not isinstance(acct, dict):
            continue
        via = [str(v) for v in acct.get("via") or []]
        root, why = _reaches_root(via)
        nk = G.account_key(mi.target_key, str(user))
        node = G.Node(kind=G.ACCOUNT, node_key=nk, target_key=mi.target_key, label=_clean(user),
                      attrs={"uid": acct.get("uid"), "via": via, "reaches_root": root,
                             "root_reason": why, "login_shell": bool(acct.get("login_shell"))},
                      evidence=list(priv_ev))
        if graph.add_node(node) is not None:
            by_user[str(user)] = nk
    return by_user


def _ensure_account(graph: G.Graph, mi: MachineInputs, user: str, by_user: dict[str, str]) -> str:
    """A login account named by a key but not in the privileged list still needs a node."""
    nk = by_user.get(user)
    if nk is not None:
        return nk
    nk = G.account_key(mi.target_key, user)
    graph.add_node(G.Node(kind=G.ACCOUNT, node_key=nk, target_key=mi.target_key, label=_clean(user),
                          attrs={"uid": None, "via": [], "reaches_root": False},
                          evidence=["authorized_keys"]))
    by_user[user] = nk
    return nk


# --- keys (public halves only) ------------------------------------------------------


def _parse_key_identity(ident: str) -> tuple[str, str] | None:
    """'user:SHA256:...' -> (user, fingerprint). A line Kratos couldn't fingerprint
    ('user:/path#line') has no fingerprint and can't be a reuse edge -> None."""
    user, _, rest = str(ident).partition(":")
    if not rest or not rest.startswith("SHA256:"):
        return None
    return user, rest


# --- containers ---------------------------------------------------------------------


def _container_images(mi: MachineInputs) -> list[dict[str, Any]]:
    """The running container images from the snapshot (``images`` is a dict image_id ->
    {image, digest, containers, ports, host_network})."""
    images = (mi.containers or {}).get("images")
    if isinstance(images, dict):
        return [im for im in images.values() if isinstance(im, dict)]
    if isinstance(images, list):
        return [im for im in images if isinstance(im, dict)]
    return []


def _add_containers(graph: G.Graph, mi: MachineInputs) -> dict[str, str]:
    """A container node per running container; returns container name -> node_key."""
    by_name: dict[str, str] = {}
    for im in _container_images(mi):
        for name in im.get("containers") or []:
            ident = str(name)
            nk = G.container_key(mi.target_key, ident)
            node = G.Node(kind=G.CONTAINER, node_key=nk, target_key=mi.target_key, label=_clean(ident),
                          attrs={"image": im.get("image") or im.get("digest"),
                                 "ports": im.get("ports") or [], "host_network": bool(im.get("host_network"))},
                          evidence=["container read"])
            if graph.add_node(node) is not None:
                by_name[ident] = nk
    return by_name


def _container_node_for(graph: G.Graph, mi: MachineInputs, by_name: dict[str, str],
                        f: dict[str, Any]) -> str | None:
    """Best-effort: the container a CONT finding is about (its subject/entities name it)."""
    names = {str(e) for e in f.get("entities") or []} | {str(f.get("subject") or "")}
    for ident, nk in by_name.items():
        if ident in names or any(ident in n for n in names):
            return nk
    # a container finding but no matching node: attach to the first container on the machine
    return next(iter(by_name.values()), None)


# --- code roots ---------------------------------------------------------------------


def _add_code_roots(graph: G.Graph, mi: MachineInputs,
                    by_port: dict[tuple[str, int], str]) -> dict[str, str]:
    """A code-root node per confirmed root; a ``serves`` edge from the service that serves
    it. Returns root path -> node_key."""
    import json

    by_path: dict[str, str] = {}
    for r in mi.code_roots:
        path = str(r.get("path") or "")
        if not path:
            continue
        nk = G.code_root_key(mi.target_key, path)
        serving = r.get("serving")
        if isinstance(serving, str):
            try:
                serving = json.loads(serving)
            except ValueError:
                serving = []
        serving = serving if isinstance(serving, list) else []
        node = G.Node(kind=G.CODE_ROOT, node_key=nk, target_key=mi.target_key, label=_clean(path),
                      attrs={"serving": serving}, evidence=["confirmed code root"])
        if graph.add_node(node) is None:
            continue
        by_path[path] = nk
        for s in serving:
            if not isinstance(s, dict) or not isinstance(s.get("port"), int):
                continue
            proto = str(s.get("proto") or "tcp").lower()
            svc = by_port.get((proto, int(s["port"])))
            if svc is not None:
                graph.add_edge(G.Edge(kind=G.SERVES, src=svc, dst=nk, confidence=G.OBSERVED,
                                      reason=f"this service serves {path}", evidence=["confirmed code root"]))
    return by_path


# --- the build ----------------------------------------------------------------------


def build_graph(inputs: dict[str, MachineInputs], *, caps: G.Caps | None = None,
                assume_same_network: bool = True) -> G.Graph:
    """The full typed graph for a group, from stored evidence only. Deterministic."""
    graph = G.Graph(caps=caps)
    _ensure_outside(graph)
    svc_ports: dict[str, dict[tuple[str, int], str]] = {}
    acct_users: dict[str, dict[str, str]] = {}
    key_by_fp: dict[str, list[tuple[str, str]]] = {}   # fingerprint -> [(target_key, account node_key)]

    machines = sorted(inputs)                          # deterministic machine order
    if len(machines) > graph.caps.max_machines:
        graph.caps_hit.add("machines")
        machines = machines[: graph.caps.max_machines]

    # Pass 1: nodes per machine.
    for mk in machines:
        mi = inputs[mk]
        _add_machine(graph, mi)
        if not mi.has_data():
            continue                                   # unread/stale: machine node only, never assumed
        by_port = _add_services(graph, mi)
        svc_ports[mk] = by_port
        acct_users[mk] = _add_accounts(graph, mi)
        _add_code_roots(graph, mi, by_port)
        _add_containers(graph, mi)
        # key nodes + authenticates edges + reuse index
        for ident in mi.key_identities:
            parsed = _parse_key_identity(ident)
            if parsed is None:
                continue
            user, fp = parsed
            acct_nk = _ensure_account(graph, mi, user, acct_users[mk])
            knk = G.key_node_key(mk, user, fp)
            graph.add_node(G.Node(kind=G.KEY, node_key=knk, target_key=mk, label=_clean(fp[:19] + "…"),
                                  attrs={"fingerprint": fp, "account": user}, evidence=["authorized_keys"]))
            graph.add_edge(G.Edge(kind=G.AUTHENTICATES, src=knk, dst=acct_nk, confidence=G.OBSERVED,
                                  reason=f"this key authorises {user}", evidence=["authorized_keys"]))
            key_by_fp.setdefault(fp, []).append((mk, acct_nk))

    # Pass 2: per-machine edges that reach the machine (escalates, escapes, entries).
    for mk in machines:
        mi = inputs[mk]
        if not mi.has_data():
            continue
        _add_escalations(graph, mi, acct_users.get(mk, {}), svc_ports.get(mk, {}))
        _add_entries(graph, mi, svc_ports.get(mk, {}))
        _add_container_edges(graph, mi)

    # Pass 3: cross-machine edges (key reuse, reach).
    _add_key_reuse(graph, key_by_fp)
    _add_reaches(graph, inputs, machines, svc_ports, assume_same_network)
    return graph


def _add_escalations(graph: G.Graph, mi: MachineInputs, by_user: dict[str, str],
                     by_port: dict[tuple[str, int], str]) -> None:
    """escalates: an account that reaches root -> the machine (root). A SUID-from-no-package
    backdoor (PERSIST-003) is a second way, attached to the machine's root."""
    mk = mi.target_key
    machine_nk = G.machine_key(mk)
    for user, nk in by_user.items():
        node = graph.node(nk)
        if node is not None and node.attrs.get("reaches_root"):
            graph.add_edge(G.Edge(kind=G.ESCALATES, src=nk, dst=machine_nk, confidence=G.OBSERVED,
                                  reason=f"{user} reaches root ({node.attrs.get('root_reason') or 'admin rights'})",
                                  evidence=["privileged-accounts read"]))
    for f in _by_rule(mi.findings).get("PERSIST-003", []):
        # a SUID backdoor: anyone who can run it reaches root. Attach it to the machine as a
        # standing escalation (shown as a latent escalation on the machine node's evidence).
        node = graph.node(machine_nk)
        if node is not None:
            node.attrs.setdefault("suid_backdoor", True)
            if _fid(f) not in node.evidence:
                node.evidence.append(_fid(f))


def _add_entries(graph: G.Graph, mi: MachineInputs, by_port: dict[tuple[str, int], str]) -> None:
    """exposes + foothold for every entry finding on this machine."""
    mk = mi.target_key
    machine_nk = G.machine_key(mk)
    override = getattr(mi.asset, "exposure_override", None) if mi.asset else None
    # entry findings
    for f in _entry_findings(mi):
        rid = str(f.get("rule_id") or "")
        exposure = _exposure(f) or ("network" if rid == "CONT-004" else "internet")
        outside = _outside_for(exposure, override)
        if rid == "CONT-004":
            continue                                   # handled in _add_container_edges
        target_nk = _entry_target_node(graph, mi, f, by_port)
        if target_nk is None:
            continue
        graph.add_edge(G.Edge(kind=G.EXPOSES, src=outside, dst=target_nk, confidence=G.OBSERVED,
                              reason=_entry_reason(f, exposure), evidence=[_fid(f)],
                              attrs={"entry_rule": rid, "ssvc_outcome": _outcome(f), "exposure_tier": exposure,
                                     "finding_severity": str(f.get("severity") or "info").lower(),
                                     "finding": _fid(f)}))
        graph.add_edge(G.Edge(kind=G.FOOTHOLD, src=target_nk, dst=machine_nk,
                              confidence=_foothold_confidence(f), reason=_foothold_reason(f),
                              evidence=[_fid(f)]))
    # plain internet-exposed services with no known weakness: an entry, no foothold
    for (proto, port), nk in by_port.items():
        node = graph.node(nk)
        if node is None or not node.attrs.get("public"):
            continue
        if any(e.dst == nk and e.kind == G.EXPOSES for e in graph.out_edges(G.OUTSIDE_INTERNET)) or \
           any(e.dst == nk and e.kind == G.EXPOSES for e in graph.out_edges(G.OUTSIDE_NETWORK)):
            continue
        # only when a person marked the machine internet-facing, or an SSVC exposure said so,
        # do we call a plain listener an internet entry; otherwise it is a network entry.
        outside = G.OUTSIDE_INTERNET if override == "internet" else G.OUTSIDE_NETWORK
        graph.add_edge(G.Edge(kind=G.EXPOSES, src=outside, dst=nk, confidence=G.OBSERVED,
                              reason=f"{node.label} is reachable with no weakness Kratos knows of",
                              evidence=["live listeners"],
                              attrs={"no_known_weakness": True,
                                     "exposure_tier": "internet" if outside == G.OUTSIDE_INTERNET else "network",
                                     "finding_severity": "info"}))


def _entry_target_node(graph: G.Graph, mi: MachineInputs, f: dict[str, Any],
                       by_port: dict[tuple[str, int], str]) -> str | None:
    rid = str(f.get("rule_id") or "")
    mk = mi.target_key
    if rid in ("CODE-001", "CODE-005"):
        # a web shell / untracked script: the code-root it is in (subject is the root path)
        subj = str(f.get("subject") or "")
        for r in mi.code_roots:
            path = str(r.get("path") or "")
            if path and (subj == path or subj.startswith(path) or path in subj):
                return G.code_root_key(mk, path)
        return next((G.code_root_key(mk, str(r.get("path"))) for r in mi.code_roots if r.get("path")), None)
    if rid == "CODE-003":
        for r in mi.code_roots:
            path = str(r.get("path") or "")
            if path and (str(f.get("subject") or "").startswith(path) or path in str(f.get("subject") or "")):
                return G.code_root_key(mk, path)
        return next((G.code_root_key(mk, str(r.get("path"))) for r in mi.code_roots if r.get("path")), None)
    # a package/vuln finding: the service it is exposed through (port from the exposure reason)
    reason = str((_ssvc(f).get("exposure") or {}).get("reason") or "")
    ap = _addr_port(reason)
    if ap is not None:
        for proto in ("tcp", "udp"):
            nk = by_port.get((proto, ap[1]))
            if nk is not None:
                return nk
        # a service we know from the finding but not in the listener list: make a node
        proto, port = "tcp", ap[1]
        nk = G.service_key(mk, proto, port)
        graph.add_node(G.Node(kind=G.SERVICE, node_key=nk, target_key=mk, label=f"{proto}/{port}",
                              attrs={"proto": proto, "port": port, "address": ap[0], "public": True,
                                     "from_finding": True}, evidence=[_fid(f)]))
        return nk
    # no port in the reason: attach to the machine's most-exposed public service, else skip
    pub = sorted((k for k, nk in by_port.items()), )
    for proto, port in pub:
        nk = by_port[(proto, port)]
        node = graph.node(nk)
        if node is not None and node.attrs.get("public"):
            return nk
    return None


def _entry_reason(f: dict[str, Any], exposure: str) -> str:
    rid = str(f.get("rule_id") or "")
    where = "from the internet" if exposure == "internet" else "from inside your network"
    label = {"CODE-005": "a web shell", "CODE-001": "an untracked script in served code",
             "CODE-003": "a vulnerable served dependency", "VULN-001": "a vulnerable service",
             "PKG-001": "a vulnerable package", "PKG-002": "a vulnerable package"}.get(rid, "a weakness")
    return f"{label} is reachable {where} ({_fid(f)})"


def _foothold_reason(f: dict[str, Any]) -> str:
    rid = str(f.get("rule_id") or "")
    if rid in ("CODE-001", "CODE-005"):
        return "a web shell runs code as the service account"
    if _outcome(f) == _ACT:
        return "an actively-exploited vulnerability gives code execution"
    return "the vulnerability could give code execution (not observed)"


def _add_container_edges(graph: G.Graph, mi: MachineInputs) -> None:
    """exposes (CONT-004 firewall-bypass port) and escapes (CONT-001/002/003/005/006)."""
    mk = mi.target_key
    machine_nk = G.machine_key(mk)
    by_name = {str(name): G.container_key(mk, str(name))
               for im in _container_images(mi) for name in im.get("containers") or []}
    by_rule = _by_rule(mi.findings)
    override = getattr(mi.asset, "exposure_override", None) if mi.asset else None
    for f in by_rule.get("CONT-004", []):
        cnk = _container_node_for(graph, mi, by_name, f)
        if cnk is None:
            continue
        outside = G.OUTSIDE_INTERNET if override == "internet" else G.OUTSIDE_NETWORK
        graph.add_edge(G.Edge(kind=G.EXPOSES, src=outside, dst=cnk, confidence=G.OBSERVED,
                              reason=f"a published container port the firewall doesn't filter ({_fid(f)})",
                              evidence=[_fid(f)],
                              attrs={"entry_rule": "CONT-004", "exposure_tier": "network",
                                     "finding_severity": str(f.get("severity") or "info").lower(),
                                     "finding": _fid(f)}))
        graph.add_edge(G.Edge(kind=G.FOOTHOLD, src=cnk, dst=machine_nk, confidence=G.ASSUMED,
                              reason="reaching the container is a foothold if its app is exploitable",
                              evidence=[_fid(f)]))
    for rid in sorted(_ESCAPE_RULES):
        for f in by_rule.get(rid, []):
            cnk = _container_node_for(graph, mi, by_name, f)
            if cnk is None:
                continue
            graph.add_edge(G.Edge(kind=G.ESCAPES, src=cnk, dst=machine_nk, confidence=G.OBSERVED,
                                  reason=f"this container can escape to the host ({rid})", evidence=[_fid(f)]))


def _add_key_reuse(graph: G.Graph, key_by_fp: dict[str, list[tuple[str, str]]]) -> None:
    """Undirected key-reuse: a fingerprint authorising an account on >=2 machines joins them
    (gate decision 2026-11-16: read-free, undirected -- one stolen private half reaches both)."""
    for fp in sorted(key_by_fp):
        holders = key_by_fp[fp]
        machines = sorted({mk for mk, _acct in holders})
        if len(machines) < 2:
            continue
        accts = {mk: acct for mk, acct in holders}
        for i, a in enumerate(machines):
            for b in machines[i + 1:]:
                reason = f"the same SSH key authorises an account on both (fingerprint {fp[7:23]}…)"
                for src, dst in ((a, b), (b, a)):
                    graph.add_edge(G.Edge(kind=G.KEY_REUSE, src=G.machine_key(src), dst=G.machine_key(dst),
                                          confidence=G.OBSERVED, reason=reason,
                                          evidence=["authorized_keys"],
                                          attrs={"fingerprint": fp, "accounts": [accts[src], accts[dst]],
                                                 "directed": False}))


def _covered_ranges(local_addresses: list[Any]) -> list[Any]:
    import ipaddress

    out = []
    for a in local_addresses or []:
        try:
            out.append(ipaddress.ip_address(str(a).split("%", 1)[0]))
        except ValueError:
            continue
    return out


def _add_reaches(graph: G.Graph, inputs: dict[str, MachineInputs], machines: list[str],
                 svc_ports: dict[str, dict[tuple[str, int], str]], assume_same_network: bool) -> None:
    """reaches: machine A -> a service on machine B. observed when A has an outbound socket to
    B's address:port; assumed (same network) when A and B are in the group and B's service is
    bound where A could reach it and no firewall rule is known to block it."""
    import ipaddress

    # B's reachable addresses -> (B, proto, port) for observed matching
    addr_index: dict[tuple[str, int], tuple[str, str]] = {}
    for mk in machines:
        mi = inputs[mk]
        if not mi.has_data():
            continue
        addrs = {str(a) for a in (mi.live or {}).get("local_addresses") or []}
        for (proto, port), nk in svc_ports.get(mk, {}).items():
            for a in addrs:
                addr_index[(a, port)] = (nk, proto)

    # observed: outbound sockets
    for mk in machines:
        mi = inputs[mk]
        if not mi.has_data():
            continue
        for ob in (mi.live or {}).get("outbound") or []:
            if not isinstance(ob, dict):
                continue
            remote, port = str(ob.get("remote") or ""), ob.get("remote_port")
            if not remote or not isinstance(port, int):
                continue
            hit = addr_index.get((remote, port))
            if hit is None:
                continue
            nk, _proto = hit
            if graph.machine_of(nk) == mk:
                continue
            graph.add_edge(G.Edge(kind=G.REACHES, src=G.machine_key(mk), dst=nk, confidence=G.OBSERVED,
                                  reason=f"{mi.label} has an open connection to {remote}:{port}",
                                  evidence=["outbound sockets"]))

    if not assume_same_network:
        return
    # assumed (same network): A -> B's foothold-granting services only (bounded)
    foothold_services: set[str] = set()
    for e in graph.all_edges():
        if e.kind == G.FOOTHOLD:
            foothold_services.add(e.src)
    for mk in machines:
        mi = inputs[mk]
        if not mi.has_data():
            continue
        a_ranges = _covered_ranges((mi.live or {}).get("local_addresses") or [])
        for other in machines:
            if other == mk:
                continue
            om = inputs[other]
            if not om.has_data():
                continue
            for (proto, port), nk in svc_ports.get(other, {}).items():
                if nk not in foothold_services:
                    continue
                node = graph.node(nk)
                if node is None or not node.attrs.get("public"):
                    continue
                # already observed? don't add an assumed duplicate
                key = f"{G.REACHES}|{G.machine_key(mk)}|{nk}"
                if key in graph.edges:
                    continue
                graph.add_edge(G.Edge(kind=G.REACHES, src=G.machine_key(mk), dst=nk, confidence=G.ASSUMED,
                                      reason=f"{mi.label} and {om.label} are in the same group; no firewall rule "
                                             "Kratos read blocks this (assumed)",
                                      evidence=["same group"], attrs={"assumed_same_network": True}))
