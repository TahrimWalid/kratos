"""The pinned entry-point rank table (E.1 decision 3) and the path rank key (decision 5).

An entry's strength is computed from its inputs -- the exposure tier, the SSVC decision and
the strongest finding on the node -- never from a model. The order and the PATH-001 severity
are a small table here, pinned by ``tests/test_attackpaths_rank.py``.
"""
from __future__ import annotations

from dataclasses import dataclass

from kratos.attackpaths import graph as G

# Entry strength, strongest first (decision 3):
#   0 internet + SSVC Act (active exploit)      -> high
#   1 Attend (internet, then network)           -> high
#   2 CONT-004 confirmed firewall-bypass port   -> high
#   3 web shell (CODE-005) / untracked (CODE-001)-> high
#   4 exposed service, no known weakness        -> low
ACTIVE_EXPLOIT = 0
ATTEND = 1
CONTAINER_BYPASS = 2
WEB_SHELL = 3
NO_WEAKNESS = 4

_HIGH = {ACTIVE_EXPLOIT, ATTEND, CONTAINER_BYPASS, WEB_SHELL}

_RANK_WORDS = {
    ACTIVE_EXPLOIT: "an internet-reachable service with a vulnerability under active exploitation",
    ATTEND: "a reachable service with a vulnerability that needs attention",
    CONTAINER_BYPASS: "a container port published past the firewall",
    WEB_SHELL: "a web shell or untracked script in served code",
    NO_WEAKNESS: "a reachable service with no weakness Kratos knows of",
}


@dataclass(frozen=True)
class Strength:
    rank_index: int
    severity: str
    label: str


def entry_strength(exposes_edge: G.Edge) -> Strength:
    """The strength of one entry from its ``exposes`` edge's stamped inputs."""
    a = exposes_edge.attrs
    rule = str(a.get("entry_rule") or "")
    tier = str(a.get("exposure_tier") or "network")
    outcome = str(a.get("ssvc_outcome") or "")
    if a.get("no_known_weakness"):
        idx = NO_WEAKNESS
    elif rule in ("CODE-001", "CODE-005"):
        idx = WEB_SHELL
    elif rule == "CONT-004":
        idx = CONTAINER_BYPASS
    elif outcome == "act" and tier == "internet":
        idx = ACTIVE_EXPLOIT
    elif outcome in ("act", "attend"):
        idx = ATTEND
    else:
        # an exposed vuln that is neither act nor attend reached here only as a weak entry
        idx = NO_WEAKNESS
    severity = "high" if idx in _HIGH else "low"
    return Strength(idx, severity, _RANK_WORDS[idx])


# Within one strength, internet ranks above network, and a higher finding severity first.
_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_TIER = {"internet": 0, "network": 1}


def entry_sort_key(exposes_edge: G.Edge, dst_label: str) -> tuple:
    """A deterministic ordering key for entries (lower sorts first = stronger)."""
    s = entry_strength(exposes_edge)
    a = exposes_edge.attrs
    tier = _TIER.get(str(a.get("exposure_tier") or "network"), 1)
    sev = -_SEV.get(str(a.get("finding_severity") or "info"), 0)
    return (s.rank_index, tier, sev, dst_label, exposes_edge.edge_key)
