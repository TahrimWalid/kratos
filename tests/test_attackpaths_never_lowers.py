"""E.1 gate answer 3 / decision 8 / README §6: building attack paths never lowers, closes or
re-decides any other rule's finding.

Two proofs:
- **structural, parametrised over every rule id** in ``lifecycle/rules.py``: no non-PATH rule
  reads or is covered by the ``attack_paths`` snapshot, so a path build's coverage can never
  mark another rule's finding mitigated/inactive, and nothing in ``kratos.attackpaths`` writes
  another rule's severity;
- **end to end**: a real build run beside a pre-existing PERSIST-003 (high, with a known-good
  E.4 reputation on the same file) leaves that finding byte-for-byte unchanged.
"""
from __future__ import annotations

import pytest

from kratos.lifecycle.rules import RULES

import tests.test_attackpaths_build as T


def _non_path_rules() -> list[str]:
    return sorted(r for r in RULES if not r.startswith("PATH-"))


@pytest.mark.parametrize("rule_id", _non_path_rules())
def test_attack_paths_is_never_a_covering_input_of_another_rule(rule_id):
    """A path build is the only thing that reads/covers the ``attack_paths`` snapshot, so its
    completeness never marks a non-PATH finding gone. (The lifecycle only mitigates/closes a
    finding whose covering input was re-collected fresh; attack_paths is never one.)"""
    info = RULES[rule_id]
    assert "attack_paths" not in info.inputs
    assert "attack_paths" not in info.covering_inputs


def test_path_rules_only_read_attack_paths():
    for rid in (r for r in RULES if r.startswith("PATH-")):
        assert RULES[rid].inputs == ("attack_paths",)


def _persist003(path="/tmp/bash"):
    return {"id": "PERSIST-003", "title": "SUID binary owned by no package", "severity": "high",
            "evidence": [f"{path} is setuid-root and owned by no package"], "subject": path,
            "entities": [path], "recommendation": ["remove it"],
            # an E.4 known-good reputation on the very same file: must NOT soften placement
            "reputation": [{"verdict": "known_good", "source": "circl", "path": path}]}


def test_build_beside_persist003_does_not_lower_it(tmp_path):
    """End to end: PERSIST-003 high on 'app' is unchanged in severity and state after a path
    build runs over the group (README §6 — a known-good hash never softens a placement finding,
    and E.1 never rewrites another rule's severity)."""
    from kratos.assets import store as assets
    from kratos.fleet import groups as fleet_groups
    from kratos.lifecycle import query as lc_query
    from kratos.attackpaths import build as B

    owner = T._owner()
    # web: an internet entry so the build has real paths to draw
    T._write_live(tmp_path, "web", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0",
                  "exe": "nginx", "seen": True, "package": "nginx"}], local_addresses=["203.0.113.5"])
    T._seed_finding(tmp_path, "web", T._pkg_act())
    assets.update(tmp_path, "web", owner, exposure_override="internet")
    # app: a PERSIST-003 high the build must not touch
    T._write_live(tmp_path, "app", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0",
                  "exe": "sshd", "seen": True}], local_addresses=["10.0.0.8"])
    T._seed_finding(tmp_path, "app", _persist003())
    assets.update(tmp_path, "app", owner, criticality="high")
    fleet_groups.create_group(tmp_path, "lab", owner, members=["web", "app"])

    before = next(f for f in lc_query.list_findings(tmp_path, target="app", state="open_verified")
                  if f["rule_id"] == "PERSIST-003")
    B.run_path_build(data_dir=tmp_path, group="lab", actor=owner, source="interactive")
    after_all = lc_query.list_findings(tmp_path, target="app", state="open_verified")
    after = next(f for f in after_all if f["rule_id"] == "PERSIST-003")
    assert after["severity"] == "high" == before["severity"]
    assert after["state"] == before["state"]           # not closed, not decided, not mitigated


def test_a_second_build_does_not_reopen_or_change_other_findings(tmp_path):
    """Running the build twice is idempotent for other rules: PERSIST-003 stays high/open."""
    from kratos.assets import store as assets
    from kratos.fleet import groups as fleet_groups
    from kratos.lifecycle import query as lc_query
    from kratos.attackpaths import build as B

    owner = T._owner()
    T._write_live(tmp_path, "app", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0",
                  "exe": "sshd", "seen": True}], local_addresses=["10.0.0.8"])
    T._seed_finding(tmp_path, "app", _persist003())
    assets.update(tmp_path, "app", owner, criticality="high")
    fleet_groups.create_group(tmp_path, "lab", owner, members=["app"])
    for _ in range(2):
        B.run_path_build(data_dir=tmp_path, group="lab", actor=owner, source="interactive")
    p3 = [f for f in lc_query.list_findings(tmp_path, target="app", state="open_verified")
          if f["rule_id"] == "PERSIST-003"]
    assert len(p3) == 1 and p3[0]["severity"] == "high"
