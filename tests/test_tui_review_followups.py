"""Follow-ups to the TUI review (BUGS list after the 21 review patches): small wording and
consistency fixes that each have a regression test here."""
from __future__ import annotations

from kratos.fleet import groups as G
from kratos.ssvc import present


def test_ssvc_detail_line_leaves_out_missing_parts_instead_of_saying_none():
    line = present.detail_lines({"label": "Attend", "outcome": "attend"})[0]
    assert line == "SSVC decision: Attend" and "None" not in line
    line = present.detail_lines({"label": "Act", "outcome": "act", "cve": "CVE-2024-3094"})[0]
    assert line == "SSVC decision: Act (worst CVE CVE-2024-3094)"
    line = present.detail_lines({"label": "Act", "outcome": "act", "tree": "cisa-2.0.3", "cve": "CVE-2024-3094"})[0]
    assert line == "SSVC decision: Act (CISA SSVC tree cisa-2.0.3; worst CVE CVE-2024-3094)"


def test_groups_names_a_known_machine_that_is_not_in_all_and_why(tmp_path):
    from kratos.assets import store as AS
    from kratos.lifecycle.decide import Actor

    assert G.outside_all(tmp_path, configured="web-01.example.test") == ["web-01.example.test"]
    AS.update(tmp_path, "web-01.example.test", Actor("owner", "cli"), criticality="high")
    assert G.outside_all(tmp_path, configured="web-01.example.test") == []
    assert "web-01.example.test" in G.get_group(tmp_path, "all").members
