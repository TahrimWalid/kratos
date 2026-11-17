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


def test_backup_fix_names_the_key_on_the_screen_not_the_cli_command():
    from kratos.tui_mk2.screens.backup import screen_fix

    assert screen_fix("`kratos backup key new` (the secret half goes off this computer)") == \
        "press k (the secret half goes off this computer)"
    assert screen_fix("`kratos backup create`, then `kratos backup drill <file>`") == "press n, then d"
    assert screen_fix("run `kratos backup create` by hand to see why") == "press n to see why"
    assert "press d" in screen_fix("no successful drill in 30 days: `kratos backup drill <file>`")
    # what the screen can't do stays a command
    assert "kratos backup prune" in screen_fix("move old backups elsewhere, or `kratos backup prune --keep N`")


def test_export_picker_shows_all_once_with_a_real_plural(tmp_path):
    from kratos.lifecycle.decide import Actor
    from kratos.tui_mk2.screens.export import _machine_choices

    G.create_group(tmp_path, "lab", Actor("owner", "cli"), members=["web-01.example.test"])
    labels = [label for _, label in _machine_choices(tmp_path, "web-01.example.test")]
    assert sum("@all" in label for label in labels) == 1
    assert "group @lab (1 machine)" in labels
    assert not any("machine(s)" in label for label in labels)


def test_no_list_picker_repeats_the_key_hint_it_already_prints():
    """The picker prints '↑↓ select · Enter pick · esc cancel' itself; a subtitle saying the
    same printed it twice (Export, Backup, Channels)."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1] / "src" / "kratos" / "tui_mk2"
    for path in root.rglob("*.py"):
        text = path.read_text()
        for m in re.finditer(r'subtitle="([^"]*)"', text):
            assert not re.search(r"↑↓|enter ·|· esc cancel", m.group(1)), (path.name, m.group(1))
