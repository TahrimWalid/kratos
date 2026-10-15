"""A.3: ATT&CK v19 labels from one pinned table, on every rule, in every finding
view, and as an ATT&CK Navigator layer.

- the table is generated deterministically from an official STIX bundle and
  records its version + sha256 (a real bundle can be re-checked byte for byte:
  KRATOS_ATTACK_BUNDLE=/path/enterprise-attack-19.x.json);
- every rule the engine can emit has an entry (labels, or posture with a reason),
  every label exists in the table, is current, and sits under one of its tactics;
- INTEG-001 is labelled by which file changed; an unknown file is posture;
- labels show in the TUI finding panel, the /findings details, the CLI, the
  Markdown report and the MCP finding dicts;
- the Navigator layer matches format 4.5 and lists exactly the labelled
  techniques (coverage) or only open/verified findings (observed).
"""
from __future__ import annotations

import ast
import asyncio
import hashlib
import io
import json
import os
import random
import re
import sys
import time
import uuid
from pathlib import Path

import pytest
from rich.console import Console

from kratos.adapters import findings_engine as FE
from kratos.attack import attack_of, format_label, mapping as M, navigator as N, table as TB
from kratos.attack.mapping import Behaviour, Posture
from kratos.lifecycle.rules import RULES

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "dev"))
import build_attack_table as BUILD  # noqa: E402

T = "10.0.0.5"


# --------------------------------------------------------------------------- table
def _bundle(objs: list[dict]) -> dict:
    return {"type": "bundle", "id": "bundle--x", "objects": objs}


def _ref(xid: str, url: str = "") -> list[dict]:
    return [{"source_name": "mitre-attack", "external_id": xid, "url": url or f"https://attack.mitre.org/{xid}"}]


def _mini_objects() -> list[dict]:
    return [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "name": "Enterprise ATT&CK",
         "x_mitre_version": "19.2", "modified": "2026-08-05T00:00:00Z"},
        {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1",
         "tactic_refs": ["x-mitre-tactic--p", "x-mitre-tactic--c"]},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--c", "name": "Credential Access",
         "x_mitre_shortname": "credential-access", "external_references": _ref("TA0006")},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--p", "name": "Persistence",
         "x_mitre_shortname": "persistence", "external_references": _ref("TA0003")},
        {"type": "attack-pattern", "id": "attack-pattern--new", "name": "Password Guessing",
         "x_mitre_domains": ["enterprise-attack"], "x_mitre_is_subtechnique": True, "x_mitre_platforms": ["Linux"],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
         "external_references": _ref("T1110.001")},
        {"type": "attack-pattern", "id": "attack-pattern--old", "name": "Old Thing", "revoked": True,
         "x_mitre_domains": ["enterprise-attack"],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}],
         "external_references": _ref("T1999")},
        {"type": "attack-pattern", "id": "attack-pattern--dep", "name": "Gone", "x_mitre_deprecated": True,
         "x_mitre_domains": ["enterprise-attack"], "external_references": _ref("T1998")},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "revoked-by",
         "source_ref": "attack-pattern--old", "target_ref": "attack-pattern--new"},
    ]


def test_the_generator_is_deterministic_and_order_independent():
    objs = _mini_objects()
    one = BUILD.render(BUILD.build(_bundle(objs), sha256="ab" * 32, url="u"))
    shuffled = list(objs)
    random.Random(7).shuffle(shuffled)
    two = BUILD.render(BUILD.build(_bundle(shuffled), sha256="ab" * 32, url="u"))
    assert one == two
    t = json.loads(one)
    assert t["attack_version"] == "19.2" and t["bundle"]["sha256"] == "ab" * 32
    assert t["techniques"]["T1999"]["revoked"] and t["techniques"]["T1999"]["revoked_by"] == "T1110.001"
    assert t["techniques"]["T1998"]["deprecated"]
    assert [k for k, _ in sorted(t["tactics"].items(), key=lambda kv: kv[1]["order"])] == \
        ["persistence", "credential-access"]


def test_the_generator_refuses_a_bundle_that_is_not_v19():
    objs = _mini_objects()
    objs[0] = dict(objs[0], x_mitre_version="20.0")
    with pytest.raises(SystemExit, match="v19"):
        BUILD.build(_bundle(objs), sha256="0" * 64, url="u")


def test_the_shipped_table_records_where_it_came_from():
    t = TB.table()
    assert t["attack_version"].startswith("19.") and TB.major_version() == "19"
    assert re.fullmatch(r"[0-9a-f]{64}", t["bundle"]["sha256"])
    assert t["bundle"]["url"].startswith("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/")
    assert t["domain"] == "enterprise-attack" and "MITRE" in t["_source"]
    # v19's split of Defense Evasion
    names = {v["name"] for v in t["tactics"].values()}
    assert {"Stealth", "Defense Impairment"} <= names and "Defense Evasion" not in names
    assert len(t["tactics"]) == 15 and len(t["techniques"]) > 600


@pytest.mark.skipif(not os.environ.get("KRATOS_ATTACK_BUNDLE"), reason="set KRATOS_ATTACK_BUNDLE to the STIX bundle")
def test_the_shipped_table_is_exactly_what_the_official_bundle_generates():
    raw = Path(os.environ["KRATOS_ATTACK_BUNDLE"]).read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    shipped = (ROOT / "src" / "kratos" / "attack" / "v19_table.json").read_bytes()
    assert json.loads(shipped)["bundle"]["sha256"] == sha
    url = json.loads(shipped)["bundle"]["url"]
    assert BUILD.render(BUILD.build(json.loads(raw), sha256=sha, url=url)) == shipped


def test_the_ids_0_3_noted_are_revoked_with_their_replacements():
    for old, new in (("T1070.002", "T1685.006"), ("T1562.012", "T1685.004"), ("T1562.001", "T1685")):
        assert TB.technique(old)["revoked"] and TB.technique(old)["revoked_by"] == new
        assert TB.is_current(new)


def test_label_refuses_revoked_unknown_and_wrong_tactic():
    with pytest.raises(TB.LabelError, match="revoked.*T1685.006"):
        TB.label("T1070.002")
    with pytest.raises(TB.LabelError, match="not in ATT&CK"):
        TB.label("T9999")
    with pytest.raises(TB.LabelError, match="not listed under"):
        TB.label("T1110.001", "persistence")
    lab = TB.label("T1098", "persistence", "privilege-escalation")
    assert lab["tactic"] == "Persistence" and [t["name"] for t in lab["tactics"]] == \
        ["Persistence", "Privilege Escalation"]
    assert lab["url"] == "https://attack.mitre.org/techniques/T1098" and lab["version"] == TB.attack_version()


# ------------------------------------------------------------------------- mapping
def _engine_rule_ids() -> set[str]:
    tree = ast.parse((ROOT / "src" / "kratos" / "adapters" / "findings_engine.py").read_text())
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Finding":
            for kw in node.keywords:
                if kw.arg == "id" and isinstance(kw.value, ast.Constant):
                    ids.add(kw.value.value)
    return ids


def test_every_rule_has_an_entry():
    missing = sorted((set(RULES) | _engine_rule_ids()) - set(M.RULE_ATTACK))
    assert not missing, f"no ATT&CK entry (labels or Posture) for: {missing}"


def test_the_mapping_names_no_rule_kratos_does_not_have():
    """Every entry is a real rule (registered in kratos.lifecycle.rules): a typo or a
    removed rule must not leave a stale label behind."""
    extra = sorted(set(M.RULE_ATTACK) - set(RULES))
    assert not extra, f"ATT&CK entries for rules that don't exist: {extra}"


def test_every_posture_says_why_and_every_behaviour_has_labels():
    for rid, e in M.RULE_ATTACK.items():
        assert isinstance(e, (Behaviour, Posture)), rid
        if isinstance(e, Posture):
            assert len(e.why) > 10, rid
        else:
            assert e.labels and e.why, rid


@pytest.mark.parametrize("rid", sorted(r for r, e in M.RULE_ATTACK.items() if isinstance(e, Behaviour)))
def test_every_label_is_current_in_the_table_and_its_tactic_matches(rid):
    for lab in M.RULE_ATTACK[rid].labels:
        ref = TB.technique(lab["technique_id"])
        assert ref is not None, lab["technique_id"]
        assert not ref["revoked"] and not ref["deprecated"], lab["technique_id"]
        assert lab["technique"] == ref["name"] and lab["url"] == ref["url"]
        assert "Linux" in ref["platforms"], f"{lab['technique_id']} would be hidden by the layer's Linux filter"
        for tac in lab["tactics"]:
            assert tac["shortname"] in ref["tactics"]
            assert TB.table()["tactics"][tac["shortname"]] == {**TB.table()["tactics"][tac["shortname"]],
                                                               "id": tac["id"], "name": tac["name"]}
        assert (lab["tactic_id"], lab["tactic"]) == (lab["tactics"][0]["id"], lab["tactics"][0]["name"])


def test_posture_rules_carry_no_labels_explicitly():
    for rid in ("NET-001", "NET-002", "CTX-001", "ENV-001", "OBS-001", "VULN-001", "VULN-002", "VULN-003",
                "AUTH-001", "AUTH-003", "AUTH-TREND-001", "COV-001", "PRIV-004", "LOG-003", "LOG-006",
                "SEAL-003", "PERSIST-009", "PKG-001", "LIVE-004", "LIVE-007"):
        assert isinstance(M.entry(rid), Posture), rid
        assert M.labels(rid) == [] and M.labels_for_finding(rid, ["x"]) == []


def test_the_main_behaviour_mapping():
    def ids(rid):
        return [lab["technique_id"] for lab in M.labels(rid)]
    for rid in ("AUTH-004", "CORR-001", "CORR-002", "CORR-SSH-001"):
        assert ids(rid) == ["T1110.001"]
    assert ids("PRIV-001") == ids("PRIV-003") == ["T1098"]
    assert ids("PRIV-002") == ["T1136.001", "T1098"]
    assert ids("LOG-001") == ids("LOG-002") == ids("LOG-004") == ids("SEAL-001") == ["T1685.006"]
    assert ids("LOG-005") == ["T1685.004"] and ids("SEAL-002") == ["T1685"]
    assert M.labels("LOG-001")[0]["tactic"] == "Defense Impairment"


def test_the_old_import_path_still_works():
    from kratos.logsources import attack as old

    assert old.CRON == M.CRON and old.labels("LOG-005") == M.labels("LOG-005")
    assert old.ATTACK_VERSION == TB.attack_version()


# --------------------------------------------------------------------------- INTEG
@pytest.mark.parametrize("path, tid", [
    ("/etc/passwd", "T1098"), ("/etc/shadow", "T1098"), ("/etc/sudoers", "T1548.003"),
    ("/etc/sudoers.d/90-cloud", "T1548.003"), ("/etc/crontab", "T1053.003"), ("/etc/cron.d/backup", "T1053.003"),
    ("/etc/ssh/sshd_config", "T1556"), ("/etc/pam.d/sshd", "T1556.003"), ("/root/.ssh/authorized_keys", "T1098.004"),
    ("/etc/ld.so.preload", "T1574.006"), ("/etc/systemd/system/x.service", "T1543.002"),
    ("/home/bob/.bashrc", "T1546.004"), ("/etc/modules-load.d/x.conf", "T1547.006"),
])
def test_integ_labels_follow_the_changed_path(path, tid):
    assert [lab["technique_id"] for lab in M.labels_for_finding("INTEG-001", [path])] == [tid]


def test_integ_unknown_path_is_posture_and_several_paths_union():
    assert M.labels_for_finding("INTEG-001", ["/etc/hosts", "/opt/app/config.yml"]) == []
    got = [lab["technique_id"] for lab in M.labels_for_finding("INTEG-001", ["/etc/passwd", "/etc/crontab",
                                                                             "/etc/shadow", "/etc/hosts"])]
    assert got == ["T1098", "T1053.003"]


def _integ_snapshot(tmp_path: Path, paths: list[str]) -> None:
    d = tmp_path / "baseline"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"file_integrity_diff_{int(time.time())}.json").write_text(json.dumps({
        "target": "loopback", "checked_at": "2026-10-15T00:00:00+00:00", "baseline_name": "default",
        "diff": {"changed": [{"path": p} for p in paths], "added": [], "removed": []}}))


def test_engine_labels_integ_by_path(tmp_path):
    fi = {"checked_at": "2026-10-15T00:00:00+00:00", "baseline_name": "default",
          "diff": {"changed": [{"path": "/etc/sudoers"}], "added": [], "removed": []}}
    out = {f.id: f for f in FE.generate_findings(None, None, None, None, file_integrity=fi)}
    assert [a["technique_id"] for a in out["INTEG-001"].attack] == ["T1548.003"]
    fi["diff"]["changed"] = [{"path": "/opt/app/settings.ini"}]
    out = {f.id: f for f in FE.generate_findings(None, None, None, None, file_integrity=fi)}
    assert out["INTEG-001"].attack == []


def _burst_inputs():
    patterns = {"bursts": [{"event_type": "ssh_failed_login", "count": 9, "start": "2026-10-15T00:00:00+00:00",
                            "end": "2026-10-15T00:02:00+00:00", "top_source_ips": [{"ip": "203.0.113.9", "count": 9}]}]}
    nmap = {"hosts": [{"open_ports": [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}]}]}
    return nmap, patterns


def test_engine_stamps_every_behaviour_finding_and_no_posture_one():
    nmap, patterns = _burst_inputs()
    findings = FE.generate_findings(nmap, {"by_type": {"sudo_session_open": 2}}, patterns, None)
    by = {f.id: f for f in findings}
    assert "CORR-SSH-001" in by and [a["technique_id"] for a in by["CORR-SSH-001"].attack] == ["T1110.001"]
    for f in findings:
        if isinstance(M.entry(f.id), Posture):
            assert f.attack == [], f.id
        elif isinstance(M.entry(f.id), Behaviour) and not M.entry(f.id).per_item:
            assert f.attack, f.id


# ------------------------------------------------------------------------- display
LABELLED = {"id": "CORR-SSH-001", "title": "SSH exposed with failed-login burst activity observed",
            "severity": "high", "evidence": ["e1"], "recommendation": [], "entities": ["203.0.113.9"],
            "attack": M.labels("CORR-SSH-001")}
LINE = "ATT&CK: T1110.001 Password Guessing (Credential Access)"


def _render(renderable) -> str:
    buf = io.StringIO()
    Console(file=buf, width=200, color_system=None).print(renderable)
    return buf.getvalue()


def test_format_label_and_old_style_labels():
    assert format_label(M.labels("PRIV-001")[0]) == "T1098 Account Manipulation (Persistence, Privilege Escalation)"
    old_style = {"technique_id": "T1685.006", "technique": "Clear Linux or Mac System Logs",
                 "tactic_id": "TA0112", "tactic": "Defense Impairment", "version": "19.0", "url": "u"}
    assert format_label(old_style) == "T1685.006 Clear Linux or Mac System Logs (Defense Impairment)"


def test_attack_of_falls_back_to_the_mapping_for_older_findings():
    assert attack_of({"id": "CORR-SSH-001"})[0]["technique_id"] == "T1110.001"
    assert attack_of({"id": "INTEG-001", "entities": ["/etc/crontab"]})[0]["technique_id"] == "T1053.003"
    assert attack_of({"id": "NET-002", "entities": ["22/tcp"]}) == []


def test_tui_finding_panel_shows_the_label():
    from kratos.tui_mk2 import render as R

    assert LINE in _render(R.finding_panel(LABELLED))
    assert "ATT&CK" not in _render(R.finding_panel({**LABELLED, "id": "NET-002", "attack": []}))


def test_cli_investigate_panel_shows_the_label():
    from kratos.agent import console as C

    buf = io.StringIO()
    C.render_finding(Console(file=buf, width=200, color_system=None), LABELLED)
    assert LINE in buf.getvalue()


def test_markdown_report_and_report_json_carry_labels(tmp_path):
    (tmp_path / "scans").mkdir()
    (tmp_path / "logs").mkdir()
    nmap, patterns = _burst_inputs()
    nmap_path = tmp_path / "scans" / "nmap_parsed_1.json"
    nmap_path.write_text(json.dumps(nmap))
    pat_path = tmp_path / "logs" / "auth_patterns_1.json"
    pat_path.write_text(json.dumps(patterns))
    out_json, out_md = FE.write_findings_report(tmp_path, nmap_parsed_file=nmap_path, auth_patterns_file=pat_path)[:2]
    report = json.loads(Path(out_json).read_text())
    corr = [f for f in report["findings"] if f["id"] == "CORR-SSH-001"][0]
    assert corr["attack"][0]["technique_id"] == "T1110.001" and corr.get("finding_key")   # lifecycle copy keeps it
    md = Path(out_md).read_text()
    assert "**ATT&CK**: [T1110.001 Password Guessing (Credential Access)](https://attack.mitre.org/techniques/T1110/001)" in md


def _seed_lifecycle(tmp_path):
    from kratos.lifecycle import apply as A
    from kratos.lifecycle.coverage import nothing
    from kratos.run_context import RunContext

    r = RunContext(run_id=uuid.uuid4().hex, source="interactive", target=T, session_id=None, started_at=time.time())
    A.apply_run([dict(LABELLED), {"id": "NET-002", "title": "Open ports", "severity": "medium", "evidence": ["e"],
                                  "subject": "", "entities": ["22/tcp"]},
                 {"id": "INTEG-001", "title": "changed", "severity": "medium", "evidence": ["e"], "subject": "",
                  "entities": ["/etc/passwd"]}],      # an older finding without attack: mapped on read
                target=T, coverage=nothing(), run=r, data_dir=tmp_path)


def test_lifecycle_rows_carry_labels_and_cli_show_prints_them(tmp_path, capsys):
    import argparse

    from kratos.cli import app as CLI
    from kratos.lifecycle import query as Q

    _seed_lifecycle(tmp_path)
    rows = {r["rule_id"]: r for r in Q.list_findings(tmp_path, target=T, state="all")}
    assert rows["CORR-SSH-001"]["attack"][0]["technique_id"] == "T1110.001"
    assert rows["INTEG-001"]["attack"][0]["technique_id"] == "T1098"
    assert rows["NET-002"]["attack"] == []
    args = argparse.Namespace(data_dir=tmp_path, findings_action="show", key=rows["CORR-SSH-001"]["finding_key"],
                              json=False)
    assert CLI.cmd_findings(args) == 0
    out = capsys.readouterr().out
    assert "ATT&CK: T1110.001 Password Guessing (Credential Access)  https://attack.mitre.org/techniques/T1110/001" in out


def test_findings_show_by_id_prints_the_label(tmp_path, capsys):
    import argparse

    from kratos.cli.findings_show import cmd_findings_show

    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "findings_20261015T000000Z.json").write_text(json.dumps(
        {"generated_at": "x", "inputs": {}, "findings": [{k: v for k, v in LABELLED.items() if k != "attack"}]}))
    assert cmd_findings_show(argparse.Namespace(data_dir=tmp_path, finding_id="CORR-SSH-001")) == 0
    assert "ATT&CK: T1110.001 Password Guessing (Credential Access)" in capsys.readouterr().out


def test_mcp_finding_states_carry_labels(tmp_path, monkeypatch):
    from kratos import mcp_server

    _seed_lifecycle(tmp_path)
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)
    out = mcp_server.kratos_finding_states(target=T, state="all")
    by = {f["rule_id"]: f for f in out["findings"]}
    assert by["CORR-SSH-001"]["attack"][0]["technique_id"] == "T1110.001" and by["NET-002"]["attack"] == []


def test_findings_screen_details_and_copy(tmp_path):
    asyncio.run(_findings_screen_details_and_copy(tmp_path))


async def _findings_screen_details_and_copy(tmp_path):
    from textual.app import App

    from kratos.tui_mk2.modals import InfoModal
    from kratos.tui_mk2.screens.findings import FindingsScreen

    _seed_lifecycle(tmp_path)
    screen = FindingsScreen(tmp_path, target=T)

    class Host(App):
        copied: list[str] = []

        def on_mount(self):
            self.push_screen(screen)

        def copy_to_clipboard(self, text: str) -> None:
            self.copied.append(text)

    app = Host()
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        rows = [r["rule_id"] for r in screen._rows]
        table = screen.query_one("#fd-table")
        table.move_cursor(row=rows.index("CORR-SSH-001"))
        await pilot.press("c")
        await pilot.pause()
        assert app.copied == ["T1110.001 Password Guessing (Credential Access) "
                              "https://attack.mitre.org/techniques/T1110/001"]
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, InfoModal)
        text = "".join(_render(getattr(s, "_Static__content", "")) for s in app.screen.query("Static"))
        assert "T1110.001 Password Guessing (Credential Access)" in text
        await pilot.press("escape")
        await pilot.pause()
        table.move_cursor(row=rows.index("NET-002"))
        await pilot.press("c")
        await pilot.pause()
        assert len(app.copied) == 1                       # posture: nothing copied, a note instead


# ----------------------------------------------------------------------- navigator
_LAYER_KEYS = {"versions", "name", "description", "domain", "customDataURL", "filters", "sorting", "layout",
               "hideDisabled", "techniques", "gradient", "legendItems", "showTacticRowBackground",
               "tacticRowBackground", "selectTechniquesAcrossTactics", "selectSubtechniquesWithParent",
               "selectVisibleTechniques", "metadata", "links"}
_TECH_KEYS = {"techniqueID", "tactic", "comment", "enabled", "score", "color", "metadata", "links",
              "showSubtechniques"}


def _check_layer_format(layer: dict) -> None:
    assert set(layer) <= _LAYER_KEYS and {"name", "domain"} <= set(layer)
    assert layer["versions"] == {"attack": "19", "navigator": N.NAVIGATOR_VERSION, "layer": "4.5"}
    assert layer["domain"] == "enterprise-attack" and layer["filters"] == {"platforms": ["Linux"]}
    g = layer["gradient"]
    assert len(g["colors"]) >= 2 and g["maxValue"] > g["minValue"]
    assert all(set(li) == {"label", "color"} for li in layer["legendItems"])
    assert all(set(m) == {"name", "value"} for m in layer["metadata"])
    for t in layer["techniques"]:
        assert set(t) <= _TECH_KEYS and re.fullmatch(r"T\d{4}(\.\d{3})?", t["techniqueID"])
        ref = TB.technique(t["techniqueID"])
        assert ref and TB.is_current(t["techniqueID"]) and t["tactic"] in ref["tactics"]
        assert all(set(m) == {"name", "value"} for m in t.get("metadata", []))
    json.dumps(layer)


def test_coverage_layer_lists_exactly_the_labelled_techniques():
    layer = N.coverage_layer()
    _check_layer_format(layer)
    scored = {(t["techniqueID"], t["tactic"]) for t in layer["techniques"] if "score" in t}
    expected = {(lab["technique_id"], tac["shortname"]) for rid, e in M.RULE_ATTACK.items()
                if rid in RULES and isinstance(e, Behaviour) for lab in e.labels for tac in lab["tactics"]}
    assert scored == expected
    cell = [t for t in layer["techniques"] if t["techniqueID"] == "T1110.001"][0]
    assert cell["comment"] == "Kratos rules: AUTH-004, CORR-001, CORR-002, CORR-SSH-001" and cell["score"] == 1
    # an unscored parent so the sub-technique is shown expanded
    assert {"techniqueID": "T1110", "tactic": "credential-access", "showSubtechniques": True,
            "enabled": True} in layer["techniques"]
    assert ("T1685.006", "defense-impairment") in scored and ("T1574.006", "stealth") in scored
    assert not {tid for tid, _ in scored} & {"T1070.002", "T1562.012", "T1562.001"}


def test_coverage_counts_only_rules_this_build_has():
    layer = N.coverage_layer(rule_ids={"LOG-005"})
    assert {t["techniqueID"] for t in layer["techniques"]} == {"T1685.004", "T1685"}


def test_observed_layer_uses_only_open_and_verified_findings(tmp_path):
    from kratos.lifecycle import decide as D
    from kratos.lifecycle.keys import finding_key

    _seed_lifecycle(tmp_path)
    layer = N.observed_layer(N.observed_records(tmp_path, T), scope=T)
    _check_layer_format(layer)
    scored = {t["techniqueID"]: t for t in layer["techniques"] if "score" in t}
    assert set(scored) == {"T1110.001", "T1098"}
    assert scored["T1110.001"]["score"] == N.SEVERITY_SCORE["high"] and "CORR-SSH-001 on 10.0.0.5" in \
        scored["T1110.001"]["comment"]
    D.mark_false_positive(finding_key("CORR-SSH-001", T, ""), actor=D.Actor(user="a", interface="cli"),
                          reason="lab test", data_dir=tmp_path)
    layer = N.observed_layer(N.observed_records(tmp_path, T), scope=T)
    assert {t["techniqueID"] for t in layer["techniques"] if "score" in t} == {"T1098"}
    assert N.observed_records(tmp_path, "10.9.9.9") == []


def test_attack_layer_cli_writes_both_layers(tmp_path, monkeypatch, capsys):
    import argparse

    from kratos.cli import app as CLI

    _seed_lifecycle(tmp_path)
    out = tmp_path / "cov.json"
    assert CLI.cmd_attack_layer(argparse.Namespace(data_dir=tmp_path, observed=False, target=None,
                                                   out=str(out))) == 0
    _check_layer_format(json.loads(out.read_text()))
    assert "attack-navigator" in capsys.readouterr().out
    out2 = tmp_path / "obs.json"
    assert CLI.cmd_attack_layer(argparse.Namespace(data_dir=tmp_path, observed=True, target=T, out=str(out2))) == 0
    obs = json.loads(out2.read_text())
    assert obs["name"] == f"Kratos observed: {T}" and any(t.get("score") for t in obs["techniques"])
    assert (out2.stat().st_mode & 0o777) == 0o600
    capsys.readouterr()
    assert CLI.cmd_attack_layer(argparse.Namespace(data_dir=tmp_path, observed=False, target=None, out="-")) == 0
    assert json.loads(capsys.readouterr().out)["versions"]["layer"] == "4.5"


def test_attack_layer_is_a_cli_subcommand():
    from kratos.cli.app import build_parser

    args = build_parser().parse_args(["attack-layer", "--observed", "--target", "all", "--out", "-"])
    assert args.func.__name__ == "cmd_attack_layer" and args.observed and args.target == "all"


# -------------------------------------------------------------- what the model reads
def test_compact_for_model_shortens_labels_and_leaves_everything_else():
    from kratos.attack import compact_for_model

    result = {"result": {"findings": [dict(LABELLED), {"id": "NET-002", "attack": []}], "attack": "a string"}}
    out = compact_for_model(result)
    assert out["result"]["findings"][0]["attack"] == ["T1110.001 Password Guessing"]
    assert out["result"]["findings"][1]["attack"] == [] and out["result"]["attack"] == "a string"
    assert {k: v for k, v in out["result"]["findings"][0].items() if k != "attack"} == \
        {k: v for k, v in LABELLED.items() if k != "attack"}
    assert result["result"]["findings"][0]["attack"] == LABELLED["attack"]          # the input is not changed


def test_the_model_reads_compact_labels_and_the_transcript_keeps_full_ones(tmp_path, monkeypatch):
    from kratos.agent import loop as agent_loop
    from kratos.agent.tools import TOOL_REGISTRY

    for sub in ("scans", "logs", "context", "reports", "baseline"):
        (tmp_path / sub).mkdir()
    report = {"findings": [dict(LABELLED)], "count": 1, "missing_inputs": [], "input_errors": []}
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", lambda **kw: report)
    sent: list[str] = []
    script = [json.dumps({"reasoning": "r", "tool": "correlate_findings", "args": {}}),
              json.dumps({"reasoning": "r", "final_answer": "A password-guessing burst against SSH."})]

    def chat(system_prompt, user_prompt, max_tokens=None):
        sent.append(user_prompt)
        return script.pop(0) if script else script_final()

    def script_final():
        return json.dumps({"reasoning": "r", "final_answer": "done"})

    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("check the box", tmp_path, max_iters=4)
    prompt = sent[1]
    assert '"attack": ["T1110.001 Password Guessing"]' in prompt
    assert "attack.mitre.org" not in prompt and "TA0006" not in prompt
    step = [s for s in result["transcript"] if s.get("tool") == "correlate_findings"][0]
    assert step["observation"]["result"]["findings"][0]["attack"][0]["url"] == \
        "https://attack.mitre.org/techniques/T1110/001"
