"""Edge-case coverage for the A2 Tier-1 preset store (agent/presets.py).

No TUI here -- pure store/validation logic: name slugging/validation (incl. path
traversal + reserved words), round-trip serialization correctness against the
stdlib TOML parser (adversarial goal strings), corrupt-file resilience, and the
forward-compat contract that a pipeline/unknown-kind preset is parsed and listed
but not runnable.
"""
from __future__ import annotations

import tomllib

import pytest

from kratos.agent import presets as P
from kratos.agent.presets import PresetError


# --------------------------------------------------------------------------- #
# Name slugging + validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expected", [
    ("weekly-audit", "weekly-audit"),
    ("Weekly Audit", "weekly-audit"),          # spaces + case
    ("  SSH   Review  ", "ssh-review"),        # trim + collapse
    ("my_preset", "my_preset"),                # underscore kept
    ("a!!!b@@@c", "a-b-c"),                     # symbols -> hyphen, collapsed
    ("../etc/passwd", "etc-passwd"),           # traversal neutralized
    ("/absolute/path", "absolute-path"),
    ("..", ""),                                # pure traversal -> empty
    ("...", ""),
    ("café-audit", "caf-audit"),               # non-ascii dropped
])
def test_slugify(raw, expected):
    assert P.slugify_preset_name(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "!!!", "..", "///"])
def test_validate_rejects_empty_after_slug(raw):
    ok, _canon, err = P.validate_preset_name(raw)
    assert ok is False and err


@pytest.mark.parametrize("reserved", ["run", "list", "new", "delete", "help", "preset", "Show"])
def test_validate_rejects_reserved(reserved):
    ok, _canon, err = P.validate_preset_name(reserved)
    assert ok is False and "reserved" in err.lower()


def test_validate_rejects_too_long():
    ok, _canon, err = P.validate_preset_name("x" * 65)
    assert ok is False and "too long" in err.lower()


def test_validate_accepts_normal():
    ok, canon, err = P.validate_preset_name("Weekly Audit")
    assert ok is True and canon == "weekly-audit" and err is None


# --------------------------------------------------------------------------- #
# Serializer round-trip correctness (the whole reason a hand-written writer is OK)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("goal", [
    "simple goal",
    'goal with "double quotes"',
    "goal with 'single quotes'",
    "goal with\nnewline and\ttab",
    r"goal with backslash \ and \n literal",
    'triple """ quotes """ inside',
    "unicode: café ☕ 日本語 — em-dash",
    "control chars: \x00\x01\x1f\x7f",
    "",  # empty allowed here at the serializer level (save_preset guards it separately)
])
def test_serializer_round_trips_through_tomllib(goal):
    text = P._dump_preset_toml(name="n", kind="goal", target="10.0.0.1",
                               goal=goal, created_at="2026-09-08T00:00:00Z")
    parsed = tomllib.loads(text)
    assert parsed["goal"] == goal
    assert parsed["name"] == "n"
    assert parsed["kind"] == "goal"
    assert parsed["target"] == "10.0.0.1"


# --------------------------------------------------------------------------- #
# save / load / list / delete
# --------------------------------------------------------------------------- #
def test_save_and_load_round_trip(tmp_path):
    saved = P.save_preset(tmp_path, name="Weekly Audit",
                          goal="full SSH + firewall review", target="10.136.28.168")
    assert saved.name == "weekly-audit"
    assert saved.kind == "goal"
    assert saved.target == "10.136.28.168"
    assert saved.is_runnable_tier1 is True

    loaded = P.load_preset(tmp_path, "weekly-audit")
    assert loaded is not None
    assert loaded.goal == "full SSH + firewall review"
    # Case-insensitive lookup (canonical == lowercase slug).
    assert P.load_preset(tmp_path, "WEEKLY AUDIT") is not None


def test_save_preserves_adversarial_goal(tmp_path):
    goal = 'audit "the target"\nwith\ttabs and \\ backslash and café'
    P.save_preset(tmp_path, name="tricky", goal=goal)
    assert P.load_preset(tmp_path, "tricky").goal == goal.strip()


def test_save_strips_goal_whitespace(tmp_path):
    P.save_preset(tmp_path, name="p", goal="   padded goal   ")
    assert P.load_preset(tmp_path, "p").goal == "padded goal"


def test_save_rejects_empty_goal(tmp_path):
    with pytest.raises(PresetError):
        P.save_preset(tmp_path, name="p", goal="   ")


def test_save_rejects_invalid_name(tmp_path):
    with pytest.raises(PresetError):
        P.save_preset(tmp_path, name="..", goal="something")


def test_save_without_target_omits_it(tmp_path):
    P.save_preset(tmp_path, name="p", goal="g")
    loaded = P.load_preset(tmp_path, "p")
    assert loaded.target is None


def test_list_empty_when_no_dir(tmp_path):
    presets, errors = P.list_presets(tmp_path)
    assert presets == [] and errors == []


def test_list_sorted_and_multiple(tmp_path):
    P.save_preset(tmp_path, name="zeta", goal="z")
    P.save_preset(tmp_path, name="alpha", goal="a")
    presets, errors = P.list_presets(tmp_path)
    assert [p.name for p in presets] == ["alpha", "zeta"]
    assert errors == []


def test_overwrite_keeps_siblings(tmp_path):
    P.save_preset(tmp_path, name="a", goal="first")
    P.save_preset(tmp_path, name="b", goal="keep me")
    P.save_preset(tmp_path, name="a", goal="second")  # overwrite a
    assert P.load_preset(tmp_path, "a").goal == "second"
    assert P.load_preset(tmp_path, "b").goal == "keep me"  # b untouched


def test_load_missing_returns_none(tmp_path):
    assert P.load_preset(tmp_path, "nope") is None


def test_load_invalid_name_returns_none(tmp_path):
    assert P.load_preset(tmp_path, "..") is None


def test_load_corrupt_raises(tmp_path):
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    (d / "broken.toml").write_text("this = = not valid toml", encoding="utf-8")
    with pytest.raises(PresetError):
        P.load_preset(tmp_path, "broken")


def test_list_survives_a_corrupt_file(tmp_path):
    P.save_preset(tmp_path, name="good", goal="g")
    d = P.presets_dir(tmp_path)
    (d / "bad.toml").write_text("= broken", encoding="utf-8")
    presets, errors = P.list_presets(tmp_path)
    assert [p.name for p in presets] == ["good"]     # good one still listed
    assert any("bad.toml" in name for name, _ in errors)  # bad one surfaced, not crashed


def test_delete(tmp_path):
    P.save_preset(tmp_path, name="p", goal="g")
    assert P.preset_exists(tmp_path, "p") is True
    assert P.delete_preset(tmp_path, "p") is True
    assert P.preset_exists(tmp_path, "p") is False
    assert P.delete_preset(tmp_path, "p") is False       # already gone
    assert P.delete_preset(tmp_path, "..") is False       # invalid name


# --------------------------------------------------------------------------- #
# Tier 2: a valid linear pipeline preset IS runnable (but never as a "goal").
# --------------------------------------------------------------------------- #
def test_valid_pipeline_preset_is_runnable_pipeline_not_tier1(tmp_path):
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    (d / "pipe.toml").write_text(
        'name = "pipe"\nkind = "pipeline"\n[[steps]]\ntool = "run_nmap_scan"\n',
        encoding="utf-8",
    )
    loaded = P.load_preset(tmp_path, "pipe")
    assert loaded is not None
    assert loaded.kind == "pipeline"
    assert loaded.is_runnable_tier1 is False       # never a "goal" preset
    assert loaded.is_runnable_pipeline is True      # but runnable as a pipeline
    assert loaded.is_runnable is True
    assert loaded.unsupported_reason is None
    assert [s["tool"] for s in loaded.steps] == ["run_nmap_scan"]
    # And it must appear in a normal listing, not crash it.
    presets, errors = P.list_presets(tmp_path)
    assert "pipe" in [p.name for p in presets] and errors == []


def test_unknown_kind_treated_as_unsupported(tmp_path):
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    (d / "weird.toml").write_text('name = "weird"\nkind = "from-the-future"\ngoal = "x"\n',
                                  encoding="utf-8")
    loaded = P.load_preset(tmp_path, "weird")
    assert loaded.is_runnable_tier1 is False
    assert loaded.unsupported_reason is not None


def test_missing_kind_defaults_to_goal(tmp_path):
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    (d / "minimal.toml").write_text('goal = "just a goal"\n', encoding="utf-8")
    loaded = P.load_preset(tmp_path, "minimal")
    assert loaded.kind == "goal"
    assert loaded.name == "minimal"  # fell back to filename stem
    assert loaded.is_runnable_tier1 is True


# --------------------------------------------------------------------------- #
# A2 Tier 2 -- pipeline body parse & validation (Piece A)
# --------------------------------------------------------------------------- #
def test_parse_pipeline_normalizes_valid_steps():
    raw = [
        {"tool": "run_nmap_scan", "required": True, "label": "map ports"},
        {"tool": "correlate_findings"},  # required defaults True
    ]
    parsed = P.parse_pipeline(raw)
    assert parsed.errors == []
    assert not parsed.has_conditions
    assert [s["tool"] for s in parsed.steps] == ["run_nmap_scan", "correlate_findings"]
    assert parsed.steps[0]["required"] is True and parsed.steps[0]["label"] == "map ports"
    assert parsed.steps[1]["required"] is True  # defaulted


def test_parse_pipeline_empty_and_non_list_are_errors():
    assert P.parse_pipeline([]).errors
    assert P.parse_pipeline(None).errors
    assert P.parse_pipeline("nope").errors


@pytest.mark.parametrize("bad,frag", [
    ({"required": True}, "no `tool`"),                       # missing tool
    ("not-a-table", "not a table"),                           # step isn't a table
    ({"tool": "run_nmap_scan", "args": [1, 2]}, "must be a table"),  # args not a table
    ({"tool": "run_nmap_scan", "when": 5}, "must be a string"),      # when not a string
])
def test_parse_pipeline_malformed_step_is_error(bad, frag):
    parsed = P.parse_pipeline([bad])
    assert any(frag in e for e in parsed.errors), parsed.errors


def test_parse_pipeline_strips_data_dir_and_nonloopback_target_with_warning():
    parsed = P.parse_pipeline([
        {"tool": "run_nmap_scan", "args": {"data_dir": "/x", "target": "8.8.8.8", "foo": "bar"}},
    ])
    step = parsed.steps[0]
    assert "data_dir" not in step["args"] and "target" not in step["args"]
    assert step["args"] == {"foo": "bar"}
    assert any("data_dir" in w for w in parsed.warnings)
    assert any("target" in w for w in parsed.warnings)


def test_parse_pipeline_keeps_loopback_self_target():
    parsed = P.parse_pipeline([
        {"tool": "run_nmap_scan", "args": {"target": "127.0.0.1"}},
    ])
    assert parsed.steps[0]["args"]["target"] == "127.0.0.1"


def test_parse_pipeline_unknown_tool_is_warning_only_with_registry():
    from kratos.agent.tools import TOOL_REGISTRY
    parsed = P.parse_pipeline([{"tool": "no_such_tool"}], registry=TOOL_REGISTRY)
    assert parsed.errors == []                       # unknown tool must NOT block save
    assert any("no_such_tool" in w for w in parsed.warnings)


def test_parse_pipeline_unknown_arg_name_is_warning():
    from kratos.agent.tools import TOOL_REGISTRY
    parsed = P.parse_pipeline(
        [{"tool": "run_nmap_scan", "args": {"bogus_param": 1}}], registry=TOOL_REGISTRY)
    assert parsed.errors == []
    assert any("bogus_param" in w for w in parsed.warnings)


def test_parse_pipeline_when_flags_conditions():
    parsed = P.parse_pipeline([
        {"tool": "run_nmap_scan"},
        {"tool": "run_config_audit", "when": "has_finding(min_severity='high')"},
    ])
    assert parsed.has_conditions is True
    assert parsed.steps[1]["when"] == "has_finding(min_severity='high')"


# --------------------------------------------------------------------------- #
# Runnability verdicts for pipeline presets
# --------------------------------------------------------------------------- #
def test_pipeline_with_valid_when_is_runnable(tmp_path):
    # Slice 4: a valid bounded `when` is now RUNNABLE (has_conditions is
    # informational only, no longer a blocker).
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    (d / "cond.toml").write_text(
        'name = "cond"\nkind = "pipeline"\n'
        '[[steps]]\ntool = "run_nmap_scan"\n'
        '[[steps]]\ntool = "run_config_audit"\nwhen = "has_finding(min_severity=\'high\')"\n',
        encoding="utf-8")
    loaded = P.load_preset(tmp_path, "cond")
    assert loaded.has_conditions is True
    assert loaded.is_runnable_pipeline is True and loaded.is_runnable is True
    assert loaded.unsupported_reason is None
    assert loaded.steps[1]["when"] == "has_finding(min_severity='high')"
    # Round-trips through save too.
    presets, errors = P.list_presets(tmp_path)
    assert "cond" in [p.name for p in presets] and errors == []


def test_pipeline_with_invalid_when_is_rejected(tmp_path):
    # An unrecognized/dangerous predicate is a STRUCTURAL error -> not runnable,
    # but still parsed + listed (never crashes listing).
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    (d / "bad.toml").write_text(
        'name = "bad"\nkind = "pipeline"\n'
        '[[steps]]\ntool = "run_nmap_scan"\n'
        '[[steps]]\ntool = "run_config_audit"\nwhen = "__import__(\'os\')"\n',
        encoding="utf-8")
    loaded = P.load_preset(tmp_path, "bad")
    assert loaded.is_runnable_pipeline is False
    assert loaded.pipeline_errors and any("condition" in e for e in loaded.pipeline_errors)
    presets, errors = P.list_presets(tmp_path)
    assert "bad" in [p.name for p in presets] and errors == []


def test_save_pipeline_rejects_invalid_when(tmp_path):
    with pytest.raises(PresetError):
        P.save_preset(tmp_path, name="w", kind="pipeline", steps=[
            {"tool": "run_nmap_scan"},
            {"tool": "run_config_audit", "when": "os.system('x')"},
        ])


def test_save_pipeline_with_valid_when_round_trips(tmp_path):
    saved = P.save_preset(tmp_path, name="w2", kind="pipeline", steps=[
        {"tool": "run_nmap_scan", "required": True},
        {"tool": "run_vuln_scan", "required": False, "when": "finding_count >= 2"},
        {"tool": "correlate_findings", "required": True},
    ])
    assert saved.is_runnable_pipeline
    reloaded = P.load_preset(tmp_path, "w2")
    assert reloaded.steps[1]["when"] == "finding_count >= 2"


def test_pipeline_with_structural_error_lists_but_not_runnable(tmp_path):
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    # A step with no tool -> structural parse error, but the file is valid TOML.
    (d / "broken.toml").write_text(
        'name = "broken"\nkind = "pipeline"\n[[steps]]\nlabel = "oops, no tool"\n',
        encoding="utf-8")
    loaded = P.load_preset(tmp_path, "broken")
    assert loaded.is_runnable is False
    assert loaded.pipeline_errors
    assert "invalid" in loaded.unsupported_reason.lower()
    presets, errors = P.list_presets(tmp_path)
    assert "broken" in [p.name for p in presets] and errors == []  # TOML-valid -> lists


# --------------------------------------------------------------------------- #
# Saving pipeline presets (round-trip + rejection + warnings)
# --------------------------------------------------------------------------- #
def test_save_pipeline_round_trips(tmp_path):
    steps = [
        {"tool": "run_nmap_scan", "required": True, "label": "ports"},
        {"tool": "check_ip_reputation", "required": False, "args": {"ip": "1.2.3.4"}},
        {"tool": "correlate_findings", "required": True},
    ]
    saved = P.save_preset(tmp_path, name="Nightly Sweep", kind="pipeline", steps=steps)
    assert saved.kind == "pipeline" and saved.is_runnable_pipeline
    reloaded = P.load_preset(tmp_path, "nightly-sweep")
    assert [s["tool"] for s in reloaded.steps] == [s["tool"] for s in steps]
    assert reloaded.steps[1]["args"] == {"ip": "1.2.3.4"}
    assert reloaded.steps[1]["required"] is False
    # The written file is valid TOML the stdlib parser reads back identically.
    data = tomllib.loads(saved.path.read_text(encoding="utf-8"))
    assert data["kind"] == "pipeline" and len(data["steps"]) == 3


def test_save_pipeline_serializes_arg_types_round_trip(tmp_path):
    # bool / int / str args must survive the round trip through the serializer.
    steps = [{"tool": "run_nmap_scan", "args": {"flag": True, "n": 7, "s": 'a "quoted" \\ str'}}]
    saved = P.save_preset(tmp_path, name="typed", kind="pipeline", steps=steps)
    data = tomllib.loads(saved.path.read_text(encoding="utf-8"))
    assert data["steps"][0]["args"] == {"flag": True, "n": 7, "s": 'a "quoted" \\ str'}


def test_save_pipeline_rejects_structural_error(tmp_path):
    with pytest.raises(PresetError):
        P.save_preset(tmp_path, name="bad", kind="pipeline", steps=[{"label": "no tool"}])
    with pytest.raises(PresetError):
        P.save_preset(tmp_path, name="empty", kind="pipeline", steps=[])


def test_save_pipeline_returns_warnings_but_saves(tmp_path):
    preset, warnings = P.save_preset_with_warnings(
        tmp_path, name="warny", kind="pipeline",
        steps=[{"tool": "does_not_exist"}, {"tool": "run_nmap_scan", "args": {"data_dir": "/x"}}])
    assert preset.is_runnable_pipeline
    assert any("does_not_exist" in w for w in warnings)
    assert any("data_dir" in w for w in warnings)


def test_save_unknown_kind_rejected(tmp_path):
    with pytest.raises(PresetError):
        P.save_preset(tmp_path, name="weird", kind="banana", steps=[{"tool": "run_nmap_scan"}])


# --------------------------------------------------------------------------- #
# Files-first scaffold (Piece F bridge)
# --------------------------------------------------------------------------- #
def test_scaffold_writes_valid_runnable_pipeline(tmp_path):
    path = P.write_pipeline_scaffold(tmp_path, "My Template")
    assert path.exists() and path.name == "my-template.toml"
    loaded = P.load_preset(tmp_path, "my-template")
    assert loaded.kind == "pipeline"
    assert loaded.is_runnable_pipeline is True          # a runnable starter, not a stub
    assert [s["tool"] for s in loaded.steps] == ["run_nmap_scan", "correlate_findings"]


def test_scaffold_rejects_bad_name(tmp_path):
    with pytest.raises(PresetError):
        P.write_pipeline_scaffold(tmp_path, "..")


def test_parse_pipeline_warns_when_not_ending_in_correlate():
    # Ends in correlate -> no such warning.
    ok = P.parse_pipeline([{"tool": "run_nmap_scan"}, {"tool": "correlate_findings"}])
    assert not any("correlate_findings" in w for w in ok.warnings)
    # Doesn't -> advisory warning (but still saveable/runnable).
    no = P.parse_pipeline([{"tool": "run_nmap_scan"}])
    assert any("correlate_findings" in w for w in no.warnings)
    assert no.errors == []


# --------------------------------------------------------------------------- #
# Piece H -- run-history metadata (sidecar)
# --------------------------------------------------------------------------- #
def test_record_and_read_run_meta(tmp_path):
    P.save_preset(tmp_path, name="p", goal="g")
    assert P.preset_run_meta(tmp_path) == {}
    P.record_preset_run(tmp_path, "p")
    meta = P.preset_run_meta(tmp_path)
    assert "p" in meta and meta["p"]["last_run_at"] and meta["p"]["last_status"] == "ran"
    # The sidecar is separate from the preset TOML (never rewrites it).
    assert (P.presets_dir(tmp_path) / ".runs.json").exists()
    # A run entry is not a preset (globbed by *.toml) -- listing is unaffected.
    presets, errors = P.list_presets(tmp_path)
    assert [x.name for x in presets] == ["p"] and errors == []


def test_run_meta_survives_corrupt_sidecar(tmp_path):
    P.save_preset(tmp_path, name="p", goal="g")
    (P.presets_dir(tmp_path) / ".runs.json").write_text("{ broken", encoding="utf-8")
    assert P.preset_run_meta(tmp_path) == {}          # reads as empty, never raises
    P.record_preset_run(tmp_path, "p")                # overwrites cleanly
    assert "p" in P.preset_run_meta(tmp_path)


def test_delete_prunes_run_meta(tmp_path):
    P.save_preset(tmp_path, name="p", goal="g")
    P.record_preset_run(tmp_path, "p")
    P.delete_preset(tmp_path, "p")
    assert "p" not in P.preset_run_meta(tmp_path)


# --------------------------------------------------------------------------- #
# Piece H -- import
# --------------------------------------------------------------------------- #
def test_import_goal_preset(tmp_path):
    src = tmp_path / "shared.toml"
    src.write_text('name = "Shared Goal"\nkind = "goal"\ngoal = "review ssh hardening"\n',
                   encoding="utf-8")
    preset, warnings = P.import_preset_file(tmp_path, src)
    assert preset.name == "shared-goal" and preset.goal == "review ssh hardening"
    assert P.preset_exists(tmp_path, "shared-goal")


def test_import_pipeline_preset(tmp_path):
    src = tmp_path / "sweep.toml"
    src.write_text('name = "sweep"\nkind = "pipeline"\n'
                   '[[steps]]\ntool = "run_nmap_scan"\n'
                   '[[steps]]\ntool = "correlate_findings"\n', encoding="utf-8")
    preset, _w = P.import_preset_file(tmp_path, src)
    assert preset.is_runnable_pipeline
    assert [s["tool"] for s in preset.steps] == ["run_nmap_scan", "correlate_findings"]


def test_import_missing_file_raises(tmp_path):
    with pytest.raises(PresetError):
        P.import_preset_file(tmp_path, tmp_path / "nope.toml")


def test_import_broken_pipeline_rejected(tmp_path):
    src = tmp_path / "bad.toml"
    src.write_text('name = "bad"\nkind = "pipeline"\n[[steps]]\nlabel = "no tool"\n',
                   encoding="utf-8")
    with pytest.raises(PresetError):
        P.import_preset_file(tmp_path, src)


def test_import_existing_requires_overwrite(tmp_path):
    P.save_preset(tmp_path, name="dup", goal="original")
    src = tmp_path / "dup.toml"
    src.write_text('name = "dup"\nkind = "goal"\ngoal = "new"\n', encoding="utf-8")
    with pytest.raises(PresetError):
        P.import_preset_file(tmp_path, src)                  # exists, no overwrite
    preset, _w = P.import_preset_file(tmp_path, src, overwrite=True)
    assert preset.goal == "new"


def test_import_unknown_kind_rejected(tmp_path):
    src = tmp_path / "weird.toml"
    src.write_text('name = "weird"\nkind = "from-the-future"\ngoal = "x"\n', encoding="utf-8")
    with pytest.raises(PresetError):
        P.import_preset_file(tmp_path, src)


# --------------------------------------------------------------------------- #
# A2 Piece C -- step-output threading (save/round-trip/reject)
# --------------------------------------------------------------------------- #
def test_save_pipeline_with_reference_round_trips(tmp_path):
    saved = P.save_preset(tmp_path, name="thread", kind="pipeline", steps=[
        {"tool": "correlate_findings", "label": "correlate", "required": True},
        {"tool": "check_ip_reputation", "required": False,
         "args": {"ip": {"from": "correlate", "field": "top_source_ip"}}},
    ])
    assert saved.is_runnable_pipeline
    reloaded = P.load_preset(tmp_path, "thread")
    assert reloaded.steps[1]["args"]["ip"] == {"from": "correlate", "field": "top_source_ip"}
    # The nested reference table is valid TOML read back identically by tomllib.
    data = tomllib.loads(saved.path.read_text(encoding="utf-8"))
    assert data["steps"][1]["args"]["ip"] == {"from": "correlate", "field": "top_source_ip"}


def test_save_pipeline_rejects_forward_reference(tmp_path):
    with pytest.raises(PresetError):
        P.save_preset(tmp_path, name="fwd", kind="pipeline", steps=[
            {"tool": "check_ip_reputation",
             "args": {"ip": {"from": "correlate", "field": "top_source_ip"}}},
            {"tool": "correlate_findings", "label": "correlate"},
        ])


def test_save_pipeline_rejects_type_mismatched_reference(tmp_path):
    with pytest.raises(PresetError):
        P.save_preset(tmp_path, name="tm", kind="pipeline", steps=[
            {"tool": "correlate_findings", "label": "c"},
            {"tool": "check_ip_reputation", "args": {"ip": {"from": "c", "field": "finding_count"}}},
        ])


def test_reference_pipeline_lists_when_broken(tmp_path):
    # A hand-edited file with a bad reference is TOML-valid -> lists, non-runnable.
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    (d / "bad.toml").write_text(
        'name = "bad"\nkind = "pipeline"\n'
        '[[steps]]\ntool = "check_ip_reputation"\n'
        'args = { ip = { from = "nope", field = "top_source_ip" } }\n',
        encoding="utf-8")
    loaded = P.load_preset(tmp_path, "bad")
    assert loaded.is_runnable_pipeline is False and loaded.pipeline_errors
    presets, errors = P.list_presets(tmp_path)
    assert "bad" in [p.name for p in presets] and errors == []


def test_save_generated_pipeline_round_trips(tmp_path):
    saved = P.save_preset(tmp_path, name="drafted", kind="pipeline", generated=True, steps=[
        {"tool": "run_nmap_scan"}, {"tool": "correlate_findings"}])
    assert saved.generated is True
    reloaded = P.load_preset(tmp_path, "drafted")
    assert reloaded.generated is True and reloaded.is_runnable_pipeline
    data = tomllib.loads(saved.path.read_text(encoding="utf-8"))
    assert data.get("generated") is True
    # A hand-saved (non-generated) preset defaults to generated=False.
    plain = P.save_preset(tmp_path, name="hand", kind="pipeline",
                          steps=[{"tool": "run_nmap_scan"}, {"tool": "correlate_findings"}])
    assert plain.generated is False
    assert "generated" not in tomllib.loads(plain.path.read_text(encoding="utf-8"))
