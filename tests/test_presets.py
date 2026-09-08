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
# Forward-compat: pipeline / unknown-kind presets parse + list but don't run
# --------------------------------------------------------------------------- #
def test_pipeline_preset_parsed_but_not_runnable(tmp_path):
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    (d / "pipe.toml").write_text(
        'name = "pipe"\nkind = "pipeline"\n[[steps]]\ntool = "run_nmap_scan"\n',
        encoding="utf-8",
    )
    loaded = P.load_preset(tmp_path, "pipe")
    assert loaded is not None
    assert loaded.kind == "pipeline"
    assert loaded.is_runnable_tier1 is False
    assert "pipeline" in loaded.unsupported_reason.lower()
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
