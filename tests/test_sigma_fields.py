"""Sigma -> ECS mapping covers every field real SigmaHQ Linux rules use (spec §5.10).

The rules under tests/fixtures/sigma/ are SigmaHQ's, DRL 1.1 (see the LICENSE
there). They're loaded with pySigma; full rule evaluation is C.1, not here.
"""
from __future__ import annotations

from pathlib import Path

import pytest

sigma_collection = pytest.importorskip("sigma.collection")
from sigma.rule import SigmaDetection  # noqa: E402

from kratos.events import fields as F  # noqa: E402
from kratos.events import sigma_fields as SF  # noqa: E402

RULES = sorted((Path(__file__).parent / "fixtures" / "sigma").glob("*.yml"))


def _items(det):
    for d in det.detection_items:
        if isinstance(d, SigmaDetection):
            yield from _items(d)
        else:
            yield d


def _rules():
    for path in RULES:
        for rule in sigma_collection.SigmaCollection.from_yaml(path.read_text(encoding="utf-8")).rules:
            yield path.name, rule


def _fields(rule) -> set[str]:
    return {it.field or SF.KEYWORDS for det in rule.detection.detections.values() for it in _items(det)}


def test_enough_real_rules_vendored_with_attribution():
    assert len(RULES) >= 10
    assert (RULES[0].parent / "LICENSE").read_text().startswith("# Detection Rule License (DRL) 1.1")
    for path in RULES:
        head = path.read_text(encoding="utf-8")
        assert head.startswith("# From SigmaHQ (https://github.com/SigmaHQ/sigma), rules/linux/")
        assert "\nid: " in head and "\nauthor: " in head


def test_every_referenced_field_is_mapped_or_explained():
    seen: set[str] = set()
    for name, rule in _rules():
        for field in _fields(rule):
            seen.add(field)
            assert field in SF.SIGMA_TO_ECS or field in SF.UNMAPPED, f"{name}: Sigma field {field!r} unaccounted for"
    # The rules exercise both mapped and unmapped fields.
    assert {"keywords", "Image", "CommandLine", "User"} <= seen and {"ParentImage", "CurrentDirectory"} <= seen


def test_every_rule_logsource_is_fed_or_explained():
    for name, rule in _rules():
        ls = rule.logsource
        key = (ls.product, ls.service, ls.category)
        assert key in SF.LOGSOURCES or key in SF.UNSUPPORTED, f"{name}: logsource {key} unaccounted for"


def test_mapped_targets_are_fields_events_carry():
    for sigma, ecs in SF.SIGMA_TO_ECS.items():
        assert ecs in F.BY_NAME, f"{sigma} -> {ecs}, which events don't have"
    for dataset_list in SF.LOGSOURCES.values():
        assert set(dataset_list) <= {"kratos.auth", "kratos.journal", "kratos.privileged_accounts"}


def test_the_required_process_creation_fields_are_all_accounted_for():
    for f in ("Image", "CommandLine", "ParentImage", "ProcessId", "ParentProcessId", "User", "CurrentDirectory"):
        assert f in SF.SIGMA_TO_ECS or f in SF.UNMAPPED
    assert not set(SF.SIGMA_TO_ECS) & set(SF.UNMAPPED)
    assert all(reason.strip() for reason in [*SF.UNMAPPED.values(), *SF.UNSUPPORTED.values()])
