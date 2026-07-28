"""
Scripted tests for agent/self_review_flags.py's newest check (2026-07-28):
silent-item-drop-on-subfetch-failure. No existing test file covered this
module before -- prior verification was real-candidate-only, per CLAUDE.md.
These tests target specifically the new check, using the two real bug
shapes it was built to catch (list_net_services' `if match:`, and a
cron-jobs draft's `if cron_res.ok:`) plus negative cases it must NOT flag.
"""
from __future__ import annotations

from kratos.agent.self_review_flags import scan_review_flags

_HEADER = (
    "from kratos.agent.tools import register_tool\n"
    "from typing import Any\n\n"
    '@register_tool(name="t", description="does a thing", parameters={})\n'
)


def _flag_categories(source: str) -> set[str]:
    return {f.category for f in scan_review_flags(_HEADER + source)}


def test_flags_regex_match_silent_drop():
    # The real list_net_services shape, pre-fix.
    source = (
        "def tool_t() -> dict[str, Any]:\n"
        "    services = []\n"
        "    for line in lines:\n"
        "        match = pattern.match(line)\n"
        "        if match:\n"
        "            services.append({'port': 1})\n"
        "    return {'services': services}\n"
    )
    assert "silent-item-drop-on-subfetch-failure" in _flag_categories(source)


def test_flags_attribute_ok_check_silent_drop():
    # The real enumerate_system_cron_jobs draft shape.
    source = (
        "def tool_t() -> dict[str, Any]:\n"
        "    cron_jobs = {}\n"
        "    for user in users:\n"
        "        cron_res = ssh_remote.run_remote_command(f'crontab -l -u {user}')\n"
        "        if cron_res.ok:\n"
        "            cron_jobs[user] = cron_res.stdout\n"
        "    return {'cron_jobs': cron_jobs}\n"
    )
    assert "silent-item-drop-on-subfetch-failure" in _flag_categories(source)


def test_no_flag_when_else_also_includes_the_item():
    # The real, fixed shape: always append, only the sub-fields become None.
    source = (
        "def tool_t() -> dict[str, Any]:\n"
        "    services = []\n"
        "    for line in lines:\n"
        "        match = pattern.match(line)\n"
        "        if match:\n"
        "            services.append({'process': match.group(1)})\n"
        "        else:\n"
        "            services.append({'process': None})\n"
        "    return {'services': services}\n"
    )
    assert "silent-item-drop-on-subfetch-failure" not in _flag_categories(source)


def test_no_flag_for_deliberate_boolean_filter_not_from_a_call():
    # A genuine content filter (is_risky_port is a boolean expression, not a
    # call result) -- not the bug shape, must not be flagged by this check.
    source = (
        "def tool_t() -> dict[str, Any]:\n"
        "    results = []\n"
        "    for port in ports:\n"
        "        is_risky_port = port in RISKY_PORTS\n"
        "        if is_risky_port:\n"
        "            results.append(port)\n"
        "    return {'results': results}\n"
    )
    assert "silent-item-drop-on-subfetch-failure" not in _flag_categories(source)


def test_no_flag_outside_a_loop():
    # Same `if x:`-after-a-call shape, but not inside a for/while loop --
    # this check is scoped to per-item loop drops specifically.
    source = (
        "def tool_t() -> dict[str, Any]:\n"
        "    result = ssh_remote.run_remote_command('whoami')\n"
        "    output = []\n"
        "    if result.ok:\n"
        "        output.append(result.stdout)\n"
        "    return {'output': output}\n"
    )
    assert "silent-item-drop-on-subfetch-failure" not in _flag_categories(source)


def test_no_flag_on_compound_boolop_test():
    # Deliberately conservative: a compound test (`x and y`) is left
    # unflagged rather than guessing which operand is the relevant one.
    source = (
        "def tool_t() -> dict[str, Any]:\n"
        "    results = []\n"
        "    for line in lines:\n"
        "        match = pattern.match(line)\n"
        "        if match and len(line) > 0:\n"
        "            results.append(match.group(0))\n"
        "    return {'results': results}\n"
    )
    assert "silent-item-drop-on-subfetch-failure" not in _flag_categories(source)
