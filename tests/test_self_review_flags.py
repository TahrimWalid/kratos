"""
Scripted tests for agent/self_review_flags.py's silent-item-drop-on-
subfetch-failure check. These tests target specifically that check, using
the two real bug shapes it was built to catch (list_net_services'
`if match:`, and a cron-jobs draft's `if cron_res.ok:`) plus negative
cases it must NOT flag.
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


# --- check f: a failed remote read reported as an empty result --------------
_RETURNS_EMPTY_ON_FAILURE = '''
from kratos.adapters import ssh_remote
def tool_x():
    result = ssh_remote.run_remote_command("ss -tlnp")
    if not result.ok or not result.stdout:
        return []
    return result.stdout.splitlines()
'''

_FALLS_THROUGH = '''
from kratos.adapters import ssh_remote
def tool_x():
    result = ssh_remote.run_remote_command("getent group sudo")
    users = []
    if result.ok and result.stdout:
        users = result.stdout.split(":")[3].split(",")
    return {"users": users}
'''

_HANDLES_FAILURE = '''
from kratos.adapters import ssh_remote
def tool_x():
    result = ssh_remote.run_remote_command("ss -tlnp")
    if not result.ok:
        return {"status": "error", "observation": result.stderr}
    if not result.stdout:
        return []
    return result.stdout.splitlines()
'''


def _failed_read_flags(src):
    return [f.category for f in scan_review_flags(src) if f.category.startswith("failed-read")]


def test_failed_read_returned_as_empty_is_flagged():
    assert _failed_read_flags(_RETURNS_EMPTY_ON_FAILURE) == ["failed-read-returned-as-empty"]


def test_failed_read_falling_through_is_flagged():
    assert _failed_read_flags(_FALLS_THROUGH) == ["failed-read-falls-through-as-empty"]


def test_an_explicit_error_return_is_not_flagged():
    # "no output" (a successful read that found nothing) may legitimately be empty
    assert _failed_read_flags(_HANDLES_FAILURE) == []


_CRON = '''
from kratos.adapters import ssh_remote
def tool_x():
    script = """
    for f in /var/spool/cron/crontabs/*; do
        sudo -n cat "$f" || echo "[UNREADABLE]"
    done
    """
    return ssh_remote.run_remote_script(script)
'''


def test_flags_a_folder_listed_without_sudo_when_files_need_it():
    """Seen live (demo pass 5): the glob over a root-only folder came back empty."""
    flags = [f for f in scan_review_flags(_CRON) if f.category == "folder-listed-without-sudo"]
    assert len(flags) == 1 and "/var/spool/cron/crontabs" in flags[0].message


def test_no_listing_flag_when_the_listing_uses_sudo_or_nothing_needs_it():
    with_sudo = _CRON.replace("for f in /var/spool/cron/crontabs/*;",
                              "for f in $(sudo -n find /var/spool/cron/crontabs -type f);")
    assert not [f for f in scan_review_flags(with_sudo) if f.category == "folder-listed-without-sudo"]
    plain = _CRON.replace('sudo -n cat "$f"', 'cat "$f"')
    assert not [f for f in scan_review_flags(plain) if f.category == "folder-listed-without-sudo"]


def test_every_flag_category_has_a_plain_explanation():
    import inspect
    from kratos.agent import self_review_flags as R
    used = set(__import__("re").findall(r'ReviewFlag\(\s*"([a-z-]+)"', inspect.getsource(R)))
    assert used and used <= set(R._PLAIN_GLOSS)


def test_plain_display_groups_repeated_warnings():
    from kratos.agent.self_review_flags import ReviewFlag, format_review_flags_plain

    msg = "This branch affects which data is included"
    flags = [ReviewFlag("inclusion-affecting-branch", msg, n) for n in (39, 43, 46)]
    flags.append(ReviewFlag("description-coverage", "3 branches", None))
    text = format_review_flags_plain(flags)
    assert text.count("A decision inside a loop") == 1 and "(lines 39, 43, 46)" in text
    assert text.count("technical detail") == 2
