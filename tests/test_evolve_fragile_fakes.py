"""A drafted /evolve test whose fake SSH layer reads the command text (seen live:
`if "ls" in script ... script.split("cat ")[-1]`) accepts only one way of writing the
command, so a correct tool failed every attempt. Such drafts are caught and redrafted."""
from __future__ import annotations

from kratos.agent import guided_evolve as G

_HEAD = '''TOOL_NAME = "enumerate_cron_jobs"
from unittest.mock import patch
from kratos.adapters.ssh_remote import SSHResult
'''

FRAGILE = _HEAD + '''
def test_x(registered_handler):
    def mock_run_remote_script(script):
        if "ls" in script:
            return SSHResult(ok=True, returncode=0, stdout="/etc/cron.d/a\\n", stderr="")
        path = script.split("cat ")[-1].strip()
        return SSHResult(ok=True, returncode=0, stdout=path, stderr="")
    with patch("kratos.adapters.ssh_remote.run_remote_script", side_effect=mock_run_remote_script):
        assert registered_handler()["system"] == []
'''

FIXED = _HEAD + '''
def test_x(registered_handler):
    out = "=== /etc/crontab ===\\n0 2 * * * root /usr/bin/backup.sh\\n"
    with patch("kratos.adapters.ssh_remote.run_remote_script",
               return_value=SSHResult(ok=True, returncode=0, stdout=out, stderr="")):
        assert registered_handler()["system"][0]["command"] == "/usr/bin/backup.sh"
'''

LIST_REPLIES = _HEAD + '''
def test_x(registered_handler):
    replies = [SSHResult(ok=True, returncode=0, stdout="a", stderr=""), SSHResult(ok=True, returncode=0, stdout="b", stderr="")]
    with patch("kratos.adapters.ssh_remote.run_remote_command", side_effect=replies):
        registered_handler()
    with patch("kratos.adapters.ssh_remote.run_remote_command", side_effect=lambda cmd: SSHResult(ok=True, returncode=0, stdout=cmd, stderr="")):
        registered_handler()
'''


def test_a_fake_that_reads_the_command_is_flagged():
    assert G.fragile_ssh_fakes(FRAGILE) == ["mock_run_remote_script"]
    assert G.fragile_ssh_fakes(FIXED) == []
    assert G.fragile_ssh_fakes(LIST_REPLIES) == ["a lambda"]          # the list is fine, the lambda isn't


def test_drafting_redrafts_once_and_keeps_the_good_version(monkeypatch):
    replies = iter([FRAGILE, FIXED])
    calls: list = []

    def fake_chat(system_prompt, user_prompt, max_tokens=None):
        calls.append(user_prompt)
        return next(replies)

    monkeypatch.setattr(G, "agent_chat", fake_chat)
    code = G._draft_evolve_harness(None, "enumerate_cron_jobs", "list cron jobs on the target")
    assert code.strip() == FIXED.strip() and len(calls) == 2
    assert "reads the command text" in calls[1]


def test_still_fragile_after_one_redraft_is_kept_with_a_note(monkeypatch):
    monkeypatch.setattr(G, "agent_chat", lambda **kw: FRAGILE)
    notes: list = []
    monkeypatch.setattr(G._console, "render_note", lambda console, text, **kw: notes.append(text))
    assert G._draft_evolve_harness(None, "enumerate_cron_jobs", "list cron jobs").strip() == FRAGILE.strip()
    assert notes and "depends on the exact command" in notes[0]
