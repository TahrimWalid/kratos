"""The write step names the ssh_remote call the test fakes and rejects a candidate that
reads the target through a different one. Seen live (demo pass 3): the drafted test faked
run_remote_command, the candidate called run_remote_script, the sandbox test failed on a
real SSH attempt, and the retry came back byte-identical -- the loop stalled."""
from __future__ import annotations

from pathlib import Path

from kratos.agent import self_write as SW

HARNESS = '''
from unittest.mock import patch
from kratos.adapters import ssh_remote
def test_x(registered_handler):
    with patch("kratos.adapters.ssh_remote.run_remote_command", return_value=None):
        registered_handler()
'''

_TOOL = '''from kratos.agent.tools import register_tool
from kratos.adapters import ssh_remote

@register_tool(name="list_cron", description="d", parameters={{}})
def tool_list_cron():
    result = ssh_remote.{fn}("cat /etc/crontab")
    return {{"status": "ok"}}
'''


def test_reads_the_fake_from_both_patch_forms():
    assert SW._faked_ssh_calls(HARNESS) == {"run_remote_command"}
    obj = "from unittest.mock import patch\nfrom kratos.adapters import ssh_remote\n" \
          "patch.object(ssh_remote, 'run_remote_script', return_value=None)\n"
    assert SW._faked_ssh_calls(obj) == {"run_remote_script"}
    assert SW._faked_ssh_calls("def broken(:") == set()


def test_unfaked_call_is_a_problem_and_a_faked_one_is_not():
    assert SW._unfaked_ssh_problem(_TOOL.format(fn="run_remote_command"), {"run_remote_command"}) is None
    problem = SW._unfaked_ssh_problem(_TOOL.format(fn="run_remote_script"), {"run_remote_command"})
    assert "fakes only ssh_remote.run_remote_command" in problem and "run_remote_script" in problem
    assert SW._unfaked_ssh_problem(_TOOL.format(fn="run_remote_script"), set()) is None  # no fake: no opinion


def test_write_step_rejects_the_unfaked_call_then_stages_the_fixed_one(tmp_path, monkeypatch):
    harness = tmp_path / "test_list_cron.py"
    harness.write_text(HARNESS, encoding="utf-8")
    replies = [_TOOL.format(fn="run_remote_script"), _TOOL.format(fn="run_remote_command")]
    prompts: list[str] = []

    def chat(system_prompt, user_prompt, max_tokens=None):
        prompts.append(user_prompt)
        return replies.pop(0)

    monkeypatch.setattr(SW, "agent_chat", chat)
    result = SW.write_candidate_tool(SW.WriteRequest(goal="list cron", test_file=harness),
                                     staging_dir=tmp_path / "staging")
    assert result.status == "staged" and result.attempts == 2
    assert "REMOTE CALL: the test above fakes ssh_remote.run_remote_command" in prompts[0]
    assert "which the test does not fake" in prompts[1]
    assert "run_remote_command(" in result.staging_path.read_text()
