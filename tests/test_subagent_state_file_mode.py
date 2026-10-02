"""The agent's state file holds the pairing token (the channel's signing key is derived from
it). It used to be written with the default umask -- world-readable 0644 -- so any local user
on a monitored box could read it. Found on a live install during the 0.2.0 upgrade."""
from __future__ import annotations

import os
import stat

from kratos.subagent import agent as A


def _mode(p) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


def test_state_is_written_owner_only_from_the_start(tmp_path):
    old = os.umask(0o022)  # the common default that produced 0644
    try:
        f = tmp_path / "state.json"
        A._save_state(f, {"token": "secret", "agent_id": "a"})
        assert _mode(f) == 0o600
        A._save_state(f, {"token": "rotated", "agent_id": "a"})  # rewrite keeps it
        assert _mode(f) == 0o600 and not (tmp_path / "state.tmp").exists()
    finally:
        os.umask(old)


def test_a_world_readable_file_from_an_older_agent_is_tightened_on_load(tmp_path):
    f = tmp_path / "state.json"
    f.write_text('{"token": "secret"}')
    os.chmod(f, 0o644)
    assert A._load_state(f) == {"token": "secret"}
    assert _mode(f) == 0o600


def test_installer_tightens_the_moved_aside_identity():
    from kratos.subagent import installer as I

    script = I.generate_installer("10.0.0.1", "AB12-CD34")
    assert 'chmod 600 "$OLD"' in script
