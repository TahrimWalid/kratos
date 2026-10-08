"""
Review v2 F-8: shells and interpreters are refused under their versioned
names too, both in maintainer/user actions and in the target's own
allowed-commands file; programs that run the rest of the line are refused in
that file.
"""
from __future__ import annotations

import pytest

from kratos.subagent import ceiling as C
from kratos.subagent import whitelist as W

VERSIONED = ["python3.12", "python3.12-dbg", "php8.2", "perl5.36", "perl5.36.0", "lua5.4", "tclsh8.6",
             "pypy3", "ruby3.1", "nodejs", "PYTHON3.11", "/usr/bin/python3.12", "ksh93", "gawk", "php-cgi8.1"]
BENIGN = ["fail2ban-client", "systemctl", "sha256sum", "shred", "sshd", "ssh-keygen", "envsubst", "findmnt",
          "perldoc", "pythonic", "node-red-thing", "phpize", "lsof", "chmod", "tee", "adduser"]


@pytest.mark.parametrize("program", VERSIONED)
def test_versioned_interpreters_are_recognised(program):
    assert W.is_shell_or_interpreter(program)


@pytest.mark.parametrize("program", BENIGN)
def test_ordinary_programs_are_not(program):
    assert not W.is_shell_or_interpreter(program)


@pytest.mark.parametrize("line", [
    "python3.12 -c 'import os'", "php8.2 -r 'system(1)'", "perl5.36 -e 1", "lua5.4 -e 1",
    "/usr/bin/python3.12 -c print(1)", "tclsh8.6 x",
    # wrappers that run the rest of the line as a command
    "stdbuf -oL id", "nsenter -t 1 -m id", "systemd-run id", "runuser -u root id", "flock /tmp/l id",
    "taskset 1 id", "unshare -r id", "chrt 1 id", "sudo -u root python3.12",
])
def test_the_local_allow_file_refuses_them(line):
    with pytest.raises(C.CeilingError, match="runs other commands"):
        C.parse_command_line(line)


@pytest.mark.parametrize("line", ["adduser --disabled-password --gecos '' alice", "systemctl restart nginx",
                                  "/usr/bin/sha256sum /etc/hosts", "perldoc -h"])
def test_plain_exact_commands_still_parse(line):
    assert C.parse_command_line("sudo " + line) == C.parse_command_line(line)  # a bare sudo prefix is dropped
    assert C.parse_command_line(line)


@pytest.mark.parametrize("program", ["python3.12", "php8.2", "perl5.36.0"])
def test_maintainer_and_user_actions_refuse_them_as_literal_or_enum_value(program):
    literal = W.ActionSpec(id="x.lit", layer="user", argv_template=(program, "-V"), effect="e",
                           reversibility="r", blast_radius="b", source_recommendation=("T",))
    with pytest.raises(W.HardExclusionError, match="shell/interpreter"):
        W.validate_spec(literal)
    enum = W.ActionSpec(id="x.enum", layer="user", argv_template=("busybox", "{applet}"),
                        slots={"applet": W.Slot(kind="enum", values=("true", program))}, effect="e",
                        reversibility="r", blast_radius="b", source_recommendation=("T",))
    with pytest.raises(W.HardExclusionError):
        W.validate_spec(enum)


def test_a_program_name_must_not_look_like_an_option():
    with pytest.raises(C.CeilingError, match="not a program name"):
        C.parse_command_line("-u root id")
