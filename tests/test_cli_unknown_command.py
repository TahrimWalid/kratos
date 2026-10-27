"""`kratos <word>` with a word that isn't a command used to open the full-screen app
silently (the leftover word was dropped), so `kratos doctr` or a typo like
`kratos investgate "..."` looked like it worked and then sat in the TUI. A word or
flag Kratos doesn't know is now an error that names it and suggests the closest
command; bare `kratos` (and its real global options) still opens the app."""
from __future__ import annotations

import pytest

from kratos.cli import app as cli_app


@pytest.fixture
def opened(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr("kratos.tui_mk2.app.main", lambda argv: calls.append(list(argv)) or 0)
    return calls


def test_bare_kratos_and_its_global_options_open_the_app(opened, tmp_path):
    assert cli_app.main([]) == 0
    assert cli_app.main(["--data-dir", str(tmp_path), "--no-color"]) == 0
    assert len(opened) == 2 and opened[1][:2] == ["--data-dir", str(tmp_path)]


@pytest.mark.parametrize("argv, named, suggested", [
    (["doctr"], "doctr", "doctor"),
    (["investgate", "is the box ok?"], "investgate", "investigate"),
    (["--dta-dir", "/tmp/x"], "--dta-dir", None),
])
def test_an_unknown_word_is_an_error_not_the_app(opened, capsys, argv, named, suggested):
    assert cli_app.main(argv) == 2
    assert opened == []
    err = capsys.readouterr().err
    assert f"'{named}'" in err and "kratos --help" in err
    if suggested:
        assert f"kratos {suggested}" in err


def test_version_prints_kratos_and_the_agent_it_installs(capsys):
    """`kratos --version` / `-V` (a bug report and a security advisory need it), not
    an 'unknown command' -- and it opens nothing."""
    from kratos import __version__
    from kratos.cli import app
    from kratos.subagent.agent import AGENT_VERSION

    for flag in ("--version", "-V"):
        assert app.main([flag]) == 0
        assert capsys.readouterr().out.strip() == f"kratos {__version__} (sub-agent {AGENT_VERSION})"
