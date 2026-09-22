"""
The Textual full-screen TUI for Kratos -- the primary interface.

Bare `kratos` launches this (cli/app.py's no-subcommand path -> tui_mk2/app.py::
main); `kratos <subcommand>` still dispatches through cli/app.py. The classic
prompt_toolkit REPL (cli/repl.py) is retired as the default face -- its code
remains in the tree, but no command or console script launches it. The package
directory is still named `tui_mk2` internally (a rename would touch every
import); the user-facing `kratos-mk2` command has been retired.

Build principle: implement screens whose backing mechanism ALREADY exists
first; for screens whose mechanism does not exist yet, ship the UI as a
clearly-labelled, non-functional shell (see screens/phase2_preview.py)
rather than a finished-looking screen with nothing behind it.
"""
