"""
kratos-mk2 -- the Textual full-screen TUI for Kratos.

Ships side-by-side with the classic `kratos` prompt_toolkit REPL
(src/kratos/cli/repl.py), which is completely untouched. Entry point:
`kratos-mk2` (see pyproject.toml [project.scripts]) -> tui_mk2/app.py::main.

Build principle: implement screens whose backing mechanism ALREADY exists
first; for screens whose mechanism does not exist yet, ship the UI as a
clearly-labelled, non-functional shell (see screens/phase2_preview.py)
rather than a finished-looking screen with nothing behind it.
"""
