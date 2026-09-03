"""
kratos-mk2 -- the Textual full-screen TUI for Kratos.

Ships side-by-side with the classic `kratos` prompt_toolkit REPL
(src/kratos/cli/repl.py), which is completely untouched. Entry point:
`kratos-mk2` (see pyproject.toml [project.scripts]) -> tui_mk2/app.py::main.

Design source of truth: the "Kratos TUI" design canvas, reordered into
chronological UI flow and mapped to real vs. not-yet-built mechanisms in
docs/kratos_mk2_tui.md. Build principle (per the project owner's directive):
implement screens whose backing mechanism ALREADY exists first; for screens
whose mechanism does not exist yet, ship the UI as a clearly-labelled shell
and record exactly what a future session must wire, in that same doc.
"""
