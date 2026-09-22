"""Kratos — a defensive, observe-and-recommend security assistant.

Top-level package. The things you actually run live elsewhere: the `kratos`
console script (bare command launches the Textual TUI; subcommands dispatch
through `kratos.cli.app`), the agentic loop in `kratos.agent.loop`, and the
read-only tool registry in `kratos.agent.tools`.
"""
__all__ = ["__version__"]
__version__ = "0.1.0"

