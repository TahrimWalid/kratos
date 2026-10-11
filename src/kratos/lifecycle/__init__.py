"""Finding lifecycle: stable identity, states, history and people's decisions.

Every report's findings pass through `apply.apply_run` (from
findings_engine.write_findings_report). Only a person changes a state through
`decide`; Kratos itself only makes the deterministic moves (absent in a run that
re-checked it -> mitigated/inactive; present again, or a decision that expired
or no longer covers it -> open). No agent tool and no MCP tool may call
`decide` -- tests scan for it, and `decide` refuses inside a tool call.
"""
