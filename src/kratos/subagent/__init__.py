"""
Kratos sub-agent -- capability 1 (continuous, read-only telemetry) only.

See docs/subagent_architecture.md for the full design. Summary of what exists
in this package as of this commit: a target-side daemon (agent.py) that dials
OUT to Kratos's core and forwards read-only telemetry snapshots
(collector.py) over a small framed protocol (protocol.py); a core-side
listener (core_server.py) that authenticates and stores what it receives
(kratos.storage.subagent_store); and pure liveness-derivation logic
(status.py). There is no execution channel, no command dispatch, no
whitelist, and no Tailscale integration anywhere in this package -- capability
2 (direct execution) is a separate, not-yet-built, gated piece of work.
"""
