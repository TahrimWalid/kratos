"""
Kratos sub-agent -- the target-side layer of the sub-agent architecture
(docs/subagent_architecture.md).

Capability 1 (always on, read-only): a target-side daemon (agent.py) dials OUT
to Kratos's core and forwards read-only telemetry snapshots (collector.py) over
a small framed protocol (protocol.py); a core-side listener (core_server.py)
authenticates and stores what it receives (kratos.storage.subagent_store);
status.py holds the pure liveness-derivation logic.

Capability 2 (off by default, per-target opt-in): a signed, versioned action
whitelist (whitelist.py / whitelist_templates.py) plus an HMAC-signed execution
channel (signing.py) let core dispatch a bounded, whitelisted action to the
agent -- but only when the target operator has locally opted in and the
independent security review has passed. Nothing in this package enables
execution against a real target by default.

installer.py / hub_address.py are core-side onboarding helpers (they generate a
self-contained target installer and detect the address a target should dial);
they run on the core, never on the target.

The five files agent/protocol/collector/signing/whitelist are stdlib-only and
form the deployable target bundle -- see agent.py's module docstring and
installer.py for the deployment shape.
"""
