"""Build time only: compile Sigma rules into Kratos's closed rule format.

Needs pySigma (the `sigma` extra). Imported by scripts/dev/build_sigma_pack.py
(the shipped pack) and by `kratos detect import` (a person's own rules) -- never
by the detection pass, which only reads compiled packs.

- `pipeline` -- the Kratos processing pipeline: Sigma field -> event field, per
                log source, from kratos/events/sigma_fields.py
- `backend`  -- the Kratos backend: a Sigma condition -> a closed-operator node
- `compile`  -- whole rules (and event_count correlations) -> pack rules, or a
                skip with its reason; attribution, ATT&CK tags, the pack itself
- `samples`  -- a matching and a non-matching sample event for each rule
"""
