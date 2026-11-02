"""Short-lived SSH certificates instead of one long-lived key (Phase D.1).

ca.py (the CAs and how their keys are protected), mint.py (one certificate per run and
machine), enrol.py (the person's one-time setup on a machine and Kratos's checks of it),
diagnose.py (why a certificate login failed), store.py (records, never private keys).
"""
