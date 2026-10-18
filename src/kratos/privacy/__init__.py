"""What the hosted model sees: real names, addresses and secrets replaced before a
request leaves this machine, and the real values put back in what comes back (B.2).

One place does it -- `llm_interface._metered_call` masks every request it sends, and
each function that calls it restores the text it returns (two source scans in
`tests/test_privacy_choke_point.py` keep it that way). Nothing Kratos stores is
masked: transcripts, events, findings and run records keep real values, and the
guards, the findings block and tool dispatch all work on restored text.

* `secrets`    -- passwords, keys and tokens become `[REDACTED]` first, never restored;
* `values`     -- the values Kratos already knows (accounts, machine names, addresses)
                  from snapshots, events and config, through a registry;
* `pseudonyms` -- the stable per-session map (`pseudonym_map`, personal data);
* `mask`       -- `Masker`: mask a request, restore a reply;
* `mode`       -- off / standard / strict, and the default for this model endpoint.
"""
from __future__ import annotations

from kratos.privacy.mask import Masker, request_masker
from kratos.privacy.mode import MODE_KEY, current_mode, describe_mode

__all__ = ["Masker", "request_masker", "MODE_KEY", "current_mode", "describe_mode"]
