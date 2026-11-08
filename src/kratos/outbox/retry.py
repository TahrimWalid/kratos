"""When a failed message is tried again, and which failures are final.

The schedule is the Standard Webhooks recommendation: after a failure the message is
tried again 5 s, 5 min, 30 min, 2 h, 5 h, 10 h, 14 h, 20 h and 24 h later (each with a
little jitter so many messages failing together don't all come back at once); a
message that fails all of them is ``dead`` -- kept, shown in the dead-letter list, and
delivered only when a person presses "retry now".
"""
from __future__ import annotations

import random

# seconds after the Nth failure (1-based) before the next try
SCHEDULE = (5, 5 * 60, 30 * 60, 2 * 3600, 5 * 3600, 10 * 3600, 14 * 3600, 20 * 3600, 24 * 3600)
MAX_ATTEMPTS = 1 + len(SCHEDULE)          # the first try plus one per retry
JITTER = 0.1                              # +-10 %

# HTTP answers that mean "try later", unlike every other 4xx
RETRYABLE_4XX = frozenset({408, 429})


def next_delay(failures: int, rng: random.Random | None = None) -> float | None:
    """Seconds to wait after the ``failures``-th failure (1-based), or None when the
    schedule is used up (the message is dead)."""
    if failures < 1 or failures > len(SCHEDULE):
        return None
    base = SCHEDULE[failures - 1]
    r = (rng or random).uniform(-JITTER, JITTER)
    return max(1.0, base * (1.0 + r))


def http_retryable(status: int) -> bool:
    """A webhook receiver's answer: 2xx is success (not asked here); 408/429 and 5xx are
    tried again; any other 4xx is final (the receiver rejected the message itself)."""
    if 400 <= status < 500:
        return status in RETRYABLE_4XX
    return True
