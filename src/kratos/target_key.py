"""One comparable form for a machine's name.

Every table that stores a target stores it in this form, so "ubuntu@10.0.0.5",
"10.0.0.5" and "10.0.0.5 " are the same machine, and every loopback spelling
("127.0.0.1", "localhost", "::1") is Kratos's own host.
"""
from __future__ import annotations

from typing import Any

LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})
LOOPBACK_KEY = "loopback"


def target_key(value: Any) -> str:
    """A comparable host: lower-case, without user@ or [] around IPv6, loopback names unified."""
    host = str(value or "").rpartition("@")[2].strip().strip("[]").lower()
    return LOOPBACK_KEY if host in LOOPBACK_NAMES else host
