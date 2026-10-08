"""Is a string a plausible network address? One shared rule, stdlib-only.

Used where a typed address becomes a target (tui_mk2.target_input) and where it
is written into a generated sub-agent installer (subagent.installer). This checks
FORMAT only -- an IP (v4/v6) or a syntactically valid DNS hostname -- never
whether the host exists. It rejects what a pasted command line or a sentence
looks like: spaces, quotes, slashes, '@', shell characters, leading dashes.
"""
from __future__ import annotations

import ipaddress
import re

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")
# Only digits and dots means the user meant an IPv4; if ipaddress rejects it
# (10.0.0.999, 1.2.3.4.5) it must not pass as a hostname either.
_IPV4_ISH = re.compile(r"^[0-9.]+$")
MAX_LEN = 253  # DNS name length ceiling; also caps a pasted blob


def is_ip_or_hostname(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > MAX_LEN:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if _IPV4_ISH.match(value):
        return False
    return bool(_HOSTNAME.match(value))
