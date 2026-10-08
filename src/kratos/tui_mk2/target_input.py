"""
Target-input sanity checking for kratos-mk2.

A single validator shared by every place a user can TYPE a target (the /target
command, the conversational 'change target' control, the new-session prompt, and
the first-run wizard). It exists to catch the dumb but real failure the Sprint-4
eval found: pasting a whole command line or a quoted goal into a target field
(e.g. `kratos investigate "look for X"`) used to become the active target
verbatim -- `targets[0]` = "kratos", an unresolvable host that silently broke
every subsequent investigation.

A token is accepted only if it is a well-formed IP address (v4/v6, validated by
the stdlib `ipaddress` -- so 10.0.0.999 / 1.2.3.4.5 are rejected, not waved
through) OR a syntactically valid DNS hostname (RFC-1123 labels). Everything else
-- embedded quotes/spaces/slashes/@, malformed IPs, sentences -- is rejected.

This validates FORMAT, not existence: a syntactically valid but non-existent
host (a typo'd hostname) still passes here and fails later at the reachability
probe (run_target_probe_checks) / SSH, which is the correct layer to learn a
host isn't real. Format checking can't know that. A pasted PHRASE of otherwise-
valid single-word tokens is caught separately by looks_like_word_salad (a
clarify prompt), since each word is individually a legal hostname label.
"""
from __future__ import annotations

import ipaddress
import re

from kratos.utils.hostnames import MAX_LEN as _MAX_TARGET_LEN, is_ip_or_hostname

# "Monitor the Kratos host itself" as a first-class TARGET (distinct from the
# per-turn /investigate-host override): a session whose target IS the local
# machine. Stored/resolved as loopback, which loop.py's _LOOPBACK_SELF_TARGETS
# already permits, so every target-facing path treats it like any other host.
KRATOS_HOST_VALUE = "127.0.0.1"
# The value a ClarifyModal [Kratos-Host] option carries (can't collide with a
# real typed host -- double underscores fail validation anyway).
KRATOS_HOST_SENTINEL = "__kratos_host__"
# Words a user might type meaning "this machine" -> resolved to loopback so the
# header/target actually resolves (a literal 'kratos-host' would not).
_HOST_ALIASES = {"kratos-host", "kratos_host", "kratoshost", "this-host", "thishost", "self", "localhost"}


def kratos_host_option() -> dict:
    """The [Kratos-Host] choice for a target-picker ClarifyModal."""
    return {
        "value": KRATOS_HOST_SENTINEL,
        "label": "[Kratos-Host] — this machine",
        "explanation": f"Monitor the host Kratos runs on ({KRATOS_HOST_VALUE}), as a self-check.",
    }


def expand_host_aliases(tokens: list[str]) -> list[str]:
    """Map any 'this machine' alias token to loopback, leaving others untouched."""
    return [KRATOS_HOST_VALUE if t.strip().lower() in _HOST_ALIASES else t for t in tokens]


def _is_plausible_target(tok: str) -> bool:
    """A token is a plausible target iff it's a well-formed IP (v4/v6) or a
    syntactically valid DNS hostname. This validates FORMAT only, not whether
    the host exists or is reachable -- that's the target-probe's job. It exists
    to reject 'random bs' (malformed IPs, pasted commands, sentences) before it
    becomes the active target."""
    return is_ip_or_hostname(tok)


def validate_targets(tokens: list[str]) -> tuple[list[str], str | None]:
    """Return (clean_targets, error_message).

    error_message is None when every token is a plausible IP/hostname, and
    clean_targets is the whitespace-stripped list. Otherwise clean_targets is
    empty and error_message names the first offending token, so the caller can
    reject-and-reprompt (never silently coerce garbage into the active target).
    """
    cleaned = [t.strip() for t in tokens if t.strip()]
    if not cleaned:
        return [], "No target given — enter an IP or hostname."
    for tok in cleaned:
        if not _is_plausible_target(tok):
            return [], (
                f"{tok!r} doesn't look like an IP or hostname. Enter one or more "
                "space-separated IPs/hostnames (e.g. 10.0.0.5 or host.local) — "
                "not a command or a sentence."
            )
    return cleaned, None


def looks_like_word_salad(tokens: list[str]) -> bool:
    """True when the tokens pass validate_targets (each is a bare word, so a
    strict reject would be wrong) yet look far more like a pasted phrase than a
    set of hosts: 3+ tokens that are ALL purely alphabetic. A real host almost
    always carries a dot, a digit, or is a single short name — so 'db1 web2' or
    '10.0.0.5 10.0.0.6' are NOT flagged, while 'kratos investigate the logs' is.
    The caller uses this to ASK (a clarify prompt), never to silently reject —
    the tokens are individually valid, the intent is just ambiguous."""
    if len(tokens) < 3:
        return False
    return all(t.isalpha() for t in tokens)
