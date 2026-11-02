"""Re-checks for the container findings (B.1 verifiers, D.5).

CONT-004 is re-checked with a fresh container read, which re-reads the firewall rules
and makes ONE TCP connect from Kratos to each port its model says bypasses the firewall
(no payload) -- reachability from Kratos's own vantage, never a claim about the whole
internet. The other CONT rules are re-checked with the same fresh read of the engine's
settings."""
from __future__ import annotations

from kratos.triage.context import VerifyContext
from kratos.triage.registry import Verifier, register_verifier
from kratos.triage.verdict import Verdict


def _verify_settings(ctx: VerifyContext) -> Verdict:
    from kratos.triage.verifiers import _condition_verdict

    return _condition_verdict(
        ctx, ["containers"],
        reproduced_sentence="A fresh read of the container engine still shows this setting.",
        gone_sentence="A fresh read no longer shows this -- the container was removed or re-created without it.")


def _verify_bypass(ctx: VerifyContext) -> Verdict:
    from kratos.triage.verifiers import _condition_verdict

    v = _condition_verdict(
        ctx, ["containers"],
        reproduced_sentence="A fresh read of the firewall rules still lets outside traffic reach this port.",
        gone_sentence="A fresh read no longer shows this port reachable despite the firewall -- it was bound to "
                      "127.0.0.1, filtered, or the container is gone. Note: this is Kratos's own vantage.")
    if v.verdict == "reproduced":
        confirmed = "confirmed reachable from Kratos" in v.evidence
        sentence = ("A fresh read still lets outside traffic reach this port, and Kratos connected to it just now "
                    "(no data sent)." if confirmed else
                    "A fresh read still lets outside traffic reach this port; Kratos's own connection didn't "
                    "complete (something between here and there may block it).")
        return Verdict("reproduced", sentence, checks=v.checks, evidence=v.evidence)
    return v


register_verifier(Verifier(rules=("CONT-004",), cost="quick", verify=_verify_bypass,
                           label="a fresh firewall read and a TCP connect from Kratos"))
register_verifier(Verifier(rules=("CONT-001", "CONT-002", "CONT-003", "CONT-005", "CONT-006", "CONT-007"),
                           cost="quick", verify=_verify_settings, label="a fresh read of the container engine"))
