"""Re-checks for the deployed-code findings (B.1 verifiers, E.7a §3.9): a fresh code check
re-reads the file's hash and git state (CODE-001/002/005), the lockfiles (CODE-003) or the
file's text (CODE-004). A file whose content changed is judged on its own (a new entity)."""
from __future__ import annotations

from kratos.triage.context import VerifyContext
from kratos.triage.registry import Verifier, register_verifier
from kratos.triage.verdict import Verdict


def _verify(ctx: VerifyContext) -> Verdict:
    from kratos.triage.verifiers import _condition_verdict

    return _condition_verdict(
        ctx, ["code"],
        reproduced_sentence="A fresh read of the code folder still shows this (same file content).",
        gone_sentence="A fresh, complete read of the code folder no longer shows this -- the file was removed, "
                      "restored or replaced (its new content is judged on its own).")


register_verifier(Verifier(rules=("CODE-001", "CODE-002", "CODE-003", "CODE-004", "CODE-005"), cost="slow",
                           verify=_verify, label="a fresh read of the code folder"))
