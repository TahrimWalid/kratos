"""Evidence-first triage (docs/phaseB/B.1): every serious finding is checked
again by code with a fresh, narrow read, and the verdict is shown to the person.

The model may *suggest* a finding is a false positive or less serious; only a
person can act on it (`finding_suggestions`). Nothing here changes a finding's
lifecycle state or severity -- a verdict is a separate thing a person reads.
"""
from __future__ import annotations

from kratos.triage.verdict import VERDICTS, Verdict, VerifyCheck, from_this_run, verdict_tag

__all__ = ["VERDICTS", "Verdict", "VerifyCheck", "from_this_run", "verdict_tag"]
