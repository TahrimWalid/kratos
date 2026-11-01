"""SSVC decisions for vulnerable packages and network-matched CVEs (D.3).

CISA's Stakeholder-Specific Vulnerability Categorization tree (``tree``) decides
Track / Track* / Attend / Act from four facts, each traceable to where it came from
(``inputs``, ``mission``). ``decide`` is pure. Beside the decision Kratos shows one
fact of its own, measured on the machine (``exposure``): whether the vulnerable code
is running and listening. Exposure orders findings within one decision; it never
changes CISA's outcome. ``bod2604`` adds CISA BOD 26-04's remediation timeline
beside the decision (its own table; the machine's public exposure is one of its
inputs), never in place of it. ``attach`` puts all three on findings.
"""
