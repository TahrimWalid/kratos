"""The answer checks Kratos holds every investigation answer to (D.2 §5.1).

One machine's evidence in (:class:`MachineEvidence`), the checks' verdicts out
(:func:`evaluate`), the rejections for the model (:func:`rejections`) and the NOTEs
for an answer accepted as it stands (:func:`apply_notes`). The single-machine loop
(``agent/loop.py``) and the fleet answer (``kratos/fleet/answer.py``) both use them.
"""

from kratos.agent.answer_checks.checks import (
    CORRECTION_ORDER,
    MAX_REJECTIONS,
    VIOLATION_TAGS,
    CheckResult,
    Evaluation,
    MachineEvidence,
    NotedAnswer,
    apply_notes,
    correction_text,
    evaluate,
    note_text,
    rejections,
)

__all__ = [
    "CORRECTION_ORDER", "MAX_REJECTIONS", "VIOLATION_TAGS", "CheckResult", "Evaluation", "MachineEvidence",
    "NotedAnswer", "apply_notes", "correction_text", "evaluate", "note_text", "rejections",
]
