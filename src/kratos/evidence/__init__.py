"""Evidence integrity (D.6): every evidence file Kratos writes is hashed when it is written.

``record(path, ...)`` is the one call every writer makes right after a file in an
evidence folder is complete. The hash, size, time, machine, read, transport, run and
Kratos build go into ``evidence_ledger`` -- a hash chain, so a row that is edited,
deleted, inserted or moved is detected (``kratos evidence verify``). Exports
(``kratos/export``) take each file's hash from here, never from the file as it is at
export time, unless the file predates the ledger (and then they say so).
"""
from kratos.evidence.ledger import (  # noqa: F401
    EVIDENCE_FOLDERS,
    ChainReport,
    LedgerEntry,
    is_evidence_path,
    record,
    verify_chain,
)
from kratos.evidence.transport import note_transport  # noqa: F401
