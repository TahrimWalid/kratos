"""Writing files into a bundle folder (the bundle itself is not evidence; its manifest is
recorded in the evidence ledger by ``export/create.py`` once the bundle is complete)."""
from __future__ import annotations

import hashlib
from pathlib import Path


def write_bytes(bundle: Path, rel: str, data: bytes) -> tuple[str, int]:
    p = bundle / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return hashlib.sha256(data).hexdigest(), len(data)


def write_text(bundle: Path, rel: str, text: str) -> tuple[str, int]:
    return write_bytes(bundle, rel, text.encode("utf-8"))
