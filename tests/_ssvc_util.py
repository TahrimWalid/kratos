"""A small vulnrichment-shaped tarball for tests (D.3).

Two real CISA records (tests/fixtures/vulnrichment, CC0) plus generated filler records,
so the archive clears ssvc_source.MIN_ROWS like the real one does. Built once per
process and cached: tests share the bytes.
"""
from __future__ import annotations

import functools
import io
import json
import tarfile
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "vulnrichment"
FILLER = 10_050


def cve_record(cve: str, options: dict[str, str], *, short_name: str = "CISA-ADP",
               timestamp: str = "2026-10-01T00:00:00Z") -> dict:
    return {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": cve}, "containers": {"cna": {}, "adp": [{
        "providerMetadata": {"shortName": short_name, "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0"},
        "metrics": [{"other": {"type": "ssvc", "content": {
            "id": cve, "role": "CISA Coordinator", "version": "2.0.3", "timestamp": timestamp,
            "options": [{k: v} for k, v in options.items()]}}}]}]}}


def _member_path(cve: str) -> str:
    _p, year, num = cve.split("-")
    return f"vulnrichment-develop/{year}/{int(num) // 1000}xxx/{cve}.json"


def build_tar(extra: dict[str, dict] | None = None, *, filler: int = FILLER, raw: dict[str, bytes] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def add(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        add("vulnrichment-develop/README.md", b"not a record\n")
        for f in sorted(FIXTURES.glob("CVE-*.json")):
            add(_member_path(f.stem), f.read_bytes())
        for i in range(filler):
            cve = f"CVE-1999-{10000 + i}"
            add(_member_path(cve), json.dumps(cve_record(cve, {"Exploitation": "none", "Automatable": "no",
                                                                "Technical Impact": "partial"})).encode())
        for cve, rec in (extra or {}).items():
            add(_member_path(cve), json.dumps(rec).encode())
        for name, data in (raw or {}).items():
            add(name, data)
    return buf.getvalue()


@functools.lru_cache(maxsize=1)
def default_tar() -> bytes:
    return build_tar()
