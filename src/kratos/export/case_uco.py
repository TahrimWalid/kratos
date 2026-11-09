"""The bundle as a CASE/UCO graph (``case.jsonld``) for forensic tools that read it.

CASE 1.5.0 / UCO 1.5.0 (what ``case_validate`` 0.18.0 validates by default; the tests
run it). The mapping:

- every file in the bundle -> ``uco-observable:File`` with a ``FileFacet`` (name, size)
  and a ``ContentDataFacet`` holding its SHA-256 (``uco-types:Hash``);
- every machine -> ``uco-observable:Device`` (its name, or its placeholder when redacted);
- every read Kratos made that produced an evidence file -> a
  ``case-investigation:InvestigativeAction`` (the read's name, when the file was written,
  the machine as its object, Kratos as its instrument, the file as its result);
- the export itself -> an ``InvestigativeAction`` whose result is a
  ``case-investigation:ProvenanceRecord`` (exhibit number = the export id) grouping every file.
"""
from __future__ import annotations

import json
import uuid
from typing import Any

CASE_VERSION = "1.5.0"
UCO_VERSION = "1.5.0"

CONTEXT = {
    "kb": "urn:kratos:export:",
    "case-investigation": "https://ontology.caseontology.org/case/investigation/",
    "uco-action": "https://ontology.unifiedcyberontology.org/uco/action/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-tool": "https://ontology.unifiedcyberontology.org/uco/tool/",
    "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
}


_NS = uuid.UUID("6f0b5e0a-3c1e-5d0c-9a1d-4b7a2f6e8c10")   # Kratos's namespace for export node ids


def _id(export_id: str, kind: str, *parts: Any) -> str:
    """A stable IRI per node, ending in a UUID (UCO's suggested form): the same bundle
    always gives the same graph."""
    name = "\x1f".join([export_id, kind, *(str(p) for p in parts)])
    return f"kb:{kind}-{uuid.uuid5(_NS, name)}"


def _dt(iso: str | None) -> dict[str, str] | None:
    return {"@type": "xsd:dateTime", "@value": iso} if iso else None


def _int(n: int) -> dict[str, Any]:
    return {"@type": "xsd:integer", "@value": int(n)}


def build(manifest: dict[str, Any]) -> dict[str, Any]:
    eid = manifest["export_id"]
    graph: list[dict[str, Any]] = []
    tool_id = _id(eid, "tool", "kratos")
    graph.append({"@id": tool_id, "@type": "uco-tool:Tool", "uco-core:name": "Kratos",
                  "uco-tool:version": str(manifest.get("kratos_build") or "unknown"),
                  "uco-tool:toolType": "observe-and-recommend security assistant"})
    devices: dict[str, str] = {}
    for m in manifest["machines"]:
        did = _id(eid, "device", m["shown"])
        devices[m["shown"]] = did
        graph.append({"@id": did, "@type": "uco-observable:Device", "uco-core:name": m["shown"]})

    file_ids: list[str] = []
    for f in manifest["files"]:
        fid = _id(eid, "file", f["path"])
        file_ids.append(fid)
        name = f["path"].rsplit("/", 1)[-1]
        hashes = [{"@id": _id(eid, "hash", f["path"]), "@type": "uco-types:Hash",
                   "uco-types:hashMethod": "SHA256",
                   "uco-types:hashValue": {"@type": "xsd:hexBinary", "@value": f["sha256"]}}]
        facets = [
            {"@id": _id(eid, "filefacet", f["path"]), "@type": "uco-observable:FileFacet",
             "uco-observable:fileName": name, "uco-observable:filePath": f["path"],
             "uco-observable:sizeInBytes": _int(f["size"])},
            {"@id": _id(eid, "contentfacet", f["path"]), "@type": "uco-observable:ContentDataFacet",
             "uco-observable:hash": hashes, "uco-observable:sizeInBytes": _int(f["size"])},
        ]
        desc = [f"kind: {f['kind']}", f"hash taken at: {f['hashed_at']}"]
        if f.get("original_sha256"):
            desc.append(f"original file sha256: {f['original_sha256']}")
        if f.get("warning"):
            desc.append(f["warning"])
        graph.append({"@id": fid, "@type": "uco-observable:File", "uco-core:hasFacet": facets,
                      "uco-core:description": "; ".join(desc)})
        if f["kind"] in ("evidence", "events") and f.get("machine") in devices:
            act: dict[str, Any] = {
                "@id": _id(eid, "read", f["path"]), "@type": "case-investigation:InvestigativeAction",
                "uco-core:name": str(f.get("read") or f.get("category") or f["kind"]),
                "uco-core:description": (f"Kratos read of {f.get('category') or f['kind']}"
                                         + (f" via {f['transport']}" if f.get("transport") else "")
                                         + (f", run {f['run_id']}" if f.get("run_id") else "")),
                "uco-action:instrument": {"@id": tool_id},
                "uco-action:object": [{"@id": devices[f["machine"]]}],
                "uco-action:result": [{"@id": fid}],
            }
            end = _dt(f.get("collected_at"))
            if end:
                act["uco-action:endTime"] = end
            graph.append(act)

    prov_id = _id(eid, "provenance", eid)
    graph.append({"@id": prov_id, "@type": "case-investigation:ProvenanceRecord",
                  "case-investigation:exhibitNumber": eid,
                  "uco-core:description": "Kratos incident bundle: every file in it, signed (OpenSSH SSHSIG, "
                                          f"namespace kratos-export, key {manifest['signing_key']['fingerprint']})",
                  "uco-core:object": [{"@id": i} for i in file_ids]})
    export_act = {"@id": _id(eid, "export", eid), "@type": "case-investigation:InvestigativeAction",
                  "uco-core:name": "export incident bundle",
                  "uco-core:description": f"variant {manifest['variant']}; period "
                                          f"{manifest['scope']['window'].get('start') or 'the beginning'} to "
                                          f"{manifest['scope']['window'].get('end')}",
                  "uco-action:instrument": {"@id": tool_id},
                  "uco-action:object": [{"@id": d} for d in devices.values()],
                  "uco-action:result": [{"@id": prov_id}]}
    if manifest.get("created_at"):
        export_act["uco-action:endTime"] = _dt(manifest["created_at"])
    graph.append(export_act)
    return {"@context": CONTEXT, "@graph": graph}


def dumps(graph: dict[str, Any]) -> str:
    return json.dumps(graph, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
