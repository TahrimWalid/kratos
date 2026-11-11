"""D.4 formats: every rule id maps to an OCSF class; every OCSF object Kratos produces
validates against the pinned schema (tests/fixtures/ocsf, Apache-2.0); stored ECS events
go out unchanged; the outputs are deterministic (golden)."""
from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

from kratos.adapters.auth_log_parse import classify_auth_message  # noqa: E402
from kratos.events import converters as EC  # noqa: E402
from kratos.lifecycle.rules import RULES  # noqa: E402
from kratos.outbox import render as R  # noqa: E402
from kratos.outbox.config import Channel  # noqa: E402
from kratos.outbox.formats import CHANGES, FindingChange  # noqa: E402
from kratos.outbox.formats import ecs as F_ecs  # noqa: E402
from kratos.outbox.formats import kratos_json as F_kj  # noqa: E402
from kratos.outbox.formats import ocsf as F  # noqa: E402

SCHEMAS = Path(__file__).parent / "fixtures" / "ocsf" / F.VERSION
CLASS_FILE = {2002: "vulnerability_finding", 2003: "compliance_finding", 2004: "detection_finding",
              3002: "authentication", 1007: "process_activity", 4001: "network_activity", 1001: "file_activity"}
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


def _validator(cls: int):
    schema = json.loads(gzip.decompress((SCHEMAS / f"{CLASS_FILE[cls]}.json.gz").read_bytes()))
    return jsonschema.Draft7Validator(schema)


VALIDATORS = {c: _validator(c) for c in CLASS_FILE}


def _valid(obj: dict) -> None:
    errors = sorted(VALIDATORS[obj["class_uid"]].iter_errors(obj), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors[:5]]


def test_the_schema_fixtures_are_the_pinned_version():
    assert F.VERSION == "1.9.0"
    src = (SCHEMAS.parent / "SOURCE.txt").read_text()
    assert "1.9.0" in src and "profiles=host" in src
    assert (SCHEMAS.parent / "LICENSE").read_text().lstrip().startswith("Apache License")


def test_every_rule_id_maps_to_an_ocsf_findings_class():
    ids = list(RULES) + ["SIGMA-0123abcd", "KRATOS-SSH-BRUTEFORCE"]
    for rid in ids:
        assert F.class_of(rid) in (2002, 2003, 2004), rid
    assert F.class_of("PKG-001") == F.class_of("VULN-001") == 2002
    assert F.class_of("CORR-SSH-001") == F.class_of("SIGMA-0123abcd") == F.class_of("KRATOS-X") == 2004
    assert F.class_of("NET-001") == 2003


def _change(rule_id="CORR-SSH-001", change="new", **kw) -> FindingChange:
    finding = {
        "id": rule_id, "title": "A finding", "severity": "high", "evidence": ["line one", "line two"],
        "recommendation": ["do the thing"], "subject": "", "entities": ["203.0.113.9"],
        "first_seen": "2026-11-08T10:00:00+00:00", "last_seen": "2026-11-08T11:00:00+00:00",
        "attack": [{"technique_id": "T1110.001", "technique": "Password Guessing", "tactic_id": "TA0006",
                    "tactic": "Credential Access", "version": "19.0"}],
    }
    finding.update(kw.pop("finding", {}))
    base = dict(event_id=42, change=change, at=NOW.timestamp(), finding_key="0" * 64, rule_id=rule_id,
                machine="198.51.100.7", state={"mitigated": "mitigated", "decided": "risk_accepted"}.get(change, "open"),
                severity="high", title="A finding", finding=finding, machine_label="web-01")
    base.update(kw)
    return FindingChange(**base)


@pytest.mark.parametrize("rid", sorted(RULES) + ["SIGMA-0123abcd", "KRATOS-SSH-BRUTEFORCE"])
def test_every_rule_renders_a_valid_ocsf_finding(rid):
    finding = {}
    if rid.startswith("PKG-"):
        finding = {"subject": "openssl", "entities": ["CVE-2024-0001", "openssl:CVE-2024-0002"],
                   "ssvc": {"outcome": "act", "label": "Act", "tree": "cisa-2.0.3", "cve": "CVE-2024-0001"}}
    if rid.startswith("SIGMA-"):
        finding = {"detection_rule": {"id": rid, "title": "Suspicious thing", "sigma_id": "abc", "author": "x"}}
    obj = F.finding(_change(rid, finding=finding))
    _valid(obj)
    assert obj["class_uid"] == F.class_of(rid) and obj["metadata"]["version"] == "1.9.0"


@pytest.mark.parametrize("change", CHANGES)
def test_every_change_renders_valid_with_the_right_activity_and_status(change):
    obj = F.finding(_change("PKG-001", change, finding={"entities": ["CVE-2024-0001"]}))
    _valid(obj)
    want = {"new": (1, 1), "mitigated": (3, 4), "inactive": (3, 4), "decided": (3, 3)}.get(change, (2, 2))
    assert (obj["activity_id"], obj["status_id"]) == want and obj["type_uid"] == 2002 * 100 + want[0]


def test_a_vulnerability_finding_names_its_cves_and_the_detection_its_attack_labels():
    v = F.finding(_change("PKG-001", finding={"subject": "openssl", "entities": ["CVE-2024-0001"]}))
    assert v["vulnerabilities"][0]["cve"]["uid"] == "CVE-2024-0001" and v["vulnerabilities"][0]["is_fix_available"]
    d = F.finding(_change())
    assert d["finding_info"]["attacks"][0]["technique"]["uid"] == "T1110.001"
    assert d["device"] == {"type_id": 1, "type": "Server", "ip": "198.51.100.7", "name": "web-01"}
    assert d["unmapped"]["kratos"]["change"] == "new"


def _auth_doc(msg, ident="sshd"):
    ctx = EC.ReadContext(target="ubuntu@198.51.100.7", transport="ssh", read=EC.READ_JOURNAL_AUTH, created=NOW)
    ev = EC.from_auth_event(classify_auth_message("2026-11-08T11:59:00+00:00", "198.51.100.7", ident, msg, msg),
                            ctx=ctx)
    return ev.to_ecs()


def test_stored_auth_and_sudo_events_become_valid_ocsf_events():
    fail = _auth_doc("Failed password for invalid user alice from 203.0.113.9 port 51234 ssh2")
    o = F.event(fail, machine="198.51.100.7", row_id=5)
    _valid(o)
    assert o["class_uid"] == 3002 and o["status_id"] == 2 and o["user"]["name"] == "alice"
    assert o["src_endpoint"] == {"ip": "203.0.113.9", "port": 51234}
    sudo = _auth_doc("bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id", ident="sudo")
    p = F.event(sudo, machine="198.51.100.7", row_id=6)
    _valid(p)
    assert p["class_uid"] == 1007 and p["process"]["name"] == "id"


def test_network_and_file_events_validate_and_others_are_skipped():
    net = {"@timestamp": "2026-11-08T11:00:00Z", "event": {"category": ["network"], "type": ["denied"],
           "outcome": "failure", "action": "firewall_block"}, "source": {"ip": "203.0.113.9"},
           "destination": {"ip": "198.51.100.7", "port": 22}}
    o = F.event(net, machine="198.51.100.7", row_id=1)
    _valid(o)
    assert o["activity_id"] == 5
    fil = {"@timestamp": "2026-11-08T11:00:00Z", "event": {"category": ["file"], "type": ["creation"]},
           "file": {"path": "/etc/cron.d/x"}, "user": {"name": "root"}}
    f = F.event(fil, machine="h", row_id=2)
    _valid(f)
    assert f["file"]["name"] == "x" and f["activity_id"] == 1
    assert F.event({"@timestamp": "2026-11-08T11:00:00Z", "event": {"category": ["iam"]}}, machine="h", row_id=3) \
        is None


def test_ecs_events_go_out_exactly_as_stored():
    doc = _auth_doc("Failed password for root from 203.0.113.9 port 4 ssh2")
    ch = Channel(name="s", kind="webhook", config={"url": "https://x.example", "framing": "ndjson"},
                 scopes=("events",), format="ecs")
    payload, skipped = R.events(ch, [(9, "198.51.100.7", doc)], None, at=0, first_row=9, last_row=9)
    assert skipped == 0 and json.loads(payload["body"].strip()) == doc


def test_an_ecs_finding_document_carries_rule_threat_and_lifecycle():
    d = F_ecs.finding(_change())
    assert d["event"]["kind"] == "alert" and d["rule"]["id"] == "CORR-SSH-001"
    assert d["threat"]["technique"]["id"] == ["T1110.001"] and d["kratos"]["change"] == "new"
    v = F_ecs.finding(_change("PKG-001", finding={"entities": ["CVE-2024-0001"]}))
    assert v["event"]["kind"] == "state" and v["vulnerability"]["id"] == "CVE-2024-0001"


def test_outputs_are_deterministic():
    a, b = _change(), _change()
    assert F_kj.dumps(F.finding(a)) == F_kj.dumps(F.finding(b))
    assert F_kj.dumps(F_kj.finding(a)) == F_kj.dumps(F_kj.finding(b))
    golden = F_kj.dumps(F_kj.finding(a))
    assert golden.startswith('{"data":{"change":"new","decided_by":null,"finding":{"attack":[')
    assert '"type":"kratos.finding.new"' in golden and '"timestamp":"2026-11-08T12:00:00.000Z"' in golden


def test_es_bulk_uses_a_stable_document_id_so_a_retry_overwrites():
    ch = Channel(name="s", kind="webhook", config={"url": "https://x.example", "framing": "es_bulk",
                                                   "index": "kratos-findings"}, scopes=("findings",), format="ocsf")
    p1 = R.finding(ch, _change(), None)
    p2 = R.finding(ch, _change(), None)
    action = json.loads(p1["body"].splitlines()[0])
    assert p1 == p2 and action["index"]["_index"] == "kratos-findings" and len(action["index"]["_id"]) == 32


@pytest.mark.parametrize("rid", ["HASH-001", "HASH-002", "PERSIST-003", "PKG-001", "LIVE-004"])
def test_a_reputation_is_forwarded_as_file_hashes_and_an_enrichment(rid):
    """E.4: the file a finding names, with its SHA-256 (file.hashes) and its reputation (an
    enrichment) -- valid against the pinned OCSF 1.9.0 schema; severity untouched."""
    sha = "ab" * 32
    rep = [{"path": "/tmp/.x", "sha256": sha, "verdict": "known_bad", "label": "known-bad (MalwareBazaar)",
            "note": "", "sources": [{"source": "malwarebazaar", "detail": "", "date": "2026-11-11"}],
            "checked_at": "2026-11-11T10:00:00+00:00"}]
    obj = F.finding(_change(rid, finding={"reputation": rep, "subject": "/tmp/.x",
                                          "entities": [f"/tmp/.x#{sha[:12]}"]}))
    _valid(obj)
    assert obj["severity"] == "High"
    assert obj["enrichments"][0]["value"] == "known_bad" and obj["enrichments"][0]["data"]["sha256"] == sha
    if obj["class_uid"] != 2002:
        assert obj["evidences"][0]["file"]["hashes"] == [{"algorithm_id": 3, "algorithm": "SHA-256", "value": sha}]


def test_comp001_is_a_compliance_finding_with_its_failed_checks():
    """E.2: COMP-001 forwards as OCSF Compliance Finding 2003, the failed check ids as checks
    and requirements -- valid against the pinned schema."""
    obj = F.finding(_change("COMP-001", finding={"subject": "198.51.100.7",
                                                 "entities": ["perm./etc/crontab", "sshd.root_login", "made.up"]}))
    _valid(obj)
    assert obj["class_uid"] == 2003 and obj["compliance"]["control"] == "COMP-001"
    assert obj["compliance"]["requirements"] == ["perm./etc/crontab", "sshd.root_login"]
    assert obj["compliance"]["checks"][0] == {"uid": "perm./etc/crontab", "status": "Fail", "status_id": 3,
                                              "name": "/etc/crontab is owned by root:root with mode 600 or stricter"}
    assert "ISO/IEC 27001:2022 Annex A" in obj["compliance"]["standards"]
