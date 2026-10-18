"""B.2: mask -> restore gives back exactly what was masked.

Neutral fixtures (RFC 5737 addresses, example.com / .test names, alice and bob), and
the recorded tool results the regression gate replays -- checked generically (every
maskable address gone, valid JSON kept), never by naming a lab value.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

import pytest

from kratos.privacy.mask import Masker, ip_kind
from kratos.privacy.values import KnownValues

RECORDINGS = Path(__file__).resolve().parents[1] / "evals" / "replay" / "recordings"
TARGET = "192.0.2.10"
_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w-]|\.\d)")


def _masker(**values) -> Masker:
    kv = KnownValues(target_ips={TARGET}, **values)
    return Masker(mode="standard", scope=None, data_dir=None, machine=TARGET, values=kv)


EVENT = {"@timestamp": "2026-10-01T10:00:00Z", "event": {"action": "ssh_failed_login", "outcome": "failure"},
         "source": {"ip": "203.0.113.7"}, "user": {"name": "alice"}, "host": {"name": "web1.example.com"},
         "event.original": "sshd[42]: Failed password for alice from 203.0.113.7 port 50022 ssh2"}
FINDING = {"id": "CORR-SSH-001", "severity": "high", "title": "SSH exposed with failed-login burst activity",
           "subject": "22/tcp", "entities": ["203.0.113.7", "22/tcp"],
           "evidence": ["burst of 12 failed logins from 203.0.113.7 for alice", "target 192.0.2.10"],
           "attack": [{"technique_id": "T1110.001"}]}
DIGEST = ("Kratos already checked (data):\n- sign-in activity (24 h): 12 failed SSH login(s) from 1 address(es)\n"
          "- CORR-SSH-001 (high): source 203.0.113.7\n- open ports: 22/tcp ssh on 192.0.2.10")
TRANSCRIPT = [{"goal": "who tried to log in as alice?", "final_answer": "203.0.113.7 tried alice 12 times; "
               "bob@example.com was notified."}]


@pytest.mark.parametrize("fixture", [EVENT, FINDING, DIGEST, TRANSCRIPT], ids=["event", "finding", "digest", "transcript"])
def test_neutral_fixtures_round_trip(fixture):
    text = fixture if isinstance(fixture, str) else json.dumps(fixture, ensure_ascii=False)
    m = _masker(accounts={"alice": 1001})
    masked = m.mask(text)
    for value in ("alice", "203.0.113.7", "192.0.2.10", "bob@example.com"):
        assert value not in masked
    assert m.restore(masked) == text


def test_escaped_json_and_unicode_round_trip():
    inner = json.dumps({"user": "alice", "line": 'said "hi" from 198.51.100.4 — ünïcode ✓'})
    outer = json.dumps({"observation": inner, "note": "back\\slash"}, ensure_ascii=False)
    m = _masker(accounts={"alice": 1001})
    masked = m.mask(outer)
    assert "198.51.100.4" not in masked and "alice" not in masked
    assert json.loads(json.loads(masked)["observation"])["line"].startswith('said "hi" from PUBLIC_IP_')
    assert m.restore(masked) == outer


def test_one_value_one_placeholder_within_a_request():
    m = _masker(accounts={"alice": 1001})
    out = m.mask("alice from 203.0.113.7; again alice from 203.0.113.7")
    labels = re.findall(rf"[A-Z_]+_\d+_{m.tag}", out)
    assert len(labels) == 4 and len(set(labels)) == 2


def _recorded() -> list[tuple[str, str]]:
    out = []
    for path in sorted(RECORDINGS.glob("*.json")):
        rec = json.loads(path.read_text(encoding="utf-8"))
        out.append((f"{path.stem}-collection", json.dumps(rec.get("collection"), ensure_ascii=False)))
        out += [(f"{path.stem}-call{n}", json.dumps(c, ensure_ascii=False)) for n, c in enumerate(rec.get("calls") or [])]
    return out


def test_recorded_tool_results_round_trip_and_keep_no_maskable_address():
    recs = _recorded()
    assert len(recs) > 20
    for name, text in recs:
        rec_target = json.loads(text).get("target") if text.startswith("{") else None
        target_ip = str(rec_target or "").rpartition("@")[2]
        m = Masker(mode="standard", scope=None, data_dir=None, machine=target_ip,
                   values=KnownValues(target_ips={target_ip} if target_ip else set()))
        masked = m.mask(text)
        assert m.restore(masked) == text, name
        json.loads(masked)
        for ip in _IPV4.findall(masked):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            assert ip_kind(ip)[0] is None, f"{name}: address {ip} was sent"
