"""Finding evidence is read by people: no raw None, no internal file or event names,
readable times (seen live: 'Source: None', 'sudo_session_open events = 271',
'ssh_failed_login burst: 4 events between 2026-10-04T08:55:24+00:00 and ...')."""
from __future__ import annotations

from kratos.adapters import findings_engine as FE

_NMAP = {"hosts": [{"address": "203.0.113.5", "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}]}],
         "source_file": "/data/scans/nmap_203.0.113.5_20261004_090859.xml"}
_BURST = {"event_type": "ssh_failed_login", "count": 4, "start": "2026-10-04T08:55:24+00:00",
          "end": "2026-10-04T08:55:25+00:00", "source_ips": {"203.0.113.52": 4}}


def _evidence(**kw) -> str:
    out = FE.generate_findings(_NMAP, kw.get("auth_stats"), {"bursts": [_BURST], "source_events_file": None}, None)
    return "\n".join(line for f in out for line in f.evidence)


def test_evidence_has_no_raw_none_or_internal_names():
    text = _evidence(auth_stats={"events_by_type": {"sudo_session_open": 3, "sudo_session_close": 3}})
    assert "None" not in text
    assert "Source:" not in text and ".xml" not in text and ".json" not in text and "auth_stats" not in text
    assert "ssh_failed_login" not in text and "sudo_session_open" not in text and " = " not in text
    assert "sudo sessions opened: 3" in text  # the sudo finding really was produced


def test_burst_lines_read_as_words_with_readable_times():
    text = _evidence()
    assert "burst of failed SSH logins: 4 between 2026-10-04 08:55:24 UTC and 2026-10-04 08:55:25 UTC" in text
    assert "T08:55" not in text
