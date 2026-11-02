"""One machine's evidence never lands in another machine's report (D.2, found on the lab).

A fleet run correlates several machines at once in one data folder. Two things leaked:
the findings report was `findings_<date>_<time>.json` -- two machines correlated in the
same second wrote the same file and each read back the other's findings -- and the
privileged-accounts input was "the newest snapshot of any machine", which the loader then
dropped for every other machine (their PRIV-* findings vanished).
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path

from kratos import kratos_config as kc
from kratos.adapters import findings_engine as FE
from kratos.utils import latest_file as LF
from kratos.target_key import target_key
from kratos.utils.stamped import reserve

H1, H2 = "203.0.113.10", "198.51.100.9"


def _put(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def _stats(host: str, sudo: int) -> dict:
    return {"source": f"ssh_target_measurement:ubuntu@{host}", "total_events": sudo * 2,
            "events_by_type": {"sudo_session_open": sudo, "sudo_session_close": sudo}}


def test_reserved_names_are_unique_and_keep_the_date_and_time_fields(tmp_path):
    t = datetime(2026, 11, 2, 22, 19, 52, 123456)
    names = [reserve(tmp_path, "findings", ".json", now=t)[0].name for _ in range(5)]
    assert len(set(names)) == 5
    assert names[0] == "findings_20261102_22195212345600.json"
    for n in names:
        assert LF.files_in_date_range(tmp_path, n, since="20261102", until="20261102")
    from kratos.timewin.snapshots import _STAMP_RE

    assert _STAMP_RE.search(names[0]).groups() == ("20261102", "221952")


def test_concurrent_correlations_of_two_machines_each_read_their_own_report(tmp_path):
    from kratos.agent.tools import tool_correlate_findings

    _put(tmp_path / "logs" / "auth_stats_a.json", _stats(H1, 125))
    _put(tmp_path / "logs" / "auth_stats_b.json", _stats(H2, 7))
    wrong: list[str] = []
    barrier = threading.Barrier(2)

    def worker(host: str) -> None:
        with kc.pinned_target(host):
            barrier.wait()
            for _ in range(15):
                out = tool_correlate_findings(tmp_path)
                report = json.loads(Path(out["findings_json_file"]).read_text())
                if target_key(report.get("target") or "") != host or \
                        out["inputs_used"]["auth_stats"] != ("auth_stats_a.json" if host == H1 else "auth_stats_b.json"):
                    wrong.append(f"{host} got {report.get('target')} / {out['inputs_used']['auth_stats']}")

    threads = [threading.Thread(target=worker, args=(h,)) for h in (H1, H2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not wrong, wrong[:3]
    reports = list((tmp_path / "reports").glob("findings_*.json"))
    assert len(reports) == 30                                   # one file per report, none overwritten


def test_each_machine_gets_its_own_privileged_accounts_snapshot(tmp_path):
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    for host, name, age in ((H1, "privileged_accounts_20260101_000000_000001.json", 60),
                            (H2, "privileged_accounts_20260101_000000_000002.json", 0)):
        _put(tmp_path / "context" / name, {"target": f"ubuntu@{host}", "checked_at": now, "groups": {}})
        t = time.time() - age
        os.utime(tmp_path / "context" / name, (t, t))
    assert FE.find_latest_inputs(tmp_path, H1)["privileged_accounts"].name.endswith("000001.json")
    assert FE.find_latest_inputs(tmp_path, H2)["privileged_accounts"].name.endswith("000002.json")
