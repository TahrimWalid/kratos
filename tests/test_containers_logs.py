"""Container logs as a log source (D.5 §3.8): json-file / k8s-file lines and journald-driver
entries become kratos.container events with the container fields, positions and spans
are kept, rotation and removal are handled, secrets are masked, caps and exclusions hold."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from kratos import settings_store
from kratos.collect.sync import cursors
from kratos.collect.sync.engine import SourceReport
from kratos.containers import logs as L
from kratos.containers import record as R
from kratos.containers import settings as S
from kratos.events.store import EventStore
from kratos.logsources.parsers import containers as PC
from kratos.target_key import target_key

from test_containers_judge import ctr, inv

T = "192.0.2.10"
NOW = 1793600000.0


def _ts(i: int) -> str:
    return f"2026-11-02T08:{i // 60:02d}:{i % 60:02d}.123456789Z"


def _line(i: int, text: str = "") -> str:
    return json.dumps({"log": (text or f"hello {i} from 203.0.113.{i % 250}") + "\n", "stream": "stdout",
                       "time": _ts(i)})


class FakeAgent:
    """Holds one container's log file(s) the way the agent's chunk read sees them."""

    def __init__(self, cid):
        self.cid = cid
        self.files = {0: [101, []]}       # slot -> [inode, lines]
        self.gone = False
        self.calls = []

    def text(self, slot):
        return "".join(ln + "\n" for ln in self.files[slot][1])

    def __call__(self, cid, inode, offset):
        self.calls.append((inode, offset))
        meta = {"name": "web", "image": "nginx:1.27", "image_id": "sha256:" + "c" * 64, "engine": "docker",
                "driver": "json-file"}
        if self.gone:
            return {"meta": meta, "files": [{"status": "gone", "slot": 0, "inode": None, "start": 0, "consumed": 0,
                                             "size": 0, "note": ""}], "lines": []}

        def chunk(slot, start):
            data = self.text(slot).encode()
            if start is None:
                start = 0
            start = min(start, len(data))
            body = data[start:]
            out = [("json-file", ln) for ln in body.decode().splitlines() if ln]
            return ({"status": "read", "slot": slot, "inode": self.files[slot][0], "start": start,
                     "consumed": len(body), "size": len(data), "note": ""}, out)
        cur_inode = self.files[0][0]
        if inode is not None and inode != cur_inode:
            if 1 in self.files and self.files[1][0] == inode:
                f1, lines = chunk(1, offset)
                return {"meta": meta, "files": [f1, {"status": "current", "slot": 0, "inode": cur_inode, "start": 0,
                                                     "consumed": 0, "size": 0, "note": ""}], "lines": lines}
            return {"meta": meta, "files": [{"status": "missing", "slot": 1, "inode": None, "start": 0, "consumed": 0,
                                             "size": 0, "note": ""},
                                            {"status": "current", "slot": 0, "inode": cur_inode, "start": 0,
                                             "consumed": 0, "size": 0, "note": ""}], "lines": []}
        f0, lines = chunk(0, offset if inode is not None else None)
        return {"meta": meta, "files": [f0], "lines": lines}


@pytest.fixture()
def setup(tmp_path):
    c = ctr("web", log_driver="json-file")
    R.run(tmp_path, T, reader=lambda: inv(c), connect=lambda a, p: True)
    return tmp_path, c["id"]


def _sync(data_dir, fetch, now=NOW):
    rep = SourceReport(source="containers")
    L.sync_files(data_dir, T, rep, now=now, initial_hours=48, deadline=1e18, fetch=fetch)
    return rep


def _events(data_dir):
    return EventStore(data_dir / "kratos.db").query(target_key(T), dataset="kratos.container", limit=1000,
                                                    newest_first=False)


def test_json_file_lines_become_container_events(setup):
    data_dir, cid = setup
    agent = FakeAgent(cid)
    agent.files[0][1] = [_line(i) for i in range(5)]
    rep = _sync(data_dir, agent)
    evs = _events(data_dir)
    assert rep.new_events == 5 and len(evs) == 5
    e = evs[0]
    assert e.dataset == "kratos.container" and e.container_id == cid and e.container_name == "web"
    assert e.container_image_name == "nginx:1.27" and e.container_runtime == "docker"
    assert e.container_image_hash == ("sha256:" + "c" * 64,) and e.message.startswith("hello 0")
    cur = cursors.get_cursor(data_dir, target_key(T), "containers", f"ctr:{cid}")
    assert cur.inode == 101 and int(cur.position) == len(agent.text(0).encode())
    assert cursors.covered(data_dir, target_key(T), "containers", NOW - 1, NOW)
    agent.files[0][1].append(_line(5))
    assert _sync(data_dir, agent, now=NOW + 60).new_events == 1     # only what is new


def test_rotation_mid_follow_loses_nothing(setup):
    data_dir, cid = setup
    agent = FakeAgent(cid)
    agent.files[0][1] = [_line(0), _line(1)]
    _sync(data_dir, agent)
    agent.files[0][1] += [_line(2)]                     # written before the rotation
    agent.files[1] = agent.files[0]                     # renamed to .1
    agent.files[0] = [202, [_line(3), _line(4)]]
    rep = _sync(data_dir, agent, now=NOW + 60)
    assert [e.message.split()[1] for e in _events(data_dir)] == ["0", "1", "2", "3", "4"]
    assert rep.gaps == []


def test_a_lost_rotation_is_a_recorded_gap(setup):
    data_dir, cid = setup
    agent = FakeAgent(cid)
    agent.files[0][1] = [_line(0)]
    _sync(data_dir, agent)
    agent.files[0] = [303, [_line(9)]]                  # rotated twice; the followed file is gone
    rep = _sync(data_dir, agent, now=NOW + 60)
    assert any("previous file is gone" in g for g in rep.gaps)
    gaps = [s for _src, s in cursors.spans(data_dir, target_key(T), "containers") if not s.complete]
    assert gaps


def test_a_removed_container_is_a_stated_end(setup):
    data_dir, cid = setup
    agent = FakeAgent(cid)
    agent.files[0][1] = [_line(0)]
    _sync(data_dir, agent)
    agent.gone = True
    rep = _sync(data_dir, agent, now=NOW + 60)
    assert rep.gaps == [] and rep.status == "ok"
    assert cursors.get_cursor(data_dir, target_key(T), "containers", f"ctr:{cid}").position == "ended"
    calls = len(agent.calls)
    _sync(data_dir, agent, now=NOW + 120)
    assert len(agent.calls) == calls                    # not read again


def test_secrets_in_a_line_are_masked_before_storage(setup):
    data_dir, cid = setup
    secret = "s3cr" + "et-" + "Value99"
    agent = FakeAgent(cid)
    agent.files[0][1] = [_line(0, f"login ok password={secret} user=alice")]
    _sync(data_dir, agent)
    e = _events(data_dir)[0]
    assert secret not in (e.message or "") and secret not in (e.original or "") and e.redacted


def test_caps_and_exclusions(setup):
    data_dir, cid = setup
    agent = FakeAgent(cid)
    agent.files[0][1] = [_line(i) for i in range(300)]
    settings_store.set(S.LOGS_MAX_LINES, 100, data_dir=data_dir, actor="test")
    rep = _sync(data_dir, agent)
    assert len(_events(data_dir)) == 100 and any("newest 100 were kept" in g for g in rep.gaps)
    settings_store.set(S.LOGS_EXCLUDE, ["we*"], data_dir=data_dir, actor="test")
    agent.calls.clear()
    _sync(data_dir, agent, now=NOW + 60)
    assert agent.calls == []


def test_over_ssh_the_files_are_a_stated_gap(tmp_path):
    ssh = inv(ctr("web"), via="ssh")
    R.run(tmp_path, T, reader=lambda: ssh, connect=lambda a, p: True)
    rep = SourceReport(source="containers")
    L.sync_files(tmp_path, T, rep, now=NOW, initial_hours=24, deadline=1e18)
    assert rep.status == "partial" and any("sub-agent" in g for g in rep.gaps)


def test_journald_driver_entries_are_tagged_without_a_second_read():
    cid = "f" * 64
    rec = SimpleNamespace(kind="journal", ts=NOW, text="", entry={
        "MESSAGE": "journald line from 198.51.100.23", "CONTAINER_ID_FULL": cid, "CONTAINER_NAME": "jlog",
        "IMAGE_NAME": "alpine:3.20", "_COMM": "dockerd", "PRIORITY": "6", "__CURSOR": "s=1;i=2"})
    p = PC.to_parsed(rec)
    assert p.fields["container_id"] == cid and p.fields["container_name"] == "jlog"
    assert p.fields["container_runtime"] == "docker" and p.action == "container_output"
    own = SimpleNamespace(kind="journal", ts=NOW, text="", entry={"MESSAGE": "API listen on /run/docker.sock",
                                                                 "_COMM": "dockerd"})
    assert PC.to_parsed(own) is None                     # dockerd's own lines are not container lines


def test_k8s_file_lines_and_nanosecond_times():
    p = PC.file_line("k8s-file", "2026-11-02T08:00:01.123456789+00:00 stderr F oops", {"name": "x", "engine": "podman"},
                     "a" * 64)
    assert p.message == "oops" and p.fields["container_runtime"] == "podman"
    assert abs(p.ts - PC.parse_time("2026-11-02T08:00:01.123456Z")) < 1e-6
    assert PC.file_line("json-file", "not json", {}, "a" * 64) is None
