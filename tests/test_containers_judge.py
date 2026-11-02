"""CONT-001..008 (D.5 §3.4), the snapshot, the findings and their lifecycle."""
from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest

from kratos.containers import judge as J
from kratos.containers import record as R

from test_containers_firewall import IPT_UFW_DOCKER

CID = "1" * 64
NET = "e" * 64
IMG = "sha256:" + "c" * 64


def ctr(name, **over):
    c = {"id": (name.encode().hex() * 64)[:64], "engine": "docker", "name": name, "image": "nginx:1.27",
         "image_id": IMG, "image_digest": "sha256:" + "d" * 64, "state": "running", "running": True, "pid": 10,
         "user": "", "privileged": False, "cap_add": [], "cap_drop": [], "security_opt": [], "apparmor": "docker-default",
         "network_mode": "bridge", "pid_mode": "", "ipc_mode": "private", "mounts": [], "ports": [],
         "networks": [{"name": "bridge", "id": NET, "ip": "172.17.0.2", "ip6": ""}], "labels": {}, "env_keys": [],
         "log_driver": "json-file"}
    c.update(over)
    return c


def inv(*containers, firewall=True, via="agent", procs=None, engines=None):
    return {"via": via, "complete": True,
            "engines": engines if engines is not None else [{"engine": "docker", "socket": "/run/docker.sock",
                                                            "state": "ok", "detail": "29.9.2"}],
            "infos": {"docker": {"firewall_backend": "iptables"}},
            "networks": {NET: {"id": NET, "name": "bridge", "ipv6": False,
                               "options": {"com.docker.network.bridge.name": "docker0"}}},
            "containers": {c["id"]: c for c in containers}, "procs": procs or {}, "proc_gaps": [], "listeners": [],
            "routes": {"4": ["eth0"], "6": []}, "gaps": [], "truncated": {}, "hidepid": "0",
            "firewall": {"iptables": {"status": "ok", "text": IPT_UFW_DOCKER}} if firewall else
            {"iptables": {"status": "denied", "text": ""}}}


def rules(j):
    return sorted((s["rule"], s["severity"], s["subject"]) for s in j.signals)


HOST = {4: "192.0.2.10", 6: None}


@pytest.mark.parametrize("over,rule,sev", [
    ({"privileged": True}, "CONT-001", "high"),
    ({"mounts": [{"type": "bind", "source": "/var/run/docker.sock", "destination": "/s", "rw": False}]}, "CONT-002", "high"),
    ({"mounts": [{"type": "bind", "source": "/run/podman/podman.sock", "destination": "/s", "rw": True}]}, "CONT-002", "high"),
    ({"network_mode": "host"}, "CONT-003", "medium"),
    ({"pid_mode": "host"}, "CONT-003", "medium"),
    ({"mounts": [{"type": "bind", "source": "/etc", "destination": "/host-etc", "rw": True}]}, "CONT-005", "high"),
    ({"mounts": [{"type": "bind", "source": "/var", "destination": "/v", "rw": True}]}, "CONT-005", "high"),
    ({"cap_add": ["NET_ADMIN"]}, "CONT-006", "medium"),
    ({"cap_add": ["CAP_SYS_ADMIN"]}, "CONT-006", "high"),
    ({"cap_add": ["ALL"]}, "CONT-006", "high"),
    ({"security_opt": ["seccomp=unconfined"]}, "CONT-007", "medium"),
    ({"security_opt": ["apparmor:unconfined"]}, "CONT-007", "medium"),
])
def test_each_setting_rule(over, rule, sev):
    j = J.judge(inv(ctr("app", **over)), host_addrs=HOST)
    assert rules(j) == [(rule, sev, "app")]
    s = j.signals[0]
    assert any("CIS Docker Benchmark v1.7.0 §" in e for e in s["evidence"])
    assert "app" not in s["title"] and "nginx" not in s["title"]          # machine text never in a title (A.4)
    assert f"image:sha256:{'d' * 64}" in s["entities"]


def test_a_plain_container_raises_nothing_and_read_only_or_other_mounts_dont_count():
    j = J.judge(inv(ctr("plain", mounts=[{"type": "bind", "source": "/etc", "destination": "/e", "rw": False},
                                         {"type": "bind", "source": "/srv/data", "destination": "/d", "rw": True},
                                         {"type": "volume", "source": "/var/lib/docker/volumes/x", "destination": "/x",
                                          "rw": True}],
                                ports=[{"proto": "tcp", "container_port": 80, "host_ip": "127.0.0.1", "host_port": 9090}])),
                host_addrs=HOST)
    assert j.signals == []


def test_privileged_does_not_double_count_its_capabilities_or_confinement():
    j = J.judge(inv(ctr("p", privileged=True, cap_add=["SYS_ADMIN"], security_opt=["label=disable"],
                        apparmor="unconfined")), host_addrs=HOST)
    assert rules(j) == [("CONT-001", "high", "p")]


def test_a_stopped_container_raises_no_finding_but_is_listed():
    j = J.judge(inv(ctr("old", running=False, state="exited", privileged=True)), host_addrs=HOST)
    assert j.signals == [] and j.rows[0]["running"] is False


PUBLISHED = [{"proto": "tcp", "container_port": 80, "host_ip": "0.0.0.0", "host_port": 8080},
             {"proto": "tcp", "container_port": 80, "host_ip": "::", "host_port": 8080}]


def test_bypass_confirmed_is_high_and_not_confirmed_is_medium():
    seen = []
    j = J.judge(inv(ctr("web", ports=PUBLISHED)), host_addrs=HOST, confirm=lambda p: seen.append(p) or True,
                vantage="Kratos at 192.0.2.1")
    assert rules(j) == [("CONT-004", "high", "web")] and seen == [8080]
    s = j.signals[0]
    assert any(e.startswith("Confirmed: a TCP connection from Kratos") for e in s["evidence"])
    assert [p["family"] for p in s["ports"]] == [4]        # IPv6 is proxied through INPUT on this network
    j2 = J.judge(inv(ctr("web", ports=PUBLISHED)), host_addrs=HOST, confirm=lambda p: False)
    assert rules(j2) == [("CONT-004", "medium", "web")]
    assert any("Not confirmed" in e for e in j2.signals[0]["evidence"])


def test_bypass_fix_names_the_compose_file_and_the_backend_rule():
    labels = {"com.docker.compose.project": "demo", "com.docker.compose.service": "app",
              "com.docker.compose.project.config_files": "/opt/demo/compose.yaml",
              "com.docker.compose.project.working_dir": "/opt/demo"}
    j = J.judge(inv(ctr("demo-app-1", ports=PUBLISHED, labels=labels)), host_addrs=HOST, confirm=lambda p: True)
    s = j.signals[0]
    assert any("Compose project demo service app (/opt/demo/compose.yaml)" in e for e in s["evidence"])
    texts = [f["text"] for f in s["fix"]]
    assert 'In /opt/demo/compose.yaml, service "app"' in texts[0] and '"127.0.0.1:8080:80"' in texts[0]
    assert "docker compose up -d" in texts[0]
    assert "-A DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP" in texts[1]
    assert "/etc/ufw/after.rules" in texts[1]
    doc = inv(ctr("web", ports=PUBLISHED))
    doc["infos"]["docker"]["firewall_backend"] = "nftables"
    nft = J.judge(doc, host_addrs=HOST, confirm=lambda p: True).signals[0]["fix"][1]["text"]
    assert "ct original proto-dst 8080" in nft and "-A DOCKER-USER" not in nft


def test_the_bypass_fix_is_recognised_by_the_model_as_closing_it():
    rule = "-A DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP"
    doc = inv(ctr("web", ports=PUBLISHED))
    doc["firewall"]["iptables"]["text"] = IPT_UFW_DOCKER.replace("-A FORWARD -j DOCKER-USER",
                                                                 "-A FORWARD -j DOCKER-USER\n" + rule)
    assert J.judge(doc, host_addrs=HOST, confirm=lambda p: True).signals == []


def test_unreadable_firewall_rules_are_a_stated_gap_not_a_clean_bill():
    j = J.judge(inv(ctr("web", ports=PUBLISHED), firewall=False), host_addrs=HOST)
    assert [s["rule"] for s in j.signals] == ["CONT-008"]
    assert any("can't tell" in g for g in j.gaps)


def test_over_ssh_the_engine_is_not_read_and_capabilities_are_judged_from_proc():
    procs = {5: {"engine": "docker", "container": CID, "uid": 0, "capeff": "00000000a82435fb", "ppid": 1, "comm": "sleep"},
             6: {"engine": "docker", "container": "2" * 64, "uid": 0, "capeff": "00000000a80425fb", "ppid": 1, "comm": "sh"}}
    doc = inv(firewall=False, via="ssh", procs=procs,
              engines=[{"engine": "docker", "socket": "/run/docker.sock", "state": "not_read", "detail": ""}])
    doc["containers"] = {}
    j = J.judge(doc, host_addrs=HOST)
    assert rules(j) == [("CONT-006", "high", CID[:12]), ("CONT-008", "info", "")]
    gap = " ".join(j.gaps)
    assert "sub-agent" in gap and "never asks for the docker group" in gap


def test_rootless_podman_with_its_socket_off_is_stated():
    procs = {9: {"engine": "podman", "container": CID, "uid": 1000, "capeff": "0", "ppid": 1, "comm": "sleep",
                 "rootless_owner": 1000}}
    j = J.judge(inv(procs=procs), host_addrs=HOST)
    assert any("rootless Podman containers of user 1000" in g and "podman.socket" in g for g in j.gaps)
    doc = inv(procs=procs, engines=[{"engine": "podman-rootless:1000", "socket": "/run/user/1000/podman/podman.sock",
                                     "state": "ok", "detail": "5.4"}])
    assert not any("rootless" in g for g in J.judge(doc, host_addrs=HOST).gaps)


def test_no_engine_is_nothing_but_one_line(tmp_path):
    doc = R.run(tmp_path, "192.0.2.10", reader=lambda: {"via": "agent", "complete": True, "engines": [],
                                                         "containers": {}, "procs": {}, "firewall": {}})
    assert doc["engines_found"] is False and doc["signals"] == []
    assert R.summary_line(doc) == "no container engine found"


def test_the_snapshot_is_one_file_per_machine_replaced_in_place(tmp_path):
    reader = lambda: inv(ctr("p", privileged=True))
    a = R.run(tmp_path, "192.0.2.10", reader=reader, connect=lambda a, p: True)
    b = R.run(tmp_path, "192.0.2.10", reader=reader, connect=lambda a, p: True)
    c = R.run(tmp_path, "192.0.2.11", reader=reader, connect=lambda a, p: True)
    assert a["file"] == b["file"] != c["file"]
    assert len(list((tmp_path / "containers").glob("containers_*.json"))) == 2


def test_a_failed_read_saves_nothing(tmp_path):
    from kratos.adapters.ssh_remote import SSHResult

    doc = R.run(tmp_path, "192.0.2.10", reader=lambda: SSHResult(False, 255, "", "no route"))
    assert doc["status"] == "error" and not (tmp_path / "containers").exists()


def test_the_connect_sends_no_byte():
    got = []
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def accept():
        conn, _ = srv.accept()
        conn.settimeout(2)
        try:
            got.append(conn.recv(10))
        finally:
            conn.close()
    t = threading.Thread(target=accept)
    t.start()
    assert R.tcp_connect("127.0.0.1", srv.getsockname()[1]) is True
    t.join(5)
    srv.close()
    assert got == [b""]
    assert R.tcp_connect("127.0.0.1", 1) is False


def test_the_digest_line_names_counts_and_ports_but_no_machine_text(tmp_path):
    doc = R.run(tmp_path, "192.0.2.10", reader=lambda: inv(ctr("evil‮name", ports=PUBLISHED, privileged=True)),
                connect=lambda a, p: True)
    line = R.summary_line(doc)
    assert line.startswith("1 running container(s)") and "8080/tcp" in line and "1 confirmed" in line
    assert "evil" not in line and "nginx" not in line and "1 privileged" in line


# --------------------------------------------------------------------------- findings + lifecycle
def _correlate(tmp_path, target):
    from kratos import kratos_config, run_context
    from kratos.adapters import findings_engine as FE

    kratos_config.set_active_target(target)
    with run_context.run_scope("cli"):
        out_json, _md = FE.write_findings_report(tmp_path)
    return json.loads(Path(out_json).read_text())


def _states(tmp_path):
    from kratos.lifecycle import store

    with store.opened(tmp_path) as conn:
        return {(r["rule_id"], r["subject"]): r["state"] for r in conn.execute("SELECT * FROM finding_records")}


def test_cont_findings_reach_the_report_with_their_fix_and_close_on_a_fresh_complete_read(tmp_path):
    t = "192.0.2.10"
    R.run(tmp_path, t, reader=lambda: inv(ctr("web", ports=PUBLISHED), ctr("p", privileged=True)),
          connect=lambda a, p: True)
    rep = _correlate(tmp_path, t)
    f = {x["id"]: x for x in rep["findings"]}
    assert set(f) >= {"CONT-001", "CONT-004"}
    assert f["CONT-004"]["fix"] and f["CONT-004"]["attack"] == []
    assert _states(tmp_path)[("CONT-001", "p")] == "open"
    R.run(tmp_path, t, reader=lambda: inv(ctr("web", ports=PUBLISHED)), connect=lambda a, p: True)
    _correlate(tmp_path, t)
    assert _states(tmp_path)[("CONT-001", "p")] == "mitigated"


def test_an_ssh_read_does_not_close_a_setting_seen_through_the_agent(tmp_path):
    t = "192.0.2.10"
    R.run(tmp_path, t, reader=lambda: inv(ctr("p", privileged=True)), connect=lambda a, p: True)
    _correlate(tmp_path, t)
    ssh = inv(via="ssh", firewall=False, engines=[{"engine": "docker", "socket": "/run/docker.sock",
                                                   "state": "not_read", "detail": ""}])
    ssh["containers"] = {}
    R.run(tmp_path, t, reader=lambda: ssh)
    _correlate(tmp_path, t)
    assert _states(tmp_path)[("CONT-001", "p")] == "open"


# --------------------------------------------------------------------------- found on the lab
def test_only_the_bypassed_family_is_marked_and_ipv6_shows_in_brackets():
    j = J.judge(inv(ctr("web", ports=PUBLISHED)), host_addrs=HOST, confirm=lambda p: True)
    assert j.rows[0]["ports"] == ["0.0.0.0:8080->80/tcp (reachable despite firewall)", "[::]:8080->80/tcp"]


def test_the_firewall_named_is_the_one_that_refused_the_port():
    assert J.firewall_name({}, "table inet hostfw chain input policy drop") == "the nftables firewall (table hostfw)"
    assert J.firewall_name({"firewall": {"iptables": {"text": "-A ufw-user-input -p tcp --dport 22 -j ACCEPT"}}},
                           "filter/INPUT policy DROP") == "ufw"
    # ufw disabled leaves its empty chains behind: not ufw
    assert J.firewall_name({"firewall": {"iptables": {"text": ":ufw-user-input - [0:0]"}}}, "filter/INPUT policy DROP") \
        == "the firewall"


def test_model_facts_never_call_a_container_a_package():
    from kratos import finding_facts as FF

    cont = {"id": "CONT-004", "severity": "high", "subject": "web", "entities": ["image:sha256:" + "d" * 64,
                                                                            "port:8080/tcp"]}
    assert FF.safe_facts(cont) == ["port 8080/tcp", "confirmed reachable from Kratos"]
    img = {"id": "PKG-001", "subject": "shop/web:2:openssl", "entities": ["CVE-2024-0001", "container:web"]}
    assert FF.safe_facts(img)[0] == "package openssl (inside a container image)"
    assert "web" not in " ".join(FF.safe_facts({"id": "CONT-001", "subject": "web", "entities": ["privileged"]}))


def test_journal_reads_keep_the_fields_that_say_which_container_wrote_a_line():
    from kratos.logsources import logread

    assert {"CONTAINER_ID_FULL", "CONTAINER_NAME", "IMAGE_NAME"} <= set(logread.JOURNAL_FIELDS)
    assert "_COMM=dockerd" in " ".join(logread.journal_sync_argv("container", None, 0.0))
