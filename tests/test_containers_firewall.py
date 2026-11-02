"""The firewall model behind CONT-004 (D.5 §3.3): published-port traffic vs the firewall,
per backend and per IP family; anything the model doesn't understand is "can't tell"."""
from __future__ import annotations

import json

import pytest

from kratos.containers import firewall as F

# The shape Docker 29 (iptables backend) and ufw (default deny incoming) leave, as
# iptables-save prints it -- trimmed to the chains on the paths that matter.
IPT_UFW_DOCKER = """\
*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A PREROUTING -d 172.17.0.2/32 ! -i docker0 -j DROP
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:DOCKER-BRIDGE - [0:0]
:DOCKER-CT - [0:0]
:DOCKER-FORWARD - [0:0]
:DOCKER-INTERNAL - [0:0]
:DOCKER-USER - [0:0]
:ufw-before-input - [0:0]
:ufw-user-input - [0:0]
:ufw-not-local - [0:0]
:ufw-after-input - [0:0]
:ufw-skip-to-policy-input - [0:0]
:ufw-logging-deny - [0:0]
:ufw-after-logging-input - [0:0]
:ufw-before-forward - [0:0]
:ufw-user-forward - [0:0]
-A INPUT -j ufw-before-input
-A INPUT -j ufw-after-input
-A INPUT -j ufw-after-logging-input
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A FORWARD -j ufw-before-forward
-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
-A DOCKER ! -i docker0 -o docker0 -j DROP
-A DOCKER-BRIDGE -o docker0 -j DOCKER
-A DOCKER-CT -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-FORWARD -j DOCKER-CT
-A DOCKER-FORWARD -j DOCKER-INTERNAL
-A DOCKER-FORWARD -j DOCKER-BRIDGE
-A DOCKER-FORWARD -i docker0 -j ACCEPT
-A ufw-after-input -p tcp -m tcp --dport 139 -j ufw-skip-to-policy-input
-A ufw-after-input -m addrtype --dst-type BROADCAST -j ufw-skip-to-policy-input
-A ufw-after-logging-input -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW BLOCK] "
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -p icmp -m icmp --icmp-type 3 -j ACCEPT
-A ufw-before-forward -j ufw-user-forward
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP
-A ufw-before-input -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A ufw-before-input -p udp -m udp --sport 67 --dport 68 -j ACCEPT
-A ufw-before-input -j ufw-not-local
-A ufw-before-input -j ufw-user-input
-A ufw-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW BLOCK] "
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP
-A ufw-skip-to-policy-input -j DROP
-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
"""

HOST = "192.0.2.10"


def _rs(v4: str = IPT_UFW_DOCKER, v6: str | None = None, nft: dict | None = None) -> F.Ruleset:
    fw = {"iptables": {"status": "ok", "text": v4}}
    if v6 is not None:
        fw["ip6tables"] = {"status": "ok", "text": v6}
    if nft is not None:
        fw["nft"] = {"status": "ok", "text": json.dumps(nft)}
    return F.ruleset_from(fw)


def _judge(rs, family=4, host_port=8080, forwarded=True, in_iface="eth0", container_ip="172.17.0.2"):
    return F.judge_port(rs, family=family, proto="tcp", host_port=host_port, container_port=80,
                        container_ip=container_ip, bridge="docker0", host_addr=HOST if family == 4 else "2001:db8::10",
                        in_iface=in_iface, forwarded=forwarded)


def _with_user(*rules: str) -> str:
    return IPT_UFW_DOCKER.replace("-A FORWARD -j DOCKER-USER", "-A FORWARD -j DOCKER-USER\n" + "\n".join(rules))


def test_ufw_deny_and_no_docker_user_rule_is_a_bypass():
    j = _judge(_rs())
    assert j.bypass == "yes"
    assert j.forward.verdict == "accept" and "--dport 80 -j ACCEPT" in j.forward.where
    assert j.input.verdict == "drop" and "policy DROP" in j.input.where


def test_a_docker_user_drop_for_the_port_closes_it():
    rs = _rs(_with_user("-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
                        "-A DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -j DROP"))
    j = _judge(rs)
    assert j.bypass == "no" and j.forward.verdict == "drop" and "8080" in j.forward.where
    assert _judge(rs, host_port=9090).bypass == "yes"          # a rule for another port doesn't count


def test_a_docker_user_drop_on_another_interface_does_not_count():
    assert _judge(_rs(_with_user("-A DOCKER-USER -i eth9 -j DROP"))).bypass == "yes"


def test_a_source_allow_list_then_drop_blocks_the_internet():
    rs = _rs(_with_user("-A DOCKER-USER -s 10.0.0.0/8 -j RETURN", "-A DOCKER-USER -i eth0 -j DROP"))
    assert _judge(rs).bypass == "no"


def test_an_unknown_match_is_cant_tell_never_allowed():
    j = _judge(_rs(_with_user("-A DOCKER-USER -m set --match-set blocked src -j DROP")))
    assert j.bypass == "unknown" and j.forward.verdict == "unknown" and "--match-set" in j.forward.reason


def test_an_unknown_interface_name_is_cant_tell_unless_it_is_a_bridge_or_loopback():
    rs = _rs(_with_user("-A DOCKER-USER -i eth0 -j DROP"))
    assert _judge(rs, in_iface=None).bypass == "unknown"
    assert _judge(_rs(_with_user("-A DOCKER-USER -i docker0 -j DROP")), in_iface=None).bypass == "yes"


def test_a_port_the_firewall_allows_on_input_is_meant_to_be_open():
    rs = _rs(IPT_UFW_DOCKER.replace("-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT",
                                    "-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT\n"
                                    "-A ufw-user-input -p tcp -m tcp --dport 8080 -j ACCEPT"))
    j = _judge(rs)
    assert j.bypass == "no" and j.input.verdict == "accept"


def test_no_firewall_at_all_is_open_not_a_bypass():
    rs = _rs("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n")
    assert _judge(rs).bypass == "no"


def test_ipv6_on_a_network_without_ipv6_is_proxied_and_input_decides():
    v6 = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\nCOMMIT\n"
    j = _judge(_rs(v6=v6), family=6, forwarded=False, container_ip=None)
    assert j.bypass == "no" and j.path == "proxied" and j.input.verdict == "drop"


def test_ipv6_is_judged_on_its_own_rules_when_forwarded():
    v6 = IPT_UFW_DOCKER.replace("172.17.0.2/32", "fd00::2/128").replace("-A raw", "-A raw")
    rs = _rs(v6=v6)
    assert _judge(rs, family=6, container_ip="fd00::2").bypass == "yes"
    v6_closed = v6.replace("-A FORWARD -j DOCKER-USER", "-A FORWARD -j DOCKER-USER\n-A DOCKER-USER -i eth0 -p tcp "
                                                         "-m conntrack --ctorigdstport 8080 -j DROP")
    assert _judge(_rs(v6=v6_closed), family=6, container_ip="fd00::2").bypass == "no"
    # the IPv4 rules say nothing about IPv6
    assert _judge(_rs(v4=_with_user("-A DOCKER-USER -j DROP"), v6=v6), family=6, container_ip="fd00::2").bypass == "yes"


def test_unreadable_rules_are_cant_tell():
    rs = F.ruleset_from({"iptables": {"status": "denied", "text": ""}})
    assert _judge(rs).bypass == "unknown"


# --------------------------------------------------------------------------- nftables backend
def _chain(family, table, name, hook=None, prio=None, policy="accept"):
    c = {"family": family, "table": table, "name": name}
    if hook:
        c.update({"type": "filter", "hook": hook, "prio": prio, "policy": policy})
    return {"chain": c}


def _rule(family, table, chain, *expr):
    return {"rule": {"family": family, "table": table, "chain": chain, "expr": list(expr)}}


def _m(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


NFT_DOCKER = {"nftables": [
    {"metainfo": {"version": "1.0.9"}},
    _chain("ip", "docker-bridges", "filter-FORWARD", "forward", 0),
    _rule("ip", "docker-bridges", "filter-FORWARD", {"accept": None}),
]}
NFT_INPUT_DENY = [_chain("inet", "host-fw", "input", "input", 0, "drop"),
                  _rule("inet", "host-fw", "input", _m({"meta": {"key": "iifname"}}, "lo"), {"accept": None}),
                  _rule("inet", "host-fw", "input", _m({"ct": {"key": "state"}}, ["established", "related"], "in"),
                        {"accept": None}),
                  # seen on the lab: an icmp match is simply false for a TCP packet, not "can't tell"
                  _rule("inet", "host-fw", "input", _m({"payload": {"protocol": "icmp", "field": "type"}},
                                                        "echo-request"), {"accept": None}),
                  _rule("inet", "host-fw", "input", _m({"payload": {"protocol": "tcp", "field": "dport"}}, 22),
                        {"accept": None})]


def _nft(*extra):
    return {"nftables": [*NFT_DOCKER["nftables"], *NFT_INPUT_DENY, *extra]}


def test_nftables_without_a_user_forward_table_is_a_bypass():
    rs = F.ruleset_from({"nft": {"status": "ok", "text": json.dumps(_nft())}}, "nftables")
    j = _judge(rs)
    assert j.bypass == "yes" and j.input.verdict == "drop"


def test_nftables_a_user_forward_chain_dropping_it_closes_it_at_any_priority():
    for prio in (-10, 10):
        guard = [_chain("inet", "guard", "forward", "forward", prio),
                 _rule("inet", "guard", "forward", _m({"meta": {"key": "iifname"}}, "eth0"),
                       _m({"meta": {"key": "l4proto"}}, "tcp"),
                       _m({"ct": {"key": "proto-dst", "dir": "original"}}, 8080), {"drop": None})]
        rs = F.ruleset_from({"nft": {"status": "ok", "text": json.dumps(_nft(*guard))}}, "nftables")
        j = _judge(rs)
        assert j.bypass == "no" and j.forward.verdict == "drop", prio


def test_nftables_an_unknown_expression_is_cant_tell():
    odd = [_chain("inet", "guard", "forward", "forward", -10),
           _rule("inet", "guard", "forward", _m({"payload": {"protocol": "ip", "field": "saddr"}}, "@blocklist"),
                 {"drop": None})]
    rs = F.ruleset_from({"nft": {"status": "ok", "text": json.dumps(_nft(*odd))}}, "nftables")
    assert _judge(rs).bypass == "unknown"


def test_nftables_tables_iptables_nft_keeps_are_left_to_the_iptables_walk():
    ipt_tables = [_chain("ip", "filter", "FORWARD", "forward", 0, "drop"),
                  _rule("ip", "filter", "FORWARD", {"xt": {"type": "match", "name": "conntrack"}}, {"accept": None})]
    rs = F.ruleset_from({"iptables": {"status": "ok", "text": IPT_UFW_DOCKER},
                         "nft": {"status": "ok", "text": json.dumps(_nft(*ipt_tables))}})
    assert _judge(rs).bypass == "yes"          # the xt rule was not judged twice (and wrongly)


def test_parse_iptables_save_reads_policies_rules_and_negations():
    t = F.parse_iptables_save(IPT_UFW_DOCKER)
    assert t["filter"]["INPUT"].policy == "DROP" and t["filter"]["DOCKER"].policy is None
    r = t["filter"]["DOCKER"].rules[0]
    assert r.target == "ACCEPT" and ("-i", True, ["docker0"]) in r.conds


@pytest.mark.parametrize("spec,port,ok", [("8080", 8080, True), ("8000:8100", 8080, True), ("1024:", 8080, True),
                                          (":1023", 8080, False), ("80,443,8080", 8080, True), ("9090", 8080, False)])
def test_port_specs(spec, port, ok):
    assert F._port_in(port, spec) is ok
