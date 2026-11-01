"""D.3 exposure: the reason names the listener that decided it, a wildcard listener
reaches only public addresses of its own family, and a scan target given by name is
judged by the address the scan reached."""
from __future__ import annotations

from kratos.ssvc import exposure as X
from kratos.ssvc.attach import _listening_fact


def _live(listeners, addresses):
    return {"checked_at": "2026-11-01T00:00:00+00:00", "via": "subagent", "maps_read": True, "reader_uid": 0,
            "listeners": listeners, "local_addresses": addresses, "running_packages": []}


def _listener(address, port, package="nginx"):
    return {"seen": True, "package": package, "address": address, "port": port, "exe": "/usr/sbin/nginx",
            "lib_packages": []}


def test_the_kernel_reason_names_the_listener_that_made_it_internet_facing():
    # first a tailnet-only listener, then one on every address of a machine with a public address
    live = _live([_listener("100.64.0.7", 45007), _listener("0.0.0.0", 22, "openssh-server")],
                 ["203.0.113.7", "100.64.0.7"])
    ex = X.machine_highest(live)
    assert ex.value == X.INTERNET
    assert "0.0.0.0:22" in ex.reason and "45007" not in ex.reason
    assert _listening_fact({"exposure": ex.to_dict()}).startswith("listening on 0.0.0.0:22")


def test_the_package_reason_names_the_listener_that_made_it_internet_facing():
    live = _live([_listener("10.0.0.5", 8080), _listener("203.0.113.7", 443)], ["203.0.113.7", "10.0.0.5"])
    ex = X.for_packages(["nginx"], live)
    assert ex.value == X.INTERNET
    assert "203.0.113.7:443" in ex.reason and "8080" not in ex.reason


def test_an_ipv4_wildcard_listener_is_not_internet_facing_through_a_public_ipv6_address():
    live = _live([_listener("0.0.0.0", 443)], ["10.0.0.5", "2001:db8::7"])
    assert X.for_packages(["nginx"], live).value == X.NETWORK


def test_an_ipv6_wildcard_listener_reaches_public_addresses_of_both_families():
    assert X.for_packages(["nginx"], _live([_listener("::", 443)], ["2001:db8::7"])).value == X.INTERNET
    assert X.for_packages(["nginx"], _live([_listener("::", 443)], ["203.0.113.7"])).value == X.INTERNET


def test_a_scan_target_given_by_name_is_judged_by_the_address_the_scan_reached():
    ex = X.for_scanned_ports([443], "web.example.com", addresses=["203.0.113.7"])
    assert ex.value == X.INTERNET and "203.0.113.7 is a public address" in ex.reason
    ex = X.for_scanned_ports([443], "web.example.com", addresses=["10.0.0.5"])
    assert ex.value == X.NETWORK and "not public" in ex.reason


def test_a_scan_target_given_by_name_with_no_address_says_it_does_not_know():
    ex = X.for_scanned_ports([443], "web.example.com")
    assert ex.value == X.NETWORK
    assert "web.example.com" in ex.reason and "not known" in ex.reason
    assert "the address it scanned is not public" not in ex.reason


def test_vulnerability_findings_take_the_address_from_the_scan():
    from kratos.ssvc.attach import _vuln_ports

    scan = {"findings": [{"source": "vulscan", "host": "203.0.113.7", "port": "443", "cve_ids": ["CVE-2024-0001"]},
                         {"source": "vulscan", "host": "203.0.113.7", "port": "80", "cve_ids": ["CVE-2024-0002"]}]}
    assert _vuln_ports(scan, {"CVE-2024-0001"}) == (["443"], ["203.0.113.7"])
