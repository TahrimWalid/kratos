"""E.7b exposure of the serving process (§3.4): internet > network > local > unknown, and a
root whose serving process isn't running ranks last."""
from __future__ import annotations

from kratos.review import exposure as EXP


def test_internet_public_address():
    assert EXP.root_exposure([{"address": "203.0.113.5", "pid": 1}], []) == EXP.INTERNET


def test_network_private_address():
    assert EXP.root_exposure([{"address": "10.0.0.5", "pid": 1}], []) == EXP.NETWORK


def test_local_loopback():
    assert EXP.root_exposure([{"address": "127.0.0.1", "pid": 1}], []) == EXP.LOCAL


def test_wildcard_internet_when_machine_public():
    assert EXP.root_exposure([{"address": "0.0.0.0", "pid": 1}], ["198.51.100.9"]) == EXP.INTERNET


def test_wildcard_network_without_public():
    assert EXP.root_exposure([{"address": "0.0.0.0", "pid": 1}], ["10.1.1.1"]) == EXP.NETWORK


def test_not_running_when_no_serving():
    assert EXP.root_exposure([], []) == EXP.NOT_RUNNING
    assert EXP.root_exposure(None, []) == EXP.NOT_RUNNING


def test_running_false_overrides():
    assert EXP.root_exposure([{"address": "203.0.113.5", "pid": 1}], [], running=False) == EXP.NOT_RUNNING


def test_unknown_when_unparseable():
    assert EXP.root_exposure([{"address": "???", "pid": 1}], []) == EXP.UNKNOWN


def test_most_exposed_wins():
    serving = [{"address": "127.0.0.1", "pid": 1}, {"address": "203.0.113.5", "pid": 2}]
    assert EXP.root_exposure(serving, []) == EXP.INTERNET
