"""C.3: what a person hunts for -- strict classification, normalisation, refusals."""
import pytest

from kratos.hunt import front
from kratos.hunt import indicators as I

SHA = "ab" * 32


@pytest.mark.parametrize("typed,kind,value", [
    ("198.51.100.7", "ip", "198.51.100.7"),
    ("2001:DB8:0:0::1", "ip", "2001:db8::1"),
    ("198.51.100.0/24", "ip", "198.51.100.0/24"),
    ("198.51.100.9/24", "ip", "198.51.100.0/24"),          # host bits allowed, network normalised
    ("2001:db8::/32", "ip", "2001:db8::/32"),
    ("198.51.100.7/32", "ip", "198.51.100.7"),            # a /32 is one address
    (SHA.upper(), "sha256", SHA),
    ("Evil.Example.COM.", "domain", "evil.example.com"),
    ("/tmp/x/", "path", "/tmp/x"),
    ("/usr/bin/nc", "path", "/usr/bin/nc"),
    ("svc$", "account", "svc$"),                          # only an account can end in $
])
def test_each_kind_is_detected_and_normalised(typed, kind, value):
    got = I.classify(typed)
    assert isinstance(got, I.Indicator)
    assert (got.kind, got.value) == (kind, value)


@pytest.mark.parametrize("typed,options", [
    ("alice", ("account", "program")),
    ("update.sh", ("domain", "program")),
    ("python3.10", ("account", "program")),               # numeric last label: not a domain
])
def test_ambiguous_asks(typed, options):
    got = I.classify(typed)
    assert isinstance(got, I.Ambiguous)
    assert got.options == options
    assert typed in got.question()


def test_forced_type_settles_ambiguity_and_validates():
    assert I.classify("alice", "account").kind == "account"
    assert I.classify("alice", "user").kind == "account"
    assert I.classify("update.sh", "program").value == "update.sh"
    assert I.classify("web01", "host").value == "web01"   # a one-label host name only when forced
    with pytest.raises(I.IndicatorError):
        I.classify("not an ip", "ip")
    with pytest.raises(I.IndicatorError, match="unknown type"):
        I.classify("x", "colour")


@pytest.mark.parametrize("typed,word", [("a" * 32, "MD5"), ("b" * 40, "SHA-1")])
def test_md5_and_sha1_are_refused_with_the_reason(typed, word):
    with pytest.raises(I.IndicatorError) as e:
        I.classify(typed)
    assert word in str(e.value) and "SHA-256 hashes only" in str(e.value)
    with pytest.raises(I.IndicatorError, match="SHA-256 hashes only"):
        I.classify(typed, "sha256")


@pytest.mark.parametrize("typed", ["198.51.100.999", "1.2.3.4.5", "", "a b", "x\x1b[31m", "relative/path", "a" * 2000])
def test_garbage_is_refused(typed):
    with pytest.raises(I.IndicatorError):
        I.classify(typed)


def test_cidr_network_and_membership():
    ind = I.classify("203.0.113.0/28")
    assert ind.is_cidr and ind.network.num_addresses == 16
    assert not I.classify("203.0.113.5").is_cidr


def test_parse_many_dedupes_and_caps():
    p = I.parse("198.51.100.7, 198.51.100.7 alice")
    assert [i.value for i in p.indicators] == ["198.51.100.7"] and len(p.ambiguous) == 1
    with pytest.raises(I.IndicatorError, match="at most"):
        I.parse(" ".join(f"198.51.100.{i}" for i in range(11)))


def test_command_words_and_options():
    req = front.parse_command("198.51.100.7 --since 30d --machine web01 --machine db01 --type ip")
    assert req.words == ["198.51.100.7"] and req.since == "30d" and req.machines == ["web01", "db01"]
    with pytest.raises(front.HuntUsageError):
        front.parse_command("")
    with pytest.raises(front.HuntUsageError, match="unknown option"):
        front.parse_command("x --bogus 1")
    assert front.time_bound("24h") < front.time_bound("1h")


def test_scope_refuses_a_machine_outside_it():
    req = front.parse_command("198.51.100.7 --machine db01")
    with pytest.raises(front.HuntUsageError, match="not a machine you may search"):
        front.resolve_hunt(req, scope=["web01"])
    assert front.resolve_hunt(front.parse_command("198.51.100.7"), scope=["WEB01"]).machines == ["web01"]
