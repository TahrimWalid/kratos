"""The sub-agent bundle's own tests, runnable with nothing but the standard library.

A monitored machine runs the agent with its system python3 -- as old as 3.8, with no
third-party packages. CI's `agent-bundle` job runs this file there
(`python3.8 -I -S -m unittest`, via scripts/ci/agent_bundle.py check); pytest runs it
too, on the bundle built from the same repository files. unittest only: no pytest,
no kratos import.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path


def _bundle_parent() -> str:
    given = os.environ.get("KRATOS_AGENT_BUNDLE_DIR")
    if given:
        return given
    here = Path(__file__).resolve()
    spec = importlib.util.spec_from_file_location("_agent_bundle_builder",
                                                  here.parents[2] / "scripts" / "ci" / "agent_bundle.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    tmp = tempfile.mkdtemp(prefix="kratos-bundle-test-")
    mod.build(Path(tmp))
    return tmp


_PARENT = _bundle_parent()
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

agent = importlib.import_module("subagent.agent")
ceiling = importlib.import_module("subagent.ceiling")
protocol = importlib.import_module("subagent.protocol")
reads = importlib.import_module("subagent.reads")
signing = importlib.import_module("subagent.signing")


class BundleBasics(unittest.TestCase):
    def test_it_is_the_bundle_not_the_kratos_package(self):
        self.assertTrue(agent.__file__.startswith(_PARENT), agent.__file__)
        if "pytest" not in sys.modules:  # under pytest the suite itself imported kratos
            self.assertNotIn("kratos", sys.modules)

    def test_agent_version_and_command_line(self):
        self.assertRegex(agent.AGENT_VERSION, r"^\d+\.\d+\.\d+$")
        args = agent.build_arg_parser().parse_args(["--core-host", "100.64.0.10", "--core-port", "8765"])
        self.assertEqual(args.core_host, "100.64.0.10")

    def test_every_bundle_module_imports(self):
        pkg = Path(_PARENT) / "subagent"
        for py in sorted(pkg.glob("*.py")):
            if py.stem != "__init__":
                importlib.import_module("subagent." + py.stem)


class Protocol(unittest.TestCase):
    def test_a_frame_round_trips_over_a_socket(self):
        a, b = socket.socketpair()
        try:
            msg = protocol.build_ping(123.5)
            protocol.send_frame_sync(a, msg)
            self.assertEqual(protocol.recv_frame_sync(b), msg)
        finally:
            a.close()
            b.close()

    def test_an_oversized_frame_is_refused(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.encode_frame({"type": "x", "blob": "a" * (protocol.MAX_FRAME_BYTES + 1)})


class Signing(unittest.TestCase):
    def test_a_signed_envelope_verifies_and_a_changed_one_does_not(self):
        key = signing.derive_signing_key("token-123")
        env = {"type": "exec_dispatch", "seq": 7, "action": "fail2ban.ban_ip"}
        env["sig"] = signing.sign_envelope(key, env)
        self.assertTrue(signing.verify_envelope(key, env))
        env["seq"] = 8
        self.assertFalse(signing.verify_envelope(key, env))
        self.assertFalse(signing.verify_envelope(signing.derive_signing_key("other"), dict(env, seq=7)))


class Ceiling(unittest.TestCase):
    def test_a_shell_is_never_within_the_ceiling(self):
        with self.assertRaises(ceiling.CeilingError):
            ceiling.match_argv(["sh", "-c", "id"])

    def test_a_command_line_parses_without_a_shell(self):
        self.assertEqual(ceiling.parse_command_line("adduser --disabled-password alice"),
                         ["adduser", "--disabled-password", "alice"])


class Reads(unittest.TestCase):
    """Each read runs on this Python and answers with a status -- never an exception.
    Reads needing tools the test machine lacks (journalctl, yara) report that."""

    def _status(self, probe, params):
        out = reads.run_probe(probe, params)
        self.assertIsInstance(out, dict)
        self.assertIn(out.get("status"), ("ok", "not_installed", "error", "timed_out", "refused"), out)
        return out

    def test_the_basic_reads_work(self):
        for probe in ("clock", "file_hashes", "processes"):
            self.assertEqual(self._status(probe, {})["status"], "ok", probe)

    def test_the_heavier_reads_answer(self):
        self._status("config_audit", {})
        self._status("privileged_accounts", {"since": time.time() - 86400})
        self._status("measure_auth", {"start": int(time.time()) - 3600, "granularity": 60})
        self._status("journal_fetch", {"lines": 2})

    def test_an_unknown_read_is_unsupported(self):
        self.assertEqual(reads.run_probe("rm_rf", {})["status"], "unsupported")

    def test_bad_parameters_are_refused(self):
        self.assertEqual(reads.run_probe("journal_fetch", {"lines": "all; id"})["status"], "refused")

    def test_the_starter_rules_ship_with_the_bundle(self):
        files = reads.yara_rule_files("bundled")[0]
        self.assertTrue(any(str(p).endswith("MALW_Eicar.yar") for p in files), files)


if __name__ == "__main__":
    unittest.main()
