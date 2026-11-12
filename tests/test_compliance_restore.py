"""E.2 data travels with a backup (D.8): results, owners, 'not applicable' decisions and the
CIS level come back on a new computer; the mapping is package data, nothing to restore."""
from __future__ import annotations

import time

import _backup_helpers as H

from kratos.backup import create as CR
from kratos.backup import restore as RS
from kratos.compliance import owners as O
from kratos.compliance import record, report as RP
from kratos.compliance import store
from kratos.lifecycle.decide import Actor

from tests.test_compliance import good_hardening

OWNER = Actor("owner", "cli")


def test_compliance_data_is_restored(tmp_path):
    r = H.home(tmp_path, "old")
    H.seed(r)
    h = good_hardening()
    h["stat"]["/etc/crontab"]["mode"] = 0o666
    record.run(r.data, "10.0.0.5", fetch=lambda: dict(h, via="ssh"), now=time.time())
    O.set_owner(r.data, OWNER, "cis", "2.4.1.2", "machine:10.0.0.5", "alice", due="2027-01-01")
    O.set_na(r.data, OWNER, "iso27001", "8.17", "all", "the host keeps the time", 90)
    O.set_level(r.data, OWNER, "10.0.0.5", "2")
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    new = H.home(tmp_path, "new")
    RS.restore(res.file, [ident], roots=new, actor=H.CLI, accept_signer=H.signer_of(res.file))
    assert store.latest_run(new.data, "10.0.0.5") is not None
    assert O.owners_for(new.data, "cis", "10.0.0.5")["2.4.1.2"].name == "alice"
    assert ("iso27001", "8.17") in O.na_for(new.data, "iso27001", "10.0.0.5")
    assert O.level_for(new.data, "10.0.0.5") == "l2_server"
    assert [e["kind"] for e in store.events(new.data)][:3] == ["level_set", "na_set", "owner_set"]
    doc = RP.build(new.data, "cis", ["10.0.0.5"])
    ctl = {c["control"]: c for c in doc["machines"][0]["controls"]}
    assert ctl["2.4.1.2"]["status"] == "fail" and ctl["2.4.1.2"]["owner"].startswith("alice")
