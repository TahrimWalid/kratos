"""`kratos channels`, `kratos outbox`, `kratos signing` (D.4).

    kratos channels list
    kratos channels add webhook <NAME> --url URL [--format kratos|ocsf|ecs] [--framing json|ndjson|es_bulk|hec]
    kratos channels add syslog <NAME> --host HOST [--port 6514] [--format text|ocsf|ecs]
    kratos channels add email <NAME> --host HOST --from A --to A,B [--security starttls|tls] [--username U]
    kratos channels show|test|enable|disable|remove <NAME>
    kratos channels edit <NAME> [the same options]
    kratos channels secret <NAME> signing|auth|password|client-key (--stdin | --generate | --clear)
    kratos outbox [list] [--status S] [--channel C]
    kratos outbox show <ID> | retry <ID>... | retry --dead [--channel C] | flush | prune [--apply]
    kratos signing status | rotate

Secrets are never taken from the command line (it ends up in your shell history): they
are read from standard input, or generated. A generated webhook signing secret is
printed once, to set up the receiver with.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from kratos.untrusted import safe_print as print

_FILTER_HELP = "Only send findings / alerts that match (repeat options combine)"


def _filters(sp: argparse.ArgumentParser) -> None:
    g = sp.add_argument_group("filters", _FILTER_HELP)
    g.add_argument("--min-severity", choices=("info", "low", "medium", "high", "critical"))
    g.add_argument("--min-ssvc", choices=("track", "track*", "attend", "act"),
                   help="Vulnerability findings only from this SSVC decision up")
    g.add_argument("--rules", default=None, help="Rule id prefixes, comma separated (e.g. PKG-,CORR-SSH)")
    g.add_argument("--machines", default=None, help="Only these machines (comma separated)")
    g.add_argument("--groups", default=None, help="Only machines in these groups (comma separated)")
    g.add_argument("--only-new-or-worse", action="store_true", default=None,
                   help="Findings: only new, worse, back and reopened ones (not fixes or decisions)")


def _common(sp: argparse.ArgumentParser, kind: str) -> None:
    scopes = {"webhook": "alerts,findings,events", "syslog": "alerts,findings,events", "email": "alerts,findings"}[kind]
    sp.add_argument("--scope", default=None, help=f"What it receives, comma separated: {scopes} (default alerts)")
    sp.add_argument("--max-per-minute", type=int, default=None, help="Send at most this many messages a minute "
                                                                    "(default 60; the rest wait their turn)")
    sp.add_argument("--mask-values", action="store_true", default=None,
                    help="Replace account names, addresses and host names with placeholders before sending")
    sp.add_argument("--ca-file", default=None, help="Trust this CA (a PEM file) for the receiver's certificate "
                                                    "instead of the system's CAs")
    _filters(sp)


def add_parser(sub: Any) -> None:
    ch = sub.add_parser("channels", help="Where Kratos sends what it finds: webhooks, syslog (TLS), email, ntfy, "
                                         "a SIEM (OCSF / ECS)")
    cs = ch.add_subparsers(dest="channels_action", required=True)
    cs.add_parser("list", help="Every channel: what it receives, where it sends, how delivery is going")
    add = cs.add_parser("add", help="Add a webhook, syslog or email channel")
    ks = add.add_subparsers(dest="kind", required=True)
    wh = ks.add_parser("webhook", help="HTTPS POST signed per Standard Webhooks (a SIEM's HTTP collector too)")
    wh.add_argument("name")
    wh.add_argument("--url", required=True)
    wh.add_argument("--format", choices=("kratos", "ocsf", "ecs"), default=None)
    wh.add_argument("--framing", choices=("json", "ndjson", "es_bulk", "hec"), default=None,
                    help="json (one document or array), ndjson, es_bulk (Elasticsearch/OpenSearch _bulk), "
                         "hec (Splunk-style HTTP Event Collector)")
    wh.add_argument("--index", default=None, help="es_bulk: the index to write to")
    wh.add_argument("--allow-http", action="store_true", help="Plain HTTP to a receiver on this machine or a "
                                                              "private address (readable on the wire)")
    wh.add_argument("--sign-v1a", action="store_true", help="Also sign with Kratos's Ed25519 key (v1a)")
    wh.add_argument("--no-signing-secret", action="store_true", help="Don't generate a whsec_ signing secret")
    wh.add_argument("--auth-header", default=None, help="Send this header with a value read from stdin "
                                                        "(e.g. Authorization for an HTTP collector's token)")
    _common(wh, "webhook")
    sl = ks.add_parser("syslog", help="RFC 5424 over TLS (RFC 5425), the server's certificate verified")
    sl.add_argument("name")
    sl.add_argument("--host", required=True)
    sl.add_argument("--port", type=int, default=6514)
    sl.add_argument("--format", choices=("text", "ocsf", "ecs"), default=None)
    sl.add_argument("--server-name", default=None, help="The name on the server's certificate, if not --host")
    sl.add_argument("--client-cert", default=None, help="Offer this client certificate (its key is read from stdin)")
    sl.add_argument("--pen", type=int, default=None, help="Your organisation's IANA enterprise number for the "
                                                          "structured data (default 32473)")
    _common(sl, "syslog")
    em = ks.add_parser("email", help="SMTP over STARTTLS or TLS, the server verified; one email per run or batch")
    em.add_argument("name")
    em.add_argument("--host", required=True)
    em.add_argument("--port", type=int, default=None)
    em.add_argument("--security", choices=("starttls", "tls"), default="starttls")
    em.add_argument("--from", dest="sender", required=True)
    em.add_argument("--to", required=True, help="Recipients, comma separated")
    em.add_argument("--username", default=None, help="Mail server login (its password is read from stdin)")
    _common(em, "email")
    for verb, text in (("show", "A channel's settings, what it sends and to whom, its health and history"),
                       ("test", "Send a test message now and show what happened"),
                       ("enable", "Turn a channel on"), ("disable", "Turn a channel off (its messages wait)")):
        p = cs.add_parser(verb, help=text)
        p.add_argument("name")
    rm = cs.add_parser("remove", help="Remove a channel (its messages stay in the outbox as history)")
    rm.add_argument("name")
    rm.add_argument("--yes", action="store_true", help="Really remove it")
    ed = cs.add_parser("edit", help="Change a channel's filters, rate, format, what it receives, its address")
    ed.add_argument("name")
    ed.add_argument("--url", default=None)
    ed.add_argument("--host", default=None)
    ed.add_argument("--port", type=int, default=None)
    ed.add_argument("--format", choices=("text", "kratos", "ocsf", "ecs"), default=None)
    ed.add_argument("--framing", choices=("json", "ndjson", "es_bulk", "hec"), default=None)
    ed.add_argument("--no-mask-values", action="store_true")
    ed.add_argument("--clear-filters", action="store_true")
    _common(ed, "webhook")
    se = cs.add_parser("secret", help="Set a channel's secret (read from stdin, or generated) -- never the command line")
    se.add_argument("name")
    se.add_argument("which", choices=("signing", "auth", "password", "client-key"))
    how = se.add_mutually_exclusive_group(required=True)
    how.add_argument("--stdin", action="store_true", help="Read it from standard input")
    how.add_argument("--generate", action="store_true", help="signing: generate a new whsec_ secret (printed once)")
    how.add_argument("--clear", action="store_true")
    ch.set_defaults(func=cmd_channels)

    ob = sub.add_parser("outbox", help="What Kratos has sent and what waits: attempts, failures, dead letters")
    obs = ob.add_subparsers(dest="outbox_action")
    ls = obs.add_parser("list", help="Messages, newest first")
    for p in (ob, ls):
        p.add_argument("--status", choices=("pending", "failed", "delivered", "dead"), default=None)
        p.add_argument("--channel", default=None)
        p.add_argument("--limit", type=int, default=30)
        p.add_argument("--json", action="store_true")
    sh = obs.add_parser("show", help="One message and every attempt")
    sh.add_argument("id", type=int)
    rt = obs.add_parser("retry", help="Send failed / dead messages again now (after you fixed the receiver)")
    rt.add_argument("ids", type=int, nargs="*")
    rt.add_argument("--dead", action="store_true", help="Every dead message (with --channel: of that channel)")
    rt.add_argument("--channel", default=None)
    fl = obs.add_parser("flush", help="Deliver what is due now from this terminal")
    fl.add_argument("--seconds", type=float, default=60.0)
    pr = obs.add_parser("prune", help="Delete delivered and dead messages (shown first; --apply to delete)")
    pr.add_argument("--status", default="delivered,dead")
    pr.add_argument("--older-than-days", type=float, default=30.0)
    pr.add_argument("--channel", default=None)
    pr.add_argument("--apply", action="store_true")
    ob.set_defaults(func=cmd_outbox)

    sg = sub.add_parser("signing", help="Kratos's Ed25519 signing key (webhook v1a signatures, signed exports)")
    sgs = sg.add_subparsers(dest="signing_action", required=True)
    sgs.add_parser("status", help="The key's fingerprint and public key (to give receivers)")
    sgs.add_parser("rotate", help="A new key; the old public key stays verifiable")
    sg.set_defaults(func=cmd_signing)


# --- helpers ------------------------------------------------------------------------------
def _actor():
    from kratos.lifecycle.decide import Actor

    return Actor.current("cli")


def _csv(v: str | None) -> list[str] | None:
    return [x.strip() for x in v.split(",") if x.strip()] if v else None


def _filter_dict(args: argparse.Namespace, base: dict[str, Any] | None = None) -> dict[str, Any] | None:
    keys = {"min_severity": args.min_severity, "min_ssvc": args.min_ssvc, "rule_prefixes": _csv(args.rules),
            "machines": _csv(args.machines), "groups": _csv(args.groups),
            "only_new_or_worse": args.only_new_or_worse}
    given = {k: v for k, v in keys.items() if v is not None}
    if not given and base is None:
        return None
    return {**(base or {}), **given}


def _read_stdin(what: str) -> str:
    if sys.stdin.isatty():
        import getpass

        return getpass.getpass(f"{what}: ")
    return sys.stdin.read().strip("\n") if what.endswith("key") else sys.stdin.readline().strip()


def _when(epoch: float | None) -> str:
    if not epoch:
        return "-"
    from kratos.utils.timeutil import epoch_to_utc_iso, format_for_display

    return format_for_display(epoch_to_utc_iso(epoch), "%Y-%m-%d %H:%M")


# --- channels ------------------------------------------------------------------------------
def cmd_channels(args: argparse.Namespace) -> int:
    from kratos.outbox import config as C

    dd = Path(args.data_dir)
    try:
        return _channels(args, dd)
    except C.ChannelError as e:
        print(f"[KRATOS] {e}", file=sys.stderr)
        return 2


def _channels(args: argparse.Namespace, dd: Path) -> int:
    from kratos.outbox import config as C
    from kratos.outbox import health as H

    act = args.channels_action
    if act == "list":
        h = {c.name: c for c in H.read(dd).channels}
        print(f"{'NAME':16} {'KIND':8} {'RECEIVES':24} {'FORMAT':7} {'STATE':12} {'WAITING':>7} {'DEAD':>4}  LAST SUCCESS")
        for c in C.list_channels(dd):
            x = h.get(c.name)
            ok, why = C.usable(c)
            state = "on" if ok else ("off" if not c.enabled else "not set up")
            if x and x.failing:
                state = "FAILING"
            print(f"{c.name:16} {c.kind:8} {','.join(c.scopes):24} {c.format:7} {state:12} "
                  f"{(x.backlog if x else 0):>7} {(x.dead if x else 0):>4}  {H.ago(c.last_success_at)}")
        return 0
    if act == "add":
        return _add(args, dd)
    ch = C.get_channel(dd, args.name)
    if ch is None:
        print(f"[KRATOS] no channel named {args.name!r} (kratos channels list)", file=sys.stderr)
        return 2
    if act == "show":
        print(f"[KRATOS] channel {ch.name} ({ch.kind}{', built in' if ch.builtin else ''}) -- "
              f"{'on' if ch.enabled else 'off'}")
        print(f"  {ch.disclosure()}")
        print(f"  receives: {', '.join(ch.scopes)}; format: {ch.format}; filters: {ch.filters.describe()}; "
              f"at most {ch.max_per_minute}/min")
        cfg = {k: v for k, v in ch.config.items() if v not in (None, "", False)}
        if cfg:
            print("  settings: " + ", ".join(f"{k}={v}" for k, v in sorted(cfg.items())))
        names = C.secret_names(dd, ch.name)
        print("  secrets: " + (", ".join(names) + " (kept in channel-secrets/, never shown)" if names else "none"))
        print(f"  last success: {_when(ch.last_success_at)}"
              + (f"; failing since {_when(ch.failing_since)}: {ch.last_error}" if ch.failing_since else ""))
        for e in C.history(dd, ch.name, limit=10):
            print(f"  {_when(e['at'])}  {e['action']:10} by {e['actor']} ({e['interface']})")
        return 0
    if act == "test":
        return _test(dd, ch)
    if act in ("enable", "disable"):
        C.set_enabled(dd, ch.name, act == "enable", actor=_actor())
        print(f"[KRATOS] {ch.name} turned {'on' if act == 'enable' else 'off'}"
              + ("" if act == "enable" else "; its messages wait in the outbox until you turn it on"))
        return 0
    if act == "remove":
        if not args.yes:
            print(f"[KRATOS] this removes channel {ch.name} and its secrets; its messages stay as history. "
                  "Add --yes to remove it.")
            return 1
        n = C.remove_channel(dd, ch.name, actor=_actor())
        print(f"[KRATOS] removed {ch.name}" + (f"; {n} waiting message(s) closed" if n else ""))
        return 0
    if act == "edit":
        return _edit(args, dd, ch)
    if act == "secret":
        return _secret(args, dd, ch)
    return 2


def _add(args: argparse.Namespace, dd: Path) -> int:
    from kratos.outbox import config as C

    kind = args.kind
    secrets: dict[str, str] = {}
    printed_secret = None
    if kind == "webhook":
        cfg = {"url": args.url, "framing": args.framing, "index": args.index, "allow_http": args.allow_http,
               "sign_v1a": args.sign_v1a, "ca_file": args.ca_file, "auth_header": args.auth_header}
        if not args.no_signing_secret:
            printed_secret = secrets["signing_secret"] = C.new_webhook_secret()
        if args.auth_header:
            secrets["auth_value"] = _read_stdin(f"value for the {args.auth_header} header")
        fmt = args.format or "kratos"
    elif kind == "syslog":
        cfg = {"host": args.host, "port": args.port, "ca_file": args.ca_file, "client_cert": args.client_cert,
               "server_name": args.server_name, "sd_pen": args.pen}
        if args.client_cert:
            secrets["client_key"] = _read_stdin("the client certificate's private key (PEM)")
        fmt = args.format or "text"
    else:
        cfg = {"host": args.host, "port": args.port, "security": args.security, "from": args.sender, "to": args.to,
               "username": args.username, "ca_file": args.ca_file}
        if args.username:
            secrets["password"] = _read_stdin(f"password for {args.username}")
        fmt = "text"
    ch = C.add_channel(dd, name=args.name, kind=kind, config=cfg, scopes=_csv(args.scope) or ["alerts"], format=fmt,
                       filters=_filter_dict(args), mask_values=bool(args.mask_values),
                       max_per_minute=args.max_per_minute or 60, secrets=secrets, actor=_actor())
    print(f"[KRATOS] added channel {ch.name}: {ch.disclosure()}")
    if printed_secret:
        print("[KRATOS] its signing secret (set your receiver up with it; it is shown only now):")
        print(f"  {printed_secret}")
    if ch.config.get("sign_v1a"):
        from kratos import signing

        print(f"[KRATOS] v1a public key for the receiver: {signing.public_key_whpk(dd)}")
    if "alerts" in ch.scopes:
        print("[KRATOS] triggers and schedules without their own list deliver to every alert channel "
              "(deliver = [\"all\"]); name it in a trigger's or schedule's deliver list to choose.")
    if {"findings", "events"} & set(ch.scopes):
        print("[KRATOS] forwarding starts now: earlier findings changes and events are not sent.")
    print(f"[KRATOS] try it: kratos channels test {ch.name}")
    return 0


def _edit(args: argparse.Namespace, dd: Path, ch: Any) -> int:
    from kratos.outbox import config as C

    changes: dict[str, Any] = {}
    cfg = {k: v for k, v in (("url", args.url), ("host", args.host), ("port", args.port), ("framing", args.framing),
                             ("ca_file", args.ca_file)) if v is not None}
    if cfg:
        changes["config"] = cfg
    if args.format:
        changes["format"] = args.format
    if args.scope:
        changes["scopes"] = _csv(args.scope)
    if args.max_per_minute:
        changes["max_per_minute"] = args.max_per_minute
    if args.mask_values or args.no_mask_values:
        changes["mask_values"] = bool(args.mask_values) and not args.no_mask_values
    flt = _filter_dict(args, {} if args.clear_filters else ch.filters.to_dict())
    if flt is not None and (args.clear_filters or flt != ch.filters.to_dict()):
        changes["filters"] = flt
    if not changes:
        print("[KRATOS] nothing to change")
        return 1
    new = C.edit_channel(dd, ch.name, actor=_actor(), **changes)
    print(f"[KRATOS] {new.name}: {new.disclosure()} Filters: {new.filters.describe()}.")
    return 0


def _secret(args: argparse.Namespace, dd: Path, ch: Any) -> int:
    from kratos.outbox import config as C

    key = {"signing": "signing_secret", "auth": "auth_value", "password": "password", "client-key": "client_key"}[
        args.which]
    if args.clear:
        C.set_secret(dd, ch.name, key, None, actor=_actor())
        print(f"[KRATOS] {ch.name}: {args.which} cleared")
        return 0
    if args.generate:
        if key != "signing_secret":
            print("[KRATOS] only a signing secret can be generated", file=sys.stderr)
            return 2
        value = C.new_webhook_secret()
        C.set_secret(dd, ch.name, key, value, actor=_actor())
        print(f"[KRATOS] {ch.name}: new signing secret (shown only now): {value}")
        return 0
    C.set_secret(dd, ch.name, key, _read_stdin(args.which), actor=_actor())
    print(f"[KRATOS] {ch.name}: {args.which} set")
    return 0


def _test(dd: Path, ch: Any) -> int:
    from kratos.outbox import store as S
    from kratos.outbox import worker as W
    from kratos.outbox.alerts import enqueue_alert

    if "alerts" not in ch.scopes:
        # a forwarding-only channel gets its test as an alert-shaped message anyway: say what it is
        print("[KRATOS] (this channel forwards findings/events; the test is sent as a Kratos test message)")
    res = enqueue_alert(f"Kratos test message for channel {ch.name}: if you can read this, delivery works.", "info",
                        deliver=[ch.name], data_dir=dd, kind="test", source="cli",
                        message_id=f"test:{ch.name}:{int(time.time() * 1000)}") if "alerts" in ch.scopes else \
        _enqueue_forward_test(dd, ch)
    if res.get("status") != "queued":
        print(f"[KRATOS] not sent: {res.get('observation') or res.get('status')}")
        return 1
    oid = res["outbox_ids"][0]
    print(f"[KRATOS] queued test message #{oid}; delivering ...")
    out = W.flush(dd, label="kratos channels test", deadline_seconds=20)
    deadline = time.monotonic() + 20
    while True:
        with S.opened(dd) as conn:
            row = S.get(conn, oid)
            atts = S.attempts_of(conn, oid)
        if row["status"] in ("delivered", "dead") or time.monotonic() > deadline or (
                row["status"] == "failed" and out.get("delivered_by") == "kratos channels test"):
            break
        time.sleep(0.5)
    for a in atts:
        print(f"  attempt at {_when(a['started_at'])}: {'ok' if a['ok'] else 'failed'} -- {a['detail'] or '...'}")
    if row["status"] == "delivered":
        print(f"[KRATOS] delivered to {ch.destination}")
        return 0
    if row["status"] == "pending" and out.get("delivered_by") not in (None, "kratos channels test"):
        print(f"[KRATOS] waiting: {out['delivered_by']} delivers it (see kratos outbox show {oid})")
        return 0
    print(f"[KRATOS] {row['status']}: {row['last_error']}"
          + (" -- Kratos retries it on its schedule" if row["status"] == "failed" else ""))
    return 1


def _enqueue_forward_test(dd: Path, ch: Any) -> dict[str, Any]:
    """A test findings change for a findings/events channel, in its own format."""
    from kratos.outbox import render as R
    from kratos.outbox import store as S
    from kratos.outbox.formats import FindingChange

    now = time.time()
    c = FindingChange(event_id=0, change="new", at=now, finding_key="kratos-test", rule_id="NET-001",
                      machine="kratos-test", state="open", severity="info",
                      title="Kratos test message: if your receiver shows this, forwarding works",
                      finding={"evidence": ["test"]})
    payload = R.findings_digest(ch, [c], dd) if ch.kind == "email" else R.finding(ch, c, dd)
    with S.opened(dd) as conn, S.immediate(conn):
        e = S.enqueue(conn, channel=ch.name, kind="test", message_id=f"test:{ch.name}:{int(now * 1000)}",
                      payload=payload, summary=c.title, severity="info", source="cli")
    return {"status": "queued", "outbox_ids": [e.id]}


# --- outbox ------------------------------------------------------------------------------------
def cmd_outbox(args: argparse.Namespace) -> int:
    from kratos.outbox import store as S
    from kratos.outbox import worker as W

    dd = Path(args.data_dir)
    act = args.outbox_action or "list"
    if act == "list":
        with S.opened(dd) as conn:
            rows = S.listing(conn, status=args.status, channel=args.channel, limit=max(1, min(args.limit, 1000)))
        if args.json:
            for r in rows:
                d = dict(r)
                d.pop("payload", None)
                print(json.dumps(d, sort_keys=True))
            return 0
        if not rows:
            print("[KRATOS] the outbox is empty" + (" for that filter" if args.status or args.channel else ""))
            return 0
        print(f"{'ID':>6} {'CHANNEL':14} {'KIND':16} {'STATUS':9} {'TRIES':>5} {'CREATED':16}  SUMMARY / LAST ERROR")
        for r in rows:
            tail = r["summary"] + (f"  [{r['last_error']}]" if r["last_error"] and r["status"] != "delivered" else "")
            nxt = (f" (next try {_when(r['next_attempt_at'])})" if r["status"] == "failed" else "")
            print(f"{r['id']:>6} {r['channel']:14} {r['kind']:16} {r['status']:9} {r['attempts']:>5} "
                  f"{_when(r['created_at']):16}  {tail}{nxt}")
        return 0
    if act == "show":
        with S.opened(dd) as conn:
            r = S.get(conn, args.id)
            atts = S.attempts_of(conn, args.id) if r else []
        if r is None:
            print(f"[KRATOS] no message #{args.id}", file=sys.stderr)
            return 2
        print(f"[KRATOS] #{r['id']} {r['kind']} to {r['channel']}: {r['status']}")
        print(f"  {r['summary']}")
        print(f"  message id (the receiver's idempotency key): {r['message_id']}")
        print(f"  created {_when(r['created_at'])}; machine {r['machine'] or '-'}; source {r['source'] or '-'}")
        if r["status"] == "failed":
            print(f"  next try {_when(r['next_attempt_at'])}")
        for a in atts:
            state = "in progress / interrupted" if a["finished_at"] is None else ("ok" if a["ok"] else "failed")
            print(f"  attempt {_when(a['started_at'])} by {a['holder']}: {state}"
                  + (f" -- {a['detail']}" if a["detail"] else ""))
        return 0
    if act == "retry":
        if not args.ids and not args.dead:
            print("[KRATOS] give message ids, or --dead", file=sys.stderr)
            return 2
        with S.opened(dd) as conn:
            n = S.retry_now(conn, ids=args.ids or None, channel=args.channel,
                            statuses_=("dead",) if args.dead and not args.ids else ("dead", "failed"))
        print(f"[KRATOS] {n} message(s) will be sent again now")
        W.wake()
        return 0
    if act == "flush":
        out = W.flush(dd, label="kratos outbox flush", deadline_seconds=args.seconds)
        if out["delivered_by"] not in ("kratos outbox flush",):
            print(f"[KRATOS] {out['delivered_by']} is delivering; nothing to do here "
                  f"({out['due_left']} due now)")
            return 0
        print(f"[KRATOS] {out['attempts']} attempt(s); {out['due_left']} message(s) still due now "
              "(the rest wait for their retry time)")
        return 0
    if act == "prune":
        statuses = tuple(s.strip() for s in args.status.split(",") if s.strip())
        before = time.time() - args.older_than_days * 86400
        try:
            with S.opened(dd) as conn:
                ids = S.prune_candidates(conn, statuses_=statuses, before=before, channel=args.channel)
                if not args.apply:
                    print(f"[KRATOS] would delete {len(ids)} {'/'.join(statuses)} message(s) older than "
                          f"{args.older_than_days:g} day(s) and their attempts. Add --apply to delete.")
                    return 0
                n = S.prune(conn, ids)
        except ValueError as e:
            print(f"[KRATOS] {e}", file=sys.stderr)
            return 2
        print(f"[KRATOS] deleted {n} message(s)")
        return 0
    return 2


def cmd_signing(args: argparse.Namespace) -> int:
    from kratos import signing

    dd = Path(args.data_dir)
    if args.signing_action == "rotate":
        k = signing.rotate(dd)
        print(f"[KRATOS] new signing key {k.fingerprint}; the old public key is kept in signing/retired/ so old "
              "signatures still verify. Give receivers the new public key:")
    else:
        k = signing.info(dd)
        if k is None:
            print("[KRATOS] no signing key yet: it is made the first time something is signed "
                  "(a webhook channel with --sign-v1a)")
            return 0
        print(f"[KRATOS] signing key {k.fingerprint}")
    print(f"  {k.public_openssh}")
    print(f"  {k.public_whpk}   (Standard Webhooks v1a form)")
    for old in signing.retired_public_keys(dd):
        print(f"  retired: {old}")
    return 0
