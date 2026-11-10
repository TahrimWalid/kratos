"""What Kratos keeps on this computer: one table of every kind of stored data.

`CATEGORIES` is the one answer to "what does Kratos keep about my machines, where,
and how much?" -- `kratos data`, `/doctor`'s "stored data" row and GUIDE "What
Kratos keeps" all read it. A new table or data folder needs an entry here:
`tests/test_datainv.py` scans the source for every `CREATE TABLE` and every folder
the code creates under the data folder and fails on one that isn't listed.

Kratos deletes none of this on its own (docs/phaseB/B.5 §3.1). The person prunes
with `kratos data prune` / `kratos snapshots prune`, always shown first.

Everything here only READS: sizes from the file system and SQLite's `dbstat`, the
oldest/newest record from a time column, the database opened read-only.
"""
from __future__ import annotations

import fnmatch
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from kratos import paths

DB = "kratos.db"
VULNDB = "vulndb/vulndb.sqlite"

# Personal-data labels, in plain words.
PERSONAL = "yes"
NOT_PERSONAL = "no"
SECRET = "secret"

# What a backup does with a category (docs/phaseD/D.8 §3.3). Every category has one;
# tests/test_datainv.py fails on a category without it, so new data can't be silently
# left out of `kratos backup`.
BACKUP_INCLUDE = "include"          # in every backup
BACKUP_SECRET = "secret"            # in, listed separately, left out by --without-secrets
BACKUP_REBUILDABLE = "rebuildable"  # out by default (backup_note names the rebuild command); --include-rebuildable
BACKUP_NEVER = "never"              # scratch that must not travel (backup_note says why)
BACKUP_CLASSES = (BACKUP_INCLUDE, BACKUP_SECRET, BACKUP_REBUILDABLE, BACKUP_NEVER)


@dataclass(frozen=True)
class TableRef:
    """Tables in one database file (relative to the data folder) and, optionally,
    the column that says when a row was written (epoch seconds or ISO text)."""
    db: str
    tables: tuple[str, ...]
    time_column: tuple[str, str] | None = None  # (table, column)


@dataclass(frozen=True)
class Category:
    key: str                         # short name used on the command line
    name: str                        # plain words
    description: str
    personal: str                    # yes | no | secret
    grows: str                       # how it grows, in plain words
    files: tuple[str, ...] = ()      # globs relative to the data folder (a folder name means everything in it)
    tables: tuple[TableRef, ...] = ()
    state_files: tuple[str, ...] = ()  # globs relative to Kratos's own folder (outside the data folder)
    prunable: bool = False           # `kratos data prune --category <key>` handles it
    note: str = ""                   # anything the person should know (e.g. a rolling buffer)
    backup: str = ""                 # one of BACKUP_CLASSES (required)
    backup_note: str = ""            # why it is never backed up, or how to rebuild it
    config_files: tuple[str, ...] = ()  # globs relative to the settings folder (paths.CONFIG_DIR)


CATEGORIES: tuple[Category, ...] = (
    Category(
        "sessions", "Sessions and conversations",
        "Your questions, Kratos's answers and each turn's step-by-step record.",
        PERSONAL, "one row and one file per question you ask",
        files=("sessions",),
        tables=(TableRef(DB, ("sessions", "goal_history", "session_usage"), ("goal_history", "started_at")),),
        prunable=True,
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "chat_server", "Chat-client server (kratos serve)",
        "The tokens chat clients use (stored only as scrypt hashes, with the machines and doors each may "
        "use), which Kratos session holds each client chat, and one audit row per request: when, which "
        "token, which door and model, the client's address and the user name it forwarded (for the record "
        "only), how it ended. Never the message text -- that is in the session. Plus the server's status "
        "file (address, port, investigations running).",
        PERSONAL, "one audit row per request a chat client sends; one row per token and per client chat",
        files=("serve",),
        tables=(TableRef(DB, ("serve_tokens", "serve_sessions", "serve_audit"), ("serve_audit", "at")),),
        note="revoke a token with `kratos serve token revoke`; nothing here is pruned automatically",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "traces", "Run records (traces)",
        "One file per investigation, audit, scheduled run and trigger: every model call, tool call and its "
        "result, guard and how the answer was put together. The most detailed file Kratos writes.",
        PERSONAL, "one file per run (usually tens to hundreds of KB)",
        files=("traces",),
        prunable=True,
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "host_events", "Host events",
        "The log lines Kratos has read from your machines, one record per line (usernames, addresses).",
        PERSONAL, "one row per log line read",
        tables=(TableRef(DB, ("host_events", "host_event_terms", "host_event_terms_state"), ("host_events", "ts")),),
        prunable=True,
        note="host_event_terms is the hunt's search index over these lines (addresses, accounts, hashes, programs, "
             "paths, domains); it is pruned with them",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "hunts", "Hunts",
        "Every hunt (`/hunt`, `kratos hunt`, a chat or MCP hunt, and the automatic hunts when the threat-intel "
        "cache learns a malicious address): when, who, what was hunted -- the address, account, hash or name "
        "typed --, which machines and period were searched, the coverage in one line and how many records "
        "matched.",
        PERSONAL, "one row per hunt",
        tables=(TableRef(DB, ("hunt_runs",), ("hunt_runs", "at")),),
        prunable=True,
        files=("hunt",),
        note="the indicator typed is personal data; HUNT-001 findings from automatic hunts are kept with the "
             "findings; `kratos data prune --category hunts` removes old hunt records",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "pseudonyms", "Placeholder map (masking)",
        "Which placeholder (USER_1, PUBLIC_IP_2, TARGET, ...) stood for which real account name, machine "
        "name, address or email in each conversation, so the model sees the same placeholder every time "
        "and Kratos can put the real value back.",
        PERSONAL, "one row per name or address masked, per conversation or run",
        tables=(TableRef(DB, ("pseudonym_map",), ("pseudonym_map", "first_seen")),),
        prunable=True,
        note="a conversation's map goes when you prune that conversation; maps of runs without one by age",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "findings", "Findings and decisions",
        "What Kratos found, each finding's history, your accept/ignore decisions and the findings reports.",
        PERSONAL, "one record per finding, one history row per change, one report per correlation",
        files=("reports",),
        tables=(TableRef(DB, ("finding_records", "finding_events", "finding_exceptions", "finding_imports",
                              "finding_verdicts", "finding_suggestions",
                              "anomalies", "daily_summary", "findings"), ("finding_events", "at")),),
        note="open decisions point at findings history; code verdicts and the model's suggestions sit "
             "alongside; kept unless you delete it yourself",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "snapshots", "Collected snapshots",
        "What Kratos read from your machines: port scans, logs, system context, baselines, log integrity, "
        "persistence, running processes, installed packages (the machine's and its running container "
        "images'), containers and their settings, and each machine's account list (every "
        "local account name, kept with the privileged-account read so masking can tell a real account "
        "from a name an attacker tried).",
        PERSONAL, "one file per check per machine each time it runs",
        files=("scans", "logs", "context", "baseline", "integrity", "persistence", "live", "packages", "web_signals", "sshguess",
               "containers"),
        tables=(TableRef(DB, ("persistence_baseline", "pkg_inventory"), ("pkg_inventory", "taken_at")),),
        note="`kratos snapshots prune` thins old ones (preview first)",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "collection_state", "Collection bookkeeping",
        "When each check last ran, the snapshot index, log-file positions and journal-seal results.",
        NOT_PERSONAL, "a few rows per check per machine",
        tables=(TableRef(DB, ("collect_state", "snapshots", "log_file_state", "seal_verifications", "disk_samples"),
                         ("collect_state", "started_at")),),
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "detection", "Detection rules: passes, results and your rule changes",
        "Which stored log lines each detection pass checked and how far it got, the newest detection results "
        "per machine (each matched rule, the stored log lines it matched, the addresses, users and programs "
        "they name), your on/off changes to rules with who and why, and the rule packs you imported. The "
        "matches themselves are host events (dataset kratos.detect).",
        PERSONAL, "one row per detection pass per machine, one result file per pass, one row per rule change",
        files=("detect",),
        tables=(TableRef(DB, ("detect_runs", "detect_rule_overrides", "detect_own_sessions"),
                         ("detect_runs", "started_at")),),
        note="kept unless you delete it yourself; the matches are pruned with host events",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "watch", "Continuous detection on agents",
        "Which machines a person turned continuous detection on for (who, when), which rule-pack push each "
        "agent runs, and each watched log's state: watching since when, events a minute, lag, how many matches "
        "were dropped, and the stretches of log that were not watched (with why). The matches themselves are "
        "host events (dataset kratos.detect). On each watched machine the agent keeps its own small state "
        "(rule pack, position, unsent matches -- bounded) in its state folder.",
        NOT_PERSONAL, "one row per watched machine and one per watched log; the unwatched stretches of each log "
                      "(newest 500)",
        tables=(TableRef(DB, ("detect_pack_state", "detect_watch"), ("detect_watch", "updated_at")),),
        note="kept unless you delete it yourself",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "log_sync", "Log-sync positions and coverage",
        "Where Kratos stopped reading each log, and which periods it has read completely.",
        NOT_PERSONAL, "one row per log source per machine, plus one per gap",
        tables=(TableRef(DB, ("sync_cursors", "sync_coverage"), ("sync_coverage", "end_ts")),),
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "vulndb", "Vulnerability data",
        "The public advisory, exploited-vulnerability and scoring data packages are matched against.",
        NOT_PERSONAL, "replaced by each `kratos vulndb-update` (hundreds of MB)",
        files=("vulndb",),
        tables=(TableRef(VULNDB, ("info", "meta", "ecosystems", "advisories", "ranges", "versions",
                                  "advisory_cves", "precise_cves", "seen", "kev", "epss", "cvss",
                                  "ssvc_inputs")),),
        note="public data, rebuilt from its sources on update",
        backup=BACKUP_REBUILDABLE, backup_note='public data: `kratos vulndb-update` downloads it again',
    ),
    Category(
        "threat_intel", "Threat-intel cache",
        "The offline AlienVault OTX reputation list.",
        NOT_PERSONAL, "replaced on each refresh",
        files=("threat_intel_cache",),
        backup=BACKUP_REBUILDABLE, backup_note='public data: `kratos threat-intel-sync` downloads it again',
    ),
    Category(
        "budget", "Budget ledger",
        "Every model call's tokens and cost, and spending-limit notices.",
        NOT_PERSONAL, "one row per model call",
        tables=(TableRef(DB, ("budget_ledger", "budget_state"), ("budget_ledger", "at")),),
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "subagent", "Sub-agent pairing and telemetry",
        "Paired machines, their connection history, live status, and the fix-channel allowlist.",
        PERSONAL, "telemetry and connection history are rolling (newest kept, see note)",
        tables=(TableRef(DB, ("subagent_targets", "subagent_pairing_codes", "subagent_telemetry",
                              "subagent_listeners", "subagent_connections", "subagent_connection_events",
                              "subagent_links", "whitelist_user_entries", "whitelist_maintainer_overrides",
                              "whitelist_versions", "whitelist_execution_opt_in", "whitelist_dispatch_requests",
                              "whitelist_custom_entries", "whitelist_agent_state", "whitelist_push_refusals"),
                         ("subagent_connection_events", "at")),),
        note=("live status keeps the newest 500 telemetry rows and 200 connection events per machine; "
              "unused pairing codes are removed a week after they expire"),
        backup=BACKUP_INCLUDE, backup_note='the pairing tokens in it are withheld by --without-secrets (the agents must then be paired again)',
    ),
    Category(
        "subagent_installers", "Sub-agent installer scripts",
        "Install and upgrade scripts Kratos wrote for you to copy to a machine. An install script holds "
        "a one-time pairing code.",
        SECRET, "one file per machine you set up",
        files=("kratos-subagent-install-*", "kratos-subagent-upgrade-*"),
        backup=BACKUP_NEVER, backup_note='an install script holds a one-time pairing code; Kratos writes a new one when you set up or update a machine',
    ),
    Category(
        "ssh_certificates", "SSH certificates",
        "Which machines log in with short-lived SSH certificates instead of the long-lived key, every "
        "certificate Kratos issued (its serial, key id, machine, principals, validity and the addresses it is "
        "bound to -- never a private key), and the public records of Kratos's own certificate-authority keys.",
        PERSONAL, "one row per enrolled machine, one per certificate issued, a few CA-key records",
        tables=(TableRef(DB, ("ssh_ca_keys", "ssh_certs", "ssh_enrolment"), ("ssh_certs", "issued_at")),),
        note="kept unless you remove them; manage with `kratos ssh-ca`",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "ssh_ca", "SSH certificate authority keys",
        "The private keys that sign Kratos's SSH login certificates and your machines' host certificates. The "
        "most valuable secret on this computer: keep them private and keep a copy (losing them means "
        "re-enrolling every machine). Short-lived per-run keys live here only while a run is in progress.",
        SECRET, "fixed: the user CA and host CA keys (active + next), plus a backup copy",
        files=("ssh-ca",),
        note="protection mode (file/agent/token/tpm) is shown by `kratos ssh-ca status`; this folder never leaves "
             "the Kratos host",
        backup=BACKUP_SECRET, backup_note='a TPM-sealed key is unsealed in memory into the encrypted backup; a key held on a token stays on the token (keep the token)',
    ),
    Category(
        "seal_keys", "Journal seal keys",
        "The keys that verify each machine's sealed journal. Keep them private.",
        SECRET, "one small file per machine",
        files=("fss",),
        backup=BACKUP_SECRET,
    ),
    Category(
        "agent_link_keys", "Agent link keys",
        "The private keys (active and backup) and certificate that encrypt the link to your servers' "
        "agents; every agent is pinned to these two keys. Keep them private and keep a copy: losing both "
        "means re-pairing every agent.",
        SECRET, "fixed: one active key with its certificate and one backup key",
        files=("subagent-tls",),
        note="replaced only when you run `kratos subagent-tls rotate`",
        backup=BACKUP_SECRET,
    ),
    Category(
        "settings", "Settings, presets, schedules and triggers",
        "Your settings, saved presets, schedules (with their run history) and triggers.",
        PERSONAL, "one file per preset/schedule/trigger; a line per scheduled run",
        files=("presets", "schedules", "triggers", "kratos_local_config.json"),
        tables=(TableRef(DB, ("app_settings", "schema_versions", "data_prunes"), ("data_prunes", "at")),),
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "assets", "Machines (asset records)",
        "What you said about each machine -- how much it matters, its role, whether it is reachable from the "
        "internet, its groups, who to call -- and every change to that, with who made it.",
        PERSONAL, "one row per machine; one row per edit",
        tables=(TableRef(DB, ("assets", "asset_events"), ("asset_events", "at")),),
        note="kept until you remove them; edit with /assets or `kratos assets set`",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "fleet", "Groups and fleet runs",
        "The groups of machines you made (and who changed them), and each question or audit about a group: who "
        "asked, the period, the estimate and the cost, and for each machine whether it was read and why not.",
        PERSONAL, "one row per group and member; one row per fleet run and one per machine in it",
        tables=(TableRef(DB, ("machine_groups", "group_members", "fleet_runs", "fleet_run_machines"),
                         ("fleet_runs", "started_at")),),
        note="kept until you remove them; groups are edited with /groups or `kratos groups`",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "outbox", "Outbox: messages sent to your channels",
        "Every message Kratos sent or will send to a webhook, syslog server, email inbox, SIEM or ntfy: the "
        "rendered alert or finding change (titles, severities, machines, the accounts, addresses and paths a "
        "finding names, evidence lines; secrets removed), each delivery attempt and its result, the channels "
        "you set up (where they send, what, filters -- never their secrets), who changed a channel and when, "
        "and how far each channel has forwarded findings and events. Forwarded host events are not copied: a "
        "message holds their row numbers and is rendered from the stored events when sent.",
        PERSONAL, "one row per message per channel (an alert, a finding change, a batch of up to 500 events) and "
                  "one per attempt; a few rows per channel",
        tables=(TableRef(DB, ("outbox", "outbox_attempts", "outbox_lease", "forward_cursors", "channels",
                              "channel_events"), ("outbox", "created_at")),),
        note="delivered and dead messages are kept until you prune them: `kratos outbox prune` (shown first)",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "channel_secrets", "Channel secrets",
        "The secrets your channels use: webhook signing secrets (whsec_) and Authorization values, mail server "
        "passwords, syslog client keys. Never stored in the database, never shown.",
        SECRET, "one small file per channel that has a secret",
        files=("channel-secrets",),
        backup=BACKUP_SECRET,
    ),
    Category(
        "users", "Users and their machines",
        "The people who may use Kratos through the chat server: name, role (viewer / investigator / admin), "
        "disabled or not, the machines and groups each may see, and which shared Open WebUI user ids map to whom "
        "(with the email shown to the owner). The owner is always here.",
        PERSONAL, "one row per user, per scope entry and per Open WebUI mapping",
        tables=(TableRef(DB, ("users", "user_scopes", "user_gateway_ids"), ("users", "created_at")),),
        note="changed only by the owner (`kratos users`, /users); disabling keeps the row",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "audit", "Audit trail",
        "Every allowed and refused action, with the person, the door (TUI, CLI, MCP, chat server, schedule), the "
        "credential (token id, or the gateway token and forwarded Open WebUI user), the machine, what it was about "
        "and why a refusal happened. Append-only.",
        PERSONAL, "one row per recorded action (each investigation, decision, change and refusal)",
        tables=(TableRef(DB, ("audit_log", "audit_log_prune_permit"), ("audit_log", "at")),),
        note="`kratos audit prune --older-than 365d --apply` removes old rows (preview first; the prune itself is "
             "recorded)",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "gateway_secrets", "Shared Open WebUI secrets",
        "The secret a shared Open WebUI signs each user's identity with (one per gateway token). Together with its "
        "token it can act as every mapped user -- keep both private.",
        SECRET, "one small file per gateway token",
        files=("gateway-secrets",),
        backup=BACKUP_SECRET,
    ),
    Category(
        "signing_key", "Kratos signing key",
        "Kratos's Ed25519 key that signs webhook messages (v1a), exported incident bundles and the evidence "
        "ledger's daily checkpoints; with a "
        "backup copy and the public keys of rotated-out keys. Keep it private and keep a copy.",
        SECRET, "fixed: the active key, its backup copies, retired public keys",
        files=("signing",),
        note="its fingerprint is shown by /doctor and `kratos signing status`; `kratos signing rotate` keeps old "
             "public keys verifiable",
        backup=BACKUP_SECRET,
    ),
    Category(
        "evidence_ledger", "Evidence ledger",
        "One row per evidence file Kratos writes (scans, logs, saved reads, findings reports, run records, export "
        "manifests): its path, SHA-256, size, when, which machine, read and transport -- the hash taken when the "
        "file was written, chained so an edited, deleted or moved row is detected, signed once a day.",
        PERSONAL, "one ~400-byte row per evidence file written, plus one signed checkpoint row per day",
        tables=(TableRef(DB, ("evidence_ledger",), ("evidence_ledger", "written_at")),),
        note="append-only (SQL refuses an edit or delete); `kratos evidence verify` checks the chain and every "
             "recorded file against it",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "exports", "Incident exports",
        "Incident bundles you made with /export or `kratos export create`: copies of the evidence files and "
        "events for the machines and period you chose, findings, coverage, the HTML report, the CASE/UCO graph, "
        "the signed manifest -- and each bundle's .tar.gz.",
        PERSONAL, "one folder (and one .tar.gz) per export you make; the size of what you chose to include",
        files=("exports",),
        note="a redacted bundle holds placeholders, not names; each export is listed by `kratos export list` (who, "
             "when, scope, hashes) and stays until you delete its folder",
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "kept_tools", "Kept tools",
        "Tools you approved with /evolve, their metadata and the test that defines each.",
        NOT_PERSONAL, "one file per tool you keep",
        state_files=("kept_tools", "evolve_harnesses", "tests/self_write_harnesses"),
        backup=BACKUP_INCLUDE,
    ),
    Category(
        "sandbox", "Tool candidates waiting for their sandbox test",
        "Code /evolve wrote that hasn't passed its test or been approved yet.",
        NOT_PERSONAL, "one file per candidate; disposable",
        state_files=("sandbox_staging",),
        backup=BACKUP_NEVER, backup_note="unapproved candidate code, disposable by design",
    ),
    Category(
        "settings_file", "Settings file (.env)",
        "The model you use and its API key, the SSH login Kratos uses, notification settings and other "
        "connection settings.",
        SECRET, "fixed: one small file",
        config_files=(".env",),
        backup=BACKUP_SECRET,
        note="holds API keys; `kratos init` writes it",
    ),
    Category(
        "llm_models", "Local model files",
        "Model files for running a model on this computer (only if you set one up).",
        NOT_PERSONAL, "one large file per model you download",
        state_files=("llm/models",),
        backup=BACKUP_REBUILDABLE, backup_note="download the model file again",
    ),
    Category(
        "backups", "Backup runs",
        "Every backup made, checked, drilled, restored or pruned: when, by whom, the file and its SHA-256, the "
        "size, which categories went in, the fingerprints of the keys it was encrypted to (never a secret), and "
        "how it ended -- plus the timer files `kratos backup schedule` writes. The backups themselves are "
        "outside the data folder (~/kratos-backups by default) and are encrypted.",
        PERSONAL, "one row per backup, check, drill, restore or prune",
        files=("backup",),
        tables=(TableRef(DB, ("backup_runs",), ("backup_runs", "started_at")),),
        backup=BACKUP_INCLUDE,
        note="the backup files stay until you prune them yourself: `kratos backup prune --keep N`",
    ),
    Category(
        "vulscan", "nmap vulscan CVE list",
        "The CVE list nmap's vulscan script matches services against.",
        NOT_PERSONAL, "replaced by `kratos vulscan-install`",
        state_files=("vulscan",),
        backup=BACKUP_REBUILDABLE, backup_note='public data: `kratos vulscan-install` downloads it again',
    ),
)

# Things in the data folder that are not stored data: lock files, sockets and the
# scratch folder a step creates and empties again.
RUNTIME_ENTRIES: tuple[str, ...] = ("locks", "tmp", "subagent-reads.sock", "*.tmp", ".*.tmp", "kratos.db-wal",
                                    "kratos.db-shm", "kratos.db-journal", ".backup-work")

# The database file itself is accounted table by table.
DATABASE_FILES: tuple[str, ...] = (DB,)

# SQLite's own tables.
_SQLITE_INTERNAL = ("sqlite_",)


def category(key: str) -> Category:
    for c in CATEGORIES:
        if c.key == key:
            return c
    raise KeyError(f"unknown data category {key!r}; one of: {', '.join(c.key for c in CATEGORIES)}")


def all_tables() -> set[str]:
    return {t for c in CATEGORIES for ref in c.tables for t in ref.tables}


def top_level_patterns() -> list[tuple[str, str]]:
    """(pattern, category key) for every data-folder entry a category owns."""
    out = []
    for c in CATEGORIES:
        for f in c.files:
            out.append((f.split("/")[0], c.key))
    return out


def owner_of(name: str) -> str | None:
    """The category key that owns a top-level entry of the data folder, 'runtime' or
    'database' for the non-data entries, else None."""
    if name in DATABASE_FILES:
        return "database"
    for pat in RUNTIME_ENTRIES:
        if fnmatch.fnmatch(name, pat):
            return "runtime"
    for pat, key in top_level_patterns():
        if fnmatch.fnmatch(name, pat):
            return key
    return None


# --- measuring -------------------------------------------------------------

@dataclass
class Measured:
    category: Category
    bytes: int = 0
    items: int = 0               # files + rows
    oldest: float | None = None  # epoch UTC
    newest: float | None = None
    locations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        c = self.category
        return {"category": c.key, "name": c.name, "personal": c.personal, "bytes": self.bytes,
                "items": self.items, "oldest": _iso(self.oldest), "newest": _iso(self.newest),
                "where": self.locations, "grows": c.grows, "note": c.note, "prunable": c.prunable,
                "errors": self.errors}


def _iso(t: float | None) -> str | None:
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds") if t is not None else None


def to_epoch(value: Any) -> float | None:
    """An epoch number or stored ISO text (see `timeutil.epoch_of`)."""
    from kratos.utils.timeutil import epoch_of

    return epoch_of(value)


def _walk(path: Path) -> Iterable[os.stat_result]:
    """Files under `path`. A top-level folder that is a link (a data folder moved to
    another disk) is measured where it points; links inside are never followed."""
    if path.is_symlink():
        if not path.is_dir():
            return
        path = path.resolve()
    if path.is_file():
        yield path.stat()
        return
    if not path.is_dir():
        return
    for root, dirs, files in os.walk(path, followlinks=False):
        for f in files:
            try:
                st = os.lstat(os.path.join(root, f))
            except OSError:
                continue
            if os.path.isfile(os.path.join(root, f)) and not os.path.islink(os.path.join(root, f)):
                yield st


def _measure_glob(m: Measured, base: Path, pattern: str) -> None:
    for p in sorted(base.glob(pattern)):
        m.locations.append(str(p))
        for st in _walk(p):
            m.bytes += st.st_size
            m.items += 1
            m.oldest = st.st_mtime if m.oldest is None else min(m.oldest, st.st_mtime)
            m.newest = st.st_mtime if m.newest is None else max(m.newest, st.st_mtime)


def open_readonly(db_path: Path) -> sqlite3.Connection | None:
    if not db_path.is_file():
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _table_sizes(conn: sqlite3.Connection) -> dict[str, int] | None:
    """Bytes per table (indexes counted with their table), or None without dbstat."""
    try:
        owners = {r["name"]: r["tbl_name"] for r in conn.execute("SELECT name, tbl_name FROM sqlite_schema")}
        sizes: dict[str, int] = {}
        for r in conn.execute("SELECT name, SUM(pgsize) AS b FROM dbstat GROUP BY name"):
            table = owners.get(r["name"], r["name"])
            sizes[table] = sizes.get(table, 0) + int(r["b"] or 0)
        return sizes
    except sqlite3.Error:
        return None


def _measure_tables(m: Measured, data_dir: Path, ref: TableRef, cache: dict[str, Any]) -> None:
    db_path = data_dir / ref.db
    if str(db_path) not in cache:
        try:
            conn = open_readonly(db_path)
        except sqlite3.Error as e:
            conn = None
            m.errors.append(f"{ref.db}: {e}")
        cache[str(db_path)] = (conn, _table_sizes(conn) if conn is not None else None)
    conn, sizes = cache[str(db_path)]
    if conn is None:
        return
    present = {r[0] for r in conn.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")}
    for t in ref.tables:
        if t not in present:
            continue
        m.locations.append(f"{ref.db} → {t}")
        try:
            m.items += int(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0])  # noqa: S608 -- names from CATEGORIES
        except sqlite3.Error as e:
            m.errors.append(f"{t}: {e}")
        if sizes is not None:
            m.bytes += sizes.get(t, 0)
    if ref.time_column and ref.time_column[0] in present:
        table, col = ref.time_column
        try:
            row = conn.execute(f"SELECT MIN({col}), MAX({col}) FROM {table}").fetchone()  # noqa: S608
        except sqlite3.Error:
            row = None
        if row is not None:
            for value in row:
                t = to_epoch(value)
                if t is None:
                    continue
                m.oldest = t if m.oldest is None else min(m.oldest, t)
                m.newest = t if m.newest is None else max(m.newest, t)


def measure(data_dir: Path, *, state_root: Path | None = None, config_root: Path | None = None) -> list[Measured]:
    """Every category, measured. Read-only."""
    data_dir = Path(data_dir)
    root = Path(state_root) if state_root is not None else paths.STATE_ROOT
    croot = Path(config_root) if config_root is not None else (root if state_root is not None else paths.CONFIG_DIR)
    cache: dict[str, Any] = {}
    out = []
    try:
        for c in CATEGORIES:
            m = Measured(c)
            for f in c.files:
                _measure_glob(m, data_dir, f)
            for f in c.state_files:
                _measure_glob(m, root, f)
            for f in c.config_files:
                _measure_glob(m, croot, f)
            for ref in c.tables:
                try:
                    _measure_tables(m, data_dir, ref, cache)
                except sqlite3.Error as e:
                    m.errors.append(str(e))
            out.append(m)
    finally:
        for conn, _ in cache.values():
            if conn is not None:
                conn.close()
    return out


def unlisted(data_dir: Path) -> list[Path]:
    """Entries in the data folder no category owns (e.g. files a person put there)."""
    data_dir = Path(data_dir)
    if not data_dir.is_dir():
        return []
    return sorted(p for p in data_dir.iterdir() if owner_of(p.name) is None)


def database_bytes(data_dir: Path) -> int:
    total = 0
    for name in (DB, DB + "-wal"):
        p = Path(data_dir) / name
        if p.is_file():
            total += p.stat().st_size
    return total


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


NOTHING_DELETED = "Kratos deletes nothing on its own."


def summary(data_dir: Path) -> dict[str, Any]:
    """Total, biggest category -- for /doctor."""
    measured = measure(data_dir)
    total = sum(m.bytes for m in measured)
    biggest = max(measured, key=lambda m: m.bytes, default=None)
    return {"total_bytes": total, "biggest": biggest.category.name if biggest and biggest.bytes else None,
            "biggest_bytes": biggest.bytes if biggest else 0, "categories": len(measured)}
