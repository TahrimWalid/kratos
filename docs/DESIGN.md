# Kratos — architecture & design notes

Kratos is a defensive security assistant: it investigates a monitored target
(and, optionally, its own host) over read-only channels — SSH, or a sub-agent
running on the target — and produces findings and recommendations for a human.
The primary interface is a Textual terminal UI (`tui_mk2/`); the same core is
reachable from the command line and an MCP server. It has two ways into the
same tool registry — a fixed pipeline (`kratos run`, `/run`, presets: a
deterministic sequence of tool calls) and an agentic ReAct loop
(`kratos investigate "<goal>"`, `agent/loop.py`) that picks tools based on
the stated goal. Both dispatch through the same `TOOL_REGISTRY`
(`agent/tools.py`) and the same approval gate, so a capability added to the
registry is available to either path without extra wiring.

This document exists to explain decisions that aren't obvious from reading
the code in isolation — why a boundary is enforced where it is, why a
retry loop has two independent budgets, why a setting has to be read a
particular way. It isn't a changelog; for that, use `git log`.

## Execution boundary

By default — and in every build that exists today — Kratos does not change
the state of the machine it monitors. Every target-facing tool in the
registry is read/observe-only: `run_nmap_scan`, `read_journalctl`,
`list_open_files`, `list_processes`, `check_file_integrity`, `run_yara_scan`,
`run_vuln_scan`, `run_config_audit`, `correlate_findings` (which only
synthesizes what's already been observed). These do run read-only commands on
the target to inspect it, but none of them can alter it. When an
investigation surfaces something that warrants action on the target — e.g. a
disabled fail2ban jail — Kratos's job ends at recommending that action to a
human, via a finding or the agent's final answer. It never performs it.

This is the current enforced behavior, not just a feature that hasn't been
added: there is no code path from the agent to a state-changing command on
the target. It is also the *default*, not a permanent law — a narrow,
per-target opt-in execution path is designed (see below). Approval-gating
wouldn't be the right control for target-side execution anyway: approval
mitigates a different risk (an operator making a mistake with a local-host
command, or a newly self-written tool doing something unexpected), which is
why the planned execution path is bounded by a fixed action whitelist rather
than by an approval prompt.

Concretely, this shapes a few things that otherwise look like build-order
accidents:

- `run_linux_command` (the one tool that *does* execute a command,
  approval-gated) is scoped to the Kratos host only, on purpose — it is not
  a generic remote executor, and it never SSHes anywhere.
- `adapters/ssh_remote.py::run_remote_command` / `run_remote_script` exist
  and are used internally by every target-facing tool's own fixed,
  read-only actions (journalctl, file hashing, config audit, YARA), but are
  deliberately never exposed as their own agent-callable
  `@register_tool`. Wrapping them would let the agent construct an
  arbitrary remote command, which is exactly the capability this boundary
  rules out — narrow framing (e.g. a single "enable fail2ban" tool) doesn't
  change that; the boundary is about the *category* of capability, not how
  broad a given tool's surface is.
- The target setup checklist (`adapters/target_setup.py::
  generate_target_setup_checklist`) produces shell commands for a *human*
  to paste into the target's own shell. Kratos never runs them.

There is one narrow, per-target, opt-in exception, and it is experimental
and off by default: dispatching a small set of allowlisted actions to a
target's sub-agent (see "Sub-agents" below). It is not reachable from the
agent loop's tool dispatch at all — no tool in the registry can trigger it;
it only runs from a human's typed `EXECUTE` in the UI — and it requires an
explicit switch on the target itself. The allowlist the *agent* carries, not
the signing and not the approval prompt, is what bounds the risk. It has not
yet had its independent security review, which gates enabling it on any real
target.

## Target-facing tools and operational requirements

A target needs a few things set up before Kratos can investigate it fully.
`/target <host>` runs a setup checklist and a read-only probe that checks
these automatically (for SSH; a sub-agent target gets the agent's own
capability check instead):

- SSH key auth to a user with either passwordless sudo for a small, fixed
  set of commands (`journalctl`, `sshd -T`, one of `ufw`/`nft`/`iptables`,
  `fail2ban-client`), or, for `journalctl` specifically, membership in the
  `systemd-journal` group instead of sudo — group membership grants the
  same read access with a strictly smaller blast radius if the SSH key ever
  leaks, and is the preferred option (`kratos_config.JOURNALCTL_USE_SUDO`,
  default `True` for backward compatibility).
- `yara` installed on the target for `run_yara_scan` — Kratos does not
  install it. `run_yara_scan` has its own timeout
  (`YARA_SCAN_TIMEOUT_SECONDS`, default 180s, `KRATOS_YARA_SCAN_TIMEOUT`
  override) separate from the general SSH command timeout: a broad
  `scan_path` (e.g. `/etc` or `/home`) is a normal, legitimate choice for
  an investigating agent to make, and a multi-minute YARA scan over it
  isn't misuse. Using the same short timeout as every other SSH command
  produced a misleading generic "SSH script timed out" error for what was
  actually just a large, still-running scan; the scan-specific timeout
  fails with a clear, scan-specific message instead. A true `scan_path='/'`
  is still expected to exceed even this budget.
- `lsof` installed on the target for `list_open_files`.
- The target's fail2ban `ignoreip` should include the Kratos host's own
  address — otherwise Kratos's own investigative SSH traffic can trip the
  target's SSH jail and get itself banned mid-investigation.

## Sub-agents

A sub-agent (`subagent/agent.py` and its siblings: standard library only,
Python 3.8+, installed by a generated one-command installer) runs on a
monitored machine as a service and dials *out* to Kratos's listener
(`subagent/core_server.py`), so the machine opens no inbound port and can sit
behind NAT. Pairing redeems a single-use code for a per-agent token; the
token file is owner-only, and the HMAC key every signed message uses is
derived from it. Three things travel over the connection, kept deliberately
separate:

- **Telemetry** — a read-only snapshot (host, disk, listening ports, process
  count, services, critical file hashes, recent auth summary) every 30s.
- **Investigation reads** — named probes from one closed set shipped in the
  agent (`subagent/reads.py`): clock, journal, auth journal, auth
  measurement, privileged accounts, processes, open files, file hashes, config
  audit, capabilities, YARA. Kratos names a probe and passes parameters;
  the agent validates every parameter with closed, type-strict validators and
  runs a fixed argv (or a fixed script) with no shell, a fixed environment,
  binaries only from system directories, a per-probe timeout and an output
  cap. No command text, path list or rule text is ever accepted from Kratos.
  Each request is signed for the connection's session nonce with a strictly
  increasing sequence number, so a captured request can't be replayed; reads
  need a trusted transport: a pinned TLS link (see "Encrypted link" below),
  or, for an agent from before pins, loopback or the agent's own end of the
  connection on a Tailscale interface (or one the operator names with
  `--trusted-interface`) — an address in 100.64.0.0/10 alone doesn't count,
  since that is also carrier-grade NAT space. The SSH path builds its commands with the *same* builders and both
  transports' output goes through the same parsers, so results can't drift —
  verified on real hosts (identical journal reads, config verdicts and
  exhaustive auth counts over SSH and through the agent). YARA over the agent
  uses only rules that live on the machine (shipped with the agent, or placed
  by its administrator) and returns rule/file/offset, never matched bytes,
  over a closed set of scan roots with credential paths skipped: with rules
  supplied by Kratos, even match/no-match per rule would be an oracle for
  file contents. The scan never follows a symlink: each directory and file is
  opened one component at a time with `O_NOFOLLOW`, re-checked after opening,
  and handed to `yara` as an open descriptor, so swapping a path for a link
  mid-scan can't redirect it outside the scan roots.
  **Read surface.** A normal install runs the agent as root, so these reads
  see more than an SSH login without `sudo` does: every process's open files,
  the whole journal, and sudoers grant lines (the collector sends grants only
  — Defaults, includes and alias definitions stay on the machine). Results
  reach Kratos and, during an investigation, the model provider. This is a
  deliberate trade (an incident needs root's view), stated here so it is
  made knowingly.
- **Execution (experimental, off by default)** — the agent carries its own
  ceiling (`subagent/ceiling.py`): exactly which binaries and argument shapes
  it will ever run. Kratos can push a narrower allowlist, never a wider one;
  each pushed action and the final argv are re-checked on the agent. A
  dispatch also needs the agent's local `--enable-execution` switch, a
  trusted transport, a signed heartbeat within the dead-man's window, the
  current allowlist version (anti-rollback, bounded to 2³¹−1; a push the
  agent refuses is answered, and `/whitelist` can move Kratos's count past a
  newer version the agent already holds, never the agent's back), per-target
  consent in Kratos and a typed `EXECUTE`. A queued run is claimed at most
  once, in one transaction that re-checks consent and that the request is
  under 30 s old; the approval screen cancels a request nobody sent, so it
  can't run later. Pushed actions are parsed with exact JSON types. The
  machine's administrator can add exact commands in a root-owned local file
  Kratos cannot write; those lines are deliberately exempt from the
  maintainer exclusions (sensitive paths, account changes, firewall
  binaries), so that file is a root-level escape hatch to be treated like
  `sudoers` — only shells, interpreters (under any versioned name) and
  command wrappers are refused there. None of this has had its independent
  review yet.

**Encrypted link (C.4).** The agent link is TLS with the server's public key
pinned, not a CA. Kratos makes an ECDSA P-256 key pair with a long-lived
self-signed certificate plus a *backup* key pair (`subagent/tls.py`, the
`cryptography` package, `data_dir/subagent-tls/`: folder 0700, files 0600,
refused when loose, symlinked, owned by someone else, or not matching the key
record). Every installer and update carries the SHA-256 of both keys'
SubjectPublicKeyInfo and a pin-set version (`--server-pin`,
`--server-pins-version`); the agent keeps them in its state file, and a newer
set it received later wins over the one on its service command line.

- *Why `CERT_NONE` plus a pin is sound.* The agent's context
  (`subagent/pinning.py`, stdlib, Python 3.8) turns chain and hostname checks
  off because there is no CA to check against: the only identity that matters
  is "the key this agent was given". After the handshake it takes the peer
  certificate (`getpeercert(binary_form=True)`, returned even unvalidated),
  extracts the SPKI with a small DER walker, hashes it and compares against
  every pin with `hmac.compare_digest`. The handshake itself proves the server
  holds that key's private half (it signs the handshake: TLS 1.3
  CertificateVerify, or the TLS 1.2 ECDHE key exchange; only ECDHE suites with
  AES-GCM or ChaCha20, TLS 1.2 minimum, no compression or renegotiation).
- *Pre-pin silence.* No protocol byte (hello, token, pairing code) is written
  before the pin matches; a mismatch aborts the transport, is logged locally,
  and is counted in the state file. The count is reported in the hello of the
  next good connection (`link_alerts`), since it can't be told to the server
  that failed. A pinned agent has no plaintext code path; unreadable saved
  pins stop it connecting rather than drop to plaintext.
- *DER walker.* Reads only as far as the SPKI: definite, minimal lengths, at
  most 4 length bytes, single-byte tags, every element inside its parent, no
  trailing bytes after the certificate or inside the SPKI, a 64 KiB cap. It
  fails closed (`PinError`) on anything else; fuzzed with truncations and
  random flips/insertions/deletions.
- *First-byte split.* The listener accepts its own sockets and peeks one byte
  with `MSG_PEEK` before any asyncio transport exists: 0x16 (a TLS handshake
  record) goes to `connect_accepted_socket` with the TLS context; anything
  else is plaintext (a Kratos frame's first byte is 0x00, since frames are
  under 16 MiB). Peeking doesn't consume, so neither path loses a byte; one
  port serves both during migration. The peek and the handshake each have a
  timeout, and at most 256 connections may be before their first byte or
  handshake at once (further ones are closed at once), so silent or slow
  clients can't block others or exhaust descriptors.
- *Require.* `subagent.tls.require` (people-only setting, default off) makes
  the listener refuse a plaintext hello with "update the agent", before the
  token is looked up.
- *Trust rule.* A pinned TLS link counts as a trusted transport for reads (and
  execution, which stays off) wherever the agent is.
  `--allow-untrusted-transport` is ignored once an agent has pins; it is to be
  removed once `require` has been on long enough that no unpinned agent is
  left.
- *Pin-set push and rotation.* `kratos subagent-tls rotate` (people-only)
  makes the backup key active with a new certificate, makes a new backup,
  bumps the version and deletes the retired key. The listener notices the key
  record change within 2 s, uses the new key for new connections, and sends
  every live pinned agent a `pin_set_push` (signed for the connection's
  session nonce, versioned). The agent accepts it only over a pinned TLS link,
  newer than what it holds (an equal, identical set is acknowledged), never
  empty, and saves it atomically before acknowledging. An offline agent still
  holds the old backup pin, which is now the active key, so it reconnects and
  is brought up to date. Rotation refuses while an encrypted agent hasn't
  confirmed the current set (a second rotation would leave it with neither
  key). Plaintext agents never get a push.

**Routing.** A session target (an IP or hostname) is read through a sub-agent
only after an explicit link (`subagent_links`), made when the user picks
"Sub-agent" in onboarding or accepts an offered match — never inferred, since
a wrong inference would read the wrong machine. A link is "sub-agent only" or
"SSH first, sub-agent if SSH can't connect". Routing happens at the named
fetchers in `adapters/ssh_remote.py`; `run_remote_command` /
`run_remote_script` take free command text, so they stay SSH-only and refuse
for a sub-agent-only target, and a kept tool that issues its own SSH command
is refused at dispatch for such a target (a kept tool that turned the refusal
into an empty result once made a live investigation report "no listening
services" on a box running sshd). Network scans refuse for a sub-agent-only
target and record a coverage gap; if the final answer doesn't say what wasn't
checked, the loop adds a note. Every routed result carries a transport note,
shown on screen (amber when SSH failed and the read fell back).

**Listener and pairing.** Wrong pairing codes are limited per source (an
IPv4 address or an IPv6 /64) and capped across all sources (60 a minute, so
a code's 15-minute life allows ~900 guesses against 2³²); token logins are
only limited per source, so a flood of bad codes can't lock paired agents
out. The always-on listener can bind only the addresses agents actually
dial, and restarts itself onto newer Kratos code once that code has settled
(30 s unchanged) and the listener has been idle for 60 s (no read, run or
allowlist push in flight or recent), exiting 75 so systemd starts it again.
Agents are never updated automatically: that installs new root-level code on
a machine, so `/subagent` points out an outdated agent and waits for `g`. `kratos.db` (it holds the pairing tokens) and its WAL files are
created owner-only.

**Process boundary.** The investigation usually runs in a different process
from the listener holding the agents' connections, so they talk over an
owner-only Unix socket (`subagent/local_reads.py`): created 0600 before it can
be reached, peer uid checked with `SO_PEERCRED`, a stale socket from a crashed
listener replaced and a live one never stolen, and every failure turned into a
message that says what to do.

## Time windows

A phrase like "in the last 24 hours" or "this week vs last" is resolved to
exact UTC bounds in code (`timewin/`), never by the model. Every journal fetch
uses absolute epochs and `--reverse -n N+1`: plain `--since X -n N` returns the
*oldest* N entries on systemd 249 but the newest on 255, which once hid a live
brute force from an investigation; the extra entry is how truncation is
detected and reported. Counting questions don't read a capped sample:
`timewin/measure.py` builds a POSIX-sh + portable-awk script that counts every
matching event in the window on the target (journald, falling back to classic
syslog files) and returns totals, coverage, boot gaps and a few labelled
samples; the target's clock offset is measured and applied. The answer's
numbers are then checked: a final answer about a time period carries
structured claims that are verified against these measurements, a period the
goal asked about but nobody queried is tagged, and a tool the answer cites but
never ran is flagged. Comparisons between periods are computed by Kratos.
"What did it look like then" questions are answered from Kratos's own saved
snapshots — the nearest one at or before the time asked, with its distance —
never interpolated.

## LLM backend

Every backend — local Ollama, a self-hosted OpenAI-compatible server
(vLLM, llama.cpp), or a hosted provider — is reached through one query
mechanism: `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL`
(OpenAI chat-completions-compatible). `KRATOS_LLM_BACKEND` chooses between
`llama_cpp` (a direct in-process GGUF load) and `openai_compatible` (the
unified HTTP path); `auto` (the default) prefers `llama_cpp` if a local
GGUF file is present, otherwise falls back to `openai_compatible`.

A couple of things fall out of using one HTTP-based path for every backend:

- Query calls retry with backoff on `503`/`429`/connection errors, and do
  *not* retry on a 4xx or a malformed response (those indicate a request or
  parsing problem, not a transient failure worth repeating). A large system
  prompt (as used during a write-step or investigation loop) hits
  transient server errors more often than a short one on some hosted
  backends, so this matters for the calls that actually carry weight.
- Context length is a model-*load*-time concept for the openai-compatible
  endpoint, not a per-request one — a request that passes a context-length
  option gets silently ignored; the server reports whatever context size it
  loaded the model with, regardless of what the request asked for. There is
  no way to force a different context window from a single chat completion
  call against this endpoint; set it via the backend's own model
  configuration if you need something other than its default load size.
- `/model` switches the active profile live (and persists the change to
  `.env`) in one step. See "Live-switchable settings" below for why the
  query code has to read the active profile through a function call rather
  than an imported constant for this to actually take effect mid-session.

Kratos ships as a hosted-LLM product: the primary, supported backend is a
hosted model. Self-hosting any OpenAI-compatible endpoint remains fully
supported for anyone who wants to run entirely offline, but it's an option
alongside the hosted default, not the primary positioning — see the README
for the resulting privacy and per-run cost posture.

## Model spending limits

Kratos runs a hosted, metered model by default, and schedules, triggers, MCP
clients (and later web chat) can all call it with nobody watching. OWASP lists
this as LLM10:2025 *Unbounded Consumption* ("denial of wallet"): its guidance is
per-request, per-agent and per-period budgets that throttle, reject or ask a
human when they run out. `kratos.budget` is that layer.

**One choke point.** `llm_interface._metered_call` is the only place a request
is sent to a model (and, since B.2, where it is masked -- see "Masking what the model sees"): the three request sites (the OpenAI-compatible HTTP call,
the llama.cpp server call, the in-process llama.cpp call) each hand their
request to it as a `send` function. Before sending it asks the budget guard to
check every cap and reserve the call's worst case; afterwards it records what
the call actually used. A source scan (`tests/test_budget_choke_point.py`)
fails if a request is sent anywhere else, or if anything outside
`llm_interface` talks to a model endpoint or SDK directly. Retries are separate
requests and each passes the guard; a failed request keeps a zero-token row so
failures stay visible. Budget code never calls the model itself.

**The ledger** (`budget_ledger` in `kratos.db`) is the single source of truth
for usage: one row per model call with the run, source (`interactive`,
`schedule`, `trigger`, `mcp`, `cli`, `evolve`, ... from the run context),
session, machine, model, tokens and cost. `/usage` reads it; sessions from
before it existed keep their old `session_usage` totals, which `/usage` adds in
(new calls are never written there, so nothing is counted twice). Rows are never
deleted. A call with no run scope is recorded as `unattributed` and logged as a
bug.

**Reservations make caps hold across processes.** The TUI, `kratos
scheduled-run` and `kratos mcp-serve` share `kratos.db`. Inside one
`BEGIN IMMEDIATE` transaction the guard sums the run's and the day's spending
plus every open reservation, refuses if this call's worst case
(`ceil(characters / 3.5)` prompt tokens + its `max_tokens`) would cross a hard
limit, and otherwise writes a `reserved` row. After the call that row becomes
`settled` with the real usage. A reservation whose process died is `expired`
after ten minutes, or the request timeout plus a minute if that is longer (a
call still running must not look free); it then counts as a call with unknown
usage.

**Limits** are user settings (`budget.*` in `app_settings`, Settings → Budget),
read fresh on every check, so a change applies to the next call in every
process: tokens and model calls per run, cost per local day (everything, and
unattended sources on their own), tokens per day for local or unpriced models,
fires per trigger per day, whether triggers may start investigations, the
soft-limit share and the breaker thresholds. `0` means "nothing allowed"; there
is no "unlimited". Cost is the provider's own figure when the response reports
one, else tokens × the price table (`budget.model_rates`), else unknown -- then
only the token caps apply. A local model costs nothing, but its token and call
caps still apply. "Today" is the person's local day in the display timezone.

**At a hard limit** an unattended run (`schedule`, `trigger`, `mcp`, `web`)
gets `BudgetExceeded`. An attended one is asked through a prompt provider (a
TUI modal; `input()` on the command line; nothing installed, or no terminal,
means no): only an explicit yes continues, records an `override` row with who
approved it, and lets *that run* go over *that* cap. `run_agent` turns a refusal
into status `stopped_by_budget` with a deterministic answer built from its
transcript (what ran, the findings so far, which limit, where to change it) --
not a model answer, so no answer guard needs to look at it. Unattended runs that
would use the model are refused before they start when their source is paused
or a cap they spend against is already used up; the refusal is recorded and
notified like any other run outcome. The deterministic pipeline makes no model
calls and is never limited.

**Triggers** fire at most `budget.trigger_fires_per_day` times per local day
(counted from their own fire ledger), with one "limit reached" notification per
trigger per day. An `investigate` action runs only while
`budget.trigger_investigations_allowed` is on -- off on a new install. The
first time this version runs on an existing data folder, if a trigger already
investigates, the setting is turned on once (the person already chose that),
with a one-time notice and a `note` row in the ledger.

**Circuit breaker.** A run fails for the breaker when its model was
unavailable, it errored, it hit the step limit without the rule engine ever
succeeding, or it looped (the same tool with the same arguments three times).
`budget.breaker_failures` failures within the window pause that source --
each schedule separately, triggers, MCP -- for the pause time, with one
notification; a paused source refuses to start until the pause ends or a person
resumes it in Settings → Budget. Interactive use is never paused, only warned.

**Soft limit and notifications.** At `budget.soft_limit_percent` of a limit the
TUI shows one warning line and (for the daily limits) one notification is sent;
"once" is a `budget_state` claim, so it holds across processes. Budget
notifications carry only fixed wording and numbers -- never prompts, findings
or keys.

## Live-switchable settings

A recurring bug shape, worth naming once: a module that does
`from kratos.kratos_config import SOME_SETTING` binds that name to whatever
value `SOME_SETTING` held at import time. If something later changes the
"live" value (a slash command, a test's `monkeypatch`), code holding the
frozen import never sees the update — it keeps using whatever was true when
the process started. This has bitten three different live-switchable
settings independently: the active LLM profile (`/model`), the active
investigation target (`/target`), and the journalctl sudo-vs-group-
membership flag.

The fix is the same in all three cases: read the setting through a function
call at the point of use (`kratos_config.get_active_target()`,
`llm_config.get_active_llm_base_url()`, or a plain
`_kconfig.JOURNALCTL_USE_SUDO` module-attribute lookup instead of a
`from ... import`), never through a name bound once at import time. Any new
setting that needs to change during a running process should follow the
same pattern from the start.

## Threat-intel enrichment

IP/hash/domain reputation lookups inherently send data about the protected
network to a third party. Since Kratos moved to a hosted model by default,
that is no longer the *only* thing that leaves — the core analysis already
sends logs and findings to the hosted LLM. Threat-intel is still kept
deliberately small and off by default, so that self-hosting the model leaves
nothing reaching out unless you opt in:

- **Cached (default)**: AlienVault OTX pulses, synced to a local file ahead
  of time on a schedule. A lookup during an investigation reads only this
  local cache — never a live call, regardless of whether an API key is
  configured.
- **Live escalation (opt-in)**: AbuseIPDB, reachable only when both
  `KRATOS_THREAT_INTEL_ENABLED=1` is set *and* a human approves that
  specific lookup at a real-time prompt. A configured key by itself
  activates nothing.

`check_ip_reputation` tries the cache first and only offers live escalation
if the cache had no answer; results are tagged `source: cache | live |
none` so a finding's provenance is always visible.

`correlate_findings` also runs the offline cache check automatically
against source IPs behind suspicious findings (a brute-force burst, a
correlated auth/network finding) and raises severity on a known-malicious
hit. This doesn't depend on the agent choosing to call
`check_ip_reputation` on its own — tool selection by an LLM isn't reliable
enough to gate a real corroboration signal on, so the rule engine does it
directly and unconditionally for the offline tier.

`run_vuln_scan` makes the same cloud-dependency tradeoff for CVE data:
nmap's `vulners.nse` script queries a live external API per scan, which
would reopen the same tension; `run_vuln_scan` uses `vulscan` against a
locally-cached, offline CVE database instead, at the cost of that database
needing its own periodic refresh and staleness reporting
(`check_vulscan_db_staleness`). The list vulscan ships in its repository stops
at 2013 and its maintained mirror rejects scripted downloads, so
`kratos vulscan-install` builds `cve.csv` itself from NVD's public yearly JSON
feeds, in vulscan's `ID;description` format (each ~300 MB feed is parsed as a
stream, so memory stays around 200 MB; the result replaces the old list only
after it validates). Staleness is judged by the newest CVE id the file contains
as well as the file's age. An old or missing list is returned as a
`coverage_gap`, so the final answer must say which CVEs weren't checked instead
of calling a service up to date.

## Self-writing tool loop

"Evo-loop" is the write → sandboxed test → human approval → keep pipeline
that lets Kratos extend its own tool registry at runtime
(`agent/self_write.py`, `self_test.py`, `self_approve.py`,
`self_write_loop.py`). A candidate tool is Python code the model writes
against a *human-authored* pytest harness — never synthesized from a
plain-language idea alone, since that would remove the one part of the
pipeline that actually defines "correct" for a tool that, once kept, runs
unsandboxed on the real host on every future call. The candidate is tested
inside a network-isolated, resource-capped container and only ever
imported and executed on the host after an explicit human approval; nothing
in the write or test stages runs outside the sandbox.

A generated tool that needs data from the target follows the same pattern
every hand-written target-facing tool does: import `ssh_remote` as a
module (`from kratos.adapters import ssh_remote`, never individual names)
and call `run_remote_command` / `run_remote_script` with a command that's
fixed at write time. A self-written tool doesn't get an exception from the
"no caller-built command" rule that `run_linux_command` already enforces —
building a command from a runtime argument would turn a generated tool into
exactly the generic remote executor the execution boundary rules out.

Review flags (`agent/self_review_flags.py`) are advisory signals shown to
the human reviewer before a keep decision, never a block: hardcoded
IP/credential-shaped literals inside a conditional, any loop-nested
conditional that affects what's included in the result, an "invented
filter criterion" (a hardcoded literal used in a filter role inside a
function whose own description implies general filtering logic), and a
check for a specific failure shape — a per-item loop that silently drops
the item entirely when a sub-fetch for it fails, rather than including it
with a null/error marker — and a failed remote read that comes back as an
ordinary empty result ("nothing found") instead of an error. The last two
exist because self-written tools reproduced each bug independently: an unattributed
or unresolved item is a more suspicious result for a security tool to
surface, not a less interesting one to drop. Full source is always shown
to the reviewer regardless of which flags fire — the flags direct
attention, they don't substitute for reading the code.

`run_self_write_loop` is reached only from a human's `/evolve` in the UI
(directly, or through the guided wrapper below); nothing in the agent loop's own tool
dispatch (`execute_tool_call`) can reach it, so a running investigation
can never trigger a write/test/keep cycle on its own. The agent may emit a
non-terminal `tool_proposal` suggesting a gap it noticed, but that's
render-only — it surfaces in the transcript and is never acted on
automatically.

The sandbox itself (`self_test.py`) is an ephemeral container with no
network device at all — not a disabled or firewalled one; the isolation
mechanism is the device's absence. Its image holds only the few packages the
tool layer imports (a test imports the tool layer with nothing else allowed,
so a new dependency is caught in the suite); the *running* Kratos package is
copied into each test container, so a candidate is always tested against the
Kratos it will run in, not a copy from whenever the image was built. It reuses the write step's candidate
file path only to read and execute it inside that container; nothing in
the write or approval stages ever imports or runs candidate code directly.

Two decisions in the approval step (`self_approve.py`) are deliberate and
distinct from the softer guard behavior in the agent loop's `final_answer`
checks:

- **No force-accept, ever, on the keep decision.** The agent loop's own
  structural guards eventually force-accept an answer after a bounded
  retry budget, tagging it with a note — an acceptable tradeoff for a
  one-off report conclusion. A keep decision is different: it persists a
  new capability into the tool registry, permanently, for every future
  investigation. An unanswered, denied, or interrupted approval prompt
  always resolves to a permanent reject — there's no retry budget and no
  eventual auto-accept path.
- **Per-tool `requires_approval` is decided at keep time**, as its own
  explicit question, not a global setting and not hardcoded — framed as an
  inverted question ("allow this to run without approval?") so the
  existing fail-safe (a non-"yes" answer denies) naturally defaults a
  non-answer to *requiring* approval rather than granting blanket trust.

A kept tool persists to a Python file plus a shared `metadata.json`
sidecar (`requires_approval`, kept-at timestamp, source file). That
sidecar is a classic read-modify-write target: two genuinely concurrent
keep operations (not malicious, just ordinary concurrent use) can corrupt
it if the write isn't protected. The persist step writes via a temp file
plus atomic rename, and serializes the whole read-modify-write span under
one file lock, so concurrent keeps always produce a clean, single winner
rather than a merged or corrupted file. The session store (SQLite) has the same category of risk from two concurrent `kratos`
processes and is covered by its own concurrent-write test for the same
reason — this is a recurring pattern in the codebase, not two unrelated
fixes.

Kept tools can optionally be exercised once against the real target at
keep time, read-only, before being persisted (opt-in per run, default
off) — because the sandbox's no-network isolation means a candidate can
pass its sandbox test cleanly and still fail against the real target (a
root-only file read without sudo, an assumption about command output that
doesn't hold). This closes a real trust gap the sandbox alone can't: a
mock-shaped test passing doesn't guarantee the real command against the
real target behaves the same way.

A separate, UI-agnostic wrapper (`agent/guided_evolve.py`) sits over this
same pipeline to make it usable by someone who's never used it before —
it drives the build through an abstract "ask a question / show something"
interface rather than a hardcoded prompt sequence, so the same core logic
can back more than one interface (the Textual TUI today; a future
programmatic "build the missing tool" hand-off from the presets flow,
described below). It changes none of the underlying invariants: the pytest
harness still defines "correct," an LLM-drafted harness is only ever shown
for review and never trusted unedited, the keep decision still has no
force-accept path, and the sandbox's isolation is untouched — this module
only wraps the framing around the unmodified pipeline. Where it needs to
describe what a harness actually checks in plain English, it parses the
harness's own AST rather than asking an LLM to summarize it — a summary
could drift from what the test actually asserts, which would silently
reopen exactly the rubber-stamp risk the review-flags mechanism exists to
close.

## Where settings and data live

One module, `kratos/paths.py`, decides every location, and none of them depend
on the working directory. A source checkout (including `pip install -e .`)
keeps everything next to the code, as it always has: `.env`, `data/`,
`kept_tools/`, `sandbox_staging/`, `vulscan/`, `llm/models/`. An installed copy
lives in site-packages, which isn't writable or upgrade-safe, so it uses the
XDG per-user folders: `~/.config/kratos/.env` for settings and
`~/.local/share/kratos/` for everything else, laid out like a checkout.
`KRATOS_HOME` (a real environment variable, since it decides where `.env` is)
puts settings and data under one folder. An explicit `--data-dir` still wins
for the data folder.

Folders Kratos creates are owner-only (0700), and the settings file is written
atomically and created 0600, since it holds API keys. `kratos init` creates it
from the template shipped in the package, and `/doctor` warns when it's
readable by other users.

## Stored data: the inventory and the no-deletion rule

`kratos/datainv.py` holds `CATEGORIES`: every kind of data Kratos keeps -- what it
is in plain words, where (files under the data folder, `kratos.db` tables, files
next to the code), whether it is personal data, and how it grows. `kratos data`,
`/data` and `/doctor`'s "stored data" row read it; sizes come from the file system
and SQLite's `dbstat`, with the database opened read-only.

**A new table or data folder needs a `CATEGORIES` entry.** `tests/test_datainv.py`
scans the source for every `CREATE TABLE` and every name joined onto the data
folder (`data_dir / "x"`, an f-string, or a module constant named `*_DIR`) and
fails on one no category owns. Lock files, sockets and the `tmp` scratch folder
are listed as runtime entries, not data.

**Kratos deletes nothing on its own.** `tests/test_no_automatic_deletion.py` finds
every `unlink`, `rmtree`, `remove`, `rmdir`, `truncate` call and every SQL
`DELETE FROM` / `DROP TABLE` / `VACUUM` statement and checks each against a
reviewed allowlist keyed by (file, function, kind), each with a reason: a temp file
the function just created, the person's own command, a merge of current state, a
rebuild of public data. Three automatic, bounded cleanups predate the rule and are
listed as owner decisions (sub-agent telemetry: newest 500 rows per machine;
connection events: newest 200; expired unused pairing codes after a week) and
shown in the inventory. Retention is the person's: `kratos data prune` (traces,
sessions, host events) and `kratos snapshots prune` both plan first, delete only on
`--apply` / a TUI confirmation, refuse inside an agent tool call, and `data prune`
records each prune in `data_prunes`. A prune that would leave other data claiming
something false (log-sync coverage over deleted host events) is refused unless
`--force-orphans`, which removes that claim too.

## Run records (traces)

`kratos/trace/recorder.py` writes one JSON record per run to
`data_dir/traces/<YYYY-MM-DD>/<run_id>.json` (owner-only, atomic). The record is
built in a ContextVar -- never a module global -- so parallel runs in separate
threads each have their own, and a thread started with a copied context (collection
checks, `asyncio.to_thread`) records into its run. A run opened inside another run
scope (a trigger's investigation inside a scheduled run) gets its own record with
`parent_run_id`, and the parent notes it as a `child_run`. While the run goes, a
`.partial` copy is refreshed every few seconds; a run that raises leaves it as its
record. A span that ends after its run finished (a check that was still running in
the background) rewrites the file.

Where the hooks are -- one each, so every caller is covered:

| Span | Hook |
| --- | --- |
| `run` | `run_trace(...)` in `run_agent`, `run_pipeline`, `run_standard_audit`, `run_scheduled`, `run_headless_investigation`; nested kinds become a `run` span in the same record |
| `model_call` | `llm_interface._metered_call`, the one model choke point (sizes always; text only with `trace.store_prompts`; the budget ledger row id and cost). A request made with no record open (the message router, a plain chat reply, drafts, compaction, `kratos chat`) gets one of its own (`recorder.standalone_record`): same run (budget and masking unchanged), file `<run>-<purpose>` (`recorder.purpose("route message")` names it), so every request to the model leaves a record and none takes the investigation record's name; `trace list` shows `<12 chars>-route`, and a bare id means the run's main record |
| `tool_call` | `agent.loop.execute_tool_call` (args after the dispatch guards' rewrites, approval asked/answered, result capped at `trace.max_result_bytes` with a sha256 of the whole, the envelope call id the model saw) |
| `collection_check` | `collect.runner.prepare` (reused / ran / skipped; a check's tool calls nest under it; still running at the start budget, settled later) |
| `guard` / `answer` | `agent.loop`: each rejection with its correction's first line, each NOTE a guard added, and the answer's composition (the findings block's ids in order, NOTEs, the model's text length) |
| `collection` / `collection_settled` | `agent.loop`: the collected report the model started from (every check's status/summary/finding ids, the correlation, what was still running) and the checks folded in before the answer -- enough to replay a run without the machine |

`kratos trace list/show` and `/trace` read records back and print every string
through `untrusted.for_display`. The optional OpenTelemetry copy
(`kratos/trace/otel.py`, the `otel` extra, `trace.otel_export` plus
`OTEL_EXPORTER_OTLP_ENDPOINT`) replays a finished record into spans named by the
GenAI semantic conventions (`invoke_agent kratos`, `chat {model}`,
`execute_tool {tool}`) with the run id as the OTel trace id, on its own thread with
a short timeout; it exports names, timings, token counts and statuses only.

## Session persistence

Kratos stores session/turn history in SQLite (`data_dir/kratos.db`), no
server, no auth. Every turn is its own committed write as it happens, not
buffered and flushed on exit, so a crash or Ctrl+C never loses session
state. Concurrent writers (two terminal tabs against the same store) are a
real scenario, not a hypothetical one, and are exercised with genuinely
separate OS processes rather than threads, since threads sharing the GIL
wouldn't exercise the same contention SQLite actually has to handle from
independent processes.

## Events

Every log line Kratos reads becomes one **event**: a typed record whose field
names are the [Elastic Common Schema](https://www.elastic.co/docs/reference/ecs)
(ECS 9.5.0), with Kratos's own fields under `kratos.*` (how the line was read --
`ssh`, `agent` or `local` --, which read, which run, the read's window and
coverage, the converter). One Python table (`kratos/events/fields.py`) is the
source of truth; the dataclass, the ECS document, the SQL index columns and the
committed JSON Schema (`kratos/events/schema/event-v1.schema.json`) are derived
from or tested against it. ECS because Sigma's tooling maps to ECS names, so
Sigma rules later become a mapping exercise (`kratos/events/sigma_fields.py`
already lists every field SigmaHQ's Linux rules use, mapped or with the reason
it can't be yet); OCSF, when it comes, is an export mapping, never a second copy.

The parsers are unchanged; converters map what they already produce. Four reads
record events: Kratos's own auth log (`parse_auth_log`), the target's sshd/sudo
journal (`read_journalctl`'s background auth read), the target's journal for any
unit (`read_journalctl` itself) and account/group changes
(`list_privileged_accounts`). Recording is best-effort and additive: a store
problem is logged once and the tool returns exactly what it would have without
it; events are never sent to the model as a bulk dump.

Times are absolute UTC. journald times already are; a classic syslog line has no
zone or year, so it is read in the machine's own zone when known (else UTC,
flagged `kratos.time_zone_assumed`), and a line dated more than a day ahead
belongs to the previous year. Credentials are masked before anything is stored
(`--password`/`--token`/... values, `PASSWORD=`-style assignments, `-p` for the
MySQL clients and sshpass, URL passwords, `Authorization:` values, Kratos's own
API keys), and long text is capped (raw line 2 KB, message and command line 4 KB).

Events live in `kratos.db` (`host_events`), per machine (`target_key()`), and are
append-only: a trigger aborts any UPDATE, and nothing in Kratos deletes them (a
person may). The same line read twice -- windows overlap all the time -- gets the
same deterministic ID (a hash of machine, dataset, time to the microsecond,
program and text) and is stored once. About 1 GB per million events (measured: 980 MB);
queries by time, source IP, user, program or file hash stay well under 200 ms at a
million (scripts/bench/events_bench.py). `kratos events` prints them.

**Runs.** Each piece of work -- a TUI turn, a command, a scheduled run, a trigger
investigation, an MCP call, `/evolve` -- opens a run (`kratos/run_context.py`):
an ID, how it started (`interactive`, `schedule`, `trigger`, `pipeline`, `mcp`,
`web`, `evolve`, `cli`), the machine and the session. Events carry the run ID;
spending will too. A ContextVar doesn't flow into new threads, so every worker
thread opens its own; a static check in the tests fails if a new path to the
model or a tool doesn't.

**Settings people edit** (limits and toggles, as opposed to connection settings in
`.env`) live in `kratos.db` (`app_settings`, `kratos/settings_store.py`) so every
Kratos process reads the same value without a restart. No agent tool can change
one: `set` refuses while a tool is running, and a test scans every tool's module.
Each component of `kratos.db` migrates itself through `schema_versions`.

## Collection layer

**Code collects, the model reasons.** Before the investigation loop's first model call,
`kratos.collect.runner.prepare()` makes sure the basics are fresh for the machine (ports, 24 h
of sign-in activity, log tampering, privileged accounts, where someone could keep access
(persistence), configuration, log sync): each
*check* is a registered wrapper over a tool Kratos already has (`collect/checks.py`), run
through `execute_tool_call` so the dispatch guards, approval gating and event recording still
apply. A check declares its cost class (`quick` runs at investigation start; `slow` -- known
vulnerabilities, a malware sweep, the critical-files diff -- runs in the standard audit,
schedules and `/collect all`), freshness setting (`collect.ttl.<check>_minutes`), the
findings-engine input it refreshes, the transports it supports and its own time budget. A new
detection read is a check, never a new entry in the model's tool list (that list is frozen --
`tests/test_collect_loop.py::test_the_models_tool_list_is_frozen` -- and changing what the model
sees needs the tool-selection eval with no regression).

**Freshness and claims.** `collect_state` (one row per machine and check, in `kratos.db`) holds
the last result. A result younger than its limit is reused (and re-run if its input files are
gone); a stale one is *claimed* inside `BEGIN IMMEDIATE`, so the TUI and a scheduled run never
run the same check on the same machine at once -- the loser waits for the winner's result. A
claim older than twice the budget belongs to a dead process and is taken over. A reused result
does not touch the input files, so the lifecycle's "collected in this run" rule still holds: it
can't mark a finding fixed. Checks run in parallel threads, each pinned to its machine.

**The start budget ends the wait, not the work** (phase A audit). At the start budget
(`collect.start_budget_seconds`, 15 s, the SSH warm-up included) an investigation starts. A check
still inside its own limit keeps running in the background (`prepare(background=True)`), records
its result when it finishes, and shows as "still running" in the digest; before the final answer
the loop waits for such checks for at most 20 s (`CollectionReport.settle`) and re-correlates, so
their findings reach the answer and their "still running" gap disappears. A check past its *own*
limit is cancelled: `utils/cancel.py` kills every `ssh`/`nmap` it started, and the remote side stops
too (`ssh_remote._with_remote_deadline`). Measured on a real VPS over the internet: before, every
investigation started without log tampering, open ports, what is running and persistence (cut and
thrown away at 15 s every time); now all nine checks complete -- the port scan (nmap -sV, ~2 min over
the internet, own limit 180 s) finishes in the background and is reused for an hour. `kratos collect`
and `/collect` wait for every check's own limit (`runner.full_budget`): nobody is waiting to ask the
model anything.

**SSH connections** (`utils/ssh_slots.py`). All sessions to one machine share one authenticated
connection (`ControlMaster=auto`, `ControlPersist=60`, `ServerAliveInterval=15`; the socket in a
private 0700 runtime folder, named `%C`) -- the way Ansible handles many commands to one host -- and
collection opens it before the checks start (at most 3 s). At most four sessions per machine run at
once, across every Kratos process (`flock` on per-machine slot files; a crashed process frees its
slot; a waiter stops at its own time limit or when its check is cancelled). Measured: 19 logins per
cold collection and up to 9 in one second became 1, well under sshd's `MaxStartups` (10:30:100) and
`MaxSessions` (10); cold start 4.8 → 4.1 s. A stale or killed master is replaced on the next read;
an unusable runtime folder turns sharing and the cap off with a warning, never fails a read.
`KRATOS_SSH_MUX=off`, `KRATOS_SSH_MAX_SESSIONS` (1–10) override.

**What the model receives.** A digest in the first message (`collect/digest.py`), built only
from Kratos-written text: each check's one-line summary (made from structured results, never raw
log lines), finding IDs and severities, what each finding is -- the title of rules whose titles
hold no data from the machine, else a fixed description (`finding_facts.RULE_TEXT`: PRIV-*,
PERSIST-*, LIVE-*, PKG-*) -- and facts that were validated on the way in (source addresses and a
known-malicious match, process ids, CVE ids, package names; never a path, command line or account
name written on the machine). Before the audit, LIVE-002 reached the model as "LIVE-002 (high)"
and nothing more, and the model ignored it. The correlation Kratos ran is
*seeded* into the loop (`last_correlate_findings`, the staleness warning, coverage gaps), so
Guards 1/3/4 judge the answer against it exactly as if the model had called it first. If the
model's own tools refresh an input afterwards, Kratos re-runs `correlate_findings` by code before
the guards evaluate the final answer (no model call) -- a new HIGH finding reaches Guard 3.
Counting questions are unchanged: `measure_auth_activity` counts on the target; the event store is
for rules, hunts and timelines.

**Incremental log sync** (`collect/sync/`). Per machine and source Kratos keeps a position in
`kratos.db` (`sync_cursors`) -- the journal cursor, or (inode, byte offset) of a classic file --
and reads forward from it. Journal: `journalctl --after-cursor` (the cursor is checked against
systemd's format before it is ever placed in a command), capped at `collect.sync_max_lines` per
round; no `-n` (version-dependent), no `--cursor-file` (it would write on the target). Files: a
shell script (or the agent's `file_sync` probe) slices `[offset, offset+n)` and feeds it to the same
awk extractor as `read_host_logs` in *chunk mode*, which only handles whole lines, holds back a
multi-line record still open at the end, and reports the bytes consumed so the offset moves exactly
that far. A first sync starts at the tail. Rotation by rename is followed through the old inode;
copytruncate, a vanished file, or a journal that was vacuumed past the position (found by comparing
the journal's oldest entry with where the last sync got to) are recorded as incomplete spans in
`sync_coverage`. `cursors.covered(target, source, start, end)` is true only for a window with no
hole in it. The position moves only after the events are stored. Limitation: a log deleted and
recreated that reuses the old inode and outgrows the saved offset before the next sync looks like
the same file; the tamper check (head hash) is what catches that.

**Standard audit.** `run_standard_audit()` is `prepare(classes=("quick","slow"), force=True)` plus
one correlation, reported as steps; `/run`, `kratos run` and audit schedules use it, so there is one
implementation of "look at the machine".

## Adding a detection check

A new read of the machine (Phase B and later) plugs in through two registries and touches no
hand-wired code (phase A audit: A.1, A.5 and A.2 had each added the same five pieces by hand to
`findings_engine.py`, the place every feature edited):

1. **Collection** -- `kratos.collect.registry.register(Check(...))`: cost class, freshness setting,
   the input category it writes, transports, its own time limit, priority. It runs at
   investigation start (or in the standard audit for `slow`), in parallel, under the shared SSH
   connection and session cap, and in the background if it outlasts the start budget.
2. **Findings** -- `findings_engine.register_snapshot_source(SnapshotSource(...))`: the category,
   where its files live (`folder`, `pattern`), the rules it raises (`rule_prefix`), and four
   functions -- `load` (the snapshot if recent enough), `build` (its findings; every
   `Finding(id="...")` a literal), `closes_findings` (is this read complete enough to say a
   finding is gone), `blind` (what it could not look at, per entity). `find_latest_inputs`, the
   rule-to-input map, `generate_findings`, the report loader and the lifecycle's completeness and
   blind-spot rules all iterate the registry; sources build in registration order.

Then: each rule's lifecycle kind in `lifecycle/rules.py` and its ATT&CK entry (labels or posture)
in `attack/mapping.py` -- tests fail until both exist, and the lifecycle test scans the module each
registered builder lives in. A rule whose title holds machine text gets a fixed description in
`finding_facts.RULE_TEXT`, and its validated facts go in `finding_facts.safe_facts`, so the model
and the answer's findings block can name it. Bundle-side reads follow §Sub-agents (one script and
one probe printing the same records, a bundle version bump). The model's tool list stays frozen.

## Persistence checks

**Inventory on the machine, judging on Kratos** (`adapters/persistence.py`, `kratos/persist/`).
One closed table of persistence locations per distribution family (cron, at, systemd units and
timers, SSH authorized keys, SUID/SGID files, `ld.so.preload`, kernel modules, shell startup, PAM,
boot/init, udev, package-manager hooks) is read two ways that print the **same** tab-separated
records: a fixed POSIX sh+awk script over SSH (run as the SSH user, no sudo) and the sub-agent's
`persistence_inventory` probe (a stdlib walk as root through the hardened opener in
`logsources/hostfiles.py`). One parser (`parse_output`) reads both; an awk program and its Python
twin pick the same executing lines (a test runs both on the same files under mawk/gawk/BusyBox).
The read never sends whole files -- for a text item only the lines that execute something, capped
(20 per file, 200 bytes each) and masked (`events/redact`); an authorized_keys file leaves the
machine only as key type, SHA-256 fingerprint, options and comment, never the key. Package
ownership is looked up **on the machine** from the package database files (`dpkg`'s `.list`s,
`rpm -qf` in one batch, apk's installed db), so the main noise filter doesn't need a package
database on Kratos. Reads are bounded (per-location file caps, a SUID `find` limited to local
filesystems with a timeout, a 2 MiB total cap, an overall time budget); over the budget the read
is partial and says so, never hangs.

**Judging** (`persist/judge.py`) runs entirely on Kratos from (current inventory, baseline,
ownership). The filters, in order: *owned by a package* (following a symlink to its target, which is
how an enabled unit looks) removes the bulk; *in the baseline* decides newness; a closed list of
*shapes* (`persist/shapes.py`) adds "worth a look" and, when a new unowned item is also strongly
shaped (a reverse shell, download-and-run, decode-and-run), raises it to high. Rules `PERSIST-001`
(new unowned item) through `PERSIST-008` (unowned PAM module / `pam_exec` script), plus `PERSIST-009`
(a run note listing what could not be read). `PERSIST-007` (a package's own file changed from what it
shipped, via `dpkg --verify`/`rpm -V`/`apk audit`) is the slow part and runs only in the full audit.
Each finding carries item identities (`path#sha256[:12]`, `user:fingerprint`, `module@taint`) so a
*changed* item is a new entity and reopens a decision, and ATT&CK v19 labels for the item's area
(verified against the official v19 STIX data).

**Baseline** (`persist/baseline.py`, table `persistence_baseline`, one row per machine, the identity
map zlib-compressed). Kratos's first look at a machine is the baseline; a later item not in it is
"new". The baseline is never updated with items a later run found -- a person's decision on the
finding is how "this is fine" is said -- but its *coverage* only grows: an area this Kratos knows and
the baseline doesn't, or a location that was unreadable then and readable now (SSH-as-user, then the
sub-agent as root), is merged in as a first look so a wider read doesn't report a whole machine as
new. Both are recorded (new areas, re-read gaps) as run notes.

**The check** (`persist/check.py`, `persist/record.py`). `persistence` (quick) and
`persistence_verify` (slow) register with the collection layer like any other check; the read, judge
and baseline-update happen in `record.run`, which writes `data_dir/persistence/persistence_<time>.json`
(the judged signals). `find_latest_inputs` category `persistence` picks it up; `generate_findings`
turns its signals into `PERSIST-*` findings. A read that fails saves nothing and leaves the baseline
alone, so a failed read never becomes "nothing there"; an incomplete read, or one that couldn't read
the package database, can't mark a `PERSIST-*` finding mitigated (`_apply_lifecycle` folds persistence
into the lifecycle's incomplete set). No tool is added to the model's list (A.1 is a check, not a
tool).

## Live-response reads

**What is running right now, by code** (`adapters/live_response.py`, `kratos/live/`). The same
inventory/judge split and transport pattern as the persistence check, over `/proc` instead of the
filesystem. A fixed POSIX sh+awk script over SSH (as the SSH user) and the sub-agent's
`live_inventory` probe (a stdlib walk as root) print the **same** tab-separated records; one parser
reads both (an awk program splits `/proc/<pid>/stat` into pid/ppid/start-time, another parses
`/proc/net/{tcp,tcp6,udp,udp6}`; both tested under mawk/gawk/BusyBox). Per process: pid, ppid, start
time, uid/user, `comm`, the `exe` link (with `(deleted)`/`memfd:` markers), a capped masked command
line, cwd, cgroup, whether `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH` is set (the *value* only for the
first two, masked), and socket inodes from the fd links. Listening and established sockets come from
`/proc/net`; executables in `/tmp`, `/dev/shm`, `/var/tmp` (and `/run/user` on the agent) are stat'd,
header-classified (ELF/script) and hashed through the hardened opener. Package ownership of exe paths,
preload libraries and dropped files reuses persistence's on-machine ownership lookup. Bounded (5,000
processes, a dropped-file `find` with a timeout, a 4 MiB cap, an overall budget); over the budget the
read is partial and says so. No environment value other than the preload library path ever leaves the
machine; nothing is written on the target. Dropped files over 64 MiB are listed but not hashed on
either transport (a `HBIG` record), and the SSH script's hashing runs under `timeout`: one huge
executable in `/tmp` used to keep `sha256sum` busy past the read's limit, losing the whole read.
The script also reports the temp folders it could not enter (`TDENY`) and a `hidepid` `/proc`.

**Remote deadline.** Every SSH read (`ssh_remote.run_remote_script`/`run_remote_command`) runs on the
target under `timeout -k 5 <the client's own timeout>` when the target has `timeout(1)`: killing the
local `ssh` client does not stop the remote side (no pty, no hangup), so a busy remote command used to
outlive Kratos. GNU `timeout` kills the whole process group; BusyBox's kills only its direct child, so
on BusyBox-only machines a busy grandchild can still finish on its own (each read keeps its own
internal bounds for that reason).

**Judging** (`live/judge.py`) runs entirely on Kratos from one inventory -- there is no baseline,
because "right now" is point-in-time. `LIVE-001` (deleted running binary not explained by an
upgrade), `LIVE-002` (memfd / deleted-in-tmp execution), `LIVE-003` (unowned `LD_PRELOAD`/`LD_AUDIT`;
owned is "worth a look"), `LIVE-004` (a dropped executable -- running: high, present: medium),
`LIVE-005` (a listener run by a temp/deleted/unowned process), `LIVE-006` (a shell under a network
service), and `LIVE-007` (a run note: the restart-needed hint for upgrade-deleted binaries, and what
could not be read as a non-root SSH user, with the sub-agent fix). A process is identified by
`exe|pid|starttime`, so the same process is the same finding across runs and a reused pid is a new
one; a dropped file by `path#sha256[:12]`. `LIVE-001/002/003/005/006` are *occurrence* rules (a later
run that re-read and no longer sees the process marks it inactive), `LIVE-004` is a *condition* (the
file is a state), `LIVE-007` is a run note. ATT&CK v19 labels: File Deletion (T1070.004),
Reflective Code Loading (T1620), Dynamic Linker Hijacking (T1574.006), Unix Shell + Web Shell
(T1059.004, T1505.003); `LIVE-004`/`LIVE-005` are posture and carry none.

**The check** (`live/check.py`, `live/record.py`). `live_response` (quick) registers with the
collection layer; `record.run` reads, judges and writes `data_dir/live/live_response_<time>.json`.
`find_latest_inputs` category `live_response` picks it up; `generate_findings` turns its signals into
`LIVE-*` findings. A failed read saves nothing (never "nothing running"); an incomplete read can't
mark a `LIVE-*` finding inactive. No model tool is added (A.5 is a check). Nothing is killed: a
`kill <pid>` recommendation is shown, never run.

## Package vulnerabilities

**Installed packages, matched offline** (`adapters/packages.py`, `kratos/pkgvuln/`). The inventory is
one fixed POSIX sh script (in the agent bundle) that the SSH path runs as the SSH user and the
sub-agent runs through `sh -s` (its `package_inventory` probe, agent 0.7.0): `dpkg-query -W` with the
source package and source version (Debian advisories are listed by source), `rpm -qa` with
`EPOCH:VERSION-RELEASE` and the source RPM, Alpine's `/lib/apk/db/installed` (origin), plus
`/etc/os-release`, `uname -r`, the installed module trees and `reboot-required`. One parser; names and
versions that don't look like names and versions are dropped and counted. The list is stored in
`kratos.db` → `pkg_inventory` (one row per distinct package set per machine — a re-check that finds the
same set only moves `last_seen_at`) and never leaves the Kratos machine.

**The index** (`pkgvuln/index.py`, `pkgvuln/update.py`) is a separate, replaceable file,
`data_dir/vulndb/vulndb.sqlite`, built by `kratos vulndb-update` — the only code that fetches
vulnerability data, and only when a person runs it. It holds only the releases of machines Kratos
knows (a *selector* such as `ubuntu:22.04`, `debian:12`, `alpine:3.22`, `rocky:9`), from OSV's
per-ecosystem exports (`<ecosystem>/all.zip`, verified against the object's MD5 from `x-goog-hash`, a
size cap, the zip's CRCs and a JSON parse; a raw-byte prefilter skips records naming no wanted
release, so Ubuntu's 7 GB export parses in about a minute), CISA's KEV feed, FIRST's EPSS daily file
and NVD's yearly 2.0 feeds (the network scan's streaming parser, checked against each feed's published
SHA-256) for CVSS. Later updates are incremental: OSV's `modified_id.csv` (with `If-None-Match`) names
the changed advisories, fetched one by one when there are at most 2,000; NVD's 8-day "modified" feed
replaces re-reading every year. The new index is built in `vulndb.sqlite.tmp` (a SQLite backup of the
current one for an incremental build), checked with `PRAGMA integrity_check`, and swapped in with one
`os.replace`; any OSV failure, a failed check or an interruption (tested with `kill -9`) leaves the
previous file untouched, and the next update removes the leftovers. KEV/EPSS/NVD are enrichment: one
that can't be fetched keeps its previous rows and the result names it. Only bug-fix/enhancement
notices (RHBA/RHEA/ALBA/ALEA) and withdrawn advisories are skipped. OSV's explicit `versions` lists are
kept only for entries with no range (elsewhere they are an expansion of the range, and Ubuntu's alone
is gigabytes).

**Matching** (`pkgvuln/match.py`, pure, `univers` 32.0.1 for Debian/RPM/Alpine version comparison —
no hand-written comparison; a version it can't read is counted, never guessed). Each installed
package is looked up under the name its distribution's advisories use (Debian/Ubuntu: source package
and source version; Alpine: origin; RPM: binary; a signed kernel image, whose template source
`linux-signed-*` no advisory names, as the kernel source it was built from with its own version).
When several versions are installed under one name (old kernels are kept), the package is judged by
the newest: upgrading can't fix the old copies, and a stale *running* kernel is `PKG-003`'s, whose
severity uses the running kernel's own CVEs. Affected = in an `ECOSYSTEM` range
(`introduced <= v < fixed`, or `<= last_affected`) or in an explicit version list. Per CVE, a
distribution's **per-CVE record** (`DEBIAN-CVE-*`, `UBUNTU-CVE-*`, `ALPINE-CVE-*`) decides when it names
the package; bundle notices (DSA/DLA, USN, RLSA, ALSA, RHSA) decide only otherwise — a notice fixes all
its CVEs at one version, which can be later than a given CVE needed. And when the per-CVE data covers
the release (at least 5,000 records name it — true for Ubuntu and Debian 12+, not for Debian 11), a
per-CVE record that does **not** name this release means the tracker found it unaffected, so a notice
listing that CVE among others doesn't report it (found by the cross-check below: 43 USN-only pairs on
Ubuntu 22.04). A CVE the installed version is past the fix for is "fixed", which is what the network
cross-check uses.

**Priority and rules** (`pkgvuln/priority.py`, `pkgvuln/record.py`). Per CVE: on KEV → critical ("act
now"); fixable with EPSS ≥ `vulndb.epss_high` (0.1, EPSS's commonly cited threshold) and CVSS ≥ 7 →
high; fixable CVSS ≥ 7 → medium; other fixable → low. Missing CVSS falls back to the distribution's own
rating; "negligible"/"unimportant" caps at low (KEV still wins). `PKG-001` (fixable) is one finding per
package — the first rule with a non-empty `subject` — with the CVEs as entities, so a new CVE reopens a
decision. `PKG-002` (no fix yet; low, info when all negligible, critical if one is on KEV) is one finding
per machine with `package:CVE` entities: nothing can be installed, and a fully patched Ubuntu server has
dozens of such packages, so per-package findings would be noise. `PKG-003` is a newer kernel
installed than running (running vs newest installed kernel package, plus Debian/Ubuntu's
`reboot-required`), entity the newest kernel; `PKG-004` is a run note for what wasn't covered (no or
stale data, no data for the distribution, an incomplete read). All three PKG rules are conditions; an
incomplete check (partial read, no matching data) can't close one. No ATT&CK labels (weakness, not
behaviour). The upgrade command is shown, never run; the remediation catalogue has a
`package.upgrade` template whose package must appear in a finding. `record.run` writes
`data_dir/packages/packages_<content key>.json`, named by what the result depends on (inventory hash,
index build, threshold), so repeated checks of an unchanged machine rewrite one file.

**Network cross-check** (`pkgvuln/crosscheck.py`). For each CVE `VULN-001` matched by service-version
text, if the machine's distribution lists that CVE for installed packages and every one of them is
past the fix, the CVE is noted as "already fixed by the installed packages — a backported fix" and
removed from `VULN-001`'s entities (it stays in the evidence); if none remain, `VULN-001` drops to info.
Done locally at correlation time from the saved inventory and the index. **Except** when the live-response
snapshot saw the program listening on the matched port and it is not from a package that has the fix
(`listener_doubts`, phase A audit: a build in `/usr/local`, an unowned or memory-only program): the CVE is
kept with the reason. That is the case the network check exists for (software not installed from
packages). An unseen listener (another user's socket over SSH) leaves the package verdict as it was.

**Checked against other scanners** (2026-10-15, release-day Docker images, pairs of (source
package, CVE) that are affected and fixable; Trivy 0.76.0, OSV-Scanner 2.7.0, debsecan 0.4.20.1):

| Image | Kratos | Trivy | OSV-Scanner | debsecan |
|---|---|---|---|---|
| `debian:12.0` (88 packages) | 94 | 100% | 100% | 79.8% — debsecan's bookworm feed lacks 19 pairs the DSAs and Debian's per-CVE records list (incl. KEV CVE-2023-4911) |
| `ubuntu:jammy-20220428` (101) | 215 | 99.1% — 2 pairs only in Ubuntu's USNs | 84.6% — its 39 extra are USN-listed CVEs Ubuntu's per-CVE tracker marks 22.04 unaffected (Trivy agrees with Kratos) | n/a |
| `alpine:3.17.0` / `3.22.0` | 44 / 55 | 100% / 100% | 100% / 100% | n/a |
| `rockylinux:9.0` (157) | 260 | 70.1% — Trivy reads Rocky's own errata, which has 9.x advisories OSV's Rocky export lacks | 87.5% — its extras are PyPI wheels (out of scope) and Rocky 8/10 advisories it applies to a Rocky 9 machine | n/a |

OSV-Scanner's offline mode finds nothing on Ubuntu images (it labels packages `Ubuntu:22.04`, OSV's data
says `Ubuntu:22.04:LTS`), so its online mode was used for these public images. RHEL-family coverage is
the weak spot: OSV's Rocky 9 data is incomplete; adding Red Hat's own data for Rocky would reach 74.5%
against Trivy (and add 92 pairs Trivy doesn't list), so it was not adopted without a ground truth.

**The check** (`pkgvuln/check.py`): `packages`, quick (one listing, local matching; ~0.1 s to match a
few hundred packages), 6 h freshness; `kratos vulndb-update` expires it so new data is used at the next
collection. No model tool was added.

## Log sources and tamper detection

**Sources.** `kratos/logsources/catalog.py` is a closed table of seven log sources
(auditd, sudo, cron, systemd unit activity, firewall, packages, web), each with its
journal matches and file paths **per distribution family** (Debian/Ubuntu,
Rocky/RHEL, Alpine) and, where nothing exists, the reason (OpenRC has no unit log;
apk keeps no install history). A read names a source; the table decides what that
means on the machine -- no path, pattern or match ever comes from the model or the
wire. Journal sources use a closed match enum (`cron`, `systemd_pid1`, `kernel`,
`sudo`), newest first, absolute epochs, `--output-fields` so only what Kratos
parses leaves the box.

**One extractor, two transports.** File sources go through one awk program
(`logsources/logread.py`) that understands nine time formats (syslog and RFC3339,
audit epochs, combined access logs, nginx/Apache error logs, dpkg, apt history
blocks, ISO with an offset, sudo's own logfile). It keeps only the requested
window, newest first, up to a line and byte cap, so only the window crosses the
link. Zone-less times travel as local wall-clock "pseudo-epochs" and are converted
with the machine's zone and filtered exactly on the Kratos side. It runs unchanged
under mawk, gawk and BusyBox awk (tested under all three; fixed regexes reach awk
through `ENVIRON`, never `-v`, whose escape handling differs per awk). Over SSH a
fixed script pipes each file into it **as the SSH user** -- group membership
(`adm`, `systemd-journal`, auditd's `log_group`), never `sudo cat`; the only new
sudo lines are `auditctl -s` and `auditctl -l`. The sub-agent (0.4.0) reads as
root, so it opens every file through `logsources/hostfiles.open_log_file`: each
path component opened `O_NOFOLLOW` from a pinned `/`, a regular file with exactly
one link, the name looked up again after opening and required to be the same
inode, credential paths refused -- the same approach as the YARA walker -- and
hands awk the open descriptor. A symlink or hard link to `/etc/shadow` planted in a
log directory is refused by both transports (proven on the lab). Both print the
same lines; one parser reads them. Parsers per source (`logsources/parsers/`) turn
lines into ECS events (auditd records grouped by event serial, hex-decoded
arguments; credentials in command lines and URL query values masked). Journal
events now take their ID from the entry's `__CURSOR`. Reading is the
`read_host_logs` tool: a summary for the model (counts, tops, a few masked
lines, coverage) and the events in the store -- never the raw log.

**Tamper checks** (`logsources/tamper.py`, run by `check_log_integrity`, also an
optional step of the standard audit; the investigating model reaches it as
`read_host_logs` with `source="tampering"`, while `/use` and pipelines call
`check_log_integrity` directly). `read_host_logs` is listed to the model only when
the question is about what it reads (programs run, cron, services, firewall,
installs, the web server, tampered logs): measured on the eval with
gemini-3.1-flash-lite, *any* extra entry in the tool list made a broad "check for
suspicious activity" skip the port scan in about 4 of 20 runs (losing the
exposed-SSH brute-force finding), while the same code with the old list matched
the old results. A broad investigation therefore sees exactly the established
tools; `/run` still includes the integrity check. Heuristics, each measured clean on every lab
host and read-only on a real server before shipping:

- *Log file state* (`log_file_state`): inode, size, mtime and a hash of the first
  4 KiB of each tracked log and of its first rotation, remembered per machine. A
  rename rotation (the old inode is now `.1`), a copytruncate rotation (`.1` changed
  and holds at least the old size) or logrotate's own record are rotation; a shrink
  of the same file, a new file nothing explains, a rewrite of the first 4 KiB or a
  deletion are not (`LOG-001`; wtmp/btmp shrinking is `LOG-004`). The first look is
  only a baseline.
- *Journal continuity*: from every journal file's header, a gap in sequence
  numbers *between two files that still exist* that the other files can't account
  for (journald numbers system and user journals from one counter) means a file in
  the middle was deleted (`LOG-002`). Gaps before the oldest file are retention.
- *Boots*: a previous boot whose last entries hold no orderly-shutdown message
  (`LOG-003`, low: context, not proof). In a container a forced stop or snapshot
  restore counts too, and the result says it's a container.
- *Login records*: glibc `struct utmp` parsed with `struct`; an all-zero record
  between real ones, or time running backwards (clock-change records excepted),
  is `LOG-004`. Not a whole number of 384-byte records = unknown format, not judged.
- *auditd*: running with rules last time and now stopped, emptied or disabled in
  the kernel (`LOG-005`); installed but not running is `LOG-006` (info, an ordinary
  condition that closes when auditd runs); not installed is a coverage note.

Each tamper rule carries an ATT&CK v19 label (see "ATT&CK labels"), where log clearing
and audit tampering moved to the new *Defense Impairment* tactic:
T1685.006 Clear Linux or Mac System Logs (LOG-001/002/004, SEAL-001), T1685.004
Disable or Modify Linux Audit System Log (LOG-005), T1685 Disable or Modify Tools
(SEAL-002). Evidence of tampering is
**sticky** in the lifecycle: a later run not seeing it doesn't close it, because the
next comparison is against the already-edited state; it stays open until a person
decides. A decision covers the incidents the person saw: each tamper finding's
entities name the incident -- what changed plus the time of the check that noticed it
for one-shot detections (file state, auditd), the record number for zeroed or
reordered login records, the file's current sha256 for a changed or failing archive
-- so the next incident is a new entity and reopens a decided finding.

**Journal sealing (FSS).** The machine seals its journal (`journalctl --setup-keys`,
run by a person from the setup checklist); Kratos keeps the verification key in
`data_dir/fss/<machine>.json` (0600, folder 0700), bound to the machine-id, and
never sends it anywhere -- not to the machine, the model, logs or transcripts (a
test scans every one of those surfaces; the key pattern is also masked by
`redact_secrets`). Verification runs on the Kratos host: journal files are copied
(SSH `cat` as the journal-group user, or the agent's `journal_file_chunk` in ≤4 MiB
pieces) into a private temp folder, checked with the local `journalctl --verify
--verify-key=...`, and deleted. Archived files never change, so each is verified
once and its sha256 recorded (`seal_verifications`); later runs only re-hash, and a
changed hash is `SEAL-001` even where the seal itself doesn't reach. A seal failure
is `SEAL-001`, unsealed files newer than the newest sealed one `SEAL-002`; not being
able to check (key for another machine, unreadable journal, this host's journalctl
too old) is `SEAL-003`, a run note. Entries written before sealing began, and a
`.journal~` file journald set aside after a crash, are notes, not edits. It runs in
the background after an investigation of a sealed machine (at most every
`logs.seal_verify_interval_minutes`, copying at most `logs.seal_copy_budget_mb`,
newest first, on a thread pinned to its machine), in scheduled runs and on demand,
and never blocks an investigation.

## Detection rules (Sigma)

**What ships.** `src/kratos/detect/packs/sigma-linux-<N>.json` is a **rule pack**: SigmaHQ's
Linux rules (`rules/linux/**`) at a pinned commit, compiled into Kratos's own rule format by
`scripts/dev/build_sigma_pack.py`, committed like the ATT&CK table (deterministic: the same
inputs give the same bytes; the SigmaHQ commit, the pySigma version and the DRL text's hash are
recorded in the pack). Beside it: each shipped rule's source file unmodified (`packs/sigma/`),
the Detection Rule License text (`LICENSE.DRL`) and a NOTICE naming every rule's author. Kratos
itself never needs pySigma; the `sigma` extra only serves `kratos detect import`.

**The rule format: closed operators, no regular expressions.** A rule is JSON data: id, title,
level, author and the Sigma provenance; a *scope* (the datasets of its log source, plus a closed
condition such as "an auditd `process_started` event"); a condition tree over `eq`, `contains`,
`startswith`, `endswith`, `wildcard` (only `*` and `?`), `in`, `cidr`, `exists`,
`all_of`/`any_of`/`not`; and optionally `count` (events in a window, grouped by at most one
identity field). Matching is case-insensitive unless a value is `cased`. A rule that needs a
regular expression, a numeric comparison, a field reference, or a field Kratos's events don't
carry is **skipped and listed with the reason** -- never approximated. Every pack carries its
SHA-256 and a monotonically increasing version; a pack that fails validation is refused whole.

**One evaluator, both sides.** `src/kratos/subagent/detect.py` is standard-library Python 3.8,
ships in the agent bundle (0.7.2) and is imported by core as `kratos.subagent.detect` -- the
`protocol.py` pattern, so core and an agent can never judge an event differently. It validates a
pack against size caps (1,000 rules, 512 nodes and depth 32 per rule, 1 KB per value, 32
wildcards per pattern, windows up to a day, a closed set of group-by fields) and evaluates in
bounded time: plain string tests, or a wildcard match that never backtracks (literal pieces by
`str.find`, pieces with `?` by a bit-parallel scan), over values cut at 64 Ki characters.
Counting windows keep at most `threshold` (time, id) pairs per group, at most 10,000 groups and
200,000 pairs per rule; a group fires once per window.

**Field mapping.** `events/sigma_fields.py` maps Sigma's log sources onto Kratos datasets and
Sigma fields onto event fields, checked against the real parsers' output. To answer the auditd
rules, audit events keep their record types (`kratos.audit.types`), rule key, system-call name
(ENRICHED format), every PATH name and the created ones, argv in order (`process.args`,
credentials masked argument by argument -- and now also in the raw audit lines) and the
effective uid. Sigma `aN` maps to `process.args[N]` only beside `type: EXECVE` (in a SYSCALL
record it is a raw system-call argument, which Kratos doesn't keep). Sigma's `file_event`
maps to auditd PATH records with `nametype=CREATE`. Keywords are looked for in the message
and the raw line.

**Where it runs.** The `detect` collection check (quick, after `log_sync` -- `Check.after`
makes the runner wait for it) runs `detect/run.run_pass`: per pack, the events stored for the
machine since that pack's last pass, **by row id** (log sync stores late lines; time is not a
position), in chunks each evaluated in time order. Counting rules are re-fed the earlier events
of their window as *history* (counted, never raising anything), and the last fire per group is
saved, so a burst straddling two passes is reported once. A new or changed pack looks back
`detect.lookback_hours` once. The pass stops at `detect.pass_budget_seconds` /
`detect.max_events_per_pass` and says it is behind. Bookkeeping: `detect_runs` (what was
evaluated, by row id and time span). Nothing is sent to the machine; no model is called.

**Detections become findings through one path.** Each match is a **detection event** in the
event store (dataset `kratos.detect`, `event.kind: alert`, `rule.id/name/author/...`, the
matched events' ids) with an id derived from rule + machine + matched event, so evaluating the
same events again stores nothing new. `detect/findings.py` summarises the machine's detection
events of the finding window into a snapshot (`detect/results/`), which the findings engine
turns into `SIGMA-<8 hex>` findings (a snapshot source): one per rule and subject (the count
group, else the validated source address, user or program), severity = the rule's level, ATT&CK
from its tags through the v19 table (a rejected tag was dropped at build time and recorded),
**occurrence** in the lifecycle, a `detection_rule` credit that every surface shows, and
`DETECT-001`, a run note listing the log sources the machine doesn't give (no auditd: program-
start and file rules "not checked", never "nothing found"), a pass that fell behind, or a
refused imported pack. Matched log text never reaches a title; finding entities are validated
values only. Alerts go through the existing triggers and notifier.

**Kratos's own commands are not attacks.** With an execve audit rule, every program Kratos runs
over SSH is in the audit log (a persistence read is thousands of `readlink`/`find` calls, and
`find / -perm -4000` is exactly what SigmaHQ calls reconnaissance). `detect/own.py` sets those
events aside -- and only those: sshd logs each login with the key's fingerprint and its pid; the
audit login records of that pid carry the kernel's session id (`ses`), which every program of the
login inherits and no other login can take on. A login made with Kratos's own key (fingerprint
computed from `SSH_TARGET_KEY_PATH.pub`) is Kratos's. Because a first collection's log sync can
start after the login record, the `detect` check also reads `/proc/self/sessionid` over Kratos's
shared connection (only for machines whose audit log Kratos holds) and records it
(`detect_own_sessions`). Session ids restart at boot and sshd pids are reused, so an id counts only
inside that login's lifetime (login to logout, at most an hour; a directly read id ±10 minutes).
Someone holding Kratos's private key would be treated as Kratos -- that key is the credential
Kratos is trusted with. Through a sub-agent (root, no SSH session) this doesn't apply yet (C.2).

**People decide the noise.** `detect_rule_overrides` holds a person's on/off per rule, per
machine or everywhere, with who and why (refused inside an agent tool call, like every decision
about findings). A single false alarm goes through the finding lifecycle instead.

## Presets and pipelines

Saved presets (`/preset`) let a user name and re-run an
investigation without retyping it. Two kinds share one schema and one
storage layer (`agent/presets.py`, one TOML file per preset under
`data_dir/presets/`, atomic writes):

- **Goal presets**: a named natural-language goal, run through the same
  agentic `run_agent()` loop as typing the goal directly.
- **Pipeline presets**: a named, ordered list of concrete tool-call steps,
  run through a small deterministic engine (`agent/pipeline.py`) instead
  of an LLM picking tools. Each step dispatches through the same
  `execute_tool_call` every agentic tool call goes through, so it inherits
  approval-gating, target resolution, and every dispatch-time guard for
  free — a pipeline isn't a separate, unguarded execution path.

The deterministic engine is also what `kratos run`'s "standard audit"
uses internally, replacing an older hand-coded pipeline that bypassed the
tool registry entirely (no approval-gating, no target resolution) and, as
a result, could mix Kratos-host-local analysis into what was reported as
target findings. Routing the standard audit through the same engine and
registry as everything else closed that class of bug by construction
rather than by patching the old pipeline's specific mistake.

A pipeline step may optionally carry a bounded condition (run only if an
earlier step found something matching a simple, whitelisted expression) or
reference an earlier step's output as an argument to a later step. Both
are compiled from a small, explicitly whitelisted grammar — never Python
`eval()` — so a saved pipeline can't become an arbitrary-code execution
surface just because its conditions or references are user-editable.

## Findings and severity

`adapters/findings_engine.py::correlate_findings` is the rule engine behind
investigation conclusions. It auto-discovers the newest input file per
category (`scans`, `logs`, `context`, `reports`, `baseline`) under the
active `data_dir`, so a call doesn't need to be told which specific file to
read. Finding IDs follow a fixed prefix scheme: `NET-*`, `AUTH-*`,
`CORR-*`, `INTEG-*`, `PRIV-*`, `LOG-*`/`SEAL-*`, `PERSIST-*`, `LIVE-*`, `PKG-*`. `PRIV-*` comes from `list_privileged_accounts`
snapshots, and only from one that is fresh (24 h) and of the active target, so
an old "X was just added to sudo" can't keep re-firing or leak into another
machine's report; grants to accounts that have since lost the access are kept
as history, never reported as current risk.

`VULN-*` comes from `run_vuln_scan` snapshots under the same rule (newest scan
of the active target by its own recorded time, under 24 h; another machine's
scan never feeds this one's report). VULN-001 lists vulscan's CVE matches per
service, newest first, as leads to verify rather than confirmed issues (the
matching is textual and distributions backport fixes); VULN-002 carries Nuclei
results at Nuclei's own severity (critical maps to high); VULN-003 states what
the scan could not check (no CVE list, an old one, a failed version scan, no
Nuclei, no reachable services), so a quiet scan is never reported as clean.
These on-demand snapshots (`PRIV-*`, `VULN-*`) are considered even when the
core inputs are passed explicitly, since each is already limited to a fresh
scan of the active target.

The agent loop enforces a few structural checks on any `final_answer`
before accepting it, rather than trusting the model's own claim:

- It can't conclude without a `correlate_findings` call that actually
  *succeeded* — an attempted-and-failed call has to be retried with a
  corrected call, since a real error is available to act on; only a
  never-attempted call can be waived, and only with an explicit statement
  of why.
- It can't state a file-integrity conclusion that contradicts the tool's
  own diff, and it can't dismiss a finding the correlation pass rated
  HIGH/CRITICAL.
- It can't claim a specific recency window (e.g. "in the last 24 hours")
  when `correlate_findings`'s own staleness check already flagged its
  inputs as spanning a wider range than that claim implies.
- Its numbers and "none" statements about a period are checked against the
  exhaustive measurements (see "Time windows"), and it can't cite a tool it
  never ran.
- It can't present the target as fully checked when a step reported a
  coverage gap (e.g. no network scan for a sub-agent-only target).
- If it says Kratos lacks a capability without proposing a tool for it, it
  is asked once for a structured `tool_proposal`; if it still answers in
  prose, that sentence is surfaced as a suggestion for `/evolve`. Advisory
  only — this one never tags the answer, and it ignores a sub-agent's known
  coverage limit, which no new tool could fix.

`run_linux_command` (Kratos's own host only) isn't offered to the model when
the target is remote: there it could only inspect the wrong machine, and it was
measured standing in for a missing target capability instead of a proposal.

A violated check produces one combined rejection per iteration (multiple
violations on the same answer are folded into a single retry prompt, not
one retry per violation). If the model doesn't self-correct within a small
retry budget, the loop force-accepts an answer but tags it with an explicit
inline note naming what's still unresolved — an honest "I couldn't fully
verify X" beats a clean-looking answer that silently isn't.

Each finding rule ID maps to a plain-language, one-line summary through a
static template, not an LLM call — rule IDs are a deterministic, finite
set, so a lookup table avoids adding a non-deterministic extra model call
for something entirely formulaic. A generic fallback summary covers any
rule ID that doesn't have its own template yet, so a missed entry produces
a blander sentence rather than a crash or a blank summary.

## ATT&CK labels

Every rule has exactly one entry in `kratos/attack/mapping.py::RULE_ATTACK`: either
`Behaviour` (it describes something an adversary *did* -- it carries MITRE ATT&CK
labels) or `Posture` (exposure, weakness, inventory, or a run note -- explicitly no
label, with a one-line reason). A test fails when a rule the engine can emit or the
lifecycle registers has no entry. The labels are Kratos-generated: never written by
the model, never parsed from a machine's text.

**One table, generated and pinned.** `scripts/dev/build_attack_table.py` reads MITRE's
official Enterprise STIX bundle (`mitre-attack/attack-stix-data`,
`enterprise-attack-19.2.json`, downloaded by a developer -- Kratos never fetches it)
and writes `src/kratos/attack/v19_table.json` (package data, ~250 KB vs the ~50 MB
bundle): every technique and sub-technique's name, tactics, platforms, url and
revoked/deprecated flag (with what replaced a revoked one), every tactic in matrix
order, and the bundle's version and sha256. Same bundle in, same bytes out. Every
label is built through `kratos.attack.table.label()`, which refuses an id the table
lacks, a revoked or deprecated id, or a tactic the technique isn't listed under -- at
import time, so a wrong mapping can't ship.

**Where labels are set.** `generate_findings` stamps them after the rules run
(`_stamp_attack_labels`): a finding keeps labels its builder set for its own item
(`PERSIST-001/002/007` are labelled by the area of the item they found -- cron, a
systemd unit, a shell profile, ...), gains its rule's labels otherwise, and gains
those of any rule it absorbed when overlapping findings were merged. `INTEG-001` is
labelled by which tracked file changed (`INTEG_PATHS`: `/etc/passwd` -> T1098,
`/etc/sudoers*` -> T1548.003, cron files -> T1053.003, `sshd_config` -> T1556,
`/etc/pam.d/*` -> T1556.003, `authorized_keys` -> T1098.004, ...); any other file is
posture. A finding stored before labels existed is mapped when it is read
(`attack_of`), so `/findings`, `kratos findings show` and MCP show labels for old
records too.

**What the model sees.** A tool result reaches the model through a 1500-character
window, so labels go in as `"T1110.001 Password Guessing"` strings
(`compact_for_model`); the transcript, the screen and MCP keep the full label (both
tactics, url, version). For the same reason a `correlate_findings` result reaches the model
without its people-only bookkeeping (`loop._for_model`: the report file paths and the
`inputs_used` table, ~900 characters that came before the first finding); missing inputs,
input errors and the staleness warning stay. An investigation's "not checked" NOTE names
each gap in one short line and the shared sub-agent fix once (`loop._coverage_note`); a
check's detailed run note (`PERSIST-009`, `LIVE-007`) keeps the long form, and a
restart-needed hint or a first look is never a "not checked" gap.

| Rules | Label (v19) |
| --- | --- |
| AUTH-004, CORR-001, CORR-SSH-001, CORR-002 | T1110.001 Password Guessing (Credential Access) |
| PRIV-001, PRIV-003 | T1098 Account Manipulation (Persistence, Privilege Escalation) |
| PRIV-002 | T1136.001 Local Account (Persistence); T1098 Account Manipulation |
| INTEG-001 | by changed file (above) |
| LOG-001, LOG-002, LOG-004, SEAL-001 | T1685.006 Clear Linux or Mac System Logs (Defense Impairment) |
| LOG-005 | T1685.004 Disable or Modify Linux Audit System Log (Defense Impairment) |
| SEAL-002 | T1685 Disable or Modify Tools (Defense Impairment) |
| PERSIST-001, -002, -007 | by the item's area (cron T1053.003, at T1053.002, systemd T1543.002 / timers T1053.006, SSH keys T1098.004, preload T1574.006, modules T1547.006, shell config T1546.004, PAM T1556.003, rc/boot T1037.004 / T1037, XDG T1547.013, udev T1546.017, package hooks T1546.016) |
| PERSIST-003 | T1548.001 Setuid and Setgid (Privilege Escalation) |
| PERSIST-004 | T1574.006 Dynamic Linker Hijacking (Stealth) |
| PERSIST-005 | T1547.006 Kernel Modules and Extensions (Persistence) |
| PERSIST-006 | T1098.004 SSH Authorized Keys (Persistence) |
| PERSIST-008 | T1556.003 Pluggable Authentication Modules (Persistence) |
| LIVE-001 | T1070.004 File Deletion (Stealth) |
| LIVE-002 | T1620 Reflective Code Loading (Stealth) |
| LIVE-003 | T1574.006 Dynamic Linker Hijacking (Stealth) |
| LIVE-006 | T1059.004 Unix Shell (Execution); T1505.003 Web Shell (Persistence) |
| NET-*, CTX-001, ENV-001, VULN-*, PKG-*, AUTH-001, AUTH-003, AUTH-TREND-001, COV-001, OBS-001, PRIV-004, LOG-003, LOG-006, SEAL-003, PERSIST-009, LIVE-004, LIVE-005, LIVE-007 | posture -- no label |

(The `LIVE-*` and `PKG-*` entries are in the mapping ahead of the live-response and
package checks; a test allows exactly those to be missing from the rule registry until
they are registered.) `AUTH-001` (any sudo password failure) is posture: one failure is usually a typo;
repeated guessing is `CORR-002`/`AUTH-004`, which carry T1110.001. `OBS-001`
(logging looks off) is posture: usually a stripped or container system, and auditd
stopped after it ran is `LOG-005`.

**Navigator layers.** `kratos/attack/navigator.py` builds ATT&CK Navigator layer
files (layer format 4.5, Navigator 5.3.2, domain `enterprise-attack`, ATT&CK 19,
platform filter Linux). *Coverage*: every technique a rule this build has can carry
(score 1, comment = the rule ids); *observed*: techniques in the open/verified
lifecycle records of one machine or all (score = worst severity 1..5, comment =
finding keys) -- decided and fixed findings are left out. Each cell is pinned to the
tactic the label names, so a technique sits in its v19 column (e.g. Defense
Impairment) rather than every column it is listed under; a sub-technique gets an
unscored, expanded parent so it is visible. `kratos attack-layer` writes them (0600).

## Finding lifecycle

Rules regenerate every finding from scratch each run; `kratos/lifecycle/` is a
layer *after* them that remembers. It runs inside `write_findings_report`, the
one place every path (the agent's `correlate_findings`, `kratos run`, scheduled
runs, `findings-generate`) writes a report, so one hook covers all of them, and
detection logic is untouched.

- **Identity.** `finding_key = sha256(rule_id ␟ target_key ␟ subject)`. Every
  current rule has an empty subject (one finding per rule per machine); a future
  per-entity rule (one finding per CVE+package, per persistence item) sets it.
  Each finding also carries `entities` — the concrete things it names (source
  IPs, `port/proto`, accounts, paths, CVE ids), sorted and normalised.
- **Rule kinds.** `lifecycle/rules.py` classifies every rule id the engine can
  emit as a *condition* (persists until fixed), an *occurrence* (happened in a
  window) or a *run note* (`COV-001`, `VULN-003`: how complete this run's read
  was — never stored, never hidden, never decidable, so nobody can accept an
  honesty note away). A test scans the engine for rule ids, so a new rule can't
  ship without declaring its kind.
- **Coverage-aware mitigation.** A finding absent from a run becomes *mitigated*
  (condition) or *inactive* (occurrence) only if that run re-collected every
  input its rule needs — file written during the run (10 s slack), about this
  machine, and complete (a truncated auth read covers no login-derived rule).
  Without a run context, or with stale inputs, nothing is covered and the
  finding is reported "not rechecked". Some rules need fewer inputs than they
  read: no burst in a fresh, complete auth read is enough to say a brute-force
  finding didn't recur, even though the rule also reads nmap and system context.
  **Blind spots, per entity** (`Coverage.blind`, phase A audit): a read can finish
  and still not have looked at everything -- a non-root SSH login can't open
  `/root/.ssh` or read another user's `/proc` entry, and `hidepid` hides those
  processes entirely. The persistence and live-response snapshots record what
  their read could not look at (unreadable paths and homes, processes seen but
  not readable, unopened temp folders, hidepid); a finding whose entity falls in
  such a blind spot is not marked gone, even when the rule as a whole is covered.
  Without this, a root process the sub-agent found was marked *inactive* by the
  next SSH read on an `ssh_first` link.
- **Decisions cover what the person saw.** A decision (risk accepted with a
  required, capped expiry; false positive; out of scope) records the finding's
  severity and entities at that moment. A new entity or a higher severity
  reopens it, naming what's new; counts changing don't. Scopes: this finding,
  this rule on this machine, this rule everywhere — checked in that order, newest
  active decision wins, a newer decision at the same scope revokes the older. A
  reopen or an expiry *releases* a finding: decisions made before that moment no
  longer apply to it, which stops a broad decision from silently re-hiding it.
- **Only people decide.** Kratos makes only the deterministic moves (to
  mitigated/inactive, and back to open on regression, recurrence, expiry or
  no-longer-covered — plus applying an existing broader-scope decision to a
  finding it covers). `lifecycle/decide.py` needs a TUI or CLI actor, refuses
  inside an agent tool call (`settings_store.tool_call_scope`), and a test scans
  every tool module and the MCP server for any reference to it. MCP is read-only
  (`kratos_finding_states`).
- **Nothing is hidden from the model or the guards.** `correlate_findings` still
  returns every finding, each with `state`, `change` and `decision`, plus a count
  of what the user's decisions hide. Only the person's default view folds decided
  findings — always with a count line under answers, in `/report`, `/findings`
  and scheduled notifications. Guard 3 still fires for an accepted HIGH finding
  that a dismissive answer doesn't name.
- **Storage.** `finding_records` (state, latest copy, first/last seen, last
  re-checked), `finding_events` (append-only transitions, each with actor,
  interface, reason and run id; a trigger aborts updates), `finding_exceptions`
  (decisions), `finding_imports` (report files already accounted for). One
  `BEGIN IMMEDIATE` transaction per report, idempotent per run id (scheduled runs
  write a second report in the same run). A lifecycle failure never loses the
  report: it is written without lifecycle fields plus `lifecycle_error`. Old
  `reports/findings_*.json` are imported once (machine taken from the report, its
  input files, the session that produced it, else "unknown") and never modified.

## Evidence-first triage (verdicts and retest)

`kratos.triage` re-checks a serious finding **by code** and attaches a *verdict* —
a thing a person reads, separate from the lifecycle state. Models are weak at
triage, so rules and evidence decide and the model only annotates.

- **Verdict** (`triage/verdict.py`): one of `reproduced | partly | not_reproduced |
  couldnt_check | seen`, with a `basis` (`second_read` or `this_run`), a short list of the reads it ran, Kratos-written evidence lines,
  and one sentence. It is **never** a lifecycle state and never changes severity —
  `verified` stays the person's "confirmed real" (a source scan + behaviour test
  enforce that triage imports neither `lifecycle.decide` nor writes `finding_records`).
- **A third registry** (`triage/registry.py`), alongside the collection and
  snapshot-source registries: `register_verifier(Verifier(rules=…, cost=…, verify=fn))`,
  or `register_no_verifier(NoVerifier(rules=…, reason=…))` for a rule with no safe
  fresh re-read. A completeness test requires every condition/occurrence rule to have
  one or the other — same shape as `attack/mapping.py`.
- **A verifier re-reads; it never reaches further** (`triage/context.py`): an existing
  collection check run with `force`, a tool's fetcher, or a local computation — no new
  remote command, nothing written on the target, same transports and SSH slots. A
  verifier with no safe read returns *couldn't check* with the reason. Conditions are
  re-read now; occurrences are re-checked against the logs for the window they happened
  (an ended burst still in the logs is *reproduced*; gone logs → *couldn't check*).
  Reachability (NET) is probed from Kratos's own vantage, said plainly, never the
  public internet's.
- **When it runs** (`triage/run.py`): quick verifiers run automatically for every new
  or reopened HIGH/CRITICAL finding, bounded by `triage.auto_seconds` (default 20). The
  automatic pass **re-uses the collection Kratos just ran** — the read that raised the
  finding — rather than issuing a second read, so it adds no target load and keeps every
  loop/scheduled test off the machine. Because that is not a second look, its verdicts
  carry `basis="this_run"` and may never be `reproduced`/`not_reproduced`
  (`Verdict` refuses it; `from_this_run` maps reproduced → `seen` "seen in this run's
  read — not re-checked yet", pointing to recheck/retest). Only a genuine second read —
  recheck, retest, the richer verifiers (nmap reachability, a re-hash) run on demand —
  says reproduced. Unfinished ones say "verifying…"
  and finish in the background. Unattended runs (schedule, trigger, MCP) run quick only.
- **Where the verdict shows**: the answer's findings block (`finding_facts.answer_block`
  — still Kratos-written, the answer contract holds) and the model's digest as a `[tag]`;
  `/findings` (a column + the detail view with checks and evidence), `kratos findings
  show`, the Markdown report, MCP `kratos_finding_states`, and scheduled-run
  notifications. Stored append-only in `finding_verdicts` (newest per finding shown).
- **The finding's own machine.** Re-checks and retests always read the machine the finding
  is about (`triage/run.machine_of`), and `verify_finding` pins it around every read a
  verifier makes -- never the active machine (the findings view lists every machine; the chat
  server has none active). A read that fails inside a tool ("ok" wrapper, inner "error") is
  *couldn't check*, never *not reproduced*.
- **Retest** (`triage/run.retest`, `/retest`, `kratos findings retest`): force-run the
  collection checks whose input categories cover the finding's rule, one correlation and
  the lifecycle update, then the finding's verifier — before/after state plus the
  verdict, no model call. An incomplete covering read leaves the finding open and says
  so (the Phase A blind-spot rule). Offered after a fix the recommend channel surfaced
  (`triage/offers.py` maps an action's `source_recommendation` back to the open finding).
- **The model's suggestions** (`finding_notes` in the final-answer JSON, sanitised like
  `recommended_commands`): `[{finding, suggest: false_positive|lower_severity|needs_person,
  why}]`. Bounded count/length, the finding must exist in this run, `why` cleaned for
  display (A.4). Stored in `finding_suggestions`, shown labelled "the model suggests",
  accepted through the people-only decision path or dismissed — never a state, never
  acted on by the model. No agent/MCP tool can create a verdict or a decision.

## What an answer guarantees

An investigation's answer is two things, and they are kept apart (phase A audit):

- **What Kratos found** -- written by Kratos, at the top (`finding_facts.answer_block`): every open
  HIGH/CRITICAL finding (not decided by a person) with the fact that matters -- the attacker's
  address and a known-malicious match, the program and pid, the file, the package. An item the
  analysis below doesn't discuss is marked "(not discussed below)", one whose fact is missing names
  it. It appears on every surface the answer reaches (TUI, CLI, MCP, report, notification) and
  nothing the model writes can remove it. No serious finding open: no block, so a narrow question
  ("how many sudo events yesterday") gets a plain answer.
- **The analysis** -- the model's text below it, checked by the answer guards. Guard 12: a serious
  finding the analysis leaves out, or names without its facts, is sent back once with the exact
  list (`finding_facts.left_out`); a second omission is accepted -- the block already lists it.
  Only findings the question is about count (`finding_facts.relevant_to`, a fixed topic table): a
  broad question ("check this system") is held to every serious finding, a narrow one ("has it been
  tampered with?") to the findings on its topic -- in the eval, holding narrow questions to
  everything cost a model call in most runs and added nothing the block didn't already show.
  An IP address the answer names that appears in nothing Kratos read (observations, digest, goal)
  gets a NOTE (`loop._ungrounded_ips`; whole addresses, so 10.136.28.1 is not "seen" inside
  10.136.28.168).

Why: in the audit's eval the detection was right every time (the finding was in the correlation in
5/5 runs) while the model's answer named it 0–3 times in 5 -- leaving out the attacker's address,
the threat-intel match, or a HIGH process running from memory, and once naming the wrong address.
Prompt and context changes moved those numbers only within noise. Making the findings part of the
answer by construction is what makes the answer trustworthy; the model explains, it doesn't decide
what the person gets to see.

## Untrusted input

Text that came from a monitored machine is attacker-controlled: usernames in failed
logins, URLs and user agents in web logs, process and file names, cron lines, package
descriptions. Kratos's structure already limits what it can do (fixed read-only tools, a
fixed target, dispatch guards, answers checked by rules); what is left is what a person
sees, what a person copies, and what the model reads as instructions. Stored evidence
keeps its original bytes (`event.original`, the transcript's tool results); the text is
neutralised at the **exits**, and `kratos/untrusted.py` is the one module that owns how.

- **The screen.** `for_display` removes control characters and every escape-sequence
  family (CSI, OSC including OSC 8 hyperlinks and OSC 52 clipboard writes, DCS/SOS/PM/APC,
  the 8-bit C1 forms, a bare ESC; unterminated ones run to the end of the line), and shows
  bidirectional controls, zero-width characters, Unicode tag characters and lone surrogates
  as visible `⟨U+202E⟩` markers. Plain non-ASCII text is untouched, and homoglyphs are not
  rewritten (that would corrupt real names); a word that mixes look-alike scripts gets a
  `⟨mixed scripts⟩` marker in findings. `untrusted_rich.py` makes this the default: `SafeText`,
  `SafePanel`, `SafeTable` and `SafeSyntax` clean every string they are given and never parse
  markup, `tui_mk2/safe_widgets.py` does the same for Textual's `Static`, `Label`, `Button`,
  `Option` and `DataTable` (whose plain-`str` cells are otherwise parsed as markup), and a
  source-scan test fails if a TUI module imports the unsafe classes. Backstops sit at the
  sinks: the CLI console and the transcript writer pass what they draw through
  `scrub_segments`, because nothing Kratos writes legitimately holds an escape byte. The plain
  CLI commands use `safe_print`; MCP replies, ntfy notifications and the toast notifier are
  cleaned too.
- **The model.** Each tool result is wrapped as
  `<<tool_result run=… id=…>> JSON <<end id=…>>` under one fixed line saying everything between
  the markers is data that may contain attacker text. The id has a random part per call, so a
  payload written earlier cannot contain the real end marker; strings are JSON-escaped (a newline
  is `\n`, so no payload can start a fake `Assistant:` turn), cleaned and length-capped. The
  digest of what Kratos collected, the replayed conversation on resume and the findings bundle
  of the one-shot analysis are framed the same way (`frame_text`), and the system prompt carries
  one rule saying what the markers mean. The size cap still cuts the JSON text, never the markers.
- **Suggested commands** (`kratos/remediation/`). The text a person pastes into a root shell is
  where an injection would do real harm, so there are two tiers. A **template** (a closed
  catalogue: ban an IP, enable or restart a service, lock or expire an account, remove one
  authorized key by fingerprint, kill a process, remove a cron line, restrict a file's mode) is
  chosen by the model but built by code: every value must occur in this run's evidence (an IP
  that attacked and is not the machine under investigation, an account named in a finding, a PID a
  tool listed, a path, fingerprint or cron line seen verbatim) or on a vetted list, and the
  command is rendered from a fixed shape with shell quoting. A refused template yields an
  explanation and no command. A command the model wrote in plain text that is, as a whole line,
  exactly a template's shape (optional `sudo`, for ufw an optional `to any`, nothing else) is
  checked the same way and, when its values pass, shown as the template command (`recognised`).
  Values the model chose as tool arguments are not evidence even when the tool echoes them back. A **free-form** command the model wrote is still allowed, labelled
  "written by the model", with a flag and reason for each risky shape (a download or network
  connection, a pipe into a shell or interpreter, decoding, command substitution, a host the
  evidence never mentions, an unfilled `<placeholder>`, a write to a place that keeps access); a flagged command needs a
  second confirmation before Ctrl+Y or the copy box puts it on the clipboard. Flags are
  heuristics that warn, never forbid. The catalogue is display-only: nothing is executed and it
  is not connected to the fix channel's whitelist (it only reuses its unit list).
- **Checked, not assumed.** `tests/test_untrusted*.py` drive a corpus of payload shapes
  (`tests/fixtures/untrusted/corpus.json`) through every renderer, the transcript, the widgets,
  the envelope in the real loop, and the rule engine (findings must be byte-identical except for
  the payload value itself). The full corpus is injected for real into lab machines from
  `attacker-box` by the eval harness (scenarios F1, F2, F3) outside the repo.

## Masking what the model sees

Since the hosted-model pivot every investigation sends logs, findings and conversation to a
third party. `kratos/privacy/` (OWASP LLM02:2025; reversible pseudonymisation in the manner of
Presidio's, without the NER dependency) replaces real values with placeholders before a request
leaves, and puts them back in what returns.

- **One place.** `llm_interface._metered_call` takes the two texts, masks them with a `Masker`
  and hands only the masked ones to `send(system, prompt)`; the budget estimate and the stored
  prompt (`trace.store_prompts`) are the masked text, since that is what was sent and billed. The
  three request sites build their payload only from the texts they are handed and return
  `masker.restore(reply)`. `tests/test_privacy_choke_point.py` scans for both, and that nothing
  else masks or restores. A masking error sends nothing.
- **Field-aware first, patterns second.** Value sources (`privacy/values.py`, a registry like
  the collection checks: `register_value_source`) supply what Kratos already typed: the
  privileged-account read's full local account list (saved in its snapshot, never shown to the
  model), privileged-account findings, the configured target and SSH login, sub-agent names,
  Kratos's own host name, and names in stored events. Patterns then find IPv4/IPv6, emails,
  `user@host`, and account names in their fields and log phrases (`Invalid user X from`,
  `"user": "X"`, `/home/X/`, cron `(X) CMD`).
- **Trust decides how widely.** Values from trusted sources (the account list, config,
  sub-agents) are replaced as whole words everywhere. Values only seen in logs or fields may be
  attacker text, so they are replaced only where they appeared as a name — an attacker who logs
  in as `severity` cannot blank out that word across the request. A value the conversation has
  already given a placeholder is a whole word in its later requests (the earlier answer comes
  back as context in prose; Phase B audit found the real name leaking there) -- still never a
  Kratos word. No word of Kratos's own fixed
  model-facing text is ever replaced as a free word (`privacy/vocabulary.py`: every non-docstring
  string literal of the modules that write prompts, tool descriptions, finding titles and
  `RULE_TEXT`, read once per process, plus the request's own field names). Frame markers and the
  A.4 "this is data" line are skipped entirely.
- **Placeholders keep the class.** `TARGET`/`TARGET_IP` for the machine under investigation,
  `USER_n`, `INVALID_USER_n` (a name sshd says doesn't exist), `HOST_n`, `PRIVATE_IP_n`
  (RFC 1918, CGNAT, link-local, ULA), `PUBLIC_IP_n` (documentation ranges count as public),
  `EMAIL_n`. Never replaced: loopback, unspecified, multicast, reserved and broadcast addresses;
  system accounts (UID < 1000 from the account list, else a fixed list); in standard mode an
  image's default login (`ubuntu`, `ec2-user`) and dictionary guesses that don't exist; anything
  in version position (`1.2.3.4-1`, `"version": "1.2.3.4"`, part of a longer dotted number).
- **Stable per scope, unpredictable to the machine.** The scope is the session id, else the run
  id (`run_context`). `pseudonym_map (scope, kind, machine, value, label, first_seen)` holds the
  map (personal data, in the stored-data inventory, pruned with its conversation); accounts are
  keyed by machine, so two machines' `alice` are two people. Each scope draws a random 4-character
  tag (`USER_1_k7qm`): a log line cannot name a real placeholder, so text an attacker plants is
  never restored into a real value. Allocation happens in memory and is written in one
  transaction; a value another process issued first wins and the request is masked again with
  its label.
- **Restore before anything checks.** Only labels this scope issued are restored (exact match;
  the map is re-read once if one is unknown); an invented or untagged look-alike is left as
  written and counted on the model-call span; `[REDACTED]` is never restored. Because restore
  happens inside `llm_interface`, the agent loop parses real values: the guards, the dispatch
  guards, remediation checks, the findings block and storage never see a placeholder. A
  placeholder still in a tool argument was never issued, and `execute_tool_call` refuses it.
- **Secrets first** (`privacy/secrets.py`): `events.redact` plus key blocks, `"password": "…"`
  pairs, bearer tokens and AWS/Google/GitHub/GitLab/Slack/JWT shapes become `[REDACTED]` before
  any placeholder is issued.
- **Modes**: `privacy.mask_mode` = auto (standard for a hosted endpoint, off for loopback or a
  host in `privacy.local_model_hosts`) / standard / strict / off; off sends byte-identical text.
  The model is told one line about placeholders, and only when the request carries one.

## Chat clients (`kratos serve`)

`kratos serve` (`src/kratos/serve/`) is a small Starlette server with two doors.
Starlette and uvicorn are what the MCP SDK already depends on; no web framework is
added on top.

- **OpenAI-compatible, Kratos is the model** (`/v1/models`, `/v1/chat/completions`).
  This is the primary door because the reply *is* Kratos's checked answer. In MCP
  tool mode the host's own model reads Kratos's result and writes its own reply, so
  it can drop or reword a finding and bypass the answer checks. A model id names a
  machine (`kratos/<target>`, `kratos` = the default); the target comes from the
  model name only, never from the message, and the dispatch target guard holds the
  run to it. The last user message is routed by the TUI's own router
  (`command_intent.route_message`, metered and masked like any call): chat →
  a reply; investigate (or "this machine") → an investigation of the model's
  machine; app controls, presets, Kratos's own host → "use the Kratos app". Earlier
  messages become prior context, capped (8 messages / 6,000 chars) and framed as
  data by the loop. Chat clients' own background prompts (`### Task: … <chat_history>`
  — title, tags, follow-ups) are answered by code with no model call.
- **MCP over Streamable HTTP, stateless, start-then-poll** (`/mcp`, official SDK,
  `stateless_http=True, json_response=True`). `kratos_start_investigation` returns
  a random id (bound to the token; another token gets "no investigation");
  `kratos_get_investigation` returns progress lines, then the checked answer and
  findings. Both take `wait_seconds` (0–120, a long poll: the tools are `async` and
  sleep on the event loop, never block it) so a host that makes one tool call per
  turn gets the answer in that call; an empty id means the token's newest. Each run
  is recorded in `serve_sessions` as `mcp:<id>` → session (`RunRequest.on_session`),
  so after a restart the state is rebuilt from the session's turn and transcript
  (`interrupted` when the server stopped mid-run); the in-memory list (last 200) only
  adds live progress. The read tools are the stdio server's, limited to the token's
  machines. No approvals, no `input_required`. Open WebUI 0.12.3 with a Gemini model
  needs *Legacy* function calling: Gemini's OpenAI-compatible stream omits the
  tool-call `index` Open WebUI requires, and its non-streamed path runs no tools.

**One runner for every headless door** (`serve/runs.py::run_investigation`, also
used by `kratos mcp-serve`): budget `precheck` before anything starts → session →
`run_agent` inside `pinned_target(target)`, `approval_provider_scope(deny)`,
`clarify_provider_scope(None)` and `run_scope(source)`, with
`tool_filter=headless_tool_filter` (drops every `tool_reaches_approval` tool) and
`should_stop` → transcript saved, turn completed (`cancelled` when stopped).

**Per-run state, not process globals** (Phase B README §4.3). Several investigations
run at once in one process, so what a run may use is a contextvar for that run:
the tool filter and progress callback (`agent/loop.py`), the approval and clarify
providers (scopes that override the process-wide ones the TUI installs), the
machine (`pinned_target`). Approval-log entries carry the run id, so one run's
approval can never satisfy another run's backstop. The router runs without
`redirect_stderr` (it swaps `sys.stderr` process-wide). `serve.max_parallel`
(default 2) bounds concurrent investigations in arrival order; SSH slots and
collection claims already make runs on one machine share work. Two connections
opening a brand-new `kratos.db` at once used to fail on `PRAGMA journal_mode=WAL`
("database is locked", returned without the busy handler); `connect_store` now
retries it within the busy timeout.

**Streaming only the checked answer.** While the run works: Kratos-written
progress lines in `delta.reasoning_content` (Open WebUI shows it as "thinking"; it
also reads `reasoning` / `thinking`) and an SSE comment `: keep-alive` after 10 s
of silence. When the run has finished — every answer check done — the whole
answer goes out as one `content` delta, then `finish_reason: stop` with `usage`,
then `[DONE]`. The model's tokens are never streamed. An error after streaming
started is a plain-words content chunk. A client that disconnects (the stream is
cancelled, or `is_disconnected()`) sets the run's stop flag:
`InvestigationStopped` before the next model call or tool dispatch; the run
record ends as `stopped` (not a crash `.partial`).

**Markdown is a display, and an exfiltration path** (`untrusted.md_code`,
`md_block`, `for_markdown`; `serve/render.py`). `run_agent` reports
`answer_parts` (block + notes + analysis, which add up to `final_answer` exactly).
The block and NOTEs — Kratos's text quoting machine values — go out line by line
in inline code spans (inert, and they wrap). The model's analysis keeps its
formatting but: images removed; links shown as `label (hxxps[:]//host[.]tld/…)`
unless the host is on `serve.link_hosts`; bare URLs, `www.` and e-mail addresses
defanged; `<` escaped (raw HTML, autolinks); reference definitions broken; its code
blocks re-fenced with a fence no line inside can close. Defanging uses plain
brackets — Open WebUI reads `\[ … \]` as LaTeX. Suggested commands are fenced
blocks under a Kratos-written label (template or model) with the A.4 flags above.
The A.4 corpus has 22 Markdown/HTML cases; the test renders every exit with a real
CommonMark+GFM renderer (markdown-it, linkify on) and checks the HTML for images,
links, `src=` and raw tags.

**Security model** (single owner — PRD decision 2; several people sharing one
Kratos waits for D.7):

- *Bind*: `127.0.0.1` by default. Any other address needs `--host` **and** the
  people-only setting `serve.allow_non_loopback`, and prints a clear-text warning;
  remote use goes through a TLS reverse proxy.
- *Host / Origin*: a request whose `Host` isn't the bind address, `127.0.0.1`,
  `localhost` or `[::1]` (with or without the port) or on `serve.allowed_hosts` gets
  421 (DNS-rebinding defence); any `Origin` header gets 403 (no browser talks to
  this server). No CORS headers, no cookies, no pages. The MCP app also gets the
  SDK's `TransportSecuritySettings` with the same hosts and no origins.
- *Tokens*: `krt_<12 hex id>_<43-char secret>`, 256-bit secret, stored as scrypt
  (n=2^14, r=8, p=1, 16-byte salt; parameters per row), compared with
  `hmac.compare_digest`; a malformed or unknown id costs the same scrypt work.
  Verified tokens are cached per process by SHA-256 of the presented token, and the
  row is re-read on every request so a revoke applies at once. Created and revoked
  only on the command line or in the app (refused inside a `web`/`mcp` run); no
  endpoint touches them. Scope: listed machines (none = the default machine) and
  doors (`openai`; `mcp` only with `--mcp`). Failed attempts are throttled per
  address by the sub-agent listener's `AuthFailureLimiter` (10 per minute); a throttled
  address is refused without the scrypt check unless its token names a live token id (then
  checked in full) -- `proxy_headers` is off, so behind a reverse proxy every client is one
  address and wrong guesses would otherwise lock the owner out.
- *Limits*: body size (`serve.max_body_bytes`), `serve.requests_per_hour` per token
  (the audit log's metered rows plus this process's requests still running, checked
  and reserved under one lock -- simultaneous requests can't all pass one count),
  `serve.max_parallel` (investigations and chat `/retest`s); budget source `web`
  (unattended caps; `precheck` refuses before routing). At most `MAX_OPEN_TURNS` (16) chat
  turns are open at once (429 "busy" past that). Turns run on the server's own bounded
  thread pool and hand progress back with `call_soon_threadsafe` into an asyncio queue, so an
  open stream holds no thread: before the Phase B audit each open chat held two threads of
  the shared default pool (cpu+4) and with ~5 chats open on a 4-core host the whole server --
  auth included -- stopped answering until runs ended.
- *Audit* (`serve_audit`, append-only by trigger): one row per request — time,
  token id, door, endpoint, model/target, client address, the forwarded user name
  (record only, never trusted), run id, status, metered, duration, bytes out —
  never the message text. In the stored-data inventory; nothing pruned
  automatically.
- *Code-built answers* (the iteration-limit fallback, a budget stop) carry
  `answer_parts` with the whole text as the block, so a chat shows them inert like
  the findings block, not as model prose.
- *Unreachable*: approval-reaching tools (per-run filter), `/evolve`,
  `/whitelist`, `/run-fix`, finding decisions, settings, target setup, presets,
  the fix channel. The read-only chat commands are `/findings`, `/usage`,
  `/retest`, `/help`.

Notes for the security review: the new surface is an HTTP listener (uvicorn) on
loopback; token storage and timing; DNS rebinding (Host allow-list, Origin refusal,
the MCP app's own check); Markdown exfiltration (images/links/HTML in machine text
and the model's analysis — a chat app still renders the *person's own* typed
Markdown, outside Kratos); concurrency (per-run contextvars; the approval log is a
process list tagged by run id); an MCP investigation id is a bearer secret within
its token. Known limits: the hourly reservation is per process (two `kratos serve`
processes on one data folder would each count only their own requests in flight).

## MCP server surface

`kratos mcp-serve` exposes five tools over stdio — `investigate`,
`get_findings`, `finding_states` (read-only finding lifecycle), `notify_findings`,
`list_sessions`. Kratos's own agent loop
remains the sole orchestrator regardless of how a request arrives: MCP
never exposes the internal tool registry directly, so an external client's
own model can't pick which internal tool runs or in what order.

Any tool whose handler can reach the interactive approval prompt is
excluded from the set available during an MCP-triggered investigation --
per run, through `run_agent(tool_filter=...)` (not listed to the model,
refused at dispatch, the collection included); `TOOL_REGISTRY` itself is
never changed (the old delete-under-a-lock is gone, B.3).
This is checked by scanning each handler's source for the approval call
directly, not by trusting the registry's `requires_approval` flag alone —
a couple of tools call the prompt conditionally from inside their own
handler with the flag itself set to `False` at the registry level, so the
flag alone is an incomplete signal. The exclusion exists because MCP's
stdio transport keeps stdin open as the live protocol channel for the
whole connection; the approval prompt's blocking read has no way to fail
safe there the way it does at a closed terminal, so the model has to be
structurally prevented from ever selecting a tool that could reach it,
rather than the call being intercepted after the fact.

`notify_findings` takes only a session id — no free-form message or
severity parameter — and refuses to send anything unless the resolved
session genuinely completed with at least one real finding attached. Both
the message content and the severity are derived from the stored findings
themselves (severity uses the highest severity actually present, mapped
onto ntfy's three tiers), never from caller-supplied text; there's no
parameter through which a connecting client can inject an arbitrary
notification.

Where notifications go is the install's own choice, never the project's:
there is no default ntfy topic in the source, and sending is off until
`KRATOS_NTFY_TOPIC` is set. An ntfy topic is unauthenticated — the topic name
is the only thing standing between the findings and anyone who subscribes —
so a topic written in public source would publish every default install's
findings. For the same reason a topic that ever appeared in the source is
refused, `/doctor` warns when a topic sits on the public server without an
access token, and real deployments are pointed at a self-hosted ntfy
(`KRATOS_NTFY_BASE_URL`) or a token (`KRATOS_NTFY_TOKEN`).

## Interface notes

The Textual TUI (`tui_mk2/`) is what bare `kratos` launches. The older
prompt_toolkit REPL (`cli/repl.py`) is still in the tree, but nothing launches
it any more. Two notes that still apply:

- The approval gate (`agent/tools.py::request_approval`) has one fail-safe
  for every interface: the TUI renders it as a modal through a provider hook,
  and any error or non-answer still resolves to "no" inside
  `request_approval` itself.
- At a plain terminal (`kratos investigate`), the prompt must get a static
  terminal to read from. A busy-spinner animation
  running on top of the blocking read can eat keystrokes before they reach
  it — `agent/console.py` tracks the active spinner and stops it before
  any approval prompt renders, for exactly this reason.

## Packaging, CI and the regression gate

The package is `kratos-security-assistant` on PyPI (the import name and command
stay `kratos`); `requires-python >= 3.10`. Non-Python data (the starter YARA
rules, the settings template, the ATT&CK table, the event schema) ships as
package data, and `scripts/ci/package_check.py` keeps the wheel honest: it reads
the source for every path the code opens from its own location
(`files("kratos.attack")...`, `Path(__file__).parents[1] / "yara_rules"`, ...),
resolves each to a package file, and fails if one is missing from the built
wheel or if a referenced path doesn't exist. Its `install` mode installs the
wheel into a fresh venv and runs `kratos --help --all`, `init`, `doctor`,
`subagent-install` + `sh -n`, `attack-layer`, and imports every module, so a
forgotten dependency surfaces in CI, not on a user's first run.

CI is one job list, `scripts/ci/jobs.toml`: `.github/workflows/ci.yml` is
generated from it (`tests/test_ci_jobs.py` fails if they drift) and
`scripts/ci/run_local.sh` runs the same jobs here in containers, because the
repository isn't pushed. The jobs: ruff (narrow -- syntax errors, undefined
names, unused imports; the codebase keeps its own formatting, so no formatter is
enforced, and a stdout `print` in library code is caught by a test rather than
ruff because it would corrupt `mcp-serve`'s JSON-RPC channel); the full suite on
Python 3.10-3.13 and under `Europe/Helsinki`; the sub-agent bundle's own tests on
`python:3.8-slim` with nothing installed (the bundle must run on a monitored
machine's own old Python); the awk-portability tests with mawk, gawk and BusyBox
all present so none silently skips; a package build + the checks above on 3.10
and 3.13; and the gate's replay smoke with a scripted model. The suite runs as an
unprivileged user, since several tests check file permissions. CI sends nothing
anywhere -- no keys, no model calls, no lab. `release.yml` is manual-only
(`workflow_dispatch`), builds, attests provenance (PEP 740), and publishes
through PyPI Trusted Publishing on a protected environment; a local dry run
(`scripts/ci/release_dryrun.sh`) exercises it up to the upload.

The **regression gate** (`evals/`) measures the part Phase A found fragile: not
whether detection works (the rule engine is deterministic) but whether the
answer *carries* what was found. A scenario is a goal, a `kind`, and a scorer;
the scorer reads a run's payload and returns a verdict two ways -- *person sees*
(the whole answer) and *model alone* (the analysis with Kratos's findings block
and NOTEs removed, so a drop in the model's own reasoning shows even when the
block covers for it). It runs *live* (the lab, real model) or in *replay*
(recorded tool results from a run record, real model, no machine): replay patches
`agent.loop`'s collection and tool dispatch to return the recording's results, and
a call that isn't recorded is marked "left the recording", neither pass nor fail.
The drop rule (`evals/gate.py`): hard scenarios -- prompt injection, the approval
and boundary cases -- must pass every run; scored scenarios are compared to a
committed baseline (`evals/baselines/<model>.json`), a scenario more than two runs
below is re-run at N=10 and fails if still 20 points down, and the scored total
may not drop more than 5 points. The gate decides on *person sees*; a *model
alone* drop is a warning. The lab setups themselves are kept out of the
repository (Phase A's "never vendor offensive tooling"): live mode delegates each
scenario's setup to the external durable harness, replay needs no lab, and a test
scans every committed recording for non-lab addresses and key-shaped strings. The
gate must be run for any change to the prompt, the digest, the model's tool list,
or the shape of an answer.

## Known limitations

- **CVE matching is textual**: vulscan matches nmap's detected product and
  version against CVE description text. It surfaces real candidates, but
  distribution backports and loosely worded descriptions mean both false
  matches and misses; results are leads, not a verdict. Where the package check
  has data for the machine, matches the installed packages already fix are marked
  and dropped (see "Package vulnerabilities").
- **Package data covers distribution packages only**: language packages (pip,
  npm, ...), container images and software installed outside the package manager
  are not matched; Ubuntu Pro/ESM packages are matched against the plain release.
- **OT/ICS coverage**: neither of `run_vuln_scan`'s two scanners
  meaningfully covers OT/ICS protocols (Modbus, DNP3, etc.) — Nuclei's
  templates are overwhelmingly HTTP/web-focused, and vulscan only
  correlates whatever nmap's own service-version probes can fingerprint,
  which has similarly thin OT/ICS coverage. A clean `run_vuln_scan` result
  is not evidence an OT/ICS device is safe.
- **Evo-loop keep-decision provenance**: nothing cryptographically ties a
  persisted "keep" decision to having actually come from a real approval
  prompt. Accepted for a trusted, single-user, local-execution threat
  model; closing it needs a signed or nonce-bound approval record, which
  is real, currently-unjustified work — revisit if Kratos ever becomes
  multi-user or exposes the self-writing loop as a remote/API surface.
- **Terminal resize corruption in the plain-terminal renderer**
  (`kratos investigate` and the retired REPL; the TUI redraws itself): the
  Rich-based renderer treats the terminal as an append-only stream and
  relies on terminal scrollback to remember what's already been printed.
  A mid-session resize can visibly corrupt already-printed bordered panels,
  because most terminals' reflow-on-resize logic is built for reflowable
  prose, not precisely-positioned box-drawing layouts. Two partial
  mitigations are in place (ignoring stale `COLUMNS`/`LINES` environment
  variables in favor of a live terminal-size query; reserving one column
  of margin so a panel row can't be mistaken for terminal-wrapped text),
  but neither fully closes the gap for every terminal's reflow
  implementation. The complete fix is the full-screen TUI — an alternate
  screen buffer with an in-memory render model and an explicit redraw on
  resize — which is now the default interface.
- **CLI-wide rich rendering**: only `investigate` and the shared approval
  gate render through the styled console layer; the other fixed-pipeline
  subcommands (`scan`, `chat`, `run`, etc.) keep plain-text output. An
  audit found well over a hundred plain `print()`/`input()` call sites
  across those subcommands — a large enough scope that folding it in
  opportunistically wasn't worth the risk; it stays a deliberately
  deferred, separately-scoped item.
- **SSH key scope**: the Kratos SSH key can run any of its fixed,
  read-only remote commands if it leaks, rather than being restricted via
  `authorized_keys` to a single forced-command dispatcher. A forced-command
  restriction is real defense in depth, but Kratos's remote commands are
  varied enough (journalctl, firewall status, fail2ban, YARA, a multi-line
  config-audit script) that maintaining a dispatcher whitelist would be an
  ongoing tax on every future tool that issues a new remote command, not a
  one-time add — deferred rather than built opportunistically.
- **Sub-agent coverage**: a target reached only through its sub-agent gets
  no network view (port or vulnerability scans need a direct path from
  Kratos), and kept tools that issue their own SSH command can't run there.
  Both are reported as gaps rather than silently skipped.
- **One target per investigation**: a session can store several targets but
  investigates the first; multi-target runs are not built.
- **Journal sealing and the process list**: `journalctl --verify-key=` takes the
  key on its command line, so while a verification runs another user on the
  Kratos host could read it from `/proc/<pid>/cmdline` unless `/proc` is mounted
  with `hidepid`. Run Kratos on a single-user host, or mount `/proc` with
  `hidepid=2`.
- **Log sources read the current file and its first plain rotation only**:
  compressed rotations (`.gz` …) are listed as not read and make the earlier part
  of a window "unknown". Over SSH, logs a group can't read (root-only files on
  Rocky/RHEL, `btmp`, `/var/log/messages` on Alpine, whose group is usually also
  the admin group) are reported with the fix; the sub-agent reads them as root.
- **Tamper heuristics have known blind spots**: a log edited in place after its
  first 4 KiB without changing its size, a copytruncate rotation compressed
  immediately (only logrotate's root-only state file shows it), a log rotated
  several times between two checks, and logs on a machine whose clock jumps.
  Evidence is reported as what was seen, not as proof.
