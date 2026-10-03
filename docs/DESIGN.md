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
  are refused on a plain (non-loopback, non-Tailscale) network unless the
  operator allowed it at install, because the channel has no encryption of
  its own. The SSH path builds its commands with the *same* builders and both
  transports' output goes through the same parsers, so results can't drift —
  verified on real hosts (identical journal reads, config verdicts and
  exhaustive auth counts over SSH and through the agent). YARA over the agent
  uses only rules that live on the machine (shipped with the agent, or placed
  by its administrator) and returns rule/file/offset, never matched bytes,
  over a closed set of scan roots with credential paths skipped: with rules
  supplied by Kratos, even match/no-match per rule would be an oracle for
  file contents.
- **Execution (experimental, off by default)** — the agent carries its own
  ceiling (`subagent/ceiling.py`): exactly which binaries and argument shapes
  it will ever run. Kratos can push a narrower allowlist, never a wider one;
  each pushed action and the final argv are re-checked on the agent. A
  dispatch also needs the agent's local `--enable-execution` switch, a
  trusted transport, a signed heartbeat within the dead-man's window, the
  current allowlist version (anti-rollback), per-target consent in Kratos and
  a typed `EXECUTE`. The machine's administrator can add exact commands in a
  root-owned local file Kratos cannot write. None of this has had its
  independent review yet.

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

## Session persistence

Kratos stores session/turn history in SQLite (`data_dir/kratos.db`), no
server, no auth. Every turn is its own committed write as it happens, not
buffered and flushed on exit, so a crash or Ctrl+C never loses session
state. Concurrent writers (two terminal tabs against the same store) are a
real scenario, not a hypothetical one, and are exercised with genuinely
separate OS processes rather than threads, since threads sharing the GIL
wouldn't exercise the same contention SQLite actually has to handle from
independent processes.

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
`CORR-*`, `INTEG-*`, `PRIV-*`. `PRIV-*` comes from `list_privileged_accounts`
snapshots, and only from one that is fresh (24 h) and of the active target, so
an old "X was just added to sudo" can't keep re-firing or leak into another
machine's report; grants to accounts that have since lost the access are kept
as history, never reported as current risk.

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

## MCP server surface

`kratos mcp-serve` exposes four tools over stdio — `investigate`,
`get_findings`, `notify_findings`, `list_sessions`. Kratos's own agent loop
remains the sole orchestrator regardless of how a request arrives: MCP
never exposes the internal tool registry directly, so an external client's
own model can't pick which internal tool runs or in what order.

Any tool whose handler can reach the interactive approval prompt is
excluded from the set available during an MCP-triggered investigation.
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

## Known limitations

- **CVE matching is textual**: vulscan matches nmap's detected product and
  version against CVE description text. It surfaces real candidates, but
  distribution backports and loosely worded descriptions mean both false
  matches and misses; results are leads, not a verdict.
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
