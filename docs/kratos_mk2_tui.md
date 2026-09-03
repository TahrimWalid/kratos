# Kratos mk2 — Textual TUI (build + audit map)

Status: **in progress.** This doc is the working map between the *"Kratos TUI"*
design canvas and the code in `src/kratos/tui_mk2/`. It exists so a future
session can, at a glance, see **which screens are built, which have
a real backing mechanism, and which are UI-only shells waiting for a mechanism
to be coded** — then pick up the next piece without re-deriving all of this.

Design source: the `Kratos TUI.dc.html` canvas (design project
`05f89ebe-…`). The canvas is a *design exploration* — 16 "turns", 64 option
variants, 108 terminal mockups, authored newest-first (t19 → t4). This doc
**re-orders it into chronological UI flow** (the order a real user meets each
screen) and, per the project owner's directive, sequences the *build* by
**mechanism-already-exists first, then new**.

---

## How to run it

```bash
kratos-mk2                 # after `pip install -e .` picks up the new script
# or, without reinstalling:
.venv/bin/python -m kratos.tui_mk2.app
```

`kratos-mk2` is a **separate entry point**. The classic `kratos` REPL
(`src/kratos/cli/repl.py`) is completely untouched and still the default.

**Promoting mk2 to `kratos` later** (when you no longer need the old REPL): in
`pyproject.toml` point `kratos` at `kratos.tui_mk2.app:main` and delete the
`kratos-mk2` line. That's the whole swap — nothing else depends on the name.
Reverting is the same edit backwards.

---

## Architecture (how mk2 plugs into existing Kratos)

- **Framework:** Textual (the canvas itself specifies it — turn 14c: "a Textual
  app with fixed-column views"). Added as a dependency in `pyproject.toml`.
- **Nothing new in the agent/tools layer** except one small, backward-compatible
  hook: `agent/tools.py::set_approval_prompt_provider()`. When the TUI installs
  a provider, `request_approval` renders a **Textual modal** instead of a
  blocking `input()`; the fail-safe (any error → deny) and the central
  `_approval_log` recording stay in `request_approval` itself, so no gate can
  bypass them. Default (no provider) = byte-identical classic behavior.
- **Investigations / evo-loop run on Textual thread workers** (`run_agent` is
  blocking). The UI is only ever touched from the event loop via
  `call_from_thread`. `run_agent`'s existing `on_step` hook drives the live
  transcript. Interrupt (esc) cancels at the next step boundary (a blocking
  LLM/tool call can't be killed mid-call — the "interrupted — N of ~M steps"
  wording is honest about that).
- **Persistence and resume** reuse `storage/session_store.py` and even the
  classic REPL's *pure* context builders (`cli/repl.py::_build_light/full_resume_context`)
  so "resume" can never mean two different things across the two front-ends.
- **Palette (turn 7a):** Textual's built-in ctrl+p palette is disabled
  (`ENABLE_COMMAND_PALETTE = False`) so our `CommandPaletteModal` owns it.

### File map
| File | Role |
|---|---|
| `tui_mk2/theme.py` | Canvas palette + app-wide Textual CSS |
| `tui_mk2/render.py` | Rich renderable builders for the transcript log |
| `tui_mk2/modals.py` | Approval, resume-tier, confirm, prompt, help, list-picker, palette |
| `tui_mk2/approvals.py` | `request_approval` → Textual modal bridge (thread-safe) |
| `tui_mk2/screens/launch.py` | Session chooser (turns 6a–6e) |
| `tui_mk2/screens/session.py` | Main workspace (idle, live run, commands, header/footer) |
| `tui_mk2/app.py` | `KratosTUI` app + first-run flow + `main()` |

---

## Status legend

- ✅ **Built** — UI implemented **and** backed by a real, existing mechanism.
- 🟡 **Partial** — UI built; mechanism exists but approximate, or a sub-flow is deferred.
- 🔲 **Shell / planned** — mechanism does **not** exist in code yet. Build the UI as a
  clearly-labelled shell and record what must be wired under **To wire**.

---

## Chronological UI flow

### 0. Onboarding & pairing (first thing a brand-new user meets)

| Canvas | Screen | Status | Notes / To wire |
|---|---|---|---|
| (existing wizard) | First-run trust + optional default target | ✅ | `app.py::_boot_flow`, gated on `kratos_local_config.json`'s `trusted` flag, same as classic REPL. |
| 13a–13f | Tailscale account connect (OAuth connect / waiting / success / denied / abandoned / already-done) | 🔲 | **No Tailscale integration exists** (confirmed: `docs/subagent_architecture.md` §"What this doc does NOT cover"). **To wire:** OAuth device-flow client, account-state persistence, then a Textual screen set mirroring the "waiting for external action" pattern (shared with 13g). |
| 13g–13i, 12a | Add-a-server / sub-agent **pairing wizard** (generate command+code → waiting → connected; timeout; handshake failure) | 🔲 | **No sub-agent, no pairing.** **To wire:** the sub-agent binary + an ephemeral scoped Tailscale auth-key issue/poll loop (arch doc control 5), then the wizard screen. |
| 19e | First-discoverable direct-execution suggestion (once, post-pairing, dismissible per target) | 🔲 | Depends on pairing + per-target flag store. Shell only until then. |
| 10b | First-run tips strip above the prompt | ✅ | Rendered in the idle state (`session.py::_render_idle`). |

### 1. Launch — recent sessions (turn 6)

| Canvas | Screen | Status | Notes / To wire |
|---|---|---|---|
| 6a / 6e | Recent-sessions chooser (mac + PowerShell chrome) | ✅ | `screens/launch.py`, `SessionStore.list_recent_sessions`. Adaptation: selection is a real cursor (↑↓ + Enter) rather than number keys — more idiomatic full-screen; `#` column kept. Chrome variants are irrelevant in a real TUI (the terminal supplies the window chrome). |
| 6b | Resume-depth sub-prompt (light / full / back) | ✅ | `ResumeTierModal`; context via the classic REPL's pure builders. Small-context warning honored. |
| 6c | New session (target prompt, last-used default) | ✅ | `PromptModal` for target + optional name. |
| 6d | Archived sessions view | ✅ | `a` toggles it; `SessionStore.list_archived_sessions` + `restore_session`. |
| 6a "[m] more" | Overflow paging past `CHOOSER_SESSION_LIMIT` | 🟡 | Mechanism exists (`list_recent_sessions(offset=…)`); UI shows a note. **To wire:** a second-page view (low priority — single-digit session counts today). |
| — | Full-tier on-screen transcript **replay** | ✅ | `SessionScreen._render_full_replay` / `_render_replay_turn` / `_render_step_replay`: `[f]` resume re-renders the most recent `FULL_RESUME_DETAILED_TURN_CAP` turns (chat replies, tool lines, findings, conclusions) through the same bubble helpers, each stamped at its real historical display-zone time; older turns collapse to one-liners. |

### 2. Idle / empty state (turn 5)

| Canvas | Screen | Status | Notes |
|---|---|---|---|
| 5a | Idle: KRATOS wordmark, target/mode/tools grid, "describe what to investigate", tips | ✅ | `session.py::_render_idle`. `tools` count is live from `TOOL_REGISTRY` (built-in + kept). |

### 3. A live turn — chat vs. investigation

| Canvas | Screen | Status | Notes / To wire |
|---|---|---|---|
| (routing) | plain input → chat-or-investigate decision | ✅ | Reuses `cli/repl.py::_route_input` (one cheap no-tools LLM call) verbatim. |
| (live run) | step-by-step tool-call lines, finding panels, concluding panel, "Done in Ns" | ✅ | `run_agent` + `on_step`; renderables from `render.py`. Transcript persisted per turn (same layout as classic REPL). |
| (messaging feel) | per-message + per-bubble timestamps + date divider (WhatsApp-style) | ✅ | `render.py::timestamped` (trailing time on each `you>`/`Kratos:` header), `render.py::day_divider` (dotted full-date chip on display-zone day-change), and an **in-bubble** time in the bottom-right border of every finding/result panel. `/report` stamps each finding with when it was originally found (its turn's `completed_at`). Mirrors the classic REPL's `_print_trailing_timestamp` / `_DayMarker`. **All formatting routes through `kratos.utils.timeutil`** (storage stays UTC; display zone resolved once in `SessionScreen.on_mount` / `LaunchScreen.on_mount` and passed as `tz=` to every `format_for_display` / `now_for_display`). Render helpers take pre-formatted display strings — the single place display-zone lives. |
| 9a/9b/9c | Header live clock + timezone; `/timezone` override | ✅ (prompt 🔲) | Live clock + display-zone abbreviation in the header (`_tz_label` reports the resolved DISPLAY zone via `%Z`, so it's honest under an override). `/timezone [<zone>\|auto]` sets/clears a persisted display override (`timeutil.set_display_timezone_override`) and live-re-resolves the session's zone. The rare **auto-detect-failed fallback prompt** (9b) still needs a Textual modal — deferred (auto-detect covers the normal case). |
| 7b | Interrupt (esc) → resumable, "nothing left running" | 🟡 | Cancels at next step boundary; turn marked `cancelled`. **To wire (nicety):** a one-key "resume from here" affordance (today: just type a new goal). |
| 7c | Context-window meter in the footer, warns before compact | 🟡 | **Approximate** — Kratos exposes no real token count, so it's a char-based heuristic vs `LLAMA_N_CTX*4`. **To wire:** surface real prompt-token usage from the LLM layer (`llm_interface`) and feed it here. |
| 14b | Context **compaction** firing (the event) | 🔲 | No compaction mechanism exists in the agent loop. **To wire:** actual transcript compaction in `agent/loop.py`, then render the event. |

### 4. In-session commands

| Canvas | Command | Status | Notes / To wire |
|---|---|---|---|
| 7a | `/` command palette (filter as you type) | ✅ | `CommandPaletteModal` opens on **ctrl+p** AND on typing a lone `/` in the empty prompt (`on_input_changed`). Filters as you type; a typed command with args (`/rename foo`) passes straight through, so inline usage isn't lost. |
| 8a | `/help` grouped reference | ✅ | `HelpModal`. |
| 8b | `/rename` (inline before/after) | ✅ | `session.py::_rename_flow`, same validation family as classic `/rename`. |
| 16c | `/model` backend selection + reachability + cost/privacy | ✅ | `ListPickerModal` + `llm_profiles` validate + `check_endpoint_reachable` + `switch_profile`, in a worker. Each option carries an honest cost/privacy blurb derived from its endpoint (`_profile_blurb`: loopback → local/free/private; else cloud/third-party/billed). |
| — | `/scan` · `/run` · `/logs-parse` · `/findings-generate` shortcuts | ✅ | `SessionScreen._run_shortcut`: runs the real `build_parser()` → `args.func(args)` path in a worker, captures stdout/stderr (ANSI-stripped) into a result panel. Any approval it triggers still routes to the modal. |
| — | `/evolve` LLM-drafted starter harness | ✅ | On a missing harness, offers an LLM draft (reuses `cli/repl.py::_draft_evolve_harness`), shown for review; save-and-build / save-to-edit / discard. Never trusted unedited — same human-authored-test principle as the classic REPL. |
| — | `/target`, `/target verify` (+ setup checklist + probe) | ✅ | `target_setup.generate_target_setup_checklist` + `ssh_remote.run_target_probe_checks`. |
| — | `/clear`, `/reset`, `/delete` | ✅ | `/reset`/`/delete` use a native `ConfirmModal` (no force-accept). `/delete` pops back to the chooser. |
| 9a/9b/9c | Header live clock + auto TZ; TZ fallback prompt; TZ override | 🟡 | Live clock + auto TZ done (`_refresh_header`). Fallback prompt / settings override: **To wire** (needs `/settings`). |
| 10a | Double-esc → edit a previous turn in place | 🔲 | No transcript-rewind/re-send mechanism. **To wire:** turn history navigation + truncate-and-resend in the session model. |

### 5. Remediation & approvals

| Canvas | Screen | Status | Notes / To wire |
|---|---|---|---|
| (existing gates) | Generic approval gate (run_linux_command, capture_traffic, vulscan-staleness, live threat-intel, self-write keep) | ✅ | `ApprovalModal` via the provider bridge. Fail-safe preserved. |
| 19b | **Recommend-only remediation** — show the exact command for the human to run themselves | 🟡 | `render.py::recommended_fix_panel` exists. Today Kratos surfaces recommendations inside the `final_answer` text (mk2 shows that). **To wire (nicety):** have the agent emit a structured "recommended command" so it renders as the dedicated 19b panel with a copy affordance. |
| 14d | Copy-to-clipboard confirmation | 🔲 | No clipboard action yet. **To wire:** a copy binding on command panels + a transient confirm toast. |
| 19a / 19d / 19e | Direct-execution **opt-in** (dedicated consent screen), settings toggle, first-run suggestion | 🔲 | **Direct execution does not exist** (arch doc capability 2, off by default, gated on the whitelist being built). **To wire:** the per-target toggle store + the sub-agent execution channel **and** the fixed narrow action whitelist (arch doc control 3 — the real security boundary), THEN this consent UI. Consent copy must use the arch doc's plain-risk wording (control 6). |
| 12c / 19c | Upgraded **critical gate** — typed `EXECUTE` | 🔲 | The typed-EXECUTE gate only means something once EXECUTE can dispatch to a sub-agent. **To wire:** same prerequisites as 19a; the risk disclosure (effect/reversibility/blast-radius) must come from the trusted whitelist action definition, **never** LLM-generated (arch doc control 7). |
| 16a | Sub-agent drops mid-type → field pulled live | 🔲 | Depends on the execution channel + liveness signal. |

### 6. Reporting (turn 4 / 16b)

| Canvas | Screen | Status | Notes |
|---|---|---|---|
| 4a | `/report` — findings sorted high→low severity | ✅ | `session.py::_render_report` aggregates `correlate_findings` output across the session's saved transcripts (same data path as `mcp_server.py::kratos_get_findings`). New UI, pre-existing data. |
| 16b | `/report` with **zero findings** — confidently clean (green, not empty) | ✅ | Handled — green "no findings" panel. |

### 7. Sub-agent status, reachability & multi-target (turns 11, 12, 15, 18)

All 🔲 — **no sub-agent, telemetry, or execution channel exists.**

| Canvas | Screen | To wire |
|---|---|---|
| 11a / 12b | Persistent sub-agent status chip (connected / unreachable / zombie) | Sub-agent liveness protocol; then a header/footer chip. |
| 18a / 18b | Zombie sub-agent (network up, process unresponsive) as a third tier | A responsiveness heartbeat distinct from TCP reachability. |
| 11b | Total target loss during investigation | Distinguish "core can't reach target at all" from a single tool timeout. |
| 11c–11f | Dispatch/refuse/drop-mid-exec/success outcomes | The execution channel + its outcome protocol (arch doc capability 2). |
| 12d / 12e | "No EXECUTE offered" when unreachable; multi-target dashboard | Reachability state; multi-target execution (explicitly out of scope in current code — `/target` uses only the first). |
| 15a–15d | Emergency revoke, core-off-tailnet, queued critical approvals, sandbox-never-produces-candidate | Revoke = tailnet key removal; queueing = a serialized approval queue; 15d is an evo-loop `LoopOutcome` state that CAN be surfaced today (nicety). |
| 17a–17e | State-drift hash check at EXECUTE, multi-target broadcast matrix, etc. | All depend on the execution channel. 17d (sandbox-hostility forensic view) could reuse existing `self_test` sandbox signals — a nearer-term nicety. |

### 8. Error / capability-limit states (turn 14, 17)

| Canvas | Screen | Status | To wire |
|---|---|---|---|
| 14a | Kratos's own model/API failure banner | 🟡 | Errors are shown inline (routing/investigation failures render as red lines). **To wire:** a full-width banner that distinguishes "Kratos can't think" from a tool/target problem. |
| 17b | Local inference hardware failure (OOM/thermal) | 🔲 | Needs host-health signals from the LLM layer. |
| 14c | Terminal-too-narrow hard block | ✅ | `app.py::TooSmallScreen` + `KratosTUI._apply_size_guard` (min 72×18). Blocks/clears live on resize; boot-gated so it can't race the first screen push. |
| 17c | Payload exceeds context before compaction | 🔲 | Depends on real token accounting (see 7c). |

---

## What a future session should do next (suggested order)

1. **Phase 1 polish — DONE:** full-tier on-screen replay, terminal-too-narrow
   guard (14c), `/model` cost/privacy blurbs, `/scan`-family shortcuts, the
   `/`-live palette, and the `/evolve` LLM-drafted-harness flow all shipped.
   Small remainders: chooser "[m] more" second page; 15d evo-loop "never
   produced a candidate" surfaced from `LoopOutcome`; a fuller 19b structured
   "recommended command" panel + 14d copy affordance.
2. **Real token accounting** (unblocks 7c accurate meter, 17c, 14b compaction):
   surface prompt-token usage from `llm_interface`.
3. **Sub-agent, telemetry-first** (arch doc capability 1, low risk): build the
   sub-agent + Tailscale pairing (turns 13/12a), then the status chips (11a/12b/18).
4. **Direct execution** (arch doc capability 2 — **gated on control 3's narrow
   whitelist existing first**): opt-in consent (19a/d/e) + typed-EXECUTE gate
   (12c/19c) + dispatch outcomes (11c–f), risk copy sourced from the whitelist,
   never the LLM.

**Hard constraint carried from `docs/subagent_architecture.md`:** direct
execution is opt-in, off by default, and the **action whitelist is the real
security boundary** (signing is not). Do not ship the execute path with any
arbitrary-path / arbitrary-write whitelist entry; sensitive paths
(`authorized_keys`, `sudoers.d`, cron, systemd units, `~/.ssh`) must be
unreachable through it regardless of framing.

---

## Verification done so far (headless Textual pilots)

- Boot → first-run trust → target-skip → chooser → new session → idle; `/help`,
  `/report`, command palette all reachable (no real LLM needed).
- Chat routing, live investigation rendering (tool lines + finding panels +
  concluding panel), transcript persistence, and `/report` aggregation — with
  `_route_input`/`run_agent` mocked (no network).
- Approval bridge: `request_approval` from a worker thread → `ApprovalModal` →
  `y` approves, `n`/esc deny (fail-safe intact).
- Full `pytest`: 129 passed / 37 skipped — **zero regression** from the
  `agent/tools.py` provider hook.
