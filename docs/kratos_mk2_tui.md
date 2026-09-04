# Kratos mk2 — Textual TUI (build + audit map)

Status: **Phase 1 complete. Phase 2 UI shells complete (both halves).** All
sub-agent / Tailscale / telemetry / execution screens exist as **UI-only shells**
in a dedicated `/preview` gallery (`tui_mk2/screens/phase2_preview.py`, 11
shells) — every one carries a persistent "NOT WIRED" banner + a to-wire note
tied to its backend layer, and the gallery is reachable ONLY via `/preview`
(never the normal flow) so a shell can't be mistaken for a wired capability.
**Backend is still fully greenfield** (no Tailscale/sub-agent/telemetry/
execution/whitelist code — confirmed). Safe half (zero execution): Tailscale
onboarding (Layer 1), pairing wizard (Layer 2), sub-agent status + zombie
(Layer 3), multi-target dashboard. Execution half — every one **gated on
Layer 4 (whitelist)** with its own gate banner: direct-execution consent +
settings (19a/d/e), typed-EXECUTE critical gate + drop-mid-approval + state-drift
(12c/19c/16a/17a), dispatch outcomes (11c–f), emergency revoke + queued approvals
(15a/15c), multi-target broadcast (17e — flagged as the doc's worst case, its own
review gate). Plus edge/error shells (14a/14b/17b/17c, 17d). The gallery is now **1:1 with the
canvas's Phase-2 screens** — the previously-noted-only variants are drawn as
their own panels: OAuth denied/abandoned/already-set-up (13d/e/f), disconnect &
unpair (13j/13m), total target loss (11b), regressed-unreachable (13k), core-off-
tailnet (15b), and the two no-EXECUTE-field states (12d unreachable, 18b zombied)
in the gated critical-gate shell. **Direct execution
cannot ship until the narrow action whitelist is designed and independently
reviewed — the whitelist, not signing, is the security boundary; the whitelist is
human-owned security work, must bound parameters (not just verbs), and Control 7
risk text comes from the trusted action definition, never the LLM.** See
`docs/subagent_architecture.md` v2 for the authoritative backend spec. This doc
is the working map between the *"Kratos TUI"*
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
| 6a "[m] more" | Overflow paging past `CHOOSER_SESSION_LIMIT` | ✅ | `m` pages forward through recent sessions via `list_recent_sessions(offset=…)`, wrapping back to page 1 after the last page (so nothing becomes unreachable). Footer shows the page number + whether more exist. |
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
| 9a/9b/9c | Header live clock + timezone; `/timezone` override; fallback prompt | ✅ | Live clock + display-zone abbreviation in the header (`_tz_label` reports the resolved DISPLAY zone via `%Z`, honest under an override). `/timezone [<zone>\|auto]` sets/clears a persisted override and live-re-resolves the session's zone. **9b fallback prompt done** (`_maybe_timezone_fallback`): if the system zone genuinely can't be detected (`display_tz_status` source `fallback`), a one-time modal asks for a zone; persisted so it never nags again. |
| 7b | Interrupt (esc) → resumable, "nothing left running" | ✅ | Cancels at next step boundary; turn marked `cancelled`. `ctrl+r` re-runs the last goal (an honest re-run — `run_agent` has no mid-loop checkpoint, so true "continue from step N" isn't possible); the interrupt note points at it. |
| 7c | Context-window meter in the footer, warns before compact | ✅ | **Real** now — the LLM layer exposes `get_last_token_usage()` / `get_context_window_tokens()` (backend commit); the footer shows `prompt_tokens` vs the context window (e.g. `50% (3.1k/6.1k)`), updates live after each step via `on_step`, and warns "will compact soon" at ≥85%. `reset_session_token_usage()` on session mount. |
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
| — | `/timezone` (+ 9a/9b/9c) | ✅ | See the 9a/9b/9c row under "A live turn" above — live clock, display-zone `%Z`, `/timezone` override, and the 9b fallback prompt are all done. |
| 10a | Edit a previous turn in place | ✅ | ↑/↓ recall prior turns into the prompt for editing (adapted from the mockup's double-esc — doesn't collide with esc=interrupt). Resending a recalled turn discards it and everything after via `SessionStore.archive_turns_from` (non-destructive soft-delete, recoverable), rebuilds the resume context, then re-runs. |

### 5. Remediation & approvals

| Canvas | Screen | Status | Notes / To wire |
|---|---|---|---|
| (existing gates) | Generic approval gate (run_linux_command, capture_traffic, vulscan-staleness, live threat-intel, self-write keep) | ✅ | `ApprovalModal` via the provider bridge. Fail-safe preserved. |
| 19b | **Recommend-only remediation** — show the exact command for the human to run themselves | ✅ | The agent now emits structured `recommended_commands` (`[{command, explanation, run_on}]`, backend commit). Each renders as a green `render.py::recommended_command_panel` — command, what it does, where to run it, and "Kratos does not execute it". `ctrl+y` copies them. Never a claim anything ran (permanent observe-and-recommend boundary). |
| 14d | Copy-to-clipboard confirmation | ✅ | `ctrl+y` copies Kratos's most recent answer/reply (`_last_answer`) via Textual's `copy_to_clipboard` (terminal OSC-52), with a transient confirmation toast. Per-command copy panels wait on 19b's structured command. |
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
| 15a–15c | Emergency revoke, core-off-tailnet, queued critical approvals | Revoke = tailnet key removal; queueing = a serialized approval queue. |
| 15d | Sandbox never produces a viable candidate | ✅ (the evo-loop half) | `/evolve` now reports each `LoopOutcome` distinctly: `write_failed` ("never produced a testable candidate"), `stalled_no_variation` ("converged, then repeated"), `exhausted_retries`, `infra_error` — the 15d "never got there" vs. "got there and stopped" distinction. |
| 17a–17e | State-drift hash check at EXECUTE, multi-target broadcast matrix, etc. | All depend on the execution channel. 17d (sandbox-hostility forensic view) could reuse existing `self_test` sandbox signals — a nearer-term nicety. |

### 8. Error / capability-limit states (turn 14, 17)

| Canvas | Screen | Status | To wire |
|---|---|---|---|
| 14a | Kratos's own model/API failure banner | ✅ | `render.py::llm_failure_banner` — a full-width red banner shown when routing or an investigation fails because Kratos's own model is unreachable (`_route_input` returns None, or `run_agent` returns `llm_unavailable`), explicitly distinguishing "Kratos can't think" from a tool/target problem. Other tool/target errors still render inline. |
| 17b | Local inference hardware failure (OOM/thermal) | 🔲 | Needs host-health signals from the LLM layer. |
| 14c | Terminal-too-narrow hard block | ✅ | `app.py::TooSmallScreen` + `KratosTUI._apply_size_guard` (min 72×18). Blocks/clears live on resize; boot-gated so it can't race the first screen push. |
| 17c | Payload exceeds context before compaction | 🔲 | Depends on real token accounting (see 7c). |

---

## What a future session should do next (suggested order)

1. **Phase 1 — COMPLETE (closed out).** Every Phase-1 screen is built,
   including the two that needed backend support (now landed): the **real** 7c
   token meter (wired to `get_last_token_usage()`/`get_context_window_tokens()`,
   live per step) and the **structured** 19b recommended-command panels (wired
   to the agent's `recommended_commands`). Full list: full-tier replay,
   terminal-too-narrow guard (14c), `/model` blurbs, `/scan`-family shortcuts,
   `/`-live palette, `/evolve` LLM-drafted-harness, chooser `[m]` paging,
   evo-loop outcome messaging (15d), `ctrl+y` copy (14d), 9b timezone fallback,
   edit-a-previous-turn (10a), `ctrl+r` re-run (7b), 14a LLM-failure banner,
   7c meter, 19b commands.
2. **Token accounting — DONE** (`llm_interface.get_last_token_usage()` etc.,
   wired into 7c). Still open, and dependent on it: an actual transcript
   **compaction** mechanism in `agent/loop.py`, which would then unblock the 14b
   "compaction fired" event and 17c "payload exceeds context" screens.
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
