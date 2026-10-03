# Kratos

**Self-hostable, self-growing security analysis, with a terminal UI built for all.**

<p align="center">
  <img src="docs/images/investigation.gif" width="840" alt="Asking Kratos whether anyone tried to brute-force SSH: it measures the last 24 hours, scans, audits the config, correlates three findings and answers with a copyable fix">
</p>

Kratos looks over a machine and tells you, in plain English, what's going on with it: failed logins, exposed ports, changed files, risky configuration. It explains what it found and what it would do about it. By default it doesn't change the machine itself — acting on its advice is your call (see [Safe by default](#safe-by-default)).

It reaches a machine over SSH, or — for a box you can't or won't open to SSH — through a small agent that dials out to Kratos. It talks to a hosted model by default, so you can start in minutes; point it at a model you host yourself and nothing leaves your hardware.

When Kratos runs into something it has no tool for, it can write one, test it in a sandbox, and keep it — but only after you've read the code and approved it.

---

## What it does

**Investigate in plain words.** Ask *"has anyone been trying to log in as root?"* or *"is anything listening that shouldn't be?"*. Kratos picks its own read-only checks — auth logs, open ports, who can become root (and who was just added), processes, open files, file integrity, configuration, a YARA sweep of the usual malware drop locations, known vulnerabilities — runs them one at a time, correlates what it saw, and writes up findings with a recommended next step. If your request could go several ways, it asks first.

**Answers you can check.** Findings come from a rule engine (plain rules, no model), and the model's conclusion is checked against them: it can't call a host clean over a real high-severity finding, can't claim a time period its data doesn't cover, and can't finish without running the correlation step. "In the last 24 hours" means exactly that — Kratos counts every matching event in that window on the target itself and says if any part wasn't covered. It can also compare periods (*"this week vs last"*) and look up what a machine looked like at a past time from its own saved observations. And when an answer says Kratos couldn't check something, that gap is turned into a suggestion you can build with `/evolve`.

**Repeatable when you need it.** `/run` is a fixed audit with no model in the loop. Save any investigation as a **preset**, chain read-only tools into a **pipeline** (or describe one in words and let Kratos draft it for your review), preview a run with `/plan`, put it on a **schedule**, and set **triggers** that notify you or show a response playbook when a finding appears. Alerts go to your phone through [ntfy](https://ntfy.sh).

**Reach any box.** Over SSH (nothing installed on the target), or through a **sub-agent**: a small agent that dials out to Kratos — no inbound port, works behind NAT, best over Tailscale — streams live status and answers investigations with its own fixed set of reads.

**Grows with you.** `/evolve` writes a new tool when Kratos is missing one: you approve a test, it writes the tool, tests it in a locked-down sandbox, and shows you the code and its review flags. Nothing is kept until you say yes.

**Fits how you work.** A full-screen terminal UI with a command palette, session history and four themes; `kratos investigate "<goal>"` and `kratos run` for scripts and cron; and an [MCP](https://modelcontextprotocol.io) server so other agent tools (e.g. Claude Desktop) can ask Kratos to investigate — read-only. `/doctor` checks your whole setup and tells you the fix for anything wrong.

---

## What it looks like in use

When a request could go several genuinely different ways, Kratos asks instead of guessing:

<p align="center">
  <img src="docs/images/clarify.svg" width="820" alt="Kratos asking how deep to go, with three labeled choices and one recommended">
</p>

A machine reached only through its sub-agent: every read says how it was obtained, the network scan that needs a direct path is skipped, and the answer says what wasn't checked:

<p align="center">
  <img src="docs/images/subagent_investigation.svg" width="840" alt="An investigation of a box reached through its sub-agent: the port scan is refused, each read is marked as read through the sub-agent, and the answer notes that network exposure was not checked">
</p>

And `/doctor` checks the model, the target and the tools in one go:

<p align="center">
  <img src="docs/images/doctor.svg" width="840" alt="The /doctor self-check: a verdict over a table of checks, with an inline fix for the warning">
</p>

---

## Safe by default

Kratos observes and recommends. Every tool it can point at a target is read-only: it inspects logs, ports, processes and files and changes nothing there. A sub-agent runs only its own built-in reads (unless you turn on the experimental channel below), and no command text is ever sent to it. Recommended fixes are shown as commands for **you** to run — Kratos does not run them.

Everywhere a decision has real consequences — running a command on the Kratos machine, keeping a self-written tool — Kratos asks, and a non-answer means no. There is no "force yes."

**One experimental, off-by-default exception.** Kratos contains a path to carry out a small set of allowlisted fixes (for example, ban an IP in fail2ban) through a box's sub-agent. It is off for every box, and turning it on takes all of: a switch set on the box itself when the agent is started (the installer never sets it), your consent for that box in Kratos, the action being in that box's allowlist, and typing `EXECUTE` for each run. The allowlist is the safety boundary: the agent carries its own list of exactly which programs and arguments it will ever run, and Kratos can narrow that list but never widen it. **This path has not yet had its independent security review — don't enable it on a machine you care about.**

---

## Your data and your bill

Be aware of two things before you point Kratos at anything real:

- **By default, your data goes to a hosted model.** The logs, scan output, and findings Kratos reasons over are sent to whatever LLM you configure. If that's a cloud provider, that provider sees them. If you want nothing to leave your hardware, self-host the model (see [Backends](#backends)) — Kratos works the same either way.
- **A cloud model costs money per run.** Each investigation spends tokens. `/usage` shows what a session has cost so far, and scheduled runs warn you before they rack up a recurring bill. A self-hosted model is free to run.

Alerts (from schedules, triggers, or the notify tool) go through [ntfy](https://ntfy.sh) and are **off until you choose your own topic** (`KRATOS_NTFY_TOPIC` in `.env`; `/doctor` suggests a random one). Kratos ships no default topic on purpose: an ntfy topic has no password, so **anyone who knows the topic name can read every alert sent to it**, findings included. On the public ntfy.sh server, use a long random topic at the very least; for real deployments, run your own ntfy server (`KRATOS_NTFY_BASE_URL`) or use an ntfy access token (`KRATOS_NTFY_TOKEN`).

The sub-agent's link to Kratos carries no encryption of its own, which is why Tailscale (or another private network) is the recommended way to connect one. Over a plain network the agent sends status but refuses investigation reads unless you allow it when you install it.

One optional feature, threat-intel enrichment, is **off by default** and, when you turn it on, sends an IP address to a reputation service to check it. It's clearly separate from the core analysis, and Kratos runs fully without it.

---

## Install

You'll need Linux, Python 3.10 or newer, and a way to reach the machine you want to watch (SSH, or a sub-agent you install on it).

```bash
git clone https://github.com/TahrimWalid/kratos.git
cd kratos
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

(On Debian/Ubuntu, `python3 -m venv` needs the `python3-venv` package first.)

A few standard tools aren't Python packages — install them with your package manager:

- **`nmap`** on the Kratos machine (required for the port scan and the standard audit) — e.g. `sudo apt install nmap`.
- **`nuclei`** on the Kratos machine (optional, for deeper vulnerability scanning) — see the [nuclei install guide](https://github.com/projectdiscovery/nuclei#install-nuclei). Without it the vulnerability scan skips the active checks.
- **The CVE list** the vulnerability scan matches service versions against (optional): run `kratos vulscan-install` once. It downloads nmap's [vulscan](https://github.com/scipag/vulscan) script and its CVE list. Be aware that the freely downloadable list stops at **2013**: matches are real, but anything newer isn't checked, and Kratos says so in its answer. `/doctor` shows how far your copy goes.
- **[Incus](https://linuxcontainers.org/incus/)** on the Kratos machine (only for `/evolve`): new tools are tested inside a throwaway container with no network. The first `/evolve` builds the sandbox image once (a few minutes, needs internet).
- **`yara`** and **`lsof`** on the **machine you watch** — Kratos's setup check tells you if they're missing and gives you the command.

Then tell Kratos which model to use. Create your settings file and fill in three values:

```bash
kratos init
# then edit the .env file it names:
#   LLM_BASE_URL   the model's OpenAI-compatible endpoint
#   LLM_API_KEY    your key (or a placeholder for a local server)
#   LLM_MODEL      the model name
```

(You can also add a model from inside Kratos, under Settings → Models.)

**Where your settings and data live.** In a git checkout like the one above, everything stays in the checkout folder: `.env`, `data/` (sessions, findings, the session database), `kept_tools/`, `vulscan/`. A copy installed as a package (`pip install` without `-e`) uses per-user folders instead: settings in `~/.config/kratos/.env`, everything else under `~/.local/share/kratos/`. Set `KRATOS_HOME` to keep it all under one folder of your choice. `kratos init` and `/doctor` show the exact paths, and it doesn't matter which folder you start `kratos` from.

Start it:

```bash
kratos
```

---

## First steps

<p align="center">
  <img src="docs/images/home.svg" width="840" alt="Kratos home screen — the KRATOS wordmark, target/model/tools cards, and starter tips">
</p>

1. **Connect a machine.** Start a new session (or `/target <host>`). Kratos asks how to reach it — direct SSH or a sub-agent — and walks you through the one-time setup on that box.
2. **Ask a question.** Type what you want to know, in normal words. Kratos picks its own read-only tools and explains what it finds.
3. **Check your setup** any time with `/doctor`, and see a session's findings with `/report`.

Type `/guide` inside Kratos for the short version, `?` for every command, or read the full [user guide](docs/GUIDE.md).

---

## Machines you can't SSH into

<p align="center">
  <img src="docs/images/onboard.svg" width="410" alt="Choosing how Kratos should reach a new machine: direct SSH, a sub-agent, or later, with a panel explaining the highlighted option">
  <img src="docs/images/subagent.svg" width="410" alt="The /subagent screen: paired boxes with their status, agent version and last contact, and the details of one linked to a target">
</p>

Pick **Sub-agent** when you add a machine and Kratos generates a one-command installer for it (and can copy and run it over SSH for you, once). The agent runs as a service, dials out to Kratos, and opens no port on the box. From then on:

- **Status** streams in continuously (uptime, disk, listening ports, critical file hashes), whether or not you're investigating.
- **Investigations** read the box through the agent's fixed set of reads: logs and auth activity, privileged accounts, processes, open files, configuration, file hashes, and YARA with the rules on the box itself (credential files are never scanned, and only rule/file/offset comes back). No command text is ever sent to the agent, every request is signed, and a replayed one is refused.
- **What it can't do** is reach the box over the network: port and vulnerability scans are skipped for a box reached only through its agent, and the answer says so.

Kratos never guesses which machine a target is: choosing Sub-agent links the box once its agent checks in, and a target that merely *looks* like a paired box is offered, never linked silently. `/target link` switches a target between "sub-agent only" and "SSH first, sub-agent if SSH fails". `/subagent` manages the agents (add, update in place, unpair) and an always-on listener so status keeps arriving after you close Kratos.

---

## It grows with you

<p align="center">
  <img src="docs/images/evolve.svg" width="820" alt="The /evolve review: the tool's description, review flags, passing tests and source, and the keep decision">
</p>

If Kratos needs a check it doesn't have, `/evolve` builds one. You give it the idea; Kratos drafts a test that defines "correct" (you read and can edit it), writes the tool, runs the test in a container with no network, and shows you the code with review flags pointing at what's worth a second look — such as a failed read that would quietly come back as "nothing found". Nothing is kept until you say yes, and by default a kept tool still asks before each run. You can always run just one tool, directly, with `/use`.

---

## Themes

Kratos ships in Kratos Red by default, with Slate Blue, Matrix Green, and Cyan built in (`Ctrl+T`, or Settings). Danger-red and safe-green stay constant in every theme, so the colors that mean something never move.

<p align="center">
  <img src="docs/images/theme-green.svg" width="410" alt="Matrix Green theme">
  <img src="docs/images/theme-cyan.svg" width="410" alt="Cyan theme">
</p>

---

## Backends

One setting drives every backend. Point `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL` at:

- a **hosted provider** (any OpenAI-compatible API) — the quickest way to start;
- a **model you host yourself** — Ollama, vLLM, or llama.cpp — if you want your data to stay entirely local.

Self-hosting is fully supported; it's just not the default, because most people would rather not run a model to try a tool. `/model` switches backends live, and the home screen always shows whether the current one is local or billed.

---

## How it's built

```mermaid
flowchart TD
    you([You]) --> entry

    subgraph entry [How you talk to Kratos]
        tui[Terminal UI]
        cli[Command line<br/>investigate / run / scheduled runs]
        mcp[MCP server<br/>read/investigate only]
    end

    entry --> brain

    subgraph brain [Kratos core]
        loop[Agentic loop<br/>picks read-only tools, step by step]
        pipeline[Deterministic pipelines<br/>fixed, repeatable audits]
        evolve[Self-writing loop<br/>write, sandbox-test, your review, keep]
        rules[Findings engine<br/>plain rules, no model]
    end

    llm[(Language model<br/>hosted by default, or self-hosted)]
    loop <--> llm
    evolve <--> llm

    brain -->|read-only, over SSH| target[[Monitored machine]]
    brain -->|signed, named reads only| agent[Sub-agent on a machine<br/>dials out to Kratos]
    agent -->|status + read results| brain
    rules --> out[Plain-language findings<br/>and recommended commands]

    subgraph optin [Experimental, off by default]
        allow{{Allowlist held by the agent<br/>the security boundary}}
    end
    out -.->|you opt in per box, type EXECUTE| allow
    allow -.-> agent
```

The core reasons about a goal and picks its own read-only tools; a findings engine (plain rules, no model) correlates what was observed. The dashed path is the experimental, off-by-default fix channel described above. More detail in [docs/DESIGN.md](docs/DESIGN.md).

---

## Status and roadmap

Kratos is under active development. Working today: investigations and fixed audits, over SSH or a sub-agent; exact time windows and period comparisons; the findings engine and its checks on the model's conclusions; presets, pipelines, schedules and triggers; the self-writing loop; the MCP server; and the terminal UI. Its 1,800+ automated tests pass on Python 3.10 and 3.12.

Not yet: an independent security review of the experimental fix channel (required before it should be enabled anywhere real), running one investigation across several machines at once, and email delivery for scheduled reports.

---

## Where it came from

Kratos began as a Bachelor's thesis (Tampere University of Applied Sciences, Software Engineering, 2026): could a quantized model on ARM edge hardware produce meaningful, explainable security analysis with nothing sent off the machine? The answer was yes. It has grown well past that first prototype since, but the two ideas at its center — explain everything in plain language, and never act without a person — are the same ones it started with.

## License

Kratos is released under the [MIT License](LICENSE) — use it, change it, build on
it freely; just keep the copyright notice when you redistribute it.

One exception for the bundled extras: the YARA rules under `src/kratos/yara_rules/` are
third-party and stay under their own GPLv2 license (see
[`src/kratos/yara_rules/README.md`](src/kratos/yara_rules/README.md)). They're included as separate data
files the scanner reads, not part of Kratos's own code.
