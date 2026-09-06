# Attack scripts — source IP requirement

Run these scripts from a source IP **distinct from Kratos's own host**, not from the
same machine Kratos runs on. This isn't just a test-hygiene nicety:

1. **fail2ban collateral bans**: even with Kratos's host added to the target's
   fail2ban `ignoreip` (see `docs/target_hardening_checklist.md`, item 3b), an attack
   launched from Kratos's own IP would be exempted from banning too — defeating the
   point of testing detection against a real ban.
2. **Realism**: a real attacker is a distinct network entity from the thing
   investigating. Running both from the same host tests a scenario that can't happen
   in a real deployment.

For the current lab (Incus-based target on the `incusbr0` bridge), spin up a second
Incus container on the same network to get a genuinely distinct IP — confirmed live
(2026-07-12) via the target's own sshd journal that this produces a real distinct
source IP, unlike a default-bridge Docker container on the same host (which NATs
egress through the host's own IP and would NOT be distinct):

```bash
incus launch images:ubuntu/jammy attacker-box
incus exec attacker-box -- bash -c "apt-get update -qq && apt-get install -y -qq hydra openssh-client"
incus list   # confirm attacker-box's IP is different from Kratos's own host IP
```

Then run the attack script itself from inside that container, e.g.:

```bash
incus exec attacker-box -- bash -c "$(cat ssh_bruteforce.sh)"
```

(or copy the script + wordlist in via `incus file push` and run it there directly —
either works; the fixed target host/user embedded in the script itself are unaffected
either way).

## Container lifecycle policy (DECIDED 2026-09-06)

**Persist both.** `attacker-box` and `kratos-target` are kept running indefinitely on
purpose — `kratos-target` is the monitored host for essentially all dev/eval work, and
`attacker-box` is cheap to leave alongside it. This is a deliberate decision, not an
unaddressed gap: the host has room, and rebuilding the lab image on every use would cost
more than the idle resources they hold. No automatic teardown.

Tear them down manually only when you genuinely want the host resources back (both are
recreatable — `kratos-target` from the lab image build, `attacker-box` via the
`incus launch … && apt-get install hydra …` steps above):

```bash
incus stop attacker-box kratos-target        # frees CPU/RAM, keeps the containers
incus delete attacker-box kratos-target       # also frees disk (full teardown)
```
