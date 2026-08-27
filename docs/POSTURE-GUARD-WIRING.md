# Wiring the WhatsApp posture guard so it can actually refuse a start

**DO NOT RUN ANY OF THIS BEFORE THE LIVE DEMO.** An `ExecStartPre` that fails blocks the start
of `zc-shop.service`. Wiring an unproven-in-that-position check into the one unit a live demo
depends on is the wrong trade hours beforehand, and the WhatsApp session behind it has already
been lost to a two-hour outage once.

## What was measured, and what was false

Measured on the box 2026-08-27: `ExecStartPre` appears **zero** times in `zc-shop.service`, with
`ExecStart` at **1** as the positive control proving the unit file was readable and greppable.

Two durable records asserted the opposite. `TESTING.md` said the guard "runs as `ExecStartPre`
and refuses to start the shop", and the handoff said the guard "gates boot on it". Both have
been corrected at source.

What is true: `~/whatsapp_posture_guard.sh` exists, is executable, and passes when run by hand.
That is the trap rather than the reassurance. A script that agrees with the current config is
indistinguishable from a gate, and this one had never refused a start in its life. The scenario
it exists for is a config edit that opens `group_policy` or empties `allowed_groups`, and the
precedent is real: a roughly 30-person group-spam incident is what caused the posture to be
installed. The daemon also rewrites `config.toml` on some paths, so the config changing
underneath is not hypothetical.

**The guard is not lost and does not need reconstructing.** This repo has tracked it at
`scripts/whatsapp_posture_guard.sh` since 2026-07-27, with two-way controls beside it at
`scripts/test_whatsapp_posture_guard.sh` that CI already runs. What was never true is that
anything invoked it at boot, or that the repo copy and the box copy had ever been compared.

## What ships with this document

- `deploy/zc-shop.service.d/10-posture-guard.conf`, a systemd **drop-in** rather than an edit to
  the unit. The live unit has never been read into this repo, so there is no tracked copy to
  edit and no honest way to ship a replacement. A drop-in asserts exactly one line and is
  removed by deleting one directory.
- A `map` entry in `deploy/deploy-targets.json` placing the guard at
  `~/.zeroclaw/bin/whatsapp_posture_guard.sh` so its hash lands in the generated manifest. Until
  now the running copy sat at `~/whatsapp_posture_guard.sh`, outside `ZEROCLAW_HOME`, where no
  map entry could reach it and nothing would notice it being edited.
- `require_directives` on the `zc-shop.service` unit entry, asserted by a new
  `required-directives` row in `deploy/box_selfcheck.py`. That row is what stops this
  regressing: `check_unit_definitions` has been collecting `ExecStartPre` into the published
  `/selfcheck` payload all along, and nothing ever read it back.

## Preconditions, in this order

The order is not advice. `deploy/x402-feed-gate.service` was committed with an `ExecStart`
pointing at a binary that did not exist; installing it verbatim would have failed 203/EXEC on
every start. An `Exec*` line is a guess until its target is read back off the box.

1. **Diff the two copies before anything overwrites either.** They have never been compared.

        diff -u ~/whatsapp_posture_guard.sh REPO/scripts/whatsapp_posture_guard.sh; echo "diff rc=$?"

   `rc=0` means they agree and the sync is a no-op in content. **Any other rc is a finding to
   read, not a file to clobber.** The box copy may carry a fix that never came back to the repo.

2. **Place the guard at the tracked path**, as part of a full tree sync that regenerates the
   manifest at the same commit. A single-file install is wrong here: `deploy/make_invariants.py`
   derives the manifest from `git ls-files` at one commit, so a fresh file against an older one turns
   `manifest` red, and `deploy/deploy-targets.json` already documents that trap under the
   `box_selfcheck.py` entry.

3. **Confirm the target exists and is executable, at the path the drop-in names.**

        test -x ~/.zeroclaw/bin/whatsapp_posture_guard.sh && echo PRESENT-AND-EXECUTABLE || echo ABSENT-STOP-HERE

4. **Run it by hand against the live config and read its output.**

        ~/.zeroclaw/bin/whatsapp_posture_guard.sh; echo "guard rc=$?"

   Expect `whatsapp group posture OK (allowed_groups non-empty, group_policy not open)` and
   `rc=0`. If it refuses here, **stop**: the posture is genuinely open and that is a live
   finding, not a wiring problem. Fix the config first.

Only when all four hold does the drop-in get installed.

## Install

    install -d ~/.config/systemd/user/zc-shop.service.d
    install -m644 REPO/deploy/zc-shop.service.d/10-posture-guard.conf ~/.config/systemd/user/zc-shop.service.d/10-posture-guard.conf
    systemctl --user daemon-reload
    systemctl --user cat zc-shop.service | grep -n ExecStartPre

A copied unit fragment is inert until the reload, so the reload is not optional. That `grep` is
the confirmation that systemd merged the drop-in, not merely that a file was copied.

## The two-way proof

**This is the point of the whole task.** An `ExecStartPre` that has never refused is the same
unproven script in a new location. One direction alone proves nothing: only-must-pass is
satisfied by a guard that refuses nothing, which is the fail-open being closed; only-must-refuse
is satisfied by a guard that refuses everything, which just wedges the shop.

### Direction A: with a good config the unit starts and the guard says so

    systemctl --user restart zc-shop.service
    systemctl --user is-active zc-shop.service
    journalctl --user -u zc-shop.service --since "-2 min" --no-pager | grep -c "whatsapp group posture OK"

Direction A passes when `is-active` reports `active` **and** that count is at least 1. The count
matters more than the status: an active shop with no pass line in the boot output is a shop
whose start path never ran the guard, which is the exact state being fixed. Note `grep -c`
prints `0` and exits 1 on no match, so read the printed number rather than the exit code.

### Direction B: with a deliberately opened policy the start is REFUSED

**`config.toml` is never touched.** The proof uses a scratch config and a second, temporary
drop-in that hands it to the guard on the guard's own command line, so the variable reaches the
guard process and nothing else. That matters: a bare `Environment=` in a drop-in applies to the
whole service, so it would also enter the daemon's environment at `ExecStart`.

Write the scratch config, one line per key:

    printf '%s\n' 'allowed_groups = []' 'group_policy = "all"' 'mode = "personal"' > ~/.zeroclaw/posture-proof-bad.toml

Write the temporary proof drop-in. The `%h` is written ONCE and must not be doubled: it is a
systemd specifier that has to survive into the file, and `printf` interprets `%` only inside its
FORMAT string, never inside an argument, so `%%h` here would be emitted literally. Measured:
`printf '%s\n' 'x=%%h'` prints `x=%%h`, and systemd would then resolve a path that does not exist
and refuse the start for the wrong reason, which reads exactly like the guard being broken.

    printf '%s\n' '[Service]' 'ExecStartPre=/usr/bin/env ZC_CONFIG=%h/.zeroclaw/posture-proof-bad.toml %h/.zeroclaw/bin/whatsapp_posture_guard.sh' > ~/.config/systemd/user/zc-shop.service.d/99-proof-badconfig.conf

Read the file back before reloading and confirm it carries a single `%h` in both places:

    cat ~/.config/systemd/user/zc-shop.service.d/99-proof-badconfig.conf

Then drive it:

    systemctl --user daemon-reload
    systemctl --user restart zc-shop.service ; echo "restart rc=$? (NON-ZERO IS THE PASS)"
    systemctl --user is-active zc-shop.service
    journalctl --user -u zc-shop.service --since "-2 min" --no-pager | grep -i "REFUSING TO START"

Direction B passes when the restart returns **non-zero**, `is-active` reports `failed` or
`activating`, and the journal carries `REFUSING TO START: allowed_groups is EMPTY`. Read that
message, not just the failure: a start that fails for an unrelated reason looks identical from
the exit code alone. A zero exit means the guard did not refuse in this position, and the
drop-in should be removed with the escape hatch below rather than left in place.

Both `10-` and `99-` run, in name order, so the good config passes first and the bad one refuses
second. The start being refused is what is under test either way.

**What this does not exercise, stated rather than glossed:** the production drop-in's exact
`argv` has no `/usr/bin/env` prefix, so Direction B proves the guard refuses under systemd at the
installed path in the `ExecStartPre` position, not that byte-identical argv. The alternative was
editing the live `config.toml`, which the daemon rewrites on some paths and which leaves the shop
refusing if a restore is missed. That trade was made deliberately.

## Restore, idempotent and safe to run twice

Run this whether or not Direction B was reached, and run it again if unsure. Every step is a
no-op when it has already been done.

    rm -f ~/.config/systemd/user/zc-shop.service.d/99-proof-badconfig.conf
    rm -f ~/.zeroclaw/posture-proof-bad.toml
    systemctl --user daemon-reload
    systemctl --user reset-failed zc-shop.service
    systemctl --user restart zc-shop.service
    systemctl --user is-active zc-shop.service
    systemctl --user cat zc-shop.service | grep -c posture-proof-bad

`rm -f` is silent on an absent file, `daemon-reload` and `restart` are idempotent, and
`reset-failed` is harmless when nothing has failed.

**`reset-failed` is the step most people skip and the one that leaves a shop that will not
start.** Repeated failed starts trip systemd's start rate limiter, after which a restart is
refused with `start request repeated too quickly` and looks exactly like the guard still
refusing when the config is already fine.

The final `grep -c` must print `0`. Anything else means the proof drop-in is still merged and
the shop is still gated on a config file that has been deleted.

## The escape hatch: one line, no editor, no repo checkout on the box

If the guard misbehaves at the worst possible moment, this removes everything this document
added and returns the shop to exactly its pre-wiring behaviour. It touches only the drop-in
directory. `zc-shop.service` itself is never modified by any step here, which is the whole
reason this is a drop-in.

    rm -rf ~/.config/systemd/user/zc-shop.service.d && systemctl --user daemon-reload && systemctl --user reset-failed zc-shop.service && systemctl --user restart zc-shop.service

Then confirm, because an exit code reports that commands ran and not that the shop is serving:

    systemctl --user is-active zc-shop.service

**Do not reach for `ExecStartPre=-` instead.** A leading dash makes a non-zero exit non-fatal,
so the guard would run, print its refusal, and the shop would start anyway. That restores the
exact fail-open the guard exists to remove, while looking wired. Removing the drop-in is visible
to the `required-directives` row in the next hourly selfcheck; defanging it in place is not.

**Using the escape hatch is not silent, and that is deliberate.** With `require_directives` in
place, the next `zc-selfcheck` run reports `required-directives` red with
`zc-shop.service: no ExecStartPre= line at all`, and that verdict is published at `/selfcheck`.
Pulling the guard under pressure is the correct move at the wrong moment; the assertion is what
stops it quietly becoming permanent.

## Verifying the wiring later without opening a shell

`deploy/box_selfcheck.py` publishes every configured unit's definition, structure only with
values withheld, into the verdict served at `/selfcheck`. So the question "did the
`ExecStartPre` land, and is it still there" is answerable over HTTPS:

    curl -s https://x402.perfpilot.dev/selfcheck | python3 -m json.tool

Read the `required-directives` check and the `zc-shop.service` entry under `unit_definitions`.
This route was deliberately not fetched while preparing this change, because the box was frozen
for the demo, but it is the intended instrument afterwards and it needs no session on the node.

## What could not be established without the box

Stated rather than filled in.

- **The live `zc-shop.service` content.** Never read into this repo. Whether it sets
  `Restart=always`, what its `ExecStart` is, and whether it already carries a `.d` directory are
  all unknown. The drop-in is additive precisely so none of those need to be known.
- **Whether the box copy and the repo copy of the guard are byte-identical.** Precondition 1
  exists because this is unknown, and the answer decides whether step 2 is a no-op or a
  reconciliation.
- **Whether `zc-qr.service` and `zc-tunnel.service` should be alive.** They are deliberately not
  added to `units[]` on a guess; see the drift-gate note in `deploy/deploy-targets.json`.
- **Whether `zeroclaw` itself reads `ZC_CONFIG`.** It is why Direction B scopes the variable to
  the guard's own command line rather than setting it service-wide.
