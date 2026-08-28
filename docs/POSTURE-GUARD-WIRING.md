# Moving the WhatsApp posture guard under the deploy root so drift covers it

**THE INSTALL BELOW REPLACES A LIVE START GATE, so read the preconditions before running any
of it.** `~/.config/systemd/user/zc-shop.service.d/10-posture-guard.conf` already exists on the
box and already supplies the `ExecStartPre`. The file shipped here carries that same name, so
installing it does not add a gate, it repoints the existing one at a different path. An
`ExecStartPre` whose target is absent fails 203/EXEC and blocks the start of
`zc-shop.service`, and the WhatsApp session behind that service has been lost to a two-hour
outage once.

## What is wired, and what is not

`ExecStartPre` appears **zero** times in `zc-shop.service` itself, with `ExecStart` at **1** as
the positive control proving the unit file was readable and greppable. That measurement settles
nothing about the start path: systemd merges `<unit>.d/*.conf` drop-ins from separate files, so
the bare unit reads zero whether or not a guard is wired. The merged unit is the surface that
answers the question.

    systemctl --user cat zc-shop.service

Read that way on 2026-08-27 the box carries `ExecStartPre` at 1 and `ExecStart` at 1, supplied
by a 72-byte `~/.config/systemd/user/zc-shop.service.d/10-posture-guard.conf` dated 2026-07-27
that names `/bin/bash` and the home-directory copy at `~/whatsapp_posture_guard.sh`. The guard
has been observed refusing a start from that position and passing on the revert, recorded in
`docs/transcripts/whatsapp-allowlist-gate.md`. The scenario it exists for is a config edit that
opens `group_policy` or empties `allowed_groups`, and the precedent is real: a roughly
30-person group-spam incident is what caused the posture to be installed. The daemon also
rewrites `config.toml` on some paths, so the config changing underneath is not hypothetical.

**What is NOT covered is the deployed copy of the script.** It runs from
`~/whatsapp_posture_guard.sh`, outside `ZEROCLAW_HOME`, which is the root every `dst` in
`deploy/deploy-targets.json` resolves against. No map entry can reach it, so nothing hashes it
and nothing would report it being edited. This repo has tracked the script at
`scripts/whatsapp_posture_guard.sh` since 2026-07-27, with two-way controls beside it at
`scripts/test_whatsapp_posture_guard.sh` that CI already runs, and the two copies have never
been compared against each other. Closing that is what this change is for.

## What ships with this document

- `deploy/zc-shop.service.d/10-posture-guard.conf`, a tracked copy of the drop-in already
  running on the box, repointed at the deployed path. The live unit has never been read into
  this repo, so there is no tracked copy to edit and no honest way to ship a replacement of the
  unit itself. A drop-in asserts exactly one line and is reviewable in full. It carries the
  name the live one already has, so installing it is an overwrite rather than an addition.
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

**Back up the live drop-in first. The `install` below overwrites it.**

    cp ~/.config/systemd/user/zc-shop.service.d/10-posture-guard.conf ~/10-posture-guard.conf.bak
    install -d ~/.config/systemd/user/zc-shop.service.d
    install -m644 REPO/deploy/zc-shop.service.d/10-posture-guard.conf ~/.config/systemd/user/zc-shop.service.d/10-posture-guard.conf
    systemctl --user daemon-reload
    systemctl --user cat zc-shop.service | grep -n ExecStartPre

A copied unit fragment is inert until the reload, so the reload is not optional. That `grep` is
the confirmation that systemd merged the drop-in, not merely that a file was copied, and after
this step it has to name the deployed path rather than the home-directory one.

## The two-way proof

**Re-run this after the overwrite, because the path changed.** The refusal on record was
produced by a drop-in naming `~/whatsapp_posture_guard.sh`; the one installed above names
`%h/.zeroclaw/bin/whatsapp_posture_guard.sh`, and a gate is only as good as the argv it
actually runs. One direction alone proves nothing: only-must-pass is satisfied by a guard that
refuses nothing, which is the fail-open this gate exists to close; only-must-refuse is
satisfied by a guard that refuses everything, which just wedges the shop.

### Direction A: with a good config the unit starts and the guard says so

    systemctl --user restart zc-shop.service
    systemctl --user is-active zc-shop.service
    journalctl --user -u zc-shop.service --since "-2 min" --no-pager | grep -c "whatsapp group posture OK"

Direction A passes when `is-active` reports `active` **and** that count is at least 1. The count
matters more than the status: an active shop with no pass line in the boot output is a shop
whose start path did not run the guard, which is what the overwrite could break. Note `grep -c`
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

If the guard misbehaves at the worst possible moment, this restores the drop-in the box was
already running and starts the shop under it. `zc-shop.service` itself is never modified by any
step here, which is the whole reason this is a drop-in.

    cp ~/10-posture-guard.conf.bak ~/.config/systemd/user/zc-shop.service.d/10-posture-guard.conf && rm -f ~/.config/systemd/user/zc-shop.service.d/99-proof-badconfig.conf && systemctl --user daemon-reload && systemctl --user reset-failed zc-shop.service && systemctl --user restart zc-shop.service

**Do not reach for `rm -rf ~/.config/systemd/user/zc-shop.service.d` instead.** That directory
is not something this document created. It holds the drop-in that has been gating the shop's
start since 2026-07-27, so removing it does not undo an install, it deletes the guard and
starts a shop with no pre-check at all. Restoring from the backup taken in the install step is
the only form of this that ends with a gate still in place.

Then confirm, because an exit code reports that commands ran and not that the shop is serving:

    systemctl --user is-active zc-shop.service

**Do not reach for `ExecStartPre=-` instead.** A leading dash makes a non-zero exit non-fatal,
so the guard would run, print its refusal, and the shop would start anyway. That restores the
exact fail-open the guard exists to remove, while looking wired. Deleting the guard is visible
to the `required-directives` row in the next hourly selfcheck; defanging it in place is not.

**Removing the guard entirely is not silent, and that is deliberate.** With
`require_directives` in place, a `zc-selfcheck` run against a unit whose merged definition
carries no `ExecStartPre` reports `required-directives` red with
`zc-shop.service: no ExecStartPre= line at all`, and that verdict is published at `/selfcheck`.
Restoring the backed-up drop-in leaves the row green, because the assertion is a substring on
the script's filename rather than on a full path. That is the point of keying it that way: the
shop keeps a gate and the row keeps meaning something.

## Verifying the wiring later without opening a shell

`deploy/box_selfcheck.py` publishes every configured unit's definition, structure only with
values withheld, into the verdict served at `/selfcheck`. So the question "did the
`ExecStartPre` land, and is it still there" is answerable over HTTPS:

    curl -s https://x402.perfpilot.dev/selfcheck | python3 -m json.tool

Read the `required-directives` check and the `zc-shop.service` entry under `unit_definitions`.
That entry comes from `systemctl --user cat`, so it already carries whatever the drop-ins merge
in, and the whole question is answerable without a session on the node.

## What could not be established without the box

Stated rather than filled in.

- **The live `zc-shop.service` content.** Never read into this repo. Whether it sets
  `Restart=always` and what its `ExecStart` is are both unknown. It does carry a `.d`
  directory with `10-posture-guard.conf` in it, which is why the file shipped here lands as an
  overwrite rather than as an addition.
- **Whether the box copy and the repo copy of the guard are byte-identical.** Precondition 1
  exists because this is unknown, and the answer decides whether step 2 is a no-op or a
  reconciliation.
- **Whether `zc-qr.service` and `zc-tunnel.service` should be alive.** They are deliberately not
  added to `units[]` on a guess; see the drift-gate note in `deploy/deploy-targets.json`.
- **Whether `zeroclaw` itself reads `ZC_CONFIG`.** It is why Direction B scopes the variable to
  the guard's own command line rather than setting it service-wide.
