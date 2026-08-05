#!/usr/bin/env python3
"""The stranger's evening, timed for real: empty folder, one clone, three commands, a clock.

    $ python demo/clean_clone.py
    $ git clone https://github.com/belumume/zeroclaw-solana
    ...
    $ python scripts/verify-proof.py          -> exit 0
    $ python scripts/verify_proof_offline.py  -> exit 0
    $ python scripts/certify_publish_tx.py    -> exit 0
    CLEAN CLONE VERIFIED in 74s | nothing installed, no key, no account
    775 tx | 0 failed | ...   <- the ring close: higher than the number the video opened on

Beat 13 films this. The elapsed figure is measured by this run, never quoted, because the claim
"a stranger can verify this in about a minute" is exactly the kind a judge tests. The clone is a
REAL network clone of the public repo into a directory that did not exist when the command
started, so what the camera sees is what a stranger gets.

Each sub-command's full output is deliberately NOT dumped: the beat is speed-ramped in the edit
and what must be LEGIBLE is one line per command plus the clock. The full outputs are the other
beats' job. Any sub-command failing prints its tail and fails the whole run loudly, because a
green clock over a red command would be the exact dishonesty this project's gates exist to catch.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time

REPO_URL = "https://github.com/belumume/zeroclaw-solana"
COMMANDS = (
    ("python scripts/verify-proof.py", "scripts/verify-proof.py"),
    ("python scripts/verify_proof_offline.py", "scripts/verify_proof_offline.py"),
    ("python scripts/certify_publish_tx.py", "scripts/certify_publish_tx.py"),
)
FEED = "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg"


def run(args, cwd, env=None):
    return subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def main():
    t0 = time.monotonic()
    workdir = tempfile.mkdtemp(prefix="stranger-")
    print(f"$ git clone {REPO_URL}")
    r = run(["git", "clone", "--quiet", REPO_URL], workdir)
    if r.returncode != 0:
        print((r.stderr or "")[-400:])
        print("FAIL  the clone itself failed; nothing below means anything")
        return 2
    clone = os.path.join(workdir, "zeroclaw-solana")
    print(f"  cloned in {time.monotonic() - t0:.0f}s")

    for cmd, script in COMMANDS:
        t = time.monotonic()
        r = run([sys.executable, script], clone)
        took = time.monotonic() - t
        status = "exit 0" if r.returncode == 0 else f"EXIT {r.returncode}"
        print(f"$ {cmd:<41} -> {status}  ({took:.0f}s)")
        if r.returncode != 0:
            print((r.stdout or "")[-300:])
            print((r.stderr or "")[-300:])
            print("FAIL  a stranger running this would have seen red. So do we.")
            return 1

    elapsed = time.monotonic() - t0
    print(
        f"\nCLEAN CLONE VERIFIED in {elapsed:.0f}s | nothing installed, no key, no account"
    )

    # The ring close, exactly as the plan's beat 13 specifies: re-run the OPENING beat's command
    # (feed_heartbeat, which ships on main and therefore exists in the clone) so the seq on screen
    # is the CLONE proving the feed moved while the judge watched. chain_history lives on the
    # submission branch and is deliberately NOT used here: a stranger's clone would not have it.
    r = run(
        [sys.executable, "scripts/feed_heartbeat.py"],
        clone,
        env={**os.environ, "FEED_PDA": FEED},
    )
    if r.returncode == 0 and r.stdout:
        print(r.stdout.strip())
    else:
        print(
            "ring close unavailable this run (heartbeat did not return); the clock above stands"
        )

    shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
