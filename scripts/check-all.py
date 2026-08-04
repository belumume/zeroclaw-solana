#!/usr/bin/env python3
"""Run EVERY publish gate, so which gates ran stops depending on what someone typed.

WHY THIS EXISTS. The one-pager, a judge-facing deliverable, was committed and pushed with
two em-dashes in it. Four gates were run before that commit and the slop gate was not one
of them, so the check that would have caught it reported nothing and looked exactly like a
check that passed. That is not a one-off: three different ad-hoc subsets were run in a
single session, each chosen by hand, none of them complete.

SCOPE IS DISCOVERED, NOT LISTED, and that decision was earned the hard way in the same
session: a checker written minutes earlier hardcoded which shapes were valid and produced
72 false positives, every one a correct file. A hand-written list here would rot the same
way, because a gate added later joins no list by itself.

THE FLOOR IS THE POINT. A discovery step that silently finds nothing would run zero gates
and report a clean sweep, which is the exact false-green this whole file exists to prevent.
Fewer gates than the floor is a broken walk, not a healthy repo, and it exits non-zero.

Gates needing network or a live host are declared below WITH their reason rather than
quietly omitted, because an undocumented omission is indistinguishable from an oversight.

Run: python3 scripts/check-all.py
"""

import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
MIN_GATES = 7  # below this the discovery walk is broken; see the docstring

# Declared exclusions, each with the reason it cannot run unattended on a clean machine.
EXCLUDED = {
    "check-config-drift.py": "compares against the LIVE host config; needs the running node",
    "check-host-compat.sh": "clones upstream; belongs in host-drift.yml on a schedule",
}


def discover():
    """Every tracked check-*.py, from git's own index rather than a hand list."""
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "scripts/check-*.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    names = sorted(pathlib.Path(p).name for p in out.split("\n") if p.strip())
    return [n for n in names if n != "check-all.py"]


def main() -> int:
    gates = discover()
    if len(gates) < MIN_GATES:
        print(
            f"FAIL  discovery found {len(gates)} gate(s); expected at least {MIN_GATES}."
        )
        print("      The walk is broken, so a clean result here would mean nothing.")
        return 2

    runnable = [g for g in gates if g not in EXCLUDED]
    print(f"running {len(runnable)} gate(s), {len(EXCLUDED)} declared-excluded\n")

    failures = []
    for g in runnable:
        t0 = time.time()
        r = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / g)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT),
        )
        dt = time.time() - t0
        mark = "ok  " if r.returncode == 0 else "FAIL"
        print(f"  {mark} {g:<28} rc={r.returncode}  {dt:5.1f}s")
        if r.returncode != 0:
            failures.append((g, r.returncode, (r.stdout or r.stderr or "").strip()))

    for g, reason in sorted(EXCLUDED.items()):
        print(f"  skip {g:<28} {reason}")

    if failures:
        print(f"\n{len(failures)} gate(s) FAILED:\n")
        for g, rc, out in failures:
            print(f"  --- {g} (rc={rc}) ---")
            for line in out.split("\n")[-12:]:
                print(f"    {line}")
        return 1

    print(f"\nall {len(runnable)} gate(s) pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
