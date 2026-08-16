#!/usr/bin/env python3
"""Prove `check-deploy-content-staleness.py` can return every verdict it claims. (stdlib only)

    python3 scripts/mutation-check-deploy-staleness.py

Exit 0 = every control behaved. 1 = at least one did not. 2 = the controls could not run.

WHY A STALENESS GATE NEEDS THIS MORE THAN MOST. Its healthy answer is a red, because the box is
behind today. A red is exactly what a gate that resolved the wrong ref also prints, and it prints
it with the same confident list of filenames. So "it found drift" is worth nothing on its own:
what makes the verdict evidence is that the same code, on an input where the answer is known,
returns PASS and returns CANNOT VERIFY. Controls A and B are that demonstration, and they run
entirely offline against this clone's own history.

Control D is the mutation. It disables the comparison inside the gate and requires the real
2026-08-06 drift to stop being reported, because a gate that would pass whatever it was handed
detects nothing and a suite full of green controls cannot tell the difference. The substitution
is ASSERTED to have applied before the mutant runs: an anchor that has drifted out of the source
silently produces a byte-identical copy, and the control then certifies the unmodified gate.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "check-deploy-content-staleness.py"
CANNOT_CHECK = 2

# The box's real deployed sha as of 2026-08-16, pinned so these controls stay offline and stay
# reproducible after the box is finally brought current. Once it is, the live gate goes green
# and this commit is still the input on which the detector must demonstrably fire.
STALE_SHA = "4e65a5ca2b9eda1f5a9208f21ae25f4c39222d2a"


def git(*args: str) -> str:
    r = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return r.stdout.strip() if r.returncode == 0 else ""


def run(script: pathlib.Path, *args: str) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(ROOT),
    )
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def report(name: str, ok: bool, detail: str) -> bool:
    print(f"  {'ok  ' if ok else 'FAIL'} {name:<46} {detail}")
    return ok


def main() -> int:
    if not GATE.is_file():
        print(f"CANNOT VERIFY  no gate at {GATE.relative_to(ROOT)}")
        return CANNOT_CHECK

    head = git("rev-parse", "origin/main") or git("rev-parse", "HEAD")
    root_commit = (git("rev-list", "--max-parents=0", "HEAD") or "").split("\n")[-1]
    if not head or not root_commit:
        print("CANNOT VERIFY  this clone has no history to build controls from")
        return CANNOT_CHECK
    if not git("cat-file", "-t", STALE_SHA) == "commit":
        print(
            f"CANNOT VERIFY  the pinned stale commit {STALE_SHA[:12]} is not in this clone, "
            f"so the mutation control has no input on which the gate must fire."
        )
        return CANNOT_CHECK

    print("controls for check-deploy-content-staleness.py\n")
    ok = True

    # A. THE PASS VERDICT IS REACHABLE. A box deployed at the current ref must come back green.
    # Without this the gate could be one that reddens on everything, which is indistinguishable
    # from a working detector on a repo that happens to be stale.
    rc, out = run(GATE, "--sha", head)
    ok &= report(
        "A  box current  -> PASS",
        rc == 0 and "PASS" in out,
        f"rc={rc}",
    )

    # B. A LOOKUP THAT SHARES NOTHING IS NOT A FINDING. The root commit predates every mapped
    # path, so nothing matches. That is byte-identical in shape to a wrong ref, and it must
    # report CANNOT VERIFY rather than printing a full drift list that reads as real.
    rc, out = run(GATE, "--sha", root_commit)
    ok &= report(
        "B  nothing matches -> CANNOT VERIFY",
        rc == CANNOT_CHECK and "CANNOT VERIFY" in out,
        f"rc={rc}",
    )

    # C. AN UNRESOLVABLE SHA IS NOT DRIFT. A box reporting a commit this clone has never fetched
    # would otherwise compare as every file missing, which is the loudest possible false red.
    rc, out = run(GATE, "--sha", "0" * 40)
    ok &= report(
        "C  unknown sha -> CANNOT VERIFY",
        rc == CANNOT_CHECK and "cannot resolve" in out,
        f"rc={rc}",
    )

    # D. THE DETECTOR IS LOAD-BEARING. On the real stale commit the gate must FAIL, and with the
    # comparison neutered it must stop failing. Only the pair proves the red came from the
    # comparison rather than from anywhere else in the file.
    rc, out = run(GATE, "--sha", STALE_SHA)
    ok &= report(
        "D1 real stale deploy -> FAIL",
        rc == 1 and "DRIFTED" in out,
        f"rc={rc}",
    )

    src = GATE.read_text(encoding="utf-8")
    anchor = "        elif got == want:"
    if anchor not in src:
        ok &= report(
            "D2 mutant stops detecting",
            False,
            "the mutation anchor is gone from the gate; this control is testing nothing",
        )
    else:
        mutant_src = src.replace(anchor, "        elif True:", 1)
        if mutant_src == src:
            ok &= report(
                "D2 mutant stops detecting", False, "substitution did not apply"
            )
        else:
            # THE MUTANT RUNS FROM scripts/, NOT FROM A TEMP DIRECTORY, and that is a
            # correctness requirement rather than tidiness. The gate resolves its own repo root
            # as `__file__.parent.parent`, so a copy in a temp directory resolves a root with no
            # deploy map, exits CANNOT VERIFY before comparing anything, and prints no drift.
            # This control asserted only the absence of drift, so the first version of it passed
            # against a mutant that had never run. It now asserts the mutant REACHED the
            # comparison, by requiring the summary line the gate prints just before it.
            mutant = GATE.parent / "_mutant_deploy_staleness.py"
            try:
                mutant.write_text(mutant_src, encoding="utf-8")
                rc_m, out_m = run(mutant, "--sha", STALE_SHA)
            finally:
                mutant.unlink(missing_ok=True)
            reached = "mapped file(s)" in out_m
            # The mutant treats every present file as matching, so the four DRIFTED lines must
            # vanish. The four NEVER DEPLOYED ones survive, because that branch is untouched,
            # which is why this asserts on the drift line rather than on the exit code.
            ok &= report(
                "D2 mutant reaches comparison, stops detecting drift",
                reached and "DRIFTED" not in out_m,
                f"rc={rc_m}, reached={'yes' if reached else 'NO'}, "
                f"drift={'yes' if 'DRIFTED' in out_m else 'no'}",
            )

    print()
    if ok:
        print(
            "all controls behaved; the gate's verdicts are evidence rather than assertions"
        )
        return 0
    print("a control did not behave, so this gate's verdict cannot be trusted yet")
    return 1


if __name__ == "__main__":
    sys.exit(main())
