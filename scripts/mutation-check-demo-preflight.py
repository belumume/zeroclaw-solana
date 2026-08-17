#!/usr/bin/env python3
"""Prove scripts/test_demo_preflight.py can FAIL, by breaking the thing it claims to test.

    python3 scripts/mutation-check-demo-preflight.py

Exit 0 = the suite is load-bearing. 1 = a mutant survived. 2 = could not mutate.

WHY. A green suite is equally consistent with a working classifier and with a suite that
asserts nothing. The only way to tell is to break the classifier and require the suite to
notice. Two mutants are used rather than one, because they break the retry in OPPOSITE
directions and a suite could catch either alone while missing the other.

EVERY SUBSTITUTION IS ASSERTED BEFORE IT IS USED. A mutation control whose anchor has
rotted silently runs the UNMODIFIED code and reports the reassuring answer, which is the
exact failure it exists to prevent. Anchors are matched against the file, indentation
preserved, and a missing anchor exits 2 rather than passing.

The mutants run in a temp copy of scripts/, so the real tree is never modified.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = "demo-preflight.py"
SUITE = "test_demo_preflight.py"

# (label, anchor in demo-preflight.py, replacement, what the suite must notice)
MUTANTS = [
    (
        "retry everything",
        "            retryable = status >= 500 or status in (408, 429)",
        "            retryable = True",
        "a 404 would be retried and called TRANSPORT, so the over-correction control "
        "and the once-only count must both go red",
    ),
    (
        "retry nothing",
        "            retryable = status >= 500 or status in (408, 429)",
        "            retryable = False",
        "a 503 would be asked once and called SUBSTANCE, so the exhaustion count must "
        "go red",
    ),
    (
        "capture label raises again",
        "    except ValueError:\n        return str(path)",
        "    except RuntimeError:\n        return str(path)",
        "an out-of-root --capture-dir would raise ValueError again, which is the "
        "regression this tool shipped with, so the out-of-root case must go red",
    ),
]


def run_suite(scripts_dir):
    r = subprocess.run(
        [sys.executable, str(scripts_dir / SUITE)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main() -> int:
    src = (ROOT / "scripts" / TARGET).read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory() as td:
        work = pathlib.Path(td) / "scripts"
        shutil.copytree(
            ROOT / "scripts", work, ignore=shutil.ignore_patterns("__pycache__")
        )

        # A baseline that is not green means the mutants prove nothing, because a red
        # mutant would be indistinguishable from a red baseline.
        rc, out = run_suite(work)
        if rc != 0:
            print("FAIL  baseline suite is not green in the temp copy; cannot mutate.")
            print(out[-1200:])
            return 2
        print(f"baseline  rc=0  {out.strip().splitlines()[-1]}")

        survivors = []
        for label, anchor, repl, expect in MUTANTS:
            if anchor not in src:
                print(
                    f"FAIL  anchor for mutant {label!r} not found in scripts/{TARGET}."
                )
                print("      The anchor has rotted, so this control would run the")
                print("      UNMODIFIED code and report a pass that means nothing.")
                return 2
            (work / TARGET).write_text(
                src.replace(anchor, repl), encoding="utf-8", newline="\n"
            )
            rc, out = run_suite(work)
            last = out.strip().splitlines()[-1] if out.strip() else "(no output)"
            # rc 0 means the mutant survived. Any non-zero means the suite noticed; rc 2
            # would mean it could not run, which is not a catch, so require exactly 1.
            caught = rc == 1
            print(
                f"  {'ok  ' if caught else 'FAIL'} mutant {label:<18} rc={rc}  {last}"
            )
            if not caught:
                survivors.append((label, expect, out[-700:]))
            (work / TARGET).write_text(src, encoding="utf-8", newline="\n")

        # The real tree must be untouched. Cheap to assert, and this is the class of
        # script that would be worst to be wrong about.
        if (ROOT / "scripts" / TARGET).read_text(encoding="utf-8") != src:
            print("FAIL  the tracked file changed during this run.")
            return 2

    if survivors:
        print(
            f"\n{len(survivors)} mutant(s) SURVIVED; the suite is not load-bearing:\n"
        )
        for label, expect, out in survivors:
            print(f"  --- {label} ---\n  expected: {expect}")
            for line in out.split("\n")[-8:]:
                if line.strip():
                    print(f"    {line}")
        return 1

    print(f"\nall {len(MUTANTS)} mutant(s) caught; the suite is load-bearing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
