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

# (label, anchor in demo-preflight.py, replacement, what must notice it, which runner)
#
# EVERY REPLACEMENT IS TYPE-CORRECT ON PURPOSE. A mutant that crashes exits non-zero too, so a
# harness keying on the exit code cannot tell "the checker noticed" from "the mutant could not
# run" -- and the second proves nothing while looking identical. Swapping a digest for a
# length-derived digest keeps a hex string flowing through, where swapping it for an int would
# die in the f-string slice two lines later and score as a catch.
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
    (
        "currency by byte length",
        '    return hashlib.sha256(b.replace(b"\\r\\n", b"\\n").replace(b"\\r", b"\\n")).hexdigest()',
        "    return hashlib.sha256(str(len(b)).encode()).hexdigest()",
        "the digest becomes a pure function of LENGTH, which is the check this replaced, "
        "so the same-length-edit case must go red",
        "selftest",
    ),
    (
        "currency without eol normalising",
        '    return hashlib.sha256(b.replace(b"\\r\\n", b"\\n").replace(b"\\r", b"\\n")).hexdigest()',
        "    return hashlib.sha256(b).hexdigest()",
        "the same content re-encoded CRLF would read DIFFERS, so the over-correction "
        "case must go red",
        "selftest",
    ),
    (
        "currency accepts a 404 page",
        '    r = probe("pay page", PAY_URL, 200, want_body=True)',
        '    r = probe("pay page", PAY_URL, 404, want_body=True)',
        "an error page would be scored as served content, which is the false-DIFFERS this "
        "replaced, so the 404 case must go red",
        "selftest",
    ),
    (
        "currency header lookup is case-sensitive again",
        '        got_hdr = _hdr(w.headers, "access-control-expose-headers")',
        '        got_hdr = w.headers.get("access-control-expose-headers")',
        "a title-cased header would read ABSENT on a current Worker, so the "
        "title-case case must go red",
        "selftest",
    ),
    (
        "currency baseline searches the whole file",
        "    body = text[start : end if end != -1 else len(text)]",
        "    body = text",
        "a decoy literal above cors() would become the baseline, so the decoy case "
        "must go red",
        "selftest",
    ),
    (
        "currency by header presence",
        "            mine, theirs = _hdr_tokens(got_hdr), _hdr_tokens(want_hdr)",
        "            mine, theirs = _hdr_tokens(got_hdr), _hdr_tokens(got_hdr)",
        "the worker verdict becomes a presence ratchet that can only say CURRENT, so the "
        "stale-header case must go red",
        "selftest",
    ),
]


def run_suite(scripts_dir):
    return _run([sys.executable, str(scripts_dir / SUITE)])


def run_selftest(scripts_dir):
    """The currency block's control lives in the target itself, not in SUITE.

    Kept as a SECOND runner rather than folded into the first, because a mutant must be judged
    by the checker that is supposed to notice it. Running both and accepting either red would
    let a currency mutant be "caught" by an unrelated failure in the retry suite, which is a
    catch that proves nothing about the case it was written for.
    """
    return _run([sys.executable, str(scripts_dir / TARGET), "--selftest"])


def _run(argv):
    r = subprocess.run(
        argv, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    return r.returncode, (r.stdout or "") + (r.stderr or "")


RUNNERS = {"suite": run_suite, "selftest": run_selftest}


def main() -> int:
    src = (ROOT / "scripts" / TARGET).read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory() as td:
        work = pathlib.Path(td) / "scripts"
        shutil.copytree(
            ROOT / "scripts", work, ignore=shutil.ignore_patterns("__pycache__")
        )

        # A baseline that is not green means the mutants prove nothing, because a red
        # mutant would be indistinguishable from a red baseline.
        # BOTH runners must be green before any mutant is judged, not just the one that happens
        # to run first. A red baseline in either makes every mutant it judges unreadable.
        for which, fn in RUNNERS.items():
            rc, out = fn(work)
            if rc != 0:
                print(f"FAIL  baseline {which} is not green in the temp copy.")
                print(out[-1200:])
                return 2
            print(f"baseline {which:<9} rc=0  {out.strip().splitlines()[-1]}")

        survivors = []
        for mutant in MUTANTS:
            label, anchor, repl, expect = mutant[:4]
            run = RUNNERS[mutant[4] if len(mutant) > 4 else "suite"]
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
            rc, out = run(work)
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
