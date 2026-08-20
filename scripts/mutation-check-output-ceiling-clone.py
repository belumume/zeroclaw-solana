#!/usr/bin/env python3
"""Prove the clone-path controls in verify-output-ceiling-agreement.py can FAIL.

A selftest that has only ever printed `all pass` certifies nothing about the code it
covers, and that is not a general worry here -- it is the specific one. The clone path was
added so a stranger with no ledger gets a real check rather than exit 2, and a check that
can only ever pass would be strictly worse than the honest refusal it replaced, because it
carries a green verdict.

So each mutant below disables ONE mechanism the clone path depends on and asserts that a
NAMED control goes red. A mutant that changes nothing, or that reddens the whole suite
indiscriminately, proves nothing about the specific control it is aimed at.

TWO MECHANICAL RULES, both enforced rather than intended:

  THE ANCHOR MUST BE PRESENT. `str.replace` on a string that is not there is a silent no-op,
  so the mutant would be byte-identical to the original and the harness would report the
  UNMODIFIED gate as having survived. Every anchor is asserted before it is used, and the
  anchors are the ones most likely to be reworded, so this fires as a stale-anchor alarm.
  THE MUTANT MUST BE A DIFFERENT LENGTH. CPython reuses a cached `.pyc` when the source's
  SIZE and MTIME both match what the cache recorded, so a same-length edit landing inside
  one filesystem tick can execute the OLD bytecode while the file on disk reads new. Each
  mutant is also written under a DIFFERENT FILENAME, which gives it its own cache entry, so
  the two defences are independent and neither is load-bearing alone.

  python3 scripts/mutation-check-output-ceiling-clone.py

Exit: 0 every mutant was caught, 1 a mutant survived (the control it targets is inert),
2 could not run.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "verify-output-ceiling-agreement.py"
# Written beside the gate on purpose: it resolves ROOT as `__file__.parent.parent`, so a
# mutant run from anywhere else would find no plugins/ and fail for the wrong reason.
MUTANT = ROOT / "scripts" / "mutant-under-test-ceiling.py"

# (label, anchor, replacement, the control that must go red)
MUTANTS = [
    (
        # `stored, why = load_extract()` alone appears TWICE -- here and in extract_drift()
        # -- and `replace(..., 1)` would have hit the WRONG one, mutating a function this
        # mutant is not aimed at while reporting on this one. The anchor carries the two
        # following lines to make it unique, and ANCHOR_MUST_BE_UNIQUE below enforces that
        # rather than leaving it to whoever edits this list next.
        "clone fallback disabled: no claims when the ledger is absent",
        '    stored, why = load_extract()\n    if why:\n        return None, "", [], why',
        '    stored, why = None, "mutant: clone fallback disabled"\n'
        '    if why:\n        return None, "", [], why',
        "clone: an honest extract reaches a verdict with no ledger at all",
    ),
    (
        "the `0 of 0 is not agreement` guard removed",
        "    if not compared:",
        "    if False:  # mutant",
        "an extract publishing no measurement exits CANNOT_CHECK, never PASS",
    ),
    (
        "the extract-freshness assertion removed",
        "        return claimed, origin, extract_drift(claimed), None",
        "        return claimed, origin, [], None  # mutant",
        "working tree: a STALE extract FAILS, it is not merely noted",
    ),
    (
        # The first version of this mutant set PLANT to a real published figure, and it
        # SURVIVED -- not because the control is weak, but because in a ledgerless checkout
        # the fixture's figures are 7,101+ and 505 disagrees with them just as loudly. An
        # environment-dependent mutant tests a different thing in each environment, which is
        # the one property a control must not have. Making the plant a NO-OP is
        # environment-independent: an extract identical to the honest one must not fail,
        # so the control that expects a failure has to go red.
        "the clone plant neutered: the 'planted' extract equals the honest one",
        '                (set(pl[v_clone]["claims"]) - {was}) | {PLANT}',
        '                set(pl[v_clone]["claims"])  # mutant: no-op',
        "clone: a planted disagreement FAILS against the extract",
    ),
]


def run(path: pathlib.Path) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, str(path), "--selftest"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main() -> int:
    if not GATE.is_file():
        print(f"cannot run: {GATE.name} is missing", file=sys.stderr)
        return 2
    src = GATE.read_text(encoding="utf-8")

    rc, out = run(GATE)
    # Read the selftest's OWN denominator rather than counting `ok` prefixes: the gate's
    # per-crate report lines share that prefix, so a naive count read 49 where 34 controls
    # ran. A number inflated by unrelated output is worse than no number, because it looks
    # like a measurement.
    tail = [ln for ln in out.splitlines() if ln.startswith("selftest:")]
    controls = tail[0].split("across ")[-1] if tail else "an unknown number of"
    if rc != 0:
        print(
            f"cannot run: the UNMUTATED selftest already fails (rc={rc}). Fix that first; "
            "a mutation result is meaningless against a red baseline.",
            file=sys.stderr,
        )
        return 2
    print(f"baseline: the unmutated selftest passes -- {controls}\n")

    survivors = []
    for label, anchor, replacement, expect in MUTANTS:
        if src.count(anchor) > 1:
            print(
                f"  FAIL {label}\n       the anchor appears {src.count(anchor)} times, "
                "so replace(count=1) would mutate whichever came first, not necessarily "
                "the site this mutant is aimed at"
            )
            survivors.append(label)
            continue
        if anchor not in src:
            print(
                f"  FAIL {label}\n       anchor not found, so nothing was mutated and "
                f"this mutant tests the ORIGINAL file: {anchor!r}"
            )
            survivors.append(label)
            continue
        if len(anchor) == len(replacement):
            print(
                f"  FAIL {label}\n       mutant is the same LENGTH as the anchor; a "
                "cached .pyc could mask it"
            )
            survivors.append(label)
            continue
        mutated = src.replace(anchor, replacement, 1)
        if mutated == src:
            print(f"  FAIL {label}\n       replace() was a no-op")
            survivors.append(label)
            continue
        try:
            MUTANT.write_text(mutated, encoding="utf-8", newline="")
            m_rc, m_out = run(MUTANT)
        finally:
            MUTANT.unlink(missing_ok=True)
            for junk in (ROOT / "scripts" / "__pycache__").glob("mutant-under-test*"):
                junk.unlink(missing_ok=True)

        caught = m_rc == 3 and f"FAIL {expect}" in m_out
        print(f"  {'ok  ' if caught else 'FAIL'} {label}")
        print(f"       rc={m_rc} (3 == a control failed), targets: {expect}")
        if not caught:
            survivors.append(label)
            # A mutant that reddens NOTHING is an inert control. One that reddens something
            # ELSE is an imprecise control, and the distinction changes the remedy.
            reds = [ln.strip() for ln in m_out.splitlines() if ln.startswith("  FAIL")]
            print(f"       controls that DID go red: {reds or 'none'}")

    if survivors:
        print(
            f"\nFAIL  {len(survivors)} of {len(MUTANTS)} mutant(s) survived. The control "
            "each one targets does not actually detect its defect:\n"
            + "\n".join(f"    {s}" for s in survivors),
            file=sys.stderr,
        )
        return 1
    print(
        f"\nPASS  all {len(MUTANTS)} mutant(s) were caught by the control aimed at them; "
        f"the clone path's controls are load-bearing"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
