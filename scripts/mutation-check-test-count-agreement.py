#!/usr/bin/env python3
"""Prove each load-bearing piece of `check-test-count-agreement.py` is load-bearing. (stdlib only)

    python3 scripts/mutation-check-test-count-agreement.py

Exit 0 = every control behaved. 1 = at least one mutant survived. 2 = the controls could not run.

WHY THE SELFTEST IS NOT ENOUGH. That suite proves the gate returns the right verdict on the
inputs it is handed. It cannot prove the verdict came from the code that is supposed to
produce it. A gate that reddened on everything and a gate that reddened on nothing both
satisfy some of its cases, and a suite of 38 green cases looks identical either way. Each
control below disables ONE piece and requires the suite to go RED.

FOUR PROPERTIES EVERY CONTROL HOLDS, each of which has cost this repo a false green before:
  - the ANCHOR is asserted present before substituting. An anchor that has drifted out of the
    source produces a byte-identical copy, and the control then certifies the real gate.
  - the anchor's INDENTATION is preserved. A replacement dedented against its block is an
    IndentationError, and a mutant that cannot start looks exactly like a mutant that did not
    fire.
  - the replacement is a DIFFERENT LENGTH from the anchor. CPython validates a cached `.pyc`
    on the source's SIZE and MTIME, so a same-length edit landing inside one filesystem tick
    can execute the OLD bytecode -- which fails in both directions at once, since a mutant may
    appear caught while the real code ran, or a fix may appear to pass while it never loaded.
    Each mutant here is also written to a UNIQUELY NAMED file, so no cache can be shared.
  - a run that produced no `selftest:` line did not reach the suite, and is scored as a
    control FAILURE rather than as a catch. An exit code alone cannot tell a crash from a
    verdict: a mutant with a syntax error exits 1, and 1 is inside the gate's own vocabulary.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "check-test-count-agreement.py"
SELFTEST_FAILED = (
    3  # the gate signals a failed control OUTSIDE its own 0/1/2 vocabulary
)
STARTED_MARKER = "selftest:"  # printed only once the suite has actually run

# (label, anchor, replacement, what it disables and which case must go red)
MUTANTS = (
    (
        "the plural `tests` requirement",
        r'    r"(?<![\w.,-])(\d[\d,]*)(?!\d)(?:[ \t]+[A-Za-z][\w-]*)?[ \t]+tests\b", re.IGNORECASE',
        r'    r"(?<![\w.,-])(\d[\d,]*)(?!\d)(?:[ \t]+[A-Za-z][\w-]*)?[ \t]+tests?\b", re.IGNORECASE',
        "admitting the singular; the must-not-fire cases built from `--test-threads=1` and "
        "`ZEROCLAW_DEVNET_PROOF=1 cargo test` must go red",
    ),
    (
        "line-level crate attribution",
        "    if len(named) == 1:",
        "    if False and len(named) == 1:",
        "so a line naming another crate is judged against the wrong one",
    ),
    (
        "README-level crate attribution",
        '    if pathlib.PurePosixPath(doc_rel).name.lower() == "readme.md" and parent in known:',
        '    if False and pathlib.PurePosixPath(doc_rel).name.lower() == "readme.md" and parent in known:',
        "so a crate README's own claims fall back to the union and stop being gated strictly",
    ),
    (
        "the SUM as an accepted figure",
        "    return set(counts) | {sum(counts)}",
        "    return set(counts)",
        "so a published crate TOTAL reads as a figure no target printed",
    ),
    (
        "the union-completeness guard",
        "    union_complete = not broken and set(known) <= set(measured)",
        "    union_complete = True",
        "so an incomplete union manufactures a failure against a correct figure",
    ),
    (
        "the compared-nothing refusal",
        "    if compared == 0:",
        "    if compared == -1:",
        "so a run that compared nothing at all reports a pass",
    ),
    (
        "lazy expansion, forced always-on",
        "    if any(v not in union for v in unattributed):",
        "    if True or any(v not in union for v in unattributed):",
        "so a satisfied unattributed claim still drags every remaining crate into the build",
    ),
    (
        "lazy expansion, forced always-off",
        "    if any(v not in union for v in unattributed):",
        "    if False and any(v not in union for v in unattributed):",
        "so an unsatisfied unattributed claim is judged against a union that was never grown",
    ),
    (
        "the presence short-circuit on a partial union",
        "            if value in union:",
        "            if False and value in union:",
        "so a figure the union already contains is re-judged as though absence were in doubt",
    ),
)


def indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def main() -> int:
    if not GATE.is_file():
        print(f"cannot check: {GATE} is missing")
        return 2
    src = GATE.read_text(encoding="utf-8")

    # The unmutated gate must be GREEN first. A control suite run against an already-red gate
    # scores every mutant as a catch and proves nothing at all.
    base = subprocess.run(
        [sys.executable, str(GATE), "--selftest"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if base.returncode != 0:
        print("cannot check: the unmutated gate's own selftest is not green, so every")
        print("mutant below would score as a catch regardless of the mutation.")
        print((base.stdout or "") + (base.stderr or ""))
        return 2
    print("baseline: the unmutated gate's selftest is green")

    failures = []
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        for i, (label, anchor, replacement, why) in enumerate(MUTANTS):
            if src.count(anchor) != 1:
                failures.append(
                    f"{label}: the anchor appears {src.count(anchor)} time(s), not once, so the "
                    f"substitution could not be applied and this control tested nothing"
                )
                continue
            if len(anchor) == len(replacement):
                failures.append(f"{label}: mutant is the same length as the anchor")
                continue
            if indent_of(anchor) != indent_of(replacement):
                failures.append(f"{label}: mutant changes the anchor's indentation")
                continue

            # A unique filename per mutant, so no two mutants can share a cached .pyc.
            mutant = tmp / f"mutant_{i}_{len(replacement)}.py"
            mutant.write_text(src.replace(anchor, replacement), encoding="utf-8")
            r = subprocess.run(
                [sys.executable, str(mutant), "--selftest"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            out = (r.stdout or "") + (r.stderr or "")
            if STARTED_MARKER not in out:
                failures.append(
                    f"{label}: the mutant never reached the suite (rc={r.returncode}), so this "
                    f"control cannot tell a catch from a crash"
                )
                continue
            if r.returncode != SELFTEST_FAILED:
                failures.append(
                    f"{label}: SURVIVED (rc={r.returncode}); disabling it should have reddened "
                    f"the suite by {why}"
                )
                continue
            print(f"  caught  {label}")

    print(f"\nmutation controls: {len(MUTANTS) - len(failures)}/{len(MUTANTS)}")
    for f in failures:
        print(f"  FAIL  {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
