#!/usr/bin/env python3
"""Control for check-silent-regressions.py: prove it can still FAIL after the HEAD narrowing.

WHY THIS EXISTS. On 2026-08-19 that gate was narrowed from `git log --all` to `git log HEAD`,
because `--all` walks every fetched ref: an identifier declared and dropped on somebody else's
unmerged branch read as a regression on a main that never contained it, so the verdict depended on
which branches a clone happened to fetch and CI fetches them all. The narrowing is correct and it
is still a NARROWING, and "the false positive stopped firing" is equally consistent with having
disabled the detector for the whole surrounding topic. Only a control separates those two.

The four cases below are that separation:

  A  baseline intact          -> rc 0    the tree is healthy and the gate agrees
  B  baseline emptied         -> rc 1    the narrowed walk STILL finds real silent removals in
                                         HEAD's own history, and names them
  C  B again, detection broken-> rc 0    B's failure came from the detector rather than from
                                         anything incidental
  D  bogus positive control   -> rc 2    the gate's own built-in control refuses to report

B is the over-correction control: if the narrowing had over-narrowed, B would go green and this
file would say so. C is what makes B worth believing.

Run: python scripts/mutation-check-silent-regressions.py
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "check-silent-regressions.py"
BASELINE = ROOT / "scripts" / "silent-regressions-baseline.json"

# Mutating the DETECTION, not the walk. Breaking the born-set instead would trip the gate's own
# built-in positive control and exit 2, which proves the control works and says nothing about
# whether the detector does. This anchor is the one line that records a finding.
ANCHOR = '            silent.append((name, bsha[:7], bsubj, f"{rsha} {rsubj}"))'
# Deliberately a DIFFERENT LENGTH from the anchor. A same-length replacement can collide with
# CPython's bytecode cache, which keys on source SIZE and MTIME, so a mutant edited inside one
# clock tick would execute the ORIGINAL bytecode and the control would silently test nothing.
MUTANT = (
    "            pass  # MUTANT: finding never recorded, so the detector cannot report"
)


def run(gate: pathlib.Path, root: pathlib.Path, extra: list[str] | None = None):
    proc = subprocess.run(
        [sys.executable, str(gate), *(extra or [])],
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def purge_pycache(root: pathlib.Path) -> None:
    for d in root.rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)


def main() -> int:
    src = GATE.read_text(encoding="utf-8")
    if ANCHOR not in src:
        print(
            "FAIL  mutation anchor is stale; this control would test the unmodified gate."
        )
        print(f"      looked for: {ANCHOR!r}")
        return 2
    if BASELINE.exists():
        accepted = json.loads(BASELINE.read_text(encoding="utf-8")).get("accepted", {})
    else:
        print("FAIL  baseline file is absent; case B would be vacuous.")
        return 2
    if len(accepted) < 3:
        print(
            f"FAIL  baseline accepts only {len(accepted)}; case B needs real recorded losses."
        )
        return 2

    results: list[tuple[str, bool, str]] = []

    # ---- A: healthy tree, intact baseline -> pass
    rc, _out = run(GATE, ROOT)
    results.append(("A intact baseline is GREEN", rc == 0, f"rc={rc}"))

    # ---- B and C run against a scratch copy of the gate + an emptied baseline.
    with tempfile.TemporaryDirectory() as td:
        work = pathlib.Path(td) / "scripts"
        work.mkdir(parents=True)
        empty = work / "silent-regressions-baseline.json"
        empty.write_text(
            json.dumps(
                {"_what": "emptied by mutation-check", "accepted": {}}, indent=2
            ),
            encoding="utf-8",
        )

        # The gate resolves its baseline from its OWN parent's parent, so a scratch copy of the
        # gate beside a scratch baseline reads the scratch one while still running `git log` in
        # the real repo via cwd. That is what lets B run without touching the tracked baseline.
        plain = work / "check-silent-regressions.py"
        plain.write_text(src, encoding="utf-8")
        purge_pycache(pathlib.Path(td))
        rc_b, out_b = run(plain, ROOT)
        named = [n for n in accepted if n in out_b]
        results.append(
            (
                "B emptied baseline still FAILS (over-correction control)",
                rc_b == 1,
                f"rc={rc_b}",
            )
        )
        results.append(
            (
                "B names real recorded losses",
                len(named) >= 3,
                f"named {len(named)} of {len(accepted)}: {', '.join(sorted(named)[:6])}",
            )
        )

        # ---- C: same as B with the detector disabled -> must go green
        mut = work / "check-silent-regressions.py"
        mutated = src.replace(ANCHOR, MUTANT)
        if mutated == src:
            results.append(("C mutation applied", False, "replace() was a no-op"))
        else:
            mut.write_text(mutated, encoding="utf-8")
            purge_pycache(pathlib.Path(td))
            rc_c, _ = run(mut, ROOT)
            results.append(
                (
                    "C detector disabled -> B's failure disappears",
                    rc_c == 0,
                    f"rc={rc_c} (expected 0; anything else means B failed for another reason)",
                )
            )

    # ---- D: the gate's own built-in positive control must refuse on a bogus token
    rc_d, _ = run(GATE, ROOT, ["--control", "__no_such_identifier_anywhere__"])
    results.append(("D bogus positive control REFUSES", rc_d == 2, f"rc={rc_d}"))

    width = max(len(n) for n, _, _ in results)
    bad = 0
    for name, ok, detail in results:
        if not ok:
            bad += 1
        print(f"  {'ok  ' if ok else 'FAIL'} {name:<{width}}  {detail}")

    print()
    if bad:
        print(
            f"{bad} of {len(results)} control(s) FAILED. The gate's verdict is not trustworthy."
        )
        return 1
    print(
        f"{len(results)}/{len(results)} controls pass: the gate fails when it should."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
