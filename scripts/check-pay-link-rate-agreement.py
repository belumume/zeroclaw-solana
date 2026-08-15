#!/usr/bin/env python3
"""The rate constants exist in two files. Assert they still agree.

WHY THE DUPLICATION EXISTS AT ALL, since duplication is normally the defect. `pay_link.py` runs
inside the agent workspace on the box, and `deploy/deploy-targets.json` copies exactly one file
there from `scripts/`: `pay_link.py` itself. `scripts/rate_crosscheck.py` never lands on the box,
so importing it is impossible rather than merely awkward. The choice was a second copy with a
gate, or an unverified rate on the money path. This file is the gate.

WHAT IT COMPARES, and the direction matters. `scripts/rate_crosscheck.py` is the ORIGINAL. Its
values are READ OUT OF ITS SOURCE here, never restated, so editing the original makes this gate
say so instead of quietly comparing against a copy of what someone once believed it said. Only
the jailed copy's values are declared, because that is the side being checked.

OFFLINE. Both files are parsed, not executed and not fetched from. A BCB or ECB outage cannot
redden a gate about constants.

Exit codes follow the house convention: 0 agree, 1 a real disagreement.

Run: python3 scripts/check-pay-link-rate-agreement.py
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ORIGINAL = ROOT / "scripts" / "rate_crosscheck.py"
JAILED = ROOT / "skills" / "solana-pay" / "scripts" / "pay_link.py"

# Every constant that decides what price a customer is shown. A value present in one file and
# absent from the other is a disagreement too, which is why the names are listed rather than
# discovered: a rename in one copy must fail here, not silently drop out of the comparison.
SHARED = [
    "PTAX_URL",
    "ECB_URL",
    "MAX_WALKBACK_DAYS",
    "MAX_DIVERGENCE",
    "MIN_PLAUSIBLE",
    "MAX_PLAUSIBLE",
]


def read_consts(path: pathlib.Path) -> dict[str, str]:
    """Module-level `NAME = value` assignments, normalised, from SOURCE text.

    Deliberately textual rather than importing: importing `pay_link.py` runs it, and importing
    either would let a bytecode cache answer instead of the file. Whitespace inside a
    parenthesised string concatenation is collapsed so the two spellings of a wrapped URL
    compare equal while any real character difference still does not.
    """
    if not path.is_file():
        print(f"FAIL  {path} is missing.", file=sys.stderr)
        sys.exit(1)
    src = path.read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for name in SHARED:
        m = re.search(
            rf"^{name}\s*=\s*(\(.*?\)|[^\n]+)$", src, re.MULTILINE | re.DOTALL
        )
        if m:
            out[name] = re.sub(r"\s+", "", m.group(1))
    # MIN_PLAUSIBLE and MAX_PLAUSIBLE are written as one tuple assignment in both files.
    pair = re.search(
        r"^MIN_PLAUSIBLE,\s*MAX_PLAUSIBLE\s*=\s*([^\n]+)$", src, re.MULTILINE
    )
    if pair:
        lo, _, hi = pair.group(1).partition(",")
        out["MIN_PLAUSIBLE"] = lo.strip()
        out["MAX_PLAUSIBLE"] = hi.strip()
    return out


def main() -> int:
    original = read_consts(ORIGINAL)
    jailed = read_consts(JAILED)

    missing = [n for n in SHARED if n not in original or n not in jailed]
    if missing:
        print(
            f"FAIL  constant(s) not found in both files: {missing}\n"
            f"      A rename or deletion in one copy is a disagreement, not an exemption.\n"
            f"      original={ORIGINAL.name} jailed={JAILED.name}",
            file=sys.stderr,
        )
        return 1

    bad = [(n, original[n], jailed[n]) for n in SHARED if original[n] != jailed[n]]
    for name in SHARED:
        same = original[name] == jailed[name]
        print(f"  {'ok  ' if same else 'FAIL'} {name} = {original[name]}")
    if bad:
        print(
            "\nFAIL  the two copies price differently:\n"
            + "\n".join(
                f"    {n}\n      {ORIGINAL.name}: {a}\n      {JAILED.name}: {b}"
                for n, a, b in bad
            )
            + "\n  The jailed copy is what a customer is priced by. Reconcile before shipping.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nPASS  {len(SHARED)}/{len(SHARED)} rate constants agree across both copies"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
