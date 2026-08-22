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


def main(
    original_path: pathlib.Path = ORIGINAL, jailed_path: pathlib.Path = JAILED
) -> int:
    original = read_consts(original_path)
    jailed = read_consts(jailed_path)

    missing = [n for n in SHARED if n not in original or n not in jailed]
    if missing:
        print(
            f"FAIL  constant(s) not found in both files: {missing}\n"
            f"      A rename or deletion in one copy is a disagreement, not an exemption.\n"
            f"      original={original_path.name} jailed={jailed_path.name}",
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
                f"    {n}\n      {original_path.name}: {a}\n      {jailed_path.name}: {b}"
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


def selftest() -> int:
    """Prove this gate can FAIL, which nothing did until 2026-08-22.

    The gate was carefully built -- it reads the ORIGINAL's values out of source rather than
    restating them, and lists constant names explicitly so a rename cannot silently drop out of
    the comparison. That care is exactly why an uncontrolled green here would be believed. A
    checker is a hypothesis until it has produced the opposite verdict on a known input.

    Every case runs against COPIES in a temp dir. The real tree is never written, and the last
    case asserts that by digesting both real files before and after.
    """
    import hashlib
    import shutil
    import tempfile

    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (ORIGINAL, JAILED)}
    cases: list[tuple[str, int, int]] = []  # (name, expected_rc, actual_rc)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="rate-agreement-selftest-"))
    try:
        orig = tmp / "rate_crosscheck.py"
        jail = tmp / "pay_link.py"

        # 1. UNMODIFIED copies must PASS. This is the over-correction control: without it, a
        #    gate that failed on everything would satisfy every must-fail case below.
        shutil.copyfile(ORIGINAL, orig)
        shutil.copyfile(JAILED, jail)
        cases.append(("unmodified copies agree", 0, main(orig, jail)))

        # 2. A PLANTED DISAGREEMENT on the constant that decides what a customer pays.
        #    MAX_DIVERGENCE is the tolerance between two rate sources; widening it in the jailed
        #    copy alone is the shape that prices a customer off an uncorroborated rate.
        text = jail.read_text(encoding="utf-8")
        planted = re.sub(
            r"^MAX_DIVERGENCE\s*=\s*[^\n]+$",
            "MAX_DIVERGENCE = 0.99",
            text,
            count=1,
            flags=re.MULTILINE,
        )
        if planted == text:
            print(
                "FAIL  selftest could not plant a MAX_DIVERGENCE disagreement; the constant's "
                "spelling changed and this case is now vacuous.",
                file=sys.stderr,
            )
            return 1
        jail.write_text(planted, encoding="utf-8", newline="")
        cases.append(("planted value disagreement", 1, main(orig, jail)))

        # 3. A RENAME in one copy must FAIL too, not silently drop from the comparison. This is
        #    the case the SHARED list exists for, so it needs its own control.
        jail.write_text(
            re.sub(
                r"^MAX_DIVERGENCE\b",
                "MAX_DIVERGENCE_RENAMED",
                text,
                count=1,
                flags=re.MULTILINE,
            ),
            encoding="utf-8",
            newline="",
        )
        cases.append(("renamed constant", 1, main(orig, jail)))

        # 4. Restoring agreement must return to PASS, proving case 2 failed on the PLANT rather
        #    than on anything the copying did.
        jail.write_text(text, encoding="utf-8", newline="")
        cases.append(("restored copies agree", 0, main(orig, jail)))

        # 5, 6. A missing file is a failure, not a skip -- on EITHER side. read_consts is used
        #    symmetrically for both paths, so testing only one leaves the other's branch
        #    unexercised, and an asymmetric control is the shape that reads as covered.
        cases.append(
            ("missing jailed file", 1, _rc_of_missing(orig, tmp / "absent.py"))
        )
        cases.append(
            ("missing original file", 1, _rc_of_missing(tmp / "absent.py", jail))
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (ORIGINAL, JAILED)}
    untouched = before == after

    failed = [c for c in cases if c[1] != c[2]]
    print(
        f"\n  selftest: {len(cases) - len(failed)}/{len(cases)} cases behaved as required"
    )
    for name, want, got in cases:
        print(
            f"    {'ok  ' if want == got else 'FAIL'} {name}: wanted rc={want}, got rc={got}"
        )
    print(
        f"    {'ok  ' if untouched else 'FAIL'} real tree unwritten (2 files digested before and after)"
    )
    if failed or not untouched:
        return 1
    print("\nPASS  the gate produces BOTH verdicts on known inputs")
    return 0


def _rc_of_missing(original: pathlib.Path, jailed: pathlib.Path) -> int:
    """read_consts exits rather than returning, so the missing-file case needs its own harness.

    Named for the two SIDES rather than for which one is absent, because either may be: the
    missing-file branch is symmetric and testing only one side leaves the other unexercised.
    """
    try:
        return main(original, jailed)
    except SystemExit as e:
        return int(e.code or 0)


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(selftest())
    sys.exit(main())
