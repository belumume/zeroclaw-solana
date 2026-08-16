#!/usr/bin/env python3
"""Controls for check-shop-constant-agreement.py.

Run from the repository root:  python3 scripts/test_check_shop_constant_agreement.py

The gate passes on the real tree, which by itself is worth nothing: a checker that has never been
shown to fail cannot distinguish a clean repo from a broken instrument. Every case below builds a
synthetic tree in the gate's own expected layout, plants exactly one defect, and requires the
verdict it should produce.

THREE OUTCOMES, kept distinct on purpose. 0 is agreement, 1 is a real disagreement, 2 is could-not-
check. Collapsing 2 into 1 would make a red mean either "the constants drifted" or "I could not
read the table", and those need opposite responses. Collapsing 2 into 0 is the failure this whole
gate exists to prevent.

Stdlib only. Touches no network and nothing outside a temp directory.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "check-shop-constant-agreement.py"

MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
LABEL = "ZeroClaw Shop"

SKILL_OK = f"""# Solana Pay

## Never recall these four fields. Read them here, every time.

    recipient   {MERCHANT}
    mint        {MINT}   (mainnet USDC)
    label       {LABEL}
    network     mainnet. Real money. Say mainnet, never devnet.
"""

SCRIPT_OK = f'''#!/usr/bin/env python3
"""A stand-in carrying only the constants the gate reads."""

MERCHANT = "{MERCHANT}"
MINT = "{MINT}"
LABEL = "{LABEL}"
'''

AGREE, DISAGREE, CANNOT = 0, 1, 2

CASES = [
    ("the real values agree", SKILL_OK, SCRIPT_OK, AGREE),
    # Each side drifting, separately, because a gate that only reads one side would pass one of these.
    (
        "the SKILL's label drifts to the placeholder that reached a customer",
        SKILL_OK.replace(f"label       {LABEL}", "label       Demo Shop"),
        SCRIPT_OK,
        DISAGREE,
    ),
    (
        "the SCRIPT's label drifts",
        SKILL_OK,
        SCRIPT_OK.replace(f'LABEL = "{LABEL}"', 'LABEL = "Demo Shop"'),
        DISAGREE,
    ),
    (
        "the SKILL's recipient drifts by one character",
        SKILL_OK.replace(MERCHANT, MERCHANT[:-1] + "K", 1),
        SCRIPT_OK,
        DISAGREE,
    ),
    (
        "the SCRIPT's mint drifts",
        SKILL_OK,
        SCRIPT_OK.replace(MINT, "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"),
        DISAGREE,
    ),
    (
        "the network row says devnet",
        SKILL_OK.replace(
            "network     mainnet. Real money. Say mainnet, never devnet.",
            "network     devnet. Test money only.",
        ),
        SCRIPT_OK,
        DISAGREE,
    ),
    # COULD-NOT-CHECK, which must never read as a pass.
    (
        "a missing table row is CANNOT-CHECK, not a pass",
        SKILL_OK.replace(f"    label       {LABEL}\n", ""),
        SCRIPT_OK,
        CANNOT,
    ),
    (
        "a script with no LABEL constant is CANNOT-CHECK, not a pass",
        SKILL_OK,
        SCRIPT_OK.replace(f'LABEL = "{LABEL}"\n', ""),
        CANNOT,
    ),
    (
        "an absent skill file is CANNOT-CHECK, not a pass",
        None,
        SCRIPT_OK,
        CANNOT,
    ),
    # OVER-CORRECTION CONTROLS. These share the defects' vocabulary and must still PASS.
    (
        "the word devnet inside a prohibition still passes",
        SKILL_OK,
        SCRIPT_OK,
        AGREE,
    ),
    (
        "a mint row with its parenthetical gloss still passes",
        SKILL_OK.replace("(mainnet USDC)", "(mainnet USDC, 6 decimals)"),
        SCRIPT_OK,
        AGREE,
    ),
    (
        "a LABEL mentioned in a comment does not satisfy the anchored constant read",
        SKILL_OK,
        SCRIPT_OK.replace(
            f'LABEL = "{LABEL}"', f'# LABEL = "Demo Shop"\nLABEL = "{LABEL}"'
        ),
        AGREE,
    ),
]


def run_case(skill: str | None, script: str) -> tuple[int, str]:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="constagree-"))
    try:
        (tmp / "scripts").mkdir()
        (tmp / "skills" / "solana-pay" / "scripts").mkdir(parents=True)
        shutil.copy2(GATE, tmp / "scripts" / GATE.name)
        if skill is not None:
            (tmp / "skills" / "solana-pay" / "SKILL.md").write_text(
                skill, encoding="utf-8"
            )
        (tmp / "skills" / "solana-pay" / "scripts" / "pay_link.py").write_text(
            script, encoding="utf-8"
        )
        p = subprocess.run(
            [sys.executable, str(tmp / "scripts" / GATE.name)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    names = {AGREE: "agree", DISAGREE: "disagree", CANNOT: "cannot-check"}
    passed = failed = 0
    for desc, skill, script, want in CASES:
        rc, out = run_case(skill, script)
        ok = rc == want
        print(f"{'PASS' if ok else 'FAIL'}  [{names[want]:12s}] {desc}")
        if not ok:
            failed += 1
            print(
                f"        wanted rc={want} ({names[want]}), got rc={rc}: {out.strip()[:170]}"
            )
        else:
            passed += 1
    print(f"\nRESULT: {passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
