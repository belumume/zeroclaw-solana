#!/usr/bin/env python3
"""Prove every check in `certify_x402_payment_tx.py` is load-bearing.

A self-test that passes tells you the checks AGREE with the transactions it was given. It does not
tell you any of them is doing work: delete a condition and a suite whose negative cases were never
really exercised by it goes on printing green. So each check here is neutered in a copy of the
source, the copy's own self-test is run, and the run is REQUIRED to fail.

Two properties this file needs to be worth anything, both of which have silently broken elsewhere
in this repo:

  the substitution must APPLY. An anchor keyed on source text rots the moment that line is edited,
  after which the "mutant" is byte-identical to the original and the control certifies nothing
  while passing. Every row asserts its anchor exists before mutating.

  the harness must be able to produce GREEN. A control that only ever reports failure cannot
  distinguish a load-bearing check from a broken runner, so an unmutated copy is run first and is
  required to pass.

Mutations replace a CONDITION, never a line, so indentation is untouched and the mutant always
compiles. A mutant that fails to parse would be recorded as "did not pass" for the wrong reason.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE / "certify_x402_payment_tx.py"
# Sits beside the target so its own `parent.parent / docs/proof-bundle` still resolves. The
# leading underscore keeps it out of the `check-*.py` and `certify_*.py` globs.
MUTANT = HERE / "_mutant_certify_x402.py"

# (label, exact source fragment, replacement, effect). Each fragment is a CONDITION, and each is
# unique to the code path it guards rather than to a message a rewording would move.
#
# `effect` is what removing the check costs, and the distinction is the point rather than
# bookkeeping. "verdict" means the certifier would ACCEPT a transaction it must refuse, so the
# mutant's suite has to go red. "diagnostic" means another check still refuses and only the reason
# is lost, so the mutant's suite legitimately stays green and what must change is the OUTPUT.
#
# Recording a check as diagnostic is a claim that it is redundant for safety, so it is asserted
# rather than assumed: the row still fails if the mutant's output is byte-identical, which is what
# a check that does nothing at all would produce.
MUTATIONS = [
    (
        "the credited-account check",
        "at(A_RECEIVER_ATA) != want_ata",
        "False",
        "verdict",
    ),
    ("the mint-account check", "at(A_TOKEN_MINT) != mint", "False", "verdict"),
    (
        "the token-program check",
        "at(A_TOKEN_PROGRAM) != token_prog",
        "False",
        "verdict",
    ),
    ("the payload-mint check", "data[DATA_MINT_SLICE] != mint", "False", "verdict"),
    ("the program allowlist", 'ix["program"] not in allowed', "False", "verdict"),
    ("the single-spend check", "len(spends) != 1", "False", "verdict"),
    # Falls through to the `!= IX_TRANSFER_FIXED` check, which refuses anyway. Its value is
    # telling the operator a recurring delegation was pulled rather than reporting an
    # unrecognised discriminator.
    (
        "the recurring-pull refusal",
        "data[0] == IX_TRANSFER_RECURRING",
        "False",
        "diagnostic",
    ),
    # Removing this lets nothing bad through; it lets the positional reads run off the end of a
    # short account list. Failing closed BEFORE that read is the whole job, so the mutant raises
    # rather than mis-certifying, and the row asserts exactly that.
    (
        "the account-count check",
        'len(spend["accounts"]) != len(ACCT_NAMES)',
        "False",
        "crash",
    ),
    ("the local spend ceiling", "amount > max_amount_base_units", "False", "verdict"),
    ("the challenge-nonce memo check", "expected_memo is not None", "False", "verdict"),
    ("the versioned-message refusal", "msg and msg[0] & 0x80", "False", "verdict"),
    (
        "the both-receiver-forms refusal",
        "expected_receiver_b58 and expected_receiver_ata_b58",
        "False",
        "verdict",
    ),
    # Not a check but the derivation the positional check rests on. Corrupting the PDA marker
    # must break the calibration against the real on-chain token account.
    (
        "the PDA derivation itself",
        b'_PDA_MARKER = b"ProgramDerivedAddress"'.decode(),
        '_PDA_MARKER = b"ProgramDerivedAddres!"',
        "verdict",
    ),
]


def run(path: Path) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main() -> int:
    src = TARGET.read_text(encoding="utf-8")
    passed = failed = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal passed, failed
        print(
            f"{'PASS' if ok else 'FAIL'}  {name}"
            + (f"  ({detail[:90]})" if detail else "")
        )
        if ok:
            passed += 1
        else:
            failed += 1

    try:
        # The harness must be able to report green, or "everything failed" proves nothing.
        MUTANT.write_text(src, encoding="utf-8", newline="\n")
        rc, baseline = run(MUTANT)
        tail = baseline.strip().splitlines()[-1] if baseline.strip() else ""
        check(
            "an UNMUTATED copy still passes, so the harness can report green",
            rc == 0,
            tail,
        )

        for label, anchor, repl, effect in MUTATIONS:
            n = src.count(anchor)
            if n != 1:
                check(
                    f"{label}: anchor is unique",
                    False,
                    f"found {n} occurrences of {anchor!r}; a stale or ambiguous anchor "
                    f"certifies nothing while passing",
                )
                continue
            MUTANT.write_text(src.replace(anchor, repl), encoding="utf-8", newline="\n")
            rc, out = run(MUTANT)
            fails = [ln for ln in out.splitlines() if ln.startswith("FAIL")]
            if effect == "verdict":
                # rc alone is not enough: a mutant that CRASHES also exits non-zero, and
                # "could not start" would then be recorded as "the check fired".
                check(
                    f"{label} changes the VERDICT",
                    rc != 0 and len(fails) >= 1,
                    f"{len(fails)} case(s) went red"
                    if fails
                    else (
                        "MUTANT CRASHED, which is not evidence a case exercises it"
                        if rc != 0
                        else "SUITE STILL GREEN, so no case exercises it"
                    ),
                )
            elif effect == "crash":
                check(
                    f"{label} prevents an out-of-range read",
                    rc != 0 and not fails and "IndexError" in out,
                    "the mutant raised IndexError, so the check is what fails closed first"
                    if "IndexError" in out
                    else f"expected an IndexError, got rc={rc} with {len(fails)} red case(s)",
                )
            else:
                check(
                    f"{label} changes the DIAGNOSTIC (another check still refuses)",
                    out != baseline,
                    "the refusal reason changed"
                    if out != baseline
                    else "OUTPUT IDENTICAL, so it does nothing at all",
                )
    finally:
        MUTANT.unlink(missing_ok=True)

    print(f"\nRESULT: {passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
