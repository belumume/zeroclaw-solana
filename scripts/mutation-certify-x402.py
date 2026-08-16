#!/usr/bin/env python3
"""Prove every check in `certify_x402_payment_tx.py` is load-bearing.

A self-test that passes tells you the checks AGREE with the transactions it was given. It does not
tell you any of them is doing work: delete a condition and a suite whose negative cases were never
really exercised by it goes on printing green. So each check here is neutered in a copy of the
source, the copy's own self-test is run, and the run is REQUIRED to fail.

FOUR PROPERTIES THIS FILE NEEDS TO BE WORTH ANYTHING, each of which has silently broken somewhere
in this repo or in an earlier draft of this very file:

  the substitution must APPLY. An anchor keyed on source text rots the moment that line is edited,
  after which the "mutant" is byte-identical to the original and the control certifies nothing
  while passing. Every row asserts its anchor exists, exactly once, before mutating.

  the harness must be able to produce GREEN. A control that only ever reports failure cannot
  distinguish a load-bearing check from a broken runner, so an unmutated copy is run first and is
  required to pass.

  a CRASHING mutant is not a caught case. A mutant that dies also exits non-zero, so reading exit
  codes alone records "could not start" as "the check fired". Verdict rows require a red CASE.

  a check cited as the REASON another is only diagnostic must itself be anchored. Otherwise the
  pair is mutually redundant with neither half proven, and deleting the backstop leaves the whole
  suite green. An adversarial review found exactly that here: the recurring-pull row was justified
  by the discriminator check, and the discriminator check had no row.

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
# bookkeeping. "verdict" means the certifier would ACCEPT something it must refuse, so a CASE has
# to go red. "diagnostic" means another check still refuses and only the reason is lost, so the
# suite legitimately stays green and what must change is the OUTPUT.
#
# Recording a row as diagnostic is a claim that the check is redundant for safety. It is asserted
# rather than assumed twice over: the row fails if the output is byte-identical, and the check
# named as its backstop carries a verdict row of its own.
MUTATIONS = [
    # --- where the money goes
    (
        "the credited-account check",
        "at(A_RECEIVER_ATA) != want_ata",
        "False",
        "verdict",
    ),
    # --- where the money comes from
    (
        "the funding-delegation check",
        "at(A_DELEGATION) != delegation",
        "False",
        "verdict",
    ),
    (
        "the payload-delegator check",
        "data[DATA_DELEGATOR_SLICE] != delegator",
        "False",
        "verdict",
    ),
    (
        "the debited-token-account check",
        "at(A_DELEGATOR_ATA) != derive_ata(delegator, mint, token_prog)",
        "False",
        "verdict",
    ),
    # --- what is being moved
    ("the mint-account check", "at(A_TOKEN_MINT) != mint", "False", "verdict"),
    (
        "the token-program check",
        "at(A_TOKEN_PROGRAM) != token_prog",
        "False",
        "verdict",
    ),
    (
        "the trailing self-CPI program check",
        "at(A_SUBSCRIPTIONS_PROGRAM) != allowance",
        "False",
        "verdict",
    ),
    ("the payload-mint check", "data[DATA_MINT_SLICE] != mint", "False", "verdict"),
    ("the local spend ceiling", "amount > max_amount_base_units", "False", "verdict"),
    # --- what kind of spend it is
    (
        "the transferFixed discriminator check",
        "data[0] != IX_TRANSFER_FIXED",
        "False",
        "verdict",
    ),
    # Falls through to the discriminator row above, which is anchored, so only the reason is
    # lost: the operator would be told the byte is unrecognised rather than that a recurring
    # delegation was pulled.
    (
        "the recurring-pull refusal",
        "data[0] == IX_TRANSFER_RECURRING",
        "False",
        "diagnostic",
    ),
    ("the payload-length check", "len(data) != TRANSFER_DATA_LEN", "False", "verdict"),
    (
        "the account-count check",
        'len(spend["accounts"]) != len(ACCT_NAMES)',
        "False",
        "verdict",
    ),
    ("the single-spend check", "len(spends) != 1", "False", "verdict"),
    # --- what else rides along. A permitted PROGRAM is not a permitted ACTION.
    (
        "the program allowlist's final else",
        'raise CertificationError(f"ix{k} invokes an unexpected program {who}{hint}")',
        "pass",
        "verdict",
    ),
    # Falls through to the nonce-identity check, which is anchored: with no nonce configured
    # every account fails that comparison. Only the reason is lost.
    ("the System-with-no-nonce refusal", "nonce is None", "False", "diagnostic"),
    (
        "the AdvanceNonceAccount data check",
        'ix["data"] != SYS_ADVANCE_NONCE',
        "False",
        "verdict",
    ),
    (
        "the nonce-account identity check",
        'not ix["accounts"] or ix["accounts"][0] != nonce',
        "False",
        "verdict",
    ),
    ("the priority-fee ceiling", "fee > max_priority_lamports", "False", "verdict"),
    (
        "the ATA CreateIdempotent check",
        'not ix["data"] or ix["data"][0] != IX_CREATE_IDEMPOTENT',
        "False",
        "verdict",
    ),
    (
        "the ATA target check",
        'len(ix["accounts"]) < 4 or ix["accounts"][1] != want_ata',
        "False",
        "verdict",
    ),
    # --- flags are part of what executes
    (
        "the delegatee-is-signer check",
        'not spend["signer"][A_DELEGATEE]',
        "False",
        "verdict",
    ),
    ("the writable-slot check", 'not spend["writable"][slot]', "False", "verdict"),
    # --- the memo binds the payment to one challenge
    ("the memo-count check", "len(memos) != 1", "False", "verdict"),
    (
        "the memo-equality check",
        'memos[0]["data"] != expected_memo',
        "False",
        "verdict",
    ),
    ("the unconfigured-memo refusal", "if memos:", "if False:", "verdict"),
    # --- the parser refuses what it cannot read exactly
    # Falls through to the trailing-bytes check, which is anchored: a lookup entry is at
    # least 34 bytes, so a non-zero count always leaves an unconsumed tail.
    ("the v0 address-table-lookup refusal", "if n_lookups:", "if False:", "diagnostic"),
    ("the trailing-bytes check", "i != len(msg)", "False", "verdict"),
    (
        # An unknown version puts the header at the wrong offset, which the anchored bounds
        # and trailing-bytes checks then catch. Only the reason is lost.
        "the message-version check",
        "versioned and (msg[0] & 0x7F) != 0",
        "False",
        "diagnostic",
    ),
    ("the account-index bound", "a >= n_keys", "False", "crash"),
    # Python slices truncate silently, so every short read yields a value that fails an
    # anchored equality downstream. This turns that luck into an explicit refusal.
    ("the truncation check", "i + n > len(b)", "False", "diagnostic"),
    # --- config is required, and must be an address
    (
        "the both-receiver-forms refusal",
        "expected_receiver_b58 and expected_receiver_ata_b58",
        "False",
        "verdict",
    ),
    (
        "the delegation-required check",
        "not expected_delegation_b58",
        "False",
        "crash",
    ),
    # A short decode fails whichever anchored positional comparison it feeds. This says so
    # at the config boundary instead, where the operator can act on it.
    ("the address-length check", "len(out) != 32", "False", "diagnostic"),
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
            + (f"  ({detail[:88]})" if detail else "")
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
                    f"found {n} occurrence(s); a stale or ambiguous anchor certifies nothing "
                    f"while passing",
                )
                continue
            MUTANT.write_text(src.replace(anchor, repl), encoding="utf-8", newline="\n")
            rc, out = run(MUTANT)
            fails = [ln for ln in out.splitlines() if ln.startswith("FAIL")]
            if effect == "verdict":
                # rc alone is not enough: a crashing mutant also exits non-zero, and "could not
                # start" would then be recorded as "the check fired".
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
                # Some checks prevent an EXCEPTION rather than a mis-certification: without them
                # the gate raises something a caller catching CertificationError would not
                # handle. Still fail-closed, and a different claim from "a case went red", so it
                # is asserted separately rather than folded in.
                check(
                    f"{label} prevents an unhandled exception",
                    rc != 0 and not fails,
                    "the mutant raised instead of certifying"
                    if rc != 0
                    else "SUITE STILL GREEN, so it prevents nothing",
                )
            else:
                check(
                    f"{label} changes the DIAGNOSTIC (an anchored check still refuses)",
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
