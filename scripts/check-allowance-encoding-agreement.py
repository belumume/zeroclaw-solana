#!/usr/bin/env python3
"""Bind the two copies of the SF Allowances transfer encoding.

`plugins/x402-pay-build/src/build.rs` duplicates the instruction encoding that
`plugins/allowance-spend-build/src/allowance.rs` already implements. The duplication is deliberate:
no plugin in this repo path-depends on another, each carries its own workspace, and upstream CI
iterates the plugin manifests expecting standalone crates. What duplication costs is that the two
copies can drift silently, and a money-path encoding that drifts produces a transaction the audited
program rejects at best and misroutes at worst.

So the copies are BOUND rather than merely documented as duplicates. This gate reads the values out
of the ORIGINAL's source by regex and requires the duplicate to agree. It deliberately restates
neither: a checker carrying its own copy of the constants is a third copy, and then there are three
things to keep in step instead of two.

Exit 0 they agree, 1 they differ, 2 could not check. A could-not-check is NOT a pass, because a
regex that stops matching after a refactor would otherwise report agreement over nothing.

Controls, since a checker that has only ever agreed has not been shown to disagree:
  --selftest   perturbs each bound value in a copy of the duplicate and requires a complaint
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORIGINAL = ROOT / "plugins/allowance-spend-build/src/allowance.rs"
DUPLICATE = ROOT / "plugins/x402-pay-build/src/build.rs"

# (label, name, value pattern). Each captures ONE group: the value.
#
# Neither side's expected VALUE appears here, which is what keeps this from becoming a third copy
# of the constants and a third thing to keep in step.
#
# Every pattern is anchored to a DECLARATION with `(?m)^(?:pub )?const`, because the original
# documents several of these constants in a doc comment that quotes the declaration verbatim. An
# unanchored pattern matches the prose as well and the gate reports two hits where it wanted one,
# which is a could-not-check rather than a finding. Read declarations, not prose.
BOUND = [
    (
        "subscriptions program id",
        "SUBSCRIPTIONS_PROGRAM_ID",
        r'&str\s*=\s*"([1-9A-HJ-NP-Za-km-z]+)"',
    ),
    ("transferFixed discriminator", "IX_TRANSFER_FIXED", r"u8\s*=\s*(\d+)"),
    ("event-authority seed", "EVENT_AUTHORITY_SEED", r'&\[u8\]\s*=\s*b"([^"]+)"'),
    ("transfer payload length", "TRANSFER_DATA_LEN", r"usize\s*=\s*([0-9 +]+?);"),
]


def declaration(name: str, value: str) -> str:
    """A pattern that matches the CONST DECLARATION of `name` and nothing that merely quotes it."""
    return rf"(?m)^(?:pub )?const {name}:\s*{value}"


# The account order is the other half of the encoding and is not a constant, so it is bound by
# extracting the AccountMeta sequence from each builder and comparing the shapes.
# The account expression can be a field (`r.delegation`) OR a CALL (`event_authority()`), and an
# identifier-only character class silently skips the calls. It read 7 of 9 accounts and reported
# agreement, which is a gate agreeing over a partial read. MIN_ACCOUNTS below is the floor that
# turns a future under-read into a failure instead of a quieter pass.
META = re.compile(
    r"AccountMeta::(writable|readonly)\(\s*([A-Za-z0-9_.()]+)\s*,\s*(true|false)\s*\)"
)
MIN_ACCOUNTS = 9
# Field names differ between the two structs by design (`v.agent` against `r.agent`), so the
# comparison is on WRITABILITY, SIGNER-NESS and POSITION, which is what the program checks.
ORIGINAL_FN = "pub fn transfer_delegation_ix"
DUPLICATE_FN = "pub fn transfer_fixed_ix"


def one(pattern: str, text: str, what: str) -> str | None:
    hits = re.findall(pattern, text)
    if len(hits) != 1:
        print(f"CANNOT CHECK  {what}: matched {len(hits)} time(s), expected exactly 1")
        return None
    return hits[0].strip() if isinstance(hits[0], str) else hits[0]


def account_shape(text: str, fn_header: str, what: str) -> list[tuple[str, str]] | None:
    start = text.find(fn_header)
    if start < 0:
        print(f"CANNOT CHECK  {what}: {fn_header!r} not found")
        return None
    body = text[start : text.find("\n}", start)]
    shape = [(m.group(1), m.group(3)) for m in META.finditer(body)]
    if len(shape) < MIN_ACCOUNTS:
        print(
            f"CANNOT CHECK  {what}: read {len(shape)} AccountMeta entries in {fn_header!r}, "
            f"expected at least {MIN_ACCOUNTS}. A partial read would compare a prefix and call "
            f"it agreement."
        )
        return None
    return shape


def compare(dup_text: str | None = None) -> int:
    if not ORIGINAL.is_file() or not DUPLICATE.is_file():
        print(
            f"CANNOT CHECK  one of the two files is missing:\n  {ORIGINAL}\n  {DUPLICATE}"
        )
        return 2
    orig = ORIGINAL.read_text(encoding="utf-8")
    dup = dup_text if dup_text is not None else DUPLICATE.read_text(encoding="utf-8")

    unreadable, differ = [], []
    for label, name, value in BOUND:
        pat = declaration(name, value)
        o = one(pat, orig, f"{label} in the original")
        d = one(pat, dup, f"{label} in the duplicate")
        if o is None or d is None:
            unreadable.append(label)
        elif o != d:
            differ.append(f"{label}: original {o!r}, duplicate {d!r}")

    o_shape = account_shape(orig, ORIGINAL_FN, "the original's account list")
    d_shape = account_shape(dup, DUPLICATE_FN, "the duplicate's account list")
    if o_shape is None or d_shape is None:
        unreadable.append("account list")
    elif o_shape != d_shape:
        differ.append(
            f"account list: {len(o_shape)} vs {len(d_shape)} entries, or the writable/signer "
            f"pattern differs\n    original  {o_shape}\n    duplicate {d_shape}"
        )

    if unreadable:
        print(
            f"\nFAIL  {len(unreadable)} value(s) could not be read, which is not a pass:"
        )
        for u in unreadable:
            print(f"        {u}")
        print("      A pattern that stopped matching reports agreement over nothing.")
        return 2
    if differ:
        print(
            f"\nFAIL  the two copies of the encoding disagree on {len(differ)} value(s):"
        )
        for d in differ:
            print(f"        {d}")
        print(
            "\n      They are duplicated on purpose (no plugin here depends on another), so the\n"
            "      duplicate must be corrected to match the original rather than the reverse."
        )
        return 1

    print(
        f"checked {len(BOUND)} bound constant(s) and the {len(o_shape or [])}-account instruction "
        f"layout, read from both sources"
    )
    print("\nOK  the two copies of the allowances transfer encoding agree.")
    return 0


def selftest() -> int:
    """Perturb each bound value in a COPY and require a complaint. Nothing on disk is touched."""
    dup = DUPLICATE.read_text(encoding="utf-8")
    cases = [
        ("the program id", "IX_TRANSFER_FIXED: u8 = 4", "IX_TRANSFER_FIXED: u8 = 5"),
        ("the event-authority seed", 'b"event_authority"', 'b"event_authorityX"'),
        (
            "the payload length",
            "TRANSFER_DATA_LEN: usize = 8 + 32 + 32",
            "TRANSFER_DATA_LEN: usize = 8 + 32 + 33",
        ),
        (
            "a writable flag",
            "AccountMeta::writable(r.delegation, false)",
            "AccountMeta::readonly(r.delegation, false)",
        ),
        (
            "the signer flag",
            "AccountMeta::readonly(r.agent, true)",
            "AccountMeta::readonly(r.agent, false)",
        ),
        (
            "an account being dropped",
            "            AccountMeta::readonly(event_authority(), false),\n",
            "",
        ),
    ]
    passed = failed = 0

    rc = compare(dup)
    ok = rc == 0
    print(
        f"{'PASS' if ok else 'FAIL'}  the UNPERTURBED duplicate agrees, so the check can say yes"
    )
    passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

    for label, old, new in cases:
        if dup.count(old) != 1:
            print(
                f"FAIL  perturbing {label}: anchor matched {dup.count(old)} time(s), not 1"
            )
            failed += 1
            continue
        rc = compare(dup.replace(old, new, 1))
        ok = rc != 0
        print(f"{'PASS' if ok else 'FAIL'}  perturbing {label} is caught (rc={rc})")
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

    # The file on disk must be untouched: a control that edits the thing it checks is a hazard.
    assert DUPLICATE.read_text(encoding="utf-8") == dup, (
        "the duplicate was modified on disk"
    )
    print(f"\nRESULT: {passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else compare())
