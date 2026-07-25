#!/usr/bin/env python3
"""Regression tests for the pay-link recipient invariant.

Run: python3 test_pay_link.py     (stdlib only, no network, no deps)

WHAT THIS DEFENDS
-----------------
`pay_link.py` is the last thing that runs before a customer is shown an address and
asked for money. Before this check existed, the merchant address lived only in prose:
SKILL.md instructed the agent to use it, and conceded in the same sentence that "the
enforced versions live in the plugins" -- for the recipient there was no enforced
version anywhere in the path. The pay page does not re-derive it either; it regexes the
recipient out of the URL and transfers to whatever it finds.

The failure is not theoretical, and it is not primarily an injection story. It fired
once with NO ATTACKER PRESENT: stale rows in the agent's memory store caused it to
recall a different wallet and emit a link paying that address (BUILD-JOURNAL
2026-07-24). ATTACKER_FROM_REAL_INCIDENT below is that wallet.

The reason this class is worth a dedicated test is that it routes around every custody
control in the project rather than defeating any of them. No key is touched, nothing is
signed, no approval prompt fires, and the money that moves belongs to the customer, so
neither the on-chain allowance cap nor the approval gate nor the T0/T1 tiering is even
on the path. An invariant enforced in code is the only thing that closes it.
"""

import base64
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("pay_link.py")
MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
ATTACKER_FROM_REAL_INCIDENT = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

# (description, url, must_be_accepted)
CASES = [
    (
        "legit merchant link",
        f"solana:{MERCHANT}?amount=25&spl-token={USDC_DEVNET}",
        True,
    ),
    ("merchant, no query params", f"solana:{MERCHANT}", True),
    (
        "merchant with a reference",
        f"solana:{MERCHANT}?amount=1&reference={MERCHANT}",
        True,
    ),
    (
        "attacker wallet from the real memory-bloat incident",
        f"solana:{ATTACKER_FROM_REAL_INCIDENT}?amount=25&spl-token={USDC_DEVNET}",
        False,
    ),
    ("empty recipient", "solana:?amount=25", False),
    (
        "merchant smuggled into a query param, attacker in the recipient slot",
        f"solana:{ATTACKER_FROM_REAL_INCIDENT}?reference={MERCHANT}",
        False,
    ),
    (
        "lookalike address differing in the final character",
        f"solana:{MERCHANT[:-1]}K?amount=25",
        False,
    ),
    (
        "merchant address with trailing whitespace padding",
        f"solana:{MERCHANT}x?amount=25",
        False,
    ),
]


def run(url):
    p = subprocess.run(
        [sys.executable, str(SCRIPT), url],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    failures = []
    for desc, url, must_accept in CASES:
        rc, out = run(url)
        if must_accept:
            ok = rc == 0 and PAGE_OK(out, url)
            detail = "expected a pay-page link"
        else:
            ok = rc != 0 and "REFUSED" in out
            detail = "expected a hard refusal"
        print(f"{'PASS' if ok else 'FAIL'}  {desc}")
        if not ok:
            failures.append(f"{desc}: {detail}, got rc={rc} out={out.strip()[:200]!r}")

    # usage errors must also fail closed, not fall through to a link
    for bad in ["", "https://example.com/", "solana", "not-a-url"]:
        rc, out = run(bad)
        ok = rc != 0
        print(f"{'PASS' if ok else 'FAIL'}  non-solana input rejected: {bad!r}")
        if not ok:
            failures.append(f"non-solana input {bad!r} was accepted")

    print()
    if failures:
        print(f"{len(failures)} FAILURE(S):")
        for f in failures:
            print("  -", f)
        return 1
    print("all pay-link recipient invariants hold")
    return 0


def PAGE_OK(out, url):
    """An accepted run must emit a page link whose payload round-trips to the input."""
    line = out.strip().splitlines()[-1] if out.strip() else ""
    if "?u=" not in line:
        return False
    payload = line.split("?u=", 1)[1]
    try:
        return base64.urlsafe_b64decode(payload).decode() == url
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main())
