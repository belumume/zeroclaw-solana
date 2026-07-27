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


# AMOUNT INVARIANT, added 2026-07-27.
#
# The recipient cases above defend the address. Nothing defended the FIGURE, and the
# runtime trace showed why that mattered: at 2026-07-27T13:11:14Z the agent called the
# `calculator` tool with {"a":80,"b":5.0827,"function":"divide"} and the host refused it
# ("Missing required parameter: values (array of numbers)", duration_ms 0, output empty).
# SKILL.md instructs the model to compute `BRL / rate` itself in any case, so every
# figure this shop has quoted was model arithmetic that nothing downstream re-derived.
#
# Case 1 is that exact order, kept verbatim rather than minimised: if it stops passing,
# the guard has stopped covering the incident it was built for.
#
# (description, brl, rate, amount_in_url, must_be_accepted)
AMOUNT_CASES = [
    ("the real R$80 order the calculator failed on", "80", "5.0827", "15.74", True),
    ("the real R$45 WhatsApp order", "45", "5.0827", "8.85", True),
    ("the real R$150 Telegram order", "150", "5.0827", "29.51", True),
    ("the real R$60 order", "60", "5.0827", "11.80", True),
    ("trailing-zero form of a correct amount", "60", "5.0827", "11.8", True),
    # A model that drops a digit, transposes, or mis-rounds produces exactly these.
    ("off by a factor of ten", "80", "5.0827", "157.40", False),
    ("off by one cent", "80", "5.0827", "15.73", False),
    ("rate applied upside down", "80", "5.0827", "406.62", False),
    ("amount left at the BRL figure, unconverted", "80", "5.0827", "80", False),
    # A zero or negative rate must never reach a division.
    ("zero rate", "80", "0", "15.74", False),
    ("negative rate", "80", "-5.0827", "15.74", False),
    ("rate that is not a number", "80", "five", "15.74", False),
]


def run(url, extra=None):
    p = subprocess.run(
        [sys.executable, str(SCRIPT), url] + list(extra or []),
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

    for desc, brl, rate, amount, must_accept in AMOUNT_CASES:
        url = f"solana:{MERCHANT}?amount={amount}&spl-token={USDC_DEVNET}"
        rc, out = run(url, ["--brl", brl, "--rate", rate])
        if must_accept:
            ok = rc == 0 and PAGE_OK(out, url)
            detail = "expected a pay-page link"
        else:
            ok = rc != 0 and "REFUSED" in out
            detail = "expected a hard refusal"
        print(f"{'PASS' if ok else 'FAIL'}  amount: {desc}")
        if not ok:
            failures.append(
                f"amount/{desc}: {detail}, got rc={rc} out={out.strip()[:200]!r}"
            )

    # One flag alone verifies nothing, so it must refuse rather than silently skip the
    # check. A guard that quietly does nothing is the failure mode this whole file exists
    # to prevent.
    base = f"solana:{MERCHANT}?amount=15.74&spl-token={USDC_DEVNET}"
    for lone in (["--brl", "80"], ["--rate", "5.0827"]):
        rc, out = run(base, lone)
        ok = rc != 0 and "REFUSED" in out
        print(
            f"{'PASS' if ok else 'FAIL'}  amount: {lone[0]} alone is refused, not ignored"
        )
        if not ok:
            failures.append(
                f"{lone[0]} alone did not refuse: rc={rc} out={out.strip()[:200]!r}"
            )

    # Verification requested against a URL that carries nothing to verify.
    rc, out = run(
        f"solana:{MERCHANT}?spl-token={USDC_DEVNET}",
        ["--brl", "80", "--rate", "5.0827"],
    )
    ok = rc != 0 and "REFUSED" in out
    print(
        f"{'PASS' if ok else 'FAIL'}  amount: verification requested but URL has no amount="
    )
    if not ok:
        failures.append(
            f"missing amount= was accepted: rc={rc} out={out.strip()[:200]!r}"
        )

    # BACKWARD COMPATIBILITY. The live shop calls this script with the URL and a language
    # and nothing else. That path must be byte-identical to before the flags existed, or
    # deploying this change breaks the running shop before SKILL.md catches up.
    for extra in ([], ["pt"], ["en"]):
        rc, out = run(base, extra)
        line = out.strip().splitlines()[-1] if out.strip() else ""
        expect_lang = f"&lang={extra[0]}" if extra else ""
        ok = (
            rc == 0
            and line.startswith("https://")
            and line.endswith(expect_lang or line[-1])
        )
        if extra and not line.endswith(f"&lang={extra[0]}"):
            ok = False
        print(f"{'PASS' if ok else 'FAIL'}  no-flags compatibility: extra={extra!r}")
        if not ok:
            failures.append(
                f"compat extra={extra!r}: rc={rc} out={out.strip()[:200]!r}"
            )

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
