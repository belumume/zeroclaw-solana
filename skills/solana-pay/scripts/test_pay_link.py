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
import tempfile
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("pay_link.py")
MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
ATTACKER_FROM_REAL_INCIDENT = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
# Kept, and now a NEGATIVE control: this is the mint the agent recalled from its
# memory store on 2026-08-06 while the deployed skill said mainnet. A suite that
# only ever passes the right mint cannot tell a pinned constant from a pass-through.
USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

# (description, url, must_be_accepted)
CASES = [
    (
        "legit merchant link",
        f"solana:{MERCHANT}?amount=25&spl-token={USDC_MAINNET}",
        True,
    ),
    ("merchant, no query params", f"solana:{MERCHANT}", True),
    (
        "merchant with a reference",
        f"solana:{MERCHANT}?amount=1&reference={MERCHANT}&spl-token={USDC_MAINNET}",
        True,
    ),
    (
        "attacker wallet from the real memory-bloat incident",
        f"solana:{ATTACKER_FROM_REAL_INCIDENT}?amount=25&spl-token={USDC_DEVNET}",
        False,
    ),
    ("empty recipient", "solana:?amount=25", False),
    # THE MINT PIN, both directions. Case 1 is the 2026-08-06 incident verbatim: the
    # agent recalled this mint from three rows in its memory store while the deployed
    # skill said mainnet, and the pay page refused the link it produced. If this case
    # ever passes again, the pin has become a pass-through.
    (
        "devnet mint the agent recalled from memory on 2026-08-06",
        f"solana:{MERCHANT}?amount=8.80&spl-token={USDC_DEVNET}",
        False,
    ),
    (
        "amount with no spl-token, which Solana Pay reads as native SOL",
        f"solana:{MERCHANT}?amount=8.80",
        False,
    ),
    (
        "duplicate spl-token: this parser reads the first, the page reads the last",
        f"solana:{MERCHANT}?amount=8.80&spl-token={USDC_MAINNET}&spl-token={USDC_DEVNET}",
        False,
    ),
    # OVER-CORRECTION CONTROL. The first version of this pin refused every link without
    # a mint, which killed the legitimate flow where the customer sets the amount in
    # their own wallet and the page renders "(amount set in your wallet)". Nothing to
    # reprice means nothing to refuse. If this case ever fails, the pin over-reached
    # again in exactly the way it did the first time.
    (
        "no amount and no mint: the customer-sets-it flow, still accepted",
        f"solana:{MERCHANT}",
        True,
    ),
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
    # LABEL. Until this shipped it was the one pinned constant with nothing enforcing it, and
    # SKILL.md said so in its own words. A stale one reached a customer's approval screen on
    # 2026-08-06. The wallet renders `label` as WHO IS BEING PAID, so a wrong value misnames the
    # shop on the last screen before money moves.
    (
        "the correct label passes",
        f"solana:{MERCHANT}?amount=25&spl-token={USDC_MAINNET}&label=ZeroClaw%20Shop",
        True,
    ),
    (
        "the correct label in the + encoding also passes",
        f"solana:{MERCHANT}?amount=25&spl-token={USDC_MAINNET}&label=ZeroClaw+Shop",
        True,
    ),
    (
        "the placeholder name that reached a real customer is REFUSED",
        f"solana:{MERCHANT}?amount=25&spl-token={USDC_MAINNET}&label=Demo%20Shop",
        False,
    ),
    (
        "a plausible near-miss on the shop's own name is REFUSED",
        f"solana:{MERCHANT}?amount=25&spl-token={USDC_MAINNET}&label=ZeroClaw%20Store",
        False,
    ),
    (
        "a duplicated label is REFUSED, like a duplicated mint or amount",
        f"solana:{MERCHANT}?amount=25&spl-token={USDC_MAINNET}"
        f"&label=ZeroClaw%20Shop&label=Attacker",
        False,
    ),
    # THE OVER-CORRECTION CONTROLS. The check is deliberately split so that ABSENT is not treated
    # as WRONG: `label` is optional in the Solana Pay spec and a wallet then shows the recipient
    # address, which is less informative and is not misleading. If either of these ever starts
    # failing, the guard was widened into refusing legitimate links.
    (
        "an ABSENT label still passes, because absent is not wrong",
        f"solana:{MERCHANT}?amount=25&spl-token={USDC_MAINNET}",
        True,
    ),
    (
        "a bare merchant link with no query at all still passes",
        f"solana:{MERCHANT}",
        True,
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


# The rate is FETCHED by the script now, so the amount cases must PLANT it rather than pass it.
# Planting happens here, in a temp wrapper that patches urlopen and then exec's the real script
# unmodified. Deliberately NOT an env var or a --test flag in pay_link.py: that file's own rule
# is that anything an agent can reach is not a control, so a production test hook would be the
# exact bypass the fetch exists to remove. Nothing in pay_link.py knows this wrapper exists.
#
# It also keeps the suite OFFLINE and deterministic. Fixtures that pinned a July rate and
# compared it against a live fetch would both hit the network and rot as the rate moved.
_STUB = """
import json, re, sys, urllib.request
RATE = __RATE__
SCRIPT = __SCRIPT__

class _Resp:
    def __init__(self, text):
        self._b = text.encode("utf-8")
        self.status = 200
    def read(self):
        return self._b
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False

def _planted(req, timeout=None):
    if RATE == "FAIL":
        raise OSError("planted: source unreachable")
    url = getattr(req, "full_url", None) or str(req)
    if "olinda" in url:
        m = re.search(r"'(\\d{2})-(\\d{2})-(\\d{4})'", url)
        mm, dd, yyyy = m.groups()
        return _Resp(json.dumps({"value": [{"cotacaoVenda": RATE,
                                            "dataHoraCotacao": yyyy + "-" + mm + "-" + dd + " 13:00:00"}]}))
    m = re.search(r"/v1/(\\d{4}-\\d{2}-\\d{2})", url)
    return _Resp(json.dumps({"rates": {"BRL": RATE}, "date": m.group(1)}))

urllib.request.urlopen = _planted
sys.argv = [SCRIPT] + sys.argv[1:]
exec(compile(open(SCRIPT, encoding="utf-8").read(), SCRIPT, "exec"), {"__name__": "__main__"})
"""


def run(url, extra=None, planted_rate=None):
    """planted_rate=None runs the script untouched, so no-flag cases stay a real end-to-end run."""
    if planted_rate is None:
        cmd = [sys.executable, str(SCRIPT), url] + list(extra or [])
    else:
        _r = planted_rate if planted_rate == "FAIL" else float(planted_rate)
        body = _STUB.replace("__RATE__", repr(_r)).replace(
            "__SCRIPT__", repr(str(SCRIPT))
        )
        fh = tempfile.NamedTemporaryFile(
            "w", suffix="_ratestub.py", delete=False, encoding="utf-8"
        )
        fh.write(body)
        fh.close()
        cmd = [sys.executable, fh.name, url] + list(extra or [])
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
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

    # THE RATE IS NOW FETCHED, so these prove the new refusals actually fire. Without the
    # first case the cross-check could be refusing everything; without the rest it could be
    # refusing nothing. A supplied rate can only ever ADD a refusal: the figure used is always
    # the published one, so passing a rate cannot relax anything.
    # DUPLICATE amount=, the smuggling shape the spl-token guard already refuses. This parser
    # reads the first and the pay page reads the last, so without the guard the check verifies
    # one figure while the customer is shown another. Both orders are planted, because a guard
    # that only catches "correct first" would pass whichever way the attacker writes it.
    for desc, amt_qs, must_accept in [
        ("duplicate amount, correct one first", "amount=15.32&amount=1532", False),
        ("duplicate amount, correct one last", "amount=1532&amount=15.32", False),
        ("CONTROL single amount still accepted", "amount=15.32", True),
    ]:
        u = f"solana:{MERCHANT}?{amt_qs}&spl-token={USDC_MAINNET}"
        rc, out = run(u, ["--brl", "80"], planted_rate="5.2236")
        ok = (
            (rc == 0 and PAGE_OK(out, u))
            if must_accept
            else (rc != 0 and "REFUSED" in out)
        )
        print(f"{'PASS' if ok else 'FAIL'}  amount-dup: {desc}")
        if not ok:
            failures.append(f"amount-dup/{desc}: got rc={rc} out={out.strip()[:160]!r}")

    URL_80 = f"solana:{MERCHANT}?amount=15.74&spl-token={USDC_MAINNET}"
    for desc, extra, planted, must_accept in [
        (
            "CONTROL a supplied rate that agrees is accepted",
            ["--brl", "80", "--rate", "5.0827"],
            "5.0827",
            True,
        ),
        (
            "a supplied rate 2.7% stale is refused (the July rate against today's)",
            ["--brl", "80", "--rate", "5.0827"],
            "5.2236",
            False,
        ),
        (
            "a wildly wrong supplied rate is refused",
            ["--brl", "80", "--rate", "1.0"],
            "5.0827",
            False,
        ),
        (
            "CONTROL --brl alone, no rate supplied, is the primary form and is accepted",
            ["--brl", "80"],
            "5.0827",
            True,
        ),
        (
            "--rate without --brl is refused: no order value to price",
            ["--rate", "5.0827"],
            "5.0827",
            False,
        ),
        (
            "a published rate outside the plausible band is refused",
            ["--brl", "80"],
            "30.50",
            False,
        ),
        (
            "an unreachable rate source refuses rather than pricing the order",
            ["--brl", "80"],
            "FAIL",
            False,
        ),
        # THE DOCUMENTED ATTACK SHAPE, verbatim from the note in pay_link.py that said it passed
        # every check. The rate had a plausibility band and the figure a customer pays had none.
        (
            "the documented sub-currency-unit order value is refused",
            ["--brl", "0.05"],
            "5.0827",
            False,
        ),
        (
            "just below the floor is refused",
            ["--brl", "0.99"],
            "5.0827",
            False,
        ),
        (
            "an order orders of magnitude above the ceiling is refused",
            ["--brl", "50001"],
            "5.0827",
            False,
        ),
        # The in-band CONTROL is the "--brl alone is the primary form and is accepted" case above,
        # at R$ 80. Without it these three would be satisfied by a band that refuses everything.
    ]:
        rc, out = run(URL_80, extra, planted_rate=planted)
        ok = (
            (rc == 0 and PAGE_OK(out, URL_80))
            if must_accept
            else (rc != 0 and "REFUSED" in out)
        )
        print(f"{'PASS' if ok else 'FAIL'}  rate: {desc}")
        if not ok:
            failures.append(f"rate/{desc}: got rc={rc} out={out.strip()[:160]!r}")

    for desc, brl, rate, amount, must_accept in AMOUNT_CASES:
        url = f"solana:{MERCHANT}?amount={amount}&spl-token={USDC_MAINNET}"
        # Each case keeps the intent it was written with, under the new contract.
        # A VALID rate is now the PUBLISHED one: plant it and do not pass it, so the case
        # still tests the division and nothing else. A zero, negative or non-numeric rate
        # can no longer reach a division at all, so those cases move to testing the
        # cross-check: they are passed as `--rate` against a sane planted rate and must
        # refuse. Same fixtures, same failure they were written to catch.
        try:
            usable = float(rate) > 0
        except ValueError:
            usable = False
        if usable:
            rc, out = run(url, ["--brl", brl], planted_rate=rate)
        else:
            rc, out = run(url, ["--brl", brl, "--rate", rate], planted_rate="5.0827")
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
    base = f"solana:{MERCHANT}?amount=15.74&spl-token={USDC_MAINNET}"
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
        f"solana:{MERCHANT}?spl-token={USDC_MAINNET}",
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
    """An accepted run must emit a page link whose payload round-trips to the input.

    FINDS the link line rather than assuming it is the last one. The script also prints the
    rate's provenance to stderr so an operator can see which published figure priced the
    order, and this helper reads stdout and stderr combined, so position is not a contract.
    """
    line = next((ln for ln in out.splitlines() if "?u=" in ln), "")
    if not line:
        return False
    payload = line.strip().split("?u=", 1)[1]
    try:
        return base64.urlsafe_b64decode(payload).decode() == url
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main())
