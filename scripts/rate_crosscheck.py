#!/usr/bin/env python3
"""BRL/USD for the pay path, from a named central bank, corroborated by an independent source.

WHY THIS EXISTS. The shop quotes an order in reais and settles in USDC. Until now the exchange
rate was supplied by the model in its prompt, which is a model-chosen number on a money path:
the same defect class as an agent talked into moving funds, and the one the custody argument
exists to exclude.

WHY NOT AN ON-CHAIN ORACLE. Researched 2026-08-15: there is no readable, persistently-updated
BRL/USD account on Solana mainnet. Pyth publishes an FX.USD/BRL feed id but its Solana push-feed
set is entirely crypto, so reading it means creating and funding the account, and after
2026-07-31 its API requires a paid plan. Switchboard On-Demand is pay-per-read by architecture,
with no persistent account to read for free. Chainlink on Solana carries crypto pairs only.
Publishing our own feed needs the mainnet program deployment that is deliberately not being
bought. So the honest claim this script supports is "a rate from a named central-bank
publication, cross-checked against an independent source, re-derivable by any third party" and
NOT "an on-chain oracle". Do not let a later edit upgrade that sentence.

THE DESIGN, mirroring payment-watch's corroboration rather than inventing a new shape. PTAX is
the SOURCE OF TRUTH: it is Brazil's central bank, and it is the rate Brazilian invoices are
legally referenced against. Frankfurter/ECB is a CORROBORATOR with no authority to set the
price; its only power is to REFUSE by disagreeing. One source of truth, one independent check.

FAIL CLOSED, EVERYWHERE, and note which of these an attacker can induce cheaply. No rate
published for the day (weekends and holidays return an EMPTY value list, confirmed live), the
two sources disagreeing beyond the band, them reporting different dates, a rate outside the
plausibility band, a hostile response shape, an unreachable endpoint: every one refuses. There
is deliberately NO fallback to a last-known or caller-supplied rate, because a fallback restores
the hole under exactly the conditions an attacker can induce, and inducing a fetch failure is
cheaper than forging anything.

NO DATE ARGUMENT, BY DESIGN. A caller who picks the date picks the rate. The script takes the
most recent published business day, walking back at most MAX_WALKBACK_DAYS, and refuses rather
than reaching further. Same reasoning as the sibling's deleted `--rpc`: anything an agent can
reach (argv, env, config, memory) is not a control, and this runs at the last point before a
customer is asked for money.

WHAT THIS DOES NOT CLOSE, stated because a partial fix presented as a whole one is worse than
none. The order VALUE stays model-supplied. pay_link.py now refuses an implausible one, so
"Table 4, R$ 0.05" no longer produces a link, but a PLAUSIBLE wrong amount still does. This
removes one free parameter of two and narrows the second. Closing it needs a price source the
model cannot author: a priced SKU table, an order id resolved against a store, or a merchant
confirmation certifying the serialized bytes rather than a sentence.

EXIT CODES, matching verify-proof.py, feed_heartbeat.py and rate_from_feed.py:
  0  a corroborated rate was read and printed
  1  REFUSED: a real finding. Never retry; the answer will not change.
  2  COULD NOT CHECK: transport failed. Retrying is reasonable.

Usage:  python3 scripts/rate_crosscheck.py
        python3 scripts/rate_crosscheck.py --selftest
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
import urllib.error
import urllib.request
from typing import NoReturn

PTAX_URL = (
    "https://olinda.bcb.gov.br/olinda/servico/PTAX/versao/v1/odata/"
    "CotacaoDolarDia(dataCotacao=@dataCotacao)?@dataCotacao='{mmddyyyy}'&$format=json"
)
ECB_URL = "https://api.frankfurter.dev/v1/{date}?base=USD&symbols=BRL"

UA = {
    "User-Agent": "zeroclaw-solana rate-crosscheck (+https://github.com/belumume/zeroclaw-solana)"
}
TIMEOUT_S = 20

# A weekend plus one public holiday is 3 days; 4 gives one day of slack. Reaching further would
# mean quoting today's order at a rate from the week before, which is a real finding, not a
# transport hiccup, so it refuses rather than walking on.
MAX_WALKBACK_DAYS = 4

# Divergence band. Its job is catching a BROKEN or WRONG-CURRENCY read, not calibrating the
# normal spread between a central-bank ask and an ECB reference midpoint. One live observation
# (2026-08-14: PTAX venda 5.2236 vs ECB 5.1762) put that spread at 0.91%; this is one sample and
# is deliberately NOT presented as a distribution. 2.5% leaves room for a wider day while still
# rejecting anything structurally wrong.
MAX_DIVERGENCE = 0.025

# Absolute plausibility. BRL/USD has not been outside this in decades. It exists because the
# sibling script's controls proved a value can be perfectly well-formed, correctly signed, fresh
# and still be a THERMOMETER reading of 30.50 degrees. A band alone did not catch that there;
# here the currency is named by the endpoint, and this catches the gross case regardless.
MIN_PLAUSIBLE, MAX_PLAUSIBLE = 3.0, 10.0


def refuse(msg: str) -> NoReturn:
    print(f"REFUSED: {msg}", file=sys.stderr)
    sys.exit(1)


def cannot_check(msg: str) -> NoReturn:
    print(f"COULD NOT CHECK: {msg}", file=sys.stderr)
    sys.exit(2)


# --------------------------------------------------------------------------- pure, so the
# guards below are all reachable from --selftest with no network at all.


def parse_ptax(payload: object) -> tuple[float, str] | None:
    """(sell_rate, 'YYYY-MM-DD') for a published day, or None when the day has no publication.

    Returns None rather than raising for the empty case, because an empty list is the NORMAL
    weekend answer and the caller walks back. Every other malformed shape raises ValueError:
    a hostile or changed endpoint controls this whole structure.
    """
    if not isinstance(payload, dict):
        raise ValueError("PTAX payload is not an object")
    rows = payload.get("value")
    if not isinstance(rows, list):
        raise ValueError("PTAX 'value' is not a list")
    if not rows:
        return None
    row = rows[0]
    if not isinstance(row, dict):
        raise ValueError("PTAX row is not an object")
    rate = row.get("cotacaoVenda")
    if isinstance(rate, bool) or not isinstance(rate, (int, float)):
        raise ValueError("PTAX cotacaoVenda is not a number")
    stamp = row.get("dataHoraCotacao")
    if not isinstance(stamp, str) or len(stamp) < 10:
        raise ValueError("PTAX dataHoraCotacao is not a timestamp")
    return float(rate), stamp[:10]


def parse_ecb(payload: object) -> tuple[float, str]:
    if not isinstance(payload, dict):
        raise ValueError("ECB payload is not an object")
    rates = payload.get("rates")
    if not isinstance(rates, dict):
        raise ValueError("ECB 'rates' is not an object")
    rate = rates.get("BRL")
    if isinstance(rate, bool) or not isinstance(rate, (int, float)):
        raise ValueError("ECB BRL rate is not a number")
    date = payload.get("date")
    if not isinstance(date, str) or len(date) != 10:
        raise ValueError("ECB 'date' is not a date")
    return float(rate), date


def divergence(a: float, b: float) -> float:
    """Symmetric relative difference, so neither source is privileged by the arithmetic."""
    mean = (a + b) / 2.0
    if mean <= 0:
        raise ValueError("non-positive mean rate")
    return abs(a - b) / mean


def adjudicate(
    ptax: tuple[float, str],
    ecb: tuple[float, str],
    max_div: float = MAX_DIVERGENCE,
) -> tuple[bool, str]:
    """(ok, reason). PTAX sets the price; ECB may only refuse by disagreeing."""
    p_rate, p_date = ptax
    e_rate, e_date = ecb
    if p_date != e_date:
        return False, (
            f"sources report different dates (PTAX {p_date}, ECB {e_date}); "
            "comparing rates across days is not a corroboration"
        )
    if not (MIN_PLAUSIBLE <= p_rate <= MAX_PLAUSIBLE):
        return (
            False,
            f"PTAX rate {p_rate} outside plausible BRL/USD band [{MIN_PLAUSIBLE}, {MAX_PLAUSIBLE}]",
        )
    if not (MIN_PLAUSIBLE <= e_rate <= MAX_PLAUSIBLE):
        return (
            False,
            f"ECB rate {e_rate} outside plausible BRL/USD band [{MIN_PLAUSIBLE}, {MAX_PLAUSIBLE}]",
        )
    div = divergence(p_rate, e_rate)
    if div > max_div:
        return False, (
            f"sources diverge {div * 100:.2f}% (PTAX {p_rate}, ECB {e_rate}), "
            f"over the {max_div * 100:.2f}% band"
        )
    return True, f"corroborated within {div * 100:.2f}%"


# --------------------------------------------------------------------------- network


def _get_json(url: str) -> object:
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, headers=UA), timeout=TIMEOUT_S
        ) as r:
            if r.status != 200:
                raise urllib.error.URLError(f"HTTP {r.status}")
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        cannot_check(f"{url.split('/')[2]}: {type(exc).__name__}: {exc}")


def latest_ptax(today: _dt.date) -> tuple[float, str]:
    for back in range(MAX_WALKBACK_DAYS + 1):
        day = today - _dt.timedelta(days=back)
        payload = _get_json(PTAX_URL.format(mmddyyyy=day.strftime("%m-%d-%Y")))
        try:
            got = parse_ptax(payload)
        except ValueError as exc:
            refuse(f"PTAX response malformed for {day}: {exc}")
        if got is not None:
            return got
    refuse(
        f"PTAX published no rate in the last {MAX_WALKBACK_DAYS + 1} days ending {today}; "
        "refusing rather than quoting an older rate"
    )


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--selftest":
        return selftest()
    if argv:
        print("usage: rate_crosscheck.py [--selftest]", file=sys.stderr)
        return 2

    ptax = latest_ptax(_dt.date.today())
    payload = _get_json(ECB_URL.format(date=ptax[1]))
    try:
        ecb = parse_ecb(payload)
    except ValueError as exc:
        refuse(f"ECB response malformed: {exc}")

    ok, reason = adjudicate(ptax, ecb)
    if not ok:
        refuse(reason)
    print(f"{ptax[0]:.4f}")
    print(
        f"BRL per USD {ptax[0]:.4f} on {ptax[1]} (BCB PTAX venda, {reason}; "
        f"ECB via Frankfurter {ecb[0]:.4f})",
        file=sys.stderr,
    )
    return 0


# --------------------------------------------------------------------------- selftest


def selftest() -> int:
    cases: list[tuple[str, bool]] = []

    def check(name: str, got: object, want: object) -> None:
        cases.append((name, got == want))

    # THE REAL-WORLD CONTROL: the exact values measured live on 2026-08-14. If this ever fails,
    # the band has been tightened past reality and the script will refuse every honest day.
    check(
        "1  live 2026-08-14 values are ACCEPTED",
        adjudicate((5.2236, "2026-08-14"), (5.1762, "2026-08-14"))[0],
        True,
    )
    # BAND IS LOAD-BEARING: same real values, band at zero, must now refuse. Without this the
    # acceptance above could be passing because nothing is being compared at all.
    check(
        "2  control: band=0 refuses the same real values",
        adjudicate((5.2236, "2026-08-14"), (5.1762, "2026-08-14"), max_div=0.0)[0],
        False,
    )
    check(
        "3  gross divergence refused",
        adjudicate((5.22, "2026-08-14"), (4.10, "2026-08-14"))[0],
        False,
    )
    check(
        "4  a THERMOMETER (30.50) refused by the plausibility band",
        adjudicate((30.50, "2026-08-14"), (30.50, "2026-08-14"))[0],
        False,
    )
    check(
        "5  different dates refused even when the rates agree",
        adjudicate((5.2236, "2026-08-14"), (5.2236, "2026-08-13"))[0],
        False,
    )
    check(
        "6  identical rates on one date accepted",
        adjudicate((5.20, "2026-08-14"), (5.20, "2026-08-14"))[0],
        True,
    )
    # The weekend case must be None (walk back), NOT an exception and NOT a zero.
    check(
        "7  empty PTAX day yields None so the caller walks back",
        parse_ptax({"value": []}),
        None,
    )
    check(
        "8  a published PTAX day parses",
        parse_ptax(
            {
                "value": [
                    {
                        "cotacaoCompra": 5.223,
                        "cotacaoVenda": 5.2236,
                        "dataHoraCotacao": "2026-08-14 13:10:22.94166",
                    }
                ]
            }
        ),
        (5.2236, "2026-08-14"),
    )

    def raises(fn) -> bool:
        try:
            fn()
        except ValueError:
            return True
        except Exception:
            return False
        return False

    check(
        "9  PTAX value not a list raises",
        raises(lambda: parse_ptax({"value": "5.22"})),
        True,
    )
    check(
        "10 PTAX rate as string raises",
        raises(
            lambda: parse_ptax(
                {"value": [{"cotacaoVenda": "5.22", "dataHoraCotacao": "2026-08-14 x"}]}
            )
        ),
        True,
    )
    # bool is a subclass of int in Python; True must not sail through as a rate of 1.0.
    check(
        "11 PTAX rate as bool raises",
        raises(
            lambda: parse_ptax(
                {"value": [{"cotacaoVenda": True, "dataHoraCotacao": "2026-08-14 x"}]}
            )
        ),
        True,
    )
    check(
        "12 PTAX payload not an object raises",
        raises(lambda: parse_ptax(["nope"])),
        True,
    )
    check(
        "13 ECB rates missing raises",
        raises(lambda: parse_ecb({"date": "2026-08-14"})),
        True,
    )
    check(
        "14 ECB date missing raises",
        raises(lambda: parse_ecb({"rates": {"BRL": 5.1}})),
        True,
    )
    check(
        "15 ECB well-formed parses",
        parse_ecb({"rates": {"BRL": 5.1762}, "date": "2026-08-14"}),
        (5.1762, "2026-08-14"),
    )
    check(
        "16 divergence is symmetric",
        round(divergence(5.2236, 5.1762), 12),
        round(divergence(5.1762, 5.2236), 12),
    )

    failed = [n for n, ok in cases if not ok]
    for name, ok in cases:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if failed:
        print(f"\n{len(failed)}/{len(cases)} selftest case(s) FAILED.", file=sys.stderr)
        return 1
    print(f"\n{len(cases)}/{len(cases)} pass")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
