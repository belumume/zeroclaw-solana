#!/usr/bin/env python3
"""Turn a Solana Pay `solana:` URL into a TAPPABLE https pay-page link.

The shop's chat channels (Telegram, WhatsApp) are text-only: they cannot send
an image, and a raw `solana:` URI is not clickable in a chat message. This wraps
the request in a hosted pay page whose https link IS auto-linked and tappable in
any chat. Tapping it opens a page that renders a scannable QR, an "open wallet"
button (Phantom/Solflare), and the amount, so a customer can actually pay.

Usage: python3 tools/pay_link.py '<solana:...url...>' [lang] [--brl V --rate R]
Prints one line: the https pay-page link to send the customer.

`--brl` and `--rate` are optional and, when both are given, make this script
RE-DERIVE the amount rather than trust the one in the URL. See the AMOUNT block
below for why that is not redundant with the recipient check above it.

`lang` is optional and is `pt` when the customer is being served in Portuguese.
Without it the page falls back to the BROWSER's language, which is why a customer
quoted in Portuguese could still land on an English checkout: the page's own
translation was complete, the link simply never said which language to use. That
break of character lands on the one screen where someone decides whether to trust
a payment page.

It is whitelisted to exactly two values rather than passed through, because this
string is appended to a URL a customer is about to click. Only chrome is
translated; the recipient, amount and asset never pass through the language layer.
"""

import base64
import datetime as _dt
import json
import re
import sys
import urllib.request
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from urllib.parse import unquote_plus

PAGE = "https://zeroclaw-shop-pay.pages.dev/"

# The merchant address is a FIXED CONSTANT of this shop. It is hardcoded here, and
# deliberately not read from argv, env, config or agent memory, because every one of
# those is reachable by the agent and this script is the last point in the pay path
# that runs before a customer is asked for money.
#
# Why this check exists at all: the recipient used to live only in prose. SKILL.md
# told the agent to use this address and conceded in the same breath that "the
# enforced versions live in the plugins" -- for the recipient there was no enforced
# version anywhere. Nothing downstream re-derived it either: the pay page regexes the
# recipient out of the URL and transfers to whatever it finds, showing the customer
# only a truncated form.
#
# That gap is not hypothetical. It already fired ONCE WITH NO ATTACKER PRESENT: stale
# rows in the agent's memory store caused it to recall a different wallet and emit a
# link paying that address instead (BUILD-JOURNAL 2026-07-24). An attacker who can get
# text in front of this agent plants the same thing deliberately, and it is invisible
# to every custody control the project has, because no key is touched, no transaction
# is signed, and no approval prompt fires. The funds that move are the customer's.
MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"

# The MINT is pinned for exactly the reasons the merchant above is pinned, and it is
# here because the guard above was written for one field while its sibling was left a
# pass-through. Substitute "mint" into the paragraph above and every clause still holds:
# it is a fixed constant of this shop, argv and memory are both reachable by the agent,
# and this is the last code that runs before a customer is asked for money.
#
# The recipient incident repeated itself on the mint on 2026-08-06, again with no
# attacker. The pay page had moved to mainnet, the deployed SKILL.md was corrected to
# match, and the agent KEPT emitting devnet links: three rows in its memory store held
# the devnet mint, written by the skill's own instruction to record {reference, amount,
# mint, customer} after every order. Eleven days of accumulated memory outvoted the
# file. Correcting the memory clears today's rows and nothing more, because the next
# order writes a new one; the constant has to stop being an input.
#
# ABSENT is refused too, not just MISMATCHED, and that is the deny-by-default choice
# rather than an oversight. Solana Pay reads a missing `spl-token` as native SOL, so a
# dropped parameter turns "8.80 USDC" into 8.80 SOL, which at current prices is a
# roughly seventy-fold overcharge to a real customer. A SOL path, if this shop ever
# wants one, needs an explicit flag that says so.
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

# The LABEL is the third constant of this shop, and SKILL.md pins the same value. Kept here as
# well rather than imported, for the reason the other two are here: this script runs inside the
# channel's workspace jail and cannot reach repo root, so a shared constant is not available to
# it. `scripts/check-pay-link-rate-agreement.py` is the pattern for binding a duplicated constant
# by reading the other copy's SOURCE rather than restating it.
LABEL = "ZeroClaw Shop"

# ---------------------------------------------------------------- THE EXCHANGE RATE
# The rate is FETCHED HERE, for the same reason the merchant and the mint are pinned here:
# every other source is reachable by the agent, and this is the last code that runs before a
# customer is asked for money. It used to arrive on argv from the model, which made the
# arithmetic checkable and the INPUT unverifiable -- a consistent lie passed every guard.
#
# BCB PTAX is the source of truth: Brazil's central bank, and the rate Brazilian invoices are
# legally referenced against. ECB via Frankfurter is a CORROBORATOR with no authority to set
# the price and only the power to refuse by disagreeing. Both are keyless. Measured 2026-08-14:
# the two sit 0.91% apart on the same day, which is why one alone is not enough.
#
# THESE CONSTANTS ARE DUPLICATED FROM scripts/rate_crosscheck.py ON PURPOSE and must not drift.
# The deploy map copies only this file into the agent workspace (deploy/deploy-targets.json),
# so importing the original is impossible on the box. `scripts/check-pay-link-rate-agreement.py`
# reads the original's values out of its SOURCE and fails if these disagree.
PTAX_URL = (
    "https://olinda.bcb.gov.br/olinda/servico/PTAX/versao/v1/odata/"
    "CotacaoDolarDia(dataCotacao=@dataCotacao)?@dataCotacao='{mmddyyyy}'&$format=json"
)
ECB_URL = "https://api.frankfurter.dev/v1/{date}?base=USD&symbols=BRL"
MAX_WALKBACK_DAYS = 4
MAX_DIVERGENCE = 0.025
MIN_PLAUSIBLE, MAX_PLAUSIBLE = 3.0, 10.0

# THE ORDER VALUE GETS A BAND TOO, for the same reason the rate has one, and the asymmetry is
# what makes the case: this file already refuses an implausible EXCHANGE RATE in code, while the
# figure a customer actually pays had no bound at all. "Table 4, R$ 0.05" is the documented attack
# shape and it passed everything.
#
# The bounds are deliberately WIDE and product-neutral. This shop has no catalog, so no narrow
# figure could be justified without inventing one, and a band that assumes a menu would refuse
# legitimate orders at a shop that sells something else. What a wide band does remove is the class
# of value no merchant transaction has: a sub-currency-unit total, and a fat-finger that is orders
# of magnitude out.
#
# WHAT THE BAND ALONE DOES NOT DO: R$ 25 for a R$ 60 order sits inside it. The band removes a
# class of absurd value; the SOURCE of the value is what the block below addresses.
MIN_ORDER_BRL, MAX_ORDER_BRL = Decimal("1.00"), Decimal("50000.00")
FETCH_TIMEOUT_S = 20

# ------------------------------------------------------------- THE ORDER VALUE'S SOURCE
# Every other constant on this path was moved from ASSERTED to DERIVED. The recipient, the mint
# and the label are pinned against a value the agent cannot reach. The exchange rate is fetched
# from BCB and corroborated by the ECB, because verifying the caller's arithmetic against the
# caller's own rate caught arithmetic error and not intent error: a consistent lie passed
# everything. The order value is the last field still asserted, and it is the one a customer pays.
#
# SKILL.md already states the invariant in words: "the order value comes from the operator or the
# customer, never from you." A responsibility assigned in prose to a model is not a constraint on
# it. That sentence is the whole argument this shop is built on, so it is enforced here instead.
#
# `--quote` carries the verbatim text the figure came from, and `--brl` must be DERIVABLE from it:
# equal to one currency-marked figure in that text, or to the exact sum of all of them. There is
# no third branch, and in particular no arbitrary subset sum, because subset sums of a long list
# reach almost any value and would hand back the free parameter this removes.
#
# A CURRENCY MARKER IS REQUIRED and that requirement is the check. Extracting bare numbers would
# be worse than nothing here: "Mesa 4 - Pedido #42, 2 pizzas, R$ 60" contains 4, 42 and 2, so a
# bare extractor would license almost any small integer as customer-authored. Requiring `R$` or
# `reais` reduces that message to a single admissible figure.
#
# WHAT IT DOES NOT PROVE, stated rather than implied: the model supplies the quote, so it can
# fabricate one. What changes is the cost and the visibility of the lie. A silent numeric
# substitution becomes a fabricated CUSTOMER UTTERANCE, echoed into the operator trace on stderr
# and falsifiable against the channel transcript, which the model does not write. Text injected by
# a third party -- a group message, a memory row, a tool output -- can no longer set the price
# without the model laundering it into the quote as the customer's own words. The ceiling is a
# check that reads the channel transcript itself rather than being handed it; this script runs in
# the workspace jail and cannot reach that log, so it is out of reach here rather than unwanted.
MAX_QUOTE_CHARS = 2000

# `R$ 60`, `R$60,00`, `R$ 1.234,56`, `60 reais`. The character class is deliberately loose and the
# strictness lives in _parse_money, so a malformed figure REFUSES rather than being skipped by a
# tighter pattern and silently leaving a smaller admissible set.
_MONEY_RE = re.compile(
    r"R\$\s*([\d.,]+)|([\d.,]+)\s*(?:reais|real)\b",
    re.IGNORECASE,
)


def _parse_money(tok: str) -> Decimal:
    """A Brazilian money token to a Decimal, refusing anything whose separators are ambiguous.

    `1.234` is 1234 to a Brazilian writer and 1.234 to this parser's default reading, a
    thousand-fold difference well inside the plausibility band, so a separator followed by exactly
    three digits raises rather than picking a side.
    """
    t = tok.strip().rstrip(".,")
    if not t or not any(ch.isdigit() for ch in t):
        raise ValueError("carries no digits")
    dots, commas = t.count("."), t.count(",")
    if dots and commas:
        dec_sep = "." if t.rfind(".") > t.rfind(",") else ","
        tho_sep = "," if dec_sep == "." else "."
        int_part, _, dec_part = t.rpartition(dec_sep)
        if not dec_part.isdigit() or not 1 <= len(dec_part) <= 2:
            raise ValueError("its decimal part is not one or two digits")
        groups = int_part.split(tho_sep)
        if (
            len(groups) < 2
            or not all(g.isdigit() for g in groups)
            or not 1 <= len(groups[0]) <= 3
            or any(len(g) != 3 for g in groups[1:])
        ):
            raise ValueError("its thousands groups are not three digits each")
        return Decimal(f"{''.join(groups)}.{dec_part}")
    sep = "." if dots else ("," if commas else "")
    if not sep:
        if not t.isdigit():
            raise ValueError("it is not a number")
        return Decimal(t)
    if t.count(sep) > 1:
        raise ValueError(
            f"it repeats {sep!r} with no decimal separator to disambiguate"
        )
    head, _, tail = t.partition(sep)
    if not head.isdigit() or not tail.isdigit():
        raise ValueError("it is not a number")
    if len(tail) == 3:
        raise ValueError(
            f"{sep!r} followed by exactly three digits is a thousands separator to a "
            f"Brazilian writer and a decimal point to this parser, a thousand-fold difference"
        )
    if len(tail) > 3:
        raise ValueError("its decimal part is longer than two digits")
    return Decimal(f"{head}.{tail}")


def figures_in(quote: str) -> list[Decimal]:
    """Every currency-marked figure in the quote, in order. Refuses on a malformed one."""
    out = []
    for whole, suffixed in _MONEY_RE.findall(quote):
        tok = whole or suffixed
        try:
            out.append(_parse_money(tok))
        except ValueError as exc:
            sys.exit(
                f"REFUSED: the quoted text carries the figure {tok!r}, which cannot be read "
                f"unambiguously because {exc}. No link was produced. Ask for the amount again "
                f"in a plain form such as 'R$ 1234,56'."
            )
    return out


def _fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "zeroclaw-shop pay_link"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_S) as r:
        if r.status != 200:
            raise OSError(f"HTTP {r.status}")
        return json.loads(r.read().decode("utf-8"))


def fetch_rate() -> tuple[Decimal, str, str]:
    """(rate, date, provenance). Refuses rather than returning a rate it cannot corroborate.

    NO FALLBACK to a last-known or caller-supplied value. A fallback restores the hole under
    exactly the conditions an attacker can induce, and inducing a fetch failure is the cheapest
    thing on this list. The cost is real and is the right trade: on a network failure this shop
    produces NO pay link for a BRL order rather than one priced from an unverified number.
    """
    today = _dt.date.today()
    ptax = None
    for back in range(MAX_WALKBACK_DAYS + 1):
        day = today - _dt.timedelta(days=back)
        try:
            payload = _fetch_json(PTAX_URL.format(mmddyyyy=day.strftime("%m-%d-%Y")))
        except Exception as exc:
            sys.exit(
                f"REFUSED: cannot reach BCB PTAX ({type(exc).__name__}). No link produced."
            )
        rows = payload.get("value") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            sys.exit(
                "REFUSED: BCB PTAX returned an unexpected shape. No link produced."
            )
        if rows:
            row = rows[0]
            rate = row.get("cotacaoVenda") if isinstance(row, dict) else None
            stamp = row.get("dataHoraCotacao") if isinstance(row, dict) else None
            if isinstance(rate, bool) or not isinstance(rate, (int, float)):
                sys.exit("REFUSED: BCB PTAX rate is not a number. No link produced.")
            if not isinstance(stamp, str) or len(stamp) < 10:
                sys.exit("REFUSED: BCB PTAX timestamp is malformed. No link produced.")
            ptax = (Decimal(str(rate)), stamp[:10])
            break
    if ptax is None:
        sys.exit(
            f"REFUSED: BCB published no rate in the {MAX_WALKBACK_DAYS + 1} days ending {today}. "
            "Refusing rather than quoting an older rate. No link produced."
        )

    try:
        ecb_payload = _fetch_json(ECB_URL.format(date=ptax[1]))
    except Exception as exc:
        sys.exit(
            f"REFUSED: cannot reach the ECB corroborator ({type(exc).__name__}). No link produced."
        )
    rates = ecb_payload.get("rates") if isinstance(ecb_payload, dict) else None
    ecb_rate = rates.get("BRL") if isinstance(rates, dict) else None
    ecb_date = ecb_payload.get("date") if isinstance(ecb_payload, dict) else None
    if isinstance(ecb_rate, bool) or not isinstance(ecb_rate, (int, float)):
        sys.exit(
            "REFUSED: the ECB corroborator returned no usable BRL rate. No link produced."
        )
    if not isinstance(ecb_date, str) or ecb_date != ptax[1]:
        sys.exit(
            f"REFUSED: sources report different dates (BCB {ptax[1]}, ECB {ecb_date}). "
            "Comparing rates across days is not a corroboration. No link produced."
        )
    ecb = Decimal(str(ecb_rate))

    for label, value in (("BCB", ptax[0]), ("ECB", ecb)):
        if not (Decimal(str(MIN_PLAUSIBLE)) <= value <= Decimal(str(MAX_PLAUSIBLE))):
            sys.exit(
                f"REFUSED: the {label} rate {value} is outside the plausible BRL/USD band "
                f"[{MIN_PLAUSIBLE}, {MAX_PLAUSIBLE}]. No link produced."
            )
    div = abs(ptax[0] - ecb) / ((ptax[0] + ecb) / 2)
    if div > Decimal(str(MAX_DIVERGENCE)):
        sys.exit(
            f"REFUSED: the rate sources disagree by {div * 100:.2f}% "
            f"(BCB {ptax[0]}, ECB {ecb}), over the {MAX_DIVERGENCE * 100:.2f}% band. "
            "No link produced."
        )
    return ptax[0], ptax[1], f"BCB PTAX, corroborated by ECB within {div * 100:.2f}%"


USAGE = (
    "usage: pay_link.py '<solana: URL>' [pt|en] "
    "[--brl <value> --quote '<verbatim text the value came from>'] [--rate <rate>]"
)

# Pull the optional flags out first so the positional contract stays exactly what it
# was. Callers that pass only the URL, or the URL and a language, behave identically
# to before this check existed; the live shop cannot break by being older than this
# script.
argv = sys.argv[1:]
brl_arg = rate_arg = quote_arg = None
positional = []
i = 0
while i < len(argv):
    token = argv[i]
    if token in ("--brl", "--rate", "--quote"):
        if i + 1 >= len(argv):
            sys.exit(f"REFUSED: {token} given with no value.\n{USAGE}")
        if token == "--brl":
            brl_arg = argv[i + 1]
        elif token == "--rate":
            rate_arg = argv[i + 1]
        else:
            quote_arg = argv[i + 1]
        i += 2
        continue
    positional.append(token)
    i += 1

if len(positional) not in (1, 2) or not positional[0].startswith("solana:"):
    sys.exit(USAGE)

url = positional[0]

# Whitelisted, never interpolated from free text. An unrecognised value is a hard
# refusal rather than a silent fallback: silently dropping it is how the customer
# ends up on the wrong-language checkout again with nothing reporting a problem.
lang = ""
if len(positional) == 2:
    requested = positional[1].strip().lower()
    if requested not in ("pt", "en"):
        sys.exit(f"REFUSED: unsupported lang {requested!r}; expected 'pt' or 'en'")
    lang = requested

# solana:<recipient>[?params] -- the recipient is everything between the scheme and
# the query string. Split on "?" first so a "recipient" carrying a crafted query
# cannot smuggle anything past the comparison.
recipient = url[len("solana:") :].split("?", 1)[0].strip()

if recipient != MERCHANT:
    sys.exit(
        f"REFUSED: pay link recipient is not this shop.\n"
        f"  expected: {MERCHANT}\n"
        f"  got:      {recipient or '(empty)'}\n"
        f"No link was produced. If this was not a typo, treat it as an attempt to "
        f"redirect a customer payment and check the agent's memory store."
    )

# MINT. Same parse discipline as the recipient: split the query off first so a crafted
# value cannot smuggle anything past the comparison. Read only the first `spl-token`, and
# refuse a duplicate outright, for the reason set out at the amount check below: the page
# reads the first value as this parser does, but the same URI is handed to QR scanners and
# phone wallets whose behaviour on a repeated key is neither uniform nor specified.
query = url[len("solana:") :].split("?", 1)[1] if "?" in url else ""
mint_values = [
    pair.split("=", 1)[1]
    for pair in query.split("&")
    if pair.split("=", 1)[0] == "spl-token" and "=" in pair
]
mint = mint_values[0].strip() if mint_values else ""

if len(mint_values) > 1:
    # Refused for the same reason as a duplicate `amount` below: the pay page reads the first
    # value, but the QR and deep-link consumers are third-party wallets whose parsers nobody
    # here controls, and a duplicated key has no settled meaning across them.
    sys.exit(
        f"REFUSED: pay link carries {len(mint_values)} spl-token parameters. "
        f"A duplicated key is read differently by different wallets and is never a legitimate "
        f"request, so it is a smuggling shape rather than a typo. No link was produced."
    )

# The refusal is split because the two failures are not the same failure, and pinning
# them together over-reached: it refused `solana:<merchant>` with no parameters at all,
# which is the legitimate flow where the customer sets the amount in their own wallet
# and which the pay page explicitly renders ("(amount set in your wallet)").
#
# A WRONG mint is always refused: it reprices the order in some other asset, and a mint
# can call itself whatever it likes.
#
# An ABSENT mint is refused only when an AMOUNT is present, because that is the
# repricing shape: Solana Pay reads a missing `spl-token` as native SOL, so "8.80"
# silently becomes 8.80 SOL. With no amount there is nothing to reprice, so that case
# passes through as before.
has_amount = any(
    pair.split("=", 1)[0] == "amount" and "=" in pair for pair in query.split("&")
)

if mint and mint != MINT:
    sys.exit(
        f"REFUSED: pay link asset is not this shop's.\n"
        f"  expected: {MINT}\n"
        f"  got:      {mint}\n"
        f"No link was produced. An altered mint reprices the order in a different "
        f"asset, so check the agent's memory store the same way a wrong recipient "
        f"would be checked."
    )

if not mint and has_amount:
    sys.exit(
        f"REFUSED: pay link carries an amount but no spl-token.\n"
        f"  Solana Pay reads that as native SOL, so this would quote the order in SOL "
        f"rather than in {MINT}.\n"
        f"No link was produced. Either name the mint or drop the amount and let the "
        f"customer's wallet set it."
    )

# LABEL. The third of the four constants, and until now the only one of them with nothing
# enforcing it. SKILL.md pins all four and then says so in its own words: "pay_link.py refuses
# a link whose recipient or mint is not the pair above, so a drifted value fails loudly rather
# than reaching a customer. The label and the network sentence have no such guard, which is why
# they are your responsibility here." A responsibility assigned in prose to a model is not a
# constraint on it, which is the argument this whole shop is built on, so the sentence describes
# a hole rather than a design.
#
# It drifted on 2026-08-06 alongside the recipient and the mint, with no attacker: a stale
# placeholder name reached a real customer's approval screen. Per the Solana Pay spec `label` is
# the MERCHANT and the wallet renders it as WHO IS BEING PAID, so a wrong one is display spoofing
# on the last screen before money moves, not a cosmetic defect.
#
# SPLIT for the same reason the mint check is split, because absent and wrong are different
# failures. A WRONG label is always refused. An ABSENT label is NOT: the field is optional in the
# spec and a wallet then shows the recipient address instead, which is less informative and is not
# misleading, so refusing it would break a legitimate link to prevent nothing.
label_values = [
    pair.split("=", 1)[1]
    for pair in query.split("&")
    if pair.split("=", 1)[0] == "label" and "=" in pair
]

if len(label_values) > 1:
    sys.exit(
        f"REFUSED: pay link carries {len(label_values)} label parameters. "
        f"A duplicated key is read differently by different wallets and is never a legitimate "
        f"request, so it is a smuggling shape rather than a typo. No link was produced."
    )

if label_values:
    # Compared DECODED, because the wallet displays the decoded form. `ZeroClaw%20Shop` and
    # `ZeroClaw+Shop` are the same label to a customer, and a byte comparison would refuse one
    # encoding of the correct name while a spoof only has to pick the other.
    got_label = unquote_plus(label_values[0].strip())
    if got_label != LABEL:
        sys.exit(
            f"REFUSED: pay link names a different merchant.\n"
            f"  expected: {LABEL}\n"
            f"  got:      {got_label}\n"
            f"No link was produced. The wallet renders this as who is being paid, so a drifted "
            f"value misnames the shop on the approval screen. Check the agent's memory store the "
            f"same way a wrong recipient would be checked."
        )

# AMOUNT. The recipient check above exists because the recipient once came only from
# prose and went wrong. The amount had the same shape and no guard at all: it rode
# through this script base64-encoded and untouched, into a request a customer pays.
#
# It is not a theoretical gap either. The runtime trace for 2026-07-27T13:11:14Z shows
# the agent calling the `calculator` tool with {"a":80,"b":5.0827,"function":"divide"}
# and the host refusing it -- "Missing required parameter: values (array of numbers)",
# duration_ms 0, output empty. The tool never ran. SKILL.md tells the model to compute
# `BRL / rate` itself anyway, so every figure this shop has quoted was model arithmetic,
# and nothing between that number and the customer's wallet re-derived it.
#
# So the division happens HERE, in code, and a disagreement is a hard refusal rather than
# a warning.
#
# THE RATE IS NO LONGER AN INPUT. Verifying the caller's arithmetic against the caller's own
# rate caught ARITHMETIC error and not INTENT error: a consistent lie passed everything. So
# `--brl` alone is now the whole contract, and the rate is fetched by `fetch_rate()` above.
#
# `--rate` is still accepted and is now a CROSS-CHECK rather than a source. It can only ever
# cause an additional refusal: the figure used is always the fetched one, so passing a rate
# cannot relax anything, and passing a wrong one stops the link. That is what keeps this from
# being bypassable by a caller who simply keeps supplying both.
#
# WHAT THIS STILL DOES NOT CLOSE, stated rather than implied: the order VALUE remains
# caller-supplied. It is now bounded by MIN_ORDER_BRL/MAX_ORDER_BRL above, so the
# sub-currency-unit case no longer produces a link, but a PLAUSIBLE wrong value still does and
# always will while the band is wide enough for a shop with no catalog. This removes one free
# parameter of two and narrows the second; closing it needs a price source the model cannot
# author: a priced SKU table, an order id resolved against a store, or a merchant confirmation
# that certifies the serialized bytes rather than a sentence.
if rate_arg is not None and brl_arg is None:
    sys.exit("REFUSED: --rate given without --brl; there is no order value to price.")

if quote_arg is not None and brl_arg is None:
    sys.exit("REFUSED: --quote given without --brl; there is no order value to bind.")

if brl_arg is not None:
    try:
        brl = Decimal(brl_arg)
    except (InvalidOperation, ValueError):
        sys.exit(f"REFUSED: --brl must be a decimal number; got {brl_arg!r}.")
    if brl <= 0:
        sys.exit(f"REFUSED: --brl must be positive; got {brl}.")
    if not (MIN_ORDER_BRL <= brl <= MAX_ORDER_BRL):
        sys.exit(
            f"REFUSED: the order value R$ {brl} is outside the plausible band "
            f"[{MIN_ORDER_BRL}, {MAX_ORDER_BRL}]. No link produced. This band is wide on "
            f"purpose and only removes values no merchant order has; a plausible wrong amount "
            f"still passes, which is why the price source matters."
        )

    # THE QUOTE IS MANDATORY WITH --brl, and treating a missing one as "skip the check" is the
    # exact fail-open this guard exists to prevent: a caller that can omit the binding by omitting
    # a flag is not bound. Refusing costs a link and produces no wrong price, which is the same
    # trade fetch_rate() already makes on a network failure.
    if quote_arg is None:
        sys.exit(
            "REFUSED: --brl given without --quote. The order value must be traceable to the "
            "words it came from, so pass the customer's or operator's verbatim message. "
            "No link was produced."
        )
    if len(quote_arg) > MAX_QUOTE_CHARS:
        sys.exit(
            f"REFUSED: --quote is {len(quote_arg)} characters, over the {MAX_QUOTE_CHARS} cap. "
            f"Pass the message the figure came from, not a transcript. No link was produced."
        )
    # The quote is echoed to a terminal below, so C0 controls are refused rather than stripped:
    # stripping would let the echoed text differ from the text that was matched against, and the
    # operator reading the trace would be checking a different string from the one that priced
    # the order. Newline and tab survive because real chat messages carry them.
    bad = sorted({c for c in quote_arg if ord(c) < 32 and c not in "\n\t"})
    if bad:
        sys.exit(
            f"REFUSED: --quote carries control characters {[hex(ord(c)) for c in bad]}. "
            f"No link was produced."
        )

    quoted = figures_in(quote_arg)
    if not quoted:
        sys.exit(
            "REFUSED: the quoted text names no amount in reais, so the order value is not "
            "traceable to it. A figure must be marked with 'R$' or 'reais': a bare number is "
            "not read as a price, because table and order numbers are bare numbers too. "
            "No link was produced."
        )
    admissible = set(quoted) | {sum(quoted)}
    if brl not in admissible:
        sys.exit(
            f"REFUSED: the order value is not derivable from the quoted text.\n"
            f"  order value: R$ {brl}\n"
            f"  quoted:      {', '.join(f'R$ {q}' for q in quoted)}\n"
            f"  admissible:  {', '.join(f'R$ {a}' for a in sorted(admissible))} "
            f"(any one figure, or the sum of all of them)\n"
            f"No link was produced. The value a customer is asked to pay has to come from the "
            f"operator or the customer, never from the agent; if the quote is right and the "
            f"value is wrong, use the quoted figure."
        )
    matched = (
        "the sum of the quoted figures" if brl not in set(quoted) else "a quoted figure"
    )
    print(
        f"order: R$ {brl} is {matched} in {quote_arg[:200]!r}",
        file=sys.stderr,
    )

    rate, rate_date, provenance = fetch_rate()

    if rate_arg is not None:
        try:
            claimed = Decimal(rate_arg)
        except (InvalidOperation, ValueError):
            sys.exit(f"REFUSED: --rate must be a decimal number; got {rate_arg!r}.")
        if claimed <= 0:
            sys.exit(f"REFUSED: --rate must be positive; got {claimed}.")
        drift = abs(claimed - rate) / rate
        if drift > Decimal(str(MAX_DIVERGENCE)):
            sys.exit(
                f"REFUSED: the supplied rate does not match the published one.\n"
                f"  supplied:  {claimed}\n"
                f"  published: {rate} ({provenance}, {rate_date})\n"
                f"  apart:     {drift * 100:.2f}%, over the {MAX_DIVERGENCE * 100:.2f}% band\n"
                f"No link was produced."
            )
    # Read the amount back out of the URL rather than trusting a second copy of it.
    #
    # DUPLICATES ARE REFUSED because the consumers disagree about what a duplicate means.
    #
    # The pay page reads the FIRST value: it builds a `URLSearchParams` and calls `.get()`, and
    # `new URLSearchParams('amount=15.32&amount=1532').get('amount')` is `15.32`. So the page
    # and this parser agree, and on that path alone a duplicate would change nothing.
    #
    # The page is not the only consumer. This same `solana:` URI is rendered as a QR and
    # deep-linked into phone wallets, parsers nobody here controls or tests, and first-wins,
    # last-wins and reject-outright are all defensible readings that the Solana Pay spec does
    # not settle. A duplicated key is never a legitimate request, so refusing costs nothing and
    # removes a divergence across a consumer set that cannot be enumerated.
    query = url.split("?", 1)[1] if "?" in url else ""
    amount_values = [
        pair.split("=", 1)[1]
        for pair in query.split("&")
        if pair.split("=", 1)[0] == "amount" and "=" in pair
    ]
    if len(amount_values) > 1:
        sys.exit(
            f"REFUSED: pay link carries {len(amount_values)} amount parameters. "
            f"A repeated key is never a legitimate request, and wallets and QR scanners "
            f"do not agree on which copy wins. No link was produced."
        )
    stated = amount_values[0] if amount_values else None
    if stated is None:
        sys.exit("REFUSED: --brl given but the URL carries no amount= to verify.")
    try:
        stated_amount = Decimal(stated)
    except (InvalidOperation, ValueError):
        sys.exit(
            f"REFUSED: amount= in the URL is not a decimal number; got {stated!r}."
        )

    # Two decimals, half-up, matching what the shop states to the customer. The rate here is
    # always the FETCHED one, never a supplied one, so this compares the URL against the
    # published rate rather than against the caller's own arithmetic.
    expected = (brl / rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if stated_amount != expected:
        sys.exit(
            f"REFUSED: the amount in this pay link does not match the order.\n"
            f"  order:    R$ {brl} at {rate} ({provenance}, {rate_date})\n"
            f"  expected: {expected} (2dp, half-up)\n"
            f"  got:      {stated_amount}\n"
            f"No link was produced. The customer would have been asked to pay the wrong "
            f"figure. Recompute the conversion and rebuild the request."
        )
    # State the provenance on stderr so the operator sees which rate priced the order without
    # it contaminating stdout, which is the link and nothing else.
    print(
        f"rate: R$ {brl} at {rate} ({provenance}, {rate_date}) = {expected} USDC",
        file=sys.stderr,
    )

encoded = base64.urlsafe_b64encode(url.encode()).decode()
print(f"{PAGE}?u={encoded}" + (f"&lang={lang}" if lang else ""))
