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
import sys
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

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

USAGE = "usage: pay_link.py '<solana: URL>' [pt|en] [--brl <value> --rate <rate>]"

# Pull the optional flags out first so the positional contract stays exactly what it
# was. Callers that pass only the URL, or the URL and a language, behave identically
# to before this check existed; the live shop cannot break by being older than this
# script.
argv = sys.argv[1:]
brl_arg = rate_arg = None
positional = []
i = 0
while i < len(argv):
    token = argv[i]
    if token in ("--brl", "--rate"):
        if i + 1 >= len(argv):
            sys.exit(f"REFUSED: {token} given with no value.\n{USAGE}")
        if token == "--brl":
            brl_arg = argv[i + 1]
        else:
            rate_arg = argv[i + 1]
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
# value cannot smuggle anything past the comparison. Read only the first `spl-token`,
# because a duplicated parameter is itself a smuggling shape and the page's own parser
# takes the last one.
query = url[len("solana:") :].split("?", 1)[1] if "?" in url else ""
mint_values = [
    pair.split("=", 1)[1]
    for pair in query.split("&")
    if pair.split("=", 1)[0] == "spl-token" and "=" in pair
]
mint = mint_values[0].strip() if mint_values else ""

if len(mint_values) > 1:
    sys.exit(
        f"REFUSED: pay link carries {len(mint_values)} spl-token parameters. "
        f"This parser reads the first and the pay page reads the last, so a duplicate "
        f"is a smuggling shape rather than a typo. No link was produced."
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
# So when the caller supplies the inputs, the division happens HERE, in code, and a
# disagreement is a hard refusal rather than a warning. Both flags are required together
# because one alone cannot re-derive anything.
#
# THE LIMIT, stated rather than implied: the model supplies both the amount and the
# inputs, so this catches ARITHMETIC error and not INTENT error -- a consistent lie
# passes. Closing that needs this script to fetch the rate itself and accept only the
# order value, which trades a network call in the pay path. Arithmetic error is the
# failure actually observed, so this is the proportionate step, not the final one.
if (brl_arg is None) != (rate_arg is None):
    sys.exit(
        "REFUSED: --brl and --rate must be given together; one alone verifies nothing."
    )

if brl_arg is not None and rate_arg is not None:
    try:
        brl = Decimal(brl_arg)
        rate = Decimal(rate_arg)
    except (InvalidOperation, ValueError):
        sys.exit(
            f"REFUSED: --brl/--rate must be decimal numbers; got {brl_arg!r} and {rate_arg!r}."
        )
    if rate <= 0:
        sys.exit(f"REFUSED: --rate must be positive; got {rate}.")

    # Read the amount back out of the URL rather than trusting a second copy of it.
    query = url.split("?", 1)[1] if "?" in url else ""
    stated = None
    for pair in query.split("&"):
        key, _, value = pair.partition("=")
        if key == "amount":
            stated = value
            break
    if stated is None:
        sys.exit(
            "REFUSED: --brl/--rate given but the URL carries no amount= to verify."
        )
    try:
        stated_amount = Decimal(stated)
    except (InvalidOperation, ValueError):
        sys.exit(
            f"REFUSED: amount= in the URL is not a decimal number; got {stated!r}."
        )

    # Two decimals, half-up, matching what SKILL.md instructs and what the shop states
    # to the customer.
    expected = (brl / rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if stated_amount != expected:
        sys.exit(
            f"REFUSED: the amount in this pay link does not match the order.\n"
            f"  order:    R$ {brl} at rate {rate}\n"
            f"  expected: {expected} (2dp, half-up)\n"
            f"  got:      {stated_amount}\n"
            f"No link was produced. The customer would have been asked to pay the wrong "
            f"figure. Recompute the conversion and rebuild the request."
        )

encoded = base64.urlsafe_b64encode(url.encode()).decode()
print(f"{PAGE}?u={encoded}" + (f"&lang={lang}" if lang else ""))
