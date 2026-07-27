#!/usr/bin/env python3
"""Turn a Solana Pay `solana:` URL into a TAPPABLE https pay-page link.

The shop's chat channels (Telegram, WhatsApp) are text-only: they cannot send
an image, and a raw `solana:` URI is not clickable in a chat message. This wraps
the request in a hosted pay page whose https link IS auto-linked and tappable in
any chat. Tapping it opens a page that renders a scannable QR, an "open wallet"
button (Phantom/Solflare), and the amount, so a customer can actually pay.

Usage: python3 tools/pay_link.py '<solana:...url...>' [lang]
Prints one line: the https pay-page link to send the customer.

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

if len(sys.argv) not in (2, 3) or not sys.argv[1].startswith("solana:"):
    sys.exit("usage: pay_link.py '<solana: URL>' [pt|en]")

url = sys.argv[1]

# Whitelisted, never interpolated from free text. An unrecognised value is a hard
# refusal rather than a silent fallback: silently dropping it is how the customer
# ends up on the wrong-language checkout again with nothing reporting a problem.
lang = ""
if len(sys.argv) == 3:
    requested = sys.argv[2].strip().lower()
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

encoded = base64.urlsafe_b64encode(url.encode()).decode()
print(f"{PAGE}?u={encoded}" + (f"&lang={lang}" if lang else ""))
