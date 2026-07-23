#!/usr/bin/env python3
"""Turn a Solana Pay `solana:` URL into a TAPPABLE https pay-page link.

The shop's chat channels (Telegram, WhatsApp) are text-only: they cannot send
an image, and a raw `solana:` URI is not clickable in a chat message. This wraps
the request in a hosted pay page whose https link IS auto-linked and tappable in
any chat. Tapping it opens a page that renders a scannable QR, an "open wallet"
button (Phantom/Solflare), and the amount, so a customer can actually pay.

Usage: python3 tools/pay_link.py '<solana:...url...>'
Prints one line: the https pay-page link to send the customer.
"""

import base64
import sys

PAGE = "https://zeroclaw-shop-pay.pages.dev/"

if len(sys.argv) != 2 or not sys.argv[1].startswith("solana:"):
    sys.exit("usage: pay_link.py '<solana: URL>'")

encoded = base64.urlsafe_b64encode(sys.argv[1].encode()).decode()
print(f"{PAGE}?u={encoded}")
