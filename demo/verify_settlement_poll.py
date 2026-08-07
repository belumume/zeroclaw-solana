#!/usr/bin/env python3
"""Prove the pay page POLLS for settlement rather than only checking on load.

WHY THIS EXISTS. On a phone the wallet never consults this page: scanning the QR hands the
`solana:` URI straight to the wallet, which builds and submits on its own. So a load-time check
alone leaves an open tab showing a live QR indefinitely after the order settles, and the customer's
only signal is to reload. The operator hit exactly that four times in one evening.

The existing verifiers all pass with or without the poll, because they assert on the FIRST render.
A green suite that cannot tell the two builds apart is not evidence, so this asserts on the
BEHAVIOUR OVER TIME and ships a control that fails when the poll is removed.
"""

from __future__ import annotations

import base64
import sys
import urllib.parse
from pathlib import Path

from playwright.sync_api import sync_playwright

MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
# An unsettled reference, so the card stays payable and the poll keeps running for the whole window.
UNSETTLED = "6NpAbULXSDAYHCwMd5tmor9rBq9V2Y3EG6gLMDptk11w"
WINDOW_MS = 15000  # POLL_MS is 6s, so a correct build makes at least two calls in this window.


def pay_url(reference: str) -> str:
    sol = (
        f"solana:{MERCHANT}?amount=0.39&spl-token={MINT}"
        f"&reference={reference}&label=ZeroClaw%20Shop&message=Pedido"
    )
    u = urllib.parse.quote(base64.b64encode(sol.encode()).decode())
    return f"https://zeroclaw-shop-pay.pages.dev/?u={u}&lang=pt"


def count_reference_calls(page_html: str | None, url: str) -> tuple[int, str]:
    """Return (getSignaturesForAddress calls observed, final card class)."""
    calls = 0

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 390, "height": 844})

        def on_request(req):
            nonlocal calls
            if req.method == "POST" and req.post_data and "getSignaturesForAddress" in req.post_data:
                calls += 1

        page.on("request", on_request)

        if page_html is not None:
            # Control build: serve a locally mutated page rather than the deployed one.
            page.route("**/index.html*", lambda r: r.fulfill(status=200, content_type="text/html", body=page_html))
            page.route("https://zeroclaw-shop-pay.pages.dev/?*", lambda r: r.fulfill(status=200, content_type="text/html", body=page_html))

        page.goto(url, wait_until="networkidle")
        page.wait_for_timeout(WINDOW_MS)
        cls = page.eval_on_selector("#card", "e=>e.className")
        browser.close()
    return calls, cls


def main() -> int:
    url = pay_url(UNSETTLED)

    live_calls, live_cls = count_reference_calls(None, url)
    print(f"deployed page : {live_calls} reference call(s) in {WINDOW_MS/1000:.0f}s, card={live_cls!r}")

    # CONTROL: the same page with the poll disabled. If this scores the same as the deployed build,
    # the measurement cannot discriminate and proves nothing.
    built = Path("webshop-pay/index.html").read_text(encoding="utf-8")
    if "watchForSettlement();" not in built:
        print("FAIL  control anchor 'watchForSettlement();' absent from the built page", file=sys.stderr)
        return 2
    control_html = built.replace("watchForSettlement();", "/*poll disabled for control*/;", 1)
    ctrl_calls, ctrl_cls = count_reference_calls(control_html, url)
    print(f"control (poll off): {ctrl_calls} reference call(s), card={ctrl_cls!r}")

    ok = True
    if live_calls < 2:
        print(f"FAIL  deployed page made {live_calls} call(s); a 6s poll must make at least 2 in {WINDOW_MS/1000:.0f}s", file=sys.stderr)
        ok = False
    if ctrl_calls != 1:
        print(f"FAIL  control made {ctrl_calls} call(s); with the poll off it must make exactly 1", file=sys.stderr)
        ok = False
    if live_cls != "card" or ctrl_cls != "card":
        print("FAIL  an unsettled reference must stay payable in both builds", file=sys.stderr)
        ok = False

    if not ok:
        return 1
    print()
    print("PASS  the page polls the reference while the card is payable, and the control")
    print("      with the poll removed makes exactly one call, so the difference is the poll")
    print("      and not the page loading twice.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
