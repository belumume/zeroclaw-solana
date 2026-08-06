"""Render the three shoot links against PRODUCTION and assert each card state.

shoot_links.py checks preconditions -- the page is up, the mint is pinned, the
fixtures still mean what they should. None of that is the card. The card is
built by JavaScript from the chain at load time, so the only way to know what
his phone will show is to load it in a browser and read the DOM.

Driven at the PHONE viewport (390x844, dpr 3), because that is the device the
beat is shot on and the payable card is already known to clip at that height.

Each state asserts BOTH what must be present and what must be ABSENT. A refusal
that merely lacks a Pay button could be a blank page; a refusal that shows both
addresses in full AND has no Pay button is the actual behaviour being filmed.

THE MIDDLE CASE IS THE CONTROL. A page that refused everything would satisfy
beats 1 and 2b while being completely broken, so "the guard fires" is only
evidence alongside a payable link that still renders its Pay button.

Uses the same python-playwright binding as demo/verify_paid_link_refused.py.

    python demo/verify_shoot_links_live.py
"""

from __future__ import annotations

import sys
from base64 import urlsafe_b64encode

LIVE = "https://zeroclaw-shop-pay.pages.dev"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
TAMPERED = MERCHANT[:-1] + "K"
PAID_REF = "9TNKoCvVow1ktRgMMapJ9d9GWhgTYCA9i3r3MZ71FUT2"
UNPAID_REF = "5Zzguz4NsSRFxGkHfM4KmJTNVPMJ2P3jFa2y8bTHY4kW"

CASES = {
    "beat1-tampered": ("0.39", TAMPERED, UNPAID_REF),
    "beat2a-payable": ("0.39", MERCHANT, UNPAID_REF),
    "beat2b-paid": ("5.00", MERCHANT, PAID_REF),
}


def url(amount: str, recipient: str, reference: str) -> str:
    solana = (
        f"solana:{recipient}?amount={amount}&spl-token={MINT}"
        f"&reference={reference}&label=ZeroClaw%20Shop&message=Pedido"
    )
    return f"{LIVE}/index.html?lang=pt&u={urlsafe_b64encode(solana.encode()).decode()}"


def render_all() -> dict | None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("COULD NOT RUN: python playwright not importable", file=sys.stderr)
        return None

    out: dict = {}
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(channel="chrome")
            ctx = browser.new_context(
                viewport={"width": 390, "height": 844},
                device_scale_factor=3,
                is_mobile=True,
            )
            for name, (amount, recipient, reference) in CASES.items():
                page = ctx.new_page()
                page.goto(
                    url(amount, recipient, reference),
                    wait_until="networkidle",
                    timeout=60000,
                )
                # The settled check is an RPC round trip AFTER load, so the card
                # can still be replaced after networkidle. Wait rather than race.
                page.wait_for_timeout(4000)
                card = page.query_selector("#card")
                out[name] = {
                    "cls": card.get_attribute("class") if card else None,
                    "text": " ".join(page.evaluate("document.body.innerText").split()),
                    "pay": page.evaluate(
                        "(() => { const p = document.getElementById('pay');"
                        " return !!(p && p.offsetParent !== null && !p.disabled); })()"
                    ),
                    "qr": page.evaluate("!!document.querySelector('#qr img')"),
                    "scrollX": page.evaluate(
                        "document.documentElement.scrollWidth - window.innerWidth"
                    ),
                }
                page.close()
            browser.close()
    except Exception as e:
        # Deliberately broad. This is a verification harness, so the ONE outcome
        # it must never produce is a pass it did not earn. Every driver failure
        # -- a launch error, a navigation timeout, a page crash, a selector that
        # vanished -- maps to COULD NOT RUN (rc 2) rather than to a verdict.
        print(f"COULD NOT RUN: {type(e).__name__}: {e}", file=sys.stderr)
        return None
    return out


def main() -> int:
    got = render_all()
    if got is None:
        return 2

    fails: list[str] = []

    def check(name: str, cond: bool, what: str) -> None:
        print(f"  {'ok  ' if cond else 'FAIL'}  {what}")
        if not cond:
            fails.append(f"{name}: {what}")

    r = got["beat1-tampered"]
    print(f"\nBEAT 1  tampered recipient   class={r['cls']}")
    check("beat1", "err" in (r["cls"] or ""), "card is in the error state")
    check("beat1", not r["pay"], "NO Pay button")
    check("beat1", "RECUSADO" in r["text"].upper(), "reads RECUSADO")
    check(
        "beat1",
        "ZWiLHK" in r["text"] and "ZWiLHJ" in r["text"],
        "BOTH addresses in full",
    )

    r = got["beat2a-payable"]
    print(f"\nBEAT 2a payable, unsettled   class={r['cls']}")
    check("beat2a", "err" not in (r["cls"] or ""), "card is NOT in the error state")
    check("beat2a", r["pay"], "Pay button LIVE  <- the control")
    check("beat2a", r["qr"], "QR rendered")
    check("beat2a", "0.39" in r["text"], "amount 0.39 on screen")
    check("beat2a", r["scrollX"] == 0, f"no horizontal scroll (delta-x {r['scrollX']})")

    r = got["beat2b-paid"]
    print(f"\nBEAT 2b already settled      class={r['cls']}")
    check("beat2b", not r["pay"], "NO Pay button")
    check("beat2b", "PAGO" in r["text"].upper(), "reads Pago")
    check("beat2b", "0.39" in r["text"], "shows 0.39, the amount the CHAIN recorded")
    check(
        "beat2b", "5.00" not in r["text"], "does NOT echo the 5.00 the link asked for"
    )

    print()
    if fails:
        print(f"{len(fails)} FAILURE(S) -- do not shoot from these links:")
        for f in fails:
            print(f"  {f}")
        return 1
    print(
        "All three links render as the script's ON SCREEN spec describes. Safe to shoot."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
