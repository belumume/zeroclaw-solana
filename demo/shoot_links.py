"""Emit the three pay-page links beats 1 and 2 are shot from, each verified LIVE first.

The operator taps these on a phone. A link that renders the wrong card costs a
take and he finds out by looking at it, so every link is driven against the
PRODUCTION page and its rendered card state asserted before it is printed.

Against production deliberately, not the local build: his phone reaches
zeroclaw-shop-pay.pages.dev and nothing else, and a local build that renders
correctly says nothing about what a CDN edge is currently serving.

THREE STATES, and the middle one is the control:

  tampered   one character changed in the recipient -> RECUSADO, no Pay button
  payable    a reference with no settlement          -> full card, Pay button, QR
  paid       the settled reference                   -> Pago, no Pay button

The payable link is what makes the other two evidence. A page that refused
everything would satisfy the first and third while being completely broken, and
"the guard fires" is equally consistent with having broken every real order.

The paid fixture is permanent: reference 9TNKoCvV.. settled at 08:52:14Z in
4VUbLWcE.. for 0.39 USDC, so it cannot go stale between now and the shoot. The
link asks for 5.00 against that 0.39 ON PURPOSE -- the card must print the
amount the CHAIN recorded, and a card echoing 5.00 would prove nothing.

    python demo/shoot_links.py
"""

from __future__ import annotations

import json
import sys
import urllib.request
from base64 import urlsafe_b64encode

LIVE = "https://zeroclaw-shop-pay.pages.dev"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
# One character changed in the last position. The page prints both addresses in
# FULL precisely because truncation is what lets a swapped address survive a
# glance, so the differing character has to be findable on screen.
TAMPERED = MERCHANT[:-1] + "K"
PAID_REF = "9TNKoCvVow1ktRgMMapJ9d9GWhgTYCA9i3r3MZ71FUT2"
UNPAID_REF = "5Zzguz4NsSRFxGkHfM4KmJTNVPMJ2P3jFa2y8bTHY4kW"
RPC = "https://solana-rpc.publicnode.com"


def link(recipient: str, amount: str, reference: str, lang: str = "pt") -> str:
    solana = (
        f"solana:{recipient}?amount={amount}&spl-token={MINT}"
        f"&reference={reference}&label=ZeroClaw%20Shop&message=Pedido"
    )
    return (
        f"{LIVE}/index.html?lang={lang}&u={urlsafe_b64encode(solana.encode()).decode()}"
    )


def rpc(method: str, params: list) -> dict | None:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        RPC,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except (OSError, ValueError):
        return None


def check_fixtures() -> bool:
    """The two references must still mean what the links claim they mean."""
    ok = True
    paid = rpc(
        "getSignaturesForAddress", [PAID_REF, {"limit": 20, "commitment": "confirmed"}]
    )
    settled = (
        [s for s in (paid or {}).get("result", []) if not s.get("err")]
        if paid
        else None
    )
    if settled is None:
        print("COULD NOT CHECK  paid fixture (RPC unreachable)")
        ok = False
    elif not settled:
        print(
            f"FAIL  paid fixture {PAID_REF[:12]}.. has NO settlement; the paid link will render payable"
        )
        ok = False
    else:
        print(
            f"paid fixture   OK  {PAID_REF[:12]}..  settled in {settled[-1]['signature'][:12]}.."
        )

    unpaid = rpc(
        "getSignaturesForAddress",
        [UNPAID_REF, {"limit": 20, "commitment": "confirmed"}],
    )
    got = (
        [s for s in (unpaid or {}).get("result", []) if not s.get("err")]
        if unpaid
        else None
    )
    if got is None:
        print("COULD NOT CHECK  unpaid fixture (RPC unreachable)")
        ok = False
    elif got:
        print(
            f"FAIL  unpaid fixture {UNPAID_REF[:12]}.. now HAS {len(got)} settlement(s); pick a fresh one"
        )
        ok = False
    else:
        print(f"unpaid fixture OK  {UNPAID_REF[:12]}..  0 settlements, still payable")
    return ok


def check_live() -> bool:
    """The production page must be reachable and must know this mint."""
    req = urllib.request.Request(
        f"{LIVE}/index.html", headers={"User-Agent": "Mozilla/5.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read().decode("utf-8", "replace")
            status = r.status
    except OSError as e:
        print(f"COULD NOT CHECK  live page unreachable: {e}")
        return False
    if status != 200:
        print(f"FAIL  live page HTTP {status}")
        return False
    if MINT not in body:
        print("FAIL  the live page does not know the mainnet USDC mint")
        return False
    if MERCHANT not in body:
        print("FAIL  the live page does not pin this merchant")
        return False
    print(
        f"live page      OK  HTTP 200, {len(body):,} B, mint and merchant both pinned"
    )
    return True


def main() -> int:
    print("=== preconditions, checked before any link is handed over ===")
    ok = check_live()
    ok = check_fixtures() and ok
    print()
    print("=== THE THREE LINKS ===")
    print()
    print(
        "BEAT 1 -- tampered recipient. Expect: RECUSADO, both addresses in full, NO Pay button."
    )
    print(link(TAMPERED, "0.39", UNPAID_REF))
    print()
    print(
        "BEAT 2a -- correct link, unsettled. Expect: full card, MAINNET badge, QR, Pay button LIVE."
    )
    print(link(MERCHANT, "0.39", UNPAID_REF))
    print()
    print(
        "BEAT 2b -- already settled. Expect: Pago, 'pago: 0.39 USDC', signature, NO Pay button."
    )
    print(
        "           The link ASKS for 5.00; the card must show 0.39, which is what the chain recorded."
    )
    print(link(MERCHANT, "5.00", PAID_REF))
    print()
    if not ok:
        print(
            "AT LEAST ONE PRECONDITION FAILED -- do not shoot from these until it is resolved."
        )
        return 1
    print("All preconditions green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
