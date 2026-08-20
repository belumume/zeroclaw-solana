#!/usr/bin/env python3
"""Prove the pay page refuses a link it cannot check for settlement, and still pays a link it can.

WHY THIS EXISTS. The already-paid guard rests entirely on the Solana Pay reference: the key rides
the transfer as a read-only non-signer account, so it is the thing `getSignaturesForAddress` is
asked about. A link with no reference, or with one that is not a pubkey, has nothing to ask about.
`settledSignature()` returns null for it forever, `checkAlreadyPaid()` reads that null as "not
settled", and the card keeps offering Pay however many times the order has already been paid.

So stripping `?reference=` from a pay URL SILENTLY DISABLED the double-payment check. Silently is
the whole problem: the page rendered exactly as it does when the guard is working, the poll kept
running against nothing, and the only visible outcome was a customer paying one order twice. The
recipient is pinned in the page, so no third party profits and nobody is robbed -- the victim
simply pays the legitimate merchant a second time, which the shop then owes back.

A REFUSAL ALONE PROVES NOTHING, and this file exists mostly to say what the refusal must NOT eat.
A page that refused everything would pass every refusal case below and be worthless. So the two
control cases drive links the page MUST still honour: an unsettled reference stays fully payable
with its Pay button and QR, and a settled one still lands on the existing already-paid card with
the figure the CHAIN recorded. If either of those stops holding, the fix has done more damage than
the defect.

HERMETIC BY CONSTRUCTION. Every RPC answer below is fulfilled by this harness, on the hosts the
page itself names, so nothing here reaches a live third party and no rate limit, pruning window or
devnet outage can turn it red. That also makes the settled case deterministic rather than dependent
on a mainnet transaction still being visible from whichever endpoint the page is pinned to today.

THE REQUEST COUNTER IS CALIBRATED. Every refusal case asserts ZERO requests reach the RPC hosts,
which is the claim that a hostile reference never touches an endpoint. A zero from a counter that
can only ever read zero is worth nothing, so the two control cases assert the SAME counter reads at
least one on the same run. Without that pair, a broken glob and a working guard are the same
number.

Run it:  python demo/verify_reference_required.py [--viewport desktop|phone] [--shots DIR]

Needs playwright (pip install playwright). It drives the system Chrome via channel="chrome", so no
browser download is required. Everything else is stdlib.
"""

from __future__ import annotations

import argparse
import http.server
import json
import socketserver
import sys
import threading
from base64 import urlsafe_b64encode
from pathlib import Path
from urllib.parse import quote

REPO = Path(__file__).resolve().parent.parent
PAGE_DIR = REPO / "webshop-pay"
APP = PAGE_DIR / "src" / "app.js"

# Read the pins out of the shipped page rather than restating them. A second copy here would drift
# from the page, and the drifted copy is the one a later reader trusts. The two host constants in
# particular drive the intercept globs below, so a repoint cannot leave this harness intercepting a
# host nothing contacts and reporting zero requests for free.
MERCHANT_MARKER = "var MERCHANT='"
RPC_MARKER = "var RPC='"
PROXY_MARKER = "var SETTLEMENT_PROXY='"

MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # mainnet USDC

# A syntactically valid pubkey. Its real on-chain history is irrelevant here because every answer
# about it is fulfilled by this harness; what matters is only that `isPubkey()` accepts it, so the
# page gets past the branch under test and into the settlement path the control cases exercise.
VALID_REFERENCE = "Ap15VZt5TJPpExnezgTRYkXeTuwfXoYVpK6ZNLi7y4ZM"

# Two malformed shapes, because they are rejected for different reasons and only one of them
# exercises the layout. `not-a-pubkey` fails the base58 ALPHABET (a hyphen is not in it); the long
# run fails the LENGTH while being made entirely of legal base58 characters, so a filter keyed on
# characters alone would wave it through.
MALFORMED_CHARS = "not-a-pubkey"
# 150 characters with no break opportunity anywhere in them. This is the shape that widens the card
# past the viewport and scrolls the whole page sideways unless the detail line wraps, which is why
# the refusal asks for `wrap` where the two address refusals must not.
MALFORMED_LONG = "z" * 150
# The refusal caps what it echoes, so a hostile reference cannot grow the card without bound.
ECHO_CAP = 64

# A surrogate pair sitting exactly ON the cap. 63 ASCII characters then one astral codepoint, so
# the emoji occupies UTF-16 indices 63 and 64: a cap applied with String.slice cuts between them
# and leaves a lone high surrogate, which renders as a replacement glyph. A cap applied by
# CODEPOINT keeps the emoji whole, because it is the 64th codepoint and the cap is 64.
#
# The assertion below is the whole emoji's presence rather than the absence of a broken glyph,
# because absence is the harder thing to observe through a JSON round trip and presence
# discriminates the two implementations exactly as well.
MALFORMED_SURROGATE = "z" * 63 + "\U0001f600" + "z" * 90

# The exact source of the branch under test, used by the mutation control at the end of the run.
# Asserted to appear EXACTLY ONCE in the built page before it is substituted: a control keyed to a
# string that has since moved applies to nothing, produces a mutant byte-identical to the real
# page, and then passes -- certifying the detector rather than testing it.
BRANCH_ANCHOR = "}else if(!isPubkey(reference)){"

# A real finalized mainnet signature, so the explorer link on the already-paid card points at
# something that exists. It is SERVED by this harness rather than looked up, which is what keeps
# the case deterministic: the transaction it names has already aged out of the page's own pinned
# endpoint, and a harness that depended on seeing it would be red for a reason about node
# housekeeping rather than about the page.
SETTLED_SIG = "4VUbLWcE2dPPYAXQVtH2WhvgP33KrbUiX2ruA9PeyfKMU4k5iPgFSL3xkg8wLtjk8GumPYdyNR92haxgEasDstUh"
CHAIN_AMOUNT = "0.39"  # what the served settlement credits the merchant
LINK_AMOUNT = (
    "5.00"  # what the link ASKS for, so an echo of the request is distinguishable
)

VIEWPORTS = {
    "desktop": {"viewport": {"width": 1280, "height": 900}, "device_scale_factor": 2},
    "phone": {
        "viewport": {"width": 390, "height": 844},
        "device_scale_factor": 3,
        "is_mobile": True,
        "has_touch": True,
    },
}


def read_pin(marker: str) -> str:
    src = APP.read_text(encoding="utf-8")
    i = src.index(marker) + len(marker)
    return src[i : src.index("'", i)]


def pay_url(reference: str | None, amount: str, lang: str) -> str:
    """A pay link, with the reference omitted entirely when `reference` is None.

    Omission is a distinct case from a malformed value and has to be driven as one: an absent
    parameter and an unparseable one arrive at the same refusal but by different routes, and a
    guard written against only the empty string would let `reference=@@@` through.
    """
    solana = f"solana:{read_pin(MERCHANT_MARKER)}?amount={amount}&spl-token={MINT}"
    if reference is not None:
        solana += f"&reference={quote(reference, safe='')}"
    solana += f"&label={quote('Mesa 4')}&message={quote('Pedido 412')}"
    # ?u= base64url, the form skills/solana-pay/scripts/pay_link.py actually emits.
    return f"/index.html?lang={lang}&u={urlsafe_b64encode(solana.encode()).decode()}"


def serve() -> tuple[socketserver.TCPServer, int]:
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(PAGE_DIR), **kw)

        def log_message(self, *a):  # silence; the harness owns the output
            pass

    socketserver.TCPServer.allow_reuse_address = True
    # Port 0: nobody but this script addresses this server, so it must not claim a named port.
    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def signatures_body(settled: bool) -> str:
    result = (
        [
            {
                "signature": SETTLED_SIG,
                "err": None,
                "slot": 437552699,
                "confirmationStatus": "finalized",
            }
        ]
        if settled
        else []
    )
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result})


def transaction_body(merchant: str) -> str:
    """A settlement crediting the merchant CHAIN_AMOUNT, shaped the way merchantCredit() reads it.

    Balances rather than a stated figure, because that is how the page derives what was actually
    paid: the link says what was REQUESTED and only the chain says what was PAID, and on a receipt
    those are different claims. The link in this case asks for LINK_AMOUNT so the two cannot be
    confused if the page ever starts echoing the request.
    """
    dec, paid = 6, 390000  # 0.390000 USDC
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "slot": 437552699,
                "transaction": {"message": {"accountKeys": [merchant]}},
                "meta": {
                    "err": None,
                    "preBalances": [0],
                    "postBalances": [0],
                    "preTokenBalances": [
                        {
                            "owner": merchant,
                            "mint": MINT,
                            "uiTokenAmount": {"amount": "0", "decimals": dec},
                        }
                    ],
                    "postTokenBalances": [
                        {
                            "owner": merchant,
                            "mint": MINT,
                            "uiTokenAmount": {"amount": str(paid), "decimals": dec},
                        }
                    ],
                },
            },
        }
    )


# FACTORIES, NOT DEFAULT ARGUMENTS, and the difference is not style.
#
# The obvious way to bind a loop variable into a playwright route handler is a default argument --
# `def handler(route, settled=settled)`. It does not work, and it fails SILENTLY in the reassuring
# direction: playwright inspects the handler's arity and, for a handler taking more than one
# parameter, calls it as `handler(route, route.request)`. The Request object lands in `settled`,
# every truthiness test on it passes, and the harness serves a settlement for every case including
# the one whose whole job is to prove an unsettled link stays payable.
#
# Measured here on the first run: the `valid-unpaid` control rendered the already-paid card. That
# control is the only reason this was caught -- with only refusal cases the suite would have gone
# green while testing one case six times. A closure over a factory's arguments takes exactly one
# parameter, so there is no second slot for playwright to fill.
def rpc_handler(settled: bool, merchant: str):
    def handler(route):
        body = route.request.post_data or ""
        if "getSignaturesForAddress" in body:
            out = signatures_body(settled)
        elif "getTransaction" in body:
            out = transaction_body(merchant)
        else:
            out = json.dumps({"jsonrpc": "2.0", "id": 1, "result": None})
        # A fulfilled cross-origin response still has to satisfy CORS or the browser discards it
        # before the page sees it, and `rpc()` reads a discarded response as "the chain did not
        # answer" -- which is a fail-open null, so every case would pass for the wrong reason.
        route.fulfill(
            status=200,
            content_type="application/json",
            headers={"access-control-allow-origin": "*"},
            body=out,
        )

    return handler


def counter(calls: dict, hosts: dict):
    def on_request(req):
        if req.method == "POST" and any(h in req.url for h in hosts.values()):
            calls["n"] += 1

    return on_request


PROBE = """() => {
  const card = document.getElementById('card');
  const pay  = document.getElementById('pay');
  const qr   = document.querySelector('#qr img, #qr canvas');
  const text = card ? card.innerText.replace(/\\s+/g, ' ').trim() : '';
  const doc  = document.scrollingElement;
  return {
    lang:      document.documentElement.lang,
    cardClass: card ? card.className : null,
    payable:   !!pay && pay.offsetParent !== null,
    qr:        !!qr,
    // A hostile reference has no break opportunity in it, so this is the number that says whether
    // the detail line wrapped or widened the whole document.
    docOverflow: doc.scrollWidth - doc.clientWidth,
    text:      text,
  };
}"""

# name, reference, lang, serve a settlement?, must the Pay button survive?, phrases that must appear
#
# The two control rows are the point of the file. `valid-unpaid` is the happy path the demo films,
# and `valid-settled` is the guard the refusal must not have displaced.
CASES = [
    (
        "no-reference",
        None,
        "pt",
        False,
        False,
        ["conferido on-chain", "não traz a referência"],
    ),
    (
        "no-reference-en",
        None,
        "en",
        False,
        False,
        ["checked against the chain", "no order reference"],
    ),
    (
        "malformed-chars",
        MALFORMED_CHARS,
        "pt",
        False,
        False,
        ["conferido on-chain", MALFORMED_CHARS],
    ),
    ("malformed-long", MALFORMED_LONG, "pt", False, False, ["conferido on-chain"]),
    (
        "malformed-surrogate",
        MALFORMED_SURROGATE,
        "pt",
        False,
        False,
        ["conferido on-chain", "z" * 63 + "\U0001f600"],
    ),
    ("valid-unpaid", VALID_REFERENCE, "pt", False, True, ["Mesa 4"]),
    (
        "valid-settled",
        VALID_REFERENCE,
        "pt",
        True,
        False,
        ["já foi pago", f"{CHAIN_AMOUNT} USDC"],
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--viewport", choices=sorted(VIEWPORTS), default="desktop")
    ap.add_argument("--shots", default=None, help="directory to write frames into")
    args = ap.parse_args()

    if not (PAGE_DIR / "index.html").exists():
        print(f"FAIL  no built page at {PAGE_DIR / 'index.html'}", file=sys.stderr)
        print("      run: python webshop-pay/build.py", file=sys.stderr)
        return 2
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "FAIL  playwright is not installed:  pip install playwright",
            file=sys.stderr,
        )
        return 2

    merchant = read_pin(MERCHANT_MARKER)
    hosts = {
        "primary": read_pin(RPC_MARKER).split("//", 1)[1].split("/")[0],
        "proxy": read_pin(PROXY_MARKER).split("//", 1)[1].split("/")[0],
    }
    print(f"pinned merchant : {merchant}")
    print(f"intercepting    : {hosts['primary']}, {hosts['proxy']}")

    profile = VIEWPORTS[args.viewport]
    vw, vh = profile["viewport"]["width"], profile["viewport"]["height"]
    print(f"viewport        : {args.viewport}  {vw}x{vh}")
    print(
        f"link asks for   : {LINK_AMOUNT} USDC   served settlement: {CHAIN_AMOUNT} USDC"
    )

    shots = Path(args.shots).resolve() if args.shots else None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)

    srv, port = serve()
    failures: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chrome")
            for name, reference, lang, settled, want_payable, must_show in CASES:
                page = browser.new_page(**profile)
                calls = {"n": 0}

                # Counted on the REQUEST event rather than inside the route handler, so a request
                # that somehow escapes the globs is still seen. The globs then answer it, which is
                # what keeps the run hermetic.
                page.on("request", counter(calls, hosts))
                for h in hosts.values():
                    page.route(f"**{h}**", rpc_handler(settled, merchant))

                page.goto(
                    f"http://127.0.0.1:{port}{pay_url(reference, LINK_AMOUNT, lang)}"
                )
                # Long enough for the settlement lookup and its one escalation to land.
                page.wait_for_timeout(3000)
                r = page.evaluate(PROBE)

                print(f"\n--- {name} ---")
                print(f"  class={r['cardClass']}  payable={r['payable']}  qr={r['qr']}")
                print(f"  rpc requests: {calls['n']}")
                print(f"  document overflow: +{r['docOverflow']}px")
                print(f"  on screen: {r['text'][:200]}")

                if r["payable"] != want_payable:
                    failures.append(
                        f"{name}: expected payable={want_payable}, got {r['payable']}"
                    )
                if r["docOverflow"] > 1:
                    failures.append(
                        f"{name}: the page scrolls sideways (+{r['docOverflow']}px)"
                    )
                for phrase in must_show:
                    if phrase not in r["text"]:
                        failures.append(f"{name}: the card does not show {phrase!r}")

                if want_payable:
                    if not r["qr"]:
                        failures.append(
                            f"{name}: the QR did not render on a payable link"
                        )
                    if LINK_AMOUNT not in r["text"]:
                        failures.append(
                            f"{name}: the payable card does not show {LINK_AMOUNT}"
                        )

                # The reference cases must never touch an endpoint; the control cases must. Both
                # halves are asserted, because one without the other is not a measurement.
                if reference is None or reference in (
                    MALFORMED_CHARS,
                    MALFORMED_LONG,
                    MALFORMED_SURROGATE,
                ):
                    if calls["n"] != 0:
                        failures.append(
                            f"{name}: {calls['n']} request(s) reached an RPC host; a reference "
                            "this page cannot look up must never be sent to one"
                        )
                elif calls["n"] < 1:
                    failures.append(
                        f"{name}: 0 requests reached an RPC host, so the zero asserted on the "
                        "refusal cases above is not evidence -- the counter never fires at all"
                    )

                if name == "malformed-long":
                    if MALFORMED_LONG in r["text"]:
                        failures.append(
                            f"{name}: the card echoes all {len(MALFORMED_LONG)} characters of the "
                            "reference; the echo is supposed to be capped"
                        )
                    if MALFORMED_LONG[:ECHO_CAP] not in r["text"]:
                        failures.append(
                            f"{name}: the card does not show the first {ECHO_CAP} characters of "
                            "the reference, so the customer cannot see which link is wrong"
                        )
                if name == "valid-settled":
                    if LINK_AMOUNT in r["text"]:
                        failures.append(
                            f"{name}: the card shows the link's {LINK_AMOUNT}, so the figure is an "
                            "echo of the request rather than the settlement"
                        )
                    if SETTLED_SIG not in r["text"]:
                        failures.append(
                            f"{name}: no settling signature on the already-paid card"
                        )

                if shots:
                    out = shots / f"reference-required-{name}-{vw}x{vh}.png"
                    page.screenshot(path=str(out))
                    print(f"  frame: {out.name}")
                page.close()

            # THE MUTATION CONTROL. Everything above is consistent with a page that refuses a
            # reference-less link for some reason that has nothing to do with the branch under
            # test, and with a harness that cannot tell a refusal from a payable card at all.
            # This serves the SAME built page with only that branch neutralised and requires the
            # reference-less link to become payable again. If it does not, the six results above
            # are measuring something else and the suite must not report a pass.
            built = (PAGE_DIR / "index.html").read_text(encoding="utf-8")
            if built.count(BRANCH_ANCHOR) != 1:
                print(
                    f"FAIL  the control anchor {BRANCH_ANCHOR!r} appears "
                    f"{built.count(BRANCH_ANCHOR)} time(s) in the built page; expected exactly "
                    "one. A control keyed to a string that has moved silently tests nothing.",
                    file=sys.stderr,
                )
                return 2
            mutated = built.replace(BRANCH_ANCHOR, "}else if(false){", 1)
            page = browser.new_page(**profile)
            mcalls = {"n": 0}
            page.on("request", counter(mcalls, hosts))
            for h in hosts.values():
                page.route(f"**{h}**", rpc_handler(False, merchant))
            page.route(
                "**/index.html*",
                lambda route: route.fulfill(
                    status=200, content_type="text/html", body=mutated
                ),
            )
            page.goto(f"http://127.0.0.1:{port}{pay_url(None, LINK_AMOUNT, 'pt')}")
            page.wait_for_timeout(3000)
            c = page.evaluate(PROBE)
            print("\n--- CONTROL: no-reference, branch neutralised ---")
            print(f"  class={c['cardClass']}  payable={c['payable']}  qr={c['qr']}")
            print(f"  rpc requests: {mcalls['n']}")
            print(f"  on screen: {c['text'][:160]}")
            if not c["payable"]:
                failures.append(
                    "control: a reference-less link is STILL refused with the branch removed, so "
                    "the refusal the cases above observed is not coming from the branch this "
                    "file exists to test"
                )
            page.close()
            browser.close()
    finally:
        srv.shutdown()

    print()
    if failures:
        for f in failures:
            print(f"FAIL  {f}", file=sys.stderr)
        return 1
    print(
        "PASS  the page discriminates on whether it can CHECK the link, not on the link:"
    )
    print(
        "      a missing or malformed reference is refused without any endpoint being"
    )
    print(
        "      contacted, while a well-formed one still pays when unsettled and still"
    )
    print(
        "      lands on the already-paid card, with the chain's figure, when settled."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
