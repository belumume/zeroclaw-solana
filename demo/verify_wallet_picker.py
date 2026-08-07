#!/usr/bin/env python3
"""Prove the pay page lets the customer CHOOSE a wallet, and that choosing costs no layout.

WHY THIS EXISTS. Until 2026-08-07 the page resolved a wallet with one line:

    var provider=(window.phantom&&window.phantom.solana)||window.solflare||window.solana;

A fixed priority chain. `window.solana` is last-writer-wins across every injected extension, so the
customer got whichever won an invisible race. Measured in the operator's Brave: window.phantom
absent, window.solflare absent, window.solana present with isPhantom TRUE, which is Brave Wallet
masquerading as Phantom -- so even an isPhantom check cannot tell them apart. He clicked pay and was
connected to Brave with no prompt and no choice.

A Wallet Standard picker had been built for this on 2026-07-23 and destroyed on 2026-07-24 by a
commit about payer preflight that never mentions wallets, because it lived in the GENERATED
index.html rather than in src/. This harness exists so that cannot recur silently.

WHAT IS ASSERTED, and the second one is the regression that killed the first attempt:
  1. Several wallets -> a picker appears ON CLICK, listing every one of them.
  2. The card's rendered height at load is IDENTICAL with and without wallets present. The original
     listed wallets on load and pushed the QR below the fold; deferring to the click is what keeps
     the phone plate the opening shot is keyed to from moving.
  3. Exactly one wallet -> NO picker. A picker with one option is a pointless click.
  4. Zero wallets -> the existing no-wallet message, unchanged.
  5. base58 encoding round-trips a known vector, including leading zero bytes, which is the part a
     naive implementation drops and which would silently corrupt a signature.

CONTROL: assertion 1 is only meaningful if the page can FAIL it, so the run also drives a build with
the picker disabled and requires no picker to appear.
"""

from __future__ import annotations

import base64
import http.server
import re
import socketserver
import sys
import threading
from pathlib import Path

SHOP = Path(__file__).resolve().parent.parent / "webshop-pay"

PAYABLE = (
    "solana:C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
    "?amount=0.39&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    "&reference=FL3tB2wQ7xKZmYQ8sVJqLxHc4nEeRk9wPzYvBdGtNaXu"
    "&label=ZeroClaw%20Shop&message=Pedido"
)

# Two fake Wallet Standard wallets. Registered the way a real extension registers: by listening for
# the app-ready event the page dispatches. Nothing is stubbed inside the page itself.
FAKE_WALLETS = """
(function(names){
  var mk = function(n){ return {
    name: n, version: '1.0.0', icon: 'data:image/svg+xml;base64,PHN2Zy8+', chains: ['solana:mainnet'],
    accounts: [],
    features: {
      'standard:connect': { version:'1.0.0', connect: async function(){ return {accounts:[]}; } },
      'solana:signAndSendTransaction': { version:'1.0.0', signAndSendTransaction: async function(){ return [{signature:new Uint8Array(64)}]; } }
    }
  };};
  var ws = names.map(mk);
  window.addEventListener('wallet-standard:app-ready', function(e){
    ws.forEach(function(w){ try { e.detail.register(w); } catch(_){} });
  });
})(%NAMES%);
"""


def serve(directory: Path):
    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(directory), **k)

        def log_message(self, *a):
            pass

    class S(socketserver.TCPServer):
        allow_reuse_address = True

    srv = S(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def b58_reference(raw: bytes) -> str:
    """Independent base58, so the page's encoder is checked against something, not itself."""
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alpha[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def main() -> int:
    from playwright.sync_api import sync_playwright

    src = (SHOP / "src" / "app.js").read_text(encoding="utf-8")
    if "enumerateWallets" not in src:
        print(
            "FAIL  src/app.js has no enumerateWallets. The picker is not in SOURCE, which is"
        )
        print(
            "      exactly how it was lost last time: written into the generated file only."
        )
        return 1

    srv, port = serve(SHOP)
    results: list[tuple[str, bool, str]] = []
    try:
        u = base64.b64encode(PAYABLE.encode()).decode()
        url = f"http://127.0.0.1:{port}/index.html?u={u}&lang=pt"

        with sync_playwright() as p:
            b = p.chromium.launch()

            def run(names: list[str], viewport=None):
                ctx = b.new_context(viewport=viewport or {"width": 1280, "height": 900})
                pg = ctx.new_page()
                if names:
                    pg.add_init_script(
                        FAKE_WALLETS.replace("%NAMES%", str(names).replace("'", '"'))
                    )
                pg.goto(url, wait_until="networkidle")
                card_h = pg.evaluate(
                    "document.getElementById('card').getBoundingClientRect().height"
                )
                qr = pg.evaluate("!!document.querySelector('#qr img')")
                pg.click("#pay")
                pg.wait_for_timeout(600)
                btns = pg.eval_on_selector_all(
                    ".wallet-btn span", "els => els.map(e => e.textContent)"
                )
                status = pg.evaluate(
                    "(document.getElementById('status')||{}).textContent || ''"
                )
                ctx.close()
                return card_h, qr, btns, status

            # 1. several wallets -> picker on click, naming both
            h2, qr2, btns2, _ = run(["Phantom", "Solflare"])
            ok = sorted(btns2) == ["Phantom", "Solflare"]
            results.append(("two wallets -> picker lists both", ok, f"got {btns2}"))
            results.append(("QR still rendered", qr2, ""))

            # 2. layout at LOAD is unaffected by wallets being present
            h0, qr0, btns0, st0 = run([])
            results.append(
                (
                    "card height identical at load, wallets vs none",
                    abs(h2 - h0) < 0.5,
                    f"{h2:.1f} vs {h0:.1f}",
                )
            )

            # 3. zero wallets -> the existing message, no picker
            results.append(("no wallets -> no picker", btns0 == [], f"got {btns0}"))
            results.append(
                ("no wallets -> message shown", "wallet" in st0.lower(), st0[:60])
            )

            # 4. exactly one -> no picker, straight through
            _, _, btns1, st1 = run(["Phantom"])
            results.append(
                (
                    "one wallet -> no picker, connects directly",
                    btns1 == [],
                    f"got {btns1}",
                )
            )

            # 4b. A wallet that registers via Wallet Standard AND injects window.solana is ONE
            # wallet and must be listed once. Missed entirely by the fakes above, because they only
            # register; found by driving the live page in a real Brave, which does both and came
            # back as "Brave Wallet" plus "Injected wallet". The dedupe keys on name, so two names
            # for one extension slipped through it.
            ctx = b.new_context()
            pgd = ctx.new_page()
            pgd.add_init_script(FAKE_WALLETS.replace("%NAMES%", '["DualWallet"]'))
            pgd.add_init_script(
                "window.solana={isDual:true,connect:async()=>({publicKey:null})};"
            )
            pgd.goto(url, wait_until="networkidle")
            pgd.click("#pay")
            pgd.wait_for_timeout(500)
            dual = pgd.eval_on_selector_all(
                ".wallet-btn span", "els => els.map(e => e.textContent)"
            )
            # One registered wallet plus its own injected global collapses to a direct connect,
            # so there is no picker at all rather than a picker with a phantom duplicate in it.
            results.append(
                (
                    "registered wallet + its injected global counts ONCE",
                    dual == [],
                    f"got {dual}",
                )
            )
            ctx.close()

            # 4c. EIGHT wallets must not push the QR out of view, and the two-wallet cases above
            # are structurally blind to this: the list grows ~50px per wallet, so the defect only
            # appears past about four. Measured in the operator's own Brave, which registers eight:
            # the card grew 887 -> 1286 and the QR's bottom edge landed at 972 against a 900-tall
            # viewport. His window happened to be 982 tall and cleared it by ten pixels, which is
            # the only reason he did not hit it. The phone path must stay reachable after the
            # picker opens, however many wallets are installed.
            EIGHT = [
                "Backpack",
                "Brave Wallet",
                "Phantom",
                "MetaMask",
                "Magic Eden",
                "Solflare",
                "Jupiter",
                "Glow",
            ]
            for vw, vh in ((1280, 900), (390, 844)):
                ctx = b.new_context(viewport={"width": vw, "height": vh})
                p8 = ctx.new_page()
                p8.add_init_script(
                    FAKE_WALLETS.replace("%NAMES%", str(EIGHT).replace("'", '"'))
                )
                p8.goto(url, wait_until="networkidle")
                p8.click("#pay")
                p8.wait_for_timeout(600)
                geo = p8.evaluate("""() => {
                  var q = document.querySelector('#qr img');
                  var r = q ? q.getBoundingClientRect() : null;
                  return {n: document.querySelectorAll('.wallet-btn').length,
                          bottom: r ? r.bottom : null, vh: window.innerHeight};
                }""")
                ok = (
                    geo["n"] == 8
                    and geo["bottom"] is not None
                    and geo["bottom"] <= geo["vh"]
                )
                results.append(
                    (
                        f"8 wallets -> QR still fully in view at {vw}x{vh}",
                        ok,
                        f"{geo['n']} listed, qr bottom {geo['bottom']} vs vh {geo['vh']}",
                    )
                )
                ctx.close()

            # 4d. The list is height-capped, so the wallet the customer last used must be hoisted
            # to the top rather than left wherever registration order put it. Solflare is 6th of
            # the eight above and would sit below the fold of its own scrolling box.
            ctx = b.new_context()
            ph = ctx.new_page()
            ph.add_init_script(
                FAKE_WALLETS.replace("%NAMES%", str(EIGHT).replace("'", '"'))
            )
            ph.add_init_script(
                "try{localStorage.setItem('zeroclaw_last_wallet','Solflare')}catch(e){}"
            )
            ph.goto(url, wait_until="networkidle")
            ph.click("#pay")
            ph.wait_for_timeout(600)
            order = ph.eval_on_selector_all(
                ".wallet-btn span", "els => els.map(e => e.textContent)"
            )
            badge = ph.eval_on_selector_all(
                ".wallet-btn .lastused", "els => els.length"
            )
            results.append(
                (
                    "last-used wallet is hoisted to the top of the capped list",
                    order[:1] == ["Solflare"] and badge == 1,
                    f"order starts {order[:2]}, {badge} badge(s)",
                )
            )
            ctx.close()

            # 5. base58, including leading zeros
            pg = b.new_page()
            pg.goto(url, wait_until="networkidle")
            vectors = [
                bytes(range(1, 33)),
                b"\x00\x00" + bytes(range(1, 31)),
                bytes(64),
            ]
            b58_ok = True
            for v in vectors:
                got = pg.evaluate("bs => b58(new Uint8Array(bs))", list(v))
                want = b58_reference(v)
                if got != want:
                    b58_ok = False
                    results.append(
                        ("base58 vector", False, f"got {got[:20]} want {want[:20]}")
                    )
            if b58_ok:
                results.append(
                    (
                        f"base58 matches an independent encoder on {len(vectors)} vectors",
                        True,
                        "",
                    )
                )

            # CONTROL: with the picker neutered, assertion 1 must fail.
            ctx = b.new_context()
            pgc = ctx.new_page()
            pgc.add_init_script(
                FAKE_WALLETS.replace("%NAMES%", '["Phantom", "Solflare"]')
            )
            pgc.add_init_script("window.__killPicker=1")
            pgc.goto(url, wait_until="networkidle")
            pgc.evaluate("window.enumerateWallets = function(){ return [] }")
            pgc.click("#pay")
            pgc.wait_for_timeout(400)
            ctl = pgc.eval_on_selector_all(".wallet-btn", "e => e.length")
            results.append(
                (
                    "CONTROL: neutered enumeration renders no picker",
                    ctl == 0,
                    f"got {ctl}",
                )
            )
            ctx.close()

            b.close()
    finally:
        srv.shutdown()

    bad = [r for r in results if not r[1]]
    for name, ok, note in results:
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}{('   ' + note) if note else ''}")
    print()
    if bad:
        print(f"FAIL  {len(bad)} of {len(results)}")
        return 1
    print(
        f"PASS  {len(results)}/{len(results)}. The customer chooses, and choosing costs no layout."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
