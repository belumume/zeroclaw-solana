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
import json
import socketserver
import sys
import threading
from pathlib import Path

SHOP = Path(__file__).resolve().parent.parent / "webshop-pay"

# THE OPERATOR'S MEASURED ENVIRONMENT, as data rather than as constants in this file. It is loaded
# rather than hardcoded because this harness's whole failure history is fixtures that described an
# imagined machine: the wallet list was invented twice before it was measured once, and both times
# every assertion here passed while a defect was live on the deployed page. A number in test code
# is indistinguishable from a number someone picked; a number in a profile carries its provenance
# and its measurement date with it.
#
# REFUSES rather than falling back. A default would silently restore exactly the invented fixture
# this file exists to eliminate, and the failure would look like a pass.
PROFILE_PATH = Path(__file__).resolve().parent / "operator-profile.json"
try:
    OPERATOR_PROFILE = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(
        f"cannot read {PROFILE_PATH.name}: {exc}\n"
        "This harness asserts geometry against the operator's real environment and refuses to\n"
        "invent one. Restore the profile rather than adding a default here."
    ) from exc

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
            # LANGUAGE-AGNOSTIC ON PURPOSE. The harness loads the page with `lang=pt`, so
            # asserting the English word "wallet" was testing the page's language rather than
            # its behaviour: it passed only while that string had no translation, and went red
            # the moment one was added. The behaviour under test is that a wallet-less browser
            # is TOLD SO, in whatever language the link requested, so accept either noun.
            named_a_wallet = any(w in st0.lower() for w in ("wallet", "carteira"))
            results.append(("no wallets -> message shown", named_a_wallet, st0[:60]))

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
            # appears past about four. RE-MEASURED 2026-08-16 against the live page in his own
            # profile: 67px per row, not 50, so eight rows occupy about 536px rather than 400.
            # On the LIVE page only seven of his eight render, because enumerateWallets
            # filters on feature presence and the real MetaMask exposes no Solana features.
            # THIS TEST DELIBERATELY RENDERS ALL EIGHT: FAKE_WALLETS stamps the Solana
            # features onto every name, so the fake MetaMask passes the filter. That is the
            # worst case and the right thing to assert geometry against; it is not a claim
            # about what his browser shows. At a 743px fold the live seven-row picker's last
            # row ended at 650, so the defect did not reproduce there, at one viewport.
            # The original Brave measurement below stands on its own conditions:
            # the card grew 887 -> 1286 and the QR's bottom edge landed at 972 against a 900-tall
            # viewport. His window happened to be 982 tall and cleared it by ten pixels, which is
            # the only reason he did not hit it. The phone path must stay reachable after the
            # picker opens, however many wallets are installed.
            # READ FROM THE PROFILE, not written here. `demo/operator-profile.json` carries the
            # measured environment with its provenance, so re-measuring is a data edit the harness
            # picks up rather than a code change, and so a reader can tell a measured number from
            # one somebody chose. The list was invented twice before it was measured once.
            # SHAPE, checked the same way the file read is. A profile that parses as JSON but has
            # the wrong structure would otherwise surface as a raw KeyError, which reads as a bug
            # in this harness rather than as a bad profile, and sends the reader to the wrong file.
            try:
                registered = OPERATOR_PROFILE["wallets"]["registered"]
                if not isinstance(registered, list) or not all(
                    isinstance(w, str) for w in registered
                ):
                    raise TypeError("wallets.registered must be a list of strings")
            except (KeyError, TypeError) as exc:
                raise SystemExit(
                    f"{PROFILE_PATH.name} parsed but is not shaped as a profile: {exc}\n"
                    "Expected wallets.registered to be a list of wallet-name strings."
                ) from exc
            EIGHT = list(registered)

            # THE PROFILE MUST BE BIG ENOUGH TO SEE THE DEFECT, and this guard is the whole reason
            # the profile is data rather than a constant. Deriving the count assertion from the
            # profile is right, but on its own it makes a SHRUNKEN profile pass: two wallets, two
            # rows, QR comfortably in view, green. That is exactly the blindness this harness was
            # built after -- the fixture had two wallets against his eight, the list grows 67px per
            # row, and a below-the-fold defect is unreachable until about four rows. A profile that
            # cannot exercise the failure is not a smaller test, it is a test of nothing.
            MIN_WALLETS_TO_SEE_THE_DEFECT = 4
            if len(EIGHT) < MIN_WALLETS_TO_SEE_THE_DEFECT:
                raise SystemExit(
                    f"operator-profile.json lists {len(EIGHT)} wallet(s); the tall-list geometry "
                    f"is unreachable below {MIN_WALLETS_TO_SEE_THE_DEFECT}, so this run would pass "
                    "without testing anything. Re-measure rather than lowering this floor."
                )
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
                # Count derived from the profile, not written as 8, so a re-measurement that finds
                # nine wallets tests nine. The floor above is what stops that becoming permissive.
                ok = (
                    geo["n"] == len(EIGHT)
                    and geo["bottom"] is not None
                    and geo["bottom"] <= geo["vh"]
                )
                results.append(
                    (
                        f"{len(EIGHT)} wallets -> QR still fully in view at {vw}x{vh}",
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

            # 4e. ICONS. The operator's Brave listed Magic Eden with a blank icon slot while the
            # other seven rendered. The old filter was a hardcoded list of five types each
            # requiring a semicolon, so it silently dropped a URL-encoded SVG (comma, not
            # semicolon) and anything unlisted, and a dropped icon rendered as a hole in the row.
            # Now keyed on the property that actually matters: a data: URI, which issues no
            # third-party request and cannot execute script inside an <img>. Anything else gets a
            # lettered chip, so the row is never blank whatever the wallet supplies.
            # A real 1x1 PNG, so "does the browser decode it" is a genuine question per case.
            PNG1 = (
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
                "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
            )
            ICONS = {
                "DataPng": f"data:image/png;base64,{PNG1}",
                # Magic Eden's ACTUAL declared type, read from the operator's console export
                # 2026-08-07: `data:image/png+xml`, which is not a MIME type. They appear to have
                # copied svg+xml and swapped the subtype. The bytes are a real PNG and a browser
                # sniffs and renders them, so the icon must appear rather than fall back.
                "MagicEdenShape": f"data:image/png+xml;base64,{PNG1}",
                "UrlEncodedSvg": "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E",
                # Passes the filter and CANNOT decode: png bytes declared as svg+xml, measured
                # load=false. This is why the img carries an onerror that swaps in the chip;
                # without it the row appends an image that draws nothing and suppresses the chip.
                "UndecodableDataUri": f"data:image/svg+xml;base64,{PNG1}",
                "RemoteUrl": "https://example.invalid/icon.png",
                "NoIcon": None,
            }
            js = (
                "(function(m){var ws=Object.keys(m).map(function(n){var w={name:n,version:'1.0.0',"
                "chains:['solana:mainnet'],accounts:[],features:{"
                "'standard:connect':{version:'1.0.0',connect:async function(){return{accounts:[]}}},"
                "'solana:signAndSendTransaction':{version:'1.0.0',signAndSendTransaction:async function(){return[{signature:new Uint8Array(64)}]}}}};"
                "if(m[n]!==null)w.icon=m[n];return w;});"
                "window.addEventListener('wallet-standard:app-ready',function(e){"
                "ws.forEach(function(w){try{e.detail.register(w)}catch(_){}})});})(%M%);"
            ).replace("%M%", __import__("json").dumps(ICONS))
            ctx = b.new_context()
            pi = ctx.new_page()
            pi.add_init_script(js)
            pi.goto(url, wait_until="networkidle")
            pi.click("#pay")
            pi.wait_for_timeout(600)
            rows = pi.eval_on_selector_all(
                ".wallet-btn",
                "els => els.map(e => ({name: e.querySelector('span').textContent,"
                " img: !!e.querySelector('img'), chip: (e.querySelector('.noicon')||{}).textContent || null}))",
            )
            got = {r["name"]: r for r in rows}
            for nm, want_img, want_chip in (
                ("DataPng", True, None),
                # The incident, verbatim from his console export.
                ("MagicEdenShape", True, None),
                # Passes the filter and cannot decode -> the img's onerror must swap in the chip.
                ("UndecodableDataUri", False, "U"),
                (
                    "UrlEncodedSvg",
                    True,
                    None,
                ),  # the WIDENING: this failed before, must fire now
                (
                    "RemoteUrl",
                    False,
                    "R",
                ),  # http(s) still refused, and no longer a blank slot
                ("NoIcon", False, "N"),
            ):
                r = got.get(nm)
                ok = r is not None and r["img"] is want_img and r["chip"] == want_chip
                results.append(
                    (
                        f"icon: {nm} -> {'img' if want_img else 'chip ' + str(want_chip)}",
                        ok,
                        f"got {r}",
                    )
                )
            results.append(
                (
                    "no wallet row is ever blank (every row has an img or a chip)",
                    all(r["img"] or r["chip"] for r in rows) and len(rows) == 6,
                    f"{len(rows)} rows",
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
