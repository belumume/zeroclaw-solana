#!/usr/bin/env python3
"""Prove the pay page's merchant invariant, in both directions, and capture the frames.

WHY THIS EXISTS. The checkout page pins the one address it will ever pay. An agent that has been
talked into a different recipient still composes a perfectly well-formed Solana Pay link, and the
customer's page is the last thing standing between that link and their money. So the page refuses a
recipient it does not recognise.

A refusal alone proves nothing. A page that refused EVERYTHING would produce an identical frame, so
this script drives BOTH directions and fails unless the page discriminates: the correct recipient
must be payable, and a recipient differing by a SINGLE CHARACTER must be refused. That pair is the
evidence; either half on its own is decoration.

Run it:  python demo/verify-merchant-invariant.py [--shots DIR]

Needs playwright (pip install playwright). It drives the system Chrome via channel="chrome", so no
browser download is required. Everything else is stdlib.
"""

from __future__ import annotations

import argparse
import http.server
import socketserver
import sys
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PAGE_DIR = REPO / "webshop-pay"

# Read the pinned address out of the shipped page rather than restating it here. A second copy in
# this file would drift from the page, and the drifted copy is the one a future reader trusts.
MERCHANT_MARKER = "var MERCHANT='"

MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"  # devnet USDC, named in the page's own map


def pinned_merchant() -> str:
    src = (PAGE_DIR / "src" / "app.js").read_text(encoding="utf-8")
    i = src.index(MERCHANT_MARKER) + len(MERCHANT_MARKER)
    return src[i : src.index("'", i)]


def tamper(addr: str) -> str:
    """Change exactly one character, so the difference is the smallest one that matters.

    Base58 excludes 0, O, I and l, so substituting the last character has to land inside the
    alphabet or the page would be rejecting malformed input rather than a wrong address, which is a
    weaker and less interesting claim.
    """
    last = addr[-1]
    replacement = "K" if last != "K" else "L"
    return addr[:-1] + replacement


def pay_url(recipient: str, lang: str = "pt") -> str:
    from urllib.parse import quote

    solana = (
        f"solana:{recipient}?amount=25&spl-token={MINT}"
        f"&label={quote('Mesa 4')}&message={quote('Pedido 412')}"
    )
    return f"/index.html?lang={lang}&url={quote(solana, safe='')}"


def serve() -> tuple[socketserver.TCPServer, int]:
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(PAGE_DIR), **kw)

        def log_message(self, *a):  # silence; the harness owns the output
            pass

    socketserver.TCPServer.allow_reuse_address = True
    # Port 0: this server is addressed by nobody but this script, so it must not claim a named port.
    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


PROBE = """() => {
  const card = document.getElementById('card');
  const pay  = document.getElementById('pay');
  const qr   = document.querySelector('#qr img, #qr canvas');
  const text = card ? card.innerText.replace(/\\s+/g, ' ').trim() : '';
  return {
    lang:      document.documentElement.lang,
    title:     document.title,
    cardClass: card ? card.className : null,
    refused:   /RECUSADO|REFUSED/i.test(text),
    payable:   !!pay && pay.offsetParent !== null,
    payLabel:  pay ? pay.textContent.trim() : null,
    qr:        !!qr,
    text:      text.slice(0, 320),
  };
}"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--shots", default=None, help="directory to write the two frames into"
    )
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

    good = pinned_merchant()
    bad = tamper(good)
    diff = sum(1 for a, b in zip(good, bad) if a != b)
    print(f"pinned merchant : {good}")
    print(f"tampered        : {bad}   ({diff} character differs)")
    if diff != 1 or len(good) != len(bad):
        print(
            "FAIL  the tampered address must differ by exactly one character",
            file=sys.stderr,
        )
        return 2

    srv, port = serve()
    shots = Path(args.shots).resolve() if args.shots else None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    try:
        with sync_playwright() as p:
            # channel="chrome" uses the installed browser, so this needs no playwright download.
            browser = p.chromium.launch(channel="chrome")
            # 2x device scale: the frames are for 1080p+ video, where a 1x capture of small type
            # is exactly the softness this rebuild exists to remove.
            page = browser.new_page(
                viewport={"width": 1280, "height": 900}, device_scale_factor=2
            )

            for name, addr, want_refused in (
                ("payable", good, False),
                ("refused", bad, True),
            ):
                page.goto(f"http://127.0.0.1:{port}{pay_url(addr)}")
                page.wait_for_timeout(700)
                r = page.evaluate(PROBE)

                print(f"\n--- {name} ---")
                print(f"  lang={r['lang']}  title={r['title']}  class={r['cardClass']}")
                print(f"  refused={r['refused']}  payable={r['payable']}  qr={r['qr']}")
                print(f"  on screen: {r['text'][:200]}")

                if r["refused"] != want_refused:
                    failures.append(
                        f"{name}: expected refused={want_refused}, got {r['refused']}"
                    )
                if r["payable"] == want_refused:
                    failures.append(
                        f"{name}: pay button visibility is wrong ({r['payable']})"
                    )
                if r["lang"] != "pt-BR":
                    failures.append(
                        f"{name}: expected pt-BR localisation, got {r['lang']!r}"
                    )
                if not want_refused and not r["qr"]:
                    failures.append("payable: the QR did not render")
                if want_refused and good not in r["text"]:
                    failures.append(
                        "refused: the real shop address is not shown next to the bad one"
                    )

                if shots:
                    out = shots / f"merchant-invariant-{name}.png"
                    page.screenshot(path=str(out))
                    print(f"  frame: {out}")

            browser.close()
    finally:
        srv.shutdown()

    print()
    if failures:
        for f in failures:
            print(f"FAIL  {f}", file=sys.stderr)
        return 1

    print("PASS  the page discriminates on one character:")
    print(
        "      the pinned recipient is payable, and a one-character variant is refused"
    )
    print("      with both addresses shown in full, in Portuguese.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
