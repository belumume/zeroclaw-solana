#!/usr/bin/env python3
"""Prove the pay path loads its CODE from this origin and never from a CDN.

WHY THIS EXISTS. The desktop "Conectar carteira e pagar" button used to `import()`
@solana/web3.js from esm.sh at click time. That 802-byte stub pulls in seventeen further
esm.sh modules, so one click fanned out into 18+ third-party requests. Any shield, ad
blocker, corporate proxy or strict CSP kills the first one, and the page then renders
"o pagamento nao foi concluido" -- a payment-failed message on a page that is fine, for a
payment that never started. Reported from a real browser with wallet extensions on
2026-08-07, while esm.sh was returning HTTP 200 to the same machine.

WHAT IS ASSERTED:
  1. the vendored bundle exposes the web3 and spl namespaces app.js reaches for
  2. every symbol app.js uses is present on them, in a real browser
  3. NO SCRIPT is fetched from another origin

ASSERTION 3 IS ABOUT CODE, NOT ABOUT ALL TRAFFIC, and the distinction is the whole point.
The page legitimately calls a Solana RPC to ask the chain whether this order's reference
already settled; you cannot read a chain without one, and that endpoint is a declared,
pinned constant. A first draft of this file asserted zero third-party requests of ANY
kind, which failed on exactly that RPC call and would have pushed someone toward
"fixing" the settled-check. Code is the thing a blocker kills silently; a declared API
endpoint failing is visible and already degrades safely.

TWO CONTROLS, because a narrowed assertion that cannot fail proves nothing:
  A. the recorder must catch a deliberate cross-origin SCRIPT, or assertion 3 is void
  B. the symbol check must report a known-absent symbol as absent
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
APP = SHOP / "src" / "app.js"

# Declared, pinned data endpoints the page is DESIGNED to call. Not code.
ALLOWED_DATA_HOSTS = {"solana-rpc.publicnode.com"}

PAYABLE = (
    "solana:C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
    "?amount=0.59&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    "&reference=Ap15VZt5TJPpExnezgTRYkXeTuwfXoYVpK6ZNLi7y4ZM"
    "&label=ZeroClaw%20Shop&message=Pedido"
)

CODE_TYPES = {"script", "stylesheet"}


def serve(directory: Path):
    """Ephemeral port: a hardcoded one collides with a prior run's lingering thread."""

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


def main() -> int:
    from playwright.sync_api import sync_playwright

    src = APP.read_text(encoding="utf-8")
    # Subtract "js": it matches the string "web3.js" inside the old import URL and the
    # surrounding comment, not a symbol. A first run reported it as MISSING.
    web3_syms = sorted(set(re.findall(r"\bweb3\.([A-Za-z_$][\w$]*)", src)) - {"js"})
    spl_syms = sorted(set(re.findall(r"\bspl\.([A-Za-z_$][\w$]*)", src)))
    print(f"symbols app.js uses: {len(web3_syms)} web3, {len(spl_syms)} spl")

    offsite = re.compile(r"^https?://(?!127\.0\.0\.1|localhost)", re.I)
    seen: list[tuple[str, str]] = []  # (resource_type, url)

    srv, port = serve(SHOP)
    try:
        u = base64.b64encode(PAYABLE.encode()).decode()
        url = f"http://127.0.0.1:{port}/index.html?u={u}&lang=pt"

        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page()
            pg.on(
                "request",
                lambda r: seen.append((r.resource_type, r.url))
                if offsite.match(r.url)
                else None,
            )
            pg.goto(url, wait_until="networkidle")

            print("\n--- 1+2. the vendored bundle, in a real browser ---")
            res = pg.evaluate(
                """async ([w3, sp]) => {
                    const lib = await import('/vendor/solana-bundle.js')
                    const miss = []
                    for (const n of w3) if (!(n in (lib.web3 || {}))) miss.push('web3.' + n)
                    for (const n of sp) if (!(n in (lib.spl || {}))) miss.push('spl.' + n)
                    return {
                      exports: Object.keys(lib).sort(),
                      missing: miss,
                      control: ('ZzNotARealSymbol' in (lib.web3 || {})),
                      pk: new lib.web3.PublicKey(
                            'C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ').toBase58(),
                    }
                }""",
                [web3_syms, spl_syms],
            )
            print("  exports :", ", ".join(res["exports"]))
            print("  missing :", res["missing"] or "none")
            print(
                "  control B, ZzNotARealSymbol present:",
                res["control"],
                "(must be False)",
            )
            print("  PublicKey round-trip:", res["pk"])

            print("\n--- 3. what left this origin, split by kind ---")
            code = [(t, u_) for t, u_ in seen if t in CODE_TYPES]
            data = [(t, u_) for t, u_ in seen if t not in CODE_TYPES]
            for t, u_ in code:
                print(f"   CODE  [{t}] {u_[:120]}")
            for t, u_ in data:
                host = re.sub(r"^https?://([^/]+).*", r"\1", u_)
                mark = "declared" if host in ALLOWED_DATA_HOSTS else "UNDECLARED"
                print(f"   data  [{t}] {host}  ({mark})")
            print(
                f"  offsite code requests: {len(code)}   offsite data requests: {len(data)}"
            )

            undeclared = [
                u_
                for t, u_ in data
                if re.sub(r"^https?://([^/]+).*", r"\1", u_) not in ALLOWED_DATA_HOSTS
            ]

            print("\n--- control A: can the recorder see a cross-origin SCRIPT? ---")
            n_before = len([1 for t, _ in seen if t in CODE_TYPES])
            try:
                pg.evaluate(
                    "new Promise(r => {"
                    " const s = document.createElement('script');"
                    " s.src = 'https://esm.sh/@solana/web3.js@1.95.3';"
                    " s.onload = s.onerror = () => r(1);"
                    " document.head.appendChild(s); setTimeout(() => r(0), 4000); })"
                )
            except Exception as e:
                print("   probe threw:", type(e).__name__)
            n_after = len([1 for t, _ in seen if t in CODE_TYPES])
            caught = n_after - n_before
            print(
                f"  recorder caught {caught} deliberate offsite script(s) (must be >= 1)"
            )

            b.close()
    finally:
        srv.shutdown()

    clean = n_before == 0
    ok = (
        not res["missing"]
        and res["control"] is False
        and clean
        and not undeclared
        and caught >= 1
    )

    print()
    if ok:
        print("PASS  the pay path's CODE comes from this origin only.")
        print(f"      {len(web3_syms) + len(spl_syms)} symbols present in-browser,")
        print(
            "      0 offsite scripts, RPC is the declared endpoint, both controls fire."
        )
        return 0
    print("FAIL")
    if res["missing"]:
        print("  missing symbols:", res["missing"])
    if res["control"]:
        print("  control B failed: the symbol check cannot discriminate")
    if not clean:
        print(f"  {n_before} offsite CODE request(s) -- the CDN dependency is not gone")
    if undeclared:
        print("  undeclared third-party data host(s):", undeclared)
    if caught < 1:
        print(
            "  control A failed: the recorder never saw the probe, assertion 3 is void"
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
