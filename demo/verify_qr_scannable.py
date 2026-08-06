#!/usr/bin/env python3
"""Prove the pay page's QR is machine-readable, with two independent decoders.

WHY THIS EXISTS. On 2026-08-06 the operator scanned the pay page from a desktop screen with
Solflare's in-app scanner and nothing happened. His phone's system scanner read the same code
fine and opened Solflare correctly, so the payload was valid and the failure was the reader.
That is a resolution problem, not an encoding one, and it lands on the exact beat the bounty
listing describes by name: "a phone screen ... the agent replies with a QR. A customer wallet
pays it."

Looking at a QR tells you nothing. The only question is whether a DECODER accepts it, so this
runs two that do not share an implementation: pyzbar (zbar, C) and OpenCV's QRCodeDetector.
Agreement between them is the pass; either one alone can be fooled by a marginal render.

WHAT CHANGED, and why the numbers below are the ones that matter:
    before  createImgTag(5,8)  -> 49 modules * 5 + 16 margin =  261 px natural, shown at 190 css
    after   createImgTag(10,8) -> 49 modules * 10 + 16 margin = 506 px natural, shown at 260 css
The old pair is a DOWNSCALE of 261 into 190, which lands module boundaries on fractional pixels
and softens every edge. The new pair downscales 506 into 260, close to a clean 2:1, and
`image-rendering: pixelated` keeps the edges square rather than blurring them.

THE CONTROL MATTERS MORE THAN THE PASS. A decoder that has never been shown to fail has not
been shown to work, so this also renders the OLD geometry at a size where both decoders should
struggle, and reports it. A run where everything passes at every size is reporting on an
instrument that cannot discriminate.

No network. Serves the built page on an ephemeral port (port 0, never a fixed one, because a
throwaway server that nobody addresses must not take a named port).
"""

from __future__ import annotations

import functools
import http.server
import socketserver
import sys
import threading
from base64 import urlsafe_b64encode
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "webshop-pay"

MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
PAY_URL = (
    f"solana:{MERCHANT}?amount=0.59&spl-token={MINT}"
    "&reference=Ap15VZt5TJPpExnezgTRYkXeTuwfXoYVpK6ZNLi7y4ZM"
    "&label=ZeroClaw%20Shop&message=Pedido"
)


def serve(directory: Path):
    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(directory)
    )
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def decode_both(png: bytes) -> tuple[str | None, str | None]:
    """Returns (pyzbar_payload, cv2_payload). None where that decoder failed."""
    import numpy as np
    import cv2
    from PIL import Image
    from pyzbar.pyzbar import decode as zbar_decode
    import io

    img = Image.open(io.BytesIO(png)).convert("RGB")

    z = zbar_decode(img)
    z_payload = z[0].data.decode("utf-8") if z else None

    arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    ok, cv_payload, _, _ = cv2.QRCodeDetector().detectAndDecodeMulti(arr)
    cv_payload = cv_payload[0] if ok and cv_payload else None

    return z_payload, cv_payload


def shoot(page, url: str) -> tuple[bytes, int, int]:
    page.goto(url, wait_until="networkidle")
    page.wait_for_selector("#qr img", timeout=10_000)
    el = page.locator("#qr img")
    box = el.bounding_box()
    return el.screenshot(), round(box["width"]), round(box["height"])


def main() -> int:
    from playwright.sync_api import sync_playwright

    index = ROOT / "index.html"
    if not index.is_file():
        print(f"FATAL missing {index}. Run webshop-pay/build.py first.")
        return 2

    encoded = urlsafe_b64encode(PAY_URL.encode()).decode()
    httpd, port = serve(ROOT)
    url = f"http://127.0.0.1:{port}/index.html?u={encoded}&lang=pt"

    failures = 0
    control_discriminated = False

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            # Desktop at 1x is the case that FAILED for him: a phone camera pointed at a monitor.
            # Phone at dpr 3 is the case the listing's own scenario describes.
            for name, vw, vh, dpr in [
                ("desktop 1x", 1280, 900, 1),
                ("phone dpr2", 390, 844, 2),
                ("phone dpr3", 390, 844, 3),
            ]:
                ctx = browser.new_context(
                    viewport={"width": vw, "height": vh}, device_scale_factor=dpr
                )
                page = ctx.new_page()
                png, css_w, css_h = shoot(page, url)
                z, c = decode_both(png)
                ctx.close()

                dev_px = css_w * dpr
                modules = 49 + 2 * 8 / 10  # v8 grid plus the margin in module units
                per_module = dev_px / modules

                z_ok = z == PAY_URL
                c_ok = c == PAY_URL
                verdict = "PASS" if (z_ok and c_ok) else "FAIL"
                if verdict == "FAIL":
                    failures += 1
                print(
                    f"  {verdict}  {name:<11} css {css_w}x{css_h}  device {dev_px}px  "
                    f"~{per_module:.1f} px/module   pyzbar {'ok' if z_ok else 'NO'}  "
                    f"cv2 {'ok' if c_ok else 'NO'}"
                )
                if not z_ok and z is not None:
                    print(f"        pyzbar decoded something ELSE: {z[:60]}")

            # CONTROL. Force the OLD display size back and confirm at least one decoder
            # degrades, so a clean sweep above is evidence rather than an instrument that
            # cannot tell the sizes apart.
            ctx = browser.new_context(
                viewport={"width": 1280, "height": 900}, device_scale_factor=1
            )
            page = ctx.new_page()
            page.goto(url, wait_until="networkidle")
            page.wait_for_selector("#qr img", timeout=10_000)
            page.eval_on_selector(
                "#qr img", "e => { e.style.width='60px'; e.style.height='60px'; }"
            )
            png = page.locator("#qr img").screenshot()
            z, c = decode_both(png)
            ctx.close()
            browser.close()

            control_discriminated = not (z == PAY_URL and c == PAY_URL)
            print(
                f"  {'ok  ' if control_discriminated else 'BAD '} control 60px   "
                f"pyzbar {'ok' if z == PAY_URL else 'NO'}  cv2 {'ok' if c == PAY_URL else 'NO'}"
                f"   {'decoders discriminate by size' if control_discriminated else 'DECODERS CANNOT FAIL, the passes above prove nothing'}"
            )
    finally:
        httpd.shutdown()

    print()
    if failures:
        print(f"FAIL  {failures} viewport(s) did not decode on both readers.")
        return 1
    if not control_discriminated:
        print(
            "FAIL  the control decoded too, so this harness cannot distinguish a bad render."
        )
        return 1
    print(
        "OK    every viewport decodes on two independent readers, and the control fails."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
