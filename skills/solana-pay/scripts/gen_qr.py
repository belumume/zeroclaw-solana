#!/usr/bin/env python3
"""Render a Solana Pay URL as a QR code PNG.

Usage: python3 tools/gen_qr.py '<solana:...url...>' '<out.png>'
Requires the `qrcode` + `pillow` packages (see QUICKSTART)."""

import sys

import qrcode


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: gen_qr.py <url> <out.png>")
    url, out = sys.argv[1], sys.argv[2]
    if not url.startswith("solana:"):
        sys.exit("refusing: not a solana: URL")
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4
    )
    qr.add_data(url)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(out)
    print(out)


if __name__ == "__main__":
    main()
