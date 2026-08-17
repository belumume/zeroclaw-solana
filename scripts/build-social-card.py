#!/usr/bin/env python3
"""Render docs/assets/social-preview.png, the og:image, from source instead of an image editor.

WHY THIS EXISTS. build-field-card.py's own docstring names the defect this file closes, verbatim:
"`docs/assets/social-preview.png` is 2560x1280 and has no generator anywhere in the tree, so nobody
can change a word of it without opening an image editor and matching the typography by eye. That is
the failure this file avoids." The consequence was measurable rather than theoretical: on 2026-08-17
the card still read "887 on-chain publishes / 0 failed / 12 days" while the chain said 1,661
signatures, 0 failed, across 23.7 days. It is wired as og:image, twitter:image AND the video poster
in index.html, so it is what renders in every social share of this repo.

THE FIGURES ARE MEASURED, NOT TYPED. --refresh paginates getSignaturesForAddress for the ARM feed
PDA and counts signatures, failures and the true span, with a positive control (the oracle program
must come back executable) so an all-clean scan cannot be confused with a broken query. Without
--refresh it renders the pinned values below, so a build is reproducible offline.

AND THE FACE CARRIES ITS MEASUREMENT DATE, which is the durable half. A count without a date reads
as current forever and silently becomes false; field-card.png already stamps one for exactly this
reason and this card did not. Every figure here decays, so the stamp is what keeps it honest
between refreshes.

FONTS. No font is bundled, so one is resolved from a candidate list ordered by how close it sits to
the original hand-set face, and the resolved family is PRINTED. A silent fallback would render in
whatever the platform offers and report success, which is how an artifact ships degraded with
nothing to indicate it.

    python3 scripts/build-social-card.py --out /tmp/preview.png    # render beside the original
    python3 scripts/build-social-card.py --refresh                 # re-measure, then render
"""

import argparse
import json
import pathlib
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets" / "social-preview.png"

W, H = 2560, 1280
MARGIN = 160  # measured off the original: first non-background column
RULE_H = 14  # measured off the original

# Sampled from the shipped card rather than guessed, so a re-render matches the palette exactly.
BG = (0x0D, 0x11, 0x17)
GREEN = (0x14, 0xF1, 0x95)  # Solana green; the top rule and the headline accent
TEXT = (0xE6, 0xED, 0xF3)
BODY = (0x91, 0x98, 0xA1)
LABEL = (0x7D, 0x85, 0x90)
PURPLE = (
    0x99,
    0x45,
    0xFF,
)  # Solana brand purple, the left end of the wordmark gradient

# Pinned figures. --refresh overwrites these from chain. Keep the date beside them: a count with no
# date is the whole defect this generator exists to close.
FIGURES = {
    "publishes": "1,661",
    "failed": "0",
    "span": "23 days",
    "stamp": "figures verified 2026-08-17",
}

RPC = "https://api.devnet.solana.com"
FEED_PDA = "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg"
ORACLE = "EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn"

HEADLINE = [
    ("A shop takes orders on WhatsApp and", None),
    ("settles in ", None),
    ("mainnet USDC", GREEN),
    (".", None),
]
BODY_TEXT = [
    [
        (
            "The agent holds no key that can move money. The spend ceiling is enforced by an",
            BODY,
        )
    ],
    [
        ("audited on-chain program we did not write and cannot change", TEXT),
        (". The same box sells", BODY),
    ],
    [("its own signed readings to other machines behind an HTTP 402 paywall.", BODY)],
]
REPO_URL = "github.com/belumume/zeroclaw-solana"
FOOTER = "self-hosted  ·  Rust  ·  one binary"

# Ordered by closeness to the original humanist face. Arial is last: it is a grotesque and reads
# visibly tighter, so picking it silently would be the degraded-render case above.
FONT_SETS = [
    ("Segoe UI", "C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf"),
    (
        "Noto Sans",
        "C:/Windows/Fonts/NotoSans-Regular.ttf",
        "C:/Windows/Fonts/NotoSans-Bold.ttf",
    ),
    (
        "DejaVu Sans",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ),
    ("Arial", "C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
]


def resolve_fonts():
    for name, reg, bold in FONT_SETS:
        if pathlib.Path(reg).exists() and pathlib.Path(bold).exists():
            print(f"  font: {name}  ({reg})")
            return reg, bold
    sys.exit("no usable font found; refusing to render in an unknown face")


def rpc(method, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        RPC,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


def refresh():
    """Re-measure from chain. Positive control first, or a clean scan proves nothing."""
    ctl = rpc("getAccountInfo", [ORACLE, {"encoding": "base64"}])["result"]["value"]
    if not (ctl and ctl.get("executable")):
        sys.exit(
            "CONTROL FAILED: the oracle program did not come back executable; refusing to trust a scan"
        )
    print("  control: oracle program executable=True")

    total = failed = 0
    before = None
    oldest = newest = None
    while True:
        p = {"limit": 1000}
        if before:
            p["before"] = before
        res = rpc("getSignaturesForAddress", [FEED_PDA, p]).get("result") or []
        if not res:
            break
        for s in res:
            total += 1
            if s.get("err") is not None:
                failed += 1
            if newest is None:
                newest = s.get("blockTime")
            oldest = s.get("blockTime")
        before = res[-1]["signature"]
        if len(res) < 1000:
            break
        time.sleep(0.35)

    days = int((newest - oldest) / 86400) if (oldest and newest) else 0
    FIGURES["publishes"] = f"{total:,}"
    FIGURES["failed"] = str(failed)
    FIGURES["span"] = f"{days} days"
    FIGURES["stamp"] = f"figures verified {time.strftime('%Y-%m-%d', time.gmtime())}"
    print(f"  measured: {total:,} signatures, {failed} failed, {days} days")
    if failed:
        print(
            "  NOTE: failures are non-zero, so the card no longer reads '0 failed'. That is the point."
        )


def gradient_text(img, draw, xy, text, font, c0, c1):
    """The 'Solana' wordmark is a gradient in the original, not a flat fill. Render the text into a
    mask and paint a horizontal ramp through it, which is the only way to match it."""
    from PIL import Image, ImageDraw

    # Pillow 11 returns floats here; Image.new and paste both need ints.
    box = tuple(int(v) for v in draw.textbbox(xy, text, font=font))
    w, h = box[2] - box[0], box[3] - box[1]
    if w <= 0 or h <= 0:
        return
    ramp = Image.new("RGB", (w, h))
    rd = ImageDraw.Draw(ramp)
    for x in range(w):
        t = x / max(w - 1, 1)
        rd.line(
            [(x, 0), (x, h)],
            fill=tuple(int(c0[i] + (c1[i] - c0[i]) * t) for i in range(3)),
        )
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).text(
        (xy[0] - box[0], xy[1] - box[1]), text, font=font, fill=255
    )
    img.paste(ramp, (box[0], box[1]), mask)


def render(out_path):
    from PIL import Image, ImageDraw, ImageFont

    reg_path, bold_path = resolve_fonts()
    f = lambda p, s: ImageFont.truetype(p, s)

    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, RULE_H], fill=GREEN)

    # wordmark
    f_mark = f(bold_path, 62)
    d.text((MARGIN, 152), "ZeroClaw", font=f_mark, fill=TEXT)
    x = MARGIN + d.textlength("ZeroClaw", font=f_mark) + 40
    f_x = f(reg_path, 44)
    d.text((x, 170), "\u00d7", font=f_x, fill=LABEL)
    x += d.textlength("\u00d7", font=f_x) + 40
    gradient_text(img, d, (x, 152), "Solana", f_mark, PURPLE, GREEN)

    # headline, two lines, accent inline
    f_head = f(bold_path, 116)
    y = 330
    d.text((MARGIN, y), HEADLINE[0][0], font=f_head, fill=TEXT)
    y += 132
    x = MARGIN
    for txt, col in HEADLINE[1:]:
        d.text((x, y), txt, font=f_head, fill=col or TEXT)
        x += d.textlength(txt, font=f_head)

    # body
    f_body = f(reg_path, 52)
    f_body_b = f(bold_path, 52)
    y = 630
    for line in BODY_TEXT:
        x = MARGIN
        for txt, col in line:
            fnt = f_body_b if col == TEXT else f_body
            d.text((x, y), txt, font=fnt, fill=col)
            x += d.textlength(txt, font=fnt)
        y += 74

    # stats
    f_stat = f(bold_path, 88)
    f_label = f(reg_path, 38)
    cols = [
        (MARGIN, FIGURES["publishes"], "on-chain publishes", GREEN),
        (MARGIN + 420, FIGURES["failed"], "failed", GREEN),
        (MARGIN + 660, FIGURES["span"], "continuous, one ARM box", TEXT),
    ]
    for cx, big, small, col in cols:
        d.text((cx, 990), big, font=f_stat, fill=col)
        d.text((cx, 1108), small, font=f_label, fill=LABEL)

    # right column
    f_url = f(bold_path, 46)
    uw = d.textlength(REPO_URL, font=f_url)
    d.text((W - MARGIN - uw, 1000), REPO_URL, font=f_url, fill=TEXT)
    fw = d.textlength(FOOTER, font=f_label)
    d.text((W - MARGIN - fw, 1070), FOOTER, font=f_label, fill=LABEL)

    # the stamp: what makes every figure above honest between refreshes
    f_stamp = f(reg_path, 32)
    sw = d.textlength(FIGURES["stamp"], font=f_stamp)
    d.text((W - MARGIN - sw, 1128), FIGURES["stamp"], font=f_stamp, fill=LABEL)

    img.save(out_path, "PNG", optimize=True)
    print(f"  wrote {out_path}  ({out_path.stat().st_size:,} B, {W}x{H})")
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=pathlib.Path, default=OUT)
    ap.add_argument(
        "--refresh", action="store_true", help="re-measure the figures from chain first"
    )
    a = ap.parse_args()
    if a.refresh:
        refresh()
    render(a.out)


if __name__ == "__main__":
    main()
