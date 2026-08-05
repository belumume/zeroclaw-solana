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

Run it:  python demo/verify-merchant-invariant.py [--viewport desktop|phone] [--shots DIR]

--viewport desktop (the default) is the CORRECTNESS harness and its behaviour is frozen: same
geometry, same frame filenames, same pass/fail. --viewport phone renders the page the way the
opening two beats of the video will see it -- 390x844 at device_scale_factor=3, is_mobile -- and
writes both plates into .demo-assets/frames/ under names carrying the viewport.

Both modes also MEASURE the refused card's two differing characters and print the horizontal
offset between them, because the highlight overlay is keyed to that number and a claim
about it is worth nothing without the measurement beside it.

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

MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # mainnet USDC
RPC_MARKER = "api.mainnet-beta.solana.com"

# 0.25, not 25. The payer wallet holds 0.4 USDC, so 25 is not payable on mainnet at all --
# the amount is forced by the funds, not chosen for thrift. It also keeps a filmed payment
# at cents. COST, stated because it is real: the listing's own worked example is "charge
# table 4, 25 USDC", and 0.25 no longer matches that number literally. Mesa 4 and Pedido 412
# still do.
AMOUNT = "0.25"

# Two rendering profiles, not two code paths. "desktop" is the frozen correctness harness: 2x
# device scale because the frames feed a 1080p+ timeline, where a 1x capture of small type is
# exactly the softness this rebuild exists to remove. "phone" is what beats 1 and 2 actually film.
#
# is_mobile matters more than the width does. Without it Chrome lays the page out as a narrow
# desktop window and ignores the page's own <meta name=viewport>; with it the layout viewport is
# 390 CSS px, which is the only condition under which the measurement below means anything.
VIEWPORTS = {
    "desktop": {
        "viewport": {"width": 1280, "height": 900},
        "device_scale_factor": 2,
    },
    "phone": {
        "viewport": {"width": 390, "height": 844},
        "device_scale_factor": 3,
        "is_mobile": True,
        "has_touch": True,
    },
}


def pinned_merchant() -> str:
    src = (PAGE_DIR / "src" / "app.js").read_text(encoding="utf-8")
    i = src.index(MERCHANT_MARKER) + len(MERCHANT_MARKER)
    return src[i : src.index("'", i)]


def check_network_agreement() -> list[str]:
    """Fail loudly if this harness and the page disagree about the network.

    MERCHANT is read out of the page precisely so no second copy can drift. MINT cannot be
    read the same way -- the page's map holds more than one mint on purpose -- so it stays an
    explicit constant here and this asserts the page agrees with it. A harness that composes
    a devnet link against a mainnet page would still PASS the two-direction verdict, because
    the refusal keys on the recipient and never on the mint. It would pass while filming the
    wrong asset name, which is the shape of drift worth catching before a take, not after.
    """
    src = (PAGE_DIR / "src" / "app.js").read_text(encoding="utf-8")
    problems = []
    if MINT not in src:
        problems.append(
            f"the page does not know mint {MINT} (its KNOWN_MINTS map lacks it)"
        )
    if RPC_MARKER not in src:
        problems.append(
            f"the page's RPC is not {RPC_MARKER}; this harness assumes mainnet"
        )
    return problems


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
        f"solana:{recipient}?amount={AMOUNT}&spl-token={MINT}"
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
    // How much of the frame the card actually occupies. The whole argument for a phone
    // viewport is this number, so it is measured on every run rather than asserted once.
    cardBox:   card ? (b => ({w: b.width, h: b.height}))(card.getBoundingClientRect()) : null,
    // A screenshot is a viewport clip, so a card taller than the viewport yields a plate with
    // its own bottom missing. Beat A4 needs the QR whole, so the QR's box is measured too.
    qrBox:     qr ? (b => ({x: b.left, y: b.top, w: b.width, h: b.height}))(qr.getBoundingClientRect()) : null,
    viewH:     window.innerHeight,
    refused:   /RECUSADO|REFUSED/i.test(text),
    payable:   !!pay && pay.offsetParent !== null,
    payLabel:  pay ? pay.textContent.trim() : null,
    qr:        !!qr,
    text:      text.slice(0, 320),
  };
}"""


# Where the two addresses' differing characters actually land, measured rather than assumed.
#
# The refused card is ONE text node -- "o link pedia: <bad> / a loja e: <good>" -- so the two
# addresses appear stacked only as a WRAPPING outcome, never by design. Whether their differing
# characters share a column is therefore a property of the viewport width, the font and the
# prefixes, and it has to be re-measured at whatever viewport ships. Ranges are used rather than
# element boxes because a single character has no box of its own.
ALIGN = """(a) => {
  const div = document.querySelector('.recip');
  if (!div) return {ok: false, why: 'no .recip element on this page'};
  const node = div.firstChild;
  if (!node || node.nodeType !== 3) return {ok: false, why: '.recip has no leading text node'};
  const t = node.nodeValue;
  const iBad = t.indexOf(a.bad), iGood = t.indexOf(a.good);
  if (iBad < 0 || iGood < 0) return {ok: false, why: 'an address is not present in .recip'};
  if (iBad === iGood) return {ok: false, why: 'both addresses resolved to the same offset'};

  const rectAt = (off) => {
    const r = document.createRange();
    r.setStart(node, off); r.setEnd(node, off + 1);
    const list = r.getClientRects();
    if (!list.length) return null;
    const b = list[0];
    return {ch: t[off], x: b.left, y: b.top, w: b.width, h: b.height};
  };

  // The differing character is the LAST of each 44-char address; tamper() substitutes it.
  const bad  = rectAt(iBad  + a.bad.length  - 1);
  const good = rectAt(iGood + a.good.length - 1);
  if (!bad || !good) return {ok: false, why: 'a differing character has no client rect'};

  const doc = document.scrollingElement;
  return {
    ok: true,
    bad, good,
    dx: bad.x - good.x,
    dy: bad.y - good.y,
    sameLine: Math.abs(bad.y - good.y) < 1,
    // The union box is the "one rectangle covers both" claim, stated as numbers.
    union: {
      x: Math.min(bad.x, good.x),
      y: Math.min(bad.y, good.y),
      w: Math.max(bad.x + bad.w, good.x + good.w) - Math.min(bad.x, good.x),
      h: Math.max(bad.y + bad.h, good.y + good.h) - Math.min(bad.y, good.y),
    },
    scrollX: window.scrollX, scrollY: window.scrollY,
    // A 44-char base58 run has no break opportunity, so overflow here is a real shoot risk.
    recipOverflow: div.scrollWidth - div.clientWidth,
    docOverflow: doc.scrollWidth - doc.clientWidth,
  };
}"""


def report_alignment(r: dict, dsf: float) -> None:
    """Print the alignment measurement. Diagnostic only: it never gates the run."""
    print("\n--- character alignment (refused card) ---")
    if not r.get("ok"):
        print(f"  NOT MEASURED: {r.get('why')}")
        print("  the overlay cannot be planned from this run")
        return

    bad, good, u = r["bad"], r["good"], r["union"]
    print(f"  differing chars : link-wanted {bad['ch']!r}  vs  shop-is {good['ch']!r}")
    print(
        f"  link-wanted char: x={bad['x']:.2f}  y={bad['y']:.2f}  ({bad['w']:.2f}x{bad['h']:.2f} css px)"
    )
    print(
        f"  shop-is char    : x={good['x']:.2f}  y={good['y']:.2f}  ({good['w']:.2f}x{good['h']:.2f} css px)"
    )
    print(f"  delta-x         : {r['dx']:.2f} css px   ({r['dx'] * dsf:.2f} device px)")
    print(f"  delta-y         : {r['dy']:.2f} css px   (same line: {r['sameLine']})")
    print(
        f"  union box       : {u['w']:.2f}x{u['h']:.2f} css px at ({u['x']:.2f}, {u['y']:.2f})"
    )
    # Plate coordinates: an overlay is keyed to the captured PNG, not to CSS pixels.
    print(
        f"  union in plate  : {u['w'] * dsf:.0f}x{u['h'] * dsf:.0f} device px"
        f" at ({u['x'] * dsf:.0f}, {u['y'] * dsf:.0f})"
    )
    print(
        f"  overflow        : .recip +{r['recipOverflow']}px, document +{r['docOverflow']}px"
    )
    # A 1px delta is sub-pixel rounding between scrollWidth and clientWidth, not clipping.
    # The raw numbers print unconditionally above so the threshold cannot hide a real one.
    if r["recipOverflow"] > 1 or r["docOverflow"] > 1:
        print("  *** the address text is clipped or scrolls sideways at this width ***")

    if abs(r["dx"]) < 0.5:
        print("  ALIGNED. One rectangle covers both differing characters.")
    else:
        print(
            f"  *** NOT ALIGNED: the two differing characters are {abs(r['dx']):.2f} css px apart. ***"
        )
        print(
            "  *** A single highlight rectangle does NOT cover both at this viewport.        ***"
        )
        print(
            "  *** Fallback per the plan: two highlight rectangles. Less elegant, equally true. ***"
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--viewport",
        choices=sorted(VIEWPORTS),
        default="desktop",
        help="desktop (default, the frozen correctness harness) or phone (the shoot's plates)",
    )
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

    drift = check_network_agreement()
    if drift:
        for d in drift:
            print(f"FAIL  {d}", file=sys.stderr)
        print(
            "      this harness and the page disagree about the network; reconcile before filming",
            file=sys.stderr,
        )
        return 2

    good = pinned_merchant()
    bad = tamper(good)
    diff = sum(1 for a, b in zip(good, bad) if a != b)
    print(f"pinned merchant : {good}")
    print(f"tampered        : {bad}   ({diff} character differs)")
    print(f"network         : mainnet-beta   mint {MINT}   amount {AMOUNT} USDC")
    if diff != 1 or len(good) != len(bad):
        print(
            "FAIL  the tampered address must differ by exactly one character",
            file=sys.stderr,
        )
        return 2

    profile = VIEWPORTS[args.viewport]
    vw, vh = profile["viewport"]["width"], profile["viewport"]["height"]
    dsf = profile["device_scale_factor"]
    phone = args.viewport == "phone"
    tag = f"-{vw}x{vh}" if phone else ""
    print(
        f"viewport        : {args.viewport}  {vw}x{vh} css @ {dsf}x"
        f"  -> {vw * dsf}x{vh * dsf} device px"
        f"{'  is_mobile' if profile.get('is_mobile') else ''}"
    )

    srv, port = serve()
    # Phone mode exists to produce plates, so it writes them by default; desktop keeps its
    # write-nothing-unless-asked behaviour, and both frame filenames, exactly as they were.
    if args.shots:
        shots = Path(args.shots).resolve()
    elif phone:
        shots = REPO / ".demo-assets" / "frames"
    else:
        shots = None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)

    def shown(p: Path) -> str:
        """Repo-relative when it can be, because this command may be run on camera.

        Phone mode writes by default, so without this the operator's home path is printed with
        no flag at all. That has already cost this project two takes by other routes.
        """
        try:
            return str(p.relative_to(REPO)).replace("\\", "/")
        except ValueError:
            return str(p)

    failures: list[str] = []
    try:
        with sync_playwright() as p:
            # channel="chrome" uses the installed browser, so this needs no playwright download.
            browser = p.chromium.launch(channel="chrome")
            # The device scale is deliberately >1: the frames are for 1080p+ video, where a 1x
            # capture of small type is exactly the softness this rebuild exists to remove.
            page = browser.new_page(**profile)

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
                if r["cardBox"]:
                    cb = r["cardBox"]
                    print(
                        f"  card: {cb['w']:.0f}x{cb['h']:.0f} css px"
                        f"  -> {cb['w'] * dsf:.0f}x{cb['h'] * dsf:.0f} of {vw * dsf}x{vh * dsf} device px"
                        f"  ({cb['w'] * dsf / (vw * dsf) * 100:.0f}% of frame width)"
                    )
                    over = cb["h"] - r["viewH"]
                    if over > 0:
                        print(
                            f"  *** the card is {over:.0f} css px ({over * dsf:.0f} device px) TALLER"
                            f" than the {r['viewH']} px viewport: this plate is CLIPPED at the bottom ***"
                        )
                if r["qrBox"]:
                    q = r["qrBox"]
                    below = (q["y"] + q["h"]) - r["viewH"]
                    print(
                        f"  qr:   {q['w']:.0f}x{q['h']:.0f} css px at ({q['x']:.0f}, {q['y']:.0f})"
                        f"  -> {q['w'] * dsf:.0f}x{q['h'] * dsf:.0f} device px"
                        f"  [{'WHOLE in frame' if below <= 0 else f'CUT: {below:.0f} css px below the fold'}]"
                    )
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
                    out = shots / f"merchant-invariant-{name}{tag}.png"
                    page.screenshot(path=str(out))
                    print(f"  frame: {shown(out)}")

                # The alignment number the beat-1 overlay is keyed to. Only the refused card
                # carries both addresses, so only it can be measured. Diagnostic: it reports,
                # it never gates, so the correctness verdict is unchanged in both viewports.
                if want_refused:
                    report_alignment(
                        page.evaluate(ALIGN, {"good": good, "bad": bad}), dsf
                    )

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
