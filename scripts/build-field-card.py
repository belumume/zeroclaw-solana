#!/usr/bin/env python3
"""Render docs/assets/field-card.png, the one image that carries the whole argument.

WHY THIS EXISTS. Most people who meet this project will not clone it, will not run a
command, and will not open a document. The card is what they get instead: four claims,
every one of them already true and checkable somewhere else in this repo.

WHY IT IS A SCRIPT AND NOT A ONE-OFF. `docs/assets/social-preview.png` is 2560x1280 and
has no generator anywhere in the tree, so nobody can change a word of it without opening
an image editor and matching the typography by eye. That is the failure this file avoids.

WHAT IS DELIBERATELY NOT ON THE CARD. An image carries no re-derive command, so a figure
that decays becomes a confident lie with nothing attached to correct it. Every number here
is immutable history (mainnet transaction amounts, a program's error code) or a stable
address. The sequence number, the transaction count, the certifier's case count and the
reproduce-path timings are all real and all move, so none of them appears. The measurement
date is stamped on the face for the same reason.

FONTS. There is no bundled font, so one is resolved from a candidate list and the resolved
path is PRINTED. A silent fallback would render the card in whatever the platform offers
and report success, which is how an artifact ships degraded with nothing to indicate it.
Metrics differ between families, so a card built on Linux and one built on Windows are not
byte-identical. The content is.

    python3 scripts/build-field-card.py            # render
    python3 scripts/build-field-card.py --verify   # OCR the rendered card for identifiers

`--verify` needs Tesseract. It exits 2 (cannot check) rather than 0 when Tesseract is
absent, because a scan that never ran must not report the same thing as a scan that found
nothing.
"""

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets" / "field-card.png"

W, H = 1200, 1600
PAD = 64
CONTENT_W = W - 2 * PAD

BG = (13, 17, 23)
PANEL = (22, 27, 34)
RULE = (48, 54, 61)
TEXT = (201, 209, 217)
MUTED = (139, 148, 158)
BLUE = (88, 166, 255)
GREEN = (63, 185, 80)
AMBER = (210, 153, 34)

# Every figure below was produced by running the command named beside it, on the date in
# STAMP. Nothing here is copied out of a document.
#
#   0.5 / 0.4 / 1.0 USDC, custom error 300, the signature:
#       python3 scripts/verify_proof_offline.py
#   the audited program's address and the pinned source of error 300:
#       docs/MAINNET-PROOF.md, itself sourced to solana-foundation/subscriptions
STAMP = "figures verified 2026-08-16"

OVER_CAP_SIG = "4nbuXbWKc8Q2YiKbPnjmTyarGroaB5oT3j8iiwhU95e5H2pRn8MorGraqZaDregWmf5BwedHwaiTQo9Ff81dc9G4"
ALLOWANCES_PROGRAM = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44"
FEED_PDA = "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg"
REPO_URL = "github.com/belumume/zeroclaw-solana"

# A string that must come back from OCR. Without it a zero-hit identifier scan is equally
# consistent with an OCR run that read nothing at all.
OCR_POSITIVE_CONTROL = "zeroclaw-solana"

# A phone number, narrowed to need 9+ digits AND either a leading + or an internal
# separator. Without the separator clause a bare 9-digit run matches, and this repo prints
# slot numbers. Without the digit floor an ISO date matches. `selftest()` pins both.
PHONE_RE = re.compile(
    r"(?<![\d\w])(?=(?:[\s().+-]*\d){9,})"
    r"(?:\+[\d\s().-]{8,}\d|\d[\d\s().-]*[\s().-][\d\s().-]*\d)"
)

# Floor on the imported shape set, same reasoning as the sibling gates: a broken import
# returns an empty dict, the scan loop runs zero patterns, and the result is a PASS line
# byte-identical to a clean run.
MIN_SHAPES = 8


# --------------------------------------------------------------------------- fonts

FONT_SETS = [
    # (family label, regular, bold, mono, mono-bold) - first set that fully resolves wins.
    (
        "DejaVu (system)",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    ),
    (
        "DejaVu (system, non-Debian layout)",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
    ),
    (
        "Windows (Arial / Consolas)",
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/arialbd.ttf",
        "C:/Windows/Fonts/consola.ttf",
        "C:/Windows/Fonts/consolab.ttf",
    ),
    (
        "macOS (Helvetica / Menlo)",
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/Menlo.ttc",
    ),
]


def _matplotlib_dejavu():
    """matplotlib ships DejaVu. Used only if no system font resolved, never imported first."""
    try:
        import matplotlib
    except Exception:
        return None
    d = pathlib.Path(matplotlib.__file__).parent / "mpl-data" / "fonts" / "ttf"
    names = (
        "DejaVuSans.ttf",
        "DejaVuSans-Bold.ttf",
        "DejaVuSansMono.ttf",
        "DejaVuSansMono-Bold.ttf",
    )
    paths = [d / n for n in names]
    if all(p.is_file() for p in paths):
        return ("DejaVu (matplotlib copy)", *[str(p) for p in paths])
    return None


def resolve_fonts():
    for entry in FONT_SETS:
        label, *paths = entry
        if all(os.path.isfile(p) for p in paths):
            return label, paths
    fallback = _matplotlib_dejavu()
    if fallback:
        return fallback[0], list(fallback[1:])
    raise SystemExit(
        "FAIL  no usable font family found.\n"
        "      Tried: "
        + ", ".join(s[0] for s in FONT_SETS)
        + ", matplotlib's bundled DejaVu.\n"
        "      Install DejaVu (Debian/Ubuntu: apt-get install fonts-dejavu-core) and re-run.\n"
        "      Refusing to fall back to a bitmap default, which would render an unreadable\n"
        "      card and still exit 0."
    )


# --------------------------------------------------------------------------- layout


class Card:
    def __init__(self, draw, fonts):
        self.d = draw
        self.reg, self.bold, self.mono, self.monob = fonts
        self.y = PAD

    def f(self, kind, size):
        from PIL import ImageFont

        path = {
            "reg": self.reg,
            "bold": self.bold,
            "mono": self.mono,
            "monob": self.monob,
        }[kind]
        return ImageFont.truetype(path, size)

    def line(self, text, kind="reg", size=22, fill=TEXT, x=PAD, gap=8):
        font = self.f(kind, size)
        self.d.text((x, self.y), text, font=font, fill=fill)
        self.y += font.size + gap

    def wrapped(
        self, text, kind="reg", size=22, fill=TEXT, x=PAD, width=None, gap=8, lead=10
    ):
        """Greedy wrap measured with the real font, so it survives a font-family change."""
        font = self.f(kind, size)
        width = width or (W - PAD - x)
        words, cur, lines = text.split(), "", []
        for w in words:
            trial = f"{cur} {w}".strip()
            if self.d.textlength(trial, font=font) <= width:
                cur = trial
            else:
                if cur:
                    lines.append(cur)
                cur = w
        if cur:
            lines.append(cur)
        for ln in lines:
            self.d.text((x, self.y), ln, font=font, fill=fill)
            self.y += font.size + lead
        self.y += gap - lead if gap > lead else 0

    def fitted_mono(
        self,
        text,
        max_size,
        min_size,
        fill=TEXT,
        x=PAD,
        width=None,
        gap=8,
        measure_only=False,
    ):
        """Shrink a mono line until it fits rather than truncating a value a reader may need.

        `measure_only` advances the cursor without drawing, so a panel behind a run of these
        can be sized from what will actually be rendered rather than from a hardcoded height.
        The hardcoded version overlapped the paragraph below it.
        """
        width = width or (W - PAD - x)
        size = max_size
        while size > min_size:
            font = self.f("mono", size)
            if self.d.textlength(text, font=font) <= width:
                break
            size -= 1
        font = self.f("mono", size)
        if not measure_only:
            self.d.text((x, self.y), text, font=font, fill=fill)
        self.y += font.size + gap
        return size

    def rule(self, gap_before=18, gap_after=22, color=RULE):
        self.y += gap_before
        self.d.line([(PAD, self.y), (W - PAD, self.y)], fill=color, width=2)
        self.y += gap_after

    def kicker(self, text, color=BLUE):
        font = self.f("bold", 17)
        self.d.text((PAD, self.y), text.upper(), font=font, fill=color)
        self.y += font.size + 14


def render(out_path: pathlib.Path) -> pathlib.Path:
    from PIL import Image, ImageDraw

    label, paths = resolve_fonts()
    print(f"font family: {label}")
    for p in paths:
        print(f"  {p}")

    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    c = Card(d, paths)

    # ---- header
    c.line("zeroclaw-solana", kind="bold", size=54, fill=TEXT, gap=10)
    c.wrapped(
        "Two self-hosted ZeroClaw agents on Solana, both running now.",
        size=25,
        fill=MUTED,
        gap=0,
        lead=8,
    )
    c.rule(gap_before=24, gap_after=26)

    # ---- 1. what runs
    c.kicker("What runs")

    c.line("A DePIN node that sells its readings.", kind="bold", size=27, gap=12)
    c.wrapped(
        "An ARM box signs an ambient reading with a key generated on that box and lands it in "
        "a typed on-chain account, where a separate consumer program reads it. A systemd timer "
        "keeps it publishing with no laptop involved. The same node sells that reading per "
        "request over x402, so the machine earns the gas it spends.",
        size=22,
        gap=10,
        lead=11,
    )
    c.y += 8
    c.fitted_mono(f"feed  {FEED_PDA}", 18, 12, fill=MUTED, gap=4)
    c.fitted_mono(
        "curl  https://x402.perfpilot.dev/price   ->  HTTP 402, single-use nonce",
        18,
        12,
        fill=MUTED,
        gap=22,
    )

    c.line("A merchant terminal that settles USDC.", kind="bold", size=27, gap=12)
    c.wrapped(
        "A shop agent on WhatsApp and Telegram quotes an order and hands the customer a "
        "tappable payment link. Settlement is confirmed only from the chain: the exact amount "
        "in base units, the exact mint, the watched destination. A payment of the wrong amount, "
        "or of a token the payer minted, does not settle an order.",
        size=22,
        gap=0,
        lead=11,
    )
    c.rule(gap_before=20, gap_after=26)

    # ---- 2. custody
    c.kicker("Custody")
    c.line(
        "The limit is enforced by a deployed audited program,",
        kind="bold",
        size=27,
        gap=6,
    )
    c.line("not by our code.", kind="bold", size=27, gap=12)
    c.wrapped(
        "On mainnet, with real USDC, because a rejection that costs nothing is a weaker claim "
        "than one that does. A delegation capped at 0.5 USDC against the Solana Foundation "
        "Allowances program, audited by Cantina and none of it ours. The agent's own session "
        "key signed a 1.0 USDC transfer and the program refused it with custom error 0x12c "
        "(300, AmountExceedsLimit). The same key's 0.4 USDC transfer settled and moved value, "
        "which is the control that stops the refusal reading as a key that does not work.",
        size=22,
        gap=10,
        lead=11,
    )
    c.y += 8
    c.fitted_mono(f"program  {ALLOWANCES_PROGRAM}", 18, 11, fill=MUTED, gap=4)
    c.fitted_mono(f"refused  {OVER_CAP_SIG}", 18, 10, fill=AMBER, gap=4)
    c.fitted_mono(
        "         signed bytes committed at docs/proof-bundle/mainnet-transactions.json",
        18,
        10,
        fill=MUTED,
        gap=0,
    )
    c.rule(gap_before=20, gap_after=26)

    # ---- 3. reproduce
    c.kicker("Reproduce it")
    c.wrapped(
        "Three commands. Stdlib Python 3 and nothing else: no install, no key, no account. "
        "Two of the three never touch the network.",
        size=22,
        gap=14,
        lead=11,
    )
    cmd_x = PAD + 20
    cmd_w = CONTENT_W - 40
    clone = (
        "git clone https://github.com/belumume/zeroclaw-solana && cd zeroclaw-solana"
    )
    steps = (
        "python3 scripts/verify_proof_offline.py",
        "python3 scripts/certify_publish_tx.py",
        "python3 scripts/verify-proof.py",
    )

    def draw_commands(measure_only):
        c.fitted_mono(
            clone,
            19,
            11,
            fill=GREEN,
            x=cmd_x,
            width=cmd_w,
            gap=8,
            measure_only=measure_only,
        )
        for cmd in steps:
            c.fitted_mono(
                cmd,
                19,
                11,
                fill=TEXT,
                x=cmd_x,
                width=cmd_w,
                gap=8,
                measure_only=measure_only,
            )

    panel_top = c.y
    c.y = panel_top + 18
    draw_commands(measure_only=True)
    panel_bottom = c.y + 10
    d.rectangle([PAD, panel_top, W - PAD, panel_bottom], fill=PANEL)
    c.y = panel_top + 18
    draw_commands(measure_only=False)
    c.y = panel_bottom + 22
    c.wrapped(
        "The first two re-verify the committed on-chain bytes and drive the fail-closed action "
        "certifier, offline. The third re-checks the live claims against devnet and is allowed "
        "to go red, which is what makes a green one worth reading.",
        size=22,
        fill=MUTED,
        gap=0,
        lead=11,
    )

    # ---- footer, pinned to the bottom rather than flowing, so the URL never moves
    foot_y = H - PAD - 96
    body_end = c.y
    if body_end > foot_y - 16:
        raise SystemExit(
            f"FAIL  the body ran into the footer rule (body ends {body_end}, rule at {foot_y}).\n"
            "      Refusing to write a card whose last paragraph is overprinted by the URL."
        )
    d.line([(PAD, foot_y), (W - PAD, foot_y)], fill=RULE, width=2)
    c.y = foot_y + 26
    c.line(REPO_URL, kind="bold", size=32, fill=BLUE, gap=10)
    c.line(STAMP, kind="reg", size=18, fill=MUTED, gap=0)

    if c.y > H - PAD:
        raise SystemExit(
            f"FAIL  content overflowed the canvas (cursor {c.y} past {H - PAD}).\n"
            "      Refusing to write a card whose last block is clipped."
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_path, "PNG", optimize=True)
    print(
        f"wrote {out_path.relative_to(ROOT).as_posix()}  {out_path.stat().st_size:,} bytes  {W}x{H}"
    )
    return out_path


# --------------------------------------------------------------------------- verify

TESSERACT_CANDIDATES = [
    "tesseract",
    "/c/Program Files/Tesseract-OCR/tesseract.exe",
    "C:/Program Files/Tesseract-OCR/tesseract.exe",
    "/usr/bin/tesseract",
    "/opt/homebrew/bin/tesseract",
]


def find_tesseract():
    which = shutil.which("tesseract")
    if which:
        return which
    for cand in TESSERACT_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    return None


def ocr(binary, image, psm):
    with tempfile.TemporaryDirectory() as td:
        base = os.path.join(td, "out")
        proc = subprocess.run(
            [binary, str(image), base, "--psm", str(psm)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        txt = pathlib.Path(base + ".txt")
        if proc.returncode != 0 or not txt.is_file():
            return None
        return txt.read_text(encoding="utf-8", errors="replace")


def identifier_shapes():
    """Reuse the repo's own shape patterns rather than writing a second, drifting copy.

    Shapes, never literal names: a denylist that spells out what it protects publishes it
    the moment the repo is public. `scripts/check-identifier-leaks.py` carries that rule
    and its patterns, and importing them means a pattern fixed there is fixed here.
    """
    import importlib.util

    src = ROOT / "scripts" / "check-identifier-leaks.py"
    spec = importlib.util.spec_from_file_location("_ident", src)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    shapes = dict(mod.HOME_SHAPES)
    shapes.update(mod.OTHER_SHAPES)
    shapes["email"] = mod.EMAIL_RE
    shapes["phone"] = PHONE_RE
    if len(shapes) < MIN_SHAPES:
        raise SystemExit(
            f"FAIL  imported {len(shapes)} identifier shape(s), expected at least {MIN_SHAPES}.\n"
            "      The import from check-identifier-leaks.py is broken, so a zero-hit scan\n"
            "      below would be scanning with almost nothing."
        )
    return shapes


def selftest() -> int:
    """Prove the one pattern this file adds can go both ways, on real strings.

    The upstream shapes are already covered by `scripts/test_check_identifier_leaks.py`.
    `phone` is added here and so is covered by nothing else, and its first draft
    (`\\+?\\d[\\d\\s().-]{8,}\\d`) matched the card's own date stamp and reported the card
    as leaking a phone number. A narrowing with no over-correction control is
    indistinguishable from having switched the detector off, so the must-fire cases below
    are the whole point of this function.
    """
    must_fire = [
        "+1 (415) 555-0132",
        "call +966 50 123 4567 now",
        "0044 20 7946 0958",
        "415-555-0132",
        "+15551234567",
        "(020) 7946 0958",
    ]
    must_not_fire = [
        STAMP,  # the exact string on the card that broke the first draft
        "2026-08-16",
        "0.5 USDC",
        "300, AmountExceedsLimit",
        "slot=436587459",  # a bare 9-digit run with no separator and no plus
        "1200x1600",
        "0x12c",
    ]
    bad = []
    for s in must_fire:
        if not PHONE_RE.search(s):
            bad.append(f"must fire and did not: {s!r}")
    for s in must_not_fire:
        m = PHONE_RE.search(s)
        if m:
            bad.append(f"must not fire and did: {s!r} matched {m.group(0)!r}")
    shapes = identifier_shapes()
    for line in bad:
        print(f"  FAIL {line}")
    if bad:
        print(
            f"FAIL  {len(bad)} of {len(must_fire) + len(must_not_fire)} phone cases wrong"
        )
        return 1
    print(
        f"PASS  {len(must_fire)} must-fire and {len(must_not_fire)} must-not-fire phone "
        f"cases correct; {len(shapes)} identifier shapes imported"
    )
    return 0


def verify(image: pathlib.Path) -> int:
    if not image.is_file():
        print(f"CANNOT CHECK  {image} does not exist; render it first.")
        return 2
    binary = find_tesseract()
    if not binary:
        print("CANNOT CHECK  Tesseract not found on PATH or at any known location.")
        print(
            "              A scan that never ran must not read as a scan that found nothing."
        )
        return 2
    print(f"tesseract: {binary}")

    texts, tokens = {}, set()
    for psm in (3, 11):
        out = ocr(binary, image, psm)
        if out is None:
            print(f"CANNOT CHECK  tesseract failed at --psm {psm}.")
            return 2
        texts[psm] = out
        tokens |= set(out.split())
        print(f"  --psm {psm}: {len(out)} chars, {len(out.split())} tokens")

    union = "\n".join(texts.values())

    # POSITIVE CONTROL FIRST. Neither mode is a safe default on a card-like layout, so the
    # control is satisfied by the union and the run says which modes carried it.
    carried = [psm for psm, t in texts.items() if OCR_POSITIVE_CONTROL in t]
    if not carried:
        print(
            f"FAIL  positive control {OCR_POSITIVE_CONTROL!r} not read back from the card "
            "at either --psm.\n"
            "      The OCR did not read this image, so a zero-hit identifier scan below "
            "would mean nothing."
        )
        return 1
    print(
        f"PASS  positive control {OCR_POSITIVE_CONTROL!r} read back "
        f"(--psm {', '.join(str(p) for p in carried)})"
    )

    findings = []
    for name, rx in identifier_shapes().items():
        for m in rx.finditer(union):
            findings.append((name, m.group(0)))
    if findings:
        print(f"FAIL  {len(findings)} identifier-shaped hit(s) in the OCR text:")
        for name, hit in findings[:20]:
            print(f"      {name}: {hit!r}")
        return 1

    print(f"PASS  0 identifier-shaped hits across {len(tokens)} unioned tokens")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--verify", action="store_true", help="OCR the rendered card, do not render"
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="prove the added phone pattern can fire and can stay silent",
    )
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    if args.selftest:
        return selftest()
    if args.verify:
        rc = selftest()
        if rc != 0:
            print(
                "      refusing to report a scan whose own detector is miscalibrated."
            )
            return rc
        return verify(out)
    import importlib.util

    if importlib.util.find_spec("PIL") is None:
        print("FAIL  Pillow is required to render. pip install Pillow")
        return 2
    render(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
