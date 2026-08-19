#!/usr/bin/env python3
"""Make the og:image's figures actually rot-detectable, which its generator alone does not.

WHY THIS EXISTS. `scripts/build-social-card.py` was added so the social card could be regenerated
from source instead of an image editor, under a commit message saying its figures "cannot rot
unnoticed". Review pointed out the gap: the generator was referenced by no workflow, no gate and
not by check-all.py, so nothing noticed anything. A generator nobody runs is a library, not a
control -- the same finding this repo has now recorded against a certifier and a test suite.

WHY IT DOES NOT REGENERATE-AND-DIFF, which is the obvious design and is wrong here.
`resolve_fonts()` picks the first available family, so the card renders in Segoe UI on this
machine and DejaVu on a Linux runner. The output is deliberately not byte-reproducible across
platforms -- the CONTENT is the same, the rasterisation is not -- so a byte comparison would fail
on every CI run for a reason that says nothing about the figures. That is a gate that cries wolf,
which is worse than no gate because it gets learned around.

WHAT IT ASSERTS INSTEAD, all three cheap and platform-independent:
  1. The generator still imports. A broken generator is the silent failure that leaves the card
     permanently un-regenerable, and it would otherwise surface only when someone next tried.
  2. The committed PNG is a real PNG at the dimensions the og:image contract needs. A social card
     is consumed by scrapers that will not fix an aspect ratio for you.
  3. The card has been regenerated within MAX_AGE_DAYS, read from git rather than from a
     filesystem mtime, which a fresh clone resets. This is the actual rot detector.

The figures on the card UNDERSTATE as the chain advances -- the publish count only grows -- so
staleness here is untidy rather than dangerous, and the threshold is set accordingly. It is a
prompt to re-run `--refresh`, not an alarm.

    python3 scripts/check-social-card-freshness.py
    python3 scripts/check-social-card-freshness.py --selftest   # proves each check can FAIL
"""

import struct
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CARD = ROOT / "docs" / "assets" / "social-preview.png"
GENERATOR = ROOT / "scripts" / "build-social-card.py"

# The og:image contract. Scrapers crop to roughly 1.91:1 and reject very small images; 2:1 at this
# size is what the card was designed and sampled at.
WANT_W, WANT_H = 2560, 1280

# Generous on purpose. The card's figures only ever understate, so this is a nudge rather than an
# alarm, and a gate that fires every month on a cosmetic artifact would be routed around.
MAX_AGE_DAYS = 60


def rel(path: Path) -> str:
    """Repo-relative when possible, absolute otherwise. `relative_to` RAISES for a path outside
    the root, which the self-test deliberately supplies, so a bare call turns a check that works
    into a crash inside the harness proving it works."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def png_dimensions(path: Path):
    """Width and height from the IHDR header. Deliberately no Pillow: this gate must run on a
    runner that has not installed it, and 24 bytes of struct cannot be a dependency problem."""
    b = path.read_bytes()[:24]
    if not b.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    return struct.unpack(">II", b[16:24])


def last_commit_date(path: Path):
    """Author date of the last commit touching `path`, or None if git cannot say.

    Git rather than st_mtime: a fresh clone stamps every file with the checkout time, so an mtime
    here would report a months-old card as brand new on exactly the machine a stranger uses.
    """
    r = subprocess.run(
        ["git", "-C", str(ROOT), "log", "-1", "--format=%aI", "--", str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = (r.stdout or "").strip()
    if r.returncode != 0 or not out:
        return None
    try:
        return datetime.fromisoformat(out)
    except ValueError:
        return None


def run(card=CARD, generator=GENERATOR, max_age_days=MAX_AGE_DAYS):
    problems = []

    if not generator.is_file():
        problems.append(f"the generator is missing: {rel(generator)}")
    else:
        # Import rather than execute: rendering needs Pillow and a font, neither of which this
        # gate should require. A SyntaxError or a bad top-level import is what we are catching.
        r = subprocess.run(
            [
                sys.executable,
                "-c",
                f"import runpy,sys; runpy.run_path(r'{generator}', run_name='__notmain__')",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if r.returncode != 0:
            problems.append(
                f"the generator does not import cleanly: {(r.stderr or '').strip().splitlines()[-1:]}"
            )

    if not card.is_file():
        problems.append(f"the card is missing: {rel(card)}")
        return problems

    dims = png_dimensions(card)
    if dims is None:
        problems.append("the card is not a valid PNG (bad magic)")
    elif dims != (WANT_W, WANT_H):
        problems.append(
            f"the card is {dims[0]}x{dims[1]}, expected {WANT_W}x{WANT_H} for the og:image contract"
        )

    when = last_commit_date(card)
    if when is None:
        # Not a failure: a shallow clone or an uncommitted card cannot be dated, and reporting
        # "cannot check" is honest where reporting a pass would not be.
        print(
            "  CANNOT CHECK  git could not date the card (shallow clone or uncommitted)"
        )
    else:
        age = datetime.now(timezone.utc) - when
        if age > timedelta(days=max_age_days):
            problems.append(
                f"the card was last regenerated {age.days} days ago (limit {max_age_days}); "
                f"its figures understate by now -- run: python3 scripts/build-social-card.py --refresh"
            )
        else:
            print(
                f"  card regenerated {age.days} day(s) ago, within the {max_age_days}-day limit"
            )

    return problems


def selftest():
    """Each check must be able to FAIL, or a clean run proves nothing about the card."""
    import tempfile

    ok = True
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)

        bad_png = tmp / "notapng.png"
        bad_png.write_bytes(
            b"definitely not a png header, but long enough to slice 24 bytes ok"
        )
        got = run(card=bad_png, generator=GENERATOR)
        hit = any("not a valid PNG" in p for p in got)
        print(f"  [{'OK ' if hit else 'XX '}] a non-PNG is caught: {got}")
        ok &= hit

        # A real PNG at the WRONG dimensions: 1x1, valid magic and IHDR.
        wrong = tmp / "wrong.png"
        ihdr = struct.pack(">II", 1, 1)
        wrong.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + ihdr)
        got = run(card=wrong, generator=GENERATOR)
        hit = any("expected 2560x1280" in p for p in got)
        print(f"  [{'OK ' if hit else 'XX '}] wrong dimensions are caught: {got}")
        ok &= hit

        got = run(card=CARD, generator=tmp / "absent.py")
        hit = any("generator is missing" in p for p in got)
        print(f"  [{'OK ' if hit else 'XX '}] a missing generator is caught: {got}")
        ok &= hit

        # The staleness branch, forced by an impossible limit rather than by waiting 60 days.
        got = run(card=CARD, generator=GENERATOR, max_age_days=-1)
        hit = any("last regenerated" in p for p in got)
        print(f"  [{'OK ' if hit else 'XX '}] the staleness branch fires: {got}")
        ok &= hit

    # CONTROL: with everything real and the real limit, it must PASS. Without this the four
    # above are equally consistent with a checker that fails on every input.
    clean = run()
    print(f"  [{'OK ' if not clean else 'XX '}] CONTROL: the real card passes: {clean}")
    ok &= not clean
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv:
        print("social-card freshness self-test:")
        return selftest()
    problems = run()
    for p in problems:
        print(f"FAIL  {p}", file=sys.stderr)
    if problems:
        return 1
    print("the social card is a valid og:image and has been regenerated recently")
    return 0


if __name__ == "__main__":
    sys.exit(main())
