#!/usr/bin/env python3
"""Ask the LIVE origin whether it serves every asset the pay page loads at run time.

WHY THIS EXISTS, and it is a gap the whole gate set shares rather than one gate's oversight.
`demo/verify_no_cdn_dependency.py` already drives a real browser through
`await import('/vendor/solana-bundle.js')` and asserts ten symbols come back. It is wired
into regression-gate.yml, it has two working controls, and it passed on every single day of
the twelve days the desktop wallet path was dead. It serves `webshop-pay/` over a loopback
`http.server`, where `vendor/` is present on disk, so it answers a question about the REPO.
The outage was in what got UPLOADED. A local serve cannot see a deploy-set defect by
construction, and seven of the ten browser-driving checks under demo/ serve locally.

So this is the other half of one claim, and the two halves are deliberately split:

    scripts/deploy-pay-page.py   every ref the page makes is IN the deploy set   (static)
    this file                    every ref the page makes is SERVED by the origin (live)

The static half cannot observe a deployment and the live half cannot run without a network,
which is why this one lives in the scheduled `live smoke (never required)` job and its
classifier is unit-tested hermetically in the required one.

STATUS IS USELESS ON THIS HOST, WHICH IS THE WHOLE DIFFICULTY. Cloudflare Pages answers an
unknown path with 200 and the SPA fallback, so a missing module and a healthy one are both
`200 OK`. Measured against the live origin on 2026-08-28:

    /vendor/solana-bundle.js        200  application/javascript      455128 B
    /vendor/__control_absent__.js   200  text/html; charset=utf-8    114752 B  <- the fallback
    /_headers                       200  text/html; charset=utf-8    114752 B  <- also the fallback

The discriminator is therefore the CONTENT TYPE, never the status.

THAT THIRD ROW IS WHY THE TARGET SET IS DERIVED RATHER THAN TAKEN FROM SERVE. `_headers` is
config Cloudflare consumes and never serves, so a check asserting "every deploy-set member is
served as an asset" would be RED ON A HEALTHY ORIGIN, and a gate that reddens on correct
content gets routed around rather than followed. The set asked about here is what the PAGE
ITSELF references, read out of the page with the same function the static half uses, so a
member added later is covered without anyone remembering to add it.

Exit codes, and the three-way split is the point. Folding "I could not look" into "broken"
trains a reader to wave away a red that will one day be real:

    0  every referenced asset is served as an asset, with the bytes main says it has
    1  a FINDING ABOUT THE ORIGIN. Either an asset comes back as the SPA fallback, or it
       comes back with different bytes. Both are fixed by a deploy, and nothing in this
       tree should be changed to make them green.
    2  CANNOT CHECK. The origin was unreachable. Not a finding about the page.
    3  CONTROL DEAD. A path that cannot exist did NOT come back as the fallback, so this
       script can no longer tell a served asset from a missing one and its verdict is void.

Usage:
  python3 demo/verify_origin_serves_deploy_set.py             # ask the live origin
  python3 demo/verify_origin_serves_deploy_set.py --selftest  # classifier only, no network
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SHOP = REPO / "webshop-pay"
# Overridable so this check can be driven against a controlled origin that mimics the
# Pages fallback, which is the only way to watch it go RED without breaking production.
ORIGIN = os.environ.get(
    "PAY_PAGE_ORIGIN", "https://zeroclaw-shop-pay.pages.dev"
).rstrip("/")
# A path under the asset directory that cannot exist. It is the positive control: on a healthy
# origin it MUST come back as the fallback, which is what proves this script can tell the two
# apart. Without it, "the content type was javascript" is an assertion rather than a reading.
CONTROL_PATH = "/vendor/__control_absent__.js"

PASS, FINDING, CANNOT_CHECK, CONTROL_DEAD = 0, 1, 2, 3

# Loaded from the canonical deployer rather than restated, so the two halves cannot disagree
# about what the page references. The filename is hyphenated and therefore not importable by
# name, which is the only reason this is done by hand.
_DEPLOYER = REPO / "scripts" / "deploy-pay-page.py"


def _deployer():
    spec = importlib.util.spec_from_file_location("_deploy_pay_page", _DEPLOYER)
    if spec is None or spec.loader is None:
        sys.exit(f"REFUSED: cannot load {_DEPLOYER}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fetch(url: str) -> tuple[int, str, bytes]:
    """Status, content type and body. A 4xx IS the answer here, so it is read, not raised."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        r = urllib.request.urlopen(req, timeout=25)
        return r.status, r.headers.get("Content-Type", ""), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read()


def is_fallback(ctype: str, body: bytes) -> bool:
    """True when the origin answered with the SPA document instead of the asset.

    Both halves are required. The content type alone would call a genuine text/html asset a
    fallback, and the body sniff alone would miss a fallback served with an odd type.
    """
    return "text/html" in ctype.lower() or body[:512].lstrip().lower().startswith(
        (b"<!doctype html", b"<html")
    )


def classify(path: str, ctype: str, body: bytes, expected: bytes | None) -> str | None:
    """None when the asset is served correctly, otherwise the finding in one line."""
    if is_fallback(ctype, body):
        return (
            f"{path}: the origin answered with the page itself ({len(body)} B, {ctype}) "
            "rather than the asset. The page imports this at click time, so the wallet "
            "path is dead on the live origin. Fix with a deploy."
        )
    if expected is not None and body != expected:
        return (
            f"{path}: served ({len(body)} B) but the bytes are not the ones main carries "
            f"({len(expected)} B). The origin is running a different build of an asset the "
            "page loads. Fix with a deploy."
        )
    return None


def main() -> int:
    dp = _deployer()
    index = SHOP / "index.html"
    if not index.is_file():
        print(f"CANNOT CHECK: no {index}")
        return CANNOT_CHECK

    # The page's module graph INTERSECTED WITH the deploy set, minus the document. Derived, so a
    # member added to the deploy set later is asked about here without anyone remembering to add it.
    #
    # The intersection is deliberate AND it is COUPLED, which is the part a later reader cannot see
    # from here: unserved_refs() in the required job already refuses any deploy whose page
    # references something outside SERVE, so by the time this runs, a page ref outside SERVE should
    # not exist. Decouple those two gates and this one narrows silently rather than failing.
    html = index.read_text(encoding="utf-8")
    served = {dp._as_served(n) for n in dp.SERVE}
    refs = sorted({dp._as_served(r) for r in dp.self_contained(html)} & served)
    refs = [r for r in refs if r != "index.html"]

    print(f"origin {ORIGIN}")
    print(
        f"  {len(refs)} referenced asset(s) to check, from {len(dp.SERVE)} deploy-set member(s)"
    )
    if not refs:
        # Not a pass. The page referencing nothing is either a real change or a broken read,
        # and reporting clean would be a zero from an instrument that looked at nothing.
        print(
            "CANNOT CHECK: the page references no deploy-set asset, so nothing was asked."
        )
        return CANNOT_CHECK

    # The control first. If the origin cannot be reached at all, that is CANNOT CHECK and no
    # verdict about the assets is available.
    try:
        c_status, c_ctype, c_body = fetch(ORIGIN + CONTROL_PATH)
    except Exception as e:
        print(f"CANNOT CHECK: {ORIGIN} unreachable ({type(e).__name__}: {e})")
        return CANNOT_CHECK
    if not is_fallback(c_ctype, c_body):
        print(
            f"CONTROL DEAD: {CONTROL_PATH} cannot exist and did not come back as the page "
            f"({c_status}, {c_ctype}, {len(c_body)} B). This script can no longer tell a "
            "served asset from a missing one, so its verdict would be worthless."
        )
        return CONTROL_DEAD
    print(f"  control ok: an absent path returns the page ({c_ctype.split(';')[0]})")

    findings = []
    for ref in refs:
        local = SHOP / ref
        expected = local.read_bytes() if local.is_file() else None
        try:
            status, ctype, body = fetch(f"{ORIGIN}/{ref}")
        except Exception as e:
            print(f"CANNOT CHECK: /{ref} unreachable ({type(e).__name__}: {e})")
            return CANNOT_CHECK
        finding = classify(f"/{ref}", ctype, body, expected)
        mark = "FAIL" if finding else "ok  "
        digest = hashlib.sha256(body).hexdigest()[:12]
        print(
            f"  {mark} /{ref}  {status} {ctype.split(';')[0]}  {len(body)} B  {digest}"
        )
        if finding:
            findings.append(finding)

    if findings:
        print()
        for f in findings:
            print(f"  FINDING {f}")
        print(
            f"\nFAIL  {len(findings)} of {len(refs)} referenced asset(s) are not on the origin "
            "as main describes them. This is a finding about the ORIGIN, not about this repo."
        )
        return FINDING
    print(
        f"\nPASS  {len(refs)} of {len(refs)} referenced asset(s) served, bytes matching main."
    )
    return PASS


def selftest() -> int:
    """The classifier, driven both ways on synthetic responses. No network."""
    cases: list[tuple[str, bool]] = []

    def case(name: str, ok: bool) -> None:
        cases.append((name, ok))
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")

    asset = b"export const web3 = {};"
    page = b"<!doctype html><html><body>the shop</body></html>"

    case(
        "a served asset with matching bytes is not a finding",
        classify("/v/a.js", "application/javascript", asset, asset) is None,
    )
    # THE OUTAGE SIGNATURE. 200 plus the page, which is what the origin answered for twelve
    # days while every status-based check read it as healthy.
    case(
        "the SPA fallback is a finding even though the status is 200",
        classify("/v/a.js", "text/html; charset=utf-8", page, asset) is not None,
    )
    case(
        "a fallback served with an odd content type is still caught by the body",
        classify("/v/a.js", "application/octet-stream", page, asset) is not None,
    )
    case(
        "an asset whose bytes differ from main is a finding",
        classify("/v/a.js", "application/javascript", b"stale build", asset)
        is not None,
    )
    case(
        "with no local copy to compare, a served asset is accepted",
        classify("/v/a.js", "application/javascript", asset, None) is None,
    )
    # The two findings must be DISTINGUISHABLE, or the message cannot tell a reader whether
    # the asset is absent or merely stale, and those need different words in a deploy note.
    missing = classify("/v/a.js", "text/html", page, asset)
    drifted = classify("/v/a.js", "application/javascript", b"stale", asset)
    case(
        "the two findings do not read the same",
        missing is not None
        and drifted is not None
        and "the page itself" in missing
        and "different build" in drifted,
    )
    case(
        "is_fallback says yes to the page and no to the bundle",
        is_fallback("text/html; charset=utf-8", page)
        and not is_fallback("application/javascript", asset),
    )
    # A control that only ever sees the healthy shape has not been shown to discriminate.
    case(
        "is_fallback is not fooled by an asset that merely mentions html",
        not is_fallback("application/javascript", b"var s = '<html>';"),
    )

    passed = sum(1 for _, ok in cases if ok)
    print(f"\n  {passed}/{len(cases)}")
    return PASS if passed == len(cases) else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(selftest())
    sys.exit(main())
