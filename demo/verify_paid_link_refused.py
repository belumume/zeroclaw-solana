#!/usr/bin/env python3
"""Prove the pay page refuses a link whose reference key has already settled -- both directions.

WHY THIS EXISTS. A Solana Pay reference key is single-use: it rides the transfer as a read-only
non-signer account, so the chain can be asked whether this exact order has been paid. Until this
check existed, reloading a paid link rendered a live Pay button again, and the page would have
taken a second transfer for one order. The customer cannot see that; the shop then owes a refund,
which is the one path here that touches funds and sits behind a human checkpoint.

A refusal alone proves nothing -- a page that refused everything would look identical on the paid
case. So this drives four directions and fails unless the page DISCRIMINATES:

  paid               a reference with a real settlement    -> refused, no Pay button, amount + sig
  unpaid             a reference with no history at all     -> payable, Pay button, QR
  paid-rpc-dead      the PAID reference, primary aborted    -> refused, via the settlement proxy
  paid-rpc-429       the PAID reference, primary throttled  -> refused, via the settlement proxy
  paid-all-rpc-dead  the PAID reference, every host broken  -> payable  (fail open on the network)

Fail-open in the safe direction is the point of the design and the easiest thing to get
backwards: a network failure must never refuse a good link, because that failure is invisible to
the shop while the untaken second payment simply does not happen. `unpaid` and `paid-all-rpc-dead`
are what carry it.

A dead PRIMARY is not that case. The page escalates to the proxy, which answers and sees the
settlement, so ignorance was never the state and the card correctly refuses. Expecting a payable
card there would be asserting that the double-payment hole stays open.

The PAID case also composes its link with a DELIBERATELY WRONG amount. The card must show what the
CHAIN says was paid (0.39 USDC), not what the link asked for, or the figure on a receipt is an echo
of the request rather than a fact about the settlement.

Both fixtures are asserted against mainnet before the browser opens, so a "payable" verdict cannot
come from a fixture that quietly stopped meaning what it did when it was written.

Run it:  python demo/verify_paid_link_refused.py [--viewport desktop|phone] [--shots DIR]

Needs playwright (pip install playwright). It drives the system Chrome via channel="chrome", so no
browser download is required. Everything else is stdlib.
"""

from __future__ import annotations

import argparse
import http.server
import json
import re
import socketserver
import sys
import threading
import time
import urllib.request
from base64 import urlsafe_b64encode
from pathlib import Path
from urllib.parse import quote

REPO = Path(__file__).resolve().parent.parent
PAGE_DIR = REPO / "webshop-pay"

# Read the pinned address and the endpoint out of the shipped page rather than restating them. A
# second copy here would drift from the page, and the drifted copy is the one a reader trusts.
MERCHANT_MARKER = "var MERCHANT='"
# The page's one RPC constant. It was READ_RPC while the settlement check read from a different
# endpoint than the pay path; the pay path has since been repointed at the same host and the two
# collapsed, because two constants holding one value drift and the drifted one is the one a reader
# trusts. Still read out of the page rather than restated: the RPC-failure cases below derive their
# intercept glob from whatever the page NAMES, so a repoint cannot leave them intercepting a host
# nothing contacts and passing for free.
RPC_MARKER = "var RPC='"
# The settlement proxy, read the same way and for the same reason. The all-endpoints-dead case
# below must break BOTH hosts, and deriving this from the page means a repoint cannot leave that
# case intercepting only one of them and passing for free.
PROXY_MARKER = "var SETTLEMENT_PROXY='"

MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # mainnet USDC

# Used ONLY to tell a PRUNED lookup apart from an UNPAID reference when the page's own RPC returns
# nothing. It is deliberately not the page's endpoint: the point is to have a second opinion from a
# node with deeper retention, so a node's housekeeping cannot masquerade as an unsettled payment.
# Never used for the behaviour assertions, which must run against whatever the page actually names.
FIXTURE_ARCHIVAL_RPC = "https://api.mainnet-beta.solana.com"

# A real, finalized mainnet settlement. The operator paid this order from his phone wallet on
# 2026-08-06 and then reproduced the defect by reloading the link. It is a permanent fixture: a
# settled transaction does not un-settle, so this case cannot go stale the way a live balance does.
PAID_REFERENCE = "9TNKoCvVow1ktRgMMapJ9d9GWhgTYCA9i3r3MZ71FUT2"
PAID_AMOUNT = "0.39"  # what the CHAIN says the merchant received
LINK_AMOUNT = "5.00"  # what the link is made to ASK for, so the two cannot be confused

# 32 bytes of nothing in particular, base58-encoded: a syntactically valid pubkey with no history.
# Asserted to have zero signatures below rather than assumed, because "no history" is exactly the
# property that would make this test pass for the wrong reason if it ever stopped holding.
UNPAID_REFERENCE = "5Zzguz4NsSRFxGkHfM4KmJTNVPMJ2P3jFa2y8bTHY4kW"

VIEWPORTS = {
    "desktop": {"viewport": {"width": 1280, "height": 900}, "device_scale_factor": 2},
    "phone": {
        "viewport": {"width": 390, "height": 844},
        "device_scale_factor": 3,
        "is_mobile": True,
        "has_touch": True,
    },
}


def read_pin(marker: str) -> str:
    src = (PAGE_DIR / "src" / "app.js").read_text(encoding="utf-8")
    i = src.index(marker) + len(marker)
    return src[i : src.index("'", i)]


def rpc(endpoint: str, method: str, params: list) -> object:
    """Plain JSON-RPC from the harness, so the fixtures are checked by something other than the
    code under test. curl on this platform dies on schannel revocation for any https host, so this
    is urllib with a browser UA."""
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers={"content-type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read()).get("result")


def check_fixtures(endpoint: str) -> tuple[list[str], list[str]]:
    """Both references, asserted against the chain before anything is rendered.

    Returns (unresolved, findings), separated HERE rather than by reading the text back
    later, because the two demand opposite responses and the caller cannot recover the
    difference from a string. `unresolved` means this check could not decide: a reference
    the pinned RPC pruned and the archival cross-check could not reach, or a fixture that
    has rotted so the direction it tests proves nothing. `findings` means the page is
    wrong, and the only member is the double-payment case, which is established AFTER a
    successful archival lookup rather than by failing to look.

    Collapsing them loses money. The workflow step renders exit 2 as a warning and exit 0,
    which is right for a third-party outage and turns a customer being able to pay twice
    into a green run.
    """
    problems: list[str] = []
    findings: list[str] = []
    try:
        paid = rpc(
            endpoint,
            "getSignaturesForAddress",
            [PAID_REFERENCE, {"limit": 20, "commitment": "confirmed"}],
        )
        unpaid = rpc(
            endpoint,
            "getSignaturesForAddress",
            [UNPAID_REFERENCE, {"limit": 20, "commitment": "confirmed"}],
        )
    except (OSError, ValueError) as e:
        # OSError covers URLError and socket timeouts; ValueError covers a body that is not JSON.
        # Every one of them means the same thing here: the fixtures are unchecked, so nothing
        # below can be trusted and the run must stop rather than report a verdict it cannot back.
        # Returned as (unresolved, findings) like every other exit from this function. An
        # unreachable endpoint is the cannot-check case by definition: nothing was looked at,
        # so there is nothing to report about the page.
        return [f"could not reach {endpoint} to check the fixtures: {e}"], []

    settled = [e for e in (paid or []) if not e.get("err")]
    if not settled:
        # ZERO SIGNATURES HAS TWO CAUSES AND THEY ARE OPPOSITE VERDICTS. Either the reference was
        # never paid (a real failure), or this endpoint has PRUNED the slot it was paid in (a fact
        # about the node, not the chain). They are byte-identical in the response.
        #
        # MEASURED 2026-08-17: this fired, and it was pruning. The reference has 5 finalized,
        # non-errored signatures at slots ~437,6xx,xxx on api.mainnet-beta.solana.com, and 0 on
        # the pinned solana-rpc.publicnode.com, whose firstAvailableBlock is 439,097,325. The
        # transactions simply predate that node's retention window.
        #
        # The old comment on PAID_REFERENCE claimed this fixture "cannot go stale" because "a
        # settled transaction does not un-settle". True about the transaction, false about the
        # LOOKUP, which is what the check actually depends on.
        #
        # So: ask an ARCHIVAL endpoint before reporting a failure. A disagreement between the two
        # is the finding -- it means the page's own RPC can no longer see this settlement, which a
        # reader following the link would also hit.
        archival_settled = []
        try:
            arch = rpc(
                FIXTURE_ARCHIVAL_RPC,
                "getSignaturesForAddress",
                [PAID_REFERENCE, {"limit": 20, "commitment": "confirmed"}],
            )
            archival_settled = [e for e in (arch or []) if not e.get("err")]
        except (OSError, ValueError) as e:
            problems.append(
                f"PAID_REFERENCE {PAID_REFERENCE} returned nothing from {endpoint} and the "
                f"archival cross-check could not run ({e}); pruned and unpaid are "
                "indistinguishable here, so this is UNRESOLVED rather than a pass or a fail"
            )
        else:
            if archival_settled:
                print(f"paid fixture    : {PAID_REFERENCE}")
                print(
                    f"                  NOT VISIBLE on the pinned RPC {endpoint} (pruned), "
                    f"settled per {FIXTURE_ARCHIVAL_RPC} by "
                    f"{archival_settled[-1]['signature']}"
                )
                # PRUNED IS ONLY A DEFECT IF THE PAGE CANNOT RECOVER FROM IT. Asserting "the
                # pinned RPC must see this" would be a gate keyed to one REMEDY rather than to
                # the invariant, and it would stay red forever after the page grew a fallback --
                # punishing the fix. The invariant is: a settled reference must never leave the
                # card payable, because that invites a SECOND payment. Either the pinned RPC sees
                # it, or the page escalates to an archival endpoint that does.
                page_src = (PAGE_DIR / "src" / "app.js").read_text(encoding="utf-8")
                # Keyed on the MECHANISM, not on a constant's NAME. The first version of this
                # looked for `ARCHIVAL_RPC`, and when the escalation shipped as `SETTLEMENT_PROXY`
                # the gate reported the money bug as unfixed -- punishing the fix for choosing a
                # different word. What actually matters is that the settlement lookup consults a
                # SECOND endpoint: `rpc()` takes an optional third argument, so an escalation is a
                # getSignaturesForAddress call with one.
                escalations = re.findall(
                    r"rpc\(\s*'getSignaturesForAddress'\s*,\s*\[[^\]]*\]\s*,", page_src
                )
                has_fallback = len(escalations) >= 1
                if has_fallback:
                    print(
                        "                  pinned RPC pruned it, and the page ESCALATES to "
                        "ARCHIVAL_RPC, so the card still refuses"
                    )
                else:
                    findings.append(
                        f"MONEY BUG: the pinned RPC {endpoint} can no longer see the settlement "
                        f"for {PAID_REFERENCE} (finalized on chain), and the page has NO archival "
                        "fallback. settledSignature() returns null, checkAlreadyPaid() returns "
                        "false, and the card stays PAYABLE -- a customer reloading this link can "
                        "pay a SECOND time. Re-pin the page's RPC, or give it an archival "
                        "escalation for the empty case."
                    )
            else:
                problems.append(
                    f"PAID_REFERENCE {PAID_REFERENCE} has no confirmed non-errored signature on "
                    f"{endpoint} OR on {FIXTURE_ARCHIVAL_RPC}; the paid direction would pass for "
                    "the wrong reason"
                )
    else:
        print(f"paid fixture    : {PAID_REFERENCE}")
        print(
            f"                  settled by {settled[-1]['signature']}"
            f"  ({settled[-1].get('confirmationStatus')})"
        )
    if unpaid:
        problems.append(
            f"UNPAID_REFERENCE {UNPAID_REFERENCE} now has {len(unpaid)} signature(s); "
            "it is no longer an unpaid fixture and the payable direction is void"
        )
    else:
        print(f"unpaid fixture  : {UNPAID_REFERENCE}  (0 signatures)")
    return problems, findings


def pay_url(reference: str, amount: str, lang: str = "pt") -> str:
    solana = (
        f"solana:{read_pin(MERCHANT_MARKER)}?amount={amount}&spl-token={MINT}"
        f"&reference={reference}"
        f"&label={quote('Mesa 4')}&message={quote('Pedido 412')}"
    )
    # ?u= base64, which is the form skills/solana-pay/scripts/pay_link.py actually emits.
    return f"/index.html?lang={lang}&u={urlsafe_b64encode(solana.encode()).decode()}"


def serve() -> tuple[socketserver.TCPServer, int]:
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(PAGE_DIR), **kw)

        def log_message(self, *a):  # silence; the harness owns the output
            pass

    socketserver.TCPServer.allow_reuse_address = True
    # Port 0: this server is addressed by nobody but this script, so it must not claim a named one.
    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def breaker(breakage: str | None, calls: dict):
    """Break an endpoint the way `breakage` says, counting the requests it swallows.

    A FACTORY, NOT DEFAULT ARGUMENTS, and the difference is not style. This was written as
    `def handler(route, breakage=breakage, calls=calls)`, which does not work: playwright calls a
    route handler as `handler(route, route.request)`, truncated to the handler's arity, so the
    Request object landed in `breakage`. It is never equal to "abort", so BOTH abort cases were
    silently running as 429 cases and this file had two names for one test.

    It went unnoticed because the two breakages are expected to produce the same verdict here --
    the page reads an aborted fetch and a 429 identically, as "the chain did not answer" -- so the
    substitution cost coverage rather than correctness, and coverage loss is invisible in a green
    run. The same defect was hit from scratch while writing verify_reference_required.py, where it
    DID flip a result, which is the only reason it was found here.
    """

    def handler(route):
        calls["n"] += 1
        if breakage == "abort":
            route.abort()
        else:
            route.fulfill(
                status=429,
                content_type="application/json",
                body='{"jsonrpc":"2.0","error":{"code":429,'
                '"message":"Too many requests"},"id":1}',
            )

    return handler


PROBE = """() => {
  const card = document.getElementById('card');
  const pay  = document.getElementById('pay');
  const qr   = document.querySelector('#qr img, #qr canvas');
  const text = card ? card.innerText.replace(/\\s+/g, ' ').trim() : '';
  const doc  = document.scrollingElement;
  return {
    lang:      document.documentElement.lang,
    cardClass: card ? card.className : null,
    cardBox:   card ? (b => ({w: b.width, h: b.height}))(card.getBoundingClientRect()) : null,
    viewH:     window.innerHeight,
    payable:   !!pay && pay.offsetParent !== null,
    qr:        !!qr,
    // The overlay plate for the opening beat is keyed to there being no horizontal scroll at all.
    docOverflow: doc.scrollWidth - doc.clientWidth,
    text:      text,
  };
}"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--viewport", choices=sorted(VIEWPORTS), default="desktop")
    ap.add_argument("--shots", default=None, help="directory to write frames into")
    args = ap.parse_args()

    if not (PAGE_DIR / "index.html").exists():
        print(
            f"CANNOT CHECK  no built page at {PAGE_DIR / 'index.html'}, so there is "
            "nothing to drive; a missing local artifact, not a finding about the page.",
            file=sys.stderr,
        )
        print("      run: python webshop-pay/build.py", file=sys.stderr)
        return 2
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "CANNOT CHECK  the local dependency `playwright` is not importable, so the "
            "browser leg cannot run at all:  pip install playwright",
            file=sys.stderr,
        )
        return 2

    merchant, endpoint = read_pin(MERCHANT_MARKER), read_pin(RPC_MARKER)
    print(f"pinned merchant : {merchant}")
    print(f"pinned rpc      : {endpoint}")
    # EXIT 1, NOT 2, AND THE DIFFERENCE IS LOAD-BEARING. This reads a local file and compares a
    # pinned constant, so it cannot fail for an environmental reason: there is no network, no
    # dependency and no built artifact involved. A mismatch is a finding ABOUT THE PAGE. The
    # workflow wrapping this script converts exit 2 into a `::warning::` and exit 0, which is
    # right for a genuine cannot-check and would silently swallow this one on a money path.
    if MINT not in (PAGE_DIR / "src" / "app.js").read_text(encoding="utf-8"):
        print(f"FAIL  the page does not know mint {MINT}", file=sys.stderr)
        return 1

    unresolved, fixture_findings = check_fixtures(endpoint)
    for d in fixture_findings:
        print(f"FAIL  {d}", file=sys.stderr)
    for d in unresolved:
        print(f"CANNOT CHECK  {d}", file=sys.stderr)
    if fixture_findings:
        return 1
    if unresolved:
        return 2

    profile = VIEWPORTS[args.viewport]
    vw, vh = profile["viewport"]["width"], profile["viewport"]["height"]
    dsf = profile["device_scale_factor"]
    print(f"viewport        : {args.viewport}  {vw}x{vh} css @ {dsf}x")
    print(f"link asks for   : {LINK_AMOUNT} USDC   chain settled: {PAID_AMOUNT} USDC")

    shots = Path(args.shots).resolve() if args.shots else None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)

    # A refusal is asynchronous and its cost is not constant: the paid path makes up to four RPC
    # calls once the primary has been pruned, so the time to refuse moves with proxy load. These
    # bound the wait rather than guessing a budget that happens to work today.
    REFUSE_DEADLINE_S = 25.0  # the page stops escalating well inside this
    POLL_MS = 250
    DWELL_MS = 4000  # for a card that must STAY payable, where there is nothing to wait FOR

    # name, reference, how to break the RPC, which hosts to break, must the Pay button survive?
    #
    # RE-KEYED after the page began escalating to the proxy on a primary FAILURE and not only on an
    # empty answer. The two single-host cases previously expected a paid link to stay payable when
    # the primary died, on the premise that a dead primary means we cannot know. The proxy makes
    # that premise false: it answers, sees the settlement, and the card correctly refuses. Asserting
    # the old expectation would now be asserting that the double-payment hole stays open.
    #
    # The invariant those cases were REALLY protecting is fail-open in the safe direction: a network
    # failure must never refuse a GOOD link. That is now carried by `unpaid` (payable with every
    # endpoint healthy) and by `paid-all-rpc-dead` (payable when NOTHING can answer), so the gate
    # still fails if the page ever starts refusing on ignorance.
    CASES = [
        ("paid", PAID_REFERENCE, None, (), False),
        ("unpaid", UNPAID_REFERENCE, None, (), True),
        # primary broken, proxy alive -> the escalation must find the settlement and refuse
        ("paid-rpc-dead", PAID_REFERENCE, "abort", ("primary",), False),
        ("paid-rpc-429", PAID_REFERENCE, "429", ("primary",), False),
        # nothing can answer -> the card must stay payable rather than refuse on ignorance
        ("paid-all-rpc-dead", PAID_REFERENCE, "abort", ("primary", "proxy"), True),
    ]
    proxy = read_pin(PROXY_MARKER)
    hosts = {
        "primary": endpoint.split("//", 1)[1].split("/")[0],
        "proxy": proxy.split("//", 1)[1].split("/")[0],
    }
    # EXIT 1 for the same reason as the mint check above: both pins are read from local files and
    # compared to each other, with nothing environmental that could make this fire spuriously.
    if hosts["primary"] == hosts["proxy"]:
        print(
            "FAIL  the page names the same host for RPC and the settlement proxy, so the "
            "single-host cases below cannot distinguish an escalation from the primary answering.",
            file=sys.stderr,
        )
        return 1

    srv, port = serve()
    failures: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chrome")
            for name, reference, breakage, break_hosts, want_payable in CASES:
                page = browser.new_page(**profile)
                calls = {"n": 0}

                handler = breaker(breakage, calls)

                if breakage:
                    # Globs derived from the hosts the page actually names, so a repoint cannot
                    # leave this intercepting a host nothing contacts and passing for free.
                    for which in break_hosts:
                        page.route(f"**{hosts[which]}**", handler)

                page.goto(f"http://127.0.0.1:{port}{pay_url(reference, LINK_AMOUNT)}")
                # ASYMMETRIC ON PURPOSE, and collapsing the two directions is what made this
                # gate intermittently red against a page that was behaving correctly.
                #
                # A card that must REFUSE has something to wait for, so wait for THAT and stop
                # at the first refusal. A fixed budget here is a race: the refusal arrives after
                # up to four RPC calls, and a loaded proxy pushes it past any constant, which
                # reads as a broken page rather than as a slow endpoint. Polling is also
                # normally faster, because it leaves as soon as the card refuses.
                #
                # A card that must STAY payable has nothing to wait for. The assertion is that
                # a refusal never arrives, so the only instrument is a fixed dwell; polling
                # would exit early and weaken it into asserting nothing.
                refused_ms = None
                if want_payable:
                    page.wait_for_timeout(DWELL_MS)
                    r = page.evaluate(PROBE)
                else:
                    t0 = time.monotonic()
                    while True:
                        r = page.evaluate(PROBE)
                        if not r["payable"]:
                            refused_ms = int((time.monotonic() - t0) * 1000)
                            break
                        if time.monotonic() - t0 >= REFUSE_DEADLINE_S:
                            break
                        page.wait_for_timeout(POLL_MS)

                print(f"\n--- {name} ---")
                print(f"  class={r['cardClass']}  payable={r['payable']}  qr={r['qr']}")
                if not want_payable:
                    # Printed so a closing margin is visible while it is still passing, rather
                    # than arriving later as an intermittent red nobody can reproduce.
                    print(
                        f"  refused after: {refused_ms} ms"
                        if refused_ms is not None
                        else f"  NEVER refused within {REFUSE_DEADLINE_S:.0f}s"
                    )
                if breakage:
                    print(f"  rpc {breakage}: {calls['n']} request(s) intercepted")
                cb = r["cardBox"]
                if cb:
                    print(
                        f"  card: {cb['w']:.0f}x{cb['h']:.0f} css px  (viewport {r['viewH']})"
                    )
                print(f"  document overflow: +{r['docOverflow']}px")
                print(f"  on screen: {r['text'][:240]}")

                if r["payable"] != want_payable:
                    failures.append(
                        f"{name}: expected payable={want_payable}, got {r['payable']}"
                    )
                if r["lang"] != "pt-BR":
                    failures.append(f"{name}: expected pt-BR, got {r['lang']!r}")
                if r["docOverflow"] > 1:
                    failures.append(
                        f"{name}: the page scrolls sideways (+{r['docOverflow']}px)"
                    )
                if want_payable:
                    if not r["qr"]:
                        failures.append(f"{name}: the QR did not render")
                    if "Pago" in r["text"] and "já foi pago" in r["text"]:
                        failures.append(
                            f"{name}: refused a link it must have rendered payable"
                        )
                    if LINK_AMOUNT not in r["text"]:
                        failures.append(
                            f"{name}: the payable card does not show the {LINK_AMOUNT} amount"
                        )
                else:
                    if "já foi pago" not in r["text"]:
                        failures.append(f"{name}: no already-paid message on the card")
                    if f"{PAID_AMOUNT} USDC" not in r["text"]:
                        failures.append(
                            f"{name}: the card does not show the {PAID_AMOUNT} USDC the chain "
                            "recorded (is it echoing the link instead?)"
                        )
                    if LINK_AMOUNT in r["text"]:
                        failures.append(
                            f"{name}: the card shows the link's {LINK_AMOUNT}, so the figure is "
                            "an echo of the request rather than the settlement"
                        )
                    if not any(len(w) >= 64 for w in r["text"].split()):
                        failures.append(f"{name}: no full signature on the card")

                if shots:
                    out = shots / f"paid-link-{name}-{vw}x{vh}.png"
                    page.screenshot(path=str(out))
                    print(f"  frame: {out.name}")
                page.close()
            browser.close()
    finally:
        srv.shutdown()

    print()
    if failures:
        for f in failures:
            print(f"FAIL  {f}", file=sys.stderr)
        return 1
    print("PASS  the page discriminates on settlement, not on the link:")
    print(
        "      a settled reference is refused with the amount the CHAIN recorded and no Pay"
    )
    print("      button; an unsettled one stays fully payable; and an unreachable or")
    print(
        "      rate-limited endpoint leaves a good link payable rather than refusing it."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
