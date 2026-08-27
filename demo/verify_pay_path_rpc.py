#!/usr/bin/env python3
"""Prove the desktop pay path can reach its RPC from a browser, and that confirmation polling
resolves all three ways -- confirmed, failed on chain, and neither.

WHY THIS EXISTS. api.mainnet-beta.solana.com returns HTTP 403 to any request carrying an Origin
header, which every browser sends on every fetch and on every websocket handshake. The pay page was
pointed there, so the desktop "connect wallet and pay" button had been dead since the shop moved to
mainnet -- silently, because every phone payment works: scanning the QR hands the solana: URL to the
wallet, which builds and submits the transaction itself and never touches the page's RPC.

Two things therefore need proving, and neither can be proved from Python:

  REACHABLE   the endpoint the page names answers a fetch made from a real page origin, and the
              old one still refuses it. A Python request without an Origin header gets 200 from
              both hosts, so it cannot see this defect at all.
  RESOLVES    the confirmation poll returns the right verdict in each of its three terminal states.

THE POLL IS THE POINT OF THE SECOND HALF. By the time it runs the wallet has already broadcast and
money has already moved, so a wrong verdict here is a lie about a settled transfer. The state that
matters most is the one a live run cannot produce on demand: TIMEOUT, which is neither paid nor
failed and must never render as either.

THE CONFIRMED CASE NEEDS A SIGNATURE THAT IS STILL INSIDE THE NODE'S WINDOW, WHICH IS WHY IT IS
DISCOVERED FRESH ON EVERY RUN. The page's RPC is a keyless shared node holding a rolling slice of
history: getFirstAvailableBlock reports a floor that advances continuously, and a signature below
that floor resolves as null from then on, however alive it is on chain. Any fixture pinned to one
past payment therefore carries an expiry that is written down nowhere. So this harness asks the
page's own endpoint for a signature it listed seconds ago and polls that. Mainnet emits thousands
of free confirmed signatures a second, so a fresh fixture costs two reads -- no key, no funds, no
broadcast, and nothing that can age.

TWO of them, because awaitConfirmation accepts confirmationStatus 'confirmed' OR 'finalized' and
one signature can only be one of the two. Covering a single arm leaves the other free to break.

THE SETTLED REFERENCE STAYS, doing the job it can still do: it is the LIVE control for the
synthetic "endpoint answers not seen" interception below. It names a real mainnet payment that now
sits below the node's floor, so the endpoint genuinely answers null for it, and the page must
render that as neither paid nor failed. Its expected verdict is READ from the endpoint on each run
rather than assumed, so it reports what the poll and the chain actually disagree about and can
never go red merely for getting older.

The remaining two states are driven by intercepting the endpoint, because a chain failure and a
network that never answers are not things that can be arranged on request.

NOTHING HERE BROADCASTS. Every call is a read.

Run it:  python demo/verify_pay_path_rpc.py [--viewport desktop|phone]

Needs playwright (pip install playwright). It drives the system Chrome via channel="chrome", so no
browser download is required. Everything else is stdlib.
"""

from __future__ import annotations

import argparse
import http.server
import json
import socketserver
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PAGE_DIR = REPO / "webshop-pay"

# Read the endpoint out of the shipped page rather than restating it. A second copy here would
# drift from the page, and the drifted copy is the one a future reader trusts.
RPC_MARKER = "var RPC='"

# The page's own settlement escalation, read from the page for the same reason as RPC above.
#
# WHY THE FIXTURE DISCOVERY NEEDS IT. The primary is a keyless shared endpoint that PRUNES its
# address index, and the fixture reference settled on 2026-08-07. Once that fell outside the
# retention window, `getSignaturesForAddress` on the primary began returning an empty list for a
# transaction that is perfectly alive on chain, and this harness read that empty list as "no
# settlement to test against" and refused to run.
#
# That is precisely the failure app.js was fixed for: escalating to the proxy on an empty or absent
# answer is what closes the settled-but-pruned hole. The page escalates; this script did not, so
# the verifier was a step behind the page it verifies. Mirroring it here is not a workaround --
# querying the primary alone asks a question the page stopped asking on purpose.
PROXY_MARKER = "var SETTLEMENT_PROXY='"

# The host the page must NOT be able to use from a browser. Named here as the control: if this ever
# stops returning 403 to an Origin-bearing request, the defect this harness was written for has gone
# away and the harness should say so rather than keep passing on a stale premise.
ORIGIN_HOSTILE_RPC = "https://api.mainnet-beta.solana.com"

# The settled reference from the operator's real mainnet payment on 2026-08-06. The signature that
# settled it is DISCOVERED from this rather than pinned, so this file carries one fixture instead of
# two that can disagree.
#
# ITS SIGNATURE CANNOT BE MADE TO RESOLVE, and no escalation rescues it, so do not reach for one.
# The proxy above answers `getSignaturesForAddress` (which is why the discovery finds the reference
# at all) and refuses `getSignatureStatuses` outright -- measured, verbatim: `{"error":{"code":
# -32601,"message":"method not proxied: getSignatureStatuses"}}`, and `rpc-proxy/src/index.js`
# allows exactly getSignaturesForAddress and getTransaction. app.js passes SETTLEMENT_PROXY to
# those two by name and to nothing else, so awaitConfirmation is primary-only by construction.
# The poll therefore has exactly one
# endpoint that can answer about a signature, the page's own, and that endpoint's floor has long
# passed this one. That is not a gap: an endpoint answering null for a signature it no longer
# indexes is the live shape of the interception below, which is the job this fixture now holds.
PAID_REFERENCE = "9TNKoCvVow1ktRgMMapJ9d9GWhgTYCA9i3r3MZ71FUT2"

# Where a FRESH fixture comes from. USDC rather than an arbitrary busy address, because it is the
# mint this shop settles in: the signature polled is then a real transfer of the same instrument a
# customer moves, not a stranger's unrelated transaction. It is read from the page's OWN endpoint,
# since a signature that node has never indexed would prove nothing about the poll, and one it
# listed a second ago is inside its window by construction.
FRESH_SOURCE_LIMIT = 25

# The page must be loaded with a VALID, UNSETTLED pay link for any of this to mean anything. With no
# ?u= the page replaces the whole card with "no valid Solana Pay request in this link", which
# removes #status and #pay -- so every render assertion below would be checking a card that does not
# exist, and the poll itself throws on the missing status line. With a SETTLED reference the
# already-paid refusal removes them just the same. Same unpaid fixture as the already-paid harness,
# asserted to have no history there.
MERCHANT_MARKER = "var MERCHANT='"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # mainnet USDC
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


def _rpc(endpoint: str, method: str, params: list) -> tuple[bool, object]:
    """(answered, result) for one JSON-RPC read. Never raises, never broadcasts.

    THE BOOL IS NOT DECORATION. An endpoint that answers null and an endpoint that never answered
    are the same `None` to a caller reading only the result, and they are not the same fact: the
    first is a statement about the chain, the second is a statement about this machine's network.
    Folding them together is how a transport failure gets reported as a finding about the page.
    """
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers={"content-type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            body = json.loads(r.read())
    except urllib.error.HTTPError as e:
        # A by-design 4xx carries a body worth nothing here, but it is an ANSWER, not a crash.
        e.read()
        return False, None
    except (OSError, ValueError):
        return False, None
    if not isinstance(body, dict) or "error" in body:
        # A JSON-RPC error is an answer about ACCESS, not a result we may reason from.
        return False, None
    return True, body.get("result")


def _signatures_from(
    endpoint: str, address: str, commitment: str = "confirmed", limit: int = 20
) -> list[dict]:
    """Raw getSignaturesForAddress result, or [] on any failure.

    Collapses every failure mode to an empty list -- HTTP error, timeout, malformed JSON -- so the
    caller escalates on "no answer" exactly as app.js does, rather than only on "empty answer".
    Those two are the same condition for a keyless endpoint and treating them differently is what
    reopened the hole the proxy exists to close.
    """
    ok, res = _rpc(
        endpoint,
        "getSignaturesForAddress",
        [address, {"limit": limit, "commitment": commitment}],
    )
    return res if ok and isinstance(res, list) else []


def fresh_signature(endpoint: str, commitment: str) -> dict | None:
    """The newest non-errored mainnet signature `endpoint` will name at the commitment asked for.

    One read. Returns the whole entry rather than the signature alone, so the caller can PRINT the
    slot and confirmationStatus it was chosen for -- a fixture whose provenance is not shown is a
    fixture nobody can check.
    """
    for e in _signatures_from(endpoint, MINT, commitment, FRESH_SOURCE_LIMIT):
        if not e.get("err") and e.get("signature"):
            return e
    return None


def live_status(endpoint: str, sig: str) -> tuple[bool, dict | None]:
    """(answered, status) -- the exact getSignatureStatuses call the page's own poll makes."""
    ok, res = _rpc(
        endpoint, "getSignatureStatuses", [[sig], {"searchTransactionHistory": True}]
    )
    if not ok or not isinstance(res, dict):
        return False, None
    return True, (res.get("value") or [None])[0]


def endpoint_verdict(st: dict | None) -> str:
    """What awaitConfirmation MUST return for the status the endpoint is serving right now.

    Three lines mirroring the page's own gate, so a live fixture's expected verdict is MEASURED
    rather than assumed. That is what lets a real signature stay useful after the node stops
    indexing it: the expectation follows the endpoint instead of a date in a comment.
    """
    if not st:
        return "unknown"
    if st.get("err"):
        return "failed"
    return (
        "confirmed"
        if st.get("confirmationStatus") in ("confirmed", "finalized")
        else "unknown"
    )


def settled_signature(
    endpoint: str, proxy: str | None = None
) -> tuple[str | None, str]:
    """The signature that settled the fixture reference, oldest-first -- the same gate the page and
    plugins/payment-watch/src/watch.rs both use.

    Returns (signature, where) so the caller can REPORT which leg answered. A fixture found only
    via the proxy is still a valid fixture, but it means the primary has pruned the reference, and
    that is worth printing rather than hiding behind a bare signature.
    """
    got = [e for e in _signatures_from(endpoint, PAID_REFERENCE) if not e.get("err")]
    if got:
        return got[-1]["signature"], "primary"
    if proxy:
        deep = [e for e in _signatures_from(proxy, PAID_REFERENCE) if not e.get("err")]
        if deep:
            return deep[-1]["signature"], "proxy (primary has pruned it)"
    return None, "neither the primary nor the proxy"


def pay_url() -> str:
    from base64 import urlsafe_b64encode
    from urllib.parse import quote

    solana = (
        f"solana:{read_pin(MERCHANT_MARKER)}?amount=0.25&spl-token={MINT}"
        f"&reference={UNPAID_REFERENCE}"
        f"&label={quote('Mesa 4')}&message={quote('Pedido 412')}"
    )
    # ?u= base64, which is the form skills/solana-pay/scripts/pay_link.py actually emits.
    return f"/index.html?lang=pt&u={urlsafe_b64encode(solana.encode()).decode()}"


def fulfiller(body: str, status: int = 200):
    """One-argument handler. A two-parameter lambda gets Playwright's Request bound to the second
    parameter, because it passes as many args as the handler declares -- which fails as
    'Object of type Request is not JSON serializable' from inside route.fulfill."""

    def handle(route):
        route.fulfill(status=status, content_type="application/json", body=body)

    return handle


def serve() -> tuple[socketserver.TCPServer, int]:
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(PAGE_DIR), **kw)

        def log_message(self, *a):  # silence; the harness owns the output
            pass

    socketserver.TCPServer.allow_reuse_address = True
    # Port 0: nobody but this script addresses this server, so it must not claim a named port.
    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# Fetched from inside the page, so the browser attaches the page's own Origin exactly as it would
# for a real payment. That header is the entire defect, and no Python request can reproduce it.
REACH = """async (hosts) => {
  const out = {};
  for (const [name, url] of Object.entries(hosts)) {
    try {
      const r = await fetch(url, {
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: JSON.stringify({jsonrpc:'2.0',id:1,method:'getLatestBlockhash',
                              params:[{commitment:'confirmed'}]}),
      });
      const t = await r.text();
      out[name] = {status: r.status, ok: r.ok, body: t.slice(0, 90)};
    } catch (e) {
      out[name] = {status: 'THREW', ok: false, body: String(e).slice(0, 90)};
    }
  }
  return out;
}"""

# The page's own poll, called directly against the live endpoint with a real settled signature.
POLL_LIVE = "async (sig) => await awaitConfirmation(sig)"

# The poll against an intercepted endpoint. Attempts and interval are shortened from the page's own
# ~90s so the timeout case is drivable; the loop under test is unchanged.
POLL_FAST = """async (sig) => {
  CONFIRM_ATTEMPTS = 3; CONFIRM_INTERVAL_MS = 50;
  return await awaitConfirmation(sig);
}"""

# What the customer actually sees for a given outcome. The two invariants are asserted on this,
# never on the outcome string: only 'confirmed' may read as paid, and no failing outcome may hand
# the Pay button back.
RENDER = """(o) => {
  renderOutcome(o, '4VUbLWcE2dPPYAXQVtH2Whvg1111111111111111111111111111111111111111111111111111');
  const card = document.getElementById('card');
  const pay  = document.getElementById('pay');
  const doc  = document.scrollingElement;
  return {
    text:        card.innerText.replace(/\\s+/g, ' ').trim(),
    payOffered:  !!pay && pay.offsetParent !== null && !pay.disabled,
    explorer:    !!document.querySelector('#status a.link'),
    docOverflow: doc.scrollWidth - doc.clientWidth,
  };
}"""

# A status body that is well-formed and never confirms, for the timeout case.
NEVER = '{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":[null]},"id":1}'
# A throttle. rpc() reads any non-ok response as null, the same branch an abort takes, so the poll
# must treat it as "ask again" rather than as a verdict.
THROTTLED = (
    '{"jsonrpc":"2.0","error":{"code":429,"message":"Too many requests"},"id":1}'
)
# A transaction the chain reports as errored.
ERRORED = (
    '{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":[{"slot":1,'
    '"confirmations":0,"err":{"InstructionError":[0,{"Custom":1}]},'
    '"confirmationStatus":"confirmed"}]},"id":1}'
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--viewport", choices=sorted(VIEWPORTS), default="desktop")
    args = ap.parse_args()

    # THREE THINGS CAN GO WRONG HERE AND ONLY ONE OF THEM IS A FINDING. A missing local dependency,
    # an unbuilt page and an unreachable endpoint all mean this harness could not look; a page that
    # classifies a payment wrongly is the defect it exists to catch. Every could-not-look branch
    # therefore says CANNOT CHECK and exits 2, and every one of them names WHAT was missing, because
    # a reader who cannot tell which of the three they have will treat the next real red the same way
    # they treated this one. Only a genuine finding prints FAIL and exits 1.
    if not (PAGE_DIR / "index.html").exists():
        print(
            f"CANNOT CHECK  no built page at {PAGE_DIR / 'index.html'}, so there is nothing to "
            "drive; this is a missing local artifact, not a finding about the page.",
            file=sys.stderr,
        )
        print("              build it: python webshop-pay/build.py", file=sys.stderr)
        return 2
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "CANNOT CHECK  the local dependency `playwright` is not importable, so the browser "
            "leg cannot run at all. Every assertion here needs a real page origin, which no Python "
            "request can supply, so this is a missing tool rather than a finding about the page.",
            file=sys.stderr,
        )
        print(
            f"              install it: {sys.executable} -m pip install playwright",
            file=sys.stderr,
        )
        return 2

    endpoint = read_pin(RPC_MARKER)
    proxy = read_pin(PROXY_MARKER)
    host = endpoint.split("//", 1)[1].split("/")[0]
    print(f"page rpc        : {endpoint}")
    print(f"settlement proxy: {proxy}   (the page's own escalation)")
    print(f"origin-hostile  : {ORIGIN_HOSTILE_RPC}   (the control)")

    # The two fresh fixtures, one per arm of awaitConfirmation's confirmed/finalized gate.
    fresh = fresh_signature(endpoint, "confirmed")
    final = fresh_signature(endpoint, "finalized")
    if not fresh or not final:
        # WHICH KIND OF NOTHING THIS IS. The proxy is a second, unrelated provider, so asking it the
        # same question separates "this machine cannot reach mainnet" from "the page's own endpoint
        # would not answer". Neither is a finding about the PAGE -- the poll uses getSignatureStatuses
        # and this is getSignaturesForAddress, so a refusal here says nothing about the poll -- but a
        # reader has to be able to tell them apart to know whether to look at the network or the node.
        control = fresh_signature(proxy, "confirmed")
        print(
            "CANNOT CHECK  no fresh mainnet signature to poll: "
            + (
                "the page's own RPC named none while the settlement proxy did, so this is about "
                "that endpoint rather than about this machine"
                if control
                else "neither the page's RPC nor the settlement proxy answered, so this machine "
                "could not reach mainnet at all"
            )
            + ". The confirmed direction would pass for the wrong reason, so this is a refusal to "
            "report rather than a finding about the page.",
            file=sys.stderr,
        )
        return 2
    print(
        f"fresh fixture   : {fresh['signature']}\n"
        f"                  slot {fresh['slot']}, {fresh['confirmationStatus']}, "
        f"named by the page's own RPC seconds ago"
    )
    print(
        f"finalized twin  : {final['signature']}\n"
        f"                  slot {final['slot']}, {final['confirmationStatus']}, "
        f"the other arm of the confirmed/finalized gate"
    )

    # The settled reference, kept as the LIVE control for the 'not seen' interception. Its expected
    # verdict is READ from the endpoint, so this stays a measurement rather than a pinned guess.
    aged_sig, found_via = settled_signature(endpoint, proxy)
    aged_want: str | None = None
    skipped: list[str] = []
    if not aged_sig:
        skipped.append(
            f"the live 'not seen' control: {PAID_REFERENCE} named no non-errored signature from "
            f"{found_via}"
        )
    else:
        answered, st = live_status(endpoint, aged_sig)
        if not answered:
            skipped.append(
                f"the live 'not seen' control: {endpoint} did not answer getSignatureStatuses for "
                f"{aged_sig}, so there is no measured verdict to hold the poll to"
            )
        else:
            aged_want = endpoint_verdict(st)
            print(
                f"settled control : {aged_sig}\n"
                f"                  found via {found_via}; the page's RPC serves "
                f"{'status ' + json.dumps(st) if st else 'null'} for it, "
                f"so the poll must return {aged_want!r}"
            )

    profile = VIEWPORTS[args.viewport]
    print(f"viewport        : {args.viewport}")

    srv, port = serve()
    failures: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="chrome")
            page = browser.new_page(**profile)
            page.goto(f"http://127.0.0.1:{port}{pay_url()}")
            page.wait_for_timeout(1500)

            # --- 1. reachable from a real page origin, and the old host still is not -------------
            reach = page.evaluate(REACH, {"page": endpoint, "old": ORIGIN_HOSTILE_RPC})
            print(f"\n--- browser reachability (origin http://127.0.0.1:{port}) ---")
            for name, r in reach.items():
                print(f"  {name:5s} {str(r['status']):6s} {r['body']}")
            if not reach["page"]["ok"]:
                failures.append(
                    f"the page's own endpoint {endpoint} does not answer a browser fetch "
                    f"(status {reach['page']['status']}); the desktop pay path cannot work"
                )
            if reach["old"]["ok"]:
                failures.append(
                    f"{ORIGIN_HOSTILE_RPC} now ANSWERS an Origin-bearing browser fetch. That is the "
                    "premise this whole change rests on, and it no longer holds; re-derive before "
                    "trusting anything here"
                )

            # --- 2. the poll, all three terminal states -----------------------------------------
            print("\n--- confirmation poll ---")

            # The page's REAL loop -- 45 attempts at 2s, untouched -- against a signature the same
            # endpoint named seconds ago. This one runs first because POLL_FAST below shortens those
            # globals for the rest of the session.
            got = page.evaluate(POLL_LIVE, fresh["signature"])
            print(f"  live, fresh confirmed sig      -> {got}")
            if got != "confirmed":
                failures.append(
                    f"poll on {fresh['signature']}, which {endpoint} itself listed as "
                    f"{fresh['confirmationStatus']} at slot {fresh['slot']}, returned {got!r} "
                    "rather than 'confirmed'; a settled payment would render as 'still confirming'"
                )

            got = page.evaluate(POLL_FAST, final["signature"])
            print(f"  live, fresh finalized sig      -> {got}")
            if got != "confirmed":
                failures.append(
                    f"poll on {final['signature']}, which {endpoint} itself listed as "
                    f"{final['confirmationStatus']} at slot {final['slot']}, returned {got!r} "
                    "rather than 'confirmed'; the finalized arm of the gate is broken"
                )

            # The live twin of the 'not seen' interception below: a REAL signature the endpoint
            # really does answer null for, held to the verdict that endpoint's own answer requires.
            if aged_want:
                got = page.evaluate(POLL_FAST, aged_sig)
                print(
                    f"  live, real sig below the floor -> {got}   "
                    f"(the endpoint's own answer requires {aged_want!r})"
                )
                if got != aged_want:
                    failures.append(
                        f"poll on {aged_sig} returned {got!r} while {endpoint} serves an answer "
                        f"that requires {aged_want!r}. The page and the chain disagree about a real "
                        "signature, and 'failed' here would claim no transfer happened when nothing "
                        "at all is known about it"
                    )

            for label, body, status, want in (
                ("endpoint answers 'not seen'", NEVER, 200, "unknown"),
                ("endpoint aborted", None, 0, "unknown"),
                ("endpoint rate-limits (429)", THROTTLED, 429, "unknown"),
                ("chain reports err", ERRORED, 200, "failed"),
            ):
                page.unroute_all()
                if body is None:
                    page.route(f"**{host}**", lambda route: route.abort())
                else:
                    page.route(f"**{host}**", fulfiller(body, status))
                got = page.evaluate(POLL_FAST, fresh["signature"])
                print(f"  {label:30s} -> {got}")
                if got != want:
                    failures.append(
                        f"poll with {label} returned {got!r}, want {want!r}"
                    )
            page.unroute_all()

            # --- 3. what each outcome puts on screen --------------------------------------------
            print("\n--- rendered outcome ---")
            for outcome, may_read_paid in (
                ("confirmed", True),
                ("failed", False),
                ("unknown", False),
            ):
                page.goto(f"http://127.0.0.1:{port}{pay_url()}")
                page.wait_for_timeout(400)
                r = page.evaluate(RENDER, outcome)
                paid = "✓" in r["text"] and ("Pago" in r["text"] or "Paid" in r["text"])
                print(
                    f"  {outcome:9s} readsPaid={str(paid):5s} payOffered={str(r['payOffered']):5s} "
                    f"explorerLink={str(r['explorer']):5s} overflow=+{r['docOverflow']}px"
                )
                print(f"            {r['text'][:150]}")
                if paid != may_read_paid:
                    failures.append(
                        f"outcome {outcome!r}: reads as paid = {paid}, want {may_read_paid}"
                    )
                if r["payOffered"]:
                    failures.append(
                        f"outcome {outcome!r}: the Pay button is offered again, which is how one "
                        "order takes two transfers"
                    )
                if not may_read_paid and not r["explorer"]:
                    failures.append(
                        f"outcome {outcome!r}: no explorer link, so the customer has no way to "
                        "check whether their money moved"
                    )
                if r["docOverflow"] > 1:
                    failures.append(
                        f"outcome {outcome!r}: the page scrolls sideways (+{r['docOverflow']}px)"
                    )
            browser.close()
    finally:
        srv.shutdown()

    print()
    for s in skipped:
        print(f"CANNOT CHECK  {s}", file=sys.stderr)
    if failures:
        for f in failures:
            print(f"FAIL  {f}", file=sys.stderr)
        return 1

    # THE BANNER NAMES ONLY WHAT RAN. A sub-check that could not look is a third state, not a pass,
    # so the line that would have claimed it is dropped and the heading says PARTIAL instead. The
    # exit code stays 0 because everything reachable was checked and did hold -- returning 2 here
    # would discard a real result to report a missing control.
    claims = [
        "the pay path's endpoint answers from a real page origin while the host it",
        "replaced still refuses one; the poll returns 'confirmed' for a signature that",
        "endpoint named seconds ago, at both commitments the page's gate accepts;",
    ]
    if aged_want:
        claims.append(
            "it agrees with that endpoint about a real signature below its retention"
        )
        claims.append("floor rather than calling one paid or failed;")
    claims.append(
        "it returns 'unknown' on both a silent and an aborted endpoint and 'failed'"
    )
    claims.append(
        "only when the chain says so; and no outcome but a confirmation reads as paid"
    )
    claims.append("or hands back the Pay button.")
    head = "PASS   " if not skipped else "PARTIAL"
    print(f"{head}  {claims[0]}")
    for line in claims[1:]:
        print(f"         {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
