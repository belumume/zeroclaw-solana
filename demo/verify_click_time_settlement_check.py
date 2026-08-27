#!/usr/bin/env python3
"""Prove the pay page re-checks settlement at CLICK time, in all three directions that matter.

WHY THIS EXISTS, and why demo/verify_paid_link_refused.py does not already cover it. That gate
drives the RENDER-time check: load a settled link, get a refusal. It cannot see the window this
one is about. The page answers "has this order been paid" once at load and again on a timer, so
what the card knows at the moment a customer clicks Pay is as old as the gap between two lookups
-- POLL_MS plus the lookup itself, which rpc() bounds at 6s per call with up to two calls, so
roughly eighteen seconds. A link that settles inside that gap is still showing a live Pay button,
and clicking it sends a second transfer for one order.

app.js now re-asks immediately before signAndSendTransaction, which signs AND broadcasts in one
call and is therefore the last instruction the page controls. This drives that line.

A refusal alone proves nothing -- a page that refused every click would look identical on the
settled case -- so this fails unless the page DISCRIMINATES across three directions:

  settled     settlement appears AFTER render, before the click  -> refuses, never signs
  unsettled   no settlement at any point                          -> signs normally
  dead        settlement lookup unreachable on BOTH hosts         -> signs  (fail open on ignorance)

`unsettled` and `dead` are the over-correction controls and they are the ones that matter most.
Refusing paying customers on an RPC blip is a worse defect than the double-payment window this
line closes, because that failure is invisible to both the customer and the shop.

AND A MUTATION CONTROL, because the three above are equally consistent with a harness that cannot
see the guard at all. The `settled` scenario is re-run against a MUTANT page with the guard line
deleted, and the run FAILS unless the mutant signs. That is what makes a green run evidence about
app.js rather than evidence about this file.

HERMETIC BY CONSTRUCTION. Every JSON-RPC response is stubbed by method, so there is no mainnet
fixture to go stale and no network to be flaky. That is a deliberate division of labour: the
existing gate owns the real-chain end-to-end proof, and this one owns the click-time ordering,
which needs a settlement to appear at a controlled instant -- something no real fixture can do.

NOTHING IN THE REPOSITORY IS WRITTEN. The page is assembled into a temp tree by the project's own
build.py rather than by a second copy of the assembler here, so this cannot drift from what ships
and cannot leave the working tree dirty.

Run it:  python demo/verify_click_time_settlement_check.py

Needs playwright (pip install playwright). Drives the system Chrome via channel="chrome", so no
browser download is required. Everything else is stdlib.
"""

from __future__ import annotations

import http.server
import json
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from base64 import urlsafe_b64encode
from pathlib import Path
from urllib.parse import quote

REPO = Path(__file__).resolve().parent.parent
PAGE_DIR = REPO / "webshop-pay"

# Read the pins out of the page rather than restating them, for the reason the sibling gate gives:
# a second copy here would drift, and the drifted copy is the one a reader trusts. The RPC hosts
# especially -- the intercepts below are derived from whatever the page NAMES, so a repoint cannot
# leave this stubbing a host nothing contacts and passing for free.
MERCHANT_MARKER = "var MERCHANT='"
RPC_MARKER = "var RPC='"
PROXY_MARKER = "var SETTLEMENT_PROXY='"

# The line under test. Asserted present in the pristine source before anything runs: if it is gone,
# every case below would still pass by accident and report a guard that does not exist.
GUARD_LINE = "if(await checkAlreadyPaid())return;"

# A syntactically valid pubkey with no meaning. Nothing looks it up on a real network -- the
# settlement responses are stubbed -- so it needs only to satisfy the page's own isPubkey().
REFERENCE = "5Zzguz4NsSRFxGkHfM4KmJTNVPMJ2P3jFa2y8bTHY4kW"

# 88 base58 characters, so it satisfies isSig() and is recognisable in the card text.
STUB_SIG = "zc" * 44

# 32 zero bytes, base58: a structurally valid blockhash, which Transaction.serialize needs.
STUB_BLOCKHASH = "1" * 32

# The payer. Never signs anything; the wallet stub throws before it could.
STUB_PAYER = "D7o5YEE6ZTnQMBLbeimEBcgLxvVUZ5eNCzB6nwTU8Xdk"

AMOUNT = "0.001"  # SOL, deliberately: a SOL link skips getMint and the token-balance preflight,
# so the flow reaches the signature request. A token link stops at "this wallet holds 0" first.

# How long a click is given to reach a terminal state. Polled, not slept: the sibling gate's one
# real defect was a fixed wait racing a refusal whose timing moves with proxy load, so this waits
# for the CONDITION and reports how long it took.
TERMINAL_TIMEOUT_MS = 25000
POLL_MS = 150

# The page's own first poll tick fires at POLL_MS=6000. Every case below must reach its terminal
# state before then, which is what proves the verdict came from the click-time check rather than
# from a background poll that happened to see the same stubbed settlement.
FIRST_POLL_TICK_MS = 6000


def read_pin(src: str, marker: str) -> str:
    i = src.index(marker) + len(marker)
    return src[i : src.index("'", i)]


def host_glob(endpoint: str) -> str:
    return "**" + endpoint.split("//", 1)[-1].rstrip("/") + "**"


def build_page(dest: Path, mutate: bool) -> Path:
    """Assemble the page into `dest` using the project's own build.py.

    Copies the sources rather than importing the assembler, because build.py writes to a path
    derived from its own location. Running the real thing in a temp tree keeps this file from
    carrying a second copy of the assembly order, which is the drift build.py's own docstring
    exists to prevent.
    """
    page = dest / "webshop-pay"
    page.mkdir(parents=True, exist_ok=True)
    shutil.copytree(PAGE_DIR / "src", page / "src")
    shutil.copytree(PAGE_DIR / "vendor", page / "vendor")
    shutil.copy2(PAGE_DIR / "qrcode.js", page / "qrcode.js")
    shutil.copy2(PAGE_DIR / "build.py", page / "build.py")

    app = page / "src" / "app.js"
    src = app.read_text(encoding="utf-8")
    if mutate:
        # Delete the guard, leaving everything else byte-identical. If the harness cannot tell this
        # page from the real one, it is not measuring the guard.
        stripped = "\n".join(ln for ln in src.split("\n") if ln.strip() != GUARD_LINE)
        if stripped == src:
            raise SystemExit(
                f"FAIL mutation control could not find {GUARD_LINE!r} to remove; "
                "the mutant would be identical to the real page and would prove nothing"
            )
        app.write_text(stripped, encoding="utf-8", newline="\n")

    r = subprocess.run(
        [sys.executable, "build.py"], cwd=str(page), capture_output=True, text=True
    )
    if r.returncode != 0:
        raise SystemExit(f"FAIL build.py in temp tree: {r.stdout}{r.stderr}")
    return page


def pay_url(merchant: str) -> str:
    solana = (
        f"solana:{merchant}?amount={AMOUNT}&reference={REFERENCE}"
        f"&label={quote('Mesa 4')}&message={quote('Pedido 412')}"
    )
    return f"/index.html?u={urlsafe_b64encode(solana.encode()).decode()}"


def serve(directory: Path) -> tuple[socketserver.TCPServer, int]:
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(directory), **kw)

        def log_message(self, *a):
            pass

    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# The wallet the page will find. Two shapes, because app.js branches on them at the exact line
# under test and a guard proven on one shape says nothing about the other. Neither can move funds:
# both record the attempt and throw, so reaching the signature request is observable and reaching
# the chain is impossible.
WALLET_JS = """
(() => {
  window.__zcSign = 0;
  const record = () => { window.__zcSign++; throw new Error('ZC-STUB-STOP'); };
  const SHAPE = '__SHAPE__', ADDR = '__PAYER__';
  if (SHAPE === 'legacy') {
    // A legacy provider hands back a PublicKey object, so build a real one from the page's own
    // vendored bundle rather than a string the transaction builder would reject.
    window.backpack = {
      connect: async () => {
        const { web3 } = await import('/vendor/solana-bundle.js');
        return { publicKey: new web3.PublicKey(ADDR) };
      },
      signAndSendTransaction: async () => record(),
    };
  } else {
    // A Wallet Standard wallet hands back an address STRING; the page constructs the PublicKey.
    const wallet = {
      name: 'Stub Standard Wallet',
      icon: 'data:image/svg+xml;base64,PHN2Zy8+',
      features: {
        'standard:connect': { connect: async () => ({ accounts: [{ address: ADDR }] }) },
        'solana:signAndSendTransaction': { signAndSendTransaction: async () => record() },
      },
    };
    // The app-ready direction of the handshake: the page dispatches it inside enumerateWallets and
    // hands over a register callback. Registering from a register-wallet event instead would race
    // the page's own listener, which is added in that same function.
    window.addEventListener('wallet-standard:app-ready', (e) => {
      try { e.detail.register(wallet); } catch (_) {}
    });
  }
})();
"""

PROBE = """() => {
  const card = document.getElementById('card');
  const pay  = document.getElementById('pay');
  const text = card ? card.innerText.replace(/\\s+/g, ' ').trim() : '';
  return {
    signCalls: window.__zcSign || 0,
    payable:   !!pay && pay.offsetParent !== null,
    text:      text,
  };
}"""


class Stub:
    """Answers every JSON-RPC call the page makes, by method, from controlled state.

    `settled` starts false so the page renders payable, and is flipped by the harness at the
    instant of the click. That is the whole point: a settlement that appears between the last
    lookup and the click is the condition no render-time check can catch.

    Counts calls SINCE the flip separately, so a refusal can be attributed to the click-time
    lookup rather than to a background poll that saw the same state.
    """

    def __init__(self, mode: str):
        self.mode = mode  # settled | unsettled | dead
        self.armed = False
        self.sigs_before = 0
        self.sigs_after = 0

    def arm(self):
        self.armed = True

    def handler(self, route):
        try:
            body = json.loads(route.request.post_data or "{}")
        except Exception:
            body = {}
        calls = body if isinstance(body, list) else [body]
        method = (calls[0] or {}).get("method", "")

        if method == "getSignaturesForAddress":
            if self.armed:
                self.sigs_after += 1
            else:
                self.sigs_before += 1
            if self.mode == "dead":
                route.abort()
                return
            settled = self.mode == "settled" and self.armed
            result = (
                [
                    {
                        "signature": STUB_SIG,
                        "err": None,
                        "slot": 1,
                        "confirmationStatus": "confirmed",
                    }
                ]
                if settled
                else []
            )
        elif method == "getLatestBlockhash":
            result = {
                "context": {"slot": 1},
                "value": {
                    "blockhash": STUB_BLOCKHASH,
                    "lastValidBlockHeight": 1000,
                },
            }
        else:
            # Includes getTransaction. Null is a legitimate answer the page already handles: the
            # refusal card simply names no figure. Nothing here needs it to succeed.
            result = None

        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": (calls[0] or {}).get("id", 1),
                    "result": result,
                }
            ),
        )


def run_case(
    pw, base: str, merchant: str, globs: list[str], mode: str, shape: str
) -> dict:
    stub = Stub(mode)
    browser = pw.chromium.launch(channel="chrome", headless=True)
    try:
        ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        page = ctx.new_page()
        page.add_init_script(
            WALLET_JS.replace("__SHAPE__", shape).replace("__PAYER__", STUB_PAYER)
        )
        for g in globs:
            page.route(g, stub.handler)

        page.goto(base + pay_url(merchant), wait_until="load")
        page.wait_for_selector("#pay", state="visible", timeout=15000)

        # Arm and click together. The page's own poll does not tick until 6s after load, and the
        # elapsed assertion below proves the terminal state was reached well inside that, so the
        # settlement can only have been seen by the click-time lookup.
        stub.arm()
        t0 = time.monotonic()
        page.click("#pay")

        r = {}
        deadline = t0 + TERMINAL_TIMEOUT_MS / 1000.0
        while time.monotonic() < deadline:
            r = page.evaluate(PROBE)
            if r["signCalls"] > 0 or not r["payable"]:
                break
            page.wait_for_timeout(POLL_MS)
        r["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
        r["sigs_after_arm"] = stub.sigs_after
        r["sigs_before_arm"] = stub.sigs_before
        ctx.close()
        return r
    finally:
        browser.close()


def main() -> int:
    src = (PAGE_DIR / "src" / "app.js").read_text(encoding="utf-8")
    merchant = read_pin(src, MERCHANT_MARKER)
    globs = [
        host_glob(read_pin(src, RPC_MARKER)),
        host_glob(read_pin(src, PROXY_MARKER)),
    ]

    print("page          :", PAGE_DIR / "src" / "app.js")
    print("merchant      :", merchant)
    print("intercepting  :", ", ".join(globs))

    # POSITIVE CONTROL ON THE SUBJECT, before any browser opens. A zero here would make every case
    # below pass while measuring nothing, which is the exact shape of a green run that means
    # nothing.
    n_guard = sum(1 for ln in src.split("\n") if ln.strip() == GUARD_LINE)
    print(
        f"guard line    : {n_guard} occurrence(s) of {GUARD_LINE!r} in {len(src.splitlines())} lines"
    )
    if n_guard != 1:
        print(f"FAIL expected exactly 1 guard line in app.js, found {n_guard}")
        return 1

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "CANNOT CHECK  playwright is not installed (pip install playwright); "
            "this is not a pass"
        )
        return 2

    #  name        mode         mutant  want_sign  why
    CASES = [
        ("settled", "settled", False, False),  # refuses at the click
        ("unsettled", "unsettled", False, True),  # a good order still pays
        ("dead", "dead", False, True),  # fail open on ignorance
        (
            "MUTANT",
            "settled",
            True,
            True,
        ),  # guard removed: must sign, or this proves nothing
    ]

    failures: list[str] = []
    tmp = Path(tempfile.mkdtemp(prefix="zc-clicktime-"))
    try:
        trees = {
            False: build_page(tmp / "real", mutate=False),
            True: build_page(tmp / "mutant", mutate=True),
        }
        servers = {}
        for mutant, page_dir in trees.items():
            srv, port = serve(page_dir)
            servers[mutant] = (srv, f"http://127.0.0.1:{port}")

        with sync_playwright() as pw:
            for name, mode, mutant, want_sign in CASES:
                for shape in ("standard", "legacy"):
                    base = servers[mutant][1]
                    r = run_case(pw, base, merchant, globs, mode, shape)
                    signed = r["signCalls"] > 0
                    tag = f"{name}/{shape}"
                    print(
                        f"  {tag:<18} signed={signed!s:<5} payable={r['payable']!s:<5} "
                        f"lookups after click={r['sigs_after_arm']} "
                        f"elapsed={r['elapsed_ms']}ms"
                    )
                    if signed != want_sign:
                        failures.append(
                            f"{tag}: expected signed={want_sign}, got {signed}"
                            + (
                                "  -- the guard is not reached on this wallet shape"
                                if want_sign is False
                                else "  -- a payment that should have proceeded was blocked"
                            )
                        )
                    if not want_sign:
                        if r["payable"]:
                            failures.append(
                                f"{tag}: refused without clearing the Pay button"
                            )
                        if STUB_SIG not in r["text"]:
                            failures.append(
                                f"{tag}: refusal card does not name the settling signature"
                            )
                        if r["sigs_after_arm"] != 1:
                            failures.append(
                                f"{tag}: {r['sigs_after_arm']} settlement lookups after the click, "
                                "expected exactly 1 (the click-time check)"
                            )
                        if r["elapsed_ms"] >= FIRST_POLL_TICK_MS:
                            failures.append(
                                f"{tag}: refused after {r['elapsed_ms']}ms, at or past the "
                                f"{FIRST_POLL_TICK_MS}ms poll tick, so the background poll cannot "
                                "be ruled out as the cause"
                            )
        for srv, _ in servers.values():
            srv.shutdown()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if failures:
        for f in failures:
            print("FAIL " + f)
        return 1
    print(
        f"PASS {len(CASES) * 2} case(s): the page re-checks settlement at click time on both "
        "wallet shapes, still pays a good order, still pays when the chain cannot answer, and "
        "the mutant without the guard signs a settled order (so this gate can fail)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
