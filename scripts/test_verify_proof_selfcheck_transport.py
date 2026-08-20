#!/usr/bin/env python3
"""Controls for how the BOX SELF-CHECK block classifies its failures: transport, or a claim.

WHY THIS EXISTS, and why the neighbouring suite could not catch it.
`test_verify_proof_transport.py` proves the PREDICATE `is_transport_error` is right, in both
directions, with a mutation control. It says nothing about whether a caller consults it. The
box self-check block was the one gating block in verify-proof.py that never touched
`transport_fails`, so a 500, 502, 504 or 429 in front of the node -- which that same predicate
calls transport, and which its own suite pins -- was counted as a claim that stopped holding.
The script contradicted its own predicate at that call site.

WHAT THAT COST, in proof-check.yml rather than in theory. That workflow branches on the exit
code: 0 clean, 2 transport-only so retry, anything else a real finding that must NOT be retried.
A node briefly behind a bad gateway therefore exited 1, printed "A published claim stopped
holding. Not a transport problem.", failed on the first attempt, and named a claim that was
fine. The retry ladder the workflow builds for exactly this case was unreachable from this block.

THE DISCRIMINATING PAIR IS 500 vs 503, and it is why this suite keys on nothing else. Both are
5xx. Both must gate. They must be counted DIFFERENTLY, and before the fix they were identical:
  500  a server in front of the box declining to answer  -> transport, exit 2, retry is correct
  503  the box saying its route is live with no verdict  -> A CLAIM, exit 1, never retry
That 503 reading is deliberate and local: `is_transport_error` calls 503 transport, and this
endpoint gives it an application meaning the generic predicate cannot know -- the hourly timer
stopped. So case C is the over-correction control. Routing 503 through the predicate would make
every case here pass except that one, while converting a real finding into a retryable blip.

CALIBRATION FIRST, because an exit code is only meaningful when nothing else is failing. The
suite serves a healthy verdict and requires exit 0 before it believes any later run. If that
baseline is not clean the result is NOT CHECKED, which this repository does not treat as a pass:
it exits 2 and says which run was dirty, rather than reporting a green over an unmeasurable one.

COST: five full runs of verify-proof.py, each making real devnet RPC calls, so roughly four to
six minutes. It is not wired into CI here for that reason and because a third-party endpoint
refusing a request must never turn a pull request red; proof-check.yml is the workflow that
already owns that dependency. The 404 PEND branch is covered by verify_proof_selfcheck_control.py.

Run: python3 scripts/test_verify_proof_selfcheck_transport.py
"""

import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE / "verify-proof.py"

CLEAN = 0
CLAIM = 1  # a claim stopped holding; proof-check.yml must NOT retry
TRANSPORT = 2  # the network refused; proof-check.yml retries

TRANSPORT_LINE = "gating failure(s) were transport, not claims."
CLAIM_LINE = "gating failure(s) are claims that"

FRESH = 120


def verdict(ok=True, age=FRESH, sha="a0a7c2c994abeb2d5cd81149867f58f9a7f30e46"):
    return {
        "generated_at": "2026-08-19T06:00:00Z",
        "generated_at_epoch": 1786600800,
        "deployed_sha": sha,
        "ok": ok,
        "age_seconds": age,
        "served_at": "2026-08-19T06:02:00Z",
        "checks": [
            {"name": "manifest", "ok": True, "detail": "files match"},
            {"name": "mint", "ok": True, "detail": "no prohibited mint"},
        ],
    }


state = {"status": 200, "body": verdict()}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(state["body"]).encode()
        self.send_response(state["status"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        """Silence per-request logging so the control's own output stays readable."""


srv = HTTPServer(("127.0.0.1", 0), H)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()


def dead_port():
    """A port nothing is listening on, for the connection-refused case."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def run(url):
    t0 = time.time()
    r = subprocess.run(
        [sys.executable, str(TARGET)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "SHOP_SELFCHECK_URL": url},
    )
    return r.returncode, r.stdout + r.stderr, time.time() - t0


def run_in_process(source, url):
    """Drive a mutated verify-proof.py without writing a file.

    `__file__` is pinned to the real path so the script's own `parent` and `parent.parent`
    resolutions -- the repo root, and its offline-verifier sibling -- still land where they
    do in production. Nothing is written to disk, so there is no .pyc for a same-size,
    same-second edit to be masked by, which is the trap a temp-file mutant has to dodge.
    """
    ns = {"__name__": "vp_mutant", "__file__": str(TARGET)}
    saved = os.environ.get("SHOP_SELFCHECK_URL")
    os.environ["SHOP_SELFCHECK_URL"] = url
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            exec(compile(source, str(TARGET), "exec"), ns)
            try:
                ns["main"]()
                rc = CLEAN
            except SystemExit as exc:
                rc = exc.code if isinstance(exc.code, int) else 1
    finally:
        if saved is None:
            os.environ.pop("SHOP_SELFCHECK_URL", None)
        else:
            os.environ["SHOP_SELFCHECK_URL"] = saved
    return rc, buf.getvalue()


def serve(status, body=None):
    state["status"] = status
    state["body"] = body if body is not None else {"error": "n/a"}
    return f"http://127.0.0.1:{PORT}/selfcheck"


# The two additions under test, each unique to this block. Reverting both is the pre-fix file.
REVERSIONS = [
    (
        """            print(f"FAIL  box self-check returned HTTP {e.code}")
            selfcheck_gates = True
            fails += 1
            if is_transport_error(e):
                transport_fails += 1""",
        """            print(f"FAIL  box self-check returned HTTP {e.code}")
            selfcheck_gates = True
            fails += 1""",
    ),
    (
        """        print(f"FAIL  box self-check unreachable: {e}")
        selfcheck_gates = True
        fails += 1
        if is_transport_error(e):
            transport_fails += 1""",
        """        print(f"FAIL  box self-check unreachable: {e}")
        selfcheck_gates = True
        fails += 1""",
    ),
]


def main():
    print("CALIBRATION: an exit code means nothing while something else is failing.")
    rc, out, secs = run(serve(200, verdict()))
    print(f"  healthy verdict served -> rc={rc} ({secs:.0f}s)")
    if rc != CLEAN:
        tail = [ln for ln in out.splitlines() if ln.startswith("FAIL")]
        print(
            "\nNOT CHECKED, and NOT a pass: the baseline run is not clean, so no exit code"
        )
        print("below would be attributable to the self-check block. Failing lines:")
        for ln in tail[:8]:
            print(f"    {ln}")
        print(
            f"    ({len(tail)} FAIL line(s) in {len(out.splitlines())} lines of output)"
        )
        return 2
    print("  baseline clean, so every failure below is the self-check block's alone.\n")

    # EACH SETUP IS A THUNK, and that is load-bearing rather than a style choice. `serve()`
    # mutates one shared server state, so building these eagerly in a list literal runs every
    # serve() before any subprocess starts and leaves the LAST one standing: case A then ran
    # against case C's 503, was correctly classified as a claim, and reported the fix broken.
    # The instrument failed, not the subject. Bind the state immediately before each run.
    cases = [
        (
            "A  a 5xx in front of the box is TRANSPORT (exit 2, retryable)",
            lambda: serve(500, {"error": "bad gateway"}),
            TRANSPORT,
            TRANSPORT_LINE,
        ),
        (
            "B  an unreachable box is TRANSPORT (exit 2, retryable)",
            lambda: f"http://127.0.0.1:{dead_port()}/selfcheck",
            TRANSPORT,
            TRANSPORT_LINE,
        ),
        (
            "C  OVER-CORRECTION CONTROL: 503 stays A CLAIM (exit 1, never retried)",
            lambda: serve(503, {"error": "no verdict on disk"}),
            CLAIM,
            CLAIM_LINE,
        ),
    ]

    passed = failed = 0
    for name, setup, want_rc, want_line in cases:
        rc, out, secs = run(setup())
        ok = rc == want_rc and want_line in out
        if ok:
            passed += 1
            print(f"  ok   {name}  ({secs:.0f}s)")
        else:
            failed += 1
            print(f"  FAIL {name}\n       rc={rc} (expected {want_rc}), ")
            print(f"       {'found' if want_line in out else 'MISSING'}: {want_line!r}")
            for ln in out.splitlines()[-4:]:
                print(f"       | {ln}")

    print("\nMUTATION CONTROL (revert both additions; case A must go red):")
    src = TARGET.read_text(encoding="utf-8")
    mutant = src
    for anchor, replacement in REVERSIONS:
        if anchor not in mutant:
            print(f"  FAIL anchor absent, so this control tested nothing:\n{anchor}")
            failed += 1
            mutant = None
            break
        mutant = mutant.replace(anchor, replacement, 1)
    if mutant is not None:
        if mutant == src or len(mutant) == len(src):
            print("  FAIL the reversion changed nothing measurable; it proves nothing")
            failed += 1
        else:
            compile(
                mutant, str(TARGET), "exec"
            )  # a mutant that cannot parse tests nothing
            rc, out = run_in_process(mutant, serve(500, {"error": "bad gateway"}))
            if rc == CLAIM and CLAIM_LINE in out:
                passed += 1
                print(
                    f"  ok   pre-fix code calls a 500 a broken claim (rc={rc}); "
                    "proof-check.yml would refuse to retry it"
                )
            else:
                failed += 1
                print(
                    f"  FAIL mutant still classified it as transport (rc={rc}); case A"
                )
                print("       proves nothing about the fix")

    print(f"\n{passed}/{passed + failed} controls passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
