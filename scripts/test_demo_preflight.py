#!/usr/bin/env python3
"""Prove scripts/demo-preflight.py can report RED, and can tell the two kinds apart.

    python3 scripts/test_demo_preflight.py

Hermetic: every case is served by a localhost HTTPServer this file starts. No network,
no live host, no subprocess, so a runner is exactly where it belongs.

WHY THIS EXISTS. A preflight that always prints green is worse than no preflight,
because a green check nobody has watched fail is a hypothesis rather than a verdict.
The one behaviour the whole tool rests on is the retry, and a retry is indistinguishable
from a swallowed failure unless something counts the attempts. So these cases assert the
REQUEST COUNT the server actually saw, not just the verdict: a classifier can return the
right answer for the wrong reason, and the count is what separates those.

THE DISCRIMINATING PAIR IS THE POINT. Cases 1 and 2 differ only in the status code. A
503 must be retried to exhaustion and land TRANSPORT; a 404 must be answered once and
land SUBSTANCE. Together they pin the retry as load-bearing in BOTH directions, so
widening it into an unconditional retry and narrowing it into no retry at all each turn
a case red. Either one alone would be satisfied by a broken classifier.
"""

import importlib.util
import json
import pathlib
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load():
    """Import the script by path, because its filename is not a legal module name."""
    path = ROOT / "scripts" / "demo-preflight.py"
    spec = importlib.util.spec_from_file_location("demo_preflight", path)
    # spec_from_file_location returns ModuleSpec | None, and a None loader is possible
    # too. Passing either onward fails with an error about the wrong thing.
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Keep the wall time of this suite off the retry backoff. The attempt COUNT is what
    # is under test; how long it waits between attempts is not.
    mod.BACKOFF = (0.02, 0.02)
    return mod


def serve(status, body=b"x"):
    """Start a localhost server that always answers `status`. Returns (url, hits)."""
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def _answer(self):
            hits.append(1)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = _answer
        do_HEAD = _answer

        # The base signature is log_message(self, format, *args); naming the first
        # parameter keeps this a valid override rather than a positional-only narrowing.
        def log_message(self, format, *args):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}/probe", hits


def main() -> int:
    dp = load()
    failures = []

    ran = []

    def check(label, cond, detail):
        # The count is DERIVED. A hardcoded total drifts the moment a case is added or
        # removed, and the first draft of this file printed "11" over 10 checks, which
        # is a suite lying about its own denominator.
        ran.append(label)
        print(f"  {'ok  ' if cond else 'FAIL'} {label}: {detail}")
        if not cond:
            failures.append(label)

    print(f"{ATTEMPTS_NOTE(dp)}\n")

    # 1. A retryable status is retried to exhaustion and classified TRANSPORT.
    url, hits = serve(503)
    r = dp.probe("503", url, expect=402, want_body=True)
    check(
        "503 retried to exhaustion",
        len(hits) == dp.ATTEMPTS,
        f"server saw {len(hits)} request(s), expected {dp.ATTEMPTS}",
    )
    check(
        "503 classified TRANSPORT",
        r.verdict == dp.RED and r.kind == dp.TRANSPORT,
        f"{r.verdict} {r.kind}",
    )

    # 2. The over-correction control. A NON-retryable wrong status is an answer, so it
    #    must be asked exactly once and classified SUBSTANCE. Without this, an
    #    unconditional retry would still pass case 1.
    url, hits = serve(404)
    r = dp.probe("404", url, expect=402, want_body=True)
    check(
        "404 asked exactly once",
        len(hits) == 1,
        f"server saw {len(hits)} request(s), expected 1",
    )
    check(
        "404 classified SUBSTANCE",
        r.verdict == dp.RED and r.kind == dp.SUBSTANCE,
        f"{r.verdict} {r.kind}",
    )

    # 3. The expected status is a PASS even when urllib raises it. A 402 arrives as an
    #    HTTPError, and treating that as a failure would redden the x402 endpoint on
    #    every healthy run, which is the element this tool exists to check.
    url, hits = serve(402, b'{"x402Version":2}')
    r = dp.probe("402", url, expect=402, want_body=True)
    check("402 is a pass", r.verdict == dp.GREEN, f"{r.verdict} {r.note}")
    check("402 asked once", len(hits) == 1, f"server saw {len(hits)} request(s)")

    # 4. Nothing resolves: connection refused is TRANSPORT, retried to exhaustion. This
    #    is the shape a dead endpoint on the night produces.
    r = dp.probe("dead", "http://127.0.0.1:9/probe", expect=200)
    check(
        "unreachable host is TRANSPORT",
        r.verdict == dp.RED and r.kind == dp.TRANSPORT,
        f"{r.verdict} {r.kind}",
    )

    # 5. A wrong content-type is SUBSTANCE, not transport. The demo mp4 serving HTML
    #    would be a real finding, and a 200 alone cannot see it.
    url, _ = serve(200)
    r = dp.probe("ctype", url, expect=200, method="HEAD", want_ctype="video/mp4")
    check(
        "wrong content-type is SUBSTANCE",
        r.verdict == dp.RED and r.kind == dp.SUBSTANCE,
        f"{r.verdict} {r.kind}",
    )

    # 6. Read-only is a property of the code. Any method that could write must be
    #    refused before a request is built, because the shop moves real money.
    refused = False
    try:
        dp.fetch_once("http://127.0.0.1:9/probe", "POST", False)
    except ValueError:
        refused = True
    check("POST refused by fetch_once", refused, "ValueError raised")

    # 7. THE REGRESSION. `--capture-dir` outside the repo root must not kill the report.
    #    `capture_label` is the exact line that used to raise, and it ran AFTER every
    #    probe and after the capture had already landed on disk, exiting 1, which is the
    #    NO-GO code, so a crash was indistinguishable from a real substantive finding.
    #
    #    The first draft of this case asserted on capture_price instead and would have
    #    passed against the broken build, because capture_price never raised: the write
    #    was always fine and the FORMATTING was the defect. A case pointed one function
    #    away from the bug is worse than no case, so both directions are pinned here.
    outside = (
        pathlib.Path(tempfile.gettempdir()).resolve() / "zc-preflight-outside.json"
    )
    if str(outside).startswith(str(ROOT)):
        check(
            "out-of-root path is genuinely out of root", False, f"{outside} is inside"
        )
    else:
        crashed = False
        label = ""
        try:
            label = dp.capture_label(outside)
        except ValueError:
            crashed = True
        check(
            "out-of-root capture path does not raise",
            not crashed and label == str(outside),
            f"label={label!r}" if not crashed else "ValueError raised",
        )

    # ...and the in-root path still relativises, so the fix did not simply delete the
    # behaviour it was meant to protect.
    inside = dp.capture_label(ROOT / "preflight-captures" / "x.json")
    check(
        "in-root capture path still relativises",
        inside == "preflight-captures/x.json",
        f"label={inside!r}",
    )

    # 8. The capture itself: written, dated, and labelled as a capture rather than
    #    presented as a live fetch.
    class FakeResult:
        body = b'{"x402Version":2}'
        headers = {"Content-Type": "application/json"}
        status = 402

    with tempfile.TemporaryDirectory() as td:
        p = dp.capture_price(FakeResult(), pathlib.Path(td) / "out")
        # Read the existence check INSIDE the block. The first draft asserted p.exists()
        # after the context manager had already deleted the directory, so a correct
        # capture reported as a failure. Cheap to get wrong, and it reads as a defect in
        # the code under test rather than in the test.
        wrote = p.exists()
        rec = json.loads(p.read_text(encoding="utf-8"))
    check(
        "capture is dated and labelled a capture",
        wrote
        and "CAPTURE" in rec["label"]
        and rec["captured_at_utc"].endswith("Z")
        and rec["http_status"] == 402,
        f"{p.name}, label starts {rec['label'][:22]!r}",
    )

    print()
    # A suite that ran nothing must not print the sentence a healthy suite prints.
    FLOOR = 8
    if len(ran) < FLOOR:
        print(f"FAIL  only {len(ran)} case(s) ran, expected at least {FLOOR}.")
        return 2
    if failures:
        print(f"{len(failures)} of {len(ran)} case(s) FAILED: {', '.join(failures)}")
        return 1
    print(f"all {len(ran)} case(s) pass")
    return 0


def ATTEMPTS_NOTE(dp):
    return f"demo-preflight probe classification, {dp.ATTEMPTS} attempts per probe"


if __name__ == "__main__":
    sys.exit(main())
