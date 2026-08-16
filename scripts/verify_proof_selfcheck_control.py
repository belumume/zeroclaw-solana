"""Positive control for the box self-check claim in verify-proof.py.

Run from the repository root:  python3 scripts/verify_proof_selfcheck_control.py

Against the deployed gate today that claim prints PENDING, because the running build
predates the /selfcheck route. A check whose only observed output is PENDING has not
been shown to work: it would keep printing PENDING just as happily if its verdict
logic were deleted, and it would keep printing it after the route shipped and the
timer died.

So this serves crafted /selfcheck responses from a loopback server and asserts the
checker reaches the right verdict on each branch: a 404 from an old build, a 503 from
a live route with no verdict on disk, a fresh all-passing verdict, a drifted one, a
stale one, a malformed one, and an unexpected status. Every FAIL branch is exercised,
so the claim is known to be capable of going red before anyone relies on its green.

The 404 and 503 cases are the pair that matters most. They are the two that look alike
from a distance and need opposite responses -- one means "not shipped yet", the other
means "the check stopped running" -- so a control that only proved the endpoint can be
read would leave exactly that confusion untested.

Stdlib only, binds an ephemeral port, touches no network and no chain.
"""

import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

FRESH = 120
STALE = 99999  # comfortably past the 7800s default ceiling


def verdict(*, ok, age, checks=None, sha="abc1234"):
    return {
        "generated_at": "2026-08-16T06:00:00Z",
        "generated_at_epoch": 1786600800,
        "deployed_sha": sha,
        "ok": ok,
        "age_seconds": age,
        "served_at": "2026-08-16T06:02:00Z",
        "checks": checks
        if checks is not None
        else [
            {"name": "manifest", "ok": True, "detail": "8 files match"},
            {"name": "mint", "ok": True, "detail": "no prohibited mint"},
        ],
    }


DRIFTED = verdict(
    ok=False,
    age=FRESH,
    checks=[
        {
            "name": "manifest",
            "ok": False,
            "detail": "SKILL.md differs from the manifest",
        },
        {"name": "mint", "ok": True, "detail": "no prohibited mint"},
    ],
)

# (label, http status, body-or-None, expected line)
CASES = [
    (
        "404, build predates route",
        404,
        None,
        r"^PEND\s+box self-check not yet observable",
    ),
    (
        "503, route live, no verdict",
        503,
        {"error": "no verdict", "detail": "file absent"},
        r"^FAIL\s+box self-check endpoint is live but has no verdict",
    ),
    (
        "200, fresh and all passing",
        200,
        verdict(ok=True, age=FRESH),
        r"^PASS\s+box matches abc1234 on all 2 invariants",
    ),
    (
        "200, drifted",
        200,
        DRIFTED,
        r"^FAIL\s+box has DRIFTED from abc1234: manifest",
    ),
    (
        "200, stale (timer stopped)",
        200,
        verdict(ok=True, age=STALE),
        r"^FAIL\s+box self-check is 99999s old",
    ),
    (
        "200, malformed age",
        200,
        verdict(ok=True, age="recently"),
        r"^FAIL\s+box self-check malformed",
    ),
    (
        "200, checks not a list",
        200,
        {"ok": True, "age_seconds": FRESH, "checks": "two", "deployed_sha": "abc1234"},
        r"^FAIL\s+box self-check malformed",
    ),
    (
        "500, unexpected status",
        500,
        {"error": "boom"},
        r"^FAIL\s+box self-check returned HTTP 500",
    ),
]

# A green verdict must NOT be counted before it can go red, so the pass case also has to move the
# tally. Asserted separately below rather than folded into the pattern, because a claim that gates
# and a claim that merely prints are indistinguishable from the verdict line alone.
TALLY = re.compile(r"(\d+)/(\d+) live claims verified")

state = {"status": 200, "body": {}}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(state["body"]).encode()
        self.send_response(state["status"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Silence the per-request log so the control's own output stays readable."""


srv = HTTPServer(("127.0.0.1", 0), H)  # port 0: never collides with a live service
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

ok = True
tallies = {}
for name, status, body, pattern in CASES:
    state["status"] = status
    state["body"] = body if body is not None else {"error": "not found"}
    r = subprocess.run(
        [sys.executable, "scripts/verify-proof.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={
            **os.environ,
            "SHOP_SELFCHECK_URL": f"http://127.0.0.1:{port}/selfcheck",
        },
    )
    hit = [ln for ln in r.stdout.splitlines() if re.search(pattern, ln.strip())]
    m = TALLY.search(r.stdout)
    tallies[name] = m.group(2) if m else "?"
    shown = hit[0].strip()[:74] if hit else "expected /" + pattern[:44] + "/"
    print(f"  {name:30s} {'OK  ' if hit else 'MISS'} {shown}")
    if not hit:
        ok = False

srv.shutdown()

# The tally control. A PENDING claim must not be counted, and a judged one must be. If both read
# the same, the claim is decorative: it prints a verdict that changes nothing.
pend = tallies.get("404, build predates route")
judged = tallies.get("200, fresh and all passing")
counts = pend is not None and judged is not None and pend != judged
print(f"\n  PENDING totals {pend} live claims, a judged verdict totals {judged}")
print(f"  the claim actually gates rather than only printing: {counts}")

print(f"\nall {len(CASES)} branches reached: {ok}")
sys.exit(0 if ok and counts else 1)
