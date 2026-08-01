"""Positive control for the x402 ledger claim in verify-proof.py.

Run from the repository root:  python3 scripts/verify_proof_ledger_control.py

verify-proof.py checks a live node, and against the deployed gate today that claim
prints PENDING and gates nothing. A check whose only observed output is PENDING has
not been shown to work, and would keep printing PENDING just as happily if its
verdict logic were deleted.

This serves crafted /health payloads from a loopback server and asserts the checker
reaches the right verdict on each of the six branches: an absent ledger block, a
coherent one with sales restored, a coherent one on a node that has never sold, a
poisoned lock, a malformed field type, and the internally contradictory case where
spend exists but nothing was restored. Every FAIL branch is exercised, so the claim
is known to be capable of going red before anyone relies on it being green.

Stdlib only, binds an ephemeral port, touches no network and no chain.
"""

import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

SHOP_OK = {
    "unit": "zc-shop.service",
    "active": True,
    "state": "active",
    "trace_age_seconds": 60,
}

CASES = [
    ("absent ledger (old build)", None, r"^PEND\s+x402 cap-restart not yet observable"),
    (
        "coherent, sales restored",
        {
            "daily_cap_atomic_units": 20000000,
            "restored_sales_at_startup": 7,
            "unparseable_lines_skipped": 0,
            "redeemed_nonces": 7,
            "tracked_payer_days": 2,
            "settled_atomic_units": 3500000,
            "lock_healthy": True,
        },
        r"^PASS\s+x402 daily cap survived the last restart \(restored 7 sale",
    ),
    (
        "coherent, never sold",
        {
            "daily_cap_atomic_units": 20000000,
            "restored_sales_at_startup": 0,
            "unparseable_lines_skipped": 0,
            "redeemed_nonces": 0,
            "tracked_payer_days": 0,
            "settled_atomic_units": 0,
            "lock_healthy": True,
        },
        r"^PASS\s+x402 ledger block coherent .*shape check",
    ),
    (
        "poisoned lock",
        {
            "daily_cap_atomic_units": 20000000,
            "restored_sales_at_startup": 1,
            "unparseable_lines_skipped": 0,
            "redeemed_nonces": 1,
            "tracked_payer_days": 1,
            "settled_atomic_units": 1000000,
            "lock_healthy": False,
        },
        r"^FAIL\s+x402 ledger block malformed or lock poisoned",
    ),
    (
        "malformed field type",
        {
            "daily_cap_atomic_units": "twenty million",
            "restored_sales_at_startup": 1,
            "unparseable_lines_skipped": 0,
            "redeemed_nonces": 1,
            "tracked_payer_days": 1,
            "settled_atomic_units": 1000000,
            "lock_healthy": True,
        },
        r"^FAIL\s+x402 ledger block malformed",
    ),
    (
        "settled but nothing restored",
        {
            "daily_cap_atomic_units": 20000000,
            "restored_sales_at_startup": 0,
            "unparseable_lines_skipped": 0,
            "redeemed_nonces": 3,
            "tracked_payer_days": 1,
            "settled_atomic_units": 9000000,
            "lock_healthy": True,
        },
        r"^FAIL\s+x402 ledger inconsistent",
    ),
]

payload = {}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - matches the base signature
        """Silence the per-request log so the control's own output stays readable."""


srv = HTTPServer(("127.0.0.1", 0), H)  # port 0: never collides with a live service
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

ok = True
for name, ledger, pattern in CASES:
    payload.clear()
    payload.update({"gate": "ok", "shop": SHOP_OK, "proves": "control"})
    if ledger is not None:
        payload["ledger"] = ledger
    r = subprocess.run(
        [sys.executable, "scripts/verify-proof.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={
            **os.environ,
            "SHOP_HEALTH_URL": f"http://127.0.0.1:{port}/health",
        },
    )
    hit = [ln for ln in r.stdout.splitlines() if re.search(pattern, ln.strip())]
    print(
        f"  {name:32s} {'OK  ' if hit else 'MISS'} {(hit[0].strip()[:78] if hit else 'expected /' + pattern[:46] + '/')}"
    )
    if not hit:
        ok = False

srv.shutdown()
print("\nall six branches reached:", ok)
sys.exit(0 if ok else 1)
