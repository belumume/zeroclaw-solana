#!/usr/bin/env python3
"""Negative control for verify-proof.py's shop-liveness check.

A green "3/3 live" proves the check can AGREE with a healthy endpoint. It does not prove
the check can DISAGREE, and a liveness check that cannot go red is decoration that reads
as coverage. This plants the two answers a broken shop would actually give and requires
the script to fail on both.

The mutation vehicle here is the endpoint rather than a source file, because that is what
this check reads. A local fixture server stands in for /health, so the mutants need no
node and no network beyond loopback.

Run:  python3 scripts/mutation-check-shop-liveness.py
Exit: 0 both planted defects caught, 1 one survived, 2 inconclusive (baseline not green).
"""

import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "verify-proof.py"
PORT = 4599

# The line the check prints. Matching on the prefix rather than the whole string so that
# rewording the detail does not silently turn this control into a no-op.
PASS_RE = re.compile(r"^PASS\s+shop agent process alive")
FAIL_RE = re.compile(r"^FAIL\s+shop agent")

# Mutant 1: the daemon stopped. This is the real failure the check exists to catch, and
# the one the live endpoint has never produced, so it has never been exercised in anger.
STOPPED = {
    "gate": "ok",
    "proves": "mutation-check fixture",
    "shop": {
        "active": False,
        "state": "inactive",
        "trace_age_seconds": 12,
        "unit": "zc-shop.service",
    },
}

# Mutant 2: the endpoint answers 200 and well-formed JSON but stops reporting the shop.
# A check that defaulted a missing field to something truthy would pass this, which is why
# the reader uses .get with no default.
NO_SHOP = {"gate": "ok", "proves": "mutation-check fixture"}

_payload = {"body": b"{}"}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = _payload["body"]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - signature is the base class's
        pass


def run(url=None):
    """Run the real verifier, optionally pointing its health check at the fixture."""
    env = dict(os.environ)
    if url:
        env["SHOP_HEALTH_URL"] = url
    p = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return p.returncode, p.stdout


def main():
    print("=== baseline must be GREEN before a mutation means anything ===")
    rc, out = run()
    base_line = next(
        (line for line in out.splitlines() if "shop agent" in line), "(no line printed)"
    )
    print(f"    {base_line}")
    if rc != 0 or not PASS_RE.match(base_line.strip()):
        print(
            "BASELINE NOT GREEN. Either the shop is genuinely down or the network is "
            "refusing, and a mutation result would be meaningless either way. Aborting."
        )
        return 2

    srv = HTTPServer(("127.0.0.1", PORT), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{PORT}/health"
    results = []
    try:
        for name, payload, why in (
            ("stopped daemon", STOPPED, "systemd reports the unit inactive"),
            (
                "shop field absent",
                NO_SHOP,
                "a 200 that stops reporting the shop at all",
            ),
        ):
            print(f"\n=== MUTATION: {name} ===")
            print(f"    ({why})")
            _payload["body"] = json.dumps(payload).encode()
            rc, out = run(url)
            line = next(
                (line for line in out.splitlines() if "shop agent" in line),
                "(no line printed)",
            )
            print(f"    {line}")
            caught = rc != 0 and bool(FAIL_RE.match(line.strip()))
            print(f"    exit={rc}  (MUST be non-zero)")
            results.append((name, caught))
    finally:
        srv.shutdown()
        srv.server_close()

    print()
    if all(caught for _, caught in results):
        print(
            "RESULT: both planted defects were caught. The check has discriminative power."
        )
        return 0
    survived = [n for n, c in results if not c]
    print(
        f"RESULT: a planted defect SURVIVED ({', '.join(survived)}). The check is weaker "
        f"than its green implies."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
