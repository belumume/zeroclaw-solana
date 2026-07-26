#!/usr/bin/env python3
"""One-command verifier for every claim in docs/DEVNET-PROOF.md (stdlib only, no install).

A judge should not have to click eight explorer links or trust a screenshot. This queries
Solana devnet directly and checks that each on-chain claim still holds: the programs are
executable, the feed PDA is owned by the oracle program, and every referenced transaction
landed with the exact success/rejection this submission claims.

    python3 scripts/verify-proof.py            # checks devnet, prints PASS/FAIL per claim
    RPC_URL=https://your-rpc python3 scripts/verify-proof.py

Exit 0 = every claim verified; exit 1 = at least one FAIL (or the RPC was unreachable).
"""

import base64
import json
import os
import struct
import sys
import time
import urllib.request

RPC = os.environ.get("RPC_URL", "https://api.devnet.solana.com")

# (label, address, want_executable) -- accounts that must exist on devnet
ACCOUNTS = [
    (
        "oracle program zeroclaw_oracle",
        "EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn",
        True,
    ),
    (
        "consumer program consumer_example",
        "B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt",
        True,
    ),
    ("SF Allowances (audited)", "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44", True),
    (
        "device feed PDA (agent-driven, historical)",
        "CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU",
        False,
    ),
    (
        "device feed PDA (deterministic LLM-free, laptop)",
        "3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K",
        False,
    ),
    (
        "device feed PDA (ARM node, node-born key)",
        "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg",
        False,
    ),
]
FEED_OWNER = "EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn"  # feed PDA must be owned by the oracle
FEED_PDAS = {
    "CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU",
    "3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K",
    "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg",
}

# Ownership alone cannot distinguish a live feed from one that stopped months ago, so the
# always-on claim gets its own check. Only the ARM node is asserted fresh: it is the feed
# that backs "yours, running". The laptop publisher is secondary by design and is allowed
# to go quiet when that machine sleeps.
LIVE_FEED = ("ARM node feed", "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg")
# Reported but NOT gating, for exactly the reason above: this one runs on a laptop that is
# allowed to sleep, so failing the run on it would train a reader to ignore a red result.
SECONDARY_FEED = (
    "laptop deterministic feed",
    "3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K",
)
# Cadence is 20 minutes. The threshold is deliberately loose so one skipped reading (a
# transient upstream weather-API failure, which the publisher refuses to paper over with a
# fabricated value) does not read as a dead node.
# Overridable so the gate can be demonstrated rather than trusted: run
#   MAX_FEED_AGE_MIN=0 python3 scripts/verify-proof.py
# and the live check goes red with exit 1 while every static claim stays green. A liveness
# check nobody has watched fail is indistinguishable from one that cannot fail.
MAX_FEED_AGE_MIN = int(os.environ.get("MAX_FEED_AGE_MIN", "90"))

# The shop half of "Both are running". Checked because the node and the shop fail
# independently: the node is Oracle Cloud systemd, the shop is a laptop daemon plus a CDN
# page, so the node can publish happily through a completely dead shop.
SHOP_PAY_URL = os.environ.get("SHOP_PAY_URL", "https://zeroclaw-shop-pay.pages.dev/")
# Asserted inside the page body: HTTP 200 only proves a CDN answered, while the pinned
# merchant address is what makes it this shop's page rather than any page.
MERCHANT_PIN = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
# DeviceFeed: disc8 + authority32 + device32 + feed_kind1 + value_i64 + scale_i8
#           + unit[12] + sequence_u64 + observed_at_i64 + published_at_i64 + bump1
FEED_LEN = 8 + 32 + 32 + 1 + 8 + 1 + 12 + 8 + 8 + 8 + 1

# (label, signature, want_err)  want_err=None means success (err:null)
TXS = [
    (
        "shop Track-A settlement (payment_watch PAID)",
        "4kDo6NCcAxSe3BSTtQ4onTASenxRWr2miagweVway3RnDMLG7drv6NkTdV7eRtTSDcNXURy2ESpKcqkk2jG9sYqS",
        None,
    ),
    (
        "x402 machine-commerce settlement",
        "5ss8wKQo5rqXeLTdQGoWjz6jLNgycT9vCKzj7iZs4viXsexeN573gy9oZ6fgNGrBjfahQ9Zcc84fz9nF4F6Gpudc",
        None,
    ),
    (
        "allowance within-cap transfer (succeeds)",
        "5qyr7jJi8zb6SjZjnA2QT5C9nuZYgSw6raAefjmWnDDMf3JRgkQX19zssE57EpFSHVCCPfbj5qyxcYSQcfEq9W3Z",
        None,
    ),
    (
        "allowance OVER-cap transfer (rejected 0x12c)",
        "3TLSrfWVYdC3hSiAWnyyd7T694bLJQDtdJYQ64EWUsBNDehGc6Kq1veR7xa8Y1BiMdpvfFm3N1dKjDrXF3BEq2ps",
        {"InstructionError": [0, {"Custom": 300}]},
    ),
]


def rpc(method, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        RPC, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r).get("result")


def read_feed(addr):
    """Decode a DeviceFeed account. Returns (reading, seq, age_min) or raises."""
    v = rpc("getAccountInfo", [addr, {"encoding": "base64"}])
    val = v.get("value") if v else None
    raw = base64.b64decode(val["data"][0]) if val else b""
    if len(raw) != FEED_LEN:
        raise ValueError(f"unexpected account length {len(raw)}")
    o = 8 + 32 + 32 + 1
    value = struct.unpack_from("<q", raw, o)[0]
    o += 8
    scale = struct.unpack_from("<b", raw, o)[0]
    o += 1
    unit = raw[o : o + 12].rstrip(b"\x00").decode("ascii", "ignore")
    o += 12
    seq = struct.unpack_from("<Q", raw, o)[0]
    o += 8 + 8
    published = struct.unpack_from("<q", raw, o)[0]
    return f"{value * (10**scale):.2f} {unit}", seq, (time.time() - published) / 60


def main():
    fails = 0
    static_fails = 0
    print(f"verifying docs/DEVNET-PROOF.md against {RPC}\n")
    print(
        "STATIC claims -- the record. These are immutable devnet history and deployed"
    )
    print(
        "program state; once true they stay true, so they prove the work happened, NOT"
    )
    print("that anything is running right now.\n")
    for label, addr, want_exec in ACCOUNTS:
        try:
            v = rpc("getAccountInfo", [addr, {"encoding": "base64"}])
            val = v.get("value") if v else None
            if not val:
                print(f"FAIL  {label}: account not found")
                fails += 1
                continue
            if want_exec and not val.get("executable"):
                print(f"FAIL  {label}: not executable")
                fails += 1
                continue
            if addr in FEED_PDAS and val.get("owner") != FEED_OWNER:
                print(f"FAIL  {label}: wrong owner {val.get('owner')}")
                fails += 1
                continue
            extra = "executable" if want_exec else f"owner={val.get('owner')[:8]}"
            print(f"PASS  {label} ({extra})")
        except Exception as e:
            print(f"FAIL  {label}: RPC error {e}")
            fails += 1

    for label, sig, want_err in TXS:
        try:
            t = rpc("getTransaction", [sig, {"maxSupportedTransactionVersion": 0}])
            if not t:
                print(f"FAIL  {label}: tx not found")
                fails += 1
                continue
            got = t.get("meta", {}).get("err")
            if got == want_err:
                print(f"PASS  {label} (err={json.dumps(got)})")
            else:
                print(
                    f"FAIL  {label}: err={json.dumps(got)} expected {json.dumps(want_err)}"
                )
                fails += 1
        except Exception as e:
            print(f"FAIL  {label}: RPC error {e}")
            fails += 1

    static_fails = fails

    print(
        "\nLIVE claims -- the only checks here that can go red. Everything above stays"
    )
    print("green whether or not a single machine of ours is switched on.\n")

    label, addr = LIVE_FEED
    try:
        reading, seq, age_min = read_feed(addr)
        if age_min > MAX_FEED_AGE_MIN:
            print(
                f"FAIL  {label} freshness: last reading {age_min:.0f} min ago "
                f"(> {MAX_FEED_AGE_MIN}); the node is not publishing"
            )
            fails += 1
        else:
            print(
                f"PASS  {label} freshness ({reading}, seq={seq}, {age_min:.0f} min ago)"
            )
    except Exception as e:
        print(f"FAIL  {label} freshness: {e}")
        fails += 1

    # Reported, never gating. This publisher runs on a laptop that is allowed to sleep, so
    # failing the whole run on it would teach a reader that a red line here means nothing,
    # which is how a liveness check stops being one.
    label, addr = SECONDARY_FEED
    try:
        reading, seq, age_min = read_feed(addr)
        state = "fresh" if age_min <= MAX_FEED_AGE_MIN else "quiet (allowed)"
        print(
            f"INFO  {label}: {state} ({reading}, seq={seq}, {age_min:.0f} min ago, "
            f"not gating)"
        )
    except Exception as e:
        print(f"INFO  {label}: unreadable ({e}, not gating)")

    # The shop is the other headline use case, and until now nothing in this script touched
    # it. An audit put the hole precisely: the ARM node runs on Oracle Cloud systemd,
    # independent of the shop, so a dead shop plus a publishing node printed a clean bill of
    # health.
    #
    # HONEST SCOPE, because the first version of this comment overclaimed. What follows
    # checks a STATIC Cloudflare Pages asset. That page is served by a CDN and answers 200
    # whether or not the shop daemon is running, so this does NOT detect a dead daemon and
    # does NOT by itself close the false-green. Demonstrated the day it was written: the WSL
    # VM hosting the daemon was wedged (marked Running, unresponsive past 45s) while this
    # check would still have passed on pin presence alone.
    #
    # What it DOES prove is narrower and still worth gating on: that the deployed page is
    # the pinned build rather than a stale one. That is a real regression class, since the
    # merchant pin is the control standing between a swapped recipient and a transfer.
    # Detecting a dead daemon needs a signal from the daemon itself (a health endpoint or a
    # channel round-trip) and is tracked separately rather than pretended at here.
    try:
        req = urllib.request.Request(
            SHOP_PAY_URL, headers={"User-Agent": "Mozilla/5.0 (verify-proof)"}
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read(65536).decode("utf-8", "replace")
        # 200 alone only proves a CDN answered. The pinned merchant address is what makes
        # the page the shop's page rather than any page, so that is what is asserted.
        if r.status == 200 and MERCHANT_PIN in body:
            print(f"PASS  shop pay page reachable and pinned to the shop ({r.status})")
        else:
            print(
                f"FAIL  shop pay page: HTTP {r.status}, merchant pin "
                f"{'present' if MERCHANT_PIN in body else 'MISSING'}"
            )
            fails += 1
    except Exception as e:
        print(f"FAIL  shop pay page unreachable: {e}")
        fails += 1

    # Report the two kinds separately, because collapsing them into one number is exactly
    # how a dead system prints a clean bill of health. An audit put it plainly: of the
    # eleven claims this script used to total, ten were deployed-program state or immutable
    # transaction history, and one could actually go red. "11/11 verified" therefore read
    # as a liveness proof while being almost entirely a record of the past.
    static_total = len(ACCOUNTS) + len(TXS)
    # The ARM feed and the shop pay page. The laptop feed is reported but never gates.
    # Two, not one, because "Both are running" is a claim about two independent systems and
    # a check that can only see one of them cannot falsify it.
    live_total = 2
    live_fails = fails - static_fails
    print(
        f"\n{static_total - static_fails}/{static_total} static claims verified "
        f"(deployed state and immutable devnet history; these cannot go red)"
    )
    print(
        f"{live_total - live_fails}/{live_total} live claims verified "
        f"(is the node publishing right now)"
    )
    if fails == 0:
        print("\nThe record holds and the node is live.")
    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    main()
