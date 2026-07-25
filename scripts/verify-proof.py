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
# Cadence is 20 minutes. The threshold is deliberately loose so one skipped reading (a
# transient upstream weather-API failure, which the publisher refuses to paper over with a
# fabricated value) does not read as a dead node.
MAX_FEED_AGE_MIN = 90
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


def main():
    fails = 0
    print(f"verifying docs/DEVNET-PROOF.md against {RPC}\n")
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

    # Freshness: decode the live feed and prove it is still being written to.
    label, addr = LIVE_FEED
    try:
        v = rpc("getAccountInfo", [addr, {"encoding": "base64"}])
        val = v.get("value") if v else None
        raw = base64.b64decode(val["data"][0]) if val else b""
        if len(raw) != FEED_LEN:
            print(f"FAIL  {label} freshness: unexpected account length {len(raw)}")
            fails += 1
        else:
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
            age_min = (time.time() - published) / 60
            reading = f"{value * (10**scale):.2f} {unit}"
            if age_min > MAX_FEED_AGE_MIN:
                print(
                    f"FAIL  {label} freshness: last reading {age_min:.0f} min ago "
                    f"(> {MAX_FEED_AGE_MIN}); the node is not publishing"
                )
                fails += 1
            else:
                print(
                    f"PASS  {label} freshness ({reading}, seq={seq}, "
                    f"{age_min:.0f} min ago)"
                )
    except Exception as e:
        print(f"FAIL  {label} freshness: RPC error {e}")
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

    # +1 for the liveness check, which can fail and so must be in the denominator.
    total = len(ACCOUNTS) + len(TXS) + 1
    print(f"\n{total - fails}/{total} claims verified")
    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    main()
