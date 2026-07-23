#!/usr/bin/env python3
"""Heartbeat for a device feed: alert if the on-chain sequence stops advancing.

The DePIN node's "yours, running" proof is that the feed keeps publishing. A
scheduled publisher can die silently (host asleep, key unfunded, a crash) and
the on-chain sequence simply stops, with no signal. This heartbeat makes a
stall LOUD: it reads the feed account, checks how long since the last publish,
and exits non-zero if that exceeds the threshold, so a cron/systemd timer or a
CI check can page you.

Stdlib only. Usage:
    FEED_PDA=<base58> [RPC_URL=...] [STALE_HOURS=8] python3 scripts/feed_heartbeat.py

Exit 0 = fresh; exit 1 = STALLED (or the account/RPC is unreadable). The feed
account layout is the zeroclaw_oracle DeviceFeed:
    8 disc | 32 authority | 32 device | 1 kind | 8 value(i64) | 1 scale(i8)
    | 12 unit | 8 sequence(u64) | 8 observed_at(i64) | 8 published_at(i64) | 1 bump
"""

import base64
import json
import os
import struct
import sys
import time
import urllib.request

RPC = os.environ.get("RPC_URL", "https://api.devnet.solana.com")
FEED = os.environ.get("FEED_PDA")
STALE_HOURS = float(os.environ.get("STALE_HOURS", "8"))

if not FEED:
    print(
        "FEED_PDA env var is required (the device feed PDA, base58).", file=sys.stderr
    )
    sys.exit(1)


def rpc(method, params):
    req = urllib.request.Request(
        RPC,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


try:
    res = rpc(
        "getAccountInfo", [FEED, {"encoding": "base64", "commitment": "confirmed"}]
    )
    val = res.get("result", {}).get("value")
    if not val:
        print(f"STALLED: feed account {FEED} not found on {RPC}", file=sys.stderr)
        sys.exit(1)
    data = base64.b64decode(val["data"][0])
    sequence = struct.unpack_from("<Q", data, 94)[0]
    value = struct.unpack_from("<q", data, 73)[0]
    published_at = struct.unpack_from("<q", data, 110)[0]
except Exception as e:  # noqa: BLE001 - a heartbeat must report any failure loudly
    print(f"STALLED: could not read feed ({type(e).__name__}: {e})", file=sys.stderr)
    sys.exit(1)

age_h = (time.time() - published_at) / 3600.0
status = "FRESH" if age_h <= STALE_HOURS else "STALLED"
print(
    f"{status}: feed {FEED[:8]}.. seq={sequence} value={value} last_publish={age_h:.1f}h ago (threshold {STALE_HOURS}h)"
)
sys.exit(0 if status == "FRESH" else 1)
