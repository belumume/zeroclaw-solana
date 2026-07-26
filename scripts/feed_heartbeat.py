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

Exit 0 = fresh. Exit 1 = STALLED, meaning the feed itself stopped advancing or
the account is gone. Exit 2 = UNKNOWN, meaning the network would not answer, so
this run has no opinion either way.

That third code is the point. An alarm that fires on a network blip is an alarm
people learn to ignore, and this project has already paid for that once: a
publisher died silently for 6.6 hours while three separate layers reported fine.
"The publisher is dead" and "I could not reach the RPC just now" are different
facts and used to share exit 1, which the previous docstring admitted in passing
("or the account/RPC is unreadable") without treating it as a defect. A caller
can now retry a 2 and page on a 1. Same distinction, and the same reasoning, as
scripts/verify-proof.py; the two are separate stdlib-only files on purpose, so
the small transport predicate is duplicated rather than shared.

The feed account layout is the zeroclaw_oracle DeviceFeed:
    8 disc | 32 authority | 32 device | 1 kind | 8 value(i64) | 1 scale(i8)
    | 12 unit | 8 sequence(u64) | 8 observed_at(i64) | 8 published_at(i64) | 1 bump
"""

import base64
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

RPC = os.environ.get("RPC_URL", "https://api.devnet.solana.com")
FEED = os.environ.get("FEED_PDA")
STALE_HOURS = float(os.environ.get("STALE_HOURS", "8"))

if not FEED:
    print(
        "FEED_PDA env var is required (the device feed PDA, base58).", file=sys.stderr
    )
    sys.exit(1)


ATTEMPTS = 3


def is_transport_error(e):
    """True when the network refused, rather than the feed having a real problem."""
    if isinstance(e, urllib.error.HTTPError):
        return e.code >= 500
    if isinstance(e, urllib.error.URLError):
        return True
    return isinstance(e, (TimeoutError, ConnectionError))


class Unreachable(Exception):
    """The RPC never answered, so this run cannot judge the feed either way."""


def rpc(method, params):
    for attempt in range(ATTEMPTS):
        req = urllib.request.Request(
            RPC,
            data=json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.load(r)
        except Exception as e:
            if not is_transport_error(e):
                raise
            if attempt == ATTEMPTS - 1:
                raise Unreachable(f"{type(e).__name__}: {e}") from e
            time.sleep(1.0 * (attempt + 1))


try:
    res = (
        rpc("getAccountInfo", [FEED, {"encoding": "base64", "commitment": "confirmed"}])
        or {}
    )
    val = res.get("result", {}).get("value")
    if not val:
        # A missing account is a real finding about the feed, not about the network.
        print(f"STALLED: feed account {FEED} not found on {RPC}", file=sys.stderr)
        sys.exit(1)
    data = base64.b64decode(val["data"][0])
    sequence = struct.unpack_from("<Q", data, 94)[0]
    value = struct.unpack_from("<q", data, 73)[0]
    published_at = struct.unpack_from("<q", data, 110)[0]
except Unreachable as e:
    # Exit 2, never 1. Reporting "STALLED" here would be the alarm lying: we did not
    # observe a stalled feed, we failed to observe anything. Retries are already spent
    # by this point, so the network is genuinely not answering rather than flickering.
    print(f"UNKNOWN: RPC did not answer after {ATTEMPTS} tries ({e})", file=sys.stderr)
    sys.exit(2)
except Exception as e:  # noqa: BLE001 - any real read failure must still be loud
    # Decode failures land here and DO mean exit 1: the account answered and its bytes
    # were not a DeviceFeed, which is a genuine problem with the thing being watched.
    print(f"STALLED: could not read feed ({type(e).__name__}: {e})", file=sys.stderr)
    sys.exit(1)

age_h = (time.time() - published_at) / 3600.0
status = "FRESH" if age_h <= STALE_HOURS else "STALLED"
print(
    f"{status}: feed {FEED[:8]}.. seq={sequence} value={value} last_publish={age_h:.1f}h ago (threshold {STALE_HOURS}h)"
)
sys.exit(0 if status == "FRESH" else 1)
