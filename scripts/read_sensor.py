#!/usr/bin/env python3
"""Acquire one ambient temperature reading for the DePIN feed. No key, no account.

WHY THIS EXISTS. `e2e-localnet/src/bin/feed_publish.rs` takes FEED_VALUE and
FEED_OBSERVED_AT as environment variables and fetches nothing itself: it is the signing
and publishing half of the node. Without this, a clone reproduces a device that signs
whatever number you hand it, which is not the claim the feed makes about itself. This is
the half that turns a signing binary into a node that reads the world.

The source is open-meteo because it needs no API key and no registration. That is the
whole point: a stranger reproduces the feed end to end without asking anyone for
anything. A credentialed source would turn a reproducibility claim into a request.

IT REFUSES RATHER THAN FABRICATING. A publisher that invents a value when the upstream is
down is signing over a lie, and the one thing this feed asserts is that the number came
from somewhere. `scripts/verify-proof.py` treats a feed older than 90 minutes as stale,
which is the margin that lets a refused reading pass without reading as a dead node.

THE EXIT CODES ARE THREE-STATE ON PURPOSE, because "could not reach it" and "it answered
and the answer is unusable" need opposite responses, and a caller cannot recover the
difference from a single failure code:

    0   a reading was obtained
    1   the upstream answered and the answer is unusable: no temperature_2m in the body, or
        a 4xx that is not a throttle. Both are defects to fix, and no number of retries helps
    2   the upstream was unreachable after retries; transient, and the scheduler simply
        publishes nothing this cycle

Usage:
    python3 scripts/read_sensor.py                        # human readable
    python3 scripts/read_sensor.py --json                 # {"value": 4440, ...}
    eval "$(python3 scripts/read_sensor.py --export)"     # FEED_VALUE / FEED_OBSERVED_AT
    python3 scripts/read_sensor.py --selftest             # offline, no network

The location defaults to the reference node's. Override it for your own, or replace this
script entirely with a physical probe: anything that prints the same JSON drops in.

    FEED_LAT=51.5 FEED_LON=-0.12 python3 scripts/read_sensor.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://api.open-meteo.com/v1/forecast"

# The program stores hundredths, and feed_publish.rs documents the same scale in its own
# header: FEED_VALUE is an i64 at scale -2, so 4190 means 41.90 C. Reading it from there
# rather than restating it would be better, but that file is Rust and this is the only
# other place the constant appears, so it is pinned here and asserted by --selftest.
SCALE = -2

UA = "Mozilla/5.0 (compatible; zeroclaw-depin-node/1.0)"
ATTEMPTS = 3
TIMEOUT_S = 20
BACKOFF_S = 4


class UpstreamRejected(Exception):
    """A 4xx that is not a throttle: the request is wrong, so the answer will not change.

    Kept distinct from ConnectionError because the caller maps them to different exit codes,
    and that distinction is the whole reason this script has three of them. Folding a
    malformed coordinate into "unreachable" tells the reader to wait for an outage to pass
    when what they actually have is a typo in FEED_LAT.
    """


def endpoint(lat: str, lon: str) -> str:
    return f"{API}?latitude={lat}&longitude={lon}&current=temperature_2m"


def parse_reading(payload: dict) -> int:
    """Celsius out of the payload, scaled to the i64 the program stores.

    Raises on an absent or non-numeric field rather than substituting anything. The caller
    maps that to exit 1 and not to exit 2, because a shape change is a defect and retrying
    it just pays for it three times.
    """
    celsius = payload["current"]["temperature_2m"]
    return int(round(float(celsius) * (10**-SCALE)))


def fetch(lat: str, lon: str) -> dict:
    last = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            req = urllib.request.Request(endpoint(lat, lon), headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # Caught BEFORE the handler below because HTTPError subclasses OSError, and
            # because a 4xx IS the answer here: reading the body keeps the reason instead
            # of losing it in a traceback. A 429 deserves another attempt; a 400 does not,
            # since the request will be malformed again next time.
            body = exc.read()[:200].decode("utf-8", "replace")
            last = f"HTTP {exc.code}: {body}"
            if exc.code < 500 and exc.code != 429:
                # This will not fix itself: a malformed coordinate, a renamed parameter, a
                # removed endpoint. Retrying pays for it three times and then reports it as an
                # outage, sending the reader to the wrong problem entirely. QUICKSTART invites
                # exactly this shape by documenting the FEED_LAT and FEED_LON override.
                raise UpstreamRejected(last)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            # Named rather than blanket-caught. These are what this call can actually
            # raise: URLError and OSError cover DNS, refused connections and socket
            # timeouts, and ValueError covers a body that is not JSON. Anything outside
            # that set is a bug in this file and should crash rather than be retried
            # three times and reported to the caller as an unreachable upstream.
            last = f"{type(exc).__name__}: {exc}"
        if attempt < ATTEMPTS:
            time.sleep(BACKOFF_S)
    raise ConnectionError(last or "unreachable")


def selftest() -> int:
    """Offline. Proves the scaling and, more importantly, that the parser REFUSES."""
    failures = []

    for celsius, want in ((44.4, 4440), (-3.5, -350), (0, 0), (41.90, 4190)):
        got = parse_reading({"current": {"temperature_2m": celsius}})
        if got != want:
            failures.append(f"{celsius} C should scale to {want}, got {got}")

    # THE CONTROL. Without a case the parser must refuse, four green scaling checks say
    # nothing about whether it validates anything at all, and a parser that returned 0 for
    # everything would pass the block above on one of its four cases.
    for bad in (
        {},
        {"current": {}},
        {"current": {"temperature_2m": "warm"}},
        {"current": {"temperature_2m": None}},
    ):
        try:
            parse_reading(bad)
            failures.append(f"the parser accepted a malformed payload: {bad!r}")
        except (KeyError, TypeError, ValueError):
            pass

    checks = 8
    print(f"selftest: {checks - len(failures)} of {checks} checks pass")
    for line in failures:
        print(f"  FAIL {line}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Acquire one keyless ambient reading for the DePIN feed."
    )
    ap.add_argument("--json", action="store_true", help="emit a JSON object")
    ap.add_argument("--export", action="store_true", help="emit shell export lines")
    ap.add_argument(
        "--selftest", action="store_true", help="offline checks, no network"
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    lat = os.environ.get("FEED_LAT", "24.47")
    lon = os.environ.get("FEED_LON", "39.61")

    try:
        payload = fetch(lat, lon)
    except UpstreamRejected as exc:
        print(
            f"FAIL  the upstream refused the request, which retrying will not change: {exc}",
            file=sys.stderr,
        )
        return 1
    except ConnectionError as exc:
        print(
            f"CANNOT READ  unreachable after {ATTEMPTS} attempts: {exc}",
            file=sys.stderr,
        )
        return 2

    try:
        value = parse_reading(payload)
    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"FAIL  a response arrived with no usable temperature_2m: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1

    observed_at = int(time.time())

    if args.export:
        print(f"export FEED_VALUE={value}")
        print(f"export FEED_OBSERVED_AT={observed_at}")
    elif args.json:
        print(
            json.dumps(
                {
                    "value": value,
                    "scale": SCALE,
                    "unit": "C",
                    "observed_at": observed_at,
                    "source": "open-meteo",
                    "latitude": lat,
                    "longitude": lon,
                }
            )
        )
    else:
        print(
            f"{value / (10**-SCALE):.2f} C  ->  FEED_VALUE={value} "
            f"(scale {SCALE})  FEED_OBSERVED_AT={observed_at}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
