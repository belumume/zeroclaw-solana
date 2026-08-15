#!/usr/bin/env python3
"""Read a signed FX rate off a `zeroclaw_oracle` DeviceFeed, or refuse.

WHY THIS EXISTS. `pay_link.py` takes `--rate` from its caller, and its own comment says what
that costs: the model supplies both the amount and the inputs, so the check catches ARITHMETIC
error and not INTENT error, and a consistent lie passes. The shop settles real USDC on mainnet,
so that is an injection path to money in a running system.

WHAT IT CANNOT DO YET, STATED FIRST BECAUSE IT DECIDES WHETHER TO USE THIS AT ALL.
**No BRL/USD feed exists on chain.** The only live DeviceFeed publishes TEMPERATURE:
`feed_kind=0`, `unit="C"`, currently 30.50 degrees. An earlier version of this reader was
proven against that account and printed `33.40` as though it were a rate. Wired to the pay
path it would have quoted R$100 at 3.28 USDC instead of about 19.69, from a thermometer.

So this script REFUSES until someone pins the constants below to a real rate feed. That is the
whole point: it fails closed rather than pricing an order off whatever account it is handed.
Closing the price hole is blocked on PUBLISHING a rate feed, not on this reader.

WHAT IT STILL WOULD NOT CLOSE, once a feed exists. The order VALUE stays model-supplied, so
"table 4, R$ 0.05" passes every check here. Pinning the rate removes one free parameter of two.
Closing the second needs a priced SKU table, an order id resolved against a store, or a
merchant confirmation. This is a step, not the end of the road.

NETWORK NOTE. The feed is DEVNET and the settlement is MAINNET. Devnet SOL is free and
`register_device` is permissionless, so a devnet feed is cheap for anyone to stand up and a
devnet reset deletes it. A rate carrying mainnet weight must come from a mainnet feed.

FAIL CLOSED, EVERYWHERE. Unreachable RPC, undecodable account, wrong owner, wrong PDA, wrong
device, wrong kind, wrong unit, implausible value, stale publish: every one refuses. There is
deliberately no fallback to a caller-supplied number, because a fallback restores the hole
under exactly the conditions an attacker can induce, and inducing an RPC failure is cheaper
than forging a signature.

EXIT CODES, matching the house convention used by verify-proof.py, feed_heartbeat.py and
check-config-drift.py, so a caller can branch without parsing prose:
  0  a rate was read and printed
  1  REFUSED: a real finding. Never retry; the answer will not change.
  2  COULD NOT CHECK: transport failed. Retrying is reasonable.

NO ARGUMENTS BEYOND THE ACCOUNT, BY DESIGN. There is no `--rpc` and no `--max-age-min`. Both
existed and both were laundering devices: `--rpc http://attacker/` returns a forged account
with the right owner string and any value, which passes every content check for the price of
no keypair and no fee; `--max-age-min 999999999` accepts a year-old rate. Anything an agent can
reach (argv, env, config, memory) is not a control, and this runs at the last point before a
customer is asked for money.

Usage:  python3 scripts/rate_from_feed.py <feed-pubkey>
        python3 scripts/rate_from_feed.py --selftest
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal
from typing import NoReturn

# DeviceFeed layout, from onchain/programs/zeroclaw-oracle/src/lib.rs and mirrored in
# scripts/feed_heartbeat.py:
#   8 disc | 32 authority | 32 device | 1 kind | 8 value(i64) | 1 scale(i8)
#   | 12 unit | 8 sequence(u64) | 8 observed_at(i64) | 8 published_at(i64) | 1 bump
#
# The offsets are duplicated rather than imported because this runs inside the channel's
# workspace jail, which cannot reach repo root. scripts/check-feed-decoders.py asserts this
# decoder and feed_heartbeat.py's agree on a planted blob, so the duplication cannot drift
# silently. That gate is real; an earlier version of this docstring claimed such a test existed
# when none did, which is the same defect this project has reported upstream ten times.
OFF_AUTHORITY = 8
OFF_DEVICE = 40
OFF_KIND = 72
OFF_VALUE = 73
OFF_SCALE = 81
OFF_UNIT = 82
OFF_SEQUENCE = 94
OFF_OBSERVED_AT = 102
OFF_PUBLISHED_AT = 110
OFF_BUMP = 118
MIN_LEN = 119

# Verified against three independent sources rather than recalled: lib.rs:36 declare_id!,
# broadcast_certified.py and verify_proof_offline.py. An earlier draft carried an INVENTED
# pubkey here, which would have rejected every genuine feed while looking like a working guard.
ORACLE_PROGRAM = "EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn"
RPC = "https://api.devnet.solana.com"
MAX_AGE_SECONDS = 30 * 60

# THE PIN. Owner alone proves "a DeviceFeed", never "OUR rate feed": `register_device` has an
# unconstrained `authority: Signer` and a non-signing `device`, so anyone can stand up a feed
# genuinely owned by the oracle program and publish any number into it.
#
# EXPECTED_DEVICE is deliberately None. There is no rate feed to point at yet, and inventing a
# constant here would produce a guard that looks like a control and gates nothing. Set all four
# together when a BRL/USD feed is registered, and confirm EXPECTED_KIND against that
# registration rather than guessing: kind 0 is temperature on the live feed today.
EXPECTED_DEVICE: str | None = None
EXPECTED_KIND: int | None = None
EXPECTED_UNIT: str | None = None

# A rate that is positive, freshly published and correctly signed can still be INVERTED:
# USD/BRL 0.1969 instead of BRL/USD 5.0797. Measured, R$100 quotes at 19.69 USDC correctly and
# 507.87 USDC inverted, a 26x overcharge in real money. Every other guard passes it, so the
# band is the only thing standing between an inverted publish and a customer.
RATE_MIN = Decimal("0.5")
RATE_MAX = Decimal("50")

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _B58:
            raise ValueError(f"not base58: {c!r}")
        n = n * 58 + _B58.index(c)
    pad = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * pad + body


def refuse(msg: str) -> NoReturn:
    """Never returns. The annotation is load-bearing rather than decorative: a future edit that
    let this fall through would leave every caller running on values it had already rejected."""
    print(f"REFUSED: {msg}", file=sys.stderr)
    sys.exit(1)


def cannot_check(msg: str) -> NoReturn:
    print(f"COULD NOT CHECK: {msg}", file=sys.stderr)
    sys.exit(2)


def decode_feed(data: bytes) -> dict:
    """Pure. Bytes in, fields out, no network and no exit. Everything a guard needs to inspect
    is reachable offline, which is what makes the guards testable at their boundaries."""
    if len(data) < MIN_LEN:
        raise ValueError(f"account is {len(data)} bytes; a DeviceFeed needs {MIN_LEN}")
    scale = struct.unpack_from("<b", data, OFF_SCALE)[0]
    if not -12 <= scale <= 12:
        raise ValueError(f"scale {scale} is outside the sane range")
    return {
        "authority": b58encode(data[OFF_AUTHORITY : OFF_AUTHORITY + 32]),
        "device": b58encode(data[OFF_DEVICE : OFF_DEVICE + 32]),
        "device_raw": data[OFF_DEVICE : OFF_DEVICE + 32],
        "kind": data[OFF_KIND],
        "value": struct.unpack_from("<q", data, OFF_VALUE)[0],
        "scale": scale,
        "unit": data[OFF_UNIT : OFF_UNIT + 12]
        .rstrip(b"\x00")
        .decode("utf-8", "replace"),
        "sequence": struct.unpack_from("<Q", data, OFF_SEQUENCE)[0],
        "observed_at": struct.unpack_from("<q", data, OFF_OBSERVED_AT)[0],
        "published_at": struct.unpack_from("<q", data, OFF_PUBLISHED_AT)[0],
        "bump": data[OFF_BUMP],
        "rate": Decimal(struct.unpack_from("<q", data, OFF_VALUE)[0]).scaleb(scale),
    }


def derive_feed_pda(device_raw: bytes, bump: int, program: str) -> str:
    """Re-derive the PDA from the account's OWN stored device and bump, per the program's
    `seeds = [b"feed", device.key().as_ref()]`. A forged account can carry any device bytes it
    likes, but it cannot make them hash to the address the caller asked for, so this ties the
    contents to the address rather than trusting either alone."""
    h = hashlib.sha256(
        b"feed"
        + device_raw
        + bytes([bump])
        + b58decode(program)
        + b"ProgramDerivedAddress"
    ).digest()
    return b58encode(h)


def fetch_account(pubkey: str) -> dict:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [pubkey, {"encoding": "base64", "commitment": "finalized"}],
        }
    ).encode()
    req = urllib.request.Request(
        RPC,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "zeroclaw-rate/1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            payload = json.loads(r.read(1_000_000).decode())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        cannot_check(f"could not reach the RPC to read the rate feed: {e}")
    except json.JSONDecodeError as e:
        cannot_check(f"the RPC returned something that is not JSON: {e}")

    # isinstance throughout: a hostile RPC controls this whole structure, and an uncaught
    # TypeError here would exit 1, which the contract above reserves for a real finding.
    if not isinstance(payload, dict):
        cannot_check("the RPC response was not a JSON object")
    if payload.get("error") is not None:
        cannot_check(f"the RPC returned an error for {pubkey}: {payload['error']!r}")
    result = payload.get("result")
    if not isinstance(result, dict):
        cannot_check("the RPC response carried no result object")
    value = result.get("value")
    if value is None:
        refuse(f"no account exists at {pubkey}; nothing signed the rate.")
    if not isinstance(value, dict):
        cannot_check("the RPC returned an account that is not an object")
    return value


def read_rate(pubkey: str, now: int | None = None) -> tuple[str, int, int]:
    if EXPECTED_DEVICE is None or EXPECTED_KIND is None or EXPECTED_UNIT is None:
        refuse(
            "no rate feed is pinned. EXPECTED_DEVICE, EXPECTED_KIND and EXPECTED_UNIT are "
            "unset because no BRL/USD feed exists on chain; the only live feed publishes "
            "temperature. Refusing rather than pricing an order off an unknown account."
        )

    acct = fetch_account(pubkey)

    owner = acct.get("owner")
    if owner != ORACLE_PROGRAM:
        refuse(f"account {pubkey} is owned by {owner}, not the oracle program.")

    raw = acct.get("data")
    if not isinstance(raw, list) or len(raw) < 2 or raw[1] != "base64":
        refuse("the account data did not come back base64-encoded as requested.")
    try:
        data = base64.b64decode(raw[0], validate=True)
    except (ValueError, TypeError) as e:
        refuse(f"the account data is not valid base64: {e}")

    try:
        f = decode_feed(data)
    except ValueError as e:
        refuse(str(e))

    # Address-to-contents binding, before any field is believed.
    derived = derive_feed_pda(f["device_raw"], f["bump"], ORACLE_PROGRAM)
    if derived != pubkey:
        refuse(
            f"{pubkey} does not derive from its own stored device and bump (got {derived}); "
            "the account is not the feed PDA it claims to be."
        )
    if f["device"] != EXPECTED_DEVICE:
        refuse(
            f"feed belongs to device {f['device']}, not the pinned {EXPECTED_DEVICE}."
        )
    if f["kind"] != EXPECTED_KIND:
        refuse(f"feed kind is {f['kind']}, not the pinned {EXPECTED_KIND}.")
    if f["unit"] != EXPECTED_UNIT:
        refuse(
            f"feed unit is {f['unit']!r}, not the pinned {EXPECTED_UNIT!r}. "
            "Refusing to price an order off a feed measuring something else."
        )

    rate = f["rate"]
    if rate <= 0:
        refuse(f"the feed carries a non-positive rate ({rate}); a sale cannot use it.")
    if not RATE_MIN <= rate <= RATE_MAX:
        refuse(
            f"rate {rate} is outside the plausible band {RATE_MIN}-{RATE_MAX}. "
            "An inverted publish is positive, fresh and correctly signed, and overcharges."
        )

    # STALENESS IS A SECURITY PROPERTY. A feed that stopped advancing is an attacker-exploitable
    # frozen rate, and freezing a publisher is far cheaper than forging one.
    now = int(time.time()) if now is None else now
    age = now - f["published_at"]
    if age < 0:
        refuse(
            f"the feed's publish time is {abs(age)}s in the future; clock or data is wrong."
        )
    if age > MAX_AGE_SECONDS:
        refuse(
            f"the rate feed is stale: published {age // 60} min ago, limit "
            f"{MAX_AGE_SECONDS // 60} min (seq {f['sequence']}). No link was produced."
        )
    return str(rate), f["sequence"], age


def selftest() -> int:
    """Offline, deterministic, and driven in BOTH directions. A decoder never shown to reject
    has not been shown to work."""
    dev = bytes(range(32))
    blob = bytearray(MIN_LEN)
    blob[OFF_DEVICE : OFF_DEVICE + 32] = dev
    struct.pack_into("<q", blob, OFF_VALUE, 50797)
    struct.pack_into("<b", blob, OFF_SCALE, -4)
    blob[OFF_UNIT : OFF_UNIT + 7] = b"BRL/USD"
    struct.pack_into("<Q", blob, OFF_SEQUENCE, 42)
    blob[OFF_KIND] = 1
    blob[OFF_BUMP] = 254

    cases, failed = [], 0

    def check(label, cond, detail=""):
        nonlocal failed
        print(
            f"  {'ok  ' if cond else 'FAIL'}  {label}" + ("" if cond else f"  {detail}")
        )
        cases.append(label)
        if not cond:
            failed += 1

    f = decode_feed(bytes(blob))
    check("decodes a planted rate blob", str(f["rate"]) == "5.0797", f"got {f['rate']}")
    check("reads the unit", f["unit"] == "BRL/USD", f"got {f['unit']!r}")
    check("reads kind and sequence", f["kind"] == 1 and f["sequence"] == 42)

    # One-byte shift: the control that proves the offsets are load-bearing.
    shifted = bytearray(blob)
    shifted[OFF_VALUE : OFF_VALUE + 8] = struct.pack("<q", 50798)
    check(
        "a one-unit change moves the rate",
        str(decode_feed(bytes(shifted))["rate"]) == "5.0798",
    )

    short = bytes(blob)[: MIN_LEN - 1]
    try:
        decode_feed(short)
        check("a short account is rejected", False, "it was accepted")
    except ValueError:
        check("a short account is rejected", True)

    bad = bytearray(blob)
    struct.pack_into("<b", bad, OFF_SCALE, 100)
    try:
        decode_feed(bytes(bad))
        check("an absurd scale is rejected", False, "it was accepted")
    except ValueError:
        check("an absurd scale is rejected", True)

    # base58 round-trip, since the PDA check rests on it.
    check(
        "base58 round-trips the program id",
        b58encode(b58decode(ORACLE_PROGRAM)) == ORACLE_PROGRAM,
    )

    # The live temperature feed, verbatim, must NOT satisfy a rate pin. This is the case the
    # earlier version got wrong: it printed 33.40 off this exact account shape.
    temp = bytearray(MIN_LEN)
    struct.pack_into("<q", temp, OFF_VALUE, 3050)
    struct.pack_into("<b", temp, OFF_SCALE, -2)
    temp[OFF_UNIT] = ord("C")
    t = decode_feed(bytes(temp))
    check(
        "a temperature feed decodes as 30.50 C",
        str(t["rate"]) == "30.50" and t["unit"] == "C",
    )
    # THIS CASE EXISTS BECAUSE IT CORRECTED ME. I first asserted the band would catch the
    # thermometer. It does not: 30.50 sits comfortably inside 0.5-50, so a plausibility band is
    # no defence against reading the wrong INSTRUMENT, only against an inverted rate from the
    # right one. The UNIT pin is the check that stops this, which is why it is not optional.
    check(
        "the band does NOT catch a temperature; only the unit pin does",
        RATE_MIN <= t["rate"] <= RATE_MAX,
        f"expected 30.50 to sit inside {RATE_MIN}-{RATE_MAX}",
    )
    check("and its unit is not a rate unit", t["unit"] != "BRL/USD")

    if failed:
        print(f"\n{failed}/{len(cases)} selftest case(s) FAILED.", file=sys.stderr)
        return 1
    print(
        f"\nOK  {len(cases)}/{len(cases)}; the decoder accepts a rate blob and rejects the rest."
    )
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--selftest":
        return selftest()
    if len(argv) != 1 or argv[0].startswith("-"):
        print(
            "usage: rate_from_feed.py <feed-pubkey> | --selftest\n"
            "       there is deliberately no --rpc and no --max-age-min; see the docstring.",
            file=sys.stderr,
        )
        return 1
    rate, sequence, age = read_rate(argv[0])
    print(f"{rate} seq={sequence} age={age}s")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
