#!/usr/bin/env python3
"""Show WHERE the audited allowance program draws its line, today, on a live cluster.

Why this exists. The captured over-cap transaction failed with custom program error 300
(0x12c). Anyone can re-send that captured message with a different amount to check the
claim, and when they do they get 300 back for every amount they are likely to try,
including the amount that settled. Read alone that looks like a program refusing
everything, or like a stale capture. It is neither.

A fixed delegation carries a REMAINING balance, and the settled transfer already debited
it. So the refusal boundary today sits at the remaining allowance rather than at the
original cap. This script locates that boundary empirically instead of asserting it: it
reads the remaining allowance from the delegation account, then replays the captured
message at amounts either side of it.

Nothing is signed and nothing is broadcast. `sigVerify` is off, so the agent session key
(generated per run and discarded, exactly so it cannot be reused) is not needed, and
simulateTransaction never commits.

The run is its own control, in both directions. It requires at least one amount to be
REFUSED and at least one to be ACCEPTED, and exits non-zero otherwise. A program that had
stopped working would refuse everything; a check that had stopped checking would accept
everything. Either one fails here rather than printing a clean result over nothing.

A bundle may record more than one refused capture, from more than one delegation. Replaying
the wrong one measures a real boundary belonging to a different cap, so the choice is never
guessed: pass --signature to name which, and the error lists the candidates when it matters.

Usage:
    python3 scripts/replay_allowance_probe.py
    python3 scripts/replay_allowance_probe.py --bundle docs/proof-bundle/devnet-transactions.json --signature 3TLSrfWVYdC3hSiAWnyyd7T694bLJQDtdJYQ64EWUsBNDehGc6Kq1veR7xa8Y1BiMdpvfFm3N1dKjDrXF3BEq2ps
"""

import argparse
import base64
import json
import struct
import sys
import urllib.request

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

DEFAULT_RPC = {
    "mainnet": "https://api.mainnet-beta.solana.com",
    "devnet": "https://api.devnet.solana.com",
}

# `transferFixed` instruction data is: disc(1) || amount(u64 le) || delegator(32) || mint(32).
# The delegator is whose allowance is drawn. In this deployment that is the same key as the
# operator who pays the fee and created the delegation, which is what makes the two easy to
# conflate; upstream names the field delegator, and the roles stay distinct even where one
# key fills both.
TRANSFER_FIXED_DISC = 4
TRANSFER_FIXED_DATA_LEN = 73
# The delegation account's last sixteen bytes are two little-endian u64s: the remaining
# allowance, then the expiry. Read as an offset from the END so a future field added
# earlier in the struct does not silently shift the read.
REMAINING_OFF_FROM_END = 16
EXPIRY_OFF_FROM_END = 8


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    for byte in raw:
        if byte:
            break
        out = "1" + out
    return out or "1"


def compact_u16(buf: bytes, i: int):
    val, shift = 0, 0
    while True:
        byte = buf[i]
        i += 1
        val |= (byte & 0x7F) << shift
        if byte < 0x80:
            return val, i
        shift += 7


def decode_message(raw: bytes):
    """Return (account_keys, instructions) for a legacy transaction."""
    i = 0
    nsig, i = compact_u16(raw, i)
    i += nsig * 64
    i += 3  # header
    nkeys, i = compact_u16(raw, i)
    keys = [b58encode(raw[i + k * 32 : i + (k + 1) * 32]) for k in range(nkeys)]
    i += nkeys * 32 + 32  # keys then blockhash
    nix, i = compact_u16(raw, i)
    ixs = []
    for _ in range(nix):
        i += 1  # program id index
        naccts, i = compact_u16(raw, i)
        accts = list(raw[i : i + naccts])
        i += naccts
        dlen, i = compact_u16(raw, i)
        i += dlen
        ixs.append(accts)
    return keys, ixs


def rpc(url: str, method: str, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    payload = json.loads(urllib.request.urlopen(req, timeout=60).read())
    if "error" in payload:
        raise SystemExit(f"RPC {method} failed: {payload['error']}")
    return payload["result"]


def custom_code(err):
    """Extract the custom program error number, or None if this is not one."""
    if not err:
        return None
    inner = err.get("InstructionError") if isinstance(err, dict) else None
    if not inner or not isinstance(inner[1], dict):
        return None
    return inner[1].get("Custom")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", default="docs/proof-bundle/mainnet-transactions.json")
    ap.add_argument("--rpc", default=None)
    ap.add_argument(
        "--signature",
        default=None,
        help="which refused capture to replay, when a bundle records more than one "
        "(a unique prefix is enough)",
    )
    args = ap.parse_args()

    bundle = json.load(open(args.bundle, encoding="utf-8"))
    cluster = bundle.get("cluster", "mainnet")
    url = args.rpc or DEFAULT_RPC.get(cluster, DEFAULT_RPC["mainnet"])

    # The refused transfer is the one the bundle recorded as failing with 300.
    #
    # A BUNDLE MAY RECORD SEVERAL, and until 2026-08-19 that was fatal rather than selectable.
    # Refusing to guess is right and stays: two captures come from two different delegations
    # with different caps, so replaying the wrong one measures a boundary the surrounding prose
    # is not describing. What was missing is a way to SAY which, and a message naming the
    # candidates so a reader who hits this has somewhere to go. Without that, adding a second
    # capture to a bundle silently breaks every documented command pointing at it, and nothing
    # about the failure suggests the one-word fix.
    refused = [
        (sig, t)
        for sig, t in bundle["transactions"].items()
        if custom_code(t.get("err")) == 300
    ]
    total = len(bundle.get("transactions", {}))
    if args.signature:
        picked = [(s, t) for s, t in refused if s.startswith(args.signature)]
        if len(picked) != 1:
            raise SystemExit(
                f"--signature {args.signature!r} selects {len(picked)} of the "
                f"{len(refused)} transaction(s) refused with custom error 300 in "
                f"{args.bundle}; it must select exactly one."
            )
        refused = picked
    if len(refused) != 1:
        listing = "".join(f"\n  {s}" for s, _ in refused) or "\n  (none)"
        raise SystemExit(
            f"expected exactly one transaction refused with custom error 300 in {args.bundle}, "
            f"found {len(refused)} of {total} captured transaction(s); refusing to guess which "
            f"message to replay. Re-run with --signature naming one of:{listing}"
        )
    sig, tx = refused[0]
    raw = bytearray(base64.b64decode(tx["raw_base64"]))

    keys, ixs = decode_message(bytes(raw))

    # Locate the amount field by its instruction-data signature rather than by a hardcoded
    # offset: a byte equal to the data length immediately followed by the discriminator.
    # Refuse to patch at all unless that lands on exactly one candidate.
    search_from = 0
    hits = []
    while True:
        idx = raw.find(bytes([TRANSFER_FIXED_DISC]), search_from)
        if idx == -1:
            break
        search_from = idx + 1
        if (
            idx + TRANSFER_FIXED_DATA_LEN <= len(raw)
            and raw[idx - 1] == TRANSFER_FIXED_DATA_LEN
        ):
            hits.append(idx)
    if len(hits) != 1:
        raise SystemExit(
            f"could not uniquely locate the transferFixed amount field ({len(hits)} candidates); "
            "refusing to patch bytes blind."
        )
    amt_off = hits[0] + 1
    captured = struct.unpack_from("<Q", raw, amt_off)[0]

    # The delegation PDA is the first account of the transferFixed instruction.
    delegation = keys[ixs[0][0]]

    info = rpc(url, "getAccountInfo", [delegation, {"encoding": "base64"}])["value"]
    if info is None:
        raise SystemExit(
            f"delegation account {delegation} does not exist on {cluster}. If this ever prints, "
            "the explanation in docs/MAINNET-PROOF.md is wrong and must be rewritten."
        )
    data = base64.b64decode(info["data"][0])
    remaining = struct.unpack_from("<Q", data, len(data) - REMAINING_OFF_FROM_END)[0]
    expiry = struct.unpack_from("<Q", data, len(data) - EXPIRY_OFF_FROM_END)[0]

    print(f"cluster            : {cluster}  ({url})")
    print(f"refused capture    : {sig}")
    print(f"captured amount    : {captured}")
    print(f"delegation account : {delegation}  (EXISTS, owner {info['owner']})")
    print(f"remaining allowance: {remaining} base units")
    print(f"expiry             : {expiry}")
    print()

    probes = [(captured, "the captured amount")]
    if remaining:
        probes += [
            (remaining + 1, "remaining + 1"),
            (remaining, "exactly the remaining allowance"),
            (1, "one base unit"),
        ]
    else:
        print(
            "The allowance is fully consumed on this cluster, so every non-zero amount is"
        )
        print(
            "expected to be refused and there is no accepting case to show. Run the mainnet"
        )
        print("bundle to see both sides of the boundary.")
        print()
        probes += [(1, "one base unit")]

    refusals = accepts = 0
    print(f"{'amount':>12}  {'simulated result':<18} note")
    print("-" * 72)
    for amount, note in probes:
        patched = bytearray(raw)
        patched[amt_off : amt_off + 8] = struct.pack("<Q", amount)
        value = rpc(
            url,
            "simulateTransaction",
            [
                base64.b64encode(bytes(patched)).decode(),
                {
                    "sigVerify": False,
                    "replaceRecentBlockhash": True,
                    "commitment": "confirmed",
                    "encoding": "base64",
                },
            ],
        )["value"]
        code = custom_code(value.get("err"))
        if value.get("err") is None:
            verdict, accepts = "ACCEPTED", accepts + 1
        elif code == 300:
            verdict, refusals = "refused 300", refusals + 1
        else:
            verdict = f"refused {json.dumps(value['err'])}"
        print(f"{amount:>12}  {verdict:<18} {note}")

    print()
    # Two-directional control. Reporting a boundary requires having observed both sides of
    # it, except where the allowance is exhausted and there is no accepting side to observe.
    if refusals == 0:
        print("FAIL: nothing was refused, so this run demonstrates no boundary at all.")
        return 1
    if remaining and accepts == 0:
        print(
            "FAIL: nothing was accepted. The refusal is then not evidence about the cap,"
        )
        print(
            "      because a program refusing every amount would print the same thing."
        )
        return 1
    if remaining:
        print(
            f"PASS  the refusal boundary sits exactly at the remaining allowance ({remaining})."
        )
        print(
            "      Above it the program returns 300 (AmountExceedsLimit); at or below it the"
        )
        print(
            "      same message simulates cleanly. That is the cap arithmetic still running."
        )
    else:
        print(
            "PASS  allowance exhausted, every non-zero amount refused with 300 as expected."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
