#!/usr/bin/env python3
"""Watch the chain for a Solana Pay order to settle, live, in one terminal.

This is the reference-key poll the shop's SOP performs, run where a camera can see it.
It is a READ. It holds no key, signs nothing and can move no funds.

Honest scope, because the distinction matters on camera:
  - What this shows is the CHAIN being polled and the settlement being detected.
  - It is NOT the agent's own announcement. The agent's confirmation SOP is a separate
    thing on the box, and `docs/WRITEUP.md` documents why it does not currently announce.
    Do not narrate this as "the shop noticed".

Two modes:
  --reference <pubkey>   watch one order's Solana Pay reference (what the SOP does)
  (default)              watch the merchant's USDC token account for any incoming payment

Usage while filming:
    python demo/watch_invoice.py
    python demo/watch_invoice.py --reference 9TNKoCvVow1ktRgMMapJ9d9GWhgTYCA9i3r3MZ71FUT2

Exits 0 the moment a payment is detected, so the clip has a clean ending.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

# Two endpoints, tried in order. mainnet-beta 403s any request carrying an Origin header,
# which is every BROWSER fetch and no script -- so it is fine here and is the faster of the
# two. publicnode answers browsers but was measured timing out on getTokenAccountsByOwner,
# so it is the fallback rather than the primary. A take must not die on one endpoint.
RPCS = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
]
MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

GREEN, DIM, BOLD, RESET = "\033[32m", "\033[2m", "\033[1m", "\033[0m"


def rpc(method: str, params: list):
    """One JSON-RPC call, tried against each endpoint in turn.

    Returns None only when EVERY endpoint failed, so a single blip renders as
    'ask again' rather than as a false verdict on camera. It never raises."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    for url in RPCS:
        req = urllib.request.Request(
            url,
            data=body.encode(),
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                payload = json.loads(r.read())
            if payload.get("error"):
                continue
            return payload.get("result")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            continue
    return None


def merchant_usdc_account() -> str | None:
    res = rpc(
        "getTokenAccountsByOwner",
        [MERCHANT, {"mint": USDC}, {"encoding": "jsonParsed"}],
    )
    if not res or not res.get("value"):
        return None
    return res["value"][0]["pubkey"]


def newest_signature(account: str) -> str | None:
    res = rpc("getSignaturesForAddress", [account, {"limit": 1}])
    if not res:
        return None
    return res[0]["signature"]


def describe(sig: str) -> dict:
    tx = rpc(
        "getTransaction",
        [sig, {"maxSupportedTransactionVersion": 0, "encoding": "jsonParsed"}],
    )
    out = {"sig": sig, "amount": None, "signer": None, "err": None, "slot": None}
    if not tx:
        return out
    out["err"] = tx.get("meta", {}).get("err")
    out["slot"] = tx.get("slot")
    keys = tx.get("transaction", {}).get("message", {}).get("accountKeys", [])
    for k in keys:
        if k.get("signer"):
            out["signer"] = k.get("pubkey")
            break
    pre = {b["accountIndex"]: b for b in tx.get("meta", {}).get("preTokenBalances", [])}
    for b in tx.get("meta", {}).get("postTokenBalances", []):
        if b.get("owner") == MERCHANT and b.get("mint") == USDC:
            before = (
                pre.get(b["accountIndex"], {}).get("uiTokenAmount", {}).get("uiAmount")
                or 0
            )
            after = b.get("uiTokenAmount", {}).get("uiAmount") or 0
            if after > before:
                out["amount"] = round(after - before, 6)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reference", help="a Solana Pay reference pubkey for one order")
    ap.add_argument("--interval", type=float, default=3.0)
    # 40 minutes, not 10. The 10-minute default expired mid-shoot while the operator
    # was still paying, which is the one failure a watcher must not have: it is meant
    # to outlast the human, and a person placing an order on a phone takes longer than
    # a script author imagines. Pass --timeout to shorten it for a quick check.
    ap.add_argument("--timeout", type=float, default=2400.0)
    a = ap.parse_args()

    if a.reference:
        watching, label = a.reference, "order reference"
    else:
        acct = merchant_usdc_account()
        if not acct:
            print(
                "could not reach the chain to find the merchant's USDC account",
                file=sys.stderr,
            )
            return 2
        watching, label = acct, "the shop's USDC account"

    print()
    print(f"  {BOLD}watching {label}{RESET}")
    print(f"  {DIM}{watching}{RESET}")
    print(
        f"  {DIM}mainnet · polling getSignaturesForAddress every {a.interval:.0f}s · read only, no key{RESET}"
    )
    print()

    baseline = newest_signature(watching) if not a.reference else None
    started = time.monotonic()
    polls = 0

    while time.monotonic() - started < a.timeout:
        polls += 1
        elapsed = int(time.monotonic() - started)
        sig = newest_signature(watching)

        if sig and sig != baseline:
            d = describe(sig)
            if d["err"] is None:
                amt = f"{d['amount']} USDC" if d["amount"] is not None else "settled"
                print(f"\r  {GREEN}{BOLD}PAID{RESET}  {amt}   slot {d['slot']}")
                print(f"        from      {d['signer']}")
                print(f"        signature {d['sig']}")
                print(f"        {DIM}https://explorer.solana.com/tx/{d['sig']}{RESET}")
                print()
                return 0

        dots = "." * (polls % 4)
        sys.stdout.write(
            f"\r  {DIM}no payment yet   {elapsed:>3}s   poll {polls}{dots}   {RESET}   "
        )
        sys.stdout.flush()
        time.sleep(a.interval)

    print(f"\r  no payment within {int(a.timeout)}s" + " " * 24)
    return 1


if __name__ == "__main__":
    sys.exit(main())
