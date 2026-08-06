#!/usr/bin/env python3
"""What the DePIN node has actually EARNED, derived from two independent sources.

WHY THIS EXISTS RATHER THAN THE SOP'S SUMMARIZER. The node's own earnings report
(`sops/node-earnings-report/SOP.md`) runs `summarize_earnings.py` against
`x402-earnings.jsonl` in the agent's workspace. That ledger is real and it lives on the
node, not in this repo -- it is gitignored by design, because it is runtime state. So a
reproducing operator (and a camera) cannot read it, and the SOP's step 2 shows only a
TEMPLATE of the sentence the agent would send: `(e.g. "Your node sold N readings today
and earned X USDC over x402.")`. Filming that template, with plausible numbers dropped
into it, would be a re-enactment of a report rather than a report.

This derives the same fact from what anyone can check:

  1. THE CHAIN. Every x402 settlement is an SPL TransferChecked to the seller's token
     account carrying the challenge nonce as a Memo. Counting those IS the revenue, and
     a judge can re-run this against a public RPC with no key and no account.
  2. THE LIVE GATE. `/health` reports the node's own ledger -- what it restored at
     startup, what it has settled, and the per-payer daily cap the listing calls
     mandatory.

Then it CROSS-CHECKS them in the direction that matters: the gate must never claim more
revenue than the chain can show. Over-claiming is the dishonest direction; a fresh sale
that has not yet been folded into the startup snapshot is benign and is reported as such.

FAILS CLOSED. No gate, no chain, no settlements, or a gate claiming more than settled --
all exit non-zero and print why. A green line here means both sources were reached and
they agree.

  python demo/x402_earnings.py
  python demo/x402_earnings.py --json

Environment (so the failing direction can be DRIVEN, not just asserted):
  X402_GATE_URL   default https://x402.perfpilot.dev
  X402_RPC_URL    default https://api.devnet.solana.com
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request

GATE = os.environ.get("X402_GATE_URL", "https://x402.perfpilot.dev").rstrip("/")
RPC = os.environ.get("X402_RPC_URL", "https://api.devnet.solana.com")
UA = {"User-Agent": "Mozilla/5.0"}

# 408 and 429 are TRANSPORT, not a claim: the same boundary this repo already settled in
# scripts/verify-proof.py. A rate limit must not read as "the node earned nothing".
TRANSPORT_HTTP_CODES = frozenset({408, 429})

# Enumerated rather than caught broadly, so a genuine programming error surfaces instead
# of being reported to the operator as "the network was unavailable".
TRANSPORT_ERRORS = (
    urllib.error.URLError,
    OSError,
    socket.timeout,
    json.JSONDecodeError,
)


class Unavailable(Exception):
    """A source could not be reached. Distinct from a source that answered 'none'."""


def usdc(atomic: int) -> str:
    """Atomic base units (6 dp) as a human USDC figure."""
    return f"{atomic / 1_000_000:.2f}"


def _get_json(url: str, timeout: int = 25) -> dict:
    req = urllib.request.Request(url, headers=UA)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in TRANSPORT_HTTP_CODES and attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            raise Unavailable(f"{url} -> HTTP {e.code}") from e
        except TRANSPORT_ERRORS as e:
            if attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            raise Unavailable(f"{url} -> {type(e).__name__}: {e}") from e
    raise Unavailable(url)


def _rpc(method: str, params: list) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    req = urllib.request.Request(
        RPC, data=body.encode(), headers={"Content-Type": "application/json", **UA}
    )
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                out = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in TRANSPORT_HTTP_CODES and attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            raise Unavailable(f"rpc {method} -> HTTP {e.code}") from e
        except TRANSPORT_ERRORS as e:
            if attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            raise Unavailable(f"rpc {method} -> {type(e).__name__}: {e}") from e
        if "error" in out:
            raise Unavailable(f"rpc {method}: {out['error']}")
        return out
    raise Unavailable(method)


def challenge() -> dict:
    """The gate's own 402 names the seller, the mint and the price. Read it, never pin it."""
    req = urllib.request.Request(f"{GATE}/price", headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raise Unavailable(f"/price returned {resp.status}, expected 402")
    except urllib.error.HTTPError as e:
        if e.code != 402:
            raise Unavailable(f"/price -> HTTP {e.code}, expected 402") from e
        return json.loads(e.read().decode())
    except TRANSPORT_ERRORS as e:
        raise Unavailable(f"/price -> {type(e).__name__}: {e}") from e


def chain_settlements(seller: str, mint: str) -> list[dict]:
    """Every x402-memo SPL receipt on the seller's token account for this mint."""
    accts = (
        _rpc(
            "getTokenAccountsByOwner",
            [seller, {"mint": mint}, {"encoding": "jsonParsed"}],
        )
        .get("result", {})
        .get("value", [])
    )
    if not accts:
        raise Unavailable(
            f"seller {seller[:8]}.. has no token account for mint {mint[:8]}.."
        )
    ata = accts[0]["pubkey"]
    sigs = _rpc("getSignaturesForAddress", [ata, {"limit": 100}]).get("result", [])

    out = []
    for s in sigs:
        if s.get("err"):
            continue
        # getSignaturesForAddress carries the transaction's memo, so a receipt that
        # positively has a NON-x402 memo can be skipped without a second round trip.
        # Only a POSITIVE non-match skips: a null memo is not evidence of no memo on
        # every node, so those still get fetched. Measured: 6 signatures -> 3 fetches.
        listed = s.get("memo")
        if listed is not None and "x402-" not in listed:
            continue
        tx = _rpc(
            "getTransaction",
            [
                s["signature"],
                {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0},
            ],
        ).get("result")
        if not tx:
            continue  # pruned: absent evidence, never counted as revenue
        logs = tx.get("meta", {}).get("logMessages") or []
        memo = next(
            (
                ln.split('"')[-2]
                for ln in logs
                if "Memo" in ln and "x402-" in ln and '"' in ln
            ),
            None,
        )
        if not memo:
            continue
        atomic = 0
        for ix in tx["transaction"]["message"].get("instructions", []):
            parsed = ix.get("parsed")
            if isinstance(parsed, dict) and parsed.get("type") in (
                "transferChecked",
                "transfer",
            ):
                info = parsed.get("info", {})
                amount = info.get("tokenAmount") or {}
                atomic = int(amount.get("amount") or info.get("amount") or 0)
        out.append(
            {
                "sig": s["signature"],
                "memo": memo,
                "atomic": atomic,
                "blockTime": s.get("blockTime"),
            }
        )
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="machine-readable, for gates")
    args = ap.parse_args()

    try:
        ch = challenge()
        accepts = ch.get("accepts") or []
        if not accepts:
            raise Unavailable("challenge carries no `accepts` entry")
        seller = accepts[0]["payTo"]
        mint = accepts[0]["asset"]
        unit = int(accepts[0]["amount"])

        health = _get_json(f"{GATE}/health")
        ledger = health.get("ledger")
        if not isinstance(ledger, dict):
            raise Unavailable("/health carries no .ledger object")

        sales = chain_settlements(seller, mint)
    except Unavailable as e:
        print(f"EARNINGS UNAVAILABLE: {e}", file=sys.stderr)
        print("Refusing to report revenue from one source alone.", file=sys.stderr)
        return 2

    if not sales:
        print("EARNINGS UNAVAILABLE: zero x402 settlements on chain", file=sys.stderr)
        return 2

    n = len(sales)
    total = sum(s["atomic"] for s in sales)
    restored = int(ledger.get("restored_sales_at_startup", 0))
    cap = int(ledger.get("daily_cap_atomic_units", 0))
    skipped = int(ledger.get("unparseable_lines_skipped", 0))

    # THE CHECK THAT MATTERS, and it is directional. A gate restoring MORE sales than the
    # chain can show is claiming revenue that never settled. The reverse -- a fresh sale
    # not yet in the startup snapshot -- is benign and is reported rather than failed.
    if restored > n:
        print(
            f"EARNINGS INCONSISTENT: gate restored {restored} sales, chain shows {n}",
            file=sys.stderr,
        )
        return 1
    if skipped:
        print(
            f"EARNINGS INCONSISTENT: gate skipped {skipped} unparseable ledger lines",
            file=sys.stderr,
        )
        return 1

    last = max(s["blockTime"] for s in sales if s["blockTime"])
    day = time.strftime("%Y-%m-%d", time.gmtime(last))

    if args.json:
        print(
            json.dumps(
                {
                    "chain_settlements": n,
                    "chain_atomic_total": total,
                    "gate_restored": restored,
                    "daily_cap_atomic": cap,
                    "unit_price_atomic": unit,
                    "seller": seller,
                    "mint": mint,
                    "latest_utc_day": day,
                    "signatures": [s["sig"] for s in sales],
                },
                indent=2,
            )
        )
        return 0

    ahead = n - restored
    agree = "AGREE" if ahead == 0 else f"AGREE (+{ahead} newer than last restart)"
    print(
        f"X402 EARNINGS: {n} paid reads settled on chain, {usdc(total)} USDC, "
        f"at {usdc(unit)}/read, latest {day}"
    )
    print(
        f"  chain {n} reads / {usdc(total)} USDC   gate ledger restored {restored}   "
        f"{agree}   cap {usdc(cap)} USDC per payer per day"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
