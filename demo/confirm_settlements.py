#!/usr/bin/env python3
"""Announce merchant settlements that the chain confirms and the ledger has not yet recorded.

WHY THIS EXISTS, and why its shape is deliberately smaller than the SOP it replaces.

The `payment-confirmation` SOP's detection half works: the cron fires, `payment_watch`
runs, the chain gets polled. Its REPORTING half is prose-authored, so the model composes
the ledger record and the outgoing message, and measured on 2026-08-06 it invented them.
Four records, two with a literal ellipsis where a signature belongs, one settlement
signature shared across two different orders and amounts, and two timestamps in the
future. Checked against mainnet, not one value in that ledger matched any signature the
merchant's token account has ever carried. Prose is not a constraint on a model.

THE INVERSION. The SOP asks "which of my open orders settled", which needs a list of
open orders, which comes from the agent's memory store, which is the poisoned surface.
This asks the question that needs no such list:

    which settlements to the merchant have I not yet announced?

The merchant's own token account answers it. There is no memory surface to poison, no
order set to recall, and no field for a model to compose: every value written here is
read out of the RPC response for the transaction it describes. The signature is the
signature the chain returned. The amount is the balance delta the chain recorded. The
timestamp is the block time, which is why a record here cannot be stamped in the future.

WHAT IT CANNOT DO. It holds no key, signs nothing and moves no funds. It is two RPC
reads and an append. It also does not know order numbers, because knowing them would
mean trusting the surface this exists to route around; it names the amount and the
signature, and a human maps those to an order.

Usage:
    python demo/confirm_settlements.py --dry-run
    python demo/confirm_settlements.py
    python demo/confirm_settlements.py --seed        # adopt current history, announce none

Exit codes:
    0  ran and verified (any SEND lines printed are chain-confirmed)
    1  bad usage
    2  chain unreachable; NOTHING was announced and nothing was written
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

# mainnet-beta 403s any request carrying an Origin header, which is every browser fetch
# and no script, so it is fine from Python and is the faster of the two. publicnode
# answers browsers but was measured timing out on getTokenAccountsByOwner, so it is the
# fallback rather than the primary.
RPCS = (
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
)

MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

SEND_PREFIX = "SEND: "

# Base58 as Solana uses it: no 0, O, I or l. A real signature is 64 bytes encoded, which
# lands at 86-88 characters. This is what stops a fabricated `5QzQ1...` in the existing
# ledger from being treated as a signature and silently deduping a real settlement away.
_B58 = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


def default_ledger() -> Path:
    """The SOP's workspace ledger. Derived from the home dir, never hardcoded."""
    return (
        Path.home()
        / ".zeroclaw"
        / "agents"
        / "demo"
        / "workspace"
        / "confirmed-payments.jsonl"
    )


def is_signature(value: object) -> bool:
    """True only for a string shaped like a real base58 transaction signature."""
    return isinstance(value, str) and 86 <= len(value) <= 88 and not (set(value) - _B58)


def make_rpc(urls=RPCS, timeout: float = 20.0):
    """Build a JSON-RPC caller that tries each endpoint and never raises.

    Returns None only when EVERY endpoint failed, so a single blip is 'ask again'
    rather than a false verdict. A None here is the caller's signal to refuse to
    announce, never to treat the absence of data as the absence of a settlement.
    """

    def rpc(method: str, params: list):
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        )
        for url in urls:
            req = urllib.request.Request(
                url,
                data=body.encode(),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    payload = json.loads(resp.read())
            except (
                urllib.error.URLError,
                urllib.error.HTTPError,
                TimeoutError,
                OSError,
                ValueError,
            ):
                continue
            if payload.get("error"):
                continue
            return payload.get("result")
        return None

    return rpc


def load_ledger(path: Path) -> tuple[set[str], dict]:
    """Read the append-only ledger line by line, tolerating anything already in it.

    The existing file carries four model-fabricated records. They are EVIDENCE for the
    write-up and are never rewritten or deleted here: they are parsed past, counted, and
    left exactly where they are.
    """
    known: set[str] = set()
    stats = {"lines": 0, "usable": 0, "unparseable": 0, "no_signature": 0}
    if not path.exists():
        return known, stats

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            stats["lines"] += 1
            try:
                record = json.loads(line)
            except ValueError:
                stats["unparseable"] += 1
                continue
            sig = record.get("signature") if isinstance(record, dict) else None
            if is_signature(sig):
                known.add(sig)
                stats["usable"] += 1
            else:
                stats["no_signature"] += 1
    return known, stats


def merchant_token_account(
    rpc, merchant: str = MERCHANT, mint: str = USDC
) -> str | None:
    result = rpc(
        "getTokenAccountsByOwner",
        [merchant, {"mint": mint}, {"encoding": "jsonParsed"}],
    )
    if not result or not result.get("value"):
        return None
    return result["value"][0]["pubkey"]


def recent_signatures(rpc, account: str, limit: int) -> list[str] | None:
    result = rpc("getSignaturesForAddress", [account, {"limit": limit}])
    if result is None:
        return None
    return [entry["signature"] for entry in result if entry.get("signature")]


def settlement_from_tx(
    tx: dict, signature: str, merchant: str = MERCHANT, mint: str = USDC
) -> dict | None:
    """Turn one getTransaction response into a settlement record, or None.

    Pure: no network, no clock, no defaults. A value that is not in the response is not
    in the record. Returns None unless the transaction SUCCEEDED and the merchant's
    balance in the given mint went UP, which is what makes this a payment received
    rather than a payment sent.
    """
    if not isinstance(tx, dict):
        return None

    meta = tx.get("meta") or {}

    # A failed transaction moved nothing. Announcing one is the exact false confirmation
    # this tool exists to make impossible.
    if meta.get("err") is not None:
        return None

    pre_by_index = {
        bal.get("accountIndex"): bal for bal in (meta.get("preTokenBalances") or [])
    }

    for post in meta.get("postTokenBalances") or []:
        if post.get("owner") != merchant or post.get("mint") != mint:
            continue

        post_amount = post.get("uiTokenAmount") or {}
        decimals = post_amount.get("decimals")
        try:
            post_raw = int(post_amount.get("amount"))
        except (TypeError, ValueError):
            continue
        if not isinstance(decimals, int):
            continue

        pre_amount = (pre_by_index.get(post.get("accountIndex")) or {}).get(
            "uiTokenAmount"
        ) or {}
        try:
            pre_raw = int(pre_amount.get("amount", "0"))
        except (TypeError, ValueError):
            pre_raw = 0

        delta_raw = post_raw - pre_raw
        # Not an increase means this is the merchant sending, not receiving.
        if delta_raw <= 0:
            continue

        block_time = tx.get("blockTime")
        settled_at = None
        if isinstance(block_time, int):
            settled_at = datetime.fromtimestamp(block_time, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        payer = None
        for key in (tx.get("transaction") or {}).get("message", {}).get(
            "accountKeys"
        ) or []:
            if isinstance(key, dict) and key.get("signer"):
                payer = key.get("pubkey")
                break

        # normalize() drops the mint's trailing zeros so a human reads 0.39 rather than
        # 0.390000; format(..., "f") then keeps a large value out of exponent notation
        # (1000000000 raw renders 1000, never 1E+3). amount_raw below is the exact integer
        # the chain reported, so nothing is lost to the display form.
        amount = Decimal(delta_raw).scaleb(-decimals).normalize()

        return {
            "signature": signature,
            "slot": tx.get("slot"),
            "block_time": block_time,
            "settled_at": settled_at,
            "amount": format(amount, "f"),
            "amount_raw": str(delta_raw),
            "decimals": decimals,
            "mint": mint,
            "merchant": merchant,
            "token_account": post.get("accountIndex"),
            "payer": payer,
            "tool": "confirm_settlements.py",
        }

    return None


def collect_settlements(
    rpc, known: set[str], limit: int, merchant: str = MERCHANT, mint: str = USDC
):
    """Find chain-confirmed settlements the ledger has not recorded.

    Returns (settlements_oldest_first, stats). settlements is None when the chain could
    not be reached at all, which the caller must treat as 'announce nothing'.
    """
    stats = {"scanned": 0, "already_known": 0, "unverifiable": 0, "not_a_settlement": 0}

    account = merchant_token_account(rpc, merchant, mint)
    if account is None:
        return None, stats

    signatures = recent_signatures(rpc, account, limit)
    if signatures is None:
        return None, stats

    stats["scanned"] = len(signatures)
    found = []

    for signature in signatures:
        if signature in known:
            stats["already_known"] += 1
            continue

        tx = rpc(
            "getTransaction",
            [
                signature,
                {"maxSupportedTransactionVersion": 0, "encoding": "jsonParsed"},
            ],
        )
        if tx is None:
            # Could not verify it. Leave it unannounced and unrecorded; the next run
            # picks it up because it never entered the ledger.
            stats["unverifiable"] += 1
            continue

        record = settlement_from_tx(tx, signature, merchant, mint)
        if record is None:
            stats["not_a_settlement"] += 1
            continue
        found.append(record)

    # getSignaturesForAddress returns newest first; announce in the order things happened.
    found.reverse()
    return found, stats


def send_line(record: dict) -> str:
    return (
        f"{SEND_PREFIX}payment received: {record['amount']} USDC"
        f" from {record['payer']} at {record['settled_at']}"
        f" (signature {record['signature']})"
    )


def append_records(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Announce chain-confirmed settlements the ledger has not recorded."
    )
    parser.add_argument(
        "--ledger", type=Path, default=None, help="ledger path (append-only jsonl)"
    )
    parser.add_argument(
        "--limit", type=int, default=25, help="signatures to scan (default 25)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print what would be sent, write nothing"
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        help="record current history WITHOUT announcing it, so a first run does not "
        "announce every historical payment at once",
    )
    args = parser.parse_args(argv)

    if args.limit < 1:
        print("--limit must be at least 1", file=sys.stderr)
        return 1
    if args.dry_run and args.seed:
        print("--dry-run and --seed together would do nothing", file=sys.stderr)
        return 1

    ledger = args.ledger if args.ledger is not None else default_ledger()
    known, ledger_stats = load_ledger(ledger)

    skipped = ledger_stats["unparseable"] + ledger_stats["no_signature"]
    print(
        f"ledger {ledger}: {ledger_stats['lines']} line(s), "
        f"{ledger_stats['usable']} with a real signature, "
        f"{skipped} skipped "
        f"({ledger_stats['unparseable']} unparseable, "
        f"{ledger_stats['no_signature']} without a usable signature)",
        file=sys.stderr,
    )

    rpc = make_rpc()
    settlements, stats = collect_settlements(rpc, known, args.limit)

    if settlements is None:
        print(
            "chain unreachable: announced nothing and wrote nothing. "
            "Absence of data is not absence of a settlement.",
            file=sys.stderr,
        )
        return 2

    print(
        f"scanned {stats['scanned']} signature(s): "
        f"{stats['already_known']} already recorded, "
        f"{stats['not_a_settlement']} not an incoming settlement, "
        f"{stats['unverifiable']} could not be fetched (left for the next run), "
        f"{len(settlements)} new",
        file=sys.stderr,
    )

    if args.seed:
        append_records(ledger, settlements)
        print(f"seeded {len(settlements)} record(s); announced none", file=sys.stderr)
        return 0

    for record in settlements:
        print(send_line(record))

    if args.dry_run:
        print(
            f"dry run: wrote nothing ({len(settlements)} record(s) withheld)",
            file=sys.stderr,
        )
        return 0

    if settlements:
        append_records(ledger, settlements)

    return 0


if __name__ == "__main__":
    sys.exit(main())
