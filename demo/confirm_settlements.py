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

THE SCAN CACHE, and why it caches only NEGATIVES.

The scan is not two RPC reads. It is two, plus one `getTransaction` for every signature
in the window that the ledger has not recorded. Measured on the box 2026-08-16, on a
window of 21: 6 in the ledger, 11 that are not incoming settlements, 4 that are -- so 15
`getTransaction` calls per run, and 8,126 RPC calls a day at the observed tick rate.

The 11 are the point. A finalized transaction is immutable, so "this signature is not an
incoming settlement to the merchant" is a PERMANENT verdict, and re-deriving it costs a
network round trip every single tick forever. That is true in the healthy steady state,
not only during an outage: those 11 never enter the ledger (only settlements do), so
nothing ever stops re-fetching them. Caching that verdict takes the steady-state scan
from 13 reads to 2.

POSITIVES ARE NEVER CACHED, and that is the whole safety argument. Every field of every
announced receipt still comes from a `getTransaction` issued on the run that announces
it. A cache that stored amounts and payers would move the composition of a money message
off the chain and into a local file, which is the surface this tool exists to remove --
it would differ from the model that fabricated the 2026-08-06 records only in being a
worse-supervised author. So the cache can make the tool do LESS work; it cannot make it
say anything.

The residual risk runs the other way: a corrupted or tampered negative entry suppresses a
real settlement, and a swallowed confirmation is the failure that cannot be recovered.
Three things bound it. An entry is written only for a transaction that was actually
FETCHED and definitively classified, never for one that could not be read. Anything
malformed on load is dropped, so the cache's own failure mode is a full re-fetch, which
is exactly the pre-cache behaviour. And the default path is under ~/.zeroclaw/state/,
OUTSIDE the agent's workspace jail -- unlike the ledger, which sits inside it.

Usage:
    python demo/confirm_settlements.py --dry-run
    python demo/confirm_settlements.py
    python demo/confirm_settlements.py --seed        # adopt current history, announce none
    python demo/confirm_settlements.py --no-cache    # re-derive every verdict from chain

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


def default_cache() -> Path:
    """Where the negative-classification cache lives.

    ~/.zeroclaw/state/ rather than beside the ledger, deliberately. The ledger sits at
    ~/.zeroclaw/agents/demo/workspace/, INSIDE the agent's workspace jail, so the agent
    can write it. The state dir is outside, which is where a file that can suppress an
    announcement belongs.
    """
    return Path.home() / ".zeroclaw" / "state" / "settlement-scan-cache.json"


def is_signature(value: object) -> bool:
    """True only for a string shaped like a real base58 transaction signature."""
    return isinstance(value, str) and 86 <= len(value) <= 88 and not (set(value) - _B58)


def load_cache(path: Path) -> set[str]:
    """Signatures already proven NOT to be incoming settlements.

    Every failure mode returns the empty set, which degrades to the pre-cache behaviour
    of fetching everything. That direction is deliberate: an unreadable cache must cost
    RPC calls, never a missed receipt. Entries are re-validated with is_signature() on
    the way in, so junk in the file cannot shadow a real signature.
    """
    if path is None or not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return set()
    if not isinstance(payload, dict):
        return set()
    entries = payload.get("not_settlements")
    if not isinstance(entries, list):
        return set()
    return {entry for entry in entries if is_signature(entry)}


def save_cache(path: Path, signatures: set[str]) -> None:
    """Persist the negative verdicts. Best effort: a cache that cannot be written is a
    slower next run, never a wrong one, so a failure here is swallowed rather than
    escalated into a refusal to announce."""
    payload = {
        "version": 1,
        "note": (
            "Signatures proven not to be incoming settlements to the merchant. Derived "
            "data: delete this file at any time and the next run rebuilds it from chain."
        ),
        "not_settlements": sorted(signatures),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    except OSError:
        pass


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
    rpc,
    known: set[str],
    limit: int,
    merchant: str = MERCHANT,
    mint: str = USDC,
    cached_negative: frozenset = frozenset(),
    only: frozenset | None = None,
):
    """Find chain-confirmed settlements the ledger has not recorded.

    Returns (settlements_oldest_first, stats, negatives). settlements is None when the
    chain could not be reached at all, which the caller must treat as 'announce nothing'.

    `cached_negative` skips the fetch for signatures already proven not to be incoming
    settlements. `negatives` comes back pruned to the current window, so the cache file
    tracks the scan rather than growing without bound.

    `only` restricts the whole pass to a given set of signatures. It exists for the
    commit step of deploy/announce_settlements.sh: that step used to re-derive from
    chain and append EVERYTHING it found, so a payment landing between the announce and
    the commit was written to the ledger without ever being sent, and the next run then
    read it as already recorded. That is a swallowed confirmation, which is the one
    outcome the whole send-first/commit-after ordering exists to prevent. Restricting
    the commit to the signatures actually announced closes it. `only` can only ever
    narrow what is appended, so its own failure mode is a duplicate announcement.
    """
    stats = {
        "scanned": 0,
        "already_known": 0,
        "unverifiable": 0,
        "not_a_settlement": 0,
        "cache_hits": 0,
        "fetched": 0,
        "outside_only": 0,
    }

    account = merchant_token_account(rpc, merchant, mint)
    if account is None:
        return None, stats, set()

    signatures = recent_signatures(rpc, account, limit)
    if signatures is None:
        return None, stats, set()

    stats["scanned"] = len(signatures)
    found = []
    negatives: set[str] = set()

    for signature in signatures:
        if signature in known:
            stats["already_known"] += 1
            continue

        if only is not None and signature not in only:
            stats["outside_only"] += 1
            continue

        # A finalized transaction cannot change its mind about being a settlement, so a
        # verdict already reached is re-used rather than re-fetched. Positives are never
        # cached, so this branch can only ever skip work, never supply an announced field.
        if signature in cached_negative:
            stats["cache_hits"] += 1
            negatives.add(signature)
            continue

        tx = rpc(
            "getTransaction",
            [
                signature,
                {"maxSupportedTransactionVersion": 0, "encoding": "jsonParsed"},
            ],
        )
        stats["fetched"] += 1
        if tx is None:
            # Could not verify it. Leave it unannounced and unrecorded; the next run
            # picks it up because it never entered the ledger. Deliberately NOT cached:
            # caching an unread transaction would make a transport blip permanent.
            stats["unverifiable"] += 1
            continue

        record = settlement_from_tx(tx, signature, merchant, mint)
        if record is None:
            stats["not_a_settlement"] += 1
            negatives.add(signature)
            continue
        found.append(record)

    # getSignaturesForAddress returns newest first; announce in the order things happened.
    found.reverse()
    return found, stats, negatives


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
        "--dry-run",
        action="store_true",
        help="print what would be sent and append no LEDGER records (the scan cache, "
        "which holds only derived negative verdicts, is still updated)",
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        help="record current history WITHOUT announcing it, so a first run does not "
        "announce every historical payment at once",
    )
    parser.add_argument(
        "--cache",
        type=Path,
        default=None,
        help="path to the negative-classification cache (default ~/.zeroclaw/state/)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="ignore and do not write the cache; re-derive every verdict from chain",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=None,
        metavar="SIGNATURE",
        help="restrict the pass to these signatures (repeatable). Used by the commit "
        "step so it appends only what was actually announced.",
    )
    args = parser.parse_args(argv)

    if args.limit < 1:
        print("--limit must be at least 1", file=sys.stderr)
        return 1
    if args.dry_run and args.seed:
        print("--dry-run and --seed together would do nothing", file=sys.stderr)
        return 1

    only = None
    if args.only is not None:
        bad = [value for value in args.only if not is_signature(value)]
        if bad:
            print(
                f"--only takes base58 transaction signatures; rejected {len(bad)}: "
                f"{bad[0][:24]}...",
                file=sys.stderr,
            )
            return 1
        only = frozenset(args.only)

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

    # A commit pass narrowed by --only examines only part of the window, so it must not
    # rewrite a cache pruned to what it happened to look at. Scanning runs own the cache.
    cache_path = (
        None
        if (args.no_cache or only is not None)
        else (args.cache if args.cache is not None else default_cache())
    )
    cached_negative = frozenset(load_cache(cache_path)) if cache_path else frozenset()

    rpc = make_rpc()
    settlements, stats, negatives = collect_settlements(
        rpc, known, args.limit, cached_negative=cached_negative, only=only
    )

    if settlements is None:
        print(
            "chain unreachable: announced nothing and wrote nothing. "
            "Absence of data is not absence of a settlement.",
            file=sys.stderr,
        )
        return 2

    # The fetch count is reported next to the scan count on purpose. A cache that has
    # silently stopped working looks exactly like a healthy one from the outside -- same
    # verdict, same output -- and the only thing that distinguishes them is how many
    # transactions had to be read to reach it.
    print(
        f"scanned {stats['scanned']} signature(s): "
        f"{stats['already_known']} already recorded, "
        f"{stats['cache_hits']} skipped by cache, "
        f"{stats['not_a_settlement']} not an incoming settlement, "
        f"{stats['unverifiable']} could not be fetched (left for the next run), "
        f"{len(settlements)} new "
        f"[{stats['fetched']} transaction(s) fetched"
        + (f", {stats['outside_only']} outside --only" if only is not None else "")
        + "]",
        file=sys.stderr,
    )

    if cache_path is not None:
        save_cache(cache_path, negatives)

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
