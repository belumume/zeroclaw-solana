#!/usr/bin/env python3
"""Capture raw devnet transactions into the offline proof bundle.

Public devnet RPC retention is MEASURED at roughly 7 to 9 days, not the "roughly four" this
line asserted until 2026-08-01. Two independent readings on that date: the DePIN feed account's
signature history reached back 7.4 days (521 signatures, oldest 2026-07-25T04:12 UTC, second
page empty), and three 2026-07-23 transactions still resolved at 8.6 to 8.9 days old with a
getHealth control passing. The four-day figure was never measured and it made the window look
tighter than it is, which is the safer direction to be wrong in but still wrong. The conclusion
below is unchanged and if anything better supported. The bounty deadline and the judging date are two
weeks apart, so every explorer link in this repo is dead by the time anyone clicks it. This
script moves the evidence into the repo, where nobody else's retention policy governs it.

For each signature it fetches the raw transaction, records the bytes plus slot, block time and
digest, and writes them into docs/proof-bundle/devnet-transactions.json. That file is what
scripts/verify_proof_offline.py verifies with no network at all.

    python scripts/capture-proof-bundle.py <signature> [<signature> ...]
    python scripts/capture-proof-bundle.py --refresh        # retry everything not yet captured

THE INVARIANT THAT MATTERS: an existing CAPTURED entry is never overwritten. Re-running this
after a transaction ages out must not replace real bytes with ALREADY_PRUNED, because that would
destroy the evidence this script exists to preserve. Pass --force to overwrite deliberately.

Exit 0 if every requested signature ends up CAPTURED, 1 otherwise.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BUNDLE = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "proof-bundle"
    / "devnet-transactions.json"
)
DEFAULT_RPC = "https://api.devnet.solana.com"


def rpc(url: str, method: str, params: list) -> dict:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def fetch(url: str, sig: str) -> dict:
    """Return a bundle entry for one signature. Never raises on a missing transaction."""
    try:
        out = rpc(
            url,
            "getTransaction",
            [
                sig,
                {"encoding": "base64", "maxSupportedTransactionVersion": 0},
            ],
        )
    except Exception as exc:
        return {"status": "ERROR", "detail": str(exc)[:200]}

    if out.get("error"):
        return {"status": "ERROR", "detail": json.dumps(out["error"])[:200]}

    result = out.get("result")
    if not result:
        # Distinguish "aged out" from "never existed", because they mean different things.
        try:
            st = rpc(
                url, "getSignatureStatuses", [[sig], {"searchTransactionHistory": True}]
            )
            known = st.get("result", {}).get("value", [None])[0] is not None
        except Exception:
            known = False
        return {
            "status": "ALREADY_PRUNED" if not known else "ERROR",
            "detail": "endpoint no longer serves this transaction",
        }

    raw_b64 = result["transaction"][0]
    raw = base64.b64decode(raw_b64)
    return {
        "status": "CAPTURED",
        "slot": result.get("slot"),
        "blockTime": result.get("blockTime"),
        "err": result.get("meta", {}).get("err"),
        "raw_base64": raw_b64,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_len": len(raw),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("signatures", nargs="*")
    ap.add_argument("--rpc", default=DEFAULT_RPC)
    ap.add_argument(
        "--refresh",
        action="store_true",
        help="retry every signature in the bundle that is not CAPTURED",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="overwrite entries that are already CAPTURED (destroys held bytes)",
    )
    ap.add_argument(
        "--cluster",
        default="devnet",
        help="cluster label recorded in the bundle (default devnet)",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="bundle file to write (default docs/proof-bundle/<cluster>-transactions.json)",
    )
    args = ap.parse_args()

    # Evidence from one cluster must never land in another cluster's bundle, so the path is
    # derived from the label rather than hardcoded. Default resolves to the original file.
    bundle_path = (
        Path(args.out)
        if args.out
        else BUNDLE.parent / f"{args.cluster}-transactions.json"
    )
    bundle: dict
    if bundle_path.exists():
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        if bundle.get("cluster") and bundle["cluster"] != args.cluster:
            print(
                f"FATAL: {bundle_path.name} records cluster {bundle['cluster']!r} but "
                f"--cluster is {args.cluster!r}. Refusing to mix clusters in one bundle."
            )
            return 1
    else:
        bundle = {
            "note": f"Raw {args.cluster} transactions, verifiable with no network."
        }
        print(f"creating new bundle {bundle_path.name}")
    txs = bundle.setdefault("transactions", {})

    targets = list(args.signatures)
    if args.refresh:
        targets += [s for s, e in txs.items() if e.get("status") != "CAPTURED"]
    if not targets:
        print("nothing to do: pass signatures or --refresh")
        return 0

    captured = skipped = failed = 0
    for sig in dict.fromkeys(targets):
        existing = txs.get(sig, {})
        if existing.get("status") == "CAPTURED" and not args.force:
            print(f"SKIP   {sig[:20]}..  already captured, refusing to overwrite")
            skipped += 1
            continue

        entry = fetch(args.rpc, sig)
        if entry["status"] == "CAPTURED":
            txs[sig] = entry
            print(
                f"OK     {sig[:20]}..  slot={entry['slot']} {entry['raw_len']}B "
                f"err={entry['err']}"
            )
            captured += 1
        else:
            # Do NOT clobber a good entry with a bad one.
            if existing.get("status") == "CAPTURED":
                print(
                    f"KEEP   {sig[:20]}..  fetch said {entry['status']}, held bytes preserved"
                )
                skipped += 1
            else:
                txs[sig] = entry
                print(
                    f"MISS   {sig[:20]}..  {entry['status']}: {entry.get('detail', '')}"
                )
                failed += 1
        time.sleep(0.3)

    bundle["captured_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle["source_rpc"] = args.rpc
    bundle["cluster"] = args.cluster
    bundle_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")

    total = len(txs)
    n_cap = sum(1 for e in txs.values() if e.get("status") == "CAPTURED")
    print(f"\nbundle now holds {n_cap} captured of {total} recorded")
    print(f"this run: {captured} captured, {skipped} skipped, {failed} unavailable")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
