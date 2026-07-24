#!/usr/bin/env python3
"""One-command verifier for every claim in docs/DEVNET-PROOF.md (stdlib only, no install).

A judge should not have to click eight explorer links or trust a screenshot. This queries
Solana devnet directly and checks that each on-chain claim still holds: the programs are
executable, the feed PDA is owned by the oracle program, and every referenced transaction
landed with the exact success/rejection this submission claims.

    python3 scripts/verify-proof.py            # checks devnet, prints PASS/FAIL per claim
    RPC_URL=https://your-rpc python3 scripts/verify-proof.py

Exit 0 = every claim verified; exit 1 = at least one FAIL (or the RPC was unreachable).
"""

import json
import os
import sys
import urllib.request

RPC = os.environ.get("RPC_URL", "https://api.devnet.solana.com")

# (label, address, want_executable) -- accounts that must exist on devnet
ACCOUNTS = [
    (
        "oracle program zeroclaw_oracle",
        "EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn",
        True,
    ),
    (
        "consumer program consumer_example",
        "B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt",
        True,
    ),
    ("SF Allowances (audited)", "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44", True),
    ("device feed PDA", "CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU", False),
]
FEED_OWNER = "EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn"  # feed PDA must be owned by the oracle

# (label, signature, want_err)  want_err=None means success (err:null)
TXS = [
    (
        "shop Track-A settlement (payment_watch PAID)",
        "4kDo6NCcAxSe3BSTtQ4onTASenxRWr2miagweVway3RnDMLG7drv6NkTdV7eRtTSDcNXURy2ESpKcqkk2jG9sYqS",
        None,
    ),
    (
        "x402 machine-commerce settlement",
        "5ss8wKQo5rqXeLTdQGoWjz6jLNgycT9vCKzj7iZs4viXsexeN573gy9oZ6fgNGrBjfahQ9Zcc84fz9nF4F6Gpudc",
        None,
    ),
    (
        "allowance within-cap transfer (succeeds)",
        "5qyr7jJi8zb6SjZjnA2QT5C9nuZYgSw6raAefjmWnDDMf3JRgkQX19zssE57EpFSHVCCPfbj5qyxcYSQcfEq9W3Z",
        None,
    ),
    (
        "allowance OVER-cap transfer (rejected 0x12c)",
        "3TLSrfWVYdC3hSiAWnyyd7T694bLJQDtdJYQ64EWUsBNDehGc6Kq1veR7xa8Y1BiMdpvfFm3N1dKjDrXF3BEq2ps",
        {"InstructionError": [0, {"Custom": 300}]},
    ),
]


def rpc(method, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        RPC, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r).get("result")


def main():
    fails = 0
    print(f"verifying docs/DEVNET-PROOF.md against {RPC}\n")
    for label, addr, want_exec in ACCOUNTS:
        try:
            v = rpc("getAccountInfo", [addr, {"encoding": "base64"}])
            val = v.get("value") if v else None
            if not val:
                print(f"FAIL  {label}: account not found")
                fails += 1
                continue
            if want_exec and not val.get("executable"):
                print(f"FAIL  {label}: not executable")
                fails += 1
                continue
            if (
                addr == "CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU"
                and val.get("owner") != FEED_OWNER
            ):
                print(f"FAIL  {label}: wrong owner {val.get('owner')}")
                fails += 1
                continue
            extra = "executable" if want_exec else f"owner={val.get('owner')[:8]}"
            print(f"PASS  {label} ({extra})")
        except Exception as e:
            print(f"FAIL  {label}: RPC error {e}")
            fails += 1

    for label, sig, want_err in TXS:
        try:
            t = rpc("getTransaction", [sig, {"maxSupportedTransactionVersion": 0}])
            if not t:
                print(f"FAIL  {label}: tx not found")
                fails += 1
                continue
            got = t.get("meta", {}).get("err")
            if got == want_err:
                print(f"PASS  {label} (err={json.dumps(got)})")
            else:
                print(
                    f"FAIL  {label}: err={json.dumps(got)} expected {json.dumps(want_err)}"
                )
                fails += 1
        except Exception as e:
            print(f"FAIL  {label}: RPC error {e}")
            fails += 1

    total = len(ACCOUNTS) + len(TXS)
    print(f"\n{total - fails}/{total} claims verified")
    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    main()
