#!/usr/bin/env python3
"""Certify-then-sign: the host side of the autonomous x402 BUY path.

This is the call site for `certify_x402_payment_tx`. It exists as a tracked script because a
certifier nobody calls is a library rather than a defense, and the difference is visible to anyone
auditing this.

HOW IT DIFFERS FROM ITS SIBLING, and the difference is the whole design. `broadcast_certified.py`
guards the oracle-publish path, where intent is FIXED, so that path never asks a human and the
certifier can demand one exact shape. A purchase has VARIABLE intent: the amount changes per
request and the tier is chosen at runtime. The write-up's answer for variable intent is the audited
on-chain Allowances program, which bounds the amount and returns 0x12c over cap.

That leaves one thing the chain cannot bound. **The delegation bounds AMOUNT, not PAYEE**, and the
402 challenge naming the payee is written by the party being paid. So the payee, the mint and the
funding delegation come from operator config here and are checked against the serialized bytes
before anything is signed. A poisoned challenge redirecting the payment is within cap, structurally
valid, and refused by this script rather than by the chain.

WHAT IT DOES NOT DO BY DEFAULT: sign. Certifying is the default and needs no key, no network and no
funds, so a stranger can run it today against the captured mainnet bytes and watch it refuse a
tampered one. `--sign` is an explicit opt-in that moves real money.

There is no autonomous buyer producing input for this yet. It is the control arriving before the
capability, which is the order a spend path deserves.

Usage:
  python3 scripts/pay_x402_certified.py --self-test
  python3 scripts/pay_x402_certified.py <unsigned_b64_file> --delegation D --receiver R --mint M
  python3 scripts/pay_x402_certified.py <file> ... --sign <session_keypair.json> --broadcast

Config may come from the environment instead of the flags, which is how a jailed agent supplies it:
  ZC_X402_DELEGATION  ZC_X402_RECEIVER  ZC_X402_MINT  ZC_X402_MAX_AMOUNT  ZC_RPC
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from certify_x402_payment_tx import (  # noqa: E402
    REAL,
    CertificationError,
    certify_x402_payment_tx,
)

RPC = os.environ.get("ZC_RPC", "https://api.mainnet-beta.solana.com")


def load_config(args: argparse.Namespace) -> dict:
    """Operator config, flags first then environment. Never the challenge."""
    cfg = {
        "expected_delegation_b58": args.delegation
        or os.environ.get("ZC_X402_DELEGATION"),
        "expected_receiver_b58": args.receiver or os.environ.get("ZC_X402_RECEIVER"),
        "expected_mint_b58": args.mint or os.environ.get("ZC_X402_MINT"),
    }
    ceiling = args.max_amount or os.environ.get("ZC_X402_MAX_AMOUNT")
    if ceiling:
        cfg["max_amount_base_units"] = int(ceiling)
    if args.memo:
        cfg["expected_memo"] = args.memo.encode()
    if args.nonce_account:
        cfg["nonce_b58"] = args.nonce_account
    if args.receiver_token_account:
        cfg["expected_receiver_ata_b58"] = args.receiver_token_account
        cfg["expected_receiver_b58"] = None
    return cfg


def certify(raw: bytes, cfg: dict) -> dict:
    mint = cfg.pop("expected_mint_b58", None)
    receiver = cfg.pop("expected_receiver_b58", None)
    return certify_x402_payment_tx(raw, receiver, mint, **cfg)


def _self_test() -> int:
    """Drive the call site against the captured mainnet transfer. Offline, no key, no funds.

    Two directions, because a script only ever seen to succeed has not been seen to work: the real
    transfer certifies under its own configuration, and the same bytes are refused under a
    configuration naming a different payee.
    """
    doc = json.loads(Path(REAL).read_text(encoding="utf-8"))
    raw = None
    for v in doc["transactions"].values():
        if v["raw_len"] == 571 and not v["err"]:
            raw = base64.b64decode(v["raw_base64"])
    if raw is None:
        print("FAIL  no captured within-cap transfer to drive")
        return 1

    good = {
        "expected_delegation_b58": "HVVeimGq8VD4CuBgrvqWsgQV1GRVhfVNYQxJxTocUNY9",
        "expected_receiver_ata_b58": "98LLx6QvLcspjhCgRZa16TkCPBHSgDmvkqwyRtnb7d2o",
        "expected_mint_b58": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    }
    passed = failed = 0

    try:
        intent = certify(raw, dict(good))
        ok = intent["amount_base_units"] == 400000
        print(
            f"{'PASS' if ok else 'FAIL'}  the call site certifies the real transfer "
            f"({intent['amount_base_units']} base units)"
        )
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
    except CertificationError as e:
        print(f"FAIL  the call site certifies the real transfer ({e})")
        failed += 1

    redirected = dict(good)
    redirected["expected_receiver_ata_b58"] = (
        "EpzuUPXwMR2oWqL3MCUTjvvpfdrZXforkMt85ZCSowo3"
    )
    try:
        certify(raw, redirected)
        print("FAIL  a configuration naming a different payee is refused (certified)")
        failed += 1
    except CertificationError as e:
        print(
            f"PASS  a configuration naming a different payee is refused ({str(e)[:70]})"
        )
        passed += 1

    # The config is REQUIRED here, not defaulted, so a caller cannot fall back to whatever the
    # challenge said by supplying nothing.
    for name, drop in (
        ("delegation", "expected_delegation_b58"),
        ("mint", "expected_mint_b58"),
    ):
        partial = {k: v for k, v in good.items() if k != drop}
        try:
            certify(raw, partial)
            print(f"FAIL  a missing {name} is refused (certified)")
            failed += 1
        except CertificationError:
            print(f"PASS  a missing {name} is refused")
            passed += 1

    print(f"\nRESULT: {passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "unsigned", nargs="?", help="file holding the plugin's base64 unsigned tx"
    )
    ap.add_argument("--delegation", help="base58 funding delegation (operator config)")
    ap.add_argument("--receiver", help="base58 receiver WALLET (operator config)")
    ap.add_argument(
        "--receiver-token-account", help="its token account, if not an ATA of the mint"
    )
    ap.add_argument("--mint", help="base58 SPL mint (operator config)")
    ap.add_argument("--max-amount", help="local ceiling in atomic base units")
    ap.add_argument(
        "--memo", help="the challenge nonce the payment must carry, exactly"
    )
    ap.add_argument(
        "--nonce-account", help="base58 durable-nonce account, if one is used"
    )
    ap.add_argument(
        "--sign", metavar="KEYPAIR", help="sign with this session keypair; MOVES MONEY"
    )
    ap.add_argument(
        "--broadcast", action="store_true", help="submit the signed transaction"
    )
    ap.add_argument(
        "--self-test", action="store_true", help="drive both directions offline"
    )
    args = ap.parse_args()

    if args.self_test:
        return _self_test()
    if not args.unsigned:
        ap.error("give an unsigned-transaction file, or --self-test")

    raw = base64.b64decode(Path(args.unsigned).read_text(encoding="utf-8").strip())
    try:
        intent = certify(raw, load_config(args))
    except CertificationError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2

    print("CERTIFIED")
    for k, v in intent.items():
        print(f"  {k}: {v}")

    if not args.sign:
        print("\nNot signed. Certification is the default; --sign is what moves money.")
        return 0

    # Deliberately last, deliberately explicit, and deliberately not the default. Everything above
    # this line is free to run and proves the gate; everything below it spends.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        return int(bool(sys.stderr.write("needs: pip3 install cryptography\n"))) or 1

    secret = json.loads(Path(args.sign).read_text(encoding="utf-8"))
    key = Ed25519PrivateKey.from_private_bytes(bytes(secret[:32]))
    nsigs = raw[0]
    message = raw[1 + nsigs * 64 :]
    signed = bytearray(raw)
    signed[1 : 1 + 64] = key.sign(message)

    if not args.broadcast:
        print("\nSigned, NOT submitted. Add --broadcast to send it.")
        print(base64.b64encode(bytes(signed)).decode())
        return 0

    import urllib.request

    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [
                base64.b64encode(bytes(signed)).decode(),
                {"encoding": "base64"},
            ],
        }
    ).encode()
    req = urllib.request.Request(
        RPC, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    if "error" in out:
        print(f"RPC refused: {out['error']}", file=sys.stderr)
        return 3
    print(f"submitted: {out['result']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
