#!/usr/bin/env python3
"""Verify this project's on-chain claims with NO network access.

Why this exists: public devnet RPC retains roughly four days of transaction history. The bounty
deadline and the judging date are two weeks apart, so every explorer link in this repo is dead by
the time anyone clicks it. That makes an explorer link a convenience, not evidence.

This script verifies the evidence instead. For each transaction captured in
docs/proof-bundle/devnet-transactions.json it:

  1. recomputes sha256 over the decoded bytes and compares to the recorded digest,
  2. parses the Solana wire format to split signatures from the serialized message,
  3. verifies each ed25519 signature against that message and the matching account key,
  4. decodes the instructions so a reader sees what the transaction did.

Step 3 is the load-bearing one. An ed25519 signature that verifies against a public key is proof
that the holder of the matching private key signed exactly these bytes. No RPC, no explorer, and
no trust in this repo's own claims are involved.

Everything here is Python standard library, so a fresh clone runs it with no install step.

    python scripts/verify_proof_offline.py
    python scripts/verify_proof_offline.py --verbose

Exit 0 when every captured transaction verifies AND both self-tests pass. Non-zero otherwise.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

BUNDLE = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "proof-bundle"
    / "devnet-transactions.json"
)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    for byte in raw:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out


# --------------------------------------------------------------------------------------
# ed25519 verification, RFC 8032. Pure Python so the bundle stays checkable with no deps.
# --------------------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _x_recover(_BY)
_B = (_BX % _P, _BY % _P, 1, _BX * _BY % _P)
_IDENT = (0, 1, 1, 0)


def _add(p, q):
    # extended twisted Edwards, add-2008-hwcd-3
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(p, e: int):
    q = _IDENT
    while e > 0:
        if e & 1:
            q = _add(q, p)
        p = _add(p, p)
        e >>= 1
    return q


def _compress(p) -> bytes:
    zinv = pow(p[2], _P - 2, _P)
    x = p[0] * zinv % _P
    y = p[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x = _x_recover(y)
    if x & 1 != sign:
        x = _P - x
    point = (x, y, 1, x * y % _P)
    # reject points not on the curve
    x1, y1, z1, t1 = point
    if (-x1 * x1 + y1 * y1 - z1 * z1 - _D * t1 * t1) % _P != 0:
        return None
    return point


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid ed25519 signature over `message` by `public_key`."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    a = _decompress(public_key)
    if a is None:
        return False
    r = _decompress(signature[:32])
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = (
        int.from_bytes(
            hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
        )
        % _L
    )
    # check [s]B == R + [h]A
    lhs = _compress(_mul(_B, s))
    rhs = _compress(_add(r, _mul(a, h)))
    return lhs == rhs


# --------------------------------------------------------------------------------------
# Solana wire format
# --------------------------------------------------------------------------------------


def read_shortvec(buf: bytes, off: int) -> tuple[int, int]:
    """Solana's compact-u16. Returns (value, new_offset)."""
    value = 0
    shift = 0
    while True:
        byte = buf[off]
        off += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            break
        shift += 7
        if shift > 21:
            raise ValueError("shortvec too long")
    return value, off


def split_transaction(raw: bytes) -> tuple[list[bytes], bytes]:
    """Return (signatures, serialized_message). The message is what was signed."""
    count, off = read_shortvec(raw, 0)
    sigs = []
    for _ in range(count):
        sigs.append(raw[off : off + 64])
        off += 64
    return sigs, raw[off:]


def parse_message(msg: bytes) -> dict:
    off = 0
    versioned = False
    if msg and msg[0] & 0x80:
        versioned = True
        off = 1
    num_required, num_ro_signed, num_ro_unsigned = msg[off], msg[off + 1], msg[off + 2]
    off += 3
    n_keys, off = read_shortvec(msg, off)
    keys = []
    for _ in range(n_keys):
        keys.append(msg[off : off + 32])
        off += 32
    blockhash = msg[off : off + 32]
    off += 32
    n_ix, off = read_shortvec(msg, off)
    instructions = []
    for _ in range(n_ix):
        prog_idx = msg[off]
        off += 1
        n_acc, off = read_shortvec(msg, off)
        acc_idx = list(msg[off : off + n_acc])
        off += n_acc
        data_len, off = read_shortvec(msg, off)
        data = msg[off : off + data_len]
        off += data_len
        instructions.append(
            {"program_index": prog_idx, "accounts": acc_idx, "data": data}
        )
    return {
        "versioned": versioned,
        "num_required_signatures": num_required,
        "num_readonly_signed": num_ro_signed,
        "num_readonly_unsigned": num_ro_unsigned,
        "account_keys": keys,
        "recent_blockhash": blockhash,
        "instructions": instructions,
    }


# --------------------------------------------------------------------------------------
# Self-tests. A verifier that has never rejected anything has not been shown to work.
# --------------------------------------------------------------------------------------


def self_test(raw: bytes) -> tuple[bool, list[str]]:
    """Both controls must FAIL verification, or this script cannot be trusted."""
    notes = []
    sigs, msg = split_transaction(raw)
    parsed = parse_message(msg)
    key = parsed["account_keys"][0]
    sig = sigs[0]

    if not ed25519_verify(key, msg, sig):
        return False, [
            "POSITIVE CONTROL FAILED: an untampered signature did not verify"
        ]
    notes.append("untampered signature verifies (positive control)")

    tampered_msg = bytearray(msg)
    tampered_msg[-1] ^= 0x01
    if ed25519_verify(key, bytes(tampered_msg), sig):
        return False, ["NEGATIVE CONTROL FAILED: a corrupted message still verified"]
    notes.append("one flipped message byte is rejected (negative control)")

    tampered_sig = bytearray(sig)
    tampered_sig[0] ^= 0x01
    if ed25519_verify(key, msg, bytes(tampered_sig)):
        return False, ["NEGATIVE CONTROL FAILED: a corrupted signature still verified"]
    notes.append("one flipped signature byte is rejected (negative control)")

    return True, notes


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--bundle", default=str(BUNDLE))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    path = Path(args.bundle)
    if not path.exists():
        print(f"FAIL  bundle not found: {path}")
        return 2
    bundle = json.loads(path.read_text(encoding="utf-8"))
    entries = bundle.get("transactions", {})
    captured = {s: e for s, e in entries.items() if e.get("status") == "CAPTURED"}

    print(f"offline proof verification, no network used")
    print(
        f"bundle captured {bundle.get('captured_utc')} from {bundle.get('source_rpc')}"
    )
    print(f"{len(captured)} captured of {len(entries)} recorded signatures\n")

    if not captured:
        print("FAIL  bundle contains no captured transactions")
        return 2

    first_raw = base64.b64decode(next(iter(captured.values()))["raw_base64"])
    ok, notes = self_test(first_raw)
    for n in notes:
        print(f"  self-test  {n}")
    if not ok:
        print("\nFAIL  self-test did not pass; results would be meaningless")
        return 3
    print()

    failures = 0
    for sig_str, entry in sorted(captured.items()):
        raw = base64.b64decode(entry["raw_base64"])
        problems = []

        digest = hashlib.sha256(raw).hexdigest()
        if digest != entry["raw_sha256"]:
            problems.append("sha256 mismatch against recorded digest")

        sigs, msg = split_transaction(raw)
        parsed = parse_message(msg)

        if b58encode(sigs[0]) != sig_str:
            problems.append(
                "first signature does not match the recorded signature string"
            )

        n_required = parsed["num_required_signatures"]
        verified = 0
        for i in range(min(n_required, len(sigs))):
            if ed25519_verify(parsed["account_keys"][i], msg, sigs[i]):
                verified += 1
            else:
                problems.append(f"signature {i} failed ed25519 verification")

        status = "FAIL" if problems else "PASS"
        if problems:
            failures += 1
        print(
            f"{status}  {sig_str[:16]}..  slot={entry.get('slot')}  "
            f"sigs {verified}/{n_required} verified  {len(parsed['instructions'])} instruction(s)"
        )
        for p in problems:
            print(f"        {p}")
        if args.verbose and not problems:
            print(f"        fee payer      {b58encode(parsed['account_keys'][0])}")
            print(f"        err            {entry.get('err')}")
            for j, ix in enumerate(parsed["instructions"]):
                prog = b58encode(parsed["account_keys"][ix["program_index"]])
                print(
                    f"        instruction {j}  program={prog} data={len(ix['data'])}B "
                    f"accounts={len(ix['accounts'])}"
                )

    print()
    if failures:
        print(f"FAIL  {failures} of {len(captured)} transactions did not verify")
        return 1
    print(f"PASS  all {len(captured)} captured transactions verify offline")
    print(
        "      each signature is valid ed25519 over the exact serialized message shown,"
    )
    print("      which holds whether or not any RPC still serves these transactions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
