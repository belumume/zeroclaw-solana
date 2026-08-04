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
  4. decodes every instruction so a reader sees what the transaction did.

Step 3 is the load-bearing one. An ed25519 signature that verifies against a public key is proof
that the holder of the matching private key signed exactly these bytes. No RPC, no explorer, and
no trust in this repo's own claims are involved.

Step 4 is DERIVED, never asserted. An Anchor instruction is named by recomputing
sha256("global:<name>")[:8] and matching it against the discriminator actually present in the
bytes, so "publish_reading" is a decode result rather than a caption. Anything this script cannot
name from the bytes prints as unrecognized instead of being given a plausible label.

Everything here is Python standard library, so a fresh clone runs it with no install step.

    python scripts/verify_proof_offline.py
    python scripts/verify_proof_offline.py --verbose

Exit 0 when every captured transaction verifies AND every self-test control behaves. Non-zero
otherwise.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
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


def digest_matches(raw: bytes, recorded: str) -> bool:
    """Does `raw` hash to the digest recorded at capture time?

    Deliberately shared by the self-test and the per-transaction loop. A control that exercises a
    different code path than the thing it guards proves nothing about that thing, so this is the
    one function both go through.
    """
    return hashlib.sha256(raw).hexdigest() == recorded


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
# Instruction decoding
#
# Program addresses and instruction layouts mirror crates/solana-core (pubkey.rs, instruction.rs,
# token.rs, anchor.rs) and onchain/programs/. The two project-owned programs are decoded through
# Anchor's own discriminator rule rather than by matching a hardcoded byte string, so the printed
# name is derived from the bytes.
# --------------------------------------------------------------------------------------

SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
ALLOWANCES_PROGRAM = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44"
ORACLE_PROGRAM = "EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn"
CONSUMER_PROGRAM = "B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt"

PROGRAM_NAMES = {
    SYSTEM_PROGRAM: "System",
    TOKEN_PROGRAM: "SPL Token",
    TOKEN_2022_PROGRAM: "SPL Token-2022",
    MEMO_PROGRAM: "SPL Memo",
    COMPUTE_BUDGET_PROGRAM: "ComputeBudget",
    ALLOWANCES_PROGRAM: "SF Allowances",
    ORACLE_PROGRAM: "zeroclaw_oracle",
    CONSUMER_PROGRAM: "consumer_example",
}

# Anchor method names this project's own programs expose. The decoder tries each and keeps the
# one whose computed discriminator matches the bytes; a miss prints as unrecognized.
ANCHOR_METHODS = {
    ORACLE_PROGRAM: ("publish_reading", "register_device"),
    CONSUMER_PROGRAM: ("act_on_feed",),
}


def instruction_sighash(name: str) -> bytes:
    """Anchor's instruction discriminator: first 8 bytes of sha256("global:<name>")."""
    return hashlib.sha256(f"global:{name}".encode()).digest()[:8]


def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def _i64(data: bytes, off: int) -> int:
    return struct.unpack_from("<q", data, off)[0]


def _scaled(value: int, scale: int) -> str:
    """Render a fixed-point reading, e.g. value=3300 scale=-2 -> '33.00'."""
    if scale > 0 or scale < -9:
        return str(value)
    places = -scale
    sign = "-" if value < 0 else ""
    digits = str(abs(value)).rjust(places + 1, "0")
    if places == 0:
        return f"{sign}{digits}"
    return f"{sign}{digits[:-places]}.{digits[-places:]}"


def _amount(raw: int, decimals: int) -> str:
    return f"{raw / (10**decimals):.{decimals}f}" if decimals else str(raw)


def _printable(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    return "".join(c if 32 <= ord(c) < 127 else "." for c in text)


def decode_instruction(program: str, data: bytes, n_accounts: int) -> str:
    """Human-readable decode of one instruction, or an explicit unrecognized marker.

    Never guesses. If the program is unknown, or the discriminator does not match anything this
    decoder knows, the result says so rather than inventing a name.
    """
    try:
        if program == SYSTEM_PROGRAM and len(data) >= 4:
            tag = struct.unpack_from("<I", data, 0)[0]
            if tag == 4:
                return "AdvanceNonceAccount (durable-nonce replay guard)"
            if tag == 2 and len(data) >= 12:
                return f"Transfer {_amount(_u64(data, 4), 9)} SOL"
            return f"unrecognized System instruction (tag {tag})"

        if program in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
            if data and data[0] == 12 and len(data) >= 10:
                amount, decimals = _u64(data, 1), data[9]
                return f"TransferChecked {_amount(amount, decimals)} (raw {amount}, {decimals} dp)"
            tag = data[0] if data else None
            return f"unrecognized token instruction (tag {tag})"

        if program == MEMO_PROGRAM:
            return f'Memo "{_printable(data)}"'

        if program == COMPUTE_BUDGET_PROGRAM and data:
            if data[0] == 2 and len(data) >= 5:
                units = struct.unpack_from("<I", data, 1)[0]
                return f"SetComputeUnitLimit {units}"
            if data[0] == 3 and len(data) >= 9:
                return f"SetComputeUnitPrice {_u64(data, 1)} microlamports"
            return f"unrecognized ComputeBudget instruction (tag {data[0]})"

        if program == ALLOWANCES_PROGRAM and data:
            if data[0] == 1 and len(data) >= 33:
                return (
                    f"createFixedDelegation cap={_u64(data, 9)} raw units "
                    f"(nonce {_u64(data, 1)})"
                )
            if data[0] == 4 and len(data) >= 73:
                return f"transferFixed amount={_u64(data, 1)} raw units"
            return f"unrecognized SF Allowances instruction (tag {data[0]})"

        # Anchor programs: name the instruction by recomputing the discriminator.
        if program in ANCHOR_METHODS and len(data) >= 8:
            for name in ANCHOR_METHODS[program]:
                if data[:8] != instruction_sighash(name):
                    continue
                if name == "publish_reading" and len(data) >= 46:
                    value, scale = _i64(data, 8), struct.unpack_from("<b", data, 16)[0]
                    unit = _printable(data[17:29].rstrip(b"\x00"))
                    return (
                        f"publish_reading seq={_u64(data, 29)} "
                        f"value={_scaled(value, scale)}{unit} "
                        f"observed_at={_i64(data, 37)} feed_kind={data[45]}"
                    )
                return f"{name} (discriminator matches)"
            return "unrecognized Anchor instruction (no known discriminator matches)"

        return f"unrecognized instruction ({len(data)} bytes, {n_accounts} accounts)"
    except (struct.error, IndexError):
        return f"undecodable instruction ({len(data)} bytes)"


def describe_program(address: str) -> str:
    name = PROGRAM_NAMES.get(address)
    return f"{name}" if name else f"{address[:12]}.. (unknown program)"


# --------------------------------------------------------------------------------------
# Self-tests. A verifier that has never rejected anything has not been shown to work.
#
# Every control asserts that it actually perturbed what it claims to perturb, because a control
# that silently mutates nothing passes for the wrong reason and reports coverage it does not have.
# --------------------------------------------------------------------------------------


def self_test(raw: bytes, recorded_digest: str) -> tuple[bool, list[str]]:
    """Controls must behave exactly as named, or results are not reportable."""
    notes = []
    sigs, msg = split_transaction(raw)
    parsed = parse_message(msg)
    key = parsed["account_keys"][0]
    sig = sigs[0]

    # POSITIVE: the verifier can say yes to genuine input.
    if not ed25519_verify(key, msg, sig):
        return False, [
            "POSITIVE CONTROL FAILED: an untampered signature did not verify"
        ]
    notes.append("untampered signature verifies (positive control)")

    # NEGATIVE: one flipped message byte must be rejected.
    tampered_msg = bytearray(msg)
    tampered_msg[-1] ^= 0x01
    if bytes(tampered_msg) == msg:
        return False, [
            "CONTROL INVALID: the message-tamper control did not change any byte"
        ]
    if ed25519_verify(key, bytes(tampered_msg), sig):
        return False, ["NEGATIVE CONTROL FAILED: a corrupted message still verified"]
    notes.append("one flipped message byte is rejected (negative control)")

    # NEGATIVE: one flipped signature byte must be rejected.
    tampered_sig = bytearray(sig)
    tampered_sig[0] ^= 0x01
    if bytes(tampered_sig) == sig:
        return False, [
            "CONTROL INVALID: the signature-tamper control did not change any byte"
        ]
    if ed25519_verify(key, msg, bytes(tampered_sig)):
        return False, ["NEGATIVE CONTROL FAILED: a corrupted signature still verified"]
    notes.append("one flipped signature byte is rejected (negative control)")

    # NEGATIVE: the digest comparison must discriminate, not merely be computed.
    tampered_raw = bytearray(raw)
    tampered_raw[-1] ^= 0x01
    if bytes(tampered_raw) == raw:
        return False, ["CONTROL INVALID: the digest control did not change any byte"]
    if digest_matches(bytes(tampered_raw), recorded_digest):
        return False, [
            "NEGATIVE CONTROL FAILED: a corrupted transaction matched the digest"
        ]
    if not digest_matches(raw, recorded_digest):
        return False, ["POSITIVE CONTROL FAILED: the untampered digest did not match"]
    notes.append(
        "one flipped transaction byte breaks the sha256 match (negative control)"
    )

    # The Anchor decode is only meaningful if a WRONG name fails to match. Prove both directions.
    real = instruction_sighash("publish_reading")
    decoy = instruction_sighash("publish_reading_")
    if real == decoy:
        return False, [
            "CONTROL INVALID: two different Anchor names produced one discriminator"
        ]
    notes.append(
        "a decoy Anchor method name yields a different discriminator (negative control)"
    )

    return True, notes


def verify_one(path: Path, verbose: bool) -> int:
    """Verify ONE bundle. 0 pass, 1 failures, 2 unusable, 3 self-test failed."""
    if not path.exists():
        print(f"FAIL  bundle not found: {path}")
        return 2
    bundle = json.loads(path.read_text(encoding="utf-8"))
    entries = bundle.get("transactions", {})
    captured = {s: e for s, e in entries.items() if e.get("status") == "CAPTURED"}
    pruned = {s: e for s, e in entries.items() if e.get("status") != "CAPTURED"}

    print("offline proof verification, no network used")
    print(
        f"bundle captured {bundle.get('captured_utc')} from {bundle.get('source_rpc')}"
    )
    print(f"{len(captured)} captured of {len(entries)} recorded signatures\n")

    if not captured:
        print("FAIL  bundle contains no captured transactions")
        return 2

    first_sig, first_entry = next(iter(sorted(captured.items())))
    ok, notes = self_test(
        base64.b64decode(first_entry["raw_base64"]), first_entry["raw_sha256"]
    )
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

        if not digest_matches(raw, entry["raw_sha256"]):
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
        err = entry.get("err")
        outcome = "succeeded" if err is None else f"FAILED ON CHAIN: {json.dumps(err)}"
        print(
            f"{status}  {sig_str[:16]}..  slot={entry.get('slot')}  "
            f"sigs {verified}/{n_required} verified  {outcome}"
        )
        for p in problems:
            print(f"        {p}")
        for j, ix in enumerate(parsed["instructions"]):
            prog = b58encode(parsed["account_keys"][ix["program_index"]])
            print(
                f"        ix{j}  {describe_program(prog)}: "
                f"{decode_instruction(prog, ix['data'], len(ix['accounts']))}"
            )
            if verbose:
                # The account list matters for more than completeness. A Solana Pay reference is
                # an unfunded read-only marker that appears here and nowhere else, so this is
                # where an invoice is tied to its settlement without asking any RPC.
                for a in ix["accounts"]:
                    if a < len(parsed["account_keys"]):
                        print(
                            f"              account  {b58encode(parsed['account_keys'][a])}"
                        )
        if verbose:
            print(f"        fee payer      {b58encode(parsed['account_keys'][0])}")
            for i in range(min(n_required, len(sigs))):
                print(
                    f"        signer {i}       {b58encode(parsed['account_keys'][i])}"
                )

    if pruned:
        print()
        print(f"note  {len(pruned)} recorded signature(s) were pruned before capture:")
        for s in sorted(pruned):
            print(f"        {s[:16]}..  {pruned[s].get('status')}")
        print(
            "      those are real signatures the public endpoint no longer serves; they are"
        )
        print(
            "      recorded rather than dropped, and are NOT counted as verified below."
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


def main() -> int:
    """Check EVERY captured bundle by default, and name each one it checked.

    The default used to be the devnet bundle alone. Nothing about that was dishonest:
    every run prints the source RPC it captured from, and MAINNET-PROOF.md passes
    --bundle explicitly, so the command printed beside the mainnet claim was always
    correct. But a BARE invocation covered one chain of two and said nothing about the
    other, so its green could be read as broader than it was. Covering every bundle
    removes that ambiguity by construction rather than by remembering a flag.
    """
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--bundle",
        default=None,
        help="verify ONE bundle; default verifies every bundle in docs/proof-bundle/",
    )
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.bundle:
        return verify_one(Path(args.bundle), args.verbose)

    bundles = sorted(BUNDLE.parent.glob("*-transactions.json"))
    # A floor, so a broken glob cannot print a clean result over nothing. Discovering
    # fewer bundles than exist is exactly how a sweep reports green while checking less
    # than it claims.
    if len(bundles) < 2:
        print(f"FAIL  found {len(bundles)} bundle(s) in {BUNDLE.parent}; expected at least 2")
        return 2

    worst = 0
    for i, b in enumerate(bundles):
        if i:
            print()
            print("=" * 72)
            print()
        print(f"### {b.name}")
        worst = max(worst, verify_one(b, args.verbose))

    print()
    print("=" * 72)
    names = ", ".join(b.name for b in bundles)
    if worst:
        print(f"FAIL  at least one of {len(bundles)} bundles did not verify: {names}")
    else:
        print(f"PASS  all {len(bundles)} bundles verified offline: {names}")
    return worst


if __name__ == "__main__":
    sys.exit(main())
