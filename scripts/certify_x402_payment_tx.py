#!/usr/bin/env python3
"""Fail-closed certification for the x402 BUY path, before the host signs anything.

The sell side of this loop is proven: a ZeroClaw node serves a 402 challenge and refuses a
malformed payment. The buy side is a human at a shell who reads the challenge WITH THEIR EYES and
retypes six fields into a CLI. Making that autonomous means the host auto-signs bounded spends,
which is a real trade against the human approval gate and must be paid for with a control rather
than asserted away. This is that control, and it lands before the spender does.

WHAT MAKES AN AUTONOMOUS BUYER SAFE, and it is not this file alone:

    plugin PROPOSES   T1, keyless. It builds an UNSIGNED transaction and holds only a pubkey.
    program DISPOSES  the audited SF Allowances program is the SOLE spending authority over a
                      delegated pool and returns 0x12c (300, AmountExceedsLimit) over cap.
    host SIGNS        the delegated session key lives in the host, never in a plugin.

So "no plugin here holds a key that can move funds" survives verbatim. This file is the last gate
before the host's signature: it re-derives intent FROM THE SERIALIZED BYTES and refuses anything
that is not the one payment the operator configured.

THE CONSTRAINT THIS EXISTS FOR, which is the one that would actually lose money:

**The delegation bounds AMOUNT, not PAYEE.** `receiver` is a free typed argument. And a 402
challenge is ATTACKER-CONTROLLABLE CONTENT: the seller writes it. So a poisoned challenge naming a
different pay-to wallet produces a transaction that is *within cap*, structurally valid, and pays
the attacker. Every amount check passes. The on-chain cap does not help.

The only defence is that the payee, the mint AND the funding delegation come from JAILED OPERATOR
CONFIG and are checked against these bytes, never taken from the challenge.

THE CHECK IS POSITIONAL, AND THAT DISTINCTION IS THE WHOLE FILE. Asking whether a configured key
appears ANYWHERE in the account list is wrong twice over, and the second way is worse. It is too
weak, because a hostile transaction can list the honest key in some unrelated slot. And for the
receiver it looks for a key that is NEVER PRESENT: the program credits ASSOCIATED TOKEN ACCOUNTS,
so the destination is `ATA(receiver, mint)` and the receiver WALLET does not appear at all. A
membership check would refuse every legitimate payment while passing hand-built fixtures.

WHAT AN ALLOWLIST OF PROGRAMS DOES NOT DO, learned from an adversarial review of the first draft:
naming a program safe says nothing about what it is asked to do. System was allowlisted so a
durable nonce could be advanced, and `SystemInstruction::Transfer` is the same program, so an
appended plain SOL transfer from the fee payer certified cleanly. ComputeBudget was allowlisted so
a priority fee could be set, and an unbounded `SetComputeUnitPrice` burns the signer's lamports.
So every permitted program's INSTRUCTION DATA is now constrained, not merely its identity.

Pure stdlib, no network. Import `certify_x402_payment_tx`, or run this file for the self-test.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Program ids and layout constants. Every one is sourced, because a wrong
# constant here is a control that passes while enforcing nothing.
# ---------------------------------------------------------------------------

SYSTEM_PROGRAM = bytes(32)

# Source: plugins/allowance-spend-build/src/allowance.rs SUBSCRIPTIONS_PROGRAM_ID.
ALLOWANCE_PROGRAM_B58 = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44"
TOKEN_PROGRAM_B58 = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_B58 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ATA_PROGRAM_B58 = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
MEMO_PROGRAM_B58 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
COMPUTE_BUDGET_B58 = "ComputeBudget111111111111111111111111111111"

# Source: allowance.rs IX_TRANSFER_FIXED / IX_TRANSFER_RECURRING, themselves sourced to the
# program's transfer_fixed_delegation.rs DISCRIMINATOR and the IDL default values.
IX_TRANSFER_FIXED = 4
IX_TRANSFER_RECURRING = 5
IX_CREATE_IDEMPOTENT = 1

# SystemInstruction is a bincode u32 enum tag. AdvanceNonceAccount is variant 4; Transfer is
# variant 2, which is the one an allowlist-by-program-id lets through.
SYS_ADVANCE_NONCE = (4).to_bytes(4, "little")

# ComputeBudget instruction tags: 2 = SetComputeUnitLimit(u32), 3 = SetComputeUnitPrice(u64).
CB_SET_UNIT_LIMIT = 2
CB_SET_UNIT_PRICE = 3
DEFAULT_MAX_PRIORITY_LAMPORTS = (
    10_000  # 0.00001 SOL; a purchase needs no more than this.
)
DEFAULT_UNIT_LIMIT = 200_000  # Solana's per-instruction default when none is set.

# data = [disc:u8][amount:u64 LE][delegator:32][mint:32]
TRANSFER_DATA_LEN = 1 + 8 + 32 + 32
DATA_AMOUNT_SLICE = slice(1, 9)
DATA_DELEGATOR_SLICE = slice(9, 41)
DATA_MINT_SLICE = slice(41, 73)

# accounts, in order. Source: allowance.rs transfer instruction builder, CONFIRMED against the
# real mainnet transfer 5sHLcD1v.. in docs/proof-bundle/mainnet-transactions.json, including its
# signer and writable flags.
ACCT_NAMES = (
    "delegation_pda",
    "subscription_authority",
    "delegator_ata",
    "receiver_ata",
    "token_mint",
    "token_program",
    "delegatee_signer",
    "event_authority",
    "subscriptions_program",
)
A_DELEGATION = 0
A_DELEGATOR_ATA = 2
A_RECEIVER_ATA = 3
A_TOKEN_MINT = 4
A_TOKEN_PROGRAM = 5
A_DELEGATEE = 6
A_SUBSCRIPTIONS_PROGRAM = 8

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_PDA_MARKER = b"ProgramDerivedAddress"

# A transaction cannot reference more accounts than a shortvec-3 could describe, and a real one
# references a few dozen. The bound exists so a crafted length cannot allocate the gate to death.
MAX_KEYS = 256
MAX_INSTRUCTIONS = 64


class CertificationError(Exception):
    """Raised when the serialized tx does not match the configured payment intent."""


# ---------------------------------------------------------------------------
# Encoding and address derivation
# ---------------------------------------------------------------------------


def b58decode(s: str) -> bytes:
    num = 0
    for c in s:
        if c not in _B58:
            raise CertificationError(f"{c!r} is not a base58 character")
        num = num * 58 + _B58.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def b58key(s: str, what: str) -> bytes:
    """Decode a base58 string that must be a 32-byte public key."""
    out = b58decode(s)
    if len(out) != 32:
        raise CertificationError(
            f"{what} decodes to {len(out)} bytes, not a 32-byte address"
        )
    return out


def b58encode(b: bytes) -> str:
    num = int.from_bytes(b, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def _on_curve(b: bytes) -> bool:
    """True if the 32 bytes decompress to an ed25519 point, so NOT a valid PDA.

    Two edge cases are handled rather than left to chance, because the alternative is a silent
    disagreement with the runtime that decides what a real PDA is. A non-canonical y is REDUCED
    (curve25519-dalek masks the high bit and reduces) instead of being reported off-curve, and a
    zero denominator is off-curve (`sqrt_ratio_i(u, 0)` has no root for non-zero u) rather than
    passing through modular inversion, which would return 0 and wrongly report on-curve.
    """
    y = (int.from_bytes(b, "little") & ((1 << 255) - 1)) % _P
    yy = y * y % _P
    u = (yy - 1) % _P
    v = (_D * yy + 1) % _P
    if v == 0:
        return False
    xx = u * pow(v, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    return (x * x - xx) % _P == 0


def find_program_address(seeds: list[bytes], program: bytes) -> tuple[bytes, int]:
    for bump in range(255, -1, -1):
        h = hashlib.sha256()
        for s in seeds:
            h.update(s)
        h.update(bytes([bump]))
        h.update(program)
        h.update(_PDA_MARKER)
        cand = h.digest()
        if not _on_curve(cand):
            return cand, bump
    raise CertificationError("no off-curve bump exists for these seeds")


def derive_ata(wallet: bytes, mint: bytes, token_program: bytes) -> bytes:
    """The associated token account of (wallet, mint) under token_program."""
    return find_program_address(
        [wallet, token_program, mint], b58decode(ATA_PROGRAM_B58)
    )[0]


# ---------------------------------------------------------------------------
# Transaction parsing
# ---------------------------------------------------------------------------


def _read_shortvec(b: bytes, i: int) -> tuple[int, int]:
    """Decode a compact-u16. Rejects over-long and non-minimal encodings.

    Solana's own `decode_shortu16_len` refuses both. A lenient decoder does not let a bad
    transaction through here (it would die on chain) but it makes this parser disagree with the
    runtime about what the bytes say, and a gate that reads something other than what executes
    is not reading the transaction.
    """
    val = 0
    for n in range(3):
        if i >= len(b):
            raise CertificationError("truncated length prefix")
        c = b[i]
        i += 1
        val |= (c & 0x7F) << (7 * n)
        if not c & 0x80:
            if n and not c:
                raise CertificationError("non-minimal compact-u16 encoding")
            return val, i
    raise CertificationError("compact-u16 longer than three bytes")


def _take(b: bytes, i: int, n: int) -> tuple[bytes, int]:
    if i + n > len(b):
        raise CertificationError(
            f"truncated: wanted {n} byte(s) at offset {i} of {len(b)}"
        )
    return b[i : i + n], i + n


def parse_message(msg: bytes) -> dict:
    """Parse a legacy or v0 transaction message, refusing anything it cannot read exactly.

    v0 IS ACCEPTED, and refusing it would have been the more dangerous choice: the plugin this
    gate exists for calls `serialize_v0_no_lookups`, so a v0-only refusal would refuse every real
    payment while passing the legacy transfers captured in the proof bundle, which a different
    builder produced.

    What is refused is a v0 message carrying ADDRESS-TABLE LOOKUPS. With lookups, some accounts
    are resolved from on-chain tables at execution time and are not in this byte string, so every
    positional check would read the wrong slot while appearing to succeed.
    """
    if len(msg) < 4:
        raise CertificationError("message is too short to carry a header")
    versioned = bool(msg[0] & 0x80)
    if versioned and (msg[0] & 0x7F) != 0:
        raise CertificationError(
            f"unsupported message version v{msg[0] & 0x7F}; only legacy and v0 are understood, "
            f"and a version this parser does not know could place accounts anywhere"
        )
    i = 1 if versioned else 0
    n_req_sig, n_ro_signed, n_ro_unsigned = msg[i], msg[i + 1], msg[i + 2]
    i += 3

    n_keys, i = _read_shortvec(msg, i)
    if not 0 < n_keys <= MAX_KEYS:
        raise CertificationError(
            f"{n_keys} account keys is outside the plausible range"
        )
    if (
        n_req_sig > n_keys
        or n_ro_signed > n_req_sig
        or n_ro_unsigned > n_keys - n_req_sig
    ):
        raise CertificationError(
            "the header's signer and readonly counts are self-inconsistent"
        )
    keys = []
    for _ in range(n_keys):
        k, i = _take(msg, i, 32)
        keys.append(k)
    _, i = _take(msg, i, 32)  # recent blockhash

    def is_signer(k: int) -> bool:
        return k < n_req_sig

    def is_writable(k: int) -> bool:
        if k < n_req_sig:
            return k < n_req_sig - n_ro_signed
        return k < n_keys - n_ro_unsigned

    n_ix, i = _read_shortvec(msg, i)
    if n_ix > MAX_INSTRUCTIONS:
        raise CertificationError(f"{n_ix} instructions is outside the plausible range")
    ixs = []
    for n in range(n_ix):
        (prog_idx,), i = _take(msg, i, 1)
        if prog_idx >= n_keys:
            raise CertificationError(
                f"ix{n} names program index {prog_idx} of {n_keys} keys"
            )
        n_acct, i = _read_shortvec(msg, i)
        raw_idx, i = _take(msg, i, n_acct)
        for a in raw_idx:
            if a >= n_keys:
                raise CertificationError(
                    f"ix{n} names account index {a} of {n_keys} keys"
                )
        dlen, i = _read_shortvec(msg, i)
        data, i = _take(msg, i, dlen)
        ixs.append(
            {
                "program": keys[prog_idx],
                "accounts": [keys[a] for a in raw_idx],
                "signer": [is_signer(a) for a in raw_idx],
                "writable": [is_writable(a) for a in raw_idx],
                "data": data,
            }
        )

    if versioned:
        n_lookups, i = _read_shortvec(msg, i)
        if n_lookups:
            raise CertificationError(
                f"this v0 message carries {n_lookups} address-table lookup(s); some of its "
                f"accounts are resolved on chain and are not in these bytes, so every "
                f"positional check would read the wrong slot while appearing to succeed"
            )
    if i != len(msg):
        raise CertificationError(
            f"{len(msg) - i} trailing byte(s) after the message; a parser that ignores them is "
            f"not reading what would execute"
        )
    return {
        "keys": keys,
        "instructions": ixs,
        "versioned": versioned,
        "n_req_sig": n_req_sig,
    }


def message_of(raw_tx: bytes) -> bytes:
    """Strip the signature vector off a serialized transaction."""
    if not raw_tx:
        raise CertificationError("empty transaction")
    nsigs = raw_tx[0]
    if nsigs >= 0x80:
        raise CertificationError("multi-byte signature shortvec is unexpected here")
    if len(raw_tx) < 1 + nsigs * 64:
        raise CertificationError(
            "the signature vector runs past the end of the transaction"
        )
    return raw_tx[1 + nsigs * 64 :]


# ---------------------------------------------------------------------------
# The certification
# ---------------------------------------------------------------------------


def _check_system(ix: dict, k: int, nonce: bytes | None) -> None:
    """A permitted program is not a permitted action. System's variant 2 is Transfer."""
    if nonce is None:
        raise CertificationError(
            f"ix{k} is a System instruction and no durable nonce is configured. System's own "
            f"variant 2 is a plain SOL transfer from the fee payer, so allowing the program "
            f"without a reason to expect it hands away the signer's lamports"
        )
    if ix["data"] != SYS_ADVANCE_NONCE:
        raise CertificationError(
            f"ix{k} is a System instruction that is not AdvanceNonceAccount "
            f"(tag {int.from_bytes(ix['data'][:4], 'little') if len(ix['data']) >= 4 else '?'})"
        )
    if not ix["accounts"] or ix["accounts"][0] != nonce:
        raise CertificationError(
            f"ix{k} advances a nonce account that is not the configured one"
        )


def _check_compute_budget(
    ix: dict, k: int, max_priority_lamports: int, state: dict
) -> None:
    if not ix["data"]:
        raise CertificationError(f"ix{k} is an empty ComputeBudget instruction")
    tag = ix["data"][0]
    if tag == CB_SET_UNIT_LIMIT and len(ix["data"]) == 5:
        state["limit"] = int.from_bytes(ix["data"][1:5], "little")
    elif tag == CB_SET_UNIT_PRICE and len(ix["data"]) == 9:
        state["price"] = int.from_bytes(ix["data"][1:9], "little")
    else:
        raise CertificationError(
            f"ix{k} is a ComputeBudget instruction this gate does not understand (tag {tag}); "
            f"only SetComputeUnitLimit and SetComputeUnitPrice are permitted"
        )
    fee = state["limit"] * state["price"] // 1_000_000
    if fee > max_priority_lamports:
        raise CertificationError(
            f"the priority fee would be {fee} lamports, over the {max_priority_lamports} "
            f"ceiling; an unbounded unit price burns the signer's SOL under a permitted program"
        )


def certify_x402_payment_tx(
    raw_tx: bytes,
    expected_receiver_b58: str | None = None,
    expected_mint_b58: str | None = None,
    *,
    expected_delegation_b58: str | None = None,
    expected_receiver_ata_b58: str | None = None,
    expected_delegator_b58: str | None = None,
    token_program_b58: str = TOKEN_PROGRAM_B58,
    max_amount_base_units: int | None = None,
    max_priority_lamports: int = DEFAULT_MAX_PRIORITY_LAMPORTS,
    expected_memo: bytes | None = None,
    nonce_b58: str | None = None,
) -> dict:
    """Verify raw_tx expresses ONLY the configured x402 payment. Raise otherwise.

    Every expected value MUST come from jailed operator config. Passing anything parsed out of
    the 402 challenge defeats the entire check, because the challenge is written by the party
    being paid.

    `expected_delegation_b58` names WHICH pool funds the purchase, and it is required for the
    same reason the payee is: the delegation's on-chain cap bounds one pool, so a transaction
    naming a different delegation the host also holds is within ITS cap and drains a budget the
    operator never allocated to this.

    Give the receiver as a WALLET; its ATA is derived here, and a wallet is what an operator can
    read back and recognise. `expected_receiver_ata_b58` skips the derivation, never the check.
    """
    if not expected_mint_b58:
        raise CertificationError(
            "mint is required and must come from operator config, never from the challenge"
        )
    if not expected_delegation_b58:
        raise CertificationError(
            "the funding delegation is required and must come from operator config; without it "
            "a transaction may spend a different pool of the operator's, within that pool's cap"
        )
    _ONE_RECEIVER = (
        "give exactly one of the receiver wallet or its token account, both from operator "
        "config; neither may come from the challenge"
    )
    if expected_receiver_b58 and expected_receiver_ata_b58:
        raise CertificationError(_ONE_RECEIVER)

    allowance = b58key(ALLOWANCE_PROGRAM_B58, "the allowances program")
    mint = b58key(expected_mint_b58, "mint")
    delegation = b58key(expected_delegation_b58, "delegation")
    token_prog = b58key(token_program_b58, "token program")
    memo_prog = b58key(MEMO_PROGRAM_B58, "the memo program")
    ata_prog = b58key(ATA_PROGRAM_B58, "the ATA program")
    compute_prog = b58key(COMPUTE_BUDGET_B58, "the compute-budget program")
    nonce = b58key(nonce_b58, "nonce") if nonce_b58 else None
    delegator = (
        b58key(expected_delegator_b58, "delegator") if expected_delegator_b58 else None
    )

    if expected_receiver_ata_b58:
        want_ata = b58key(expected_receiver_ata_b58, "receiver token account")
    elif expected_receiver_b58:
        want_ata = derive_ata(
            b58key(expected_receiver_b58, "receiver"), mint, token_prog
        )
    else:
        raise CertificationError(_ONE_RECEIVER)

    ixs = parse_message(message_of(raw_tx))["instructions"]
    if not ixs:
        raise CertificationError("the transaction carries no instructions")

    # Every permitted program's DATA is constrained. Naming a program safe says nothing about
    # what it is being asked to do, which is how an appended SOL transfer certifies cleanly.
    cb_state = {"limit": DEFAULT_UNIT_LIMIT, "price": 0}
    for k, ix in enumerate(ixs):
        prog = ix["program"]
        if prog == allowance:
            continue
        if prog == SYSTEM_PROGRAM:
            _check_system(ix, k, nonce)
        elif prog == compute_prog:
            _check_compute_budget(ix, k, max_priority_lamports, cb_state)
        elif prog == ata_prog:
            if not ix["data"] or ix["data"][0] != IX_CREATE_IDEMPOTENT:
                raise CertificationError(
                    f"ix{k} is an ATA instruction that is not CreateIdempotent"
                )
            if len(ix["accounts"]) < 4 or ix["accounts"][1] != want_ata:
                raise CertificationError(
                    f"ix{k} creates a token account that is not the configured receiver's"
                )
            if ix["accounts"][3] != mint:
                raise CertificationError(
                    f"ix{k} creates a token account for the wrong mint"
                )
        elif prog == memo_prog:
            continue  # contents are checked once, below, against the configured nonce
        else:
            who = b58encode(prog)
            hint = ""
            if prog in (
                b58decode(TOKEN_PROGRAM_B58),
                b58decode(TOKEN_2022_PROGRAM_B58),
            ):
                hint = " (a DIRECT token transfer, bypassing the delegation entirely)"
            raise CertificationError(f"ix{k} invokes an unexpected program {who}{hint}")

    spends = [i for i in ixs if i["program"] == allowance]
    if len(spends) != 1:
        raise CertificationError(
            f"expected exactly ONE delegated-spend instruction, got {len(spends)}; two spends "
            f"inside one cap is the shape that drains a delegation"
        )
    spend = spends[0]
    data = spend["data"]

    if not data:
        raise CertificationError("the spend instruction carries no data")
    if data[0] == IX_TRANSFER_RECURRING:
        raise CertificationError(
            "this is transferRecurring, not transferFixed; a one-shot purchase must not pull "
            "against a recurring delegation"
        )
    if data[0] != IX_TRANSFER_FIXED:
        raise CertificationError(
            f"unexpected instruction discriminator {data[0]}, expected {IX_TRANSFER_FIXED} "
            f"(transferFixed)"
        )
    if len(data) != TRANSFER_DATA_LEN:
        raise CertificationError(
            f"transferFixed data is {len(data)} bytes, expected {TRANSFER_DATA_LEN}"
        )
    if len(spend["accounts"]) != len(ACCT_NAMES):
        raise CertificationError(
            f"transferFixed takes {len(ACCT_NAMES)} accounts, got {len(spend['accounts'])}"
        )

    def at(i: int) -> bytes:
        return spend["accounts"][i]

    # WHERE THE MONEY GOES. Positional, because the destination is a token account and the
    # receiver wallet is nowhere in these bytes.
    if at(A_RECEIVER_ATA) != want_ata:
        raise CertificationError(
            f"the credited account is {b58encode(at(A_RECEIVER_ATA))}, not the configured "
            f"receiver's {b58encode(want_ata)}. A 402 challenge is written by the seller, so a "
            f"redirected payee is the attack this refuses, and it passes every amount check"
        )
    # WHERE THE MONEY COMES FROM. The on-chain cap bounds ONE pool, so an unpinned delegation
    # means a transaction can be within a cap the operator never allocated to this purchase.
    if at(A_DELEGATION) != delegation:
        raise CertificationError(
            f"the spend draws on delegation {b58encode(at(A_DELEGATION))}, not the configured "
            f"{expected_delegation_b58}; its cap bounds a budget meant for something else"
        )
    if at(A_TOKEN_MINT) != mint:
        raise CertificationError(
            f"the spend moves {b58encode(at(A_TOKEN_MINT))}, not the configured {expected_mint_b58}"
        )
    if at(A_TOKEN_PROGRAM) != token_prog:
        raise CertificationError(
            f"the spend uses token program {b58encode(at(A_TOKEN_PROGRAM))}, not the configured "
            f"{token_program_b58}"
        )
    if at(A_SUBSCRIPTIONS_PROGRAM) != allowance:
        raise CertificationError(
            "the trailing program account is not the audited allowances program"
        )
    # The mint appears twice: as an account, and inside the payload the program cross-checks
    # against the delegation. Re-deriving both is free and catches a mismatched pair.
    if data[DATA_MINT_SLICE] != mint:
        raise CertificationError(
            f"the payload's mint is {b58encode(data[DATA_MINT_SLICE])}, not the configured "
            f"{expected_mint_b58}"
        )
    if delegator is not None:
        if data[DATA_DELEGATOR_SLICE] != delegator:
            raise CertificationError(
                f"the payload debits {b58encode(data[DATA_DELEGATOR_SLICE])}, not the configured "
                f"delegator {expected_delegator_b58}"
            )
        if at(A_DELEGATOR_ATA) != derive_ata(delegator, mint, token_prog):
            raise CertificationError(
                "the debited token account is not the configured delegator's"
            )

    # Flags are part of what executes. Without them "re-derives intent from the bytes" is false
    # for every authority in the instruction.
    if not spend["signer"][A_DELEGATEE]:
        raise CertificationError("the delegatee slot is not marked as a signer")
    for slot in (A_DELEGATION, A_DELEGATOR_ATA, A_RECEIVER_ATA):
        if not spend["writable"][slot]:
            raise CertificationError(f"{ACCT_NAMES[slot]} is not marked writable")

    amount = int.from_bytes(data[DATA_AMOUNT_SLICE], "little")
    if max_amount_base_units is not None and amount > max_amount_base_units:
        raise CertificationError(
            f"amount {amount} exceeds the configured local ceiling {max_amount_base_units}; the "
            f"on-chain cap is the authority, this is the second layer that refuses before a "
            f"signature is spent"
        )

    if nonce is not None and not any(i["program"] == SYSTEM_PROGRAM for i in ixs):
        raise CertificationError("expected a durable-nonce advance and found none")

    memos = [i for i in ixs if i["program"] == memo_prog]
    if expected_memo is None:
        if memos:
            raise CertificationError(
                f"{len(memos)} memo(s) present but none is configured; a memo this gate cannot "
                f"check is content the seller chose"
            )
    else:
        # Absence and multiplicity are separate raises rather than one, so that neutering the
        # count check produces a refusal a case can catch instead of an IndexError on memos[0].
        if not memos:
            raise CertificationError(
                "expected a memo carrying the challenge nonce and found none; without it the "
                "seller cannot bind this payment to one challenge"
            )
        if len(memos) != 1:
            raise CertificationError(
                f"expected exactly one memo, found {len(memos)}; a second memo is content the "
                f"seller chose and this gate cannot tell which one a reader will believe"
            )
        if memos[0]["data"] != expected_memo:
            raise CertificationError(
                "the memo is not exactly the expected single-use nonce, so this payment could "
                "be replayed against a different challenge or carry seller-chosen content"
            )

    return {
        "certified": True,
        "instructions": len(ixs),
        "amount_base_units": amount,
        "receiver_token_account": b58encode(want_ata),
        "delegation": expected_delegation_b58,
        "mint": expected_mint_b58,
        "priority_fee_lamports": cb_state["limit"] * cb_state["price"] // 1_000_000,
        "intent": "allowance:transferFixed -> configured receiver's token account",
    }


# ---------------------------------------------------------------------------
# Self-test.
#
# The good case is a REAL MAINNET TRANSACTION, not a fixture, and every refusal case is that
# same transaction with one field moved. A hand-built good case would only prove this file's
# parser agrees with this file's builder.
# ---------------------------------------------------------------------------

REAL = (
    Path(__file__).resolve().parent.parent
    / "docs/proof-bundle/mainnet-transactions.json"
)
USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
# The delegator of the captured mainnet transfers, published throughout this repo as the
# merchant address. Its ATA is account 2, which is what calibrates the derivation below.
MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
REAL_DELEGATION = "HVVeimGq8VD4CuBgrvqWsgQV1GRVhfVNYQxJxTocUNY9"
REAL_RECEIVER_ATA = "98LLx6QvLcspjhCgRZa16TkCPBHSgDmvkqwyRtnb7d2o"
REAL_DELEGATOR_ATA = "EpzuUPXwMR2oWqL3MCUTjvvpfdrZXforkMt85ZCSowo3"
REAL_NONCE = "6Zwppsr7ZFVinp4rFYcqjXKQ1jsvXpzFPFVVLpxLZUKm"


def _load_real() -> dict[str, bytes]:
    """The captured mainnet transfers, keyed by whether the chain accepted them."""
    doc = json.loads(REAL.read_text(encoding="utf-8"))
    out = {}
    for v in doc["transactions"].values():
        raw = base64.b64decode(v["raw_base64"])
        try:
            ix = parse_message(message_of(raw))["instructions"][0]
        except CertificationError:
            continue
        if ix["program"] != b58decode(ALLOWANCE_PROGRAM_B58):
            continue
        if not ix["data"] or ix["data"][0] != IX_TRANSFER_FIXED:
            continue
        out["over_cap" if v["err"] else "within_cap"] = raw
    return out


def _shortvec(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _rebuild(
    raw: bytes, mutate, *, as_v0: bool = False, lookups: bytes | None = None
) -> bytes:
    """Re-serialize a real transaction after mutating its parsed instruction list.

    The real account values, flags and payload survive; only the field under test moves. That is
    how a negative case inherits real bytes instead of replacing them. `as_v0` re-emits the same
    body in the wire format the allowance plugin actually produces.
    """
    msg = message_of(raw)
    p = parse_message(msg)
    ixs = mutate([dict(i) for i in p["instructions"]])
    v0 = as_v0 or p["versioned"]
    head = msg[1:4] if p["versioned"] else msg[:3]
    n_req_sig, n_ro_signed = head[0], head[1]

    # Rebuild the key table so the header's signer and writable partition still describes it:
    # writable signers, readonly signers, writable non-signers, readonly non-signers.
    buckets: list[list[bytes]] = [[], [], [], []]
    for ix in ixs:
        for a, s, w in zip(ix["accounts"], ix["signer"], ix["writable"]):
            b = (0 if w else 1) if s else (2 if w else 3)
            if not any(a in bk for bk in buckets):
                buckets[b].append(a)
        if not any(ix["program"] in bk for bk in buckets):
            buckets[3].append(ix["program"])
    keys = [k for bk in buckets for k in bk]
    n_req_sig = len(buckets[0]) + len(buckets[1])
    n_ro_signed = len(buckets[1])
    n_ro_unsigned = len(buckets[3])

    body = bytearray()
    for ix in ixs:
        body.append(keys.index(ix["program"]))
        body += _shortvec(len(ix["accounts"]))
        body += bytes(keys.index(a) for a in ix["accounts"])
        body += _shortvec(len(ix["data"]))
        body += ix["data"]

    out = bytearray()
    if v0:
        out.append(0x80)
    out += bytes([n_req_sig, n_ro_signed, n_ro_unsigned])
    out += _shortvec(len(keys))
    for k in keys:
        out += k
    out += bytes(32)
    out += _shortvec(len(ixs))
    out += body
    if v0:
        out += lookups if lookups is not None else _shortvec(0)
    return bytes([1]) + bytes(64) + bytes(out)


def _self_test() -> int:  # noqa: PLR0915 - a flat list of cases reads better than nested helpers
    passed = failed = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal passed, failed
        print(
            f"{'PASS' if ok else 'FAIL'}  {name}"
            + (f"  ({detail[:96]})" if detail else "")
        )
        if ok:
            passed += 1
        else:
            failed += 1

    # Calibration of the address derivation against real on-chain data. Without this the
    # positional check below is only as good as an unproven hash.
    got = b58encode(
        derive_ata(
            b58decode(MERCHANT), b58decode(USDC_MAINNET), b58decode(TOKEN_PROGRAM_B58)
        )
    )
    check(
        "ATA derivation reproduces a real on-chain token account",
        got == REAL_DELEGATOR_ATA,
        f"{got} vs {REAL_DELEGATOR_ATA}",
    )
    other = b58encode(
        derive_ata(
            b58decode(REAL_RECEIVER_ATA),
            b58decode(USDC_MAINNET),
            b58decode(TOKEN_PROGRAM_B58),
        )
    )
    check(
        "a different wallet derives a different token account",
        other != REAL_DELEGATOR_ATA,
    )

    real = _load_real()
    check(
        "the captured mainnet transfers are readable", len(real) == 2, f"{sorted(real)}"
    )
    if len(real) != 2:
        print(f"\nRESULT: {passed} passed, {failed} failed, {passed + failed} total")
        return 1

    cfg = {
        "expected_receiver_ata_b58": REAL_RECEIVER_ATA,
        "expected_delegation_b58": REAL_DELEGATION,
    }

    def run(tx, **kw):
        return certify_x402_payment_tx(
            tx, expected_mint_b58=USDC_MAINNET, **{**cfg, **kw}
        )

    def refuses(name, tx, **kw):
        try:
            run(tx, **kw)
            check(name, False, "certified")
        except CertificationError as e:
            check(name, True, f"refused: {e}")

    def certifies(name, tx, **kw):
        try:
            r = run(tx, **kw)
            check(
                name,
                True,
                f"{r['amount_base_units']} base units, {r['instructions']} ix",
            )
            return r
        except CertificationError as e:
            check(name, False, str(e))
            return None

    # ---- the good cases, on real bytes, in both wire formats
    r = certifies("the real within-cap mainnet transfer certifies", real["within_cap"])
    check(
        "  and reports the real amount",
        bool(r) and r["amount_base_units"] == 400000,
        f"{r['amount_base_units'] if r else '-'}",
    )
    certifies(
        "the same transfer re-emitted as v0, which is what the plugin produces",
        _rebuild(real["within_cap"], lambda i: i, as_v0=True),
    )

    # The WALLET form, end to end through the derivation rather than the escape hatch. Slot 3 is
    # moved to the merchant's own token account so a known wallet derives it.
    def to_merchant(ixs):
        ixs[0]["accounts"] = [
            b58decode(REAL_DELEGATOR_ATA) if n == A_RECEIVER_ATA else a
            for n, a in enumerate(ixs[0]["accounts"])
        ]
        return ixs

    try:
        certify_x402_payment_tx(
            _rebuild(real["within_cap"], to_merchant),
            MERCHANT,
            USDC_MAINNET,
            expected_delegation_b58=REAL_DELEGATION,
        )
        check("the WALLET form certifies end to end through the derivation", True)
    except CertificationError as e:
        check(
            "the WALLET form certifies end to end through the derivation", False, str(e)
        )

    # The chain's own refusal is a STRUCTURALLY VALID payment. Certifying it is correct: this
    # file checks intent, and the cap is the on-chain program's job rather than its own.
    r = certifies(
        "the real over-cap transfer also certifies, because intent is not amount",
        real["over_cap"],
    )
    check(
        "  and the chain is what refused it, at 0x12c",
        bool(r) and r["amount_base_units"] == 1000000,
    )
    refuses(
        "a local ceiling refuses the over-cap transfer before signing",
        real["over_cap"],
        max_amount_base_units=400000,
    )

    # ---- where the money goes
    def redirect(ixs):
        ixs[0]["accounts"] = [
            b58decode(REAL_DELEGATOR_ATA) if n == A_RECEIVER_ATA else a
            for n, a in enumerate(ixs[0]["accounts"])
        ]
        return ixs

    refuses("a REDIRECTED payee is refused", _rebuild(real["within_cap"], redirect))
    refuses(
        "certifying against a different configured receiver is refused",
        real["within_cap"],
        expected_receiver_ata_b58=REAL_DELEGATOR_ATA,
    )
    refuses(
        "the WALLET form refuses a wallet whose token account is not the credited one",
        real["within_cap"],
        expected_receiver_b58=MERCHANT,
        expected_receiver_ata_b58=None,
    )

    def swap_slot(slot, value):
        def f(ixs):
            ixs[0]["accounts"] = [
                b58decode(value) if n == slot else a
                for n, a in enumerate(ixs[0]["accounts"])
            ]
            return ixs

        return f

    # ---- where the money comes from
    refuses(
        "a spend against a DIFFERENT delegation is refused",
        real["within_cap"],
        expected_delegation_b58=REAL_RECEIVER_ATA,
    )
    refuses(
        "a payload debiting a different delegator is refused",
        real["within_cap"],
        expected_delegator_b58=REAL_RECEIVER_ATA,
    )
    try:
        run(real["within_cap"], expected_delegator_b58=MERCHANT)
        check("the real delegator passes the optional debit check", True)
    except CertificationError as e:
        check("the real delegator passes the optional debit check", False, str(e))

    # The payload's delegator and the debited token account are two claims about the same party,
    # and a transaction can make them disagree. Each case below is caught by exactly ONE of the
    # two checks, which is what proves they are not one check written twice.
    def payload_delegator(who):
        def f(ixs):
            d = bytearray(ixs[0]["data"])
            d[DATA_DELEGATOR_SLICE] = b58decode(who)
            ixs[0]["data"] = bytes(d)
            return ixs

        return f

    refuses(
        "a payload naming another delegator, while the debited account still looks right",
        _rebuild(real["within_cap"], payload_delegator(REAL_RECEIVER_ATA)),
        expected_delegator_b58=MERCHANT,
    )
    refuses(
        "a debited account that is not the payload delegator's is refused",
        _rebuild(real["within_cap"], swap_slot(A_DELEGATOR_ATA, REAL_RECEIVER_ATA)),
        expected_delegator_b58=MERCHANT,
    )

    # ---- what is being moved
    refuses(
        "a swapped mint account is refused",
        _rebuild(real["within_cap"], swap_slot(A_TOKEN_MINT, TOKEN_2022_PROGRAM_B58)),
    )
    refuses(
        "a swapped token program is refused",
        _rebuild(
            real["within_cap"], swap_slot(A_TOKEN_PROGRAM, TOKEN_2022_PROGRAM_B58)
        ),
    )
    refuses(
        "a swapped trailing self-CPI program is refused",
        _rebuild(
            real["within_cap"],
            swap_slot(A_SUBSCRIPTIONS_PROGRAM, TOKEN_2022_PROGRAM_B58),
        ),
    )

    def swap_payload_mint(ixs):
        d = bytearray(ixs[0]["data"])
        d[DATA_MINT_SLICE] = b58decode(TOKEN_2022_PROGRAM_B58)
        ixs[0]["data"] = bytes(d)
        return ixs

    refuses(
        "a swapped mint inside the payload is refused",
        _rebuild(real["within_cap"], swap_payload_mint),
    )

    # ---- what kind of spend it is
    def set_disc(v):
        def f(ixs):
            ixs[0]["data"] = bytes([v]) + ixs[0]["data"][1:]
            return ixs

        return f

    refuses(
        "a recurring pull is refused",
        _rebuild(real["within_cap"], set_disc(IX_TRANSFER_RECURRING)),
    )
    refuses(
        "an unknown discriminator is refused", _rebuild(real["within_cap"], set_disc(9))
    )
    refuses(
        "a truncated payload is refused",
        _rebuild(real["within_cap"], lambda i: [{**i[0], "data": i[0]["data"][:40]}]),
    )

    # A payload with a trailing byte: every slice this gate reads is still correct, so only the
    # length check can catch it. Without this case the length check and the mint check are one.
    refuses(
        "a payload with a trailing byte is refused",
        _rebuild(
            real["within_cap"], lambda i: [{**i[0], "data": i[0]["data"] + b"\x00"}]
        ),
    )

    def pad_accounts(ixs):
        extra = b58decode(REAL_NONCE)
        ixs[0]["accounts"] = ixs[0]["accounts"] + [extra]
        ixs[0]["signer"] = ixs[0]["signer"] + [False]
        ixs[0]["writable"] = ixs[0]["writable"] + [False]
        return ixs

    # A LONG account list, so the count check is exercised by a case rather than only by the
    # out-of-range read its absence would cause on a short one.
    refuses(
        "an extra trailing account is refused",
        _rebuild(real["within_cap"], pad_accounts),
    )
    refuses(
        "a short account list is refused before any slot is read",
        _rebuild(
            real["within_cap"],
            lambda i: [
                {
                    **i[0],
                    "accounts": i[0]["accounts"][:-1],
                    "signer": i[0]["signer"][:-1],
                    "writable": i[0]["writable"][:-1],
                }
            ],
        ),
    )

    # ---- how many, and what else rides along
    refuses(
        "a SECOND delegated spend is refused",
        _rebuild(real["within_cap"], lambda i: i + [dict(i[0])]),
    )

    def append(program_b58, data, accounts=(), signer=(), writable=()):
        prog = b58decode(program_b58) if isinstance(program_b58, str) else program_b58

        def f(ixs):
            return ixs + [
                {
                    "program": prog,
                    "accounts": list(accounts),
                    "signer": list(signer) or [False] * len(accounts),
                    "writable": list(writable) or [False] * len(accounts),
                    "data": data,
                }
            ]

        return f

    refuses(
        "a direct SPL transfer appended is refused",
        _rebuild(
            real["within_cap"],
            append(TOKEN_PROGRAM_B58, b"\x03", [b58decode(REAL_DELEGATOR_ATA)]),
        ),
    )
    refuses(
        "an unknown program appended is refused",
        _rebuild(real["within_cap"], append(bytes([7]) * 32, b"\x00")),
    )
    # THE FINDING AN ADVERSARIAL REVIEW OF THE FIRST DRAFT PRODUCED. System was allowlisted for
    # the nonce advance, and System variant 2 is a plain SOL transfer from the fee payer.
    sol_transfer = (2).to_bytes(4, "little") + (1_000_000_000).to_bytes(8, "little")
    refuses(
        "an appended plain SOL TRANSFER under the allowlisted System program is refused",
        _rebuild(
            real["within_cap"],
            append(
                SYSTEM_PROGRAM,
                sol_transfer,
                [b58decode(MERCHANT), b58decode(REAL_RECEIVER_ATA)],
            ),
        ),
    )
    refuses(
        "a System instruction with no nonce configured is refused even if it IS an advance",
        _rebuild(
            real["within_cap"],
            append(SYSTEM_PROGRAM, SYS_ADVANCE_NONCE, [b58decode(REAL_NONCE)]),
        ),
    )
    certifies(
        "a real nonce advance certifies when that nonce is configured",
        _rebuild(
            real["within_cap"],
            append(SYSTEM_PROGRAM, SYS_ADVANCE_NONCE, [b58decode(REAL_NONCE)]),
        ),
        nonce_b58=REAL_NONCE,
    )
    refuses(
        "a nonce advance on a DIFFERENT account is refused",
        _rebuild(
            real["within_cap"],
            append(SYSTEM_PROGRAM, SYS_ADVANCE_NONCE, [b58decode(REAL_RECEIVER_ATA)]),
        ),
        nonce_b58=REAL_NONCE,
    )
    refuses(
        "a configured nonce with no advance present is refused",
        real["within_cap"],
        nonce_b58=REAL_NONCE,
    )
    # The same shape one program over: ComputeBudget was allowlisted for a priority fee.
    huge_price = bytes([CB_SET_UNIT_PRICE]) + (10**12).to_bytes(8, "little")
    refuses(
        "an unbounded priority fee under the allowlisted ComputeBudget program is refused",
        _rebuild(real["within_cap"], append(COMPUTE_BUDGET_B58, huge_price)),
    )
    certifies(
        "a modest priority fee certifies",
        _rebuild(
            real["within_cap"],
            append(
                COMPUTE_BUDGET_B58,
                bytes([CB_SET_UNIT_PRICE]) + (1000).to_bytes(8, "little"),
            ),
        ),
    )
    refuses(
        "a ComputeBudget instruction this gate does not understand is refused",
        _rebuild(
            real["within_cap"], append(COMPUTE_BUDGET_B58, bytes([1]) + b"\x00" * 4)
        ),
    )
    # Same shape as the SOL transfer, but pointed AT the configured nonce account, so only the
    # data check can catch it. Without this case that check and the identity check are one.
    refuses(
        "a System instruction on the RIGHT nonce account with the wrong data is refused",
        _rebuild(
            real["within_cap"],
            append(
                SYSTEM_PROGRAM,
                sol_transfer,
                [b58decode(REAL_NONCE), b58decode(MERCHANT)],
            ),
        ),
        nonce_b58=REAL_NONCE,
    )

    # ---- the idempotent create a receiver's first payment needs
    def ata_create(target_ata, mint_b58, disc=IX_CREATE_IDEMPOTENT):
        return append(
            ATA_PROGRAM_B58,
            bytes([disc]),
            [
                b58decode(MERCHANT),
                b58decode(target_ata),
                b58decode(MERCHANT),
                b58decode(mint_b58),
            ],
        )

    certifies(
        "an idempotent create for the configured receiver certifies",
        _rebuild(real["within_cap"], ata_create(REAL_RECEIVER_ATA, USDC_MAINNET)),
    )
    refuses(
        "an ATA instruction that is not CreateIdempotent is refused",
        _rebuild(
            real["within_cap"], ata_create(REAL_RECEIVER_ATA, USDC_MAINNET, disc=0)
        ),
    )
    refuses(
        "creating a token account that is not the configured receiver's is refused",
        _rebuild(real["within_cap"], ata_create(REAL_DELEGATOR_ATA, USDC_MAINNET)),
    )
    refuses(
        "creating the receiver's account for the wrong mint is refused",
        _rebuild(
            real["within_cap"], ata_create(REAL_RECEIVER_ATA, TOKEN_2022_PROGRAM_B58)
        ),
    )

    # ---- flags are part of what executes
    def unsign_delegatee(ixs):
        ixs[0]["signer"] = [
            False if n == A_DELEGATEE else s for n, s in enumerate(ixs[0]["signer"])
        ]
        return ixs

    refuses(
        "a delegatee slot not marked as a signer is refused",
        _rebuild(real["within_cap"], unsign_delegatee),
    )

    def unwrite_receiver(ixs):
        ixs[0]["writable"] = [
            False if n == A_RECEIVER_ATA else w
            for n, w in enumerate(ixs[0]["writable"])
        ]
        return ixs

    refuses(
        "a credited account not marked writable is refused",
        _rebuild(real["within_cap"], unwrite_receiver),
    )

    # ---- the memo binds the payment to one challenge
    refuses(
        "a missing challenge-nonce memo is refused",
        real["within_cap"],
        expected_memo=b"x402-nonce-0001",
    )
    certifies(
        "the exact challenge-nonce memo certifies",
        _rebuild(real["within_cap"], append(MEMO_PROGRAM_B58, b"x402-nonce-0001")),
        expected_memo=b"x402-nonce-0001",
    )
    refuses(
        "a memo that merely CONTAINS the nonce is refused",
        _rebuild(
            real["within_cap"],
            append(MEMO_PROGRAM_B58, b"x402-nonce-0001 plus seller text"),
        ),
        expected_memo=b"x402-nonce-0001",
    )
    refuses(
        "a second memo is refused",
        _rebuild(
            _rebuild(real["within_cap"], append(MEMO_PROGRAM_B58, b"x402-nonce-0001")),
            append(MEMO_PROGRAM_B58, b"x402-nonce-0001"),
        ),
        expected_memo=b"x402-nonce-0001",
    )
    refuses(
        "an unconfigured memo is refused, because its content is the seller's",
        _rebuild(real["within_cap"], append(MEMO_PROGRAM_B58, b"anything at all")),
    )

    # ---- the parser refuses what it cannot read exactly
    good = real["within_cap"]
    refuses("trailing bytes after the message are refused", good + b"\x00")
    refuses(
        "a v0 message carrying address-table lookups is refused",
        _rebuild(
            good,
            lambda i: i,
            as_v0=True,
            lookups=_shortvec(1) + bytes(32) + b"\x00\x00",
        ),
    )
    msg = message_of(good)
    refuses(
        "an unsupported message version is refused",
        bytes([1]) + bytes(64) + b"\x81" + msg[1:],
    )
    refuses("a truncated message is refused", bytes([1]) + bytes(64) + msg[:20])
    # Byte surgery rather than _rebuild, which re-indexes and so cannot express this. The offset
    # is computed from the parsed key count, and the byte at it is asserted to be a valid index
    # first, so a wrong offset fails loudly instead of quietly testing an unchanged message.
    n_keys = len(parse_message(msg)["keys"])
    first_acct_idx = 3 + 1 + n_keys * 32 + 32 + 1 + 1 + 1
    check(
        "  the index offset was located, so the next case is not a no-op",
        msg[first_acct_idx] < n_keys,
        f"byte at {first_acct_idx} is {msg[first_acct_idx]}, against {n_keys} keys",
    )
    bad = bytearray(msg)
    bad[first_acct_idx] = n_keys
    refuses(
        "an out-of-range account index is refused", bytes([1]) + bytes(64) + bytes(bad)
    )

    # ---- config is required, and cannot be borrowed from the challenge
    def refuses_config(name: str, call) -> None:
        try:
            call()
            check(name, False, "certified")
        except CertificationError as e:
            check(name, True, f"refused: {e}")

    refuses_config(
        "an absent receiver is refused outright",
        lambda: certify_x402_payment_tx(
            good, None, USDC_MAINNET, expected_delegation_b58=REAL_DELEGATION
        ),
    )
    refuses_config(
        "supplying BOTH receiver forms is refused",
        lambda: certify_x402_payment_tx(
            good,
            MERCHANT,
            USDC_MAINNET,
            expected_delegation_b58=REAL_DELEGATION,
            expected_receiver_ata_b58=REAL_RECEIVER_ATA,
        ),
    )
    refuses_config(
        "an absent mint is refused outright",
        lambda: certify_x402_payment_tx(good, None, None, **cfg),
    )
    refuses_config(
        "an absent delegation is refused outright",
        lambda: certify_x402_payment_tx(
            good, None, USDC_MAINNET, expected_receiver_ata_b58=REAL_RECEIVER_ATA
        ),
    )
    refuses_config(
        "a configured value that is not a 32-byte address is refused",
        lambda: certify_x402_payment_tx(good, None, "abc", **cfg),
    )

    print(f"\nRESULT: {passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(_self_test())
