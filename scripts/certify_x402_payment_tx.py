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

The only defence is that the receiver and mint come from JAILED OPERATOR CONFIG and are checked
against these bytes, never taken from the challenge. That is why the expected receiver is a
required argument here rather than something this file parses out of anything.

THE CHECK IS POSITIONAL, AND THAT DISTINCTION IS THE WHOLE FILE. Asking whether the configured
receiver appears ANYWHERE in the instruction's account list is wrong twice over, and the second
way is worse than the first. It is too weak, because a hostile transaction can list the honest
receiver in some unrelated slot. And it looks for a key that is NEVER PRESENT: the program debits
and credits ASSOCIATED TOKEN ACCOUNTS, so the destination is `ATA(receiver, mint)` and the
receiver WALLET does not appear in the transaction at all. A membership check would refuse every
legitimate payment against real on-chain bytes while passing hand-built fixtures, which is why
the good case in the self-test below is a captured mainnet transaction rather than a fixture.

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

# data = [disc:u8][amount:u64 LE][delegator:32][mint:32]
TRANSFER_DATA_LEN = 1 + 8 + 32 + 32
DATA_MINT_SLICE = slice(41, 73)

# accounts, in order. Source: allowance.rs transfer instruction builder, CONFIRMED against the
# real mainnet transfer 5sHLcD1v.. in docs/proof-bundle/mainnet-transactions.json.
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
A_RECEIVER_ATA = 3
A_TOKEN_MINT = 4
A_TOKEN_PROGRAM = 5
A_SUBSCRIPTIONS_PROGRAM = 8

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_PDA_MARKER = b"ProgramDerivedAddress"


class CertificationError(Exception):
    """Raised when the serialized tx does not match the configured payment intent."""


# ---------------------------------------------------------------------------
# Encoding and address derivation
# ---------------------------------------------------------------------------


def b58decode(s: str) -> bytes:
    num = 0
    for c in s:
        num = num * 58 + _B58.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def b58encode(b: bytes) -> str:
    num = int.from_bytes(b, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def _on_curve(b: bytes) -> bool:
    """True if the 32 bytes decompress to an ed25519 point, so NOT a valid PDA."""
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= _P:
        return False
    yy = y * y % _P
    u = (yy - 1) % _P
    v = (_D * yy + 1) % _P
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
    val = 0
    shift = 0
    while True:
        c = b[i]
        i += 1
        val |= (c & 0x7F) << shift
        if not c & 0x80:
            return val, i
        shift += 7


def parse_legacy_message(msg: bytes) -> dict:
    """Parse a legacy (non-versioned) transaction message into keys + instructions."""
    if msg and msg[0] & 0x80:
        raise CertificationError(
            f"this is a v{msg[0] & 0x7F} message, not a legacy one; the allowance builder "
            f"emits legacy messages, and address-table lookups would hide accounts from "
            f"every positional check below"
        )
    i = 3
    n_keys, i = _read_shortvec(msg, i)
    keys = [msg[i + k * 32 : i + (k + 1) * 32] for k in range(n_keys)]
    i += n_keys * 32
    i += 32  # recent blockhash
    n_ix, i = _read_shortvec(msg, i)
    ixs = []
    for _ in range(n_ix):
        prog_idx = msg[i]
        i += 1
        n_acct, i = _read_shortvec(msg, i)
        acct_idx = list(msg[i : i + n_acct])
        i += n_acct
        dlen, i = _read_shortvec(msg, i)
        data = msg[i : i + dlen]
        i += dlen
        ixs.append(
            {
                "program": keys[prog_idx],
                "accounts": [keys[a] for a in acct_idx],
                "data": data,
            }
        )
    return {"keys": keys, "instructions": ixs}


def message_of(raw_tx: bytes) -> bytes:
    """Strip the signature vector off a serialized transaction."""
    if not raw_tx:
        raise CertificationError("empty transaction")
    nsigs = raw_tx[0]
    if nsigs >= 0x80:
        raise CertificationError("multi-byte signature shortvec is unexpected here")
    return raw_tx[1 + nsigs * 64 :]


# ---------------------------------------------------------------------------
# The certification
# ---------------------------------------------------------------------------


def certify_x402_payment_tx(
    raw_tx: bytes,
    expected_receiver_b58: str | None = None,
    expected_mint_b58: str | None = None,
    *,
    expected_receiver_ata_b58: str | None = None,
    token_program_b58: str = TOKEN_PROGRAM_B58,
    max_amount_base_units: int | None = None,
    expected_memo: bytes | None = None,
    nonce_b58: str | None = None,
) -> dict:
    """Verify raw_tx expresses ONLY the configured x402 payment. Raise otherwise.

    The receiver and mint MUST come from jailed operator config. Passing values parsed out of
    the 402 challenge defeats the entire check, because the challenge is written by the party
    being paid.

    Give the receiver as a WALLET (`expected_receiver_b58`); its ATA is derived here, and a
    wallet is what an operator can read back and recognise. `expected_receiver_ata_b58` is the
    escape hatch for a destination that is not an ATA of the configured mint; it skips the
    derivation, never the check.
    """
    if not expected_mint_b58:
        raise CertificationError(
            "mint is required and must come from operator config, never from the challenge"
        )
    _ONE_RECEIVER = (
        "give exactly one of the receiver wallet or its token account, both from operator "
        "config; neither may come from the challenge"
    )
    if expected_receiver_b58 and expected_receiver_ata_b58:
        raise CertificationError(_ONE_RECEIVER)

    allowance = b58decode(ALLOWANCE_PROGRAM_B58)
    mint = b58decode(expected_mint_b58)
    token_prog = b58decode(token_program_b58)
    memo_prog = b58decode(MEMO_PROGRAM_B58)
    ata_prog = b58decode(ATA_PROGRAM_B58)
    compute_prog = b58decode(COMPUTE_BUDGET_B58)
    nonce = b58decode(nonce_b58) if nonce_b58 else None

    if expected_receiver_ata_b58:
        want_ata = b58decode(expected_receiver_ata_b58)
    elif expected_receiver_b58:
        want_ata = derive_ata(b58decode(expected_receiver_b58), mint, token_prog)
    else:
        raise CertificationError(_ONE_RECEIVER)

    ixs = parse_legacy_message(message_of(raw_tx))["instructions"]
    if not ixs:
        raise CertificationError("the transaction carries no instructions")

    allowed = {SYSTEM_PROGRAM, allowance, memo_prog, ata_prog, compute_prog}
    for k, ix in enumerate(ixs):
        if ix["program"] not in allowed:
            who = b58encode(ix["program"])
            hint = ""
            if ix["program"] in (
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

    # THE CHECK THIS FILE EXISTS FOR, and it is positional. The destination is a token
    # account, so the receiver WALLET is nowhere in these bytes.
    if at(A_RECEIVER_ATA) != want_ata:
        raise CertificationError(
            f"the credited account is {b58encode(at(A_RECEIVER_ATA))}, not the configured "
            f"receiver's {b58encode(want_ata)}. A 402 challenge is written by the seller, so a "
            f"redirected payee is the attack this refuses, and it passes every amount check"
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

    amount = int.from_bytes(data[1:9], "little")
    if max_amount_base_units is not None and amount > max_amount_base_units:
        raise CertificationError(
            f"amount {amount} exceeds the configured local ceiling {max_amount_base_units}; the "
            f"on-chain cap is the authority, this is the second layer that refuses before a "
            f"signature is spent"
        )

    # An idempotent create for the receiver's token account is legitimate on a first payment,
    # and its own accounts are checked rather than waved through.
    for k, ix in enumerate(ixs):
        if ix["program"] != ata_prog:
            continue
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

    if nonce is not None:
        adv = [i for i in ixs if i["program"] == SYSTEM_PROGRAM]
        if not adv:
            raise CertificationError("expected a durable-nonce advance and found none")
        if not any(nonce in i["accounts"] for i in adv):
            raise CertificationError(
                "no System instruction references our nonce account"
            )

    if expected_memo is not None:
        memos = [i for i in ixs if i["program"] == memo_prog]
        if not memos:
            raise CertificationError(
                "expected a memo carrying the challenge nonce, found none; without it the "
                "seller cannot bind this payment to one challenge"
            )
        if not any(expected_memo in i["data"] for i in memos):
            raise CertificationError(
                "the memo does not carry the expected single-use nonce, so this payment could "
                "be replayed against a different challenge"
            )

    return {
        "certified": True,
        "instructions": len(ixs),
        "amount_base_units": amount,
        "receiver_token_account": b58encode(want_ata),
        "mint": expected_mint_b58,
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
REAL_RECEIVER_ATA = "98LLx6QvLcspjhCgRZa16TkCPBHSgDmvkqwyRtnb7d2o"
REAL_DELEGATOR_ATA = "EpzuUPXwMR2oWqL3MCUTjvvpfdrZXforkMt85ZCSowo3"


def _load_real() -> dict[str, bytes]:
    """The captured mainnet transfers, keyed by whether the chain accepted them."""
    doc = json.loads(REAL.read_text(encoding="utf-8"))
    out = {}
    for v in doc["transactions"].values():
        raw = base64.b64decode(v["raw_base64"])
        try:
            ix = parse_legacy_message(message_of(raw))["instructions"][0]
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


def _rebuild(raw: bytes, mutate) -> bytes:
    """Re-serialize a real transaction after mutating its parsed instruction list.

    The real account values and the real payload survive; only the one field under test moves.
    This is how a negative case inherits real bytes instead of replacing them.
    """
    msg = message_of(raw)
    p = parse_legacy_message(msg)
    ixs = mutate([dict(i) for i in p["instructions"]])
    keys: list[bytes] = []

    def idx(k: bytes) -> int:
        if k not in keys:
            keys.append(k)
        return keys.index(k)

    body = bytearray()
    for ix in ixs:
        prog = idx(ix["program"])
        accts = [idx(a) for a in ix["accounts"]]
        body.append(prog)
        body += _shortvec(len(accts))
        body += bytes(accts)
        body += _shortvec(len(ix["data"]))
        body += ix["data"]
    out = bytearray(msg[:3])
    out += _shortvec(len(keys))
    for k in keys:
        out += k
    out += bytes(32)
    out += _shortvec(len(ixs))
    out += body
    return bytes([1]) + bytes(64) + bytes(out)


def _self_test() -> int:
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

    cfg = {"expected_receiver_ata_b58": REAL_RECEIVER_ATA}

    def run(tx, **kw):
        return certify_x402_payment_tx(tx, None, USDC_MAINNET, **{**cfg, **kw})

    def refuses(name, tx, **kw):
        try:
            run(tx, **kw)
            check(name, False, "certified")
        except CertificationError as e:
            check(name, True, f"refused: {e}")

    # The good case is real bytes the chain accepted.
    try:
        r = run(real["within_cap"])
        check(
            "the real within-cap mainnet transfer certifies",
            r["certified"] and r["amount_base_units"] == 400000,
            f"{r['amount_base_units']} base units",
        )
    except CertificationError as e:
        check("the real within-cap mainnet transfer certifies", False, str(e))

    # The chain's own refusal is a STRUCTURALLY VALID payment. Certifying it is correct: this
    # file checks intent, and the cap is the on-chain program's job rather than its own.
    try:
        r = run(real["over_cap"])
        check(
            "the real over-cap transfer also certifies, because intent is not amount",
            r["amount_base_units"] == 1000000,
            f"{r['amount_base_units']} base units, and the chain returned 0x12c",
        )
    except CertificationError as e:
        check("the real over-cap transfer also certifies", False, str(e))

    refuses(
        "a local ceiling refuses the over-cap transfer before signing",
        real["over_cap"],
        max_amount_base_units=400000,
    )

    # THE ATTACK. The same real transaction with one account swapped.
    def redirect(ixs):
        ixs[0]["accounts"] = [
            b58decode(REAL_DELEGATOR_ATA) if i == A_RECEIVER_ATA else a
            for i, a in enumerate(ixs[0]["accounts"])
        ]
        return ixs

    refuses("a REDIRECTED payee is refused", _rebuild(real["within_cap"], redirect))
    refuses(
        "certifying against a different configured receiver is refused",
        real["within_cap"],
        expected_receiver_ata_b58=REAL_DELEGATOR_ATA,
    )

    # A mint swap in the account slot only. The payload still carries the real mint, so this
    # also proves the two mint checks are not one check written twice.
    def swap_mint(ixs):
        ixs[0]["accounts"] = [
            b58decode(TOKEN_2022_PROGRAM_B58) if i == A_TOKEN_MINT else a
            for i, a in enumerate(ixs[0]["accounts"])
        ]
        return ixs

    refuses(
        "a swapped mint account is refused", _rebuild(real["within_cap"], swap_mint)
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

    def recurring(ixs):
        ixs[0]["data"] = bytes([IX_TRANSFER_RECURRING]) + ixs[0]["data"][1:]
        return ixs

    refuses("a recurring pull is refused", _rebuild(real["within_cap"], recurring))

    def swap_token_program(ixs):
        ixs[0]["accounts"] = [
            b58decode(TOKEN_2022_PROGRAM_B58) if i == A_TOKEN_PROGRAM else a
            for i, a in enumerate(ixs[0]["accounts"])
        ]
        return ixs

    refuses(
        "a swapped token program is refused",
        _rebuild(real["within_cap"], swap_token_program),
    )

    def drop_account(ixs):
        ixs[0]["accounts"] = ixs[0]["accounts"][:-1]
        return ixs

    refuses(
        "a short account list is refused before any slot is read",
        _rebuild(real["within_cap"], drop_account),
    )

    refuses(
        "a SECOND delegated spend is refused",
        _rebuild(real["within_cap"], lambda ixs: ixs + [dict(ixs[0])]),
    )

    def direct_transfer(ixs):
        return ixs + [
            {
                "program": b58decode(TOKEN_PROGRAM_B58),
                "accounts": [b58decode(REAL_DELEGATOR_ATA)],
                "data": b"\x03",
            }
        ]

    refuses(
        "a direct SPL transfer appended is refused",
        _rebuild(real["within_cap"], direct_transfer),
    )
    refuses(
        "an unknown program appended is refused",
        _rebuild(
            real["within_cap"],
            lambda ixs: ixs
            + [{"program": bytes([7]) * 32, "accounts": [], "data": b"\x00"}],
        ),
    )

    # The memo carries the challenge nonce. The captured transfers have none, which is exactly
    # why an x402 payment needs one: without it a payment binds to no challenge.
    refuses(
        "a missing challenge-nonce memo is refused",
        real["within_cap"],
        expected_memo=b"x402-nonce-0001",
    )

    def with_memo(nonce: bytes):
        def f(ixs):
            return ixs + [
                {"program": b58decode(MEMO_PROGRAM_B58), "accounts": [], "data": nonce}
            ]

        return f

    try:
        run(
            _rebuild(real["within_cap"], with_memo(b"x402-nonce-0001")),
            expected_memo=b"x402-nonce-0001",
        )
        check("the matching challenge-nonce memo certifies", True)
    except CertificationError as e:
        check("the matching challenge-nonce memo certifies", False, str(e))

    refuses(
        "a wrong challenge-nonce memo is refused",
        _rebuild(real["within_cap"], with_memo(b"x402-nonce-9999")),
        expected_memo=b"x402-nonce-0001",
    )

    # Config is required. A caller cannot quietly certify against whatever the challenge said.
    def refuses_config(name: str, call) -> None:
        try:
            call()
            check(name, False, "certified")
        except CertificationError as e:
            check(name, True, f"refused: {e}")

    refuses_config(
        "an absent receiver is refused outright",
        lambda: certify_x402_payment_tx(real["within_cap"], None, USDC_MAINNET),
    )
    refuses_config(
        "supplying BOTH receiver forms is refused",
        lambda: certify_x402_payment_tx(
            real["within_cap"],
            MERCHANT,
            USDC_MAINNET,
            expected_receiver_ata_b58=REAL_RECEIVER_ATA,
        ),
    )
    refuses_config(
        "an absent mint is refused outright",
        lambda: certify_x402_payment_tx(
            real["within_cap"], None, None, expected_receiver_ata_b58=REAL_RECEIVER_ATA
        ),
    )
    # The wallet form derives, so a wallet that is not the receiver must also be refused.
    refuses_config(
        "the WALLET form refuses a wallet whose token account is not the credited one",
        lambda: certify_x402_payment_tx(real["within_cap"], MERCHANT, USDC_MAINNET),
    )

    # A v0 message would hide accounts behind address-table lookups, defeating every positional
    # check above, so it is refused rather than parsed.
    refuses(
        "a versioned (v0) message is refused",
        bytes([1]) + bytes(64) + bytes([0x80]) + message_of(real["within_cap"])[1:],
    )

    print(f"\nRESULT: {passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(_self_test())
