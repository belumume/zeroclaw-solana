#!/usr/bin/env python3
"""Fail-closed action certification for the DePIN oracle-publish broadcast path.

The listing names this custody-design-space frontier directly:
  "Fail-closed action certification, where nothing leaves the machine unless the
   exact serialized transaction has been verified against intent."

An agent (LLM in the loop) produces a partial transaction that the host completes
and broadcasts. Before ANYTHING leaves the machine, this certifies the exact
serialized bytes against the ONLY intent this path is allowed to express:

    exactly two instructions:
      ix0 = System program  AdvanceNonceAccount   (durable-nonce, trap #1)
      ix1 = our oracle program  publish_reading  touching OUR feed PDA
    and NO instruction invoking any other program (no SOL/SPL transfer, no CPI).

A prompt-injected agent that appends a transfer, swaps in the token program,
targets a different feed, or adds a third instruction is REFUSED (fail-closed) —
the tx never broadcasts. This is a deterministic, host-side check that does not
trust the LLM, the plugin, or the wire; it re-derives intent from the bytes.

Pure stdlib. Import `certify_publish_tx` from the broadcaster, or run this file
directly to execute the self-test (good tx passes; five injection shapes refused).
"""

from __future__ import annotations

SYSTEM_PROGRAM = bytes(32)  # base58 "111...1" (32 ones) decodes to 32 zero bytes
_ADVANCE_NONCE = bytes(
    [4, 0, 0, 0]
)  # SystemInstruction::AdvanceNonceAccount (bincode u32 LE = 4)
_TRANSFER = bytes(
    [2, 0, 0, 0]
)  # SystemInstruction::Transfer, for the self-test injection
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class CertificationError(Exception):
    """Raised when the serialized tx does not match the allowed publish intent."""


def b58decode(s: str) -> bytes:
    num = 0
    for c in s:
        num = num * 58 + _B58.index(c)
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def b58encode(b: bytes) -> str:
    num = int.from_bytes(b, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


def _read_shortvec(b: bytes, i: int):
    val = 0
    shift = 0
    while True:
        if i >= len(b):
            raise CertificationError("truncated shortvec")
        byte = b[i]
        i += 1
        val |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return val, i
        shift += 7


def parse_legacy_message(msg: bytes) -> dict:
    """Parse a legacy (non-v0) transaction message into keys + instructions.

    A VERSIONED message is refused rather than parsed. `oracle-publish` calls
    `serialize_legacy`, so v0 is not a shape this path's producer makes, but a parser that reads
    a v0 message as legacy starts three bytes early and every offset after that is wrong, which
    would silently describe a transaction other than the one being signed. Refusing what cannot
    be read exactly is the only honest option for a gate.
    """
    if msg and msg[0] & 0x80:
        raise CertificationError(
            f"this is a v{msg[0] & 0x7F} message; this path emits legacy, and reading a "
            f"versioned one as legacy misaligns every offset below"
        )
    i = 3  # 3 header bytes: num_required_sigs, num_ro_signed, num_ro_unsigned
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


def certify_publish_tx(
    raw_tx: bytes,
    oracle_program_b58: str,
    feed_pda_b58: str,
    nonce_b58: str | None = None,
) -> dict:
    """Verify raw_tx expresses ONLY the allowed oracle-publish intent. Raise otherwise."""
    oracle = b58decode(oracle_program_b58)
    feed = b58decode(feed_pda_b58)
    nonce = b58decode(nonce_b58) if nonce_b58 else None

    if not raw_tx:
        raise CertificationError("empty transaction")
    nsigs = raw_tx[0]
    if nsigs >= 0x80:
        raise CertificationError("multi-byte signature shortvec is unexpected here")
    msg = raw_tx[1 + nsigs * 64 :]
    m = parse_legacy_message(msg)
    ixs = m["instructions"]

    # Exactly the two allowed instructions — no more (blocks any appended transfer/CPI).
    if len(ixs) != 2:
        raise CertificationError(f"expected exactly 2 instructions, got {len(ixs)}")

    # ix0: System AdvanceNonceAccount (durable nonce).
    if ixs[0]["program"] != SYSTEM_PROGRAM:
        raise CertificationError("ix0 must be the System program (AdvanceNonceAccount)")
    if ixs[0]["data"][:4] != _ADVANCE_NONCE:
        raise CertificationError(
            "ix0 is a System instruction but NOT AdvanceNonceAccount"
        )
    if nonce is not None and nonce not in ixs[0]["accounts"]:
        raise CertificationError("ix0 does not reference our expected nonce account")

    # ix1: our oracle program, publishing to OUR feed PDA.
    if ixs[1]["program"] != oracle:
        raise CertificationError("ix1 must be our oracle program (publish_reading)")
    if feed not in ixs[1]["accounts"]:
        raise CertificationError(
            "ix1 does not touch our feed PDA (wrong/spoofed feed?)"
        )

    # No instruction may invoke ANY program outside the allowed set (blocks token/SOL transfers, CPIs).
    allowed = {SYSTEM_PROGRAM, oracle}
    for k, ix in enumerate(ixs):
        if ix["program"] not in allowed:
            raise CertificationError(
                f"ix{k} invokes an unexpected program {b58encode(ix['program'])} (injected?)"
            )

    return {
        "certified": True,
        "instructions": 2,
        "intent": ["system:advance_nonce", "oracle:publish_reading -> feed"],
    }


# ---------------------------------------------------------------------------
# Self-test: build a minimal good tx + five injection shapes, assert behaviour.
# ---------------------------------------------------------------------------
def _shortvec(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _build_msg(keys: list[bytes], ixs: list[tuple[int, list[int], bytes]]) -> bytes:
    m = bytearray([1, 0, 1])  # header (values irrelevant to the cert)
    m += _shortvec(len(keys))
    for k in keys:
        m += k
    m += bytes(32)  # blockhash
    m += _shortvec(len(ixs))
    for prog_idx, accts, data in ixs:
        m += bytes([prog_idx])
        m += _shortvec(len(accts)) + bytes(accts)
        m += _shortvec(len(data)) + data
    return bytes(m)


def _self_test() -> int:
    ORACLE = "EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn"
    FEED = "3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K"
    oracle_b = b58decode(ORACLE)
    feed_b = b58decode(FEED)
    nonce_b = bytes([7]) * 32
    payer_b = bytes([9]) * 32
    token_b = bytes([5]) * 32  # a stand-in "token program" for the injection test

    # keys: [payer, nonce, feed, system(0), oracle, token]
    keys = [payer_b, nonce_b, feed_b, SYSTEM_PROGRAM, oracle_b, token_b]
    SYS_IDX, ORACLE_IDX, TOKEN_IDX = 3, 4, 5
    advance = (SYS_IDX, [1], _ADVANCE_NONCE)  # touches nonce (idx1)
    publish = (ORACLE_IDX, [2, 1, 0], b"\x00" * 8 + b"payload")  # touches feed (idx2)

    def raw(msg):
        return bytes([1]) + b"\x00" * 64 + msg  # 1 empty sig + message

    results = []

    def check(name, msg, should_pass):
        try:
            certify_publish_tx(raw(msg), ORACLE, FEED, b58encode(nonce_b))
            ok = should_pass
            verdict = "PASS(certified)"
        except CertificationError as e:
            ok = not should_pass
            verdict = f"REFUSED({e})"
        results.append(ok)
        print(f"  [{'OK ' if ok else 'XX '}] {name}: {verdict}")

    print("fail-closed action certification self-test:")
    # 1. Good tx -> certified.
    check("good publish tx", _build_msg(keys, [advance, publish]), True)
    # 2. Injected SOL transfer appended (3rd instruction) -> refused.
    transfer = (SYS_IDX, [0, 1], _TRANSFER + (1_000_000).to_bytes(8, "little"))
    check(
        "injected 3rd-instruction SOL transfer",
        _build_msg(keys, [advance, publish, transfer]),
        False,
    )
    # 3. Injected token-program instruction swapped for publish -> refused.
    token_ix = (TOKEN_IDX, [2, 0], b"\x03" + (500).to_bytes(8, "little"))
    check(
        "token-program instruction instead of publish",
        _build_msg(keys, [advance, token_ix]),
        False,
    )
    # 4. ix0 is a System Transfer, not AdvanceNonce -> refused.
    bad_ix0 = (SYS_IDX, [0, 1], _TRANSFER + (1).to_bytes(8, "little"))
    check(
        "ix0 System-Transfer instead of AdvanceNonce",
        _build_msg(keys, [bad_ix0, publish]),
        False,
    )
    # 5. publish targets a DIFFERENT (spoofed) feed -> refused.
    spoof_feed = bytes([8]) * 32
    keys2 = [payer_b, nonce_b, spoof_feed, SYSTEM_PROGRAM, oracle_b]
    publish2 = (4, [2, 1, 0], b"\x00" * 8)
    advance2 = (3, [1], _ADVANCE_NONCE)
    check(
        "publish to a spoofed feed PDA", _build_msg(keys2, [advance2, publish2]), False
    )
    # 6. A VERSIONED message. Read as legacy it would misalign every offset, so the parser must
    #    refuse it rather than describe a transaction other than the one being signed. The
    #    control is case 1 above: the same body without the version byte still certifies.
    good = _build_msg(keys, [advance, publish])
    check("a versioned (v0) message", b"\x80" + good, False)

    passed = sum(results)
    print(f"\n{passed}/{len(results)} cases correct")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    import sys

    sys.exit(_self_test())
