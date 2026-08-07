#!/usr/bin/env python3
"""Controls for demo/confirm_settlements.py -- proves it REFUSES, not only that it announces.

This tool exists because a model-composed confirmation invented four settlements that had
never happened. A replacement that has only ever been seen announcing a real payment has
not been shown to be any safer, so every refusal path is driven explicitly:

  a failed transaction         must announce nothing
  an OUTGOING transfer         must announce nothing
  an already-recorded payment  must announce nothing
  an unreachable chain         must announce nothing AND exit 2
  a transaction it cannot fetch must announce nothing and leave it for the next run

THREE LAYERS, because a control on one proves nothing about the others.

  1. PURE DETECTOR. settlement_from_tx is a function over one RPC response, so the
     success/err/outgoing branches are driven directly with no network and no clock.

  2. END TO END through main(), with an injected fake RPC, asserting on the actual
     stdout SEND lines and the actual bytes appended to a real ledger file. A green
     detector proves nothing if main() never reaches it or writes the wrong record.

  3. MUTATION CONTROLS. Two refusal branches are disabled in memory and the matching
     case is REQUIRED to flip to announcing. Each asserts its target string is present
     in the source FIRST, so a control gone stale fails loudly instead of certifying an
     unmodified detector.

No network. Signatures in the fixtures are real mainnet signatures from this merchant's
own token account, so the base58 validity filter is exercised against real shapes.

  python demo/test_confirm_settlements.py
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "confirm_settlements.py"

spec = importlib.util.spec_from_file_location("confirm_settlements", SOURCE)
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)

CHECKS = 0
FAILS = 0


def check(label: str, ok: bool, detail: object = "") -> None:
    global CHECKS, FAILS
    CHECKS += 1
    if ok:
        print(f"  PASS  {label}")
    else:
        FAILS += 1
        print(f"  FAIL  {label}")
        if detail:
            print(f"        {detail}")


# Real mainnet signatures and a real payer pubkey from the merchant's own token account
# EpzuUPXwMR2oWqL3MCUTjvvpfdrZXforkMt85ZCSowo3, so the base58 validity filter is exercised
# against real shapes rather than invented ones.
#
# The transaction BODIES below are synthetic: SIG_ERR and SIG_OUT are real signatures that
# actually SUCCEEDED as incoming payments on chain, and here they are deliberately paired
# with a failed body and an outgoing body to drive the two refusal branches. The names
# describe the fixture's role in this file, not the on-chain status of that signature.
SIG_PAID = "4WG7HYF6As2AeDnJzQjuwEjEYXQK9WQKzqipqafZAirJf164Y8MEmJUsVGCkhk5bRTG5KpnixHFVAcfBkAKkuMsD"
SIG_ERR = "4rn7e9RLKMSZXP2T7ru2QUjY5w1vKQ9vYbACE9jZuFNUqxN11LmEgJEvbKjCqKHoYa5N3hnHWDAD5L3f34XuHuVW"
SIG_OUT = "5Zk9RPAffYmo9zzgXZuGrHJ8bV9Y2rnbE3ZdsPiMqzjEDWVQN2dWieiPu1VpGUMX2d4SNBt4Quqs9ewHdk3eAvbm"
SIG_KNOWN = "4VUbLWcE2dPPYAXQVtH2WhvgP33KrbUiX2ruA9PeyfKMU4k5iPgFSL3xkg8wLtjk8GumPYdyNR92haxgEasDstUh"

ATA = "EpzuUPXwMR2oWqL3MCUTjvvpfdrZXforkMt85ZCSowo3"
PAYER = "D7o5YEE6ZTnQPRd2nbdoK1rRP83mLLoapoBWgkSJFUHL"


def tx(pre_raw: str, post_raw: str, err=None, block_time=1786055214, slot=377001234):
    """A getTransaction response shaped like the real jsonParsed one."""
    return {
        "slot": slot,
        "blockTime": block_time,
        "meta": {
            "err": err,
            "preTokenBalances": [
                {
                    "accountIndex": 1,
                    "owner": cs.MERCHANT,
                    "mint": cs.USDC,
                    "uiTokenAmount": {"amount": pre_raw, "decimals": 6},
                }
            ],
            "postTokenBalances": [
                {
                    "accountIndex": 1,
                    "owner": cs.MERCHANT,
                    "mint": cs.USDC,
                    "uiTokenAmount": {"amount": post_raw, "decimals": 6},
                }
            ],
        },
        "transaction": {
            "message": {"accountKeys": [{"pubkey": PAYER, "signer": True}]}
        },
    }


TX_PAID = tx("1000000", "1390000")  # +0.39 USDC
TX_ERR = tx("1000000", "1390000", err={"InstructionError": [0, "Custom"]})
TX_OUT = tx("1390000", "1000000")  # merchant SENT 0.39, balance fell


def fake_rpc(signatures, txs, reachable=True):
    """An injected RPC. Returns None the way the real one does when everything failed."""

    def rpc(method, params):
        if not reachable:
            return None
        if method == "getTokenAccountsByOwner":
            return {"value": [{"pubkey": ATA}]}
        if method == "getSignaturesForAddress":
            return [{"signature": s} for s in signatures]
        if method == "getTransaction":
            return txs.get(params[0])
        return None

    return rpc


def run_main(argv, signatures, txs, reachable=True):
    """Drive main() end to end with an injected RPC. Returns (code, stdout, stderr)."""
    real = cs.make_rpc
    cs.make_rpc = lambda *a, **k: fake_rpc(signatures, txs, reachable)
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = cs.main(argv)
    finally:
        cs.make_rpc = real
    return code, out.getvalue(), err.getvalue()


def send_lines(stdout: str) -> list[str]:
    return [ln for ln in stdout.splitlines() if ln.startswith(cs.SEND_PREFIX)]


print("\nLAYER 1  pure detector")

_paid = cs.settlement_from_tx(TX_PAID, SIG_PAID)
check("a real settled transfer is detected", _paid is not None)
check(
    "its amount is the chain-recorded delta", _paid and _paid["amount"] == "0.39", _paid
)
check(
    "its raw amount is the integer delta",
    _paid and _paid["amount_raw"] == "390000",
    _paid,
)
check("its signature is the real signature", _paid and _paid["signature"] == SIG_PAID)
check(
    "its timestamp is derived from blockTime, so it cannot be in the future",
    # verified independently with time.gmtime(1786055214), not with the code under test
    _paid and _paid["settled_at"] == "2026-08-06T22:26:54Z",
    _paid and _paid["settled_at"],
)
check("its payer is read off the chain", _paid and _paid["payer"] == PAYER)

# Amount rendering across the range. A large delta must not reach the SEND line as 1E+3.
_big = cs.settlement_from_tx(tx("0", "1000000000"), SIG_PAID)
check(
    "a 1000 USDC delta renders as 1000, never 1E+3",
    _big and _big["amount"] == "1000",
    _big,
)
_whole = cs.settlement_from_tx(tx("0", "5000000"), SIG_PAID)
check("a whole-number delta renders as 5", _whole and _whole["amount"] == "5", _whole)
_dust = cs.settlement_from_tx(tx("0", "1"), SIG_PAID)
check(
    "a 1-unit delta keeps full precision",
    _dust and _dust["amount"] == "0.000001",
    _dust,
)

check(
    "a FAILED transaction is not a settlement",
    cs.settlement_from_tx(TX_ERR, SIG_ERR) is None,
)
check(
    "an OUTGOING transfer is not a settlement",
    cs.settlement_from_tx(TX_OUT, SIG_OUT) is None,
)
check(
    "a zero-delta transaction is not a settlement",
    cs.settlement_from_tx(tx("5", "5"), SIG_OUT) is None,
)
check(
    "a garbage response is not a settlement", cs.settlement_from_tx({}, SIG_OUT) is None
)

# The base58 filter is what stops a fabricated ledger signature deduping a real one away.
check("a real signature passes the base58 filter", cs.is_signature(SIG_PAID))
check("the fabricated '5QzQ1...' does NOT", not cs.is_signature("5QzQ1..."))
check("the fabricated '4vC...M2n' does NOT", not cs.is_signature("4vC...M2n"))
check("a base58-clean but too-short string does NOT", not cs.is_signature("5QzQ1abc"))


print("\nLAYER 2  end to end through main()")

# The four fabricated records measured on the box on 2026-08-06. They are EVIDENCE for the
# write-up: this asserts they are parsed past and counted, never rewritten or deleted.
LEGACY = [
    '{"timestamp":"2026-08-06T22:17:00Z","order":"412","amount":"0.39","reference":"412","signature":"5QzQ1..."}',
    '{"timestamp":"2026-08-06T22:17:00Z","order":"413","amount":"1.20","reference":"413","signature":"4vC...M2n"}',
    '{"timestamp":"2026-08-06T22:19:00Z","order":"414","amount":"0.75","reference":"414","signature":"3xKp9QQ"}',
    '{"timestamp":"2026-08-06T22:19:00Z","order":"415","amount":"2.50","reference":"415","signature":"3xKp9QQ"}',
]

with tempfile.TemporaryDirectory() as td:
    led = Path(td) / "confirmed-payments.jsonl"
    led.write_text("\n".join(LEGACY) + "\n", encoding="utf-8")
    before = led.read_text(encoding="utf-8")

    known, stats = cs.load_ledger(led)
    check(
        "the 4 fabricated lines are read without crashing", stats["lines"] == 4, stats
    )
    check("none of them yields a usable signature", stats["usable"] == 0, stats)
    check("all 4 are counted as skipped", stats["no_signature"] == 4, stats)
    check("so none of them can dedupe a real settlement", known == set(), known)

    code, out, err = run_main(
        ["--ledger", str(led)],
        [SIG_PAID, SIG_ERR, SIG_OUT],
        {SIG_PAID: TX_PAID, SIG_ERR: TX_ERR, SIG_OUT: TX_OUT},
    )
    lines = send_lines(out)
    check("exit 0 on a healthy run", code == 0, code)
    check("exactly ONE SEND line from three candidates", len(lines) == 1, lines)
    check("it carries the real signature", lines and SIG_PAID in lines[0], lines)
    check("it carries the real amount", lines and "0.39 USDC" in lines[0], lines)
    check(
        "the errored signature is NOT announced",
        not any(SIG_ERR in ln for ln in lines),
        lines,
    )
    check(
        "the outgoing signature is NOT announced",
        not any(SIG_OUT in ln for ln in lines),
        lines,
    )

    after = led.read_text(encoding="utf-8")
    check(
        "the 4 fabricated lines are still on disk, untouched",
        after.startswith(before),
        after[:120],
    )
    appended = [ln for ln in after.splitlines() if ln not in LEGACY and ln.strip()]
    check("exactly one record was appended", len(appended) == 1, appended)
    rec = json.loads(appended[0]) if appended else {}
    check(
        "the appended record's signature is the real one",
        rec.get("signature") == SIG_PAID,
        rec,
    )
    check("the appended record has no invented order field", "order" not in rec, rec)

    # DEDUPE: the same run again must announce nothing, because it is now recorded.
    code2, out2, _ = run_main(
        ["--ledger", str(led)],
        [SIG_PAID, SIG_ERR, SIG_OUT],
        {SIG_PAID: TX_PAID, SIG_ERR: TX_ERR, SIG_OUT: TX_OUT},
    )
    check(
        "a second run announces nothing (dedupe)",
        send_lines(out2) == [],
        send_lines(out2),
    )
    check("and exits 0", code2 == 0, code2)

with tempfile.TemporaryDirectory() as td:
    led = Path(td) / "confirmed-payments.jsonl"
    # A genuinely unparseable line, alongside a valid one, proves the JSON-error path.
    led.write_text(
        json.dumps({"signature": SIG_KNOWN}) + "\n{ this is not json\n",
        encoding="utf-8",
    )
    known, stats = cs.load_ledger(led)
    check(
        "a truncated/unparseable line is counted, not fatal",
        stats["unparseable"] == 1,
        stats,
    )
    check("the valid line beside it still registers", known == {SIG_KNOWN}, known)

    code, out, _ = run_main(["--ledger", str(led)], [SIG_KNOWN], {SIG_KNOWN: TX_PAID})
    check(
        "an already-recorded signature is not announced",
        send_lines(out) == [],
        send_lines(out),
    )

with tempfile.TemporaryDirectory() as td:
    led = Path(td) / "confirmed-payments.jsonl"
    code, out, err = run_main(
        ["--ledger", str(led)], [SIG_PAID], {SIG_PAID: TX_PAID}, reachable=False
    )
    check("unreachable chain exits 2", code == 2, code)
    check(
        "unreachable chain prints ZERO SEND lines",
        send_lines(out) == [],
        send_lines(out),
    )
    check("unreachable chain writes no ledger at all", not led.exists(), led.exists())

with tempfile.TemporaryDirectory() as td:
    led = Path(td) / "confirmed-payments.jsonl"
    # getTransaction returns nothing for a signature we were told exists.
    code, out, err = run_main(["--ledger", str(led)], [SIG_PAID], {})
    check(
        "an unfetchable transaction is not announced",
        send_lines(out) == [],
        send_lines(out),
    )
    check(
        "and is counted as left for the next run", "1 could not be fetched" in err, err
    )
    check("and nothing is written for it", not led.exists(), led.exists())

with tempfile.TemporaryDirectory() as td:
    led = Path(td) / "confirmed-payments.jsonl"
    code, out, err = run_main(
        ["--ledger", str(led), "--dry-run"], [SIG_PAID], {SIG_PAID: TX_PAID}
    )
    check("--dry-run still prints the SEND line", len(send_lines(out)) == 1, out)
    check("--dry-run writes nothing", not led.exists(), led.exists())
    check("--dry-run exits 0", code == 0, code)

with tempfile.TemporaryDirectory() as td:
    led = Path(td) / "confirmed-payments.jsonl"
    code, out, err = run_main(
        ["--ledger", str(led), "--seed"], [SIG_PAID], {SIG_PAID: TX_PAID}
    )
    check("--seed announces nothing", send_lines(out) == [], send_lines(out))
    check(
        "--seed records the history",
        led.exists() and SIG_PAID in led.read_text(encoding="utf-8"),
    )
    code2, out2, _ = run_main(["--ledger", str(led)], [SIG_PAID], {SIG_PAID: TX_PAID})
    check(
        "so a later real run stays quiet about it",
        send_lines(out2) == [],
        send_lines(out2),
    )


print("\nLAYER 3  mutation controls")

SRC = SOURCE.read_text(encoding="utf-8")

MUT_ERR = '    if meta.get("err") is not None:\n        return None'
MUT_OUT = "        if delta_raw <= 0:\n            continue"

# Assert the target EXISTS before mutating, or a stale control silently certifies an
# unmodified detector.
check("mutation target for the err check is present in the source", MUT_ERR in SRC)
check("mutation target for the outgoing check is present in the source", MUT_OUT in SRC)


def load_mutant(old: str, new: str):
    mutated = SRC.replace(old, new, 1)
    assert mutated != SRC, "substitution did not apply"
    ns = {"__name__": "confirm_settlements_mutant", "__file__": str(SOURCE)}
    exec(compile(mutated, str(SOURCE), "exec"), ns)
    return ns


if MUT_ERR in SRC:
    m = load_mutant(MUT_ERR, "    if False:\n        return None")
    check(
        "DISABLING the err check makes the FAILED transaction announce (control discriminates)",
        m["settlement_from_tx"](TX_ERR, SIG_ERR) is not None,
    )
    check(
        "and the real payment still announces under the mutant (mutation was surgical)",
        m["settlement_from_tx"](TX_PAID, SIG_PAID) is not None,
    )

if MUT_OUT in SRC:
    m = load_mutant(MUT_OUT, "        if False:\n            continue")
    check(
        "DISABLING the delta check makes the OUTGOING transfer announce (control discriminates)",
        m["settlement_from_tx"](TX_OUT, SIG_OUT) is not None,
    )

print(f"\n{CHECKS - FAILS}/{CHECKS} checks passed")
sys.exit(1 if FAILS else 0)
