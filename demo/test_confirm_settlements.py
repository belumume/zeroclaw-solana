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

FOUR LAYERS, because a control on one proves nothing about the others.

  1. PURE DETECTOR. settlement_from_tx is a function over one RPC response, so the
     success/err/outgoing branches are driven directly with no network and no clock.

  2. END TO END through main(), with an injected fake RPC, asserting on the actual
     stdout SEND lines and the actual bytes appended to a real ledger file. A green
     detector proves nothing if main() never reaches it or writes the wrong record.

  3. MUTATION CONTROLS. Two refusal branches are disabled in memory and the matching
     case is REQUIRED to flip to announcing. Each asserts its target string is present
     in the source FIRST, so a control gone stale fails loudly instead of certifying an
     unmodified detector.

  4. SCAN CACHE AND COMMIT NARROWING, driven with an RPC that COUNTS its calls, because
     the claim being made there is about work avoided and no assertion on output can see
     it. Both directions are required: repeated runs must stop re-fetching, AND a new
     payment must still be announced on the tick it arrives. A cache that quietly
     suppressed real settlements would satisfy the first half perfectly.

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

print("\nLAYER 4  scan cache and commit narrowing")

# A window shaped like the box's own on 2026-08-16: 21 signatures, 6 already in the ledger,
# 11 that are not incoming settlements, 4 that are. The four real signatures above are the
# settlements; the rest are synthetic but base58-valid, because load_cache re-validates
# every entry and a fixture with a '0' or an 'l' in it would be silently discarded, which
# would make the cache look broken when it is the fixture that is wrong.
_B58_SAFE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def synth(tag: str) -> str:
    value = tag + "z" * (88 - len(tag))
    assert cs.is_signature(value), f"fixture is not a valid signature: {tag}"
    return value


CACHE_POS = [
    SIG_PAID,
    SIG_ERR,
    SIG_OUT,
    SIG_KNOWN,
]  # role here: all four are settlements
CACHE_LEDGERED = [synth("L" + _B58_SAFE[i]) for i in range(6)]
CACHE_NEG = [synth("N" + _B58_SAFE[i]) for i in range(11)]
CACHE_WINDOW = CACHE_POS + CACHE_LEDGERED + CACHE_NEG
CACHE_NEW = synth("W9")

assert len(set(CACHE_WINDOW)) == 21, "window fixture has duplicates"

TX_IN = tx("1000000", "1390000")  # +0.39 USDC, an incoming settlement
TX_NOT = tx("1390000", "1000000")  # outgoing, so never a settlement


def counting_rpc(signatures, positives, unfetchable=frozenset()):
    """An injected RPC that records how many transactions it was asked to read."""
    tally = {"getTransaction": 0}

    def rpc(method, params):
        tally[method] = tally.get(method, 0) + 1
        if method == "getTokenAccountsByOwner":
            return {"value": [{"pubkey": ATA}]}
        if method == "getSignaturesForAddress":
            return [{"signature": s} for s in signatures]
        if method == "getTransaction":
            if params[0] in unfetchable:
                return None
            return TX_IN if params[0] in positives else TX_NOT
        return None

    return rpc, tally


def run_counted(argv, signatures, positives, unfetchable=frozenset(), module=None):
    """Drive main() with a counting RPC. Returns (code, send_lines, stderr, fetches).

    `module` is a namespace dict, which is what load_mutant hands back, so the mutant and
    the real module are driven through exactly the same path.
    """
    ns = cs.__dict__ if module is None else module
    rpc, tally = counting_rpc(signatures, positives, unfetchable)
    real = ns["make_rpc"]
    ns["make_rpc"] = lambda *a, **k: rpc
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = ns["main"](argv)
    finally:
        ns["make_rpc"] = real
    sends = [ln for ln in out.getvalue().splitlines() if ln.startswith(cs.SEND_PREFIX)]
    return code, sends, err.getvalue(), tally["getTransaction"]


def fresh_box():
    """A throwaway ledger already holding the six recorded signatures, plus a cache path."""
    box = Path(tempfile.mkdtemp(prefix="scan-cache-"))
    ledger = box / "confirmed-payments-v2.jsonl"
    ledger.write_text(
        "".join(json.dumps({"signature": s}) + "\n" for s in CACHE_LEDGERED),
        encoding="utf-8",
    )
    return ledger, box / "settlement-scan-cache.json"


# THE INCIDENT'S OWN SHAPE: the send keeps failing, so the same four stay pending and the
# scan runs again every tick. What must stop growing is the transaction reads.
ledger, cache = fresh_box()
scan = ["--ledger", str(ledger), "--cache", str(cache), "--dry-run"]

code, sends, err, cold = run_counted(scan, CACHE_WINDOW, set(CACHE_POS))
check("cold scan announces all four pending settlements", len(sends) == 4, sends)
check("cold scan fetches every unrecorded signature (21 - 6 = 15)", cold == 15, cold)

code, sends, err, warm = run_counted(scan, CACHE_WINDOW, set(CACHE_POS))
check("second tick still announces the same four", len(sends) == 4, sends)
check(
    "second tick fetches ONLY the four pending settlements, not the 11 negatives",
    warm == 4,
    warm,
)

code, sends, err, warm2 = run_counted(scan, CACHE_WINDOW, set(CACHE_POS))
check(
    "and a third tick does not creep back up (the saving is stable, not one-shot)",
    warm2 == 4,
    warm2,
)
check(
    "the run reports its own fetch count, so a dead cache is visible in the journal",
    "[4 transaction(s) fetched]" in err,
    err,
)

# POSITIVES ARE NEVER CACHED. This is the safety invariant, not an optimisation detail:
# every announced field must still be read from the chain on the run that announces it.
cached = set(json.loads(cache.read_text(encoding="utf-8"))["not_settlements"])
check("the cache holds exactly the 11 permanent negatives", len(cached) == 11, cached)
check(
    "and holds NO announced signature, so no receipt field can come from a file",
    not (cached & set(CACHE_POS)),
    cached & set(CACHE_POS),
)

# OVER-CORRECTION CONTROL. A cache that suppressed real settlements would pass every check
# above. A genuinely new payment must be announced on the tick it arrives, because the
# per-minute latency claim is published in QUICKSTART.md, the SOP and the write-up.
code, sends, err, fetched = run_counted(
    scan, [CACHE_NEW] + CACHE_WINDOW, set(CACHE_POS) | {CACHE_NEW}
)
check(
    "a NEW payment arriving while the cache is warm is announced immediately",
    len(sends) == 5 and any(CACHE_NEW in s for s in sends),
    sends,
)
check(
    "and cost exactly one extra fetch: the new one (4 pending + 1)",
    fetched == 5,
    fetched,
)

# A cache the run cannot parse must cost RPC calls, never a missed receipt.
cache.write_text("{ not json at all", encoding="utf-8")
code, sends, err, corrupt = run_counted(scan, CACHE_WINDOW, set(CACHE_POS))
check(
    "a CORRUPT cache degrades to a full re-fetch, not to silence",
    corrupt == 15 and len(sends) == 4,
    (corrupt, len(sends)),
)

# A transaction that could not be read is a transport blip, not a verdict. Caching it
# would make one bad second permanent.
ledger, cache = fresh_box()
scan = ["--ledger", str(ledger), "--cache", str(cache), "--dry-run"]
blip = CACHE_NEG[0]
run_counted(scan, CACHE_WINDOW, set(CACHE_POS), unfetchable={blip})
cached = set(json.loads(cache.read_text(encoding="utf-8"))["not_settlements"])
check(
    "an UNFETCHABLE transaction is never cached, so the next run retries it",
    blip not in cached and len(cached) == 10,
    len(cached),
)

# --no-cache is the control that proves the cache is what caused the drop above, rather
# than something else in the fixture quietly changing the fetch count.
ledger, cache = fresh_box()
nocache = ["--ledger", str(ledger), "--no-cache", "--dry-run"]
run_counted(nocache, CACHE_WINDOW, set(CACHE_POS))
code, sends, err, again = run_counted(nocache, CACHE_WINDOW, set(CACHE_POS))
check(
    "--no-cache re-derives every verdict on every run (pre-change behaviour, 15)",
    again == 15,
    again,
)
check("--no-cache writes no cache file at all", not cache.exists())

# COMMIT NARROWING. The commit step re-derives from chain; without --only it appends
# everything it finds, so a payment that settles between the announce and the commit is
# recorded having never been sent, and is then never announced. That is the swallow the
# whole send-first/commit-after ordering exists to prevent.
ledger, cache = fresh_box()
announced = CACHE_POS[:2]
arrived_mid_run = CACHE_POS[2]
commit = ["--ledger", str(ledger), "--no-cache"]
only_args = [arg for s in announced for arg in ("--only", s)]
code, sends, err, fetched = run_counted(
    commit + only_args, CACHE_WINDOW, set(CACHE_POS)
)
written = {
    json.loads(ln)["signature"]
    for ln in ledger.read_text(encoding="utf-8").splitlines()
    if ln.strip()
}
check("a narrowed commit exits 0", code == 0, err)
check(
    "it records exactly the announced signatures",
    written == set(CACHE_LEDGERED) | set(announced),
    written - set(CACHE_LEDGERED),
)
check(
    "a settlement that arrived mid-run is NOT recorded, so the next tick announces it",
    arrived_mid_run not in written,
    written,
)
check(
    "and it fetches only what it was asked about, not the whole window",
    fetched == len(announced),
    fetched,
)

# The un-narrowed commit is the behaviour being replaced. Driving it proves the swallow was
# real rather than theoretical: without --only the mid-run arrival lands in the ledger.
ledger, cache = fresh_box()
run_counted(["--ledger", str(ledger), "--no-cache"], CACHE_WINDOW, set(CACHE_POS))
written = {
    json.loads(ln)["signature"]
    for ln in ledger.read_text(encoding="utf-8").splitlines()
    if ln.strip()
}
check(
    "WITHOUT --only the mid-run arrival is silently recorded (the swallow was real)",
    arrived_mid_run in written,
    written,
)

check(
    "--only rejects anything that is not a base58 signature",
    run_counted(
        ["--ledger", str(ledger), "--no-cache", "--only", "not-a-signature"],
        CACHE_WINDOW,
        set(CACHE_POS),
    )[0]
    == 1,
)

# MUTATION CONTROL. Disable the cache-hit skip and the fetch count must climb back to the
# uncached number. Without this, "warm == 4" is equally consistent with a fixture that
# simply had four unrecorded signatures.
MUT_CACHE = "        if signature in cached_negative:"
check("mutation target for the cache skip is present in the source", MUT_CACHE in SRC)

if MUT_CACHE in SRC:
    m = load_mutant(MUT_CACHE, "        if False:")
    ledger, cache = fresh_box()
    scan = ["--ledger", str(ledger), "--cache", str(cache), "--dry-run"]
    run_counted(scan, CACHE_WINDOW, set(CACHE_POS), module=m)
    _, sends, _, mutant_warm = run_counted(scan, CACHE_WINDOW, set(CACHE_POS), module=m)
    check(
        "DISABLING the cache skip DOES restore all 15 fetches (the skip is load-bearing)",
        mutant_warm == 15,
        mutant_warm,
    )
    check(
        "while the mutant still announces the same four (mutation was surgical)",
        len(sends) == 4,
        sends,
    )

print(f"\n{CHECKS - FAILS}/{CHECKS} checks passed")
sys.exit(1 if FAILS else 0)
