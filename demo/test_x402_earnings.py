#!/usr/bin/env python3
"""Controls for demo/x402_earnings.py -- proves it can FAIL, not only that it passes.

The beat this backs exists because the earnings line was a TEMPLATE quoted as footage.
So the suite drives the directions a live run cannot produce on demand: a gate claiming
more revenue than settled, a corrupt ledger, an empty chain, and a source that is simply
down. Case 1 is the LIVE SHAPE VERBATIM as measured 2026-08-05 -- if that case stops
passing, the beat's numbers have moved and the script is dead until re-measured.

Case 12 is the mutation control: it disables the over-claim check in memory and REQUIRES
case 5 to go red. Without it, "5 passed" would be consistent with a detector that never
fires.

  python demo/test_x402_earnings.py
"""

from __future__ import annotations

import io
import re
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import take
import x402_earnings as mod

CHECKS = 0
FAILS = 0

LIVE_SELLER = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
LIVE_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

# THE LIVE SHAPE, measured 2026-08-05 after driving a genuine sale end to end. Four
# x402-memo settlements on the seller ATA 6L348Rzi.., one devnet USDC each, payer
# E36NJ7Fv.. -- our own client, so these are agent-to-agent purchases against our own
# paywall and NOT third-party customers. Three are from 2026-07-27; 3xGTNaKt.. is the
# sale driven on 2026-08-05, which is why the gate's startup snapshot (3) trails the
# chain (4). That gap is the BENIGN direction and is disclosed, never failed.
LIVE_SALES = [
    {
        "sig": "3xGTNaKt",
        "memo": "x402-18c8ffbab572271c-ba",
        "atomic": 1_000_000,
        "blockTime": 1785957000,
    },
    {
        "sig": "2erMUutQ",
        "memo": "x402-18c6396ca877977d-3f",
        "atomic": 1_000_000,
        "blockTime": 1785177451,
    },
    {
        "sig": "4qaCahTd",
        "memo": "x402-18c6350c1403d428-4",
        "atomic": 1_000_000,
        "blockTime": 1785172641,
    },
    {
        "sig": "EkBmoDkn",
        "memo": "x402-18c632a32e04eb24-1",
        "atomic": 1_000_000,
        "blockTime": 1785169983,
    },
]
# The gate's ledger as /health reported it after that sale: the snapshot is still 3
# because it is taken at STARTUP, while settled_atomic_units and redeemed_nonces moved.
LIVE_LEDGER = {
    "daily_cap_atomic_units": 20_000_000,
    "lock_healthy": True,
    "redeemed_nonces": 1,
    "restored_sales_at_startup": 3,
    "settled_atomic_units": 4_000_000,
    "tracked_payer_days": 2,
    "unparseable_lines_skipped": 0,
}
LIVE_CHALLENGE = {
    "x402Version": 2,
    "accepts": [{"payTo": LIVE_SELLER, "asset": LIVE_MINT, "amount": "1000000"}],
}


def check(name: str, cond: bool, detail: str = "") -> None:
    global CHECKS, FAILS
    CHECKS += 1
    if cond:
        print(f"  ok   {name}")
    else:
        FAILS += 1
        print(f"  FAIL {name}  {detail}")


def drive(challenge=None, health=None, sales=None, argv=("x402_earnings.py",)):
    """Run main() against injected sources. Returns (rc, stdout, stderr)."""

    def _challenge():
        if isinstance(challenge, Exception):
            raise challenge
        return challenge if challenge is not None else LIVE_CHALLENGE

    def _health(_url, timeout=25):
        if isinstance(health, Exception):
            raise health
        return {"ledger": LIVE_LEDGER} if health is None else health

    def _sales(_seller, _mint):
        if isinstance(sales, Exception):
            raise sales
        return LIVE_SALES if sales is None else sales

    orig = (mod.challenge, mod._get_json, mod.chain_settlements, sys.argv)
    mod.challenge, mod._get_json, mod.chain_settlements = _challenge, _health, _sales
    sys.argv = list(argv)
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = mod.main()
    finally:
        mod.challenge, mod._get_json, mod.chain_settlements, sys.argv = orig
    return rc, out.getvalue(), err.getvalue()


print("x402 earnings controls")

# 1 -- THE LIVE SHAPE, VERBATIM. The incident case: if this stops passing, re-measure.
rc, out, err = drive()
check("1 live shape exits 0", rc == 0, f"rc={rc} err={err.strip()}")
check("1 reports 4 paid reads", "4 paid reads" in out, out.strip())
check("1 reports 4.00 USDC", "4.00 USDC" in out, out.strip())
check("1 sources AGREE", "AGREE" in out, out.strip())
check(
    "1 discloses the startup snapshot trailing the chain",
    "+1 newer than last restart" in out,
    out.strip(),
)
check(
    "1 names the mandatory per-payer daily cap",
    "cap 20.00 USDC per payer per day" in out,
    out.strip(),
)

# 2 -- THE DEFECT THIS WHOLE BEAT REPLACES. The SOP template says "sold N readings TODAY".
# The settlements are from 2026-07-27. Any output claiming "today" is the fiction returning.
check("2 output never says 'today'", "today" not in out.lower(), out.strip())
check(
    "2 output carries an ISO date instead of a relative word",
    re.search(r"latest \d{4}-\d{2}-\d{2}", out) is not None,
    out.strip(),
)

# 3 -- gate down: refuse, never report from the chain alone.
rc, out, err = drive(challenge=mod.Unavailable("/price -> URLError"))
check("3 gate down exits 2", rc == 2, f"rc={rc}")
check("3 gate down prints no earnings line", "X402 EARNINGS" not in out, out.strip())
check("3 gate down says why", "UNAVAILABLE" in err, err.strip())

# 4 -- /health present but carrying no ledger object.
rc, out, err = drive(health={"gate": "up"})
check("4 no .ledger exits 2", rc == 2, f"rc={rc}")
check("4 no .ledger prints no earnings line", "X402 EARNINGS" not in out, out.strip())

# 5 -- THE FRAUD DIRECTION: the gate claims more sales than the chain can show.
rc, out, err = drive(health={"ledger": {**LIVE_LEDGER, "restored_sales_at_startup": 5}})
check("5 gate over-claiming exits 1", rc == 1, f"rc={rc}")
check("5 over-claim prints no earnings line", "X402 EARNINGS" not in out, out.strip())
check(
    "5 over-claim names both counts",
    "restored 5" in err and "chain shows 4" in err,
    err.strip(),
)

# 6 -- a corrupt ledger silently shrinking the restored spend must not read as healthy.
rc, out, err = drive(health={"ledger": {**LIVE_LEDGER, "unparseable_lines_skipped": 2}})
check("6 skipped ledger lines exits 1", rc == 1, f"rc={rc}")

# 7 -- THE EXACT-AGREEMENT BRANCH, which case 1 stopped covering once a same-day sale put
# the chain ahead of the startup snapshot. After a restart the gate restores everything the
# chain shows, and the verdict must then read a bare AGREE with no trailing disclosure.
rc, out, err = drive(health={"ledger": {**LIVE_LEDGER, "restored_sales_at_startup": 4}})
check("7 exact agreement exits 0", rc == 0, f"rc={rc} err={err.strip()}")
check("7 exact agreement reads a bare AGREE", "AGREE   cap" in out, out.strip())
check("7 exact agreement discloses no gap", "newer than last restart" not in out, out.strip())

# 8 -- zero settlements is UNAVAILABLE, never "earned 0.00": absence of evidence is not
# evidence the node earned nothing, and a green 0.00 on camera would be a claim.
rc, out, err = drive(sales=[])
check("8 zero settlements exits 2", rc == 2, f"rc={rc}")
check(
    "8 zero settlements prints no earnings line",
    "X402 EARNINGS" not in out,
    out.strip(),
)

# 9 -- a challenge with no `accepts` cannot name a seller, so nothing can be derived.
rc, out, err = drive(challenge={"x402Version": 2, "accepts": []})
check("9 empty accepts exits 2", rc == 2, f"rc={rc}")

# 10 -- chain unreachable.
rc, out, err = drive(sales=mod.Unavailable("rpc getSignaturesForAddress -> HTTP 500"))
check("10 chain down exits 2", rc == 2, f"rc={rc}")
check("10 chain down prints no earnings line", "X402 EARNINGS" not in out, out.strip())

# 11 -- the JSON mode a gate parses must carry the same figures as the human line.
rc, out, err = drive(argv=("x402_earnings.py", "--json"))
check("11 --json exits 0", rc == 0, f"rc={rc}")
check("11 --json carries chain count", '"chain_settlements": 4' in out, out.strip())
check("11 --json carries the signatures", "EkBmoDkn" in out, out.strip())

# 12 -- MUTATION CONTROL. Disable the over-claim check and REQUIRE case 5 to go red.
# Without this, every green above is consistent with a detector that never fires.
_src = Path(mod.__file__).read_text(encoding="utf-8")
_COND = "if restored > n:"
assert _COND in _src, f"mutation target {_COND!r} not in source -- control is stale"

_mutated = _src.replace(_COND, "if False:", 1)
_ns: dict = {"__name__": "mutated_x402_earnings", "__file__": mod.__file__}
exec(compile(_mutated, mod.__file__, "exec"), _ns)


def drive_mutant(health):
    _ns["challenge"] = lambda: LIVE_CHALLENGE
    _ns["_get_json"] = lambda _u, timeout=25: health
    _ns["chain_settlements"] = lambda _s, _m: LIVE_SALES
    orig_argv, sys.argv = sys.argv, ["x402_earnings.py"]
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = _ns["main"]()
    finally:
        sys.argv = orig_argv
    return rc, out.getvalue(), err.getvalue()


rc_m, out_m, _ = drive_mutant(
    {"ledger": {**LIVE_LEDGER, "restored_sales_at_startup": 5}}
)
check("12 mutant does NOT catch the over-claim", rc_m == 0, f"mutant rc={rc_m}")
check(
    "12 mutant would have printed the earnings line",
    "X402 EARNINGS" in out_m,
    out_m.strip(),
)

# 13 -- BINDS take.py TO THIS SCRIPT. The beat's OCR markers live in one file and the text
# they match lives in another, so either can drift alone and the break shows up only at the
# camera. Two directions, and the second is the one that matters: a marker satisfied by a
# FAILURE path would certify a frame showing a refusal as a good take.
_beat = next((b for b in take.BEATS if b.name == "x402-earnings"), None)
check("13 take.py registers the beat", _beat is not None)

if _beat is not None:
    rc_ok, out_ok, _ = drive()
    for marker in _beat.expect:
        check(f"13 marker in real output: {marker!r}", marker in out_ok, out_ok.strip())

    # Every refusal and inconsistency path, collected. No marker may appear in any of them.
    failure_streams = []
    for kwargs in (
        {"challenge": mod.Unavailable("/price -> URLError")},
        {"health": {"gate": "up"}},
        {"health": {"ledger": {**LIVE_LEDGER, "restored_sales_at_startup": 5}}},
        {"health": {"ledger": {**LIVE_LEDGER, "unparseable_lines_skipped": 2}}},
        {"sales": []},
        {"challenge": {"x402Version": 2, "accepts": []}},
        {"sales": mod.Unavailable("rpc -> HTTP 500")},
    ):
        _rc, _out, _err = drive(**kwargs)
        failure_streams.append(_out + _err)

    for marker in _beat.expect:
        hit = next((s for s in failure_streams if marker in s), None)
        check(
            f"13 marker absent from every failure path: {marker!r}",
            hit is None,
            f"appeared in: {hit!r}" if hit else "",
        )

    # OCR read the zero in "X402" as "@" on a frame where every glyph rendered crisply, and
    # failed a good take. Markers stay digit-free so that cannot recur silently.
    for marker in _beat.expect:
        check(
            f"13 marker is digit-free (OCR zero->@ trap): {marker!r}",
            not any(c.isdigit() for c in marker),
        )

print(f"\n{CHECKS - FAILS}/{CHECKS} checks passed")
sys.exit(1 if FAILS else 0)
