#!/usr/bin/env python3
"""One-command verifier for every claim in docs/DEVNET-PROOF.md (stdlib only, no install).

A judge should not have to click eight explorer links or trust a screenshot. This queries
Solana devnet directly and checks that each on-chain claim still holds: the programs are
executable, the feed PDA is owned by the oracle program, and every referenced transaction
landed with the exact success/rejection this submission claims.

    python3 scripts/verify-proof.py            # checks devnet, prints PASS/FAIL per claim
    RPC_URL=https://your-rpc python3 scripts/verify-proof.py

Exit 0 = every claim verified. Exit 1 = at least one claim FAILED, meaning a thing this
repo asserts is no longer true. Exit 2 = TRANSPORT, meaning the network would not answer,
so this run has no opinion and a retry is the right response.

That third code is the point, and this docstring claimed only two of them until 2026-08-04
while the code had carried three since 2026-07-26. Folding "the RPC was unreachable" into
exit 1 tells a stranger a claim broke when nothing broke except the connection. The sibling
`feed_heartbeat.py` had the same defect, and it got the fix when this one got only the code
change, which is the instance-fixed-class-missed shape this project keeps re-finding.
"""

import base64
import json
from pathlib import Path
import os
import struct
import sys
import time
import urllib.error
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
    (
        "device feed PDA (agent-driven, historical)",
        "CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU",
        False,
    ),
    (
        "device feed PDA (deterministic LLM-free, laptop)",
        "3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K",
        False,
    ),
    (
        "device feed PDA (ARM node, node-born key)",
        "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg",
        False,
    ),
]
FEED_OWNER = "EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn"  # feed PDA must be owned by the oracle
FEED_PDAS = {
    "CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU",
    "3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K",
    "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg",
}

# Ownership alone cannot distinguish a live feed from one that stopped months ago, so the
# always-on claim gets its own check. Only the ARM node is asserted fresh: it is the feed
# that backs "yours, running". The laptop publisher is secondary by design and is allowed
# to go quiet when that machine sleeps.
LIVE_FEED = ("ARM node feed", "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg")
# Reported but NOT gating, for exactly the reason above: this one runs on a laptop that is
# allowed to sleep, so failing the run on it would train a reader to ignore a red result.
SECONDARY_FEED = (
    "laptop deterministic feed",
    "3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K",
)
# Cadence is 20 minutes. The threshold is deliberately loose so one skipped reading (a
# transient upstream weather-API failure, which the publisher refuses to paper over with a
# fabricated value) does not read as a dead node.
# Overridable so the gate can be demonstrated rather than trusted: run
#   MAX_FEED_AGE_MIN=0 python3 scripts/verify-proof.py
# and the live check goes red with exit 1 while every static claim stays green. A liveness
# check nobody has watched fail is indistinguishable from one that cannot fail.
MAX_FEED_AGE_MIN = int(os.environ.get("MAX_FEED_AGE_MIN", "90"))

# The laptop publisher fires on this cadence. Used only to decide whether a publish
# ATTEMPT is recent enough to be meaningful, never to gate anything.
PUBLISH_CADENCE_MIN = 20

# Written by .tools/feed_publish_hidden.vbs on every run, including failed ones.
# Gitignored with the rest of .devnet-proof, so a fresh clone simply has no file here
# and the helper below returns None, which is the correct answer for a machine that
# does not run the publisher at all.
_ATTEMPT_LOG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".devnet-proof",
    "feed-attempt.log",
)


def attempt_heartbeat():
    """Age in minutes of the last publish attempt, plus how it ended.

    This exists because of a real 2026-07-26 failure. The WSL VM wedged, the publisher
    stopped running entirely, and NOTHING went red: the launcher was fire-and-forget so
    it returned 0, Task Scheduler logged ~20 consecutive successes with zero missed
    runs, and this script called a 6.6-hour-dead feed "quiet (allowed)". The publish log
    could not help either, because a script that never executes cannot write its own
    failure line.

    The root problem was that two very different situations produced an identical
    signature: a laptop that was switched off, and a publisher that ran and failed, both
    just stop appending to the publish log. The launcher now records every attempt before
    and after it runs, so the two can be told apart here.

    Returns (age_min, outcome) where outcome is "rc=N" or "no result, killed mid-run",
    or (None, None) when there is no log to read.
    """
    try:
        age_min = (time.time() - os.path.getmtime(_ATTEMPT_LOG)) / 60.0
        lines = [
            ln.strip()
            for ln in open(_ATTEMPT_LOG, "r", encoding="utf-8", errors="replace")
            if ln.strip()
        ]
    except Exception:
        return None, None

    if not lines:
        return age_min, "empty log"
    # A trailing "start" with no "rc=" after it means the run hung and was killed by the
    # task's execution time limit before it could record an outcome.
    last = lines[-1]
    return age_min, last if last.startswith("rc=") else "no result, killed mid-run"


# The shop half of "Both are running". Checked because the node and the shop fail
# independently: the node is Oracle Cloud systemd, the shop is a laptop daemon plus a CDN
# page, so the node can publish happily through a completely dead shop.
SHOP_PAY_URL = os.environ.get("SHOP_PAY_URL", "https://zeroclaw-shop-pay.pages.dev/")
# Asserted inside the page body: HTTP 200 only proves a CDN answered, while the pinned
# merchant address is what makes it this shop's page rather than any page.
MERCHANT_PIN = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
# The shop daemon's own liveness, asked of systemd inside the box and served over the
# node's named tunnel. This is the signal the pay-page check structurally cannot carry: the
# page is a CDN asset that answers whether or not the daemon runs, so until this endpoint
# existed a dead shop and a quiet one were the same observation from outside.
SHOP_HEALTH_URL = os.environ.get("SHOP_HEALTH_URL", "https://x402.perfpilot.dev/health")
# DeviceFeed: disc8 + authority32 + device32 + feed_kind1 + value_i64 + scale_i8
#           + unit[12] + sequence_u64 + observed_at_i64 + published_at_i64 + bump1
FEED_LEN = 8 + 32 + 32 + 1 + 8 + 1 + 12 + 8 + 8 + 8 + 1

# (label, signature, want_err)  want_err=None means success (err:null)
TXS = [
    (
        "shop Track-A settlement (payment_watch PAID)",
        "4kDo6NCcAxSe3BSTtQ4onTASenxRWr2miagweVway3RnDMLG7drv6NkTdV7eRtTSDcNXURy2ESpKcqkk2jG9sYqS",
        None,
    ),
    (
        "x402 machine-commerce settlement",
        "EkBmoDknDryQpDtD6hnLoCdhhRjAo3Vmn15VmkQi7niqYHnK5XYL8FpxLabDiQ2S2QuTdD3vsTXMSra72LXgApE",
        None,
    ),
    (
        "allowance within-cap transfer (succeeds)",
        "5qyr7jJi8zb6SjZjnA2QT5C9nuZYgSw6raAefjmWnDDMf3JRgkQX19zssE57EpFSHVCCPfbj5qyxcYSQcfEq9W3Z",
        None,
    ),
    # 300 is AmountExceedsLimit in the solana-foundation program's own errors.rs and IDL;
    # the citation is in docs/MAINNET-PROOF.md rather than assumed here.
    (
        "allowance OVER-cap transfer (rejected 0x12c)",
        "3TLSrfWVYdC3hSiAWnyyd7T694bLJQDtdJYQ64EWUsBNDehGc6Kq1veR7xa8Y1BiMdpvfFm3N1dKjDrXF3BEq2ps",
        {"InstructionError": [0, {"Custom": 300}]},
    ),
]


# Three attempts, ~1s then ~2s apart. Deliberately small: enough to ride out a blip,
# short enough that a genuinely unreachable RPC still fails the run promptly.
RPC_ATTEMPTS = 3

# The retry budget is GLOBAL, not per call, and that is the load-bearing part. Per call
# it looks cheap, but this script makes a dozen gating checks, so against an RPC that
# HANGS rather than refuses the worst case is attempts x timeout x checks, which is
# minutes of a reader staring at nothing. One shared budget means a genuinely dead
# endpoint costs the retries once and every later check fails fast.
RETRY_BUDGET_S = 25.0
_retry_spent = 0.0


def rpc(method, params):
    """One JSON-RPC call, retrying only a TRANSPORT failure.

    proof-check.yml already retries the whole script on a transport blip, so CI was
    resilient to a flaky network and a human running this by hand was not. That is
    backwards for the artifact whose entire job is letting a stranger re-verify the
    claims: a reader on hotel wifi got a red result while every claim still held.

    Retrying HERE is safe, and safe by construction rather than by a heuristic, which
    is the part worth keeping. The transport-versus-claim distinction this file is
    careful about survives because a claim that stopped holding does not raise. It
    arrives as a SUCCESSFUL response carrying a different value, and is judged by the
    caller. This function only ever sees the network refusing, so it can never retry a
    broken claim into looking healthy.
    """
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    global _retry_spent
    for attempt in range(RPC_ATTEMPTS):
        started = time.monotonic()
        req = urllib.request.Request(
            RPC, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.load(r).get("result")
        except Exception as e:
            # A non-transport error is the caller's to see immediately, and the last
            # attempt re-raises so an unreachable RPC still exits as a transport
            # failure with its original exception rather than a synthesised one.
            if not is_transport_error(e) or attempt == RPC_ATTEMPTS - 1:
                raise
            # Charge BOTH the failed attempt and the pause to the shared budget. The
            # attempt is the expensive half when the endpoint hangs, so a budget that
            # counted only sleeps would not bound anything.
            _retry_spent += time.monotonic() - started
            if _retry_spent >= RETRY_BUDGET_S:
                raise
            pause = 1.0 * (attempt + 1)
            time.sleep(pause)
            _retry_spent += pause


def read_feed(addr):
    """Decode a DeviceFeed account. Returns (reading, seq, age_min) or raises."""
    v = rpc("getAccountInfo", [addr, {"encoding": "base64"}])
    val = v.get("value") if v else None
    raw = base64.b64decode(val["data"][0]) if val else b""
    if len(raw) != FEED_LEN:
        raise ValueError(f"unexpected account length {len(raw)}")
    o = 8 + 32 + 32 + 1
    value = struct.unpack_from("<q", raw, o)[0]
    o += 8
    scale = struct.unpack_from("<b", raw, o)[0]
    o += 1
    unit = raw[o : o + 12].rstrip(b"\x00").decode("ascii", "ignore")
    o += 12
    seq = struct.unpack_from("<Q", raw, o)[0]
    o += 8 + 8
    published = struct.unpack_from("<q", raw, o)[0]
    return f"{value * (10**scale):.2f} {unit}", seq, (time.time() - published) / 60


def is_transport_error(e):
    """True when the network refused, rather than a claim failing to hold.

    CI needs this distinction and could not previously get it. proof-check retries a
    transport blip but must NOT retry a claim that stopped holding, and it decided which
    was which by grepping this script's own output for words like "unreachable". That
    grep reads the whole log, including the SECONDARY feed line, which is non-gating and
    prints exactly that word when its read fails. So a genuine broken claim landing in the
    same run as a secondary-read blip was classified as transport, retried three times,
    and finally reported as an RPC problem rather than as the claim that actually broke.

    An exit code cannot be misread that way, so the script now says which kind of failure
    it had and the workflow branches on a number instead of on a sentence.
    """
    if isinstance(e, urllib.error.HTTPError):
        # 429 and 408 are TRANSPORT, and reading them as claim failures was a real defect
        # rather than a theoretical one. A public Solana RPC rate-limits routinely, so a
        # reader on a shared endpoint got a red verdict reported as "this claim stopped
        # holding" when the chain had not been consulted at all. That is the worst possible
        # direction for this script to be wrong in: it is the artifact whose whole job is
        # letting a stranger re-verify, and it was telling some of them the proofs broke.
        #
        # Both are safe to retry for the same reason the docstring above gives: a claim
        # that stopped holding arrives as a SUCCESSFUL response carrying a different value,
        # so it never reaches this function and can never be retried into looking healthy.
        return e.code >= 500 or e.code in (408, 429)
    if isinstance(e, urllib.error.URLError):
        return True
    return isinstance(e, (TimeoutError, ConnectionError))


def main():
    fails = 0
    static_fails = 0
    # Counted only for GATING checks. The secondary feed never gates, so its transport
    # trouble must not make a real failure elsewhere look retryable, which is the exact
    # confusion this replaces.
    transport_fails = 0
    print(f"verifying docs/DEVNET-PROOF.md against {RPC}\n")
    print(
        "STATIC claims -- the record. These are immutable devnet history and deployed"
    )
    print(
        "program state; once true they stay true, so they prove the work happened, NOT"
    )
    print("that anything is running right now.\n")
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
            if addr in FEED_PDAS and val.get("owner") != FEED_OWNER:
                print(f"FAIL  {label}: wrong owner {val.get('owner')}")
                fails += 1
                continue
            extra = "executable" if want_exec else f"owner={val.get('owner')[:8]}"
            print(f"PASS  {label} ({extra})")
        except Exception as e:
            print(f"FAIL  {label}: RPC error {e}")
            fails += 1
            if is_transport_error(e):
                transport_fails += 1

    # A transaction the RPC will not serve has THREE possible causes and only one of
    # them is a broken claim. Public devnet prunes after about four days, so a
    # transaction older than that is absent from the endpoint while remaining a real,
    # settled transaction. Reporting that as a claim that stopped holding is a false
    # red, and a checker that cries wolf trains a reader to ignore it.
    # So: when the RPC has nothing, fall back to the captured bundle and verify the
    # signature offline. If it verifies there, the claim holds and the endpoint is
    # simply the wrong instrument for it.
    bundle_txs = {}
    bundle_path = (
        Path(__file__).resolve().parent.parent
        / "docs"
        / "proof-bundle"
        / "devnet-transactions.json"
    )
    if bundle_path.exists():
        try:
            bundle_txs = json.loads(bundle_path.read_text(encoding="utf-8")).get(
                "transactions", {}
            )
        except Exception:
            bundle_txs = {}

    def verified_offline(sig: str) -> bool:
        """True iff the captured bundle proves this transaction by signature."""
        entry = bundle_txs.get(sig)
        if not entry or entry.get("status") != "CAPTURED":
            return False
        try:
            import subprocess

            r = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parent / "verify_proof_offline.py"),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
            )
            return r.returncode == 0 and sig[:16] in r.stdout
        except Exception:
            return False

    for label, sig, want_err in TXS:
        try:
            t = rpc("getTransaction", [sig, {"maxSupportedTransactionVersion": 0}])
            if not t:
                if verified_offline(sig):
                    print(
                        f"PASS  {label}: pruned by the endpoint, verified offline from the bundle"
                    )
                else:
                    print(
                        f"FAIL  {label}: tx not found, and no captured bytes to verify offline"
                    )
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
            if is_transport_error(e):
                transport_fails += 1

    static_fails = fails

    print(
        "\nLIVE claims -- the only checks here that can go red. Everything above stays"
    )
    print("green whether or not a single machine of ours is switched on.\n")

    label, addr = LIVE_FEED
    try:
        reading, seq, age_min = read_feed(addr)
        if age_min > MAX_FEED_AGE_MIN:
            print(
                f"FAIL  {label} freshness: last reading {age_min:.0f} min ago "
                f"(> {MAX_FEED_AGE_MIN}); the node is not publishing"
            )
            fails += 1
        else:
            print(
                f"PASS  {label} freshness ({reading}, seq={seq}, {age_min:.0f} min ago)"
            )
    except Exception as e:
        print(f"FAIL  {label} freshness: {e}")
        fails += 1
        if is_transport_error(e):
            transport_fails += 1

    # Reported, never gating. This publisher runs on a laptop that is allowed to sleep, so
    # failing the whole run on it would teach a reader that a red line here means nothing,
    # which is how a liveness check stops being one.
    label, addr = SECONDARY_FEED
    try:
        reading, seq, age_min = read_feed(addr)
        if age_min <= MAX_FEED_AGE_MIN:
            print(
                f"INFO  {label}: fresh ({reading}, seq={seq}, {age_min:.0f} min ago, "
                f"not gating)"
            )
        else:
            # Stale. Two very different causes, and until 2026-07-26 they were
            # indistinguishable here, which let a dead publisher read as "allowed" for
            # 6.6 hours. The attempt heartbeat separates them.
            beat_age, outcome = attempt_heartbeat()
            recent_attempt = (
                beat_age is not None and beat_age <= 2 * PUBLISH_CADENCE_MIN
            )
            if recent_attempt:
                print(
                    f"WARN  {label}: stale AND the publisher is still firing "
                    f"({reading}, seq={seq}, {age_min:.0f} min ago; last attempt "
                    f"{beat_age:.0f} min ago, {outcome}). It is running and not "
                    f"landing, so this is broken rather than asleep. Still not "
                    f"gating: the ARM node above carries the claim."
                )
            else:
                detail = (
                    "no publish attempt logged recently, so this machine was away"
                    if beat_age is None
                    else f"last attempt {beat_age:.0f} min ago, so this machine was away"
                )
                print(
                    f"INFO  {label}: quiet (allowed) ({reading}, seq={seq}, "
                    f"{age_min:.0f} min ago; {detail}, not gating)"
                )
    except Exception as e:
        print(f"INFO  {label}: unreadable ({e}, not gating)")

    # The shop is the other headline use case, and until now nothing in this script touched
    # it. An audit put the hole precisely: the ARM node runs on Oracle Cloud systemd,
    # independent of the shop, so a dead shop plus a publishing node printed a clean bill of
    # health.
    #
    # HONEST SCOPE, because the first version of this comment overclaimed. What follows
    # checks a STATIC Cloudflare Pages asset. That page is served by a CDN and answers 200
    # whether or not the shop daemon is running, so this does NOT detect a dead daemon and
    # does NOT by itself close the false-green. Demonstrated the day it was written: the WSL
    # VM hosting the daemon was wedged (marked Running, unresponsive past 45s) while this
    # check would still have passed on pin presence alone.
    #
    # What it DOES prove is narrower and still worth gating on: that the deployed page is
    # the pinned build rather than a stale one. That is a real regression class, since the
    # merchant pin is the control standing between a swapped recipient and a transfer.
    # Detecting a dead daemon needs a signal from the daemon itself (a health endpoint or a
    # channel round-trip) and is tracked separately rather than pretended at here.
    try:
        req = urllib.request.Request(
            SHOP_PAY_URL, headers={"User-Agent": "Mozilla/5.0 (verify-proof)"}
        )
        # Read a generous cap rather than 64 KiB, and DISTINGUISH a truncated read from a
        # genuine absence. The old 65536 was a silent time bomb: the pin sat at byte 63,009
        # until the page grew by 2,545 bytes, which pushed it to 65,554 and put it EIGHTEEN
        # bytes past the cut. The gate then reported "merchant pin MISSING" about a page
        # serving the correct pin, which is the worst possible wording -- it names a
        # swapped-recipient regression when the real event was the page getting longer.
        # A cap is still right (an attacker-controlled body should not be read unbounded),
        # so the fix is to notice when the cap was reached instead of reasoning past it.
        CAP = 2_000_000
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read(CAP + 1)
        truncated = len(raw) > CAP
        body = raw[:CAP].decode("utf-8", "replace")
        # 200 alone only proves a CDN answered. The pinned merchant address is what makes
        # the page the shop's page rather than any page, so that is what is asserted.
        if r.status == 200 and MERCHANT_PIN in body:
            print(f"PASS  shop pay page reachable and pinned to the shop ({r.status})")
        elif truncated:
            print(
                f"FAIL  shop pay page: HTTP {r.status}, body exceeded the {CAP:,}-byte read "
                f"cap, so the merchant pin was NOT SEARCHED rather than found absent"
            )
            fails += 1
        else:
            print(
                f"FAIL  shop pay page: HTTP {r.status}, merchant pin "
                f"MISSING from {len(body):,} bytes read in full"
            )
            fails += 1
    except Exception as e:
        print(f"FAIL  shop pay page unreachable: {e}")
        fails += 1
        if is_transport_error(e):
            transport_fails += 1

    # The check the two above structurally cannot make. Both of them observe things OUTSIDE
    # the shop: a feed the node publishes, and a page a CDN serves. Neither can distinguish a
    # shop that is quiet from one that is stopped, which is the whole reason the 2026-07-26
    # outage sat unnoticed. This asks systemd, inside the box, and the answer travels out over
    # the node's named tunnel.
    #
    # WHAT IS GATED, and why it is not the obvious field. The gate is the unit's state, not
    # how recently it handled traffic. A shop nobody has messaged for six hours is healthy and
    # gating on trace age would paint it red, which is how a liveness line stops meaning
    # anything to whoever reads it next. The age is printed because it is worth seeing and
    # never asserted on.
    # Bound before the try so an unreachable endpoint leaves it None rather than undefined.
    # The x402 ledger check below reads it, and an unbound name there would raise inside the
    # verifier itself, which is the one place a crash reads as "the claim could not be
    # checked" when it actually means "the checker is broken".
    health = None
    try:
        req = urllib.request.Request(
            SHOP_HEALTH_URL, headers={"User-Agent": "Mozilla/5.0 (verify-proof)"}
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            health = json.loads(r.read(65536).decode("utf-8", "replace"))
        shop = health.get("shop") or {}
        # .get with no default, so a field the endpoint stops sending reads as None and fails
        # rather than defaulting to something that passes.
        alive = shop.get("active") is True and shop.get("state") == "active"
        age_s = shop.get("trace_age_seconds")
        age_note = (
            f"last handled traffic {age_s / 60:.0f} min ago"
            if isinstance(age_s, (int, float))
            else "traffic age not reported"
        )
        if r.status == 200 and alive:
            print(
                f"PASS  shop agent process alive per systemd "
                f"({shop.get('unit')}, {shop.get('state')}; {age_note}, not gating)"
            )
        else:
            print(
                f"FAIL  shop agent liveness: HTTP {r.status}, unit "
                f"{shop.get('unit')!r} state {shop.get('state')!r} "
                f"active={shop.get('active')!r}"
            )
            fails += 1
    except Exception as e:
        print(f"FAIL  shop agent /health unreachable: {e}")
        fails += 1
        if is_transport_error(e):
            transport_fails += 1

    # CLAIM: a receipt this shop sent actually reached a customer.
    #
    # Every check above observes a PROCESS or a PAGE. None of them can tell a shop whose
    # send path is refused from one that is serving customers, because a live process with
    # a dead channel passes all three. The gate now reads the settlement announcer's own
    # record of what it delivered and reports it here, which is the first signal in this
    # file that is an EFFECT of the channel working rather than a state around it.
    #
    # WHY THE ANNOUNCER RATHER THAN THE SHOP DAEMON. The announcer is a shell script that
    # never consults a model, and its `sent:` and `SEND FAILED` lines are the receipt
    # actually landing or not. The shop daemon's log cannot answer this: the announcer is a
    # separate unit whose stdout goes to the journal, so a reader pointed at the daemon log
    # would scan forever and never see a delivery.
    #
    # NOT GATED, and that is a decision rather than caution. A gate on live box state can
    # turn main red with no repo change, and a channel reconnect is exactly the transient
    # that would do it. It is also not gateable on the merits: the announcer sends only when
    # a payment settles, so an absence of receipts is what a quiet Tuesday looks like as much
    # as what a broken send path looks like, and a red that means either means neither.
    #
    # SO ONLY `connected` IS EVIDENCE. Everything else prints what is missing and asserts
    # nothing, including the empty case, which must not be read as an outage.
    rc = (health or {}).get("receipts")
    if health is None:
        # /health already failed above with its own reason. A second line about a block
        # inside a body nobody received would be noise dressed as a finding.
        pass
    elif rc is None:
        print(
            "PEND  receipt delivery not yet observable: the deployed gate predates the "
            "/health receipts block. Not gating. It becomes a live claim on the next deploy."
        )
    else:
        # .get with no default throughout, so a field the endpoint stops sending reads as
        # None and is reported as malformed rather than defaulting into something quiet.
        d = rc.get("delivery")
        scanned = rc.get("lines_scanned")
        found = rc.get("records_found")
        if (
            not isinstance(d, dict)
            or not isinstance(scanned, int)
            or not isinstance(found, int)
        ):
            print(
                f"INFO  receipt delivery block malformed: delivery={type(d).__name__}, "
                f"lines_scanned={scanned!r}, records_found={found!r}; not gating"
            )
        elif rc.get("log_readable") is not True:
            print(
                f"INFO  receipt delivery unknown: the announcer's record could not be read "
                f"({rc.get('detail')}). Nothing is claimed either way, not gating"
            )
        else:
            status = d.get("status")
            age = d.get("last_success_age_seconds")
            chan = d.get("channel")
            run = rc.get("last_run") or {}
            # The denominator travels with the count, always. A zero out of zero lines and
            # a zero out of hundreds are different verdicts about this instrument, and only
            # one of them is a statement about the shop.
            basis = f"{found} delivery record(s) in {scanned} line(s) read from {rc.get('source')}"
            run_note = ""
            if isinstance(run.get("announced"), int):
                committed = (
                    "committed" if run.get("ledger_committed") else "NOT committed"
                )
                run_note = (
                    f"; last run announced {run['announced']}, ledger {committed}"
                )
            if status == "connected":
                mins = (
                    f"{age / 60:.0f} min ago"
                    if isinstance(age, (int, float))
                    else "age unreported"
                )
                print(
                    f"INFO  receipt delivery: a receipt landed {mins} ({basis}){run_note}, "
                    f"not gating"
                )
            elif status == "failing":
                where = f" via {chan}" if chan else ""
                # The attempt age, NOT the success age, which is null here and must stay
                # null: nothing was delivered. Printing it is the whole point of the
                # separate field, because a refusal minutes old is a transient the next
                # tick may clear and one weeks old is an outage nobody noticed.
                att = d.get("last_attempt_age_seconds")
                when = (
                    f" {att / 60:.0f} min ago"
                    if isinstance(att, (int, float))
                    else " at an unknown time"
                )
                print(
                    f"INFO  receipt delivery: the newest send FAILED{where}{when} ({basis})"
                    f"{run_note}. This is positive evidence of a broken send path, but it is "
                    f"live box state, so it is reported and not gated"
                )
            elif status == "stale":
                print(
                    f"INFO  receipt delivery: newest receipt is older than the window "
                    f"({basis}){run_note}. Not evidence of health and not evidence of an "
                    f"outage either, not gating"
                )
            else:
                print(
                    f"INFO  receipt delivery: no datable delivery found ({basis}){run_note}. "
                    f"A shop that sold nothing produces exactly this, so it reads as an "
                    f"absence of sales rather than a fault, not gating"
                )

    # CLAIM: the x402 daily cap survives a restart.
    #
    # The gate rebuilds its spend ledger and its redeemed nonces from the earnings log at
    # boot, because the unit is Restart=always and a counter living only in process memory
    # would hand every payer a fresh full allowance on every restart. That property was
    # asserted in the write-up and its only evidence was a line on the node's stderr, which
    # is readable by the operator and by nobody else.
    #
    # THREE OUTCOMES, NOT TWO, following the same reasoning as the RPC corroboration in
    # payment-watch. A coherent ledger block passes. An incoherent one fails. A block that is
    # ABSENT means the node is running a build older than this check, which is a true and
    # useful thing to report and is NOT the same statement as "the cap is broken", so it
    # prints PENDING and does not gate. Collapsing "not deployed yet" into a red would make
    # the red mean two different things, and a signal that means two things means neither.
    ledger_gates = False
    led = (health or {}).get("ledger")
    if led is None:
        print(
            "PEND  x402 cap-restart not yet observable: the deployed gate predates the "
            "/health ledger block. Not gating. It becomes a live claim on the next deploy."
        )
    else:
        # .get with no default throughout, so a field the endpoint stops sending reads as
        # None and fails rather than defaulting into something that passes.
        restored = led.get("restored_sales_at_startup")
        nonces = led.get("redeemed_nonces")
        settled = led.get("settled_atomic_units")
        cap = led.get("daily_cap_atomic_units")
        healthy = led.get("lock_healthy")
        skipped = led.get("unparseable_lines_skipped")
        shaped = all(
            isinstance(x, int) for x in (restored, nonces, settled, cap, skipped)
        )
        ledger_gates = True
        if not shaped or healthy is not True:
            print(
                f"FAIL  x402 ledger block malformed or lock poisoned: restored={restored!r} "
                f"nonces={nonces!r} settled={settled!r} cap={cap!r} healthy={healthy!r}"
            )
            fails += 1
        elif settled > 0 and restored == 0:
            # The one internally contradictory state: the node has settled sales in memory
            # while claiming it restored none. Either the earnings log is not being written
            # or it is not being read, and both break the cap across the next restart.
            print(
                f"FAIL  x402 ledger inconsistent: {settled} atomic units settled but 0 sales "
                "restored at startup, so the earnings log is not round-tripping"
            )
            fails += 1
        else:
            note = (
                f"restored {restored} sale(s), {nonces} redeemed nonce(s), "
                f"{settled} atomic units against a {cap} cap"
            )
            skip_note = (
                f"; {skipped} unparseable line(s), restored spend is a lower bound"
                if skipped
                else ""
            )
            if restored == 0:
                # Honest: zero restored is also what a node that has genuinely never sold
                # anything reports, so it is not evidence of survival on its own.
                print(
                    f"PASS  x402 ledger block coherent ({note}{skip_note}). Zero restored is "
                    "consistent with a node that has not sold yet, so this is a shape check "
                    "until a sale exists."
                )
            else:
                print(
                    f"PASS  x402 daily cap survived the last restart ({note}{skip_note})"
                )

    # THE BOX'S OWN DRIFT VERDICT. deploy/box_selfcheck.py runs on the node and asserts that the
    # deployed skills and tools are byte-identical to a named commit, that the network-bearing
    # config fields still say mainnet, and that no funds-critical constant has drifted into state.
    # That verdict is worth more than anything reachable from outside, because it can see deployed
    # bytes and running services that an external prober cannot see at all -- but only if somebody
    # retrieves it. This is that somebody.
    #
    # FOUR OUTCOMES, and the HTTP status carries the distinction rather than the body:
    #   404  the deployed gate predates the /selfcheck route     -> PENDING, does not gate
    #   503  route present, no verdict on disk                    -> FAIL, the timer is not running
    #   200  a verdict                                            -> judged on `ok` and freshness
    #   anything else / unreachable                               -> FAIL
    # 404 and 503 must stay distinguishable. Collapsing them would make one red mean either "we
    # have not shipped this yet" or "the check silently stopped running", and those need opposite
    # responses.
    selfcheck_gates = False
    sc_url = os.environ.get(
        "SHOP_SELFCHECK_URL", "https://x402.perfpilot.dev/selfcheck"
    )
    # An hour of slack on top of the hourly timer, so one missed tick is not an alarm while a
    # stopped timer still is.
    max_age = int(os.environ.get("MAX_SELFCHECK_AGE_S", "7800"))
    try:
        req = urllib.request.Request(
            sc_url, headers={"User-Agent": "Mozilla/5.0 (verify-proof)"}
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            sc = json.loads(r.read(65536).decode("utf-8", "replace"))
        selfcheck_gates = True
        age = sc.get("age_seconds")
        ok = sc.get("ok")
        checks = sc.get("checks")
        sha = sc.get("deployed_sha")
        if not isinstance(age, int) or not isinstance(checks, list) or ok is None:
            print(
                f"FAIL  box self-check malformed: age={age!r} ok={ok!r} "
                f"checks={type(checks).__name__}"
            )
            fails += 1
        elif age > max_age:
            # A stale verdict is the failure this endpoint exists to make visible: the box would
            # otherwise keep serving an old green answer forever with nothing to indicate the
            # check had stopped running.
            print(
                f"FAIL  box self-check is {age}s old (limit {max_age}s), so the hourly timer is "
                "not running and the served verdict describes the past"
            )
            fails += 1
        elif ok is not True:
            bad = [c.get("name") for c in checks if c.get("ok") is not True]
            print(f"FAIL  box has DRIFTED from {sha}: {', '.join(map(str, bad))}")
            fails += 1
        else:
            print(
                f"PASS  box matches {sha} on all {len(checks)} invariants "
                f"(verdict {age}s old)"
            )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(
                "PEND  box self-check not yet observable: the deployed gate predates the "
                "/selfcheck route. Not gating. It becomes a live claim on the next deploy."
            )
        elif e.code == 503:
            print(
                "FAIL  box self-check endpoint is live but has no verdict to serve, so the "
                "hourly timer is not installed or not running"
            )
            selfcheck_gates = True
            fails += 1
        else:
            print(f"FAIL  box self-check returned HTTP {e.code}")
            selfcheck_gates = True
            fails += 1
    except Exception as e:
        # Distinct from the two above: this is transport, not a verdict. It still gates, because a
        # node nobody can reach is a real problem, but the message must not read as drift.
        print(f"FAIL  box self-check unreachable: {e}")
        selfcheck_gates = True
        fails += 1

    # Report the two kinds separately, because collapsing them into one number is exactly
    # how a dead system prints a clean bill of health. An audit put it plainly: of the
    # eleven claims this script used to total, ten were deployed-program state or immutable
    # transaction history, and one could actually go red. "11/11 verified" therefore read
    # as a liveness proof while being almost entirely a record of the past.
    static_total = len(ACCOUNTS) + len(TXS)
    # The ARM feed, the shop pay page, and the shop daemon's own systemd state. The laptop
    # feed is reported but never gates.
    # Three, not two, because "Both are running" is a claim about two independent systems and
    # the first two checks only ever observed things outside the shop. The third is the one
    # that can actually go red when the shop dies.
    # Four once the node serves the ledger block, three until then. The total is derived from
    # what actually gated rather than hardcoded, so a PENDING x402 claim cannot be counted as
    # a verified one, and the number rises on its own the moment the deploy lands. A constant
    # here would either overstate today or need remembering later.
    # Both optional claims are counted the same way and for the same reason: derive the total from
    # what actually gated, so a PENDING claim can never be tallied as a verified one and the number
    # rises by itself when the deploy lands. A constant here would either overstate today or need
    # remembering later, and nobody remembers later.
    live_total = 3 + (1 if ledger_gates else 0) + (1 if selfcheck_gates else 0)
    live_fails = fails - static_fails
    print(
        f"\n{static_total - static_fails}/{static_total} static claims verified "
        f"(deployed state and immutable devnet history; these cannot go red)"
    )
    print(
        f"{live_total - live_fails}/{live_total} live claims verified "
        f"(ARM feed publishing now; pay page is the pinned build; shop daemon alive)"
    )
    # Keep naming what this tier still cannot see, because a count that grew is exactly when
    # a reader starts assuming it covers everything. Both systems in "Both are running" now
    # have a check that can go red. What none of them prove is that the shop can complete a
    # job: /health reports the process, not the channel binding to WhatsApp or Telegram and
    # not the model provider behind it. The endpoint says so itself in its own `proves`
    # field, and only a synthetic round-trip through a real channel would close that.
    print(
        "      NOT covered above: whether the shop can complete a job end to end. "
        "/health reports the process, not the channel binding or the model provider."
    )
    if fails == 0:
        print(
            "\nThe record holds, the feed is live, and the shop daemon answered for itself."
        )
        sys.exit(0)

    # Three exit codes rather than two, because CI has to tell these apart and was
    # previously guessing from prose.
    #   0  every claim holds
    #   2  every GATING failure was the network refusing. Safe to retry.
    #   1  at least one claim stopped holding. Never retry this; it is the finding.
    # Mixed runs deliberately exit 1: if anything substantive broke, the presence of a
    # transport blip alongside it must not downgrade the verdict.
    if transport_fails == fails:
        print(
            f"\nAll {fails} gating failure(s) were transport, not claims. "
            f"Exiting 2 so a retry is allowed."
        )
        sys.exit(2)
    print(
        f"\n{fails - transport_fails} of {fails} gating failure(s) are claims that "
        f"stopped holding. Exiting 1; this is not a transport problem."
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
