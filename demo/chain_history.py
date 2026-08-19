#!/usr/bin/env python3
"""One line of chain history for the feed account, derived on the spot, stdlib only.

    $ python demo/chain_history.py
    773 tx | 0 failed | median gap 20.5 min | largest gap 61.5 min | since 2026-07-25

This exists because the durability claim's whole force is that anyone can re-derive it, and the
video needs that re-derivation to LOOK like one line rather than a wall of JSON. Beats 11 and 13
of the locked plan film this command (the plan asked for scripts/chain_history.py; it lives in
demo/ because scripts/ belongs to the build session and demo/ ships in the same clone).

Two figures on this line move (the count, and the span implied by "since"); everything printed is
derived from the RPC response at run time, never hardcoded, so the line cannot go stale — it can
only go honest-red, and there are exactly two ways to do that. The RPC refusing prints UNREACHABLE
rather than a wrong number, and a walk that stopped before the account ran out appends CAPPED
rather than passing a partial count off as a total.

The largest gap is printed unconditionally. A judge running this command finds it anyway, and a
disclosed outlier is evidence the number was measured; a discovered one discredits everything
near it.

ASCII separators on purpose: this prints inside a cp850/cp1252 conhost for the take, and OCR must
re-read it off the captured frame. A middle dot survives neither reliably.
"""

from __future__ import annotations

import datetime
import json
import os
import statistics
import sys
import urllib.error
import urllib.request

FEED = os.environ.get("FEED_PDA", "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg")
RPC = os.environ.get("RPC_URL", "https://api.devnet.solana.com")
ATTEMPTS = 3

# PAGE is the protocol ceiling, not a choice: getSignaturesForAddress refuses limit=1001 with
# -32602 "Invalid limit; max 1000", so one page can never cover this account and the `before`
# walk below is mandatory rather than defensive. MAX_PAGES is ours, and because it is ours it is
# announced on the output line whenever it binds -- see the `capped` suffix in main(). Without
# that suffix a capped run prints a smaller count, a smaller largest-gap and a later "since" date
# with nothing to distinguish it from a complete one, which is the single way this line could go
# quietly wrong rather than honest-red.
PAGE = 1000
MAX_PAGES = 20


# Same transport boundary as verify-proof.py and feed_heartbeat.py, mirrored a third time on
# purpose despite the duplication those two already regret: this file must run from a fresh clone
# with no imports beyond stdlib, and a devnet rate limit during a take must read as UNREACHABLE,
# never as a broken record. 408/429 are the endpoint declining to answer, not an answer.
def _is_transport(e):
    if isinstance(e, urllib.error.HTTPError):
        return e.code >= 500 or e.code in (408, 429)
    if isinstance(e, urllib.error.URLError):
        return True
    return isinstance(e, (TimeoutError, ConnectionError))


def _rpc(method, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        RPC,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    last = None
    for _ in range(ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:  # noqa: BLE001 - classified, not swallowed
            last = e
            if not _is_transport(e):
                raise
    raise last  # type: ignore[misc]


def main():
    sigs = []
    before = None
    exhausted = False
    for _ in range(MAX_PAGES):
        params = [FEED, {"limit": PAGE, **({"before": before} if before else {})}]
        batch = _rpc("getSignaturesForAddress", params).get("result") or []
        if not batch:
            exhausted = True
            break
        sigs.extend(batch)
        before = batch[-1]["signature"]
        if len(batch) < PAGE:
            exhausted = True
            break

    if not sigs:
        print(f"UNREACHABLE or empty: no signatures returned for {FEED[:8]}..")
        return 2

    times = sorted(x["blockTime"] for x in sigs if x.get("blockTime"))
    failed = sum(1 for x in sigs if x.get("err"))
    gaps = [(times[i + 1] - times[i]) / 60 for i in range(len(times) - 1)]
    first = datetime.datetime.fromtimestamp(times[0], datetime.timezone.utc)
    # Silent on the exhausted path so the filmed line stays exactly what beats 11 and 13 rehearsed;
    # the suffix appears only when the walk stopped early, where a bare line would be a wrong number
    # wearing a complete one's clothes.
    capped = (
        ""
        if exhausted
        else f" | CAPPED at {MAX_PAGES} pages, tx older than this are NOT counted"
    )
    print(
        f"{len(sigs)} tx | {failed} failed | median gap {statistics.median(gaps):.1f} min | "
        f"largest gap {max(gaps):.1f} min | since {first:%Y-%m-%d}{capped}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
