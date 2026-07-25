#!/usr/bin/env python3
"""Every link in the judge-facing docs points at something that exists. (stdlib only)

    python3 scripts/check-doc-links.py

Exit 0 = every link resolves to a real object. Exit 1 = at least one is dead.

WHY THIS IS NOT AN HTTP LINK CHECKER
------------------------------------
Twenty of the links here are `explorer.solana.com` URLs, and the explorer is a
single-page app: it returns HTTP 200 for a transaction signature that does not
exist, renders "not found" in JavaScript, and a checker looking at status codes
calls that a pass. Running one would produce a green result that means nothing,
which is the failure this repo spent a day removing from three other gates.

So explorer links are not fetched at all. The signature or address is extracted
from the URL and resolved against devnet directly. A dead link fails because the
thing it points at is not on chain, which is the actual claim the link makes.

`verify-proof.py` checks the eleven curated claims. This checks every link in
every judge-facing document, which is a wider and shallower net: it will not tell
you a transaction had the wrong outcome, only that it exists.

Ordinary web links are fetched, with a browser User-Agent, because Cloudflare and
several hosts answer 403 to Python's default agent and a checker that reports a
false failure gets muted just as fast as one that reports a false pass.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RPC = os.environ.get("RPC_URL", "https://api.devnet.solana.com")
UA = "Mozilla/5.0 (compatible; zeroclaw-doc-link-check/1.0)"

DOCS = [
    "README.md",
    "QUICKSTART.md",
    "TESTING.md",
    "docs/WRITEUP-DRAFT.md",
    "docs/DEVNET-PROOF.md",
    "docs/DECISIONS.md",
]

URL_RE = re.compile(r'https?://[^\s)\]<>"`]+')
EXPLORER_TX = re.compile(r"explorer\.solana\.com/tx/([1-9A-HJ-NP-Za-km-z]+)")
EXPLORER_ADDR = re.compile(r"explorer\.solana\.com/address/([1-9A-HJ-NP-Za-km-z]+)")
# A placeholder nobody has filled in is a dead link with extra steps.
PLACEHOLDER = re.compile(
    r"<[A-Za-z][^<>\n()|$]{0,60}?\b(repo|url|fill|todo|tbd)\b[^<>\n()|$]{0,60}?>",
    re.I,
)


def rpc(method, params, attempts=4):
    """Public devnet RPC rate-limits, and a 429 is our own impatience rather than a dead link.
    A checker that reports transport noise as a failure gets muted exactly as fast as one that
    reports a false pass, so back off and retry until the endpoint actually answers."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    delay, last = 1.0, None
    for attempt in range(attempts):
        if attempt:
            time.sleep(delay)
            delay *= 2
        try:
            req = urllib.request.Request(
                RPC, data=body, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=25) as r:
                result = json.load(r).get("result")
            time.sleep(0.15)  # stay under the public limit on the happy path too
            return result
        except urllib.error.HTTPError as e:
            last = e
            if e.code != 429:
                raise
        except Exception as e:
            last = e
    raise RuntimeError(f"RPC still rate-limited after {attempts} attempts: {last}")


def check_url(url):
    """(ok, detail) for a non-explorer link."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
        with urllib.request.urlopen(req, timeout=25) as r:
            return (200 <= r.status < 400), f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def main():
    findings = []
    checked = 0
    cache = {}

    for doc in DOCS:
        path = REPO / doc
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")

        for m in PLACEHOLDER.finditer(text):
            findings.append(f"{doc}: unfilled placeholder {m.group(0)!r}")

        for url in dict.fromkeys(URL_RE.findall(text)):
            url = url.rstrip(".,;")
            checked += 1
            if url in cache:
                ok, detail = cache[url]
            elif tx := EXPLORER_TX.search(url):
                sig = tx.group(1)
                try:
                    got = rpc(
                        "getTransaction", [sig, {"maxSupportedTransactionVersion": 0}]
                    )
                    ok = got is not None
                    detail = "on chain" if ok else "NOT on chain"
                except Exception as e:
                    ok, detail = False, f"RPC error {e}"
            elif ad := EXPLORER_ADDR.search(url):
                pk = ad.group(1)
                try:
                    got = rpc("getAccountInfo", [pk, {"encoding": "base64"}])
                    if got and got.get("value"):
                        ok, detail = True, "account exists"
                    else:
                        # No account is not the same as nothing there. A Solana Pay reference
                        # is a fresh keypair used only as a read-only marker in an account
                        # list; it is never funded, so it never becomes an account, and
                        # getAccountInfo on one correctly returns null. Calling that a dead
                        # link would be a false alarm on the mechanism working as designed,
                        # and a checker that cries wolf gets muted. The signature index is
                        # what resolves a reference, and it is what payment-watch polls.
                        sigs = rpc("getSignaturesForAddress", [pk, {"limit": 1}]) or []
                        ok = bool(sigs)
                        detail = (
                            "reference (no account, appears in a tx)"
                            if ok
                            else "NOT on chain at all"
                        )
                except Exception as e:
                    ok, detail = False, f"RPC error {e}"
            else:
                ok, detail = check_url(url)
            cache[url] = (ok, detail)
            print(f"{'PASS' if ok else 'FAIL'}  {detail:<18} {url[:96]}")
            if not ok:
                findings.append(f"{doc}: {url}  ({detail})")

    print()
    print(f"{checked} link(s) checked across {len(DOCS)} judge-facing documents")
    if findings:
        print(f"\n{len(findings)} problem(s):")
        for f in findings:
            print("  -", f)
        return 1
    print("Every link points at something that exists.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
