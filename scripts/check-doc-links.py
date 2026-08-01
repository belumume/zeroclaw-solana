#!/usr/bin/env python3
"""Every link in a tracked document points at something that exists. (stdlib only)

    python3 scripts/check-doc-links.py

Exit 0 = every link resolves to a real object. 1 = at least one is dead. 2 = could not verify.

SCOPE IS DERIVED, AND THAT IS A FIX RATHER THAN A STYLE CHOICE
--------------------------------------------------------------
This enumerated six documents by hand until 2026-07-27. Plugin READMEs were not among them, which
is how a dead explorer link sat in `plugins/depin-attest/README.md` through every green run of
this checker: the link was never looked at, so the gate could not have found it however correct
its logic was. A hand-maintained scope does not stay wrong, it goes wrong later, because the list
is edited by whoever remembers and the repo grows by whoever ships.

Scope is now every tracked markdown file, because a reader receives exactly the tracked tree. The
six former entries survive only as a canary: if the derivation ever stops finding them, that is a
broken instrument rather than a clean repo, and this exits 2 instead of pretending.

WHY THIS IS NOT AN HTTP LINK CHECKER
------------------------------------
Most links here are `explorer.solana.com` URLs, and the explorer is a
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
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RPC = os.environ.get("RPC_URL", "https://api.devnet.solana.com")
UA = "Mozilla/5.0 (compatible; zeroclaw-doc-link-check/1.0)"

# NOT the scope. These are the six documents this checker used to enumerate, kept as a floor: any
# derivation that stops returning them has broken, and a broken derivation reports a clean tree.
CANARY = (
    "README.md",
    "QUICKSTART.md",
    "TESTING.md",
    "docs/WRITEUP.md",
    "docs/DEVNET-PROOF.md",
    "docs/DECISIONS.md",
)

# Three shapes that are ILLUSTRATIONS of a URL rather than URLs. Fetching any of them is
# meaningless: the first cannot be encoded at all, the second is a documented shape whose secret was
# deliberately removed, and the third names a service on the READER's machine.
# They are reported as skipped rather than dropped, because a link nobody checked should say so.
ABBREVIATED = re.compile(
    r"[^\x00-\x7f]"
)  # a prose ellipsis, so the URL is a display fragment
REDACTED_QUERY = re.compile(r"REDACTED|YOUR[_-]|xxxxx", re.I)

# A loopback address resolves to whoever runs the checker, so fetching it measures the runner and
# not the documentation. It is worse than permanently red: QUICKSTART's `ssh -L 8899:127.0.0.1:8899`
# illustration went red on CI and would go GREEN on a reader's machine running the local validator
# or `scripts/qr_live_server.py`, both of which QUICKSTART tells them to start. A check whose result
# depends on unrelated local state is not a check, so this class is skipped on both outcomes rather
# than being left to flip.
LOOPBACK = re.compile(
    r"^https?://(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)(?::\d+)?(?:[/?#]|$)", re.I
)


def tracked_markdown():
    """Every markdown file a cloner receives. Raises rather than returning a short list."""
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "*.md"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if out.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {out.stderr.strip()[:200]}")
    docs = [p for p in out.stdout.splitlines() if p]
    missing = [c for c in CANARY if c not in docs]
    if missing:
        raise RuntimeError(f"derivation lost known documents: {', '.join(missing)}")
    return docs


URL_RE = re.compile(r'https?://[^\s)\]<>"`]+')
EXPLORER_TX = re.compile(r"explorer\.solana\.com/tx/([1-9A-HJ-NP-Za-km-z]+)")
EXPLORER_ADDR = re.compile(r"explorer\.solana\.com/address/([1-9A-HJ-NP-Za-km-z]+)")
# A placeholder nobody has filled in is a dead link with extra steps. Scoped to the promise this
# was built to catch, an unfilled repo URL, and deliberately NOT to a bare "url": widening the
# scope brought in skills/, where `<the full URL>` is a command template an agent fills at call
# time rather than a promise to a reader. Flagging that is a false alarm on a file working as
# designed, and TESTING.md and ci.yml both already describe this check as the repo-URL one.
# The opening guard is a LOOKAHEAD rather than a consuming class, and that is load-bearing: the
# consuming form ate the "r" of "<repo URL>", so once "url" left the alternation the one shape
# this check exists for stopped matching. Its own control caught that.
PLACEHOLDER = re.compile(
    r"<(?=[A-Za-z])[^<>\n()|$]{0,60}?\b(repo|fill|todo|tbd)\b[^<>\n()|$]{0,60}?>",
    re.I,
)


CLUSTER_RPC = {
    "devnet": "https://api.devnet.solana.com",
    "testnet": "https://api.testnet.solana.com",
    "mainnet": "https://api.mainnet-beta.solana.com",
}


def rpc_for(url):
    """The endpoint that can actually answer for THIS link.

    An explorer link carries its own cluster: `?cluster=devnet` says devnet, and no cluster
    parameter means mainnet, which is the explorer's default. Asking one hardcoded endpoint about
    every link means asking devnet about a mainnet signature and getting a truthful "no such
    transaction" that is a false red about the claim. The link is the source of truth for which
    chain it asserts, so derive from it rather than from a constant.
    """
    m = re.search(r"[?&]cluster=([a-z\-]+)", url)
    if not m:
        return CLUSTER_RPC["mainnet"]
    return CLUSTER_RPC.get(m.group(1), RPC)


def rpc(method, params, attempts=4, endpoint=None):
    """Public RPC rate-limits, and a 429 is our own impatience rather than a dead link.
    A checker that reports transport noise as a failure gets muted exactly as fast as one that
    reports a false pass, so back off and retry until the endpoint actually answers."""
    endpoint = endpoint or RPC
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
                endpoint, data=body, headers={"Content-Type": "application/json"}
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
        # 402 is this repo's own x402 gate answering correctly. The question here is whether a
        # link points at something that exists, and a payment challenge is the endpoint doing
        # exactly what README describes one line above the link. Reading it as dead would have
        # the gate contradict the sentence the link sits in, which is how a gate gets muted.
        if e.code == 402:
            return True, "HTTP 402 (x402 challenge)"
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def load_bundle():
    """Signature -> capture status from the offline proof bundle.

    Public devnet prunes after about four days, so an explorer link going dark is the expected
    end state for every transaction here rather than a defect. What separates a surviving claim
    from a lost one is whether the raw bytes were captured before that happened, so this is the
    fact the link check has to consult before calling a dead link a failure.

    Reads EVERY bundle, discovered by glob rather than named. Naming devnet-transactions.json here
    was correct while devnet was the only cluster and became a false red when a second bundle
    landed: three captured mainnet signatures reported as NOT on chain. That is the same defect as
    the one fixed in check-proof-links.py, in a second file, which is exactly why it survived that
    fix and had to be swept as a class rather than an instance.
    """
    merged = {}
    for path in sorted((REPO / "docs" / "proof-bundle").glob("*-transactions.json")):
        try:
            txs = json.loads(path.read_text(encoding="utf-8")).get("transactions", {})
        except Exception:
            continue
        for sig, entry in txs.items():
            # A CAPTURED entry anywhere wins; the other direction would lose held evidence.
            if entry.get("status") == "CAPTURED" or sig not in merged:
                merged[sig] = entry
    return merged


def main():
    findings = []
    checked = 0
    cache = {}
    bundle = load_bundle()

    try:
        docs = tracked_markdown()
    except Exception as exc:
        # Scanning nothing and scanning everything cleanly print the same closing line, so a
        # derivation that fails has to be louder than a tree that passes.
        print(f"CANNOT VERIFY  {exc}")
        return 2

    for doc in docs:
        path = REPO / doc
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")

        for m in PLACEHOLDER.finditer(text):
            findings.append(f"{doc}: unfilled placeholder {m.group(0)!r}")

        for url in dict.fromkeys(URL_RE.findall(text)):
            url = url.rstrip(".,;")
            if (
                ABBREVIATED.search(url)
                or REDACTED_QUERY.search(url)
                or LOOPBACK.search(url)
            ):
                if ABBREVIATED.search(url):
                    why = "shortened in prose"
                elif REDACTED_QUERY.search(url):
                    why = "secret removed on purpose"
                else:
                    why = "loopback illustration"
                print(f"SKIP  {why:<22} {url[:96]}")
                continue
            checked += 1
            if url in cache:
                ok, detail = cache[url]
            elif tx := EXPLORER_TX.search(url):
                sig = tx.group(1)
                try:
                    got = rpc(
                        "getTransaction",
                        [sig, {"maxSupportedTransactionVersion": 0}],
                        endpoint=rpc_for(url),
                    )
                    if got is not None:
                        ok, detail = True, "on chain"
                    else:
                        # Absent from the endpoint. Whether that is a problem depends entirely
                        # on whether we hold the bytes, so ask the bundle rather than the RPC.
                        status = bundle.get(sig, {}).get("status")
                        if status == "CAPTURED":
                            ok, detail = True, "pruned, bytes held"
                        elif status:
                            ok, detail = False, "pruned before capture"
                        else:
                            ok, detail = False, "NOT on chain"
                except Exception as e:
                    # Could not ask the endpoint. That is only a finding if the endpoint was the
                    # sole evidence: a transaction whose bytes are captured is proven offline
                    # whether or not devnet answers, so a rate limit must not turn it red.
                    if bundle.get(sig, {}).get("status") == "CAPTURED":
                        ok, detail = True, "bytes held (RPC unreachable)"
                    else:
                        ok, detail = False, f"RPC error {e}"
            elif ad := EXPLORER_ADDR.search(url):
                pk = ad.group(1)
                try:
                    got = rpc(
                        "getAccountInfo",
                        [pk, {"encoding": "base64"}],
                        endpoint=rpc_for(url),
                    )
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
                        sigs = (
                            rpc(
                                "getSignaturesForAddress",
                                [pk, {"limit": 1}],
                                endpoint=rpc_for(url),
                            )
                            or []
                        )
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
    print(f"{checked} link(s) checked across {len(docs)} tracked documents")
    if findings:
        print(f"\n{len(findings)} problem(s):")
        for f in findings:
            print("  -", f)
        return 1
    print("Every link points at something that exists.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
