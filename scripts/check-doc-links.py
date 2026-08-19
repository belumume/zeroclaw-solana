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
import urllib.parse
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
# Markdown links whose target is NOT http(s) or mailto: the relative paths a reader
# actually clicks. Checked on disk; a broken one is a dead end in the corpus a judge walks.
REL_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
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


# The trailing group accepts the two commonest deep-link forms a doc uses to cite a thread:
# `/issues/1#issuecomment-5` and `/pull/1/files`. Anchoring hard to end-of-URL sent both down the
# throttled web path, which is the exact false-404 surface this routing exists to remove.
_GH_WEB = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/(issues|pull)/(\d+)"
    r"(?:/(?:files|commits|checks))?/?(?:[#?].*)?$",
    re.I,
)
_GH_BLOB = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+?)/?$", re.I
)
# A ref whose 404 can be TRUSTED, because it cannot be the first segment of a longer
# slash-bearing branch name. Used only on the failure branch -- see the asymmetry argument in
# _github_blob_verdict.
#
# `v[0-9]...` IS DELIBERATELY ABSENT, and that is a fix rather than an oversight. As a TAG `v2` is
# unambiguous; as a branch prefix it is not, and `blob/v2/hotfix/docs/x.md` splits to ref='v2',
# path='hotfix/docs/x.md', 404s, and would then be trusted -- the precise false FAIL this guard was
# written to prevent, while the sibling `feature/...` case correctly defers. A version-tagged blob
# link now defers instead, which costs a fallback to the web path and never a wrong verdict.
_UNAMBIGUOUS_REF = re.compile(r"[0-9a-fA-F]{7,40}|main|master|HEAD")


def _is_404(stderr: str) -> bool:
    """Did gh report a genuine 404, as opposed to any other failure?

    THE URL MUST BE STRIPPED FIRST. gh echoes the REQUESTED url in its stderr, so a bare
    `"404" in err` reads the digits out of the path we just asked about. A doc linking
    `http-404-notes.md`, or an issue-numbered path, turns an unrelated 403 rate limit or a network
    error into a TRUSTED dead-link verdict on a live file. That is the false FAIL this module's own
    docstring calls strictly worse than the throttle the API routing replaced.

    Matching gh's own status text rather than a bare number: `(HTTP 404)` carries a space, which a
    path cannot.
    """
    clean = re.sub(r"https?://\S+", "<url>", stderr or "").lower()
    return "not found" in clean or "http 404" in clean


def _github_blob_verdict(url):
    """(ok, detail) for a github.com /blob/<ref>/<path> link, via the authenticated contents API.

    Same throttle as `_github_api_verdict`, same 404-means-nothing problem, different route.
    Measured 2026-08-17: after the issue links were fixed this gate still reported three
    problems, ALL of them blobs, and the authenticated contents API resolved all three --
    12,142 / 37,036 / 22,894 bytes. Zero were dead.

    Returns None when it cannot reach a verdict, so the caller falls back to the web path.
    """
    m = _GH_BLOB.match(url)
    if not m:
        return None
    owner, repo, ref, path = m.group(1), m.group(2), m.group(3), m.group(4)
    # Strip the FRAGMENT and the QUERY. Dropping the query was a FALSE PASS, verified live: a
    # `?plain=1` link built `contents/<path>?plain=1?ref=<sha>`, and with two `?` in one URL the
    # ref is ignored, so the call resolved against the DEFAULT BRANCH and returned 37036 rc=0 for a
    # ref (`deadbeefdeadbeef`) that does not exist. Any ?plain=1 / ?raw=1 blob link therefore passed
    # regardless of the commit it pinned. The mirror case is worse: where a file exists only at the
    # pinned ref, the same mangling 404s and `_UNAMBIGUOUS_REF` trusts it, failing a live link.
    path = path.split("#", 1)[0].split("?", 1)[0]
    # The REF needs the same treatment, and for the same reason. `_GH_BLOB` captures it as `[^/]+`,
    # which happily accepts a `?`, so a malformed `blob/deadbeef?plain=1/docs/x.md` would rebuild
    # the exact double-`?` this function just stopped producing on the path side. A well-formed
    # GitHub URL cannot put a query mid-path, so this is not reachable from a real link today --
    # but the whole class of defect in this file has been "the half I did not think to strip".
    ref = ref.split("#", 1)[0].split("?", 1)[0]
    # Quote the path so a space or other reserved character cannot inject further URL structure.
    # `safe="/"` keeps directory separators, which the contents API needs verbatim.
    # UNQUOTE FIRST, or this double-encodes and produces a TRUSTED FALSE FAIL. GitHub renders a
    # blob URL for a file with a space as `%20`, so a bare quote() turns `Sample%20Sublease` into
    # `Sample%2520Sublease`, the contents API 404s, and because the ref is unambiguous that 404 is
    # BELIEVED -- no fallback to the web path. Measured on a real public file: the API returns
    # size 4290060 for the `%20` form and HTTP 404 for the `%2520` form. `+` mangles the same way.
    # This was introduced by the very commit that fixed the query-string bug, which is the third
    # time in this file that a fix has carried the defect it was written to remove.
    quoted = urllib.parse.quote(urllib.parse.unquote(path), safe="/")
    p = _gh(
        ["api", f"repos/{owner}/{repo}/contents/{quoted}?ref={ref}", "--jq", ".size"]
    )
    if p is None:
        return None
    size = (p.stdout or "").strip()
    if p.returncode == 0 and size:
        # A SUCCESS is self-validating: the ref resolved and the path existed under it, so the
        # URL was split correctly. No guard needed on this branch.
        return True, f"API ok ({size} B at {ref[:12]})"
    if _is_404(p.stderr or ""):
        # A 404 is NOT self-validating, and that asymmetry is the whole point. A branch name
        # may contain slashes, but _GH_BLOB captures `[^/]+`, so `blob/feature/my-branch/x.md`
        # arrives here as ref=`feature`, path=`my-branch/x.md` -- and the slash is already gone,
        # which is why inspecting `ref` for one cannot detect the case. Querying that mis-split
        # 404s on a LIVE link: a FALSE FAIL, strictly worse than the throttle this routing
        # replaces, because it is a wrong verdict rather than a noisy one.
        # So trust a 404 only from a ref that CANNOT be the head of a longer branch name -- a
        # commit sha or a conventional single-segment name. Otherwise defer to the web path,
        # which never had to split anything. Refusing to answer beats answering wrong.
        #
        # AND THE HEX ALTERNATIVE CARRIED THE SAME ASSUMPTION THE `v[0-9]` ONE DID. Git permits a
        # branch whose first segment is hex, so `blob/abc1234/feature/docs/x.md` on a real branch
        # named `abc1234/feature` splits to ref=`abc1234`, 404s, matches the hex alternative, and
        # is believed: a dead-link verdict on a live file. `v2` was removed for exactly that
        # reasoning while the hex branch was left asserting impossibility rather than unlikelihood.
        #
        # THE DISCRIMINATOR IS THE PATH, NOT THE REF, which is both cheaper and sharper than
        # inspecting the ref at all. A slash-bearing branch can only produce a mis-split by EATING
        # a leading path segment, so it needs one to spare: with a single-segment path there is
        # nothing for it to eat and the split is unambiguous whatever the ref looks like. With two
        # or more, the ambiguity is real, and we ask whether the ref resolves as a commit rather
        # than assuming it. One extra call, only on the 404 path, which is rare by construction.
        if not _UNAMBIGUOUS_REF.fullmatch(ref):
            return None
        multi_segment = "/" in path.strip("/")
        if multi_segment and not _ref_is_a_real_commit(owner, repo, ref):
            return None  # cannot confirm the ref; the split may be wrong. Defer to the web path.
        return False, "API 404 (path genuinely absent at that ref)"
    return None


def _ref_is_a_real_commit(owner: str, repo: str, ref: str) -> bool:
    """Does `ref` resolve to a commit in this repo?

    Returns False on ANY doubt, including a transport failure, because the caller uses this to
    decide whether to TRUST a 404. Answering "yes" on a failed lookup would reintroduce the false
    FAIL; answering "no" only costs a fallback to the web path.
    """
    p = _gh(["api", f"repos/{owner}/{repo}/commits/{ref}", "--jq", ".sha"])
    return p is not None and p.returncode == 0 and bool((p.stdout or "").strip())


def _gh(args, attempts=3):
    """Run `gh api` with a retry, returning (rc, stdout, stderr) or None if gh is unusable.

    RETRIED, and the reason is specific rather than general caution. A transient gh failure
    makes the resolver return None, which falls back to the WEB path -- the very source this
    routing exists to avoid, because it answers 404 when throttled. So one flaky call
    reintroduces exactly the false 404 the fix removes, and non-deterministically.
    MEASURED 2026-08-17: a run reported a single problem, `issues/9394 HTTP 404`; the API said
    open and the next run was clean. Without this retry the gate stays non-deterministic in
    the same direction, just far more rarely, which is worse because it is then unreproducible.

    A 404 from the API is NOT retried: that is a verdict, and the whole point is to tell one
    apart from a throttle.
    """
    last = None
    for attempt in range(attempts):
        if attempt:
            time.sleep(1.0 * attempt)
        try:
            p = subprocess.run(
                ["gh"] + args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        except FileNotFoundError:
            return None  # gh not installed at all -> fall back to the web path
        except Exception as e:
            last = str(e)
            continue
        if p.returncode == 0:
            return p
        err = (p.stderr or "").lower()
        if _is_404(p.stderr or ""):
            return p  # a real verdict; do not retry it
        last = err
    # SAY SO rather than degrading quietly. Returning None sends the caller to the web path,
    # which is the source that answers 404 when throttled, so a persistent gh failure would
    # silently restore the exact false-404 this routing removes. A fail-open path that emits
    # nothing is indistinguishable from one that never ran.
    print(
        f"  note: gh unavailable after {attempts} attempts, falling back to the web path "
        f"for this link ({(last or 'no detail')[:80]})",
        file=sys.stderr,
    )
    return None


def _github_api_verdict(url):
    """(ok, detail) for a github.com issue/PR link, resolved through the AUTHENTICATED API.

    WHY THIS EXISTS, and it is a violation of the assumption `check_url` is built on.
    That function treats a 4xx as a VERDICT -- the server understood and answered -- and
    retries only 5xx/429, which is correct for every host we check except one. GitHub's WEB
    frontend answers a throttled anonymous client with **404**, so a rate-limited fetch is
    byte-identical to a dead link, and the retry logic cannot help because 404 is never
    retried by design.

    MEASURED 2026-08-17: this gate reported 16 problems on one run and 8 on another minutes
    later, DIFFERENT MEMBERS EACH TIME. Every issue URL it called 404 was then re-checked
    through the authenticated API: 12 of 12 existed, 0 genuinely unresolvable. A cited source
    blob it called 404 exists at that commit at 12,142 bytes. The anonymous API budget was
    untouched at 57 of 60, so the throttle is the web frontend specifically rather than a
    quota anything had burned. A gate that cries wolf on a dozen live links gets learned
    around, which is worse than no gate.

    Returns None when the API route is unavailable, so the caller falls back to the web path
    rather than treating a missing tool as a verdict about the link.
    """
    m = _GH_WEB.match(url)
    if not m:
        return None
    owner, repo, kind, num = m.group(1), m.group(2), m.group(3), m.group(4)
    # The API calls both issues and PRs "issues"; a PR resolves through that route too.
    p = _gh(["api", f"repos/{owner}/{repo}/issues/{num}", "--jq", ".state"])
    if p is None:
        return None  # gh absent or persistently unusable -> not a verdict, fall back
    state = (p.stdout or "").strip()
    if p.returncode == 0 and state:
        return True, f"API ok ({kind} is {state})"
    if _is_404(p.stderr or ""):
        return False, "API 404 (genuinely absent)"
    return None  # auth failure, network, rate limit -> could-not-check, fall back


def check_url(url, attempts=3):
    """(ok, detail) for a non-explorer link.

    RETRIES TRANSPORT FAILURES, and the asymmetry it fixes is the point. `rpc()` above
    already backs off because a rate-limited endpoint reports a false answer; this path
    had no retry and folded every exception into one False, so a TIMEOUT was scored
    exactly like a 404. Those are opposite findings: a 404 is a fact about the link, a
    timeout is a fact about the network, and only one of them is a defect in this repo.

    Measured 2026-08-04: the gate reported api.frankfurter.dev dead while three
    consecutive probes returned HTTP 200 in about 0.3s each. That is a false red on the
    gate the flip-sitting order runs LAST, which is the worst possible moment for one.

    A 4xx HTTPError is NOT retried: the server understood and answered, so it is a real
    verdict about the link. A 5xx or 429 IS retried, because `_http_verdict` returns None for
    those to mean "the server had a bad day, ask again" rather than "this does not exist".
    A transport failure is retried for the same reason, and a link that never answers is
    reported as UNREACHABLE rather than as broken, so the two stay distinguishable downstream.

    GITHUB ISSUE AND PR LINKS GO THROUGH THE AUTHENTICATED API FIRST, because GitHub answers a
    throttled anonymous client with 404 and this function is built on 4xx being a truthful
    answer. See `_github_api_verdict`. It returns None whenever it cannot reach a verdict, so
    an absent `gh` or a failed auth falls through to the web path below rather than becoming a
    claim about the link.
    """
    for resolver in (_github_api_verdict, _github_blob_verdict):
        gh = resolver(url)
        if gh is not None:
            return gh

    last = None
    for attempt in range(attempts):
        if attempt:
            time.sleep(1.5 * attempt)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
            with urllib.request.urlopen(req, timeout=25) as r:
                return (200 <= r.status < 400), f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            ok, note = _http_verdict(e)
            if ok is not None:
                return ok, note
            last = note  # server-side; fall through to the next attempt
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
    return False, f"UNREACHABLE after {attempts} attempts ({last})"


def _http_verdict(e):
    """Which HTTP answers are VERDICTS about the link, and which are the server having a bad day.

    A 4xx is a verdict: the server understood, and 404 means the thing is not there.

    A 5xx IS NOT, and this gate reported one as a defect before 2026-08-04. Cloudflare's 522 is
    an origin timeout, so it says the upstream failed to answer, which is a fact about the server
    rather than about the link. Measured on the run that prompted this: the flagged endpoint
    timed out once and then returned HTTP 200 on the next two probes, seconds apart. A false red
    on a healthy link is exactly how a gate gets ignored, and an ignored gate is worse than none.

    So this is the same rule the transport-retry fix established, one layer further in. That fix
    already said a timeout is not a verdict; a 5xx is a timeout that happens to arrive with a
    status code attached. 429 joins them, since a rate limit is a request about timing, not an
    answer about existence.
    """
    # 402 is this repo's own x402 gate answering correctly. The question here is whether a link
    # points at something that exists, and a payment challenge is the endpoint doing exactly what
    # the README describes one line above the link. Reading it as dead would have the gate
    # contradict the sentence the link sits in, which is how a gate gets muted.
    if e.code == 402:
        return True, "HTTP 402 (x402 challenge)"
    if e.code == 429 or 500 <= e.code <= 599:
        return None, f"HTTP {e.code} (server-side, retry)"
    return False, f"HTTP {e.code}"


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
    unverified = []  # the server never answered; not a verdict about the link
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

        for target in dict.fromkeys(REL_LINK.findall(text)):
            target = target.strip()
            if target.startswith(("http://", "https://", "mailto:")):
                continue  # the URL pass below owns these
            file_part = target.split("#")[0].strip()
            if not file_part:
                continue  # a bare #anchor is intra-document; there is no file to resolve
            checked += 1
            if not (path.parent / file_part).resolve().exists():
                findings.append(f"{doc}: relative link does not resolve -> {file_part}")

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
            # THREE OUTCOMES, NOT TWO, and the third is the considered one. A link the server
            # never answered for is UNVERIFIED: nothing was learned about it, which is a
            # different claim from "it is broken". Folding the two together makes a red mean two
            # things, and this gate produced exactly that false red on 2026-08-04, when
            # frankfurter.dev went through a brief 522 window during a run and answered 200 on
            # six probes minutes later. A publish gate that goes red because a third party
            # hiccupped is a gate people learn to ignore, and an ignored gate is worse than none.
            #
            # It is REPORTED LOUDLY rather than passed silently, because the opposite failure is
            # real too: a genuinely dead host would otherwise hide here forever. So an unverified
            # link is visible in the summary every run, and a reader can tell the difference at a
            # glance, which is the whole point of not collapsing them.
            unverified_here = (not ok) and detail.startswith("UNREACHABLE")
            mark = "PASS" if ok else ("UNVR" if unverified_here else "FAIL")
            print(f"{mark}  {detail:<18} {url[:96]}")
            if unverified_here:
                unverified.append(f"{doc}: {url}  ({detail})")
            elif not ok:
                findings.append(f"{doc}: {url}  ({detail})")

    print()
    print(f"{checked} link(s) checked across {len(docs)} tracked documents")
    if unverified:
        print(
            f"\n{len(unverified)} link(s) UNVERIFIED (the server never answered; not a verdict):"
        )
        for u in unverified:
            print("  ?", u)
        print(
            "  Re-run to settle these. They do not fail this gate, and they are not silent."
        )
    if findings:
        print(f"\n{len(findings)} problem(s):")
        for f in findings:
            print("  -", f)
        return 1
    print("Every link that answered points at something that exists.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
