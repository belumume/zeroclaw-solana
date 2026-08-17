"""Controls for check-doc-links.py's SKIP classification, in BOTH directions.

This gate was the only one of the five with no suite, which is how the loopback defect
survived: a permanently-red job was scheduled onto the judging window and read as a known
residual rather than as a bug.

The loopback case is not merely "always red". It is NON-DETERMINISTIC, which is worse,
because the outcome depends on unrelated local state. QUICKSTART's
`ssh -L 8899:127.0.0.1:8899` illustration went red on CI and would go GREEN on a reader's
machine running the local validator or `scripts/qr_live_server.py`, both of which
QUICKSTART itself tells them to start. A check that reports on the runner rather than on
the documentation is not a check.

One direction alone proves nothing. Must-skip alone passes for a classifier that skips
every URL, which would silently stop checking real links. So every skip case is paired
with a near-miss that must still be CHECKED, differing only in the discriminating feature.

Case 1 is the incident URL verbatim from QUICKSTART.md. If it stops being skipped, the
gate is back to reporting on whoever ran it.

Run: python scripts/test_check_doc_links.py
"""

import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "check-doc-links.py"

spec = importlib.util.spec_from_file_location("cdl", GATE)
cdl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cdl)

passed = failed = notrun = 0

# A FLOOR, so a silent collapse cannot read as a pass. Measured 2026-08-17: with `gh` auth cleared
# the suite printed "16 passed, 0 failed" -- byte-identical to its pre-API-routing count -- because
# the whole github block short-circuits to NOT RUN. That is indistinguishable from success in an
# exit code, and the block's own comment calls those controls "the point". Assert the count.
# 30 is MEASURED, not chosen: it is the count that runs with `gh` auth cleared, so the floor is the
# offline baseline and any silent loss of an offline case goes red. It is deliberately NOT the
# with-auth total (39), because the github block is legitimately allowed to be unavailable.
# Calibrated in both directions before shipping: raising it to 999 exits 1 with a legible message,
# leaving it at the measured value exits 0 -- an uncalibrated floor is decorative.
# RAISE THIS when you add an offline case, or the floor quietly under-asserts by exactly the number
# you added. It went 28 -> 30 when the review follow-up added two.
MIN_CASES_OFFLINE = 30


def check(name, cond, detail: object = ""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def classify(url):
    """Mirror main()'s branch order. Returns the skip reason, or None to mean CHECKED."""
    if cdl.ABBREVIATED.search(url):
        return "shortened in prose"
    if cdl.REDACTED_QUERY.search(url):
        return "secret removed on purpose"
    if cdl.LOOPBACK.search(url):
        return "loopback illustration"
    return None


print("check-doc-links SKIP classification")

# --- MUST SKIP: loopback ------------------------------------------------------------
# Case 1 is the incident, verbatim from QUICKSTART.md's ssh -L illustration.
check(
    "1  INCIDENT: the QUICKSTART loopback URL is skipped",
    classify("http://127.0.0.1:8899") == "loopback illustration",
    classify("http://127.0.0.1:8899"),
)
for u in (
    "http://localhost:8899",
    "http://127.0.0.1:3000/health",
    "https://localhost",
    "http://[::1]:8080",
    "http://0.0.0.0:9000",
    "http://LocalHost:8899",  # case-insensitivity is deliberate
):
    check(
        f"1x loopback skipped: {u}", classify(u) == "loopback illustration", classify(u)
    )

# --- MUST STILL BE CHECKED: near-misses that differ only in the discriminator --------
# Without these, a classifier that skipped everything would pass the block above.
for u in (
    "https://github.com/belumume/zeroclaw-solana",
    "https://api.devnet.solana.com",
    "http://127.0.0.1.example.com/x",  # loopback-looking HOST PREFIX, not loopback
    "https://localhost.attacker.test/path",  # localhost as a subdomain label
    "https://example.com/127.0.0.1",  # loopback only in the PATH
):
    check(f"2  still checked: {u}", classify(u) is None, classify(u))

# --- The other two classes must be unaffected by the new branch ----------------------
check(
    "3a abbreviated still skipped",
    classify("https://explorer.solana.com/tx/5ss8…") == "shortened in prose",
    classify("https://explorer.solana.com/tx/5ss8…"),
)
check(
    "3b redacted still skipped",
    classify("https://api.example.com/v1?key=REDACTED") == "secret removed on purpose",
    classify("https://api.example.com/v1?key=REDACTED"),
)

# --- MUTATION CONTROL: neuter LOOPBACK; case 1 must stop being skipped ---------------
# Targets the regex literal rather than the word, because the word also appears in the
# module docstring and in comments, and replacing one of those yields a mutant that is
# behaviourally identical to the real gate, so the control could not fail.
src = GATE.read_text(encoding="utf-8")
ANCHOR = 'r"^https?://(?:127\\.0\\.0\\.1|localhost'
assert ANCHOR in src, "mutation target is stale; this control would test nothing"
mutant_src = src.replace(ANCHOR, 'r"^https?://(?:127\\.0\\.0\\.2|localhostX', 1)
assert mutant_src != src, "mutation did not apply"

mpath = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / ".mutant-doc-links.py"
mpath.write_text(mutant_src, encoding="utf-8")
try:
    mspec = importlib.util.spec_from_file_location("cdl_mutant", mpath)
    mmod = importlib.util.module_from_spec(mspec)
    mspec.loader.exec_module(mmod)
    check(
        "4  mutation control: with LOOPBACK broken, the incident URL is no longer skipped",
        not mmod.LOOPBACK.search("http://127.0.0.1:8899"),
        "mutant still skipped it, so the control proves nothing",
    )
finally:
    mpath.unlink(missing_ok=True)

# --- The live QUICKSTART really does contain the incident URL ------------------------
# Pins the case to reality: if QUICKSTART stops carrying it, case 1 is guarding a shape
# the repo no longer has, and this suite should say so rather than passing quietly.
qs = (HERE.parent / "QUICKSTART.md").read_text(encoding="utf-8")
check(
    "5  QUICKSTART still carries the loopback illustration this case exists for",
    bool(re.search(r"127\.0\.0\.1:8899", qs)),
    "not found; case 1 may now be guarding nothing",
)

# --- REVIEW FOLLOW-UPS, all OFFLINE so they raise the floor rather than self-skipping -
# These three were defects in the FIX, found by review after it merged. Each is pinned in both
# directions: the shape that was wrong, and the neighbour that must keep working.

# (a) A QUERY STRING must be stripped from a blob path. Unstripped it built
#     `contents/<path>?plain=1?ref=<sha>`; with two `?` in one URL the ref is IGNORED, so the call
#     resolved against the DEFAULT BRANCH and returned 200 for a ref that does not exist. Verified
#     live before the fix: size 37036, rc 0, against `deadbeefdeadbeef`.
_m = cdl._GH_BLOB.match(
    "https://github.com/x402-foundation/x402/blob/deadbeefdeadbeef/specs/x.md?plain=1"
)
_path = _m.group(4).split("#", 1)[0].split("?", 1)[0] if _m else None
check("15 a query string is stripped from the blob path", _path == "specs/x.md", _path)
_m2 = cdl._GH_BLOB.match(
    "https://github.com/o/r/blob/deadbeefdeadbeef/docs/a.md#section"
)
_p2 = _m2.group(4).split("#", 1)[0].split("?", 1)[0] if _m2 else None
check(
    "15b CONTROL: a plain path is unchanged by the same stripping",
    _p2 == "docs/a.md",
    _p2,
)

# (a2) The REF half of the same defect, raised by review OF THE FIX. `_GH_BLOB` captures the ref as
#      `[^/]+`, which accepts a `?`, so a malformed URL rebuilds the same double-`?` on the other
#      side. Not reachable from a well-formed GitHub URL; added because every defect in this file
#      has been "the half I did not think to strip".
_m3 = cdl._GH_BLOB.match("https://github.com/o/r/blob/deadbeef?plain=1/docs/x.md")
_r3 = _m3.group(3).split("#", 1)[0].split("?", 1)[0] if _m3 else None
check("15c a query string is stripped from the REF too", _r3 == "deadbeef", _r3)
_m4 = cdl._GH_BLOB.match("https://github.com/o/r/blob/deadbeefdeadbeef/docs/x.md")
_r4 = _m4.group(3).split("#", 1)[0].split("?", 1)[0] if _m4 else None
check(
    "15d CONTROL: a clean ref is unchanged by the same stripping",
    _r4 == "deadbeefdeadbeef",
    _r4,
)

# (b) A VERSION-LIKE REF must NOT be trusted on a 404. `v2` looks unambiguous and is not: it is a
#     legitimate branch PREFIX, so `blob/v2/hotfix/docs/x.md` splits to ref='v2' and 404s, and
#     trusting that is the exact false FAIL the guard exists to prevent.
check(
    "16 a version-like ref is NOT trusted on a 404 (it may be a branch prefix)",
    not cdl._UNAMBIGUOUS_REF.fullmatch("v2"),
    "v2 still matches, so a mis-split 404 would be reported as a dead link",
)
for _ref in ("deadbeefdeadbeef", "main", "master", "HEAD"):
    check(
        f"16b CONTROL: {_ref!r} is still trusted on a 404",
        bool(cdl._UNAMBIGUOUS_REF.fullmatch(_ref)),
        "over-narrowed: a genuinely unambiguous ref stopped being trusted",
    )
check(
    "16c CONTROL: a plain branch name is still NOT trusted",
    not cdl._UNAMBIGUOUS_REF.fullmatch("feature"),
    "feature became trusted, which reintroduces the mis-split false FAIL",
)

# (c) DEEP LINKS to a thread must take the API route. End-anchoring sent the two commonest cited
#     forms down the throttled web path, leaving them exposed to the false 404 this all exists for.
for _u in (
    "https://github.com/zeroclaw-labs/zeroclaw/issues/9348#issuecomment-5",
    "https://github.com/zeroclaw-labs/zeroclaw/pull/9382/files",
):
    check(
        f"17 deep link takes the API route: {_u[-28:]}",
        bool(cdl._GH_WEB.match(_u)),
        "no match",
    )
for _u in (
    "https://github.com/o/r/issues",  # no number
    "https://github.com/o/r/tree/main",  # not issues/pull
):
    check(
        f"17b CONTROL: still NOT matched: {_u[-24:]}",
        cdl._GH_WEB.match(_u) is None,
        "over-widened: this should not reach the issue/PR resolver",
    )

# --- GITHUB RESOLVERS: the API route, and that it can still FAIL ---------------------
# WHY THESE EXIST. GitHub's WEB frontend answers a throttled anonymous client with 404, and
# check_url is built on 4xx being a truthful answer, so a rate-limited fetch was byte-identical
# to a dead link and was never retried. MEASURED 2026-08-17: the gate reported 16 problems on
# one run and 8 on another minutes later, with different members; all 12 issue URLs it called
# 404 existed via the authenticated API, and so did all 3 blobs (12,142 / 37,036 / 22,894 B).
#
# THE CONTROLS ARE THE POINT. Rerouting to an API that answered "fine" to everything would be a
# gate that can no longer fail, which is worse than the noise it replaced. So each resolver is
# pinned in BOTH directions, plus deferral cases proving a non-GitHub host, a non-matching
# GitHub URL and an unusable `gh` fall through to the web path instead of becoming a verdict.
#
# NETWORK-DEPENDENT by nature. A resolver that cannot reach a verdict returns None, so if `gh`
# is absent or unauthenticated these report NOT-RUN rather than failing the suite -- a missing
# tool is not evidence about the code.
print("\ngithub API resolvers")

_probe = cdl._github_api_verdict(
    "https://github.com/zeroclaw-labs/zeroclaw/issues/9348"
)
if _probe is None:
    print(
        "  NOT RUN  gh unavailable or unauthenticated; these cases need network + auth"
    )
else:
    for name, fn, url, want in (
        (
            "6  issue that exists resolves OK",
            cdl._github_api_verdict,
            "https://github.com/zeroclaw-labs/zeroclaw/issues/9348",
            True,
        ),
        (
            "7  CONTROL: an absent issue still FAILS",
            cdl._github_api_verdict,
            "https://github.com/zeroclaw-labs/zeroclaw/issues/99999999",
            False,
        ),
        (
            "8  blob at a pinned sha resolves OK",
            cdl._github_blob_verdict,
            "https://github.com/solana-foundation/subscriptions/blob/"
            "debb4f75ff7571218b39de3b633074dd843e70db/program/src/errors.rs",
            True,
        ),
        (
            "9  CONTROL: an absent blob path still FAILS",
            cdl._github_blob_verdict,
            "https://github.com/x402-foundation/x402/blob/8c308ce3040556482099958f09977fb1fe487e12/specs/definitely-not-here-9f3a.md",
            False,
        ),
        (
            "10 CONTROL: an absent ref never PASSES",
            cdl._github_blob_verdict,
            "https://github.com/x402-foundation/x402/blob/deadbeefdeadbeef/README.md",
            False,
        ),
        (
            "11 a heading anchor is stripped before the path lookup",
            cdl._github_blob_verdict,
            "https://github.com/x402-foundation/x402/blob/8c308ce3040556482099958f09977fb1fe487e12/"
            "specs/x402-specification-v2.md#scheme",
            True,
        ),
    ):
        got = fn(url)
        if got is None:
            # `None` is the resolver's explicit "I could not reach a verdict", which is exactly
            # what the probe above treats as NOT-RUN. Scoring it as a FAILURE here contradicted
            # that contract for every real case: `_gh` retries, but a throttle that outlasts the
            # retries after the probe already succeeded turned cases 6-11 red on a healthy tree.
            # A missing verdict is not evidence about the code.
            notrun += 1
            print(f"  NOT RUN  {name}  (resolver returned no verdict)")
            continue
        check(name, got[0] is want, f"got {got}")

    # Deferral: neither resolver may claim a verdict it has no business having.
    for name, url in (
        (
            "12 CONTROL: a non-github host defers to the web path",
            "https://example.com/whatever",
        ),
        (
            "13 CONTROL: a github URL that is neither issue/PR nor blob defers",
            "https://github.com/solana-foundation/subscriptions/tree/debb4f7",
        ),
        (
            "14 a slash-bearing ref is UNSPLITTABLE, so it defers instead of guessing",
            # `blob/feature/my-branch/docs/x.md` parses as ref=feature, path=my-branch/docs/x.md.
            # Querying that would 404 on a LIVE link -- a false FAIL, worse than the throttle
            # this routing replaces. Refusing to answer is the only correct third option.
            "https://github.com/x402-foundation/x402/blob/feature/my-branch/specs/x.md",
        ),
    ):
        check(
            name,
            cdl._github_api_verdict(url) is None
            and cdl._github_blob_verdict(url) is None,
            f"api={cdl._github_api_verdict(url)} blob={cdl._github_blob_verdict(url)}",
        )

print(f"\n{passed} passed, {failed} failed, {notrun} not run")

# THE FLOOR. Without this, a whole block short-circuiting to NOT RUN is indistinguishable from a
# clean pass, and that is not hypothetical: with auth cleared this printed exactly the pre-PR count.
# The github block is allowed to be unavailable; the OFFLINE cases are not allowed to vanish.
if passed + failed < MIN_CASES_OFFLINE:
    print(
        f"\nFAIL  only {passed + failed} case(s) were scored, below the floor of "
        f"{MIN_CASES_OFFLINE}. A suite that quietly stops running cases reports the same exit "
        f"code as one that passes them, so the count is asserted rather than trusted."
    )
    sys.exit(1)

sys.exit(1 if failed else 0)
