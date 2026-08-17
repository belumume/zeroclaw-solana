"""Positive control for the box self-check claim in verify-proof.py.

Run from the repository root:  python3 scripts/verify_proof_selfcheck_control.py

Against the deployed gate today that claim prints PENDING, because the running build
predates the /selfcheck route. A check whose only observed output is PENDING has not
been shown to work: it would keep printing PENDING just as happily if its verdict
logic were deleted, and it would keep printing it after the route shipped and the
timer died.

So this serves crafted /selfcheck responses from a loopback server and asserts the
checker reaches the right verdict on each branch: a 404 from an old build, a 503 from
a live route with no verdict on disk, a fresh all-passing verdict, a drifted one, a
stale one, a malformed one, and an unexpected status. Every FAIL branch is exercised,
so the claim is known to be capable of going red before anyone relies on its green.

The 404 and 503 cases are the pair that matters most. They are the two that look alike
from a distance and need opposite responses -- one means "not shipped yet", the other
means "the check stopped running" -- so a control that only proved the endpoint can be
read would leave exactly that confusion untested.

A second phase covers the gate's BUILD PROVENANCE report, which names the commit the
binary answering the request was compiled from. That one reads /health as well as
/selfcheck, so this server answers both paths for it, and its absent-field branch is
only reachable with both served locally: the live node has the field, so no amount of
crafting a /selfcheck body alone can produce the older-binary case. That branch is the
one worth controlling, because it must read as unknown rather than as a failure.

Stdlib only, binds an ephemeral port, touches no network and no chain.
"""

import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

FRESH = 120
STALE = 99999  # comfortably past the 7800s default ceiling


def verdict(*, ok, age, checks=None, sha="abc1234"):
    return {
        "generated_at": "2026-08-16T06:00:00Z",
        "generated_at_epoch": 1786600800,
        "deployed_sha": sha,
        "ok": ok,
        "age_seconds": age,
        "served_at": "2026-08-16T06:02:00Z",
        "checks": checks
        if checks is not None
        else [
            {"name": "manifest", "ok": True, "detail": "8 files match"},
            {"name": "mint", "ok": True, "detail": "no prohibited mint"},
        ],
    }


DRIFTED = verdict(
    ok=False,
    age=FRESH,
    checks=[
        {
            "name": "manifest",
            "ok": False,
            "detail": "SKILL.md differs from the manifest",
        },
        {"name": "mint", "ok": True, "detail": "no prohibited mint"},
    ],
)

# (label, http status, body-or-None, expected line)
CASES = [
    (
        "404, build predates route",
        404,
        None,
        r"^PEND\s+box self-check not yet observable",
    ),
    (
        "503, route live, no verdict",
        503,
        {"error": "no verdict", "detail": "file absent"},
        r"^FAIL\s+box self-check endpoint is live but has no verdict",
    ),
    (
        "200, fresh and all passing",
        200,
        verdict(ok=True, age=FRESH),
        r"^PASS\s+box matches abc1234 on all 2 invariants",
    ),
    (
        "200, drifted",
        200,
        DRIFTED,
        r"^FAIL\s+box has DRIFTED from abc1234: manifest",
    ),
    (
        "200, stale (timer stopped)",
        200,
        verdict(ok=True, age=STALE),
        r"^FAIL\s+box self-check is 99999s old",
    ),
    (
        "200, malformed age",
        200,
        verdict(ok=True, age="recently"),
        r"^FAIL\s+box self-check malformed",
    ),
    (
        "200, checks not a list",
        200,
        {"ok": True, "age_seconds": FRESH, "checks": "two", "deployed_sha": "abc1234"},
        r"^FAIL\s+box self-check malformed",
    ),
    (
        "500, unexpected status",
        500,
        {"error": "boom"},
        r"^FAIL\s+box self-check returned HTTP 500",
    ),
]

# A green verdict must NOT be counted before it can go red, so the pass case also has to move the
# tally. Asserted separately below rather than folded into the pattern, because a claim that gates
# and a claim that merely prints are indistinguishable from the verdict line alone.
TALLY = re.compile(r"(\d+)/(\d+) live claims verified")

state = {"status": 200, "body": {}, "health": None}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        # Path-aware only when a health body has been set, so the eight cases above -- which
        # point only SHOP_SELFCHECK_URL here -- reach exactly the same code they always did.
        if self.path.startswith("/health") and state["health"] is not None:
            body = json.dumps(state["health"]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps(state["body"]).encode()
        self.send_response(state["status"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Silence the per-request log so the control's own output stays readable."""


srv = HTTPServer(("127.0.0.1", 0), H)  # port 0: never collides with a live service
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

ok = True
tallies = {}
for name, status, body, pattern in CASES:
    state["status"] = status
    state["body"] = body if body is not None else {"error": "not found"}
    r = subprocess.run(
        [sys.executable, "scripts/verify-proof.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={
            **os.environ,
            "SHOP_SELFCHECK_URL": f"http://127.0.0.1:{port}/selfcheck",
        },
    )
    hit = [ln for ln in r.stdout.splitlines() if re.search(pattern, ln.strip())]
    m = TALLY.search(r.stdout)
    tallies[name] = m.group(2) if m else "?"
    shown = hit[0].strip()[:74] if hit else "expected /" + pattern[:44] + "/"
    print(f"  {name:30s} {'OK  ' if hit else 'MISS'} {shown}")
    if not hit:
        ok = False

# SECOND PHASE: the gate's BUILD PROVENANCE line, which reports which commit the binary
# answering the request was compiled from.
#
# It needs its own phase because it is the one report here that reads BOTH routes, so both have
# to be served locally. The eight cases above leave /health pointed at the live node, where the
# field is present, so none of them can reach the absent branch -- which is the branch that
# matters most, since an older gate binary has no build_commit at all and that must read as
# unknown rather than as a failure or as a bare None leaking into the line.
#
# NOTHING HERE GATES, so unlike the tally control above there is no count to assert. What is
# asserted is that each input reaches a DIFFERENT sentence -- absent, observed, dirty,
# placeholder, a commit this clone does not hold, and two processes disagreeing -- and a report
# that collapsed any of them into the same words would be worth nothing. The count is derived
# from BUILD_CASES below rather than typed here, so it cannot drift when a case is added.
HEAD_SHA = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
).stdout.strip()
# Without this the git-derived cases would silently degrade to an empty sha, which reads as the
# absent branch and would make three of the six cases MISS for a reason no message explains.
assert len(HEAD_SHA) == 40, (
    f"could not read HEAD; this control cannot run ({HEAD_SHA!r})"
)
ABSENT = 40 * "f"  # well-formed, and no repository holds it


def sc_with(**extra):
    v = verdict(ok=True, age=FRESH)
    v.update(extra)
    return v


# (label, health body, selfcheck extras, expected line)
BUILD_CASES = [
    (
        "field absent on both routes",
        {"shop": {}},
        {},
        r"^PEND\s+gate build provenance not yet observable",
    ),
    (
        "observed in git at build time",
        {"shop": {}},
        {"gate_build_commit": HEAD_SHA, "gate_build_commit_source": "git"},
        r"read from the repository at build time.*your HEAD is that same commit",
    ),
    (
        "built from an uncommitted tree",
        {"shop": {}},
        {
            "gate_build_commit": HEAD_SHA + "-dirty",
            "gate_build_commit_source": "git-dirty",
        },
        r"UNCOMMITTED code went into this binary.*the clean commit it was built on top of",
    ),
    (
        "build had no repository",
        {"shop": {}},
        {"gate_build_commit": "unknown", "gate_build_commit_source": "unavailable"},
        r"placeholder rather than a commit.*not a commit id",
    ),
    (
        "commit is real but not in this clone",
        {"shop": {}},
        {"gate_build_commit": ABSENT, "gate_build_commit_source": "git"},
        r"not a commit this clone holds",
    ),
    (
        "the two routes disagree",
        {"gate": {"build_commit": ABSENT, "build_commit_source": "git"}, "shop": {}},
        {"gate_build_commit": HEAD_SHA, "gate_build_commit_source": "git"},
        r"DISAGREES with /health.*so two processes answered",
    ),
]


def run_build_case(health_body, sc_extra, script="scripts/verify-proof.py"):
    state["status"] = 200
    state["body"] = sc_with(**sc_extra)
    state["health"] = health_body
    return subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={
            **os.environ,
            "SHOP_SELFCHECK_URL": f"http://127.0.0.1:{port}/selfcheck",
            "SHOP_HEALTH_URL": f"http://127.0.0.1:{port}/health",
        },
    ).stdout


print("\n  build provenance:")
seen = set()
for name, health_body, sc_extra, pattern in BUILD_CASES:
    out = run_build_case(health_body, sc_extra)
    line = next(
        (
            ln.strip()
            for ln in out.splitlines()
            if "gate build provenance" in ln or "gate binary built from" in ln
        ),
        "",
    )
    hit = bool(line and re.search(pattern, line))
    seen.add(line)
    print(f"  {name:34s} {'OK  ' if hit else 'MISS'} {line[:70]}")
    if not hit:
        ok = False

# Six inputs must produce six sentences. Without this a report that printed one constant string
# would pass every pattern above that happened to be a substring of it.
distinct = len(seen) == len(BUILD_CASES)
print(f"  {len(seen)} distinct line(s) from {len(BUILD_CASES)} input(s): {distinct}")

# MUTATION CONTROL, on the EXTRACTION rather than on the wording. A pattern check proves the
# printer works on inputs it was handed; it says nothing about whether the field lookup is the
# thing that fed it. Bogusify both field names, keep everything else, and the observed case must
# collapse to the absent branch. If it still reports a commit, the line is reading something
# other than the endpoint and every case above is decorative.
mutant = open("scripts/verify-proof.py", encoding="utf-8").read()
for real, bogus in (
    ('"gate_build_commit"', '"zzz_gate_build_commit"'),
    ('"build_commit"', '"zzz_build_commit"'),
):
    assert real in mutant, (
        f"mutation anchor {real} not found; this control tests nothing"
    )
    mutant = mutant.replace(real, bogus)
mut_path = "scripts/.verify-proof-buildprov-mutant.py"
try:
    with open(mut_path, "w", encoding="utf-8", newline="") as f:
        f.write(mutant)
    mut_out = run_build_case(
        {"shop": {}},
        {"gate_build_commit": HEAD_SHA, "gate_build_commit_source": "git"},
        script=mut_path,
    )
finally:
    if os.path.exists(mut_path):
        os.remove(mut_path)
mutant_blind = "gate build provenance not yet observable" in mut_out
print(f"  breaking the field lookup collapses it to unknown: {mutant_blind}")

srv.shutdown()

# The tally control. A PENDING claim must not be counted, and a judged one must be. If both read
# the same, the claim is decorative: it prints a verdict that changes nothing.
pend = tallies.get("404, build predates route")
judged = tallies.get("200, fresh and all passing")
counts = pend is not None and judged is not None and pend != judged
print(f"\n  PENDING totals {pend} live claims, a judged verdict totals {judged}")
print(f"  the claim actually gates rather than only printing: {counts}")

print(f"\nall {len(CASES) + len(BUILD_CASES)} branches reached: {ok}")
sys.exit(0 if ok and counts and distinct and mutant_blind else 1)
