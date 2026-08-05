"""Controls for verify-proof.py's transport-versus-claim predicate, in both directions.

That predicate decides two things, and getting it wrong is expensive in opposite ways.
Inside `rpc()` it decides whether to RETRY. In every caller it decides whether a FAIL
counts toward `transport_fails`, which is what separates exit 2 ("the network refused,
this run has no opinion, retry") from exit 1 ("a claim this repo asserts stopped holding").

CASE 1 IS THE REAL INCIDENT, and it is the reason this file exists. Until 2026-08-05 the
predicate was `return e.code >= 500`, so an HTTP 429 -- which public Solana devnet returns
routinely under no unusual load -- classified as NOT transport. A rate limit therefore
rendered as a claim that stopped holding and exited 1, the finding code, on a run where
nothing was found. If case 1 ever stops firing, a routine rate limit is being reported as
a broken claim again.

CASE 2 IS THE OTHER REQUIRED CONTROL. A widening is silently unproven: loosening a
predicate adds no failing case, so a suite that only gained case 1 would pass identically
before and after and prove nothing about what still holds. Case 2 asserts a genuine 5xx --
the behaviour that already worked -- was not lost in the edit.

MUST-NOT-FIRE IS NOT OPTIONAL HERE, because the tempting fix was "429 is 4xx, so make 4xx
transport". Cases 8 through 11 are the ones that forbid it. A 404 on a JSON-RPC endpoint
means the URL is wrong, which a retry cannot fix and which exit 2 would invite CI to retry
three times. And the misreading worth naming: a PRUNED transaction never reaches this
predicate as a 404 at all. Solana answers HTTP 200 with `result: null`, so pruning is
handled by the caller's bundle fallback. Case 8 pins that a 404 stays a real answer.

CASE 12 IS THE MUTATION CONTROL. It reverts the predicate to the pre-fix expression and
requires case 1 to go red against the mutant. Without it, "13 passed" is equally consistent
with a suite whose cases happen to agree with code that was never changed.

Run: python scripts/test_verify_proof_transport.py
"""

import importlib.util
import io
import sys
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Overridable so the suite can be pointed at a pre-fix copy of the script. Driving case 1
# against an older version is what shows the change did something.
TARGET = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "verify-proof.py"

TRANSPORT = True
CLAIM = False


def load(path, name="vp", source=None):
    """Import the hyphenated script as a module, optionally from mutated source."""
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    if source is None:
        spec.loader.exec_module(m)
    else:
        exec(compile(source, str(path), "exec"), m.__dict__)
    return m


def http(code):
    """A real urllib.error.HTTPError, not a stand-in, so the isinstance branch is exercised."""
    return urllib.error.HTTPError(
        "https://api.devnet.solana.com", code, f"HTTP {code}", {}, io.BytesIO(b"")
    )


# (name, exception, expected)
CASES = [
    # MUST classify as TRANSPORT -- the endpoint declined to answer.
    ("429 devnet rate limit (THE INCIDENT)", http(429), TRANSPORT),
    ("503 service unavailable (genuine 5xx)", http(503), TRANSPORT),
    ("500 internal server error", http(500), TRANSPORT),
    ("502 bad gateway", http(502), TRANSPORT),
    ("408 request timeout", http(408), TRANSPORT),
    (
        "URLError, DNS/connection refused",
        urllib.error.URLError("nodename nor servname"),
        TRANSPORT,
    ),
    ("TimeoutError", TimeoutError("timed out"), TRANSPORT),
    ("ConnectionError", ConnectionResetError("reset by peer"), TRANSPORT),
    # MUST NOT -- a real answer. Retrying is useless and exit 2 would be a lie.
    ("404 wrong RPC path (NOT a pruned tx)", http(404), CLAIM),
    ("403 forbidden", http(403), CLAIM),
    ("401 unauthorized", http(401), CLAIM),
    ("400 bad request", http(400), CLAIM),
    # A claim that stopped holding never raises a transport type at all.
    (
        "ValueError, unexpected account length",
        ValueError("unexpected account length 0"),
        CLAIM,
    ),
]

LABEL = {
    TRANSPORT: "TRANSPORT (retryable, exit 2)",
    CLAIM: "A CLAIM (exit 1, never retry)",
}

PRE_FIX = "return e.code >= 500 or e.code in TRANSPORT_HTTP_CODES"
MUTANT = "return e.code >= 500"


def main():
    if not TARGET.exists():
        print(f"target not found at {TARGET}")
        return 2

    vp = load(TARGET)
    npass = nfail = 0
    last = None
    for name, exc, want in CASES:
        if want != last:
            print(f"\nMUST BE {LABEL[want]}:")
            last = want
        got = vp.is_transport_error(exc)
        if got is want or got == want:
            print(f"  ok   {name}")
            npass += 1
        else:
            print(f"  FAIL {name} (got {got!r} want {want!r})")
            nfail += 1

    # Mutation control. Revert to the pre-fix expression and require case 1 to go red.
    print("\nMUTATION CONTROL (revert the fix; case 1 must go red):")
    src = TARGET.read_text(encoding="utf-8")
    if PRE_FIX not in src:
        print(
            f"  FAIL mutation anchor absent, so this control tested nothing: {PRE_FIX!r}"
        )
        nfail += 1
    else:
        mutant = load(TARGET, "vp_mutant", src.replace(PRE_FIX, MUTANT, 1))
        if mutant.is_transport_error(http(429)) is False:
            print(
                "  ok   pre-fix predicate calls a 429 a broken claim; the fix is load-bearing"
            )
            npass += 1
        else:
            print(
                "  FAIL mutant still classifies 429 as transport; case 1 proves nothing"
            )
            nfail += 1

    print(f"\n{npass} passed, {nfail} failed")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
