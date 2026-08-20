#!/usr/bin/env python3
"""Controls for build-social-card.py's --refresh measurement, in both directions.

WHY THIS FILE EXISTS. The card carries a stamp -- "figures verified <date>" -- and that stamp
is the reason a wrong figure here is worse than a stale one. A stale card understates and says
so; a card reading "0 on-chain publishes" beside today's date is a false claim wearing a
freshness badge, rendered into the og:image, twitter:image and video poster of a public repo.

THE DEFECT THESE CONTROL, measured on 2026-08-19 before the fix. A JSON-RPC error arrives with
HTTP 200, so `urlopen` raised nothing and the body simply had no `result`. `.get("result") or
[]` turned that into a page of no signatures, the walk broke on the empty page, and `refresh()`
wrote publishes="0", span="0 days" and a stamp bearing today's date, then returned normally so
`render()` committed it. The generator's own positive control did not catch it: it reads
getAccountInfo, a different method at a different moment, and it passed.

WHY EVERY CASE DRIVES `urlopen` RATHER THAN `rpc`. Substituting `rpc` is easier and would have
tested the wrong thing -- it bypasses the very function the fix lives in, so the raise on an
error body would never execute and a suite could go green over a reverted fix. These cases
replace the transport underneath the real `rpc()`, so the production path runs.

TWO MUTATION CONTROLS, and writing them found something about the fix worth recording. Mutation
A removes the raise on an error body and requires the MID-WALK case to start rendering a
truncated count; that guard is load-bearing for the verdict. Mutation B was written the same way
and FAILED, because on an empty walk the blockTime guard below the zero floor refuses the input
anyway. So the zero floor does not change whether that case is refused -- it changes what the
refusal SAYS, supplying the page denominator that separates "the feed never published" from "the
read failed". B asserts that instead. A control aimed at a verdict the guard does not decide
would have passed only by accident, and asserting the stronger claim would have asserted
something false.

NO NETWORK IS TOUCHED. Run: python3 scripts/test_build_social_card_refresh.py
"""

import importlib.util
import io
import json
import sys
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "scripts" / "build-social-card.py"

RENDERED = 0  # refresh() returned, so render() would have committed these figures
REFUSED = 1  # refresh() called sys.exit, so nothing is rendered
CRASHED = (
    2  # an exception escaped: a traceback, not a refusal, and not acceptable either
)


class Resp:
    """The two attributes rpc() actually uses off a urlopen result."""

    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b


def page(n, newest=1_700_000_000, step=1200, failures=0, blocktime=True):
    """One getSignaturesForAddress page, newest first, the way the RPC returns them."""
    return {
        "result": [
            {
                "signature": f"sig{i:04d}",
                "err": {"InstructionError": []} if i < failures else None,
                "blockTime": (newest - i * step) if blocktime else None,
            }
            for i in range(n)
        ]
    }


JSONRPC_ERROR = {
    "jsonrpc": "2.0",
    "id": 1,
    "error": {"code": -32602, "message": "boom"},
}


def transport(pages, executable=True):
    """A urlopen stand-in. `pages` are served to successive signature queries, in order."""
    seen = {"n": 0}

    def _open(req, timeout=None):
        method = json.loads(req.data.decode())["method"]
        if method == "getAccountInfo":
            return Resp({"result": {"value": {"executable": executable}}})
        i = seen["n"]
        seen["n"] += 1
        return Resp(pages[min(i, len(pages) - 1)])

    return _open


def load(source=None):
    """Fresh module per case: refresh() mutates FIGURES, so instances must not be shared."""
    spec = importlib.util.spec_from_file_location("bsc_under_test", GEN)
    m = importlib.util.module_from_spec(spec)
    if source is None:
        spec.loader.exec_module(m)
    else:
        exec(compile(source, str(GEN), "exec"), m.__dict__)
    return m


def run_case(opener, source=None):
    m = load(source)
    pinned = dict(m.FIGURES)
    saved = urllib.request.urlopen
    urllib.request.urlopen = opener
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            m.refresh()
        rc = RENDERED
    except SystemExit as exc:
        rc = REFUSED
        buf.write(str(exc.code))
    except Exception as exc:
        # Deliberately broad, and CRASHED is a distinct verdict from REFUSED: an exception
        # escaping refresh() is a traceback rather than a refusal, which is its own defect.
        rc = CRASHED
        buf.write(f"UNCAUGHT {type(exc).__name__}: {exc}")
    finally:
        urllib.request.urlopen = saved
    return rc, buf.getvalue(), dict(m.FIGURES), pinned


CASES = []


def case(name, expect_rc, check):
    def deco(fn):
        CASES.append((name, expect_rc, check, fn))
        return fn

    return deco


def unchanged(out, figures, pinned):
    """The load-bearing assertion for every refusal: the pinned figures survived intact."""
    return figures == pinned


@case(
    "1 truthful walk: the figures are measured and the page count is reported",
    RENDERED,
    lambda out, f, p: f["publishes"] == "500" and "over 1 page(s)" in out,
)
def c1():
    return run_case(transport([page(500)]))


@case(
    "2 THE INCIDENT: a JSON-RPC error at HTTP 200 is refused, not counted as zero",
    REFUSED,
    lambda out, f, p: unchanged(out, f, p) and f["publishes"] != "0",
)
def c2():
    return run_case(transport([JSONRPC_ERROR]))


@case(
    "3 a genuinely empty answer is refused too, and names the pages it fetched",
    REFUSED,
    lambda out, f, p: unchanged(out, f, p) and "across 1 page(s) fetched" in out,
)
def c3():
    return run_case(transport([{"result": []}]))


@case(
    "4 a MID-WALK failure is refused, not rendered as a truncated count",
    REFUSED,
    lambda out, f, p: unchanged(out, f, p) and "1,000 signature(s)" in out,
)
def c4():
    return run_case(transport([page(1000), JSONRPC_ERROR]))


@case(
    "5 signatures with no blockTime are refused, not rendered as '0 days'",
    REFUSED,
    lambda out, f, p: unchanged(out, f, p) and "no usable blockTime" in out,
)
def c5():
    return run_case(transport([page(5, blocktime=False)]))


@case(
    "6 CONTROL: the oracle coming back non-executable still refuses",
    REFUSED,
    lambda out, f, p: unchanged(out, f, p) and "CONTROL FAILED" in out,
)
def c6():
    return run_case(transport([page(500)], executable=False))


@case(
    "7 OVER-CORRECTION CONTROL: a real walk with failures still measures and renders",
    RENDERED,
    lambda out, f, p: f["publishes"] == "500" and f["failed"] == "7",
)
def c7():
    """Cases 2 to 6 are all refusals, and a refresh() that simply refused everything would
    satisfy every one of them while leaving the generator useless. This is the case that
    forbids it: a walk that genuinely worked must still produce figures."""
    return run_case(transport([page(500, failures=7)]))


def mutate(anchor, replacement, drive, want_rc, want, describe):
    """Apply one source substitution and require the named case to change verdict."""
    src = GEN.read_text(encoding="utf-8")
    if anchor not in src:
        return False, f"anchor absent, so this control tested nothing: {anchor!r}"
    if len(anchor) == len(replacement):
        # CPython invalidates a cached .pyc on source SIZE and mtime, so a same-length edit
        # inside one clock tick can execute the original bytecode and pass over a live mutant.
        return (
            False,
            f"mutant is the same length as {anchor!r}; the .pyc cache can mask it",
        )
    mutant = src.replace(anchor, replacement, 1)
    if mutant == src:
        return False, f"substitution did not apply for {anchor!r}"
    compile(mutant, str(GEN), "exec")  # a mutant that cannot parse tests nothing
    rc, out, figures, pinned = drive(mutant)
    if rc != want_rc or not want(out, figures, pinned):
        return (
            False,
            f"the mutant behaved as the real code did (rc={rc}); it proves nothing",
        )
    return True, describe(out, figures)


def main():
    passed = failed = 0
    for name, expect_rc, check, fn in CASES:
        rc, out, figures, pinned = fn()
        ok = rc == expect_rc and check(out, figures, pinned)
        if ok:
            passed += 1
            print(f"  ok   {name}")
        else:
            failed += 1
            print(
                f"  FAIL {name}\n       rc={rc} (expected {expect_rc}), figures={figures}"
            )
            print("       ---8<---\n" + out + "\n       --->8---")

    print("\nMUTATION CONTROLS (each guard must be shown load-bearing on its own):")
    for label, anchor, replacement, drive, want_rc, want, describe in (
        (
            "A  the raise on a JSON-RPC error body (drives case 4)",
            'if "error" in out:',
            "if False:",
            lambda src: run_case(transport([page(1000), JSONRPC_ERROR]), source=src),
            RENDERED,
            lambda out, f, p: f["publishes"] == "1,000",
            lambda out,
            f: f"removed -> {f['publishes']!r} publishes would RENDER, truncated",
        ),
        (
            # The zero floor does NOT change the VERDICT on an empty walk -- the blockTime
            # guard below it refuses that input anyway -- so asserting a render here would be
            # asserting something false, and a control that cannot fail is worse than none.
            # What the floor uniquely supplies is the DIAGNOSIS the brief asked for: the page
            # denominator, which is the only thing separating "the feed never published" from
            # "the read failed". Remove it and the refusal survives while its explanation
            # becomes wrong, blaming a missing blockTime for an answer that was never read.
            "B  the zero floor's diagnosis, incl. the page denominator (drives case 3)",
            "if total == 0:",
            "if False:",
            lambda src: run_case(transport([{"result": []}]), source=src),
            REFUSED,
            lambda out, f, p: "page(s) fetched" not in out and "blockTime" in out,
            lambda out,
            f: "removed -> still refuses, but now misdiagnoses it as a blockTime "
            "problem and names no denominator",
        ),
    ):
        ok, why = mutate(anchor, replacement, drive, want_rc, want, describe)
        if ok:
            passed += 1
            print(f"  ok   {label}\n         {why}")
        else:
            failed += 1
            print(f"  FAIL {label}\n         {why}")

    print(f"\n{passed}/{passed + failed} controls passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
