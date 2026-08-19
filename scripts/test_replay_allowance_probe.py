"""Controls for scripts/replay_allowance_probe.py, driven in every direction it can go.

WHY THIS FILE EXISTS. The probe's whole job is to answer a sceptic who has just replayed our
captured over-cap transaction, received custom error 300 at every amount they tried, and
reasonably suspects the proof is stale. Its answer is that the refusal boundary sits at the
delegation's REMAINING allowance rather than at the original cap. An instrument making that
argument is worth exactly as much as the evidence that it could have returned a different
answer, so this suite plants each wrong world and requires the probe to notice.

THE LOAD-BEARING CASE IS 3, not 1. A probe that printed PASS whenever the program refused
something would satisfy the naive reading and would be worthless, because a program that had
genuinely broken would refuse everything and print the same PASS. Case 3 is that world: every
amount refused, remaining allowance non-zero. If case 3 stops failing, the probe has stopped
distinguishing "the cap arithmetic is running" from "nothing works any more", which is the one
distinction it was written to make.

NO NETWORK IS TOUCHED. Every case substitutes the module's `rpc` function, so the suite is
deterministic and runnable in CI. The real bundle on disk is used as the fixture, and the suite
digests it before and after to prove it was never written to.
"""

import base64
import hashlib
import io
import json
import runpy
import struct
import sys
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = ROOT / "docs" / "proof-bundle" / "mainnet-transactions.json"
# The devnet bundle records TWO captures refused with 300, from two different delegations, and
# that is what cases 9 to 11 are about. It is the real fixture rather than a crafted one because
# the incident was real: adding the buy-loop capture on 2026-08-16 silently broke the command
# documented in DEVNET-PROOF.md, which had been correct when it was written.
DEVNET_BUNDLE = ROOT / "docs" / "proof-bundle" / "devnet-transactions.json"
# The capture the surrounding prose is about, cited in README, DEVNET-PROOF and verify-proof.py's
# own transaction list. The other refusal in that bundle belongs to the buy-loop run.
DEVNET_CANONICAL = "3TLSrfWVYdC3hSiAWnyyd7T694bLJQDtdJYQ64EWUsBNDehGc6Kq1veR7xa8Y1BiMdpvfFm3N1dKjDrXF3BEq2ps"
DEVNET_OTHER = "5P9wTdBHPqQASpUycrrkmcxhuRG6Pum76fRQVG3bLmeB2s1DEvkxuF7FYSodsbedtFJcmr9WyNj2774WSJa5sZcq"
PROBE = ROOT / "scripts" / "replay_allowance_probe.py"

REMAINING = 100_000
DELEGATION = "HVVeimGq8VD4CuBgrvqWsgQV1GRVhfVNYQxJxTocUNY9"
OWNER = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44"

REFUSED_300 = {"err": {"InstructionError": [0, {"Custom": 300}]}}
ACCEPTED = {"err": None}


def account_blob(remaining: int) -> str:
    """A delegation account whose last sixteen bytes are (remaining, expiry)."""
    body = bytes(171) + struct.pack("<Q", remaining) + struct.pack("<Q", 1788190366)
    return base64.b64encode(body).decode()


def load_probe(probe=None):
    mod = runpy.run_path(str(probe or PROBE), run_name="__probe__")
    return mod


def run_case(rpc_impl, argv=None, bundle=None, probe=None):
    """Execute the probe's main() with a substituted rpc, returning (rc, stdout)."""
    mod = load_probe(probe)
    mod["rpc"] = rpc_impl
    main = mod["main"]
    # main() closes over the module globals dict returned by runpy, so rebinding `rpc`
    # inside it is what the function will actually call.
    main.__globals__["rpc"] = rpc_impl
    saved = sys.argv
    sys.argv = ["replay_allowance_probe.py", "--bundle", str(bundle or BUNDLE)] + (
        argv or []
    )
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            rc = main()
    except SystemExit as exc:
        rc = exc.code if isinstance(exc.code, int) else 1
        buf.write(str(exc))
    finally:
        sys.argv = saved
    return rc, buf.getvalue()


def make_rpc(sim_for_amount, remaining=REMAINING, account_exists=True):
    """Build an rpc stand-in. `sim_for_amount` maps a replayed amount to a sim result."""

    def _rpc(url, method, params):
        if method == "getAccountInfo":
            if not account_exists:
                return {"value": None}
            return {
                "value": {"data": [account_blob(remaining), "base64"], "owner": OWNER}
            }
        if method == "simulateTransaction":
            raw = base64.b64decode(params[0])
            # Recover the amount the probe patched in, the same way the probe found it.
            i, hits = 0, []
            while True:
                i = raw.find(bytes([4]), i)
                if i == -1:
                    break
                if i + 73 <= len(raw) and raw[i - 1] == 73:
                    hits.append(i)
                i += 1
            amount = struct.unpack_from("<Q", raw, hits[0] + 1)[0]
            return {"value": sim_for_amount(amount)}
        raise AssertionError(f"unexpected rpc method {method}")

    return _rpc


def real_world(amount):
    return REFUSED_300 if amount > REMAINING else ACCEPTED


CASES = []


def case(name, marker, expect_rc):
    def deco(fn):
        CASES.append((name, marker, expect_rc, fn))
        return fn

    return deco


@case(
    "1 truthful world: boundary at the remaining allowance",
    "PASS  the refusal boundary",
    0,
)
def c1():
    return run_case(make_rpc(real_world))


@case("2 the captured amount is still refused with 300", "1000000  refused 300", 0)
def c2():
    return run_case(make_rpc(real_world))


@case("3 CONTROL: program refuses EVERY amount", "nothing was accepted", 1)
def c3():
    return run_case(make_rpc(lambda amount: REFUSED_300))


@case("4 CONTROL: program accepts EVERY amount", "nothing was refused", 1)
def c4():
    return run_case(make_rpc(lambda amount: ACCEPTED))


@case("5 CONTROL: delegation account is gone", "does not exist", 1)
def c5():
    return run_case(make_rpc(real_world, account_exists=False))


@case(
    "6 exhausted allowance: refuse-all is the CORRECT verdict", "allowance exhausted", 0
)
def c6():
    return run_case(make_rpc(lambda amount: REFUSED_300, remaining=0))


@case(
    "7 a non-300 refusal is reported verbatim, not laundered into 300", "refused {", 1
)
def c7():
    other = {"err": {"InstructionError": [0, {"Custom": 302}]}}
    return run_case(make_rpc(lambda amount: other))


@case(
    "8 CONTROL: a bundle with no refused capture is refused, not guessed",
    "expected exactly one transaction refused",
    1,
)
def c8():
    import tempfile

    src = json.loads(BUNDLE.read_text(encoding="utf-8"))
    for tx in src["transactions"].values():
        tx["err"] = None
    tmp = Path(tempfile.mkdtemp()) / "no-refusal.json"
    tmp.write_text(json.dumps(src), encoding="utf-8")
    return run_case(make_rpc(real_world), bundle=tmp)


@case(
    "9 CONTROL: two refused captures and no --signature is refused, and both are NAMED",
    "Re-run with --signature naming one of",
    1,
)
def c9():
    """THE INCIDENT. The devnet bundle really does record two refusals, so the command
    documented in DEVNET-PROOF.md failed for everyone who ran it. Refusing is correct; the
    defect was that the message named no way forward, so a reader hitting it had nowhere to
    go and the doc looked simply wrong."""
    rc, out = run_case(make_rpc(real_world), bundle=DEVNET_BUNDLE)
    # Naming the candidates is the whole repair, so assert both are actually listed rather
    # than trusting the sentence that says they will be.
    if DEVNET_CANONICAL not in out or DEVNET_OTHER not in out:
        return rc, out + "\n(BOTH candidate signatures were NOT listed)"
    return rc, out


@case(
    "10 CONTROL: --signature selects one of the two and the probe runs",
    "PASS  the refusal boundary",
    0,
)
def c10():
    """The over-correction control for case 9. Refusing every multi-capture bundle would
    satisfy case 9 perfectly and leave the documented command just as dead, so this requires
    that naming one actually gets a reader through."""
    return run_case(
        make_rpc(real_world),
        argv=["--signature", DEVNET_CANONICAL],
        bundle=DEVNET_BUNDLE,
    )


@case(
    "11 CONTROL: a --signature matching nothing is refused, not silently ignored",
    "must select exactly one",
    1,
)
def c11():
    return run_case(
        make_rpc(real_world), argv=["--signature", "ZZZnope"], bundle=DEVNET_BUNDLE
    )


def mutation_control():
    """Revert the selection and require case 10 to go red.

    Cases 9 to 11 all pass against code that never learned to select, because refusing is
    what two of them expect. Only case 10 distinguishes "names a candidate and proceeds"
    from "refuses everything", so that is the one driven against the mutant.

    The mutant is written to a fresh temp directory and is a DIFFERENT LENGTH from its
    anchor, because CPython invalidates a cached .pyc on size and mtime: a same-length edit
    inside one clock tick would execute the ORIGINAL bytecode and this control would
    silently test nothing.
    """
    import tempfile

    src = PROBE.read_text(encoding="utf-8")
    anchor, replacement = "if args.signature:", "if False:"
    if anchor not in src:
        return (
            False,
            f"mutation anchor absent, so this control tested nothing: {anchor!r}",
        )
    if len(anchor) == len(replacement):
        return (
            False,
            "mutant is the same length as its anchor; the .pyc cache can mask it",
        )
    mutant_src = src.replace(anchor, replacement, 1)
    if mutant_src == src:
        return False, "substitution did not apply"
    mutant = Path(tempfile.mkdtemp()) / "probe_mutant.py"
    mutant.write_text(mutant_src, encoding="utf-8")
    compile(mutant_src, str(mutant), "exec")  # a mutant that cannot parse tests nothing
    rc, out = run_case(
        make_rpc(real_world),
        argv=["--signature", DEVNET_CANONICAL],
        bundle=DEVNET_BUNDLE,
        probe=mutant,
    )
    if rc == 0:
        return False, "the mutant still ran; case 10 proves nothing"
    return True, f"selection removed -> the documented command dies again (rc={rc})"


def main():
    before = hashlib.sha256(BUNDLE.read_bytes()).hexdigest()
    devnet_before = hashlib.sha256(DEVNET_BUNDLE.read_bytes()).hexdigest()
    passed = failed = 0
    for name, marker, expect_rc, fn in CASES:
        rc, out = fn()
        ok = rc == expect_rc and marker in out
        if ok:
            passed += 1
            print(f"  ok   {name}")
        else:
            failed += 1
            print(
                f"  FAIL {name}\n       rc={rc} (expected {expect_rc}), "
                f"marker {marker!r} {'present' if marker in out else 'ABSENT'}"
            )
            print("       ---8<--- output\n" + out + "       --->8---")

    print("\nMUTATION CONTROL (remove the selection; case 10 must go red):")
    mut_ok, mut_why = mutation_control()
    if mut_ok:
        passed += 1
        print(f"  ok   {mut_why}")
    else:
        failed += 1
        print(f"  FAIL {mut_why}")

    after = hashlib.sha256(BUNDLE.read_bytes()).hexdigest()
    devnet_after = hashlib.sha256(DEVNET_BUNDLE.read_bytes()).hexdigest()
    if before != after or devnet_before != devnet_after:
        print(
            "FAIL: the suite modified a real proof bundle; refusing to report a result."
        )
        return 1
    print(
        f"\n{passed}/{passed + failed} controls passed (proof bundles unmodified: "
        f"mainnet {before[:12]}, devnet {devnet_before[:12]})"
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
