#!/usr/bin/env python3
"""Control for the controls: prove three mutation harnesses can tell CAUGHT from CRASHED.

WHY THIS EXISTS
---------------
`mutation-check.sh`, `mutation-check-tlv.sh` and `mutation-check-shadowed-scripts.sh`
each plant a defect and require the suite under them to go red. Until 2026-08-19 all
three decided that with `exit != 0`, and that cannot distinguish the two things a
non-zero exit means:

    CAUGHT   the harness ran, the assertions fired, the suite reported failures
    CRASHED  the harness never ran -- the mutant did not compile, the interpreter
             died, the toolchain was missing, the lockfile would not resolve

Both exit non-zero. Read as CAUGHT, a crash makes the control print "the suite
discriminates" on a day the suite never executed a single assertion. That is the exact
false green these controls exist to prevent, so it is the single most common way a
control silently stops working -- and nothing about it is visible in the output.

The two cargo-driven harnesses mutate RUST SOURCE, so "the mutant does not compile" is
not a hypothetical failure mode there, it is the MOST likely one.

HOW IT PROVES IT WITHOUT A RUST TOOLCHAIN
-----------------------------------------
The subject under test is each harness's VERDICT LOGIC, not cargo. So cargo is replaced
with a stub on PATH that reads a script of canned (stdout, exit code) responses. That
makes the crash reproducible, instant, and independent of whether this machine can build
the crate at all -- and it means this control runs on any runner, which is the whole
reason the harnesses it checks are worth wiring up.

Every scenario is run in a sandbox OUTSIDE the repository, so the real `nonce.rs` and
`mint.rs` are never mutated. The sandbox is outside on purpose: both harnesses resolve
their repo root with `git rev-parse --show-toplevel` and fall back to their own location,
so a sandbox inside the checkout would resolve to the REAL tree and mutate it.

BOTH DIRECTIONS, because one alone proves nothing. A harness that reported CRASH for
everything would pass a crash-only check while being useless, so every subject is also
driven with a genuine catch and required to return 0.

Run:  python3 scripts/mutation-check-crash-vs-catch.py
Exit: 0 all subjects discriminate, 1 at least one cannot, 2 inconclusive (setup failed).
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"

# cargo's real wording. A mutant run that reaches a verdict prints the FAILED line; one
# that dies at compile time prints neither, which is the whole discriminator.
CARGO_FAILED = "running 19 tests\ntest properties::roundtrip ... FAILED\n\ntest result: FAILED. 18 passed; 1 failed; 0 ignored\n"
CARGO_OK = "running 19 tests\n\ntest result: ok. 19 passed; 0 failed; 0 ignored\n"
CARGO_COMPILE_ERROR = (
    "   Compiling solana-core v0.1.0\n"
    "error[E0308]: mismatched types\n"
    "  --> src/nonce.rs:88:24\n"
    'error: could not compile `solana-core` (test "properties") due to 1 previous error\n'
)

# A suite that dies before asserting anything. This is what a SyntaxError in a mutated
# Python gate actually looks like, and it carries no "  FAIL" line for any case.
PY_TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "test_check_shadowed_scripts.py", line 1, in <module>\n'
    "    import check_shadowed_scripts\n"
    '  File "check-shadowed-scripts.py", line 210\n'
    "    if r.returncode ! = 0:\n"
    "                     ^\n"
    "SyntaxError: invalid syntax\n"
)


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def _stub_cargo(bindir: Path, responses) -> None:
    """A `cargo` whose Nth invocation replays responses[N-1] = (stdout, exit code)."""
    bindir.mkdir(parents=True, exist_ok=True)
    cases = []
    for i, (out, rc) in enumerate(responses, start=1):
        cases.append(
            "  %d)\n    cat <<'ZCEOF'\n%sZCEOF\n    exit %d\n    ;;" % (i, out, rc)
        )
    _write_exec(
        bindir / "cargo",
        "#!/usr/bin/env bash\n"
        "# Stub cargo for mutation-check-crash-vs-catch.py. Replays a canned script so a\n"
        "# compile failure is reproducible without a Rust toolchain.\n"
        'COUNTER="$(dirname "$0")/.calls"\n'
        'n=$(( $(cat "$COUNTER" 2>/dev/null || echo 0) + 1 ))\n'
        'echo "$n" > "$COUNTER"\n'
        'case "$n" in\n'
        + "\n".join(cases)
        + '\n  *)\n    echo "stub cargo: unscripted call $n" >&2\n    exit 127\n    ;;\nesac\n',
    )


def _run_in_sandbox(sandbox: Path, script_name: str):
    """Run a harness with the sandbox's bin first on PATH. Returns (rc, output)."""
    runner = sandbox / "run.sh"
    _write_exec(
        runner,
        "#!/usr/bin/env bash\n"
        'HERE="$(cd "$(dirname "$0")" && pwd)"\n'
        'export PATH="$HERE/bin:$PATH"\n'
        'cd "$HERE"\n'
        'exec bash "$HERE/scripts/%s"\n' % script_name,
    )
    # Invoked RELATIVE with cwd set, never as an absolute path. Measured on the dev
    # machine: bash resolved "run.sh" with cwd fine and rejected every absolute form of
    # the same file, because that bash is WSL and sees the drive as /mnt/c. A relative
    # path plus cwd is correct there, on Git Bash, and on a Linux runner alike.
    p = subprocess.run(
        ["bash", runner.name],
        cwd=str(sandbox),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _cargo_sandbox(harness: str, crate_files, responses) -> Path:
    """Sandbox holding one harness, the source it mutates, and a scripted cargo."""
    sandbox = Path(tempfile.mkdtemp(prefix="zc-crashctl-"))
    (sandbox / "scripts").mkdir()
    shutil.copy2(SCRIPTS / harness, sandbox / "scripts" / harness)
    for rel in crate_files:
        dst = sandbox / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dst)
    _stub_cargo(sandbox / "bin", responses)
    return sandbox


def _shadowed_sandbox(crashing: bool) -> Path:
    """Sandbox for the shadowed-scripts harness with a stub suite.

    The stub passes for the pristine gate (so the harness's own baseline is green) and,
    when `crashing`, dies with a traceback for any mutated gate -- naming no failing
    case, which is exactly what an unparseable mutant produces.
    """
    sandbox = Path(tempfile.mkdtemp(prefix="zc-crashctl-"))
    (sandbox / "scripts").mkdir()
    for name in ("mutation-check-shadowed-scripts.sh", "check-shadowed-scripts.py"):
        shutil.copy2(SCRIPTS / name, sandbox / "scripts" / name)
    pristine = sandbox / "pristine.py"
    shutil.copy2(SCRIPTS / "check-shadowed-scripts.py", pristine)
    on_mutant = (
        "    sys.stderr.write(%r)\n    sys.exit(1)\n" % PY_TRACEBACK
        if crashing
        else "    print('  FAIL narrowed scope missed a script')\n"
        "    print('1 of 9 cases failed')\n    sys.exit(1)\n"
    )
    (sandbox / "scripts" / "test_check_shadowed_scripts.py").write_text(
        "import sys, pathlib\n"
        "gate = pathlib.Path(sys.argv[1]).read_bytes()\n"
        "pristine = pathlib.Path(__file__).resolve().parent.parent / 'pristine.py'\n"
        "if gate == pristine.read_bytes():\n"
        "    print('9 of 9 cases pass')\n    sys.exit(0)\n"
        "else:\n" + on_mutant,
        encoding="utf-8",
        newline="\n",
    )
    return sandbox


def main() -> int:
    if not (REPO / ".git").exists():
        print("inconclusive: not a checkout")
        return 2

    nonce = "crates/solana-core/src/nonce.rs"
    mint = "crates/solana-core/src/mint.rs"
    for rel in (nonce, mint):
        if not (REPO / rel).is_file():
            print("inconclusive: %s missing; the harnesses cannot be driven" % rel)
            return 2

    # (label, subject, sandbox factory, expected rc, string the verdict must contain)
    #
    # `expect_rc` is the whole point: 0 is "this harness discriminates", 2 is "this
    # harness noticed the crash and refused to call it a catch". Before the fix every
    # CRASH row below returned 0 -- a green built on a suite that never ran.
    scenarios = [
        (
            "mutation-check.sh  CATCH (mutant fails, clean passes)",
            lambda: _cargo_sandbox(
                "mutation-check.sh",
                [nonce],
                [(CARGO_FAILED, 101), (CARGO_OK, 0)],
            ),
            "mutation-check.sh",
            0,
            "CAUGHT the injected defect",
        ),
        (
            "mutation-check.sh  CRASH (mutant does not compile)",
            lambda: _cargo_sandbox(
                "mutation-check.sh",
                [nonce],
                [(CARGO_COMPILE_ERROR, 101), (CARGO_OK, 0)],
            ),
            "mutation-check.sh",
            2,
            "That is a CRASH",
        ),
        (
            "mutation-check-tlv.sh  CATCH (both mutants fail)",
            lambda: _cargo_sandbox(
                "mutation-check-tlv.sh",
                [mint],
                [(CARGO_OK, 0), (CARGO_FAILED, 101), (CARGO_FAILED, 101)],
            ),
            "mutation-check-tlv.sh",
            0,
            "both planted defects were caught",
        ),
        (
            "mutation-check-tlv.sh  CRASH (mutant 1 does not compile)",
            lambda: _cargo_sandbox(
                "mutation-check-tlv.sh",
                [mint],
                [(CARGO_OK, 0), (CARGO_COMPILE_ERROR, 101), (CARGO_FAILED, 101)],
            ),
            "mutation-check-tlv.sh",
            2,
            "INCONCLUSIVE",
        ),
        (
            "mutation-check-shadowed-scripts.sh  CATCH (suite names a red case)",
            lambda: _shadowed_sandbox(crashing=False),
            "mutation-check-shadowed-scripts.sh",
            0,
            "every mutant was refused",
        ),
        (
            "mutation-check-shadowed-scripts.sh  CRASH (mutant will not parse)",
            lambda: _shadowed_sandbox(crashing=True),
            "mutation-check-shadowed-scripts.sh",
            1,
            "that is a CRASH",
        ),
    ]

    failed = 0
    for label, make, harness, expect_rc, expect_text in scenarios:
        sandbox = make()
        try:
            rc, out = _run_in_sandbox(sandbox, harness)
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)
        ok = rc == expect_rc and expect_text.lower() in out.lower()
        print("  %s %s" % ("ok  " if ok else "FAIL", label))
        print(
            "         rc=%s (want %s), verdict text %s"
            % (
                rc,
                expect_rc,
                "found"
                if expect_text.lower() in out.lower()
                else "MISSING: %r" % expect_text,
            )
        )
        if not ok:
            for line in out.strip().splitlines()[-8:]:
                print("         | " + line)
            failed += 1

    print()
    if failed:
        print(
            "FAIL  %d of %d scenario(s) wrong: a harness cannot tell a crashed mutant\n"
            "      from a caught one, so its green does not mean the suite ran."
            % (failed, len(scenarios))
        )
        return 1
    print(
        "PASS  %d of %d scenarios. Every harness reports a crashed mutant as a crash and\n"
        "      a genuine catch as a catch, so a non-zero exit is no longer enough to\n"
        "      make one of them print a green." % (len(scenarios), len(scenarios))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
