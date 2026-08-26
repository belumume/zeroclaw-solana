#!/usr/bin/env python3
"""Controls for check-all.py's summary, which is unfalsifiable without them.

check-all.py's whole job is to report which gates ran. A reporting fix cannot be verified by
reading it: a summary that says "11 of 13 pass" looks identical whether the counting is right
or whether it happens to agree on this machine today. So the three outcomes are driven with
synthetic gates whose behaviour is known, and the summary is required to distinguish them.

THE DEFECT THIS PINS. The summary once read "all 10 gate(s) pass" on a run where EIGHT gates
passed and TWO never executed, because a gate that could not run was folded into the pass
count. Custody is a scored axis and one of the two that cannot run reads the wasm import
table, so the summary claimed a custody check passed on a machine where it never ran. That
direction is the worst one available.

THE SECOND DEFECT, one level in. "Could not check" carried two opposite meanings: a machine
lacking a resource, and a gate whose positive control has died. The second is a defect in the
repo and the gate has stopped being evidence, yet both scored non-blocking, so a gate that
certifies blind was indistinguishable from a developer without a Rust toolchain. Measured on
check-correction-traces.py: killing one control sample made it print "that pattern is dead"
and exit 2, and check-all printed `n/a` and returned 0.

Run: python3 scripts/test_check_all.py
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = ROOT / "scripts" / "check-all.py"

GATE_BODIES = {
    # name                    exit code and what it means
    "check-aaa-passes.py": "import sys; print('OK clean'); sys.exit(0)",
    "check-bbb-fails.py": "import sys; print('FAIL a real finding'); sys.exit(1)",
    "check-ccc-cannot.py": "import sys; print('nothing to compare on this machine'); sys.exit(2)",
    # Its reason goes to STDERR on purpose. That is where check-correction-traces writes every
    # refusal, and reading stdout alone printed a fallback string for exactly the gates whose
    # reason matters most, so the row said a gate was blocking and not why.
    "check-ddd-dead.py": (
        "import sys; print('FAIL positive control for x did not fire; that pattern is dead.',"
        " file=sys.stderr); sys.exit(3)"
    ),
}


def load():
    spec = importlib.util.spec_from_file_location("check_all", TARGET)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_with(gate_names: list[str], tmp: pathlib.Path, min_gates: int = 0):
    """Drive the real main() against synthetic gates. Returns (rc, printed output)."""
    mod = load()
    mod.ROOT = tmp
    mod.MIN_GATES = min_gates
    mod.EXCLUDED = {}
    mod.discover = lambda: gate_names
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = mod.main()
    return rc, buf.getvalue()


def main() -> int:
    # Cleaned up at the end rather than left behind; a local run should not accumulate
    # directories, and an untidy control is one people stop running.
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        return _run(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run(tmp: pathlib.Path) -> int:
    (tmp / "scripts").mkdir()
    for name, body in GATE_BODIES.items():
        (tmp / "scripts" / name).write_text(body, encoding="utf-8", newline="\n")

    failures = []

    def check(label: str, cond: bool, detail: str = ""):
        print(
            f"  {'ok  ' if cond else 'FAIL'}  {label}"
            + ("" if cond else f"\n        {detail}")
        )
        if not cond:
            failures.append(label)

    # 1. A GENUINELY FAILING GATE must be reported as a failure, not counted as a pass.
    rc, out = run_with(["check-aaa-passes.py", "check-bbb-fails.py"], tmp)
    check("a failing gate makes the run fail", rc == 1, f"rc={rc}")
    check("the failing gate is named", "check-bbb-fails.py" in out, out[-300:])
    check(
        "no pass-claim is printed alongside a failure",
        "gate(s) pass" not in out,
        out[-300:],
    )

    # 2. A GATE THAT CANNOT RUN must be distinguished from a pass, in the count AND in words.
    rc, out = run_with(["check-aaa-passes.py", "check-ccc-cannot.py"], tmp)
    check("an unrunnable gate does not fail the run", rc == 0, f"rc={rc}")
    check(
        "it is excluded from the pass count", "1 of 2 gate(s) pass" in out, out[-300:]
    )
    check(
        "it is named as NOT a pass",
        "COULD NOT CHECK and is NOT a pass" in out,
        out[-300:],
    )
    check("the unrunnable gate is named", "check-ccc-cannot.py" in out, out[-300:])

    # 2b. A GATE WHOSE CONTROL IS DEAD is not the same outcome, and must BLOCK.
    #     An environment cannot-check is nobody's defect and stays non-blocking (case 2 above).
    #     This one says the gate can no longer produce the opposite verdict, so its clean line
    #     is not evidence and a run carrying it must not return 0. Measured before the state
    #     existed: killing one positive control in check-correction-traces.py made it print
    #     "that pattern is dead" and exit 2, and check-all printed `n/a` and returned 0.
    rc, out = run_with(["check-aaa-passes.py", "check-ddd-dead.py"], tmp)
    check("a dead control makes the run non-zero", rc != 0, f"rc={rc}")
    check("and it is rc=2, not a subject finding", rc == 2, f"rc={rc}")
    check("the blocking gate is named", "check-ddd-dead.py" in out, out[-400:])
    check(
        "it is excluded from the pass count, like a cannot-check",
        "1 of 2 gate(s) pass" in out,
        out[-400:],
    )
    check(
        "the summary says it BLOCKS rather than folding it into COULD NOT CHECK",
        "CANNOT PROVE IT CAN FAIL and BLOCKS this run" in out
        and "COULD NOT CHECK" not in out,
        out[-400:],
    )
    check(
        "the gate's own reason survives, from stderr",
        "that pattern is dead" in out,
        out[-400:],
    )

    # 2c. BOTH AT ONCE. A blocking gate must not hide behind a failing one, or the run reports
    #     a finding and silently drops the fact that another gate stopped being evidence.
    rc, out = run_with(["check-bbb-fails.py", "check-ddd-dead.py"], tmp)
    check("a real finding still outranks, rc=1", rc == 1, f"rc={rc}")
    check(
        "and the blocking gate is still reported",
        "check-ddd-dead.py" in out and "CANNOT DEMONSTRATE THEY CAN FAIL" in out,
        out[-400:],
    )

    # 3. THE INVERSE, which is the bug: an all-passing run must NOT use the two-outcome wording.
    rc, out = run_with(["check-aaa-passes.py"], tmp)
    check(
        "an all-clean run says all pass",
        rc == 0 and "all 1 gate(s) pass" in out,
        out[-300:],
    )
    check(
        "and does not claim a could-not-check", "COULD NOT CHECK" not in out, out[-300:]
    )
    check(
        "and adding the third state left a healthy run untouched",
        "BLOCKS this run" not in out and "DEAD" not in out,
        out[-300:],
    )

    # 4. THE FLOOR. A discovery walk that silently finds nothing must refuse rather than
    #    report a clean sweep over zero gates, which is the false-green in its purest form.
    rc, out = run_with([], tmp, min_gates=13)
    check("an empty discovery walk is refused", rc == 2, f"rc={rc}")
    check("the floor explains itself", "walk is broken" in out, out[-300:])

    # 5. MUTATION CONTROLS. Restore each defect and require the cases above to notice. Without
    #    these, every assertion could be passing for reasons unrelated to the mechanism named.
    src = TARGET.read_text(encoding="utf-8")

    def mutate(anchor: str, replacement: str, gates: list[str]):
        """Run a one-edit mutant of the real file. Returns its output, or None if stale."""
        if anchor not in src:
            return None
        ns = {"__name__": "mutant", "__file__": str(TARGET)}
        exec(compile(src.replace(anchor, replacement), "mutant", "exec"), ns)
        ns["ROOT"], ns["MIN_GATES"], ns["EXCLUDED"] = tmp, 0, {}
        ns["discover"] = lambda: gates
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = ns["main"]()
        return rc, buf.getvalue()

    # 5a. The counting fix: fold an unrunnable gate back into the numerator.
    got = mutate(
        "checked = len(runnable) - len(not_checked) - len(blocked)",
        "checked = len(runnable)",
        ["check-aaa-passes.py", "check-ccc-cannot.py"],
    )
    if got is None:
        print("  FAIL  counting mutation anchor is stale; that control proves nothing")
        failures.append("counting mutation anchor")
    else:
        check(
            "with the fix reverted, the summary inflates its own count",
            "2 of 2 gate(s) pass" in got[1],
            got[1][-300:],
        )

    # 5b. The discrimination itself. Neutralising the one branch that separates a dead control
    #     from an environment refusal must put the run back to reporting a clean, non-blocking
    #     n/a -- which is precisely the measured defect. If this mutant still blocks, case 2b is
    #     green for some reason other than the branch it claims to test.
    got = mutate(
        "if r.returncode == CONTROL_DEAD:",
        "if False:",
        ["check-aaa-passes.py", "check-ddd-dead.py"],
    )
    if got is None:
        print("  FAIL  discrimination anchor is stale; case 2b proves nothing")
        failures.append("discrimination mutation anchor")
    else:
        mrc, mout = got
        check(
            "with the discrimination disabled, a dead control stops blocking",
            mrc == 0,
            f"rc={mrc}",
        )
        check(
            "and is misreported as a plain could-not-check",
            "COULD NOT CHECK and is NOT a pass: check-ddd-dead.py" in mout,
            mout[-300:],
        )

    if failures:
        print(f"\n{len(failures)} control(s) FAILED: {', '.join(failures)}")
        return 1
    print(
        "\nOK  every control passes; the summary distinguishes pass, fail, could-not-run "
        "and cannot-prove-it-can-fail."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
