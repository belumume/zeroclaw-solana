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

Run: python3 scripts/test_check_all.py
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = ROOT / "scripts" / "check-all.py"

GATE_BODIES = {
    # name                    exit code and what it means
    "check-aaa-passes.py": "import sys; print('OK clean'); sys.exit(0)",
    "check-bbb-fails.py": "import sys; print('FAIL a real finding'); sys.exit(1)",
    "check-ccc-cannot.py": "import sys; print('nothing to compare on this machine'); sys.exit(2)",
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
    tmp = pathlib.Path(tempfile.mkdtemp())
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

    # 4. THE FLOOR. A discovery walk that silently finds nothing must refuse rather than
    #    report a clean sweep over zero gates, which is the false-green in its purest form.
    rc, out = run_with([], tmp, min_gates=13)
    check("an empty discovery walk is refused", rc == 2, f"rc={rc}")
    check("the floor explains itself", "walk is broken" in out, out[-300:])

    # 5. MUTATION CONTROL. Restore the defect and require these cases to notice. Without this,
    #    every assertion above could be passing for reasons unrelated to the counting.
    src = TARGET.read_text(encoding="utf-8")
    anchor = "checked = len(runnable) - len(not_checked)"
    if anchor not in src:
        print("  FAIL  mutation anchor is stale; the control below proves nothing")
        failures.append("mutation anchor")
    else:
        mutant_src = src.replace(anchor, "checked = len(runnable)")
        ns = {"__name__": "mutant", "__file__": str(TARGET)}
        exec(compile(mutant_src, "mutant", "exec"), ns)
        ns["ROOT"], ns["MIN_GATES"], ns["EXCLUDED"] = tmp, 0, {}
        ns["discover"] = lambda: ["check-aaa-passes.py", "check-ccc-cannot.py"]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            ns["main"]()
        mout = buf.getvalue()
        check(
            "with the fix reverted, the summary inflates its own count",
            "2 of 2 gate(s) pass" in mout,
            mout[-300:],
        )

    if failures:
        print(f"\n{len(failures)} control(s) FAILED: {', '.join(failures)}")
        return 1
    print(
        "\nOK  every control passes; the summary distinguishes pass, fail and could-not-run."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
