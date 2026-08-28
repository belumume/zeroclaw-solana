#!/usr/bin/env python3
"""Bind SKILL.md's claim about WHERE the rate provenance appears to where pay_link.py prints it.

WHY THIS GATE EXISTS, and why the test suite does not already cover it. `test_pay_link.py` pins
the SCRIPT: it proves the `rate:` line reaches stdout and that every refusal leaves stdout empty.
It says nothing about the DOCUMENT. SKILL.md could go back to telling the model to read the
provenance from stderr and all 90 of those cases would stay green, because none of them reads
SKILL.md. That is the exact defect this gate is named after: on 2026-08-27 the instruction pointed
at a sink the model cannot reach, so the model quoted the only rate it held, which was the
unverified proposal figure the same document forbids it from reporting. Nothing was red, because
nothing was comparing the two halves.

The failing half is never the code and never the prose on its own. It is the EDGE between them,
and an edge needs a gate that names both artifacts.

HOW IT DECIDES, and why it runs the script rather than grepping it. SKILL.md's own note on writing
gates over it says to assert on the EMITTED VALUE rather than on a token's presence in a document
that has to discuss the hazard it forbids. So this executes `pay_link.py` against planted rate
sources, reads the real stdout, and compares it to the example SKILL.md publishes. Both sides are
derived from the artifacts; neither is restated here.

Deliberately NOT asserted: that the word "stderr" is absent from SKILL.md. The document explains
the operator's trace and has to name it, so an absence check would be red on the correct file and
green on one that never mentioned the sink at all.

Exit codes are TRI-STATE, because "I could not look" is not a pass and not a failure:
  0  the document and the script agree
  1  they disagree
  2  CANNOT CHECK, with the reason named

Run: python3 scripts/check-rate-provenance-channel.py
     python3 scripts/check-rate-provenance-channel.py --selftest
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "skills" / "solana-pay" / "scripts" / "pay_link.py"
DOC = ROOT / "skills" / "solana-pay" / "SKILL.md"

MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
ORDER_URL = f"solana:{MERCHANT}?amount=15.74&spl-token={USDC}"

# Planted so the gate needs no network and cannot rot as the rate moves. The two sources carry
# DIFFERENT figures, inside the divergence band, so a run that reported the corroborator instead
# of the source of truth would still produce a link and would still be caught here.
BCB_RATE, ECB_RATE, RATE_DATE = 5.0827, 5.11, "2026-08-26"

STUB = """
import json, sys, urllib.request
SCRIPT = __SCRIPT__

class _Resp:
    def __init__(self, text):
        self._b = text.encode("utf-8")
        self.status = 200
    def read(self):
        return self._b
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False

def _planted(req, timeout=None):
    url = getattr(req, "full_url", None) or str(req)
    if "olinda" in url:
        return _Resp(json.dumps({"value": [{"cotacaoVenda": __BCB__,
                                            "dataHoraCotacao": __DATE__ + " 13:00:00"}]}))
    return _Resp(json.dumps({"rates": {"BRL": __ECB__}, "date": __DATE__}))

urllib.request.urlopen = _planted
sys.argv = [SCRIPT] + sys.argv[1:]
exec(compile(open(SCRIPT, encoding="utf-8").read(), SCRIPT, "exec"), {"__name__": "__main__"})
"""


def emitted(script: Path):
    """(rc, stdout, stderr) from a real priced run against planted sources."""
    body = (
        STUB.replace("__SCRIPT__", repr(str(script)))
        .replace("__BCB__", repr(BCB_RATE))
        .replace("__ECB__", repr(ECB_RATE))
        .replace("__DATE__", repr(RATE_DATE))
    )
    fh = tempfile.NamedTemporaryFile(
        "w", suffix="_gatestub.py", delete=False, encoding="utf-8"
    )
    fh.write(body)
    fh.close()
    p = subprocess.run(
        [sys.executable, fh.name, ORDER_URL, "--brl", "80", "--quote", "R$ 80"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def documented_example(doc_text: str):
    """The `rate:` line SKILL.md publishes as the shape the model should read.

    Read out of a fenced block rather than out of prose, so a sentence that merely discusses the
    line is not mistaken for the specimen.
    """
    for block in re.findall(r"```[a-zA-Z]*\n(.*?)```", doc_text, re.DOTALL):
        for line in block.splitlines():
            if line.strip().startswith("rate: "):
                return line.strip()
    return None


def shape(line: str):
    """A comparable skeleton: the prose scaffolding with every number blanked out.

    Comparing skeletons rather than text is what lets the published rate move, the divergence
    percentage change, and the order value differ, without any of that reading as drift. What it
    still catches is a renamed source, a dropped date, a reordered field or a changed prefix.
    """
    return re.sub(r"[0-9]+(?:[.,][0-9]+)*", "N", line).strip()


def check(script: Path = SCRIPT, doc: Path = DOC):
    problems = []

    if not script.exists():
        return 2, [f"CANNOT CHECK: {script} is missing"]
    if not doc.exists():
        return 2, [f"CANNOT CHECK: {doc} is missing"]

    rc, out, err = emitted(script)
    if rc != 0:
        return 2, [
            f"CANNOT CHECK: a planted priced run exited {rc}, so there is no emitted value to "
            f"compare against. stderr={err.strip()[:200]!r}"
        ]

    out_lines = [ln for ln in out.splitlines() if ln.strip()]
    real = [ln for ln in out_lines if ln.startswith("rate: ")]

    if not real:
        problems.append(
            "pay_link.py prints NO provenance line to stdout on a priced order. SKILL.md tells "
            "the model to quote the rate and date the script used, and the model receives stdout "
            "and nothing else, so that instruction cannot be followed. Print the rate line to "
            "stdout as well as to stderr."
        )
    if len(real) > 1:
        problems.append(
            f"pay_link.py prints {len(real)} provenance lines to stdout; the model cannot tell "
            f"which one priced the order."
        )
    if not out_lines or not out_lines[-1].startswith("https://"):
        problems.append(
            f"the LAST line of stdout is not the pay link, which SKILL.md tells the model to take "
            f"from there. got {out_lines[-1:]!r}"
        )
    if real and real[0] not in err:
        problems.append(
            "the provenance line reaches stdout but no longer reaches stderr, so the operator's "
            "trace has lost the figure that priced the order. It belongs on BOTH sinks."
        )

    spec = documented_example(doc.read_text(encoding="utf-8"))
    if spec is None:
        problems.append(
            "SKILL.md publishes no `rate:` specimen in a fenced block, so the model is told to "
            "quote a line whose shape the document never shows. Add the example back."
        )
    elif real and shape(spec) != shape(real[0]):
        problems.append(
            "SKILL.md's published `rate:` specimen does not match what pay_link.py emits.\n"
            f"  documented: {shape(spec)}\n"
            f"  emitted:    {shape(real[0])}\n"
            "A model quoting the documented shape would report fields the script does not print."
        )

    return (1 if problems else 0), problems


def _mutate(text, old, new, label):
    if text.count(old) != 1:
        raise AssertionError(
            f"selftest mutant {label!r}: anchor matched {text.count(old)} times, so the mutant "
            f"would be identical to the original and the control would prove nothing."
        )
    return text.replace(old, new, 1)


def selftest():
    """Drive the gate to BOTH verdicts on known inputs.

    A gate that has only ever returned 0 is a hypothesis. Each mutant below breaks exactly one
    half of the edge and must be caught; the over-correction control changes numbers that are
    ALLOWED to move and must still pass.
    """
    src = SCRIPT.read_text(encoding="utf-8")
    doc = DOC.read_text(encoding="utf-8")
    results = []

    rc, problems = check()
    results.append(("pristine tree agrees", rc == 0, f"rc={rc} {problems}"))

    tmp = Path(tempfile.mkdtemp())

    # M1: the script stops printing the provenance to stdout, which is the 2026-08-27 defect.
    m1 = tmp / "m1_pay_link.py"
    m1.write_text(
        _mutate(src, "    print(rate_line)\n", "    pass\n", "stdout-print-removed"),
        encoding="utf-8",
    )
    rc, problems = check(script=m1)
    results.append(
        (
            "MUTANT: stdout print removed is caught",
            rc == 1 and any("NO provenance" in p for p in problems),
            f"rc={rc} {problems}",
        )
    )

    # M2: the script keeps stdout but drops the operator's stderr copy.
    m2 = tmp / "m2_pay_link.py"
    m2.write_text(
        _mutate(
            src,
            "    print(rate_line, file=sys.stderr)\n",
            "    pass\n",
            "stderr-print-removed",
        ),
        encoding="utf-8",
    )
    rc, problems = check(script=m2)
    results.append(
        (
            "MUTANT: losing the operator's stderr copy is caught",
            rc == 1 and any("stderr" in p for p in problems),
            f"rc={rc} {problems}",
        )
    )

    # M3: the DOCUMENT drifts. Nothing in test_pay_link.py can see this, which is the whole
    # reason this gate exists rather than another test case.
    spec = documented_example(doc)
    if spec is None:
        results.append(
            (
                "selftest could read the documented specimen",
                False,
                "no fenced `rate:` line in SKILL.md",
            )
        )
    else:
        m3doc = tmp / "m3_SKILL.md"
        m3doc.write_text(
            _mutate(
                doc,
                spec,
                spec.replace("BCB PTAX", "ECB reference rate"),
                "doc-source-renamed",
            ),
            encoding="utf-8",
        )
        rc, problems = check(doc=m3doc)
        results.append(
            (
                "MUTANT: a renamed source in the documented specimen is caught",
                rc == 1 and any("does not match" in p for p in problems),
                f"rc={rc} {problems}",
            )
        )

        # OVER-CORRECTION CONTROL. The published rate, the divergence percentage and the order
        # value all move legitimately. A gate that flagged those would be red on every correct
        # tree and would be turned off within a week.
        m4doc = tmp / "m4_SKILL.md"
        moved = re.sub(r"[0-9]+(?:[.,][0-9]+)*", lambda m: m.group(0)[:-1] + "7", spec)
        m4doc.write_text(
            _mutate(doc, spec, moved, "doc-numbers-moved"), encoding="utf-8"
        )
        rc, problems = check(doc=m4doc)
        results.append(
            (
                "CONTROL: moved numbers in the specimen still pass",
                rc == 0,
                f"rc={rc} {problems}",
            )
        )

    # CANNOT CHECK is a distinct verdict, not a pass and not a failure.
    rc, problems = check(script=tmp / "does_not_exist.py")
    results.append(
        (
            "a missing script is CANNOT CHECK (2), not a pass",
            rc == 2,
            f"rc={rc} {problems}",
        )
    )

    failed = [r for r in results if not r[1]]
    for desc, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  selftest: {desc}")
        if not ok:
            print(f"        {detail}")
    print()
    if failed:
        print(f"{len(failed)} of {len(results)} selftest case(s) FAILED")
        return 1
    print(
        f"all {len(results)} selftest cases pass; the gate reaches 0, 1 and 2 on known inputs"
    )
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    rc, problems = check()
    if rc == 0:
        print("rate provenance channel: SKILL.md and pay_link.py agree")
        print(
            "  the model reads stdout; the `rate:` line is emitted there and to stderr"
        )
        return 0
    head = "CANNOT CHECK" if rc == 2 else "MISMATCH"
    print(f"rate provenance channel: {head}")
    for p in problems:
        print(f"  - {p}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
