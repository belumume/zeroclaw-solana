#!/usr/bin/env python3
"""Controls for demo/chain_history.py -- proves the walk reaches past one page, and that a
capped walk SAYS it was capped.

    python demo/test_chain_history.py

This file exists because the line chain_history.py prints is filmed, and three of its five
figures are decided by how far the walk gets. Measured against devnet on 2026-08-19, one page
versus the full walk renders as:

    1000 tx | 0 failed | median gap 20.5 min | largest gap 45.0 min | since 2026-08-05
    1801 tx | 0 failed | median gap 20.5 min | largest gap 61.5 min | since 2026-07-25

The count, the largest gap and the "since" date all move, and the durability claim rests on that
date. Neither line looks wrong on its own, which is the whole problem: a short walk does not
announce itself, it just prints a smaller true-looking number.

getSignaturesForAddress caps a page at 1000 by protocol (limit=1001 is refused with -32602), so
the account cannot be read in one call and the `before` walk is load-bearing rather than
defensive. MAX_PAGES is ours, so a walk that hits it must append CAPPED.

HERMETIC ON PURPOSE. _rpc is replaced with a fake serving synthetic pages, so these controls do
not touch the network: a control that needs devnet to be up cannot run on a shoot morning, and a
rate limit would read as a defect. The fake also ASSERTS the cursor it is handed, so the paging
arithmetic is checked rather than assumed.

TWO LAYERS, because a green case proves nothing about whether it could go red.

  1. BEHAVIOUR CASES. Each drives main() end to end and reads the printed line. Cases 2 and 5 are
     over-correction controls: an exactly-one-page feed and an exactly-two-page feed must NOT be
     reported as capped, or the suffix would be noise that gets learned around.

  2. MUTATION CONTROLS. Three edits are applied to the source in memory and the matching case is
     REQUIRED to flip red. Each asserts its anchor is present before substituting, that the
     result still COMPILES, and that the mutant differs in LENGTH from the original -- CPython
     keys its bytecode cache on source size plus mtime, so a same-length mutant written in the
     same clock tick can silently execute the original and certify nothing.
"""

from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.dont_write_bytecode = True  # belt-and-braces against the cache described above

TARGET = Path(__file__).resolve().parent / "chain_history.py"
SOURCE = TARGET.read_text(encoding="utf-8")

CHECKS = 0
FAILS = 0


def check(name, ok, detail=""):
    global CHECKS, FAILS
    CHECKS += 1
    if not ok:
        FAILS += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  -- ' + detail) if detail else ''}")
    return ok


# ---------------------------------------------------------------- fixtures


def _page(n, start, t_newest, step=1200):
    """One RPC page, newest-first, the order devnet actually returns."""
    return [
        {
            "signature": f"sig{start + i:06d}",
            "blockTime": t_newest - (start + i) * step,
            "err": None,
            "slot": 500_000_000 - (start + i),
        }
        for i in range(n)
    ]


def _pages(sizes, t_newest=1_760_000_000):
    out, start = [], 0
    for n in sizes:
        out.append(_page(n, start, t_newest))
        start += n
    return out


def _fake_rpc(pages, served):
    """Serve `pages` in order, asserting the caller advances the cursor correctly.

    This is what makes `before = batch[-1]["signature"]` a checked claim rather than an assumed
    one: hand back the wrong cursor and the walk raises here instead of quietly re-reading or
    skipping a page.
    """
    state = {"i": 0, "last": None}

    def rpc(method, params):
        assert method == "getSignaturesForAddress", method
        _addr, opts = params
        before = opts.get("before")
        if state["i"] == 0:
            assert before is None, f"first page must carry no cursor, got {before!r}"
        else:
            assert before == state["last"], (
                f"page {state['i'] + 1} cursor {before!r} is not the previous page's "
                f"last signature {state['last']!r}"
            )
        page = pages[state["i"]] if state["i"] < len(pages) else []
        state["i"] += 1
        if page:
            state["last"] = page[-1]["signature"]
        served.append(len(page))
        return {"result": page}

    return rpc


def run(source, sizes, tag):
    """Load `source` as a fresh module, drive main() over synthetic pages, return (line, rc)."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / f"ch_{tag}.py"
        path.write_text(source, encoding="utf-8", newline="\n")
        spec = importlib.util.spec_from_file_location(f"ch_{tag}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    served = []
    mod._rpc = _fake_rpc(_pages(sizes), served)
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = mod.main()
    return buf.getvalue().strip(), rc, served


# ---------------------------------------------------------------- layer 1


print("LAYER 1 -- behaviour")

# Case 1 (the shape devnet is actually in): two pages, second short. Must reach 1801, not 1000.
line, rc, served = run(SOURCE, [1000, 801], "c1")
check(
    "1  two-page feed walks past page one",
    line.startswith("1801 tx "),
    f"rc={rc} served={served} line={line!r}",
)
check("1b two-page feed is NOT reported capped", "CAPPED" not in line, line)

# Case 2 (over-correction control): one short page. Must not claim a cap it never hit.
line, rc, served = run(SOURCE, [500], "c2")
check("2  single short page reports its own count", line.startswith("500 tx "), line)
check("2b single short page is NOT reported capped", "CAPPED" not in line, line)

# Case 3 (must-fire): a feed that never runs out inside MAX_PAGES. The count is a floor, and the
# line has to say so.
line, rc, served = run(SOURCE, [1000] * 25, "c3")
check("3  exhausted-page feed announces the cap", "CAPPED" in line, line)
check(
    "3b capped walk still reports what it did read",
    line.startswith("20000 tx "),
    f"served {len(served)} pages: {sum(served)} of >=25000 signatures",
)

# Case 4: the account ends exactly on a page boundary, so the short-page break never fires and
# the empty-page break does. Exhausted, therefore not capped.
line, rc, served = run(SOURCE, [1000, 0], "c4")
check(
    "4  exact-multiple feed terminates on the empty page",
    line.startswith("1000 tx "),
    line,
)
check("4b exact-multiple feed is NOT reported capped", "CAPPED" not in line, line)

# Case 5: nothing on chain at all is UNREACHABLE, never a fabricated zero-tx line.
line, rc, served = run(SOURCE, [0], "c5")
check(
    "5  empty account returns rc 2 and says so",
    rc == 2 and "UNREACHABLE" in line,
    f"rc={rc} {line!r}",
)


# ---------------------------------------------------------------- layer 2

print("LAYER 2 -- mutation controls")

MUTANTS = [
    (
        "M1 cap suffix removed",
        '    capped = (\n        ""\n        if exhausted\n        else f" | CAPPED at '
        '{MAX_PAGES} pages, tx older than this are NOT counted"\n    )',
        '    capped = ""',
        [1000] * 25,
        lambda line: "CAPPED" in line,
        "case 3 (capped walk announces itself)",
    ),
    (
        "M2 pagination disabled after page one",
        "        if len(batch) < PAGE:",
        "        if True:",
        [1000, 801],
        lambda line: line.startswith("1801 tx "),
        "case 1 (walk reaches past page one)",
    ),
    (
        "M3 cursor taken from the wrong end of the page",
        '        before = batch[-1]["signature"]',
        '        before = batch[0]["signature"]',
        [1000, 801],
        lambda line: line.startswith("1801 tx "),
        "case 1 via the fake's cursor assertion",
    ),
]

for i, (name, anchor, repl, sizes, still_true, guards) in enumerate(MUTANTS):
    # A control whose anchor has drifted silently tests the unmodified file. Fail loudly instead.
    if not check(f"{name}: anchor present in source", anchor in SOURCE):
        continue
    mutated = SOURCE.replace(anchor, repl, 1)
    if not check(
        f"{name}: mutant differs in LENGTH from original",
        len(mutated) != len(SOURCE),
        f"{len(SOURCE)} -> {len(mutated)} bytes",
    ):
        continue
    try:
        compile(mutated, "<mutant>", "exec")
    except SyntaxError as e:
        check(
            f"{name}: mutant compiles",
            False,
            f"{e} (a mutant that cannot run tests nothing)",
        )
        continue
    check(f"{name}: mutant compiles", True)

    try:
        line, _rc, _served = run(mutated, sizes, f"m{i}")
        held = still_true(line)
        detail = (
            f"guarded assertion still true on the mutant: {line!r}"
            if held
            else f"broke {guards}"
        )
    except AssertionError as e:
        held, detail = False, f"broke {guards}: {e}"
    check(f"{name}: REVERTING THE FIX turns the suite red", not held, detail)


print(f"\n{CHECKS - FAILS} of {CHECKS} checks passed")
sys.exit(1 if FAILS else 0)
