#!/usr/bin/env python3
"""Bind the output-ceiling figures the ledger PUBLISHES to what the suites PRINT.

WHY THIS EXISTS. On 2026-08-19 seven of the nine output-ceiling figures in the
context-flooding row of `docs/COMPLIANCE-AUDIT.md` were wrong at once. One row published
`< 512 B total` for a plugin whose suite prints 1,970 ASCII and 3,026 multibyte; another
said a plugin had "no measured ceiling here" when it had one. Nobody was careless.

THE MECHANISM IS THE FINDING, and it is structural rather than human. Every other gate in
this repo is INTRA-artifact: it checks one file against its own source, or one document
against a script in the same tree. These numbers are produced by Rust tests under
`plugins/*/src/`, and they are published in a markdown file, and NO gate named both. Two
artifacts that no single check reads can disagree indefinitely while every gate stays
green. That is not a gap in anyone's list; it is a missing EDGE in the gate topology.

`docs/COMPLIANCE-AUDIT.md` is gitignored but `@`-imported into every session, so a wrong
figure there is re-served as authoritative on every turn, and it is judge-facing.

WHAT IT ASSERTS, in one sentence: every byte figure the ledger attributes to a plugin as a
MEASUREMENT must be a number that plugin's own tests actually printed.

THE DIRECTION IS DELIBERATE and it is the half that matters. It does NOT require every
printed figure to appear in the ledger, because a suite legitimately prints more totals
than prose quotes -- `x402-pay-build` prints 1,279 from one test and 1,280 from another,
and the ledger quoting only 1,280 is a choice, not a falsehood. Requiring the reverse
would redden a correct ledger. Publishing a number no test produces is the actual defect,
and that is what this fails on.

BOTH SIDES ARE DERIVED. The crates come from globbing `plugins/*/Cargo.toml`, the figures
come from running the suites, and the claims come from parsing the ledger. Nothing here
carries its own copy of a number: a gate holding the expected values would be a THIRD
surface drifting on its own schedule, which is the defect it exists to catch wearing a
different hat. Ceilings are being actively changed as this is written, so a gate keyed to
today's values would have been stale on arrival.

`--test-threads=1` IS LOAD-BEARING, not tidiness. Measured on `depin-attest`: the default
parallel harness interleaves stdout from concurrent tests and TEARS the lines, yielding 3
intact `MEASURED` lines plus an orphaned ` bytes` fragment where 4 lines exist. A parser
over torn output silently under-counts, and under-counting here reads as agreement.

WHAT IT CANNOT DO, stated because a gate described as coverage invites the prose beside it
to be deleted. It cannot check a crate that prints no `MEASURED` line -- `allowance-spend-
build` states its bound inside an `assert!` message, which by construction prints only when
the assert FAILS, and `spl-transfer-build` prints none at all. Both are reported as NOT
COMPARED with that reason rather than folded into a pass. It cannot tell a prose figure's
MEANING, only its value, so a ledger number that is right by coincidence passes.

AND IT GATES ONE DOCUMENT, WHICH IS NOT THE ONLY SURFACE PUBLISHING THESE FIGURES. The
tracked plugin READMEs publish them too, and being tracked they are what a stranger reads
in a fresh clone -- so they matter MORE than the gitignored ledger, and they are reported
as NOT COVERED on every run rather than left to be inferred from a green. Measured while
this gate was written: the 2026-08-19 sweep corrected the ledger and did NOT reach them,
so four values COMPLIANCE-DETAIL itself records as SUPERSEDED were still live in
`plugins/*/README.md` (lending-health 5,810; token-risk-check 1,355; payment-watch 556;
spl-transfer-build 750). That is the same one-surface-corrected defect this gate exists to
catch, surviving in the surface with the widest audience. See uncovered() and
EXCLUDED_DOCS for what is deliberately left out and why.

  python3 scripts/verify-output-ceiling-agreement.py            # run the suites, compare
  python3 scripts/verify-output-ceiling-agreement.py --selftest # controls, no cargo needed

Exit: 0 agree, 1 a published figure is not one the suites print, 2 could not check (never
a pass -- a comparison against nothing is not agreement), 3 a selftest control failed.

WHY IT IS NOT NAMED `check-*`, which is a deliberate choice and not an oversight.
`check-all.py` discovers `scripts/check-*.py` from git's index and runs every one, so that
prefix would enrol this automatically. Two measured reasons it should not be:

  COST, measured on this machine over three runs: 380s COLD (empty CARGO_TARGET_DIR),
  88s warm after other agents had moved several crates, 31s fully warm with nothing to
  rebuild. check-all's slowest current gate is 13.1s and most are under a second, so even
  the best case here is the new slowest gate by 2.4x and the cold case is 29x.
  DEPENDENCY. Every gate check-all runs today is pure Python and git. This one needs a
  Rust toolchain, so enrolling it would make check-all report CANNOT_CHECK on any machine
  without cargo -- turning a suite that answers cleanly everywhere into one that does not.

Neither is a reason to skip the check; they are reasons it belongs on a slower cadence.
It is dominated by COMPILATION, not by the tests, so CI is where it is nearly free: a job
that already has a Rust toolchain and rust-cache pays almost nothing extra. It does NOT
belong in `publish-gates`, which is deliberately toolchain-free and capped at five
minutes, and the `plugins` matrix cannot host it either -- each leg builds ONE plugin, and
this is a cross-plugin comparison needing them all at once. Setting CARGO_TARGET_DIR to a
single shared path compiles the shared dependency tree once rather than nine times, which
is most of the difference between the two numbers above.

To enrol it in check-all.py anyway, rename it to `check-output-ceiling-agreement.py` and
raise MIN_GATES there by one. Nothing else is required; discovery does the rest.
"""

import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs" / "COMPLIANCE-AUDIT.md"
CANNOT_CHECK = 2

# Documents deliberately NOT scanned, each with the reason it would be wrong to scan.
EXCLUDED_DOCS = {
    "docs/COMPLIANCE-DETAIL.md": (
        "its provenance table preserves the SUPERSEDED figures on purpose, in a column "
        "headed 'row said'. Gating it would redden a true historical record whose only "
        "remedy is deleting the record, which is how a gate gets routed around."
    ),
}

# A byte figure in prose. All three guards are load-bearing and each was earned by a
# defect the selftest caught: `(?<![\w-])` stops the `19` of a date `2026-08-19` being read
# as a figure; `(?!-\w)` stops `200-entry` / `300-position` / `4-byte` fixture sizes being
# read as one; and `(?!\d)` stops the regex BACKTRACKING to a shorter number when the third
# guard fires -- without it `300-position` yields `30`, a figure no suite ever prints, and
# the gate reddens a correct ledger on a number that appears nowhere in it.
FIGURE = re.compile(r"(?<![\w-])(\d(?:[\d,]*\d)?)(?!\d)(?!-\w)")
# A line worth reading at all: one that names a crate AND denominates something in bytes.
# Discovering the scope this way rather than naming the row means a reworded row is still
# found, while the rest of the document -- which mentions crates beside slot numbers, line
# numbers and exchange rates -- is not dragged in. Measured: without this, `oracle-publish`
# absorbed a 478,350,917 slot and `payment-watch` absorbed nine source line numbers.
BYTE_DENOMINATED = re.compile(r"\d[\d,]*\s*(?:B\b|bytes\b)")
# `--locked` matches ci.yml and makes this gate READ-ONLY with respect to the tree: without
# it `cargo test` may rewrite Cargo.lock, and a checker that edits the repo it is checking
# cannot be run safely while someone else is working in that repo. `--test-threads=1` is the
# anti-tearing measure and is asserted by the selftest, because losing it degrades the gate
# SILENTLY -- torn lines simply yield fewer figures, which reads as agreement.
CARGO_CMD = ["cargo", "test", "--locked", "--", "--nocapture", "--test-threads=1"]
# A figure introduced by one of these words is a declared BOUND, not a measurement.
BOUND_CUE = re.compile(
    r"(?:against|ceiling|budget|bound)\b[^0-9]{0,24}$", re.IGNORECASE
)
# What the suites print. Requiring the word `bytes` after every figure was the obvious
# rule and it was WRONG, caught by the first real run: oracle-publish prints
# "1930 bytes total, 530 of it fixed prose", where two byte figures share one unit, so the
# strict rule missed 530 and reddened a ledger that was telling the truth. The rule is
# therefore inverted -- every figure in a MEASURED line counts EXCEPT one denominated in
# something that is plainly not bytes ("47 chars", "16 detail lines", "3 top entries").
#
# That makes the code side deliberately PERMISSIVE, and the honest cost is stated here
# rather than discovered later: the printed set is a superset, so a published figure that
# happens to equal some unrelated number the suite printed will pass. The direction of the
# assertion is what makes that acceptable -- a permissive code side can only ever cause a
# MISS, never a false failure, and a gate that cries wolf is one people learn to skip.
# UP TO TWO DESCRIPTIVE WORDS MAY SIT BETWEEN THE FIGURE AND ITS UNIT, and omitting that was a
# real bug rather than a hypothetical: this pattern's own cited example, "16 detail lines", was
# NOT excluded by it, because "detail" sits in between. lending-health prints exactly that shape
# ("... bytes over {} detail lines"), so `16` was read as a byte figure. Measured: the line parsed
# to {16, 5602} and now parses to {5602}.
#
# It matters most on the LEDGER side. There a non-byte quantity leaking in as a byte "claim" is a
# FALSE FAILURE, which is the direction this whole gate exists to avoid, and it would have blamed
# a phantom byte mismatch that was really an unrelated line-count drift. Both sides agree today,
# so nothing was firing; the day the two counts drift independently it would have.
#
# Bounded at two words and lowercase-only on purpose, so it cannot run past a sentence into an
# unrelated unit. Verified against every MEASURED line the suites currently print: the genuine
# byte figures ("47 bytes", "530 of it fixed prose") all survive.
NON_BYTE_UNIT_AFTER = re.compile(
    r"\s*(?:[a-z][a-z-]*\s+){0,2}"
    r"(?:chars?|characters?|lines?|entries|entry|top|codepoints?|%|[KMG]i?B|kB)\b"
)


def crates(root: pathlib.Path) -> list[str]:
    """Every plugin crate, globbed rather than listed, so a new one joins unaided."""
    d = root / "plugins"
    if not d.is_dir():
        return []
    return sorted(p.parent.name for p in d.glob("*/Cargo.toml"))


def parse_measured(text: str) -> set[int]:
    """The byte values one crate's suite printed on a passing run."""
    out = set()
    for line in text.splitlines():
        i = line.find("MEASURED")
        if i < 0:
            continue
        span = line[i:]
        for m in FIGURE.finditer(span):
            if not NON_BYTE_UNIT_AFTER.match(span[m.end() :]):
                out.add(int(m.group(1).replace(",", "")))
    return out


def run_suite(crate: str, root: pathlib.Path) -> tuple[set[int], str | None]:
    """Run one crate's tests and return the figures it printed, or a reason it could not."""
    try:
        r = subprocess.run(
            CARGO_CMD,
            cwd=str(root / "plugins" / crate),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return set(), f"cargo did not run ({exc})"
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or ["no output"]
        return set(), f"the suite failed (rc={r.returncode}): {tail[0][:90]}"
    return parse_measured((r.stdout or "") + (r.stderr or "")), None


def uncovered(root: pathlib.Path, names: list[str]) -> list[tuple[str, int]]:
    """Surfaces that publish byte figures and that this gate does NOT gate.

    A plugin README is TRACKED and judge-facing, so it matters more to a stranger than the
    gitignored ledger does, and it is deliberately not gated here. The reason is precision,
    not oversight: a README mixes report ceilings with FIELD caps in one sentence
    ("capped (symbol 24, market 44, netValue 32) ... the report is 5,810 bytes"), and no
    rule this gate could apply separates them without either missing real drift or
    reddening correct prose. Reporting the count keeps the hole VISIBLE on every run
    instead of letting a green verdict imply a coverage that was never claimed.
    """
    out = []
    for crate in names:
        readme = root / "plugins" / crate / "README.md"
        if not readme.is_file():
            continue
        n = len(BYTE_DENOMINATED.findall(readme.read_text(encoding="utf-8")))
        if n:
            out.append((f"plugins/{crate}/README.md", n))
    return out


def ceiling_lines(text: str, names: list[str]) -> list[str]:
    """The lines that publish ceiling figures, discovered by shape rather than named."""
    return [
        ln
        for ln in text.splitlines()
        if BYTE_DENOMINATED.search(ln) and any(n in ln for n in names)
    ]


def claims_in(text: str, names: list[str]) -> dict[str, dict[str, list]]:
    """Byte figures the ledger attributes to each crate, split into claims and bounds.

    A crate's span runs from its name to the next crate name, so a figure belongs to
    whichever crate was named most recently before it. Segmenting this way rather than
    matching a sentence shape means the parser does not care how the prose is worded.
    """
    marks = sorted(
        (m.start(), n) for n in names for m in re.finditer(re.escape(n), text)
    )
    found = {n: {"claims": [], "bounds": []} for n in names}
    for i, (start, name) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        span = text[start + len(name) : end]
        for m in FIGURE.finditer(span):
            if NON_BYTE_UNIT_AFTER.match(span[m.end() :]):
                continue
            value = int(m.group(1).replace(",", ""))
            key = "bounds" if BOUND_CUE.search(span[: m.start()]) else "claims"
            found[name][key].append(value)
    return found


def compare(measured: dict[str, set[int]], claimed: dict[str, dict[str, list]]):
    """The whole verdict: (failures, compared, skipped). Pure, so the controls are cheap."""
    failures, compared, skipped = [], [], []
    for crate in sorted(claimed):
        claims = sorted(set(claimed[crate]["claims"]))
        bounds = sorted(set(claimed[crate]["bounds"]))
        printed = measured.get(crate)
        if printed is None:
            skipped.append((crate, "no suite result for this crate"))
            continue
        if not printed:
            skipped.append((crate, "the crate prints no MEASURED line"))
            continue
        if not claims:
            skipped.append((crate, "the ledger publishes no measured figure for it"))
            continue
        for value in claims:
            if value not in printed:
                failures.append(
                    f"{crate}: the ledger publishes {value:,} B, which its suite never "
                    f"printed. It printed {', '.join(f'{p:,}' for p in sorted(printed))}."
                )
        # Ledger-internal, needing no operand from the code: a declared bound cannot sit
        # below a figure published in the same breath as a measurement under it.
        for bound in bounds:
            if claims and bound < max(claims):
                failures.append(
                    f"{crate}: the ledger declares a ceiling of {bound:,} B under a "
                    f"published measurement of {max(claims):,} B."
                )
        compared.append((crate, claims, bounds))
    return failures, compared, skipped


def report(failures, compared, skipped, total, uncov=()) -> int:
    for crate, claims, bounds in compared:
        figs = ", ".join(f"{c:,}" for c in claims)
        tail = f" (bound {', '.join(f'{b:,}' for b in bounds)})" if bounds else ""
        mark = "FAIL" if any(c.startswith(crate + ":") for c in failures) else "ok  "
        print(f"  {mark} {crate:<24} published {figs} B{tail}")
    for crate, why in skipped:
        print(f"  n/a  {crate:<24} NOT COMPARED: {why}")

    print(
        f"\ncompared {len(compared)} of {total} plugin crate(s); "
        f"{len(skipped)} not compared, each with its reason above."
    )
    for doc, why in sorted(EXCLUDED_DOCS.items()):
        print(f"  excluded {doc}: {why.splitlines()[0]}")
    if uncov:
        total_figs = sum(n for _, n in uncov)
        print(
            f"\n  NOT COVERED: {len(uncov)} tracked plugin README(s) publish "
            f"{total_figs} byte figure(s) between them and are NOT gated here. They are\n"
            "  judge-facing and reachable in a fresh clone, so this is the surface that\n"
            "  matters most to a stranger; see uncovered() for why a per-clause\n"
            "  discriminator is needed before they can be gated without false failures."
        )
        for path, n in uncov:
            print(f"    - {path} ({n} byte figure(s))")

    if failures:
        print(
            "\nFAIL  the ledger publishes a ceiling figure its own suite does not "
            "produce:\n" + "\n".join(f"    {f}" for f in failures) + "\n"
            "  This file is @-imported, so a wrong figure is re-served as authoritative\n"
            "  every turn, and it is judge-facing. Re-derive the prose from the suites;\n"
            "  the suites are the source of truth, never this document.",
            file=sys.stderr,
        )
        return 1
    print("\nPASS  every published ceiling figure is one the suites actually print")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    if not LEDGER.is_file():
        print(f"cannot check: {LEDGER.relative_to(ROOT)} is missing")
        return CANNOT_CHECK
    names = crates(ROOT)
    if not names:
        print("cannot check: no plugins/*/Cargo.toml found, so nothing was measured")
        return CANNOT_CHECK
    if shutil.which("cargo") is None:
        print(
            "cannot check: cargo is not on PATH, so the suites that PRODUCE these "
            "figures cannot be run. A comparison against nothing is not a pass."
        )
        return CANNOT_CHECK

    measured, broken = {}, []
    for crate in names:
        figures, why = run_suite(crate, ROOT)
        if why:
            broken.append(f"{crate}: {why}")
        else:
            measured[crate] = figures
    if broken:
        print("cannot check: a suite did not produce figures to compare against:")
        for b in broken:
            print(f"  - {b}")
        return CANNOT_CHECK
    if not any(measured.values()):
        # Every crate ran and not one printed a figure. That is a broken parse or a
        # renamed marker, never a clean repo, and reporting it as agreement is the
        # exact false-green this gate exists to prevent.
        print(
            f"cannot check: {len(names)} suite(s) ran and printed 0 MEASURED figures "
            "between them. Nothing was compared, so this is not a pass."
        )
        return CANNOT_CHECK

    rows = ceiling_lines(LEDGER.read_text(encoding="utf-8"), names)
    if not rows:
        print(
            f"cannot check: no line in {LEDGER.relative_to(ROOT)} both names a plugin "
            "and denominates a figure in bytes, so there is no published claim to "
            "compare the suites against. Nothing was compared, so this is not a pass."
        )
        return CANNOT_CHECK
    claimed = claims_in("\n".join(rows), names)
    print(
        f"ran {len(names)} plugin suite(s) against {len(rows)} ceiling-publishing "
        f"line(s) in {LEDGER.relative_to(ROOT)}\n"
    )
    return report(
        *compare(measured, claimed),
        total=len(names),
        uncov=uncovered(ROOT, names),
    )


def selftest() -> int:
    """Controls. A gate that has never produced the opposite verdict certifies nothing."""
    failed = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}{'' if ok else '  <- ' + detail}")
        if not ok:
            failed.append(label)

    names = crates(ROOT)
    text = LEDGER.read_text(encoding="utf-8") if LEDGER.is_file() else ""
    if not names or not text:
        print("cannot selftest: needs plugins/ and the ledger present")
        return CANNOT_CHECK
    rows = ceiling_lines(text, names)
    check("the ceiling row is discoverable by shape", bool(rows), "found no such line")
    text = "\n".join(rows)
    claimed = claims_in(text, names)

    # The real thing, as the gate sees it today: every published figure must be printable.
    truth = {c: set(claimed[c]["claims"]) | {9_999_991} for c in names}
    f0, comp0, _ = compare(truth, claimed)
    check("over-correction: an unmodified ledger passes", not f0, "; ".join(f0))
    check("over-correction: it compared something", len(comp0) > 0, "compared nothing")

    # PLANTED MISMATCH. The defect this gate was built for, in a copy of the ledger.
    # Pick the richest claimant rather than the first, so the control exercises the
    # thousands-separator path and lands on a crate a real run actually compares.
    victim = max(names, key=lambda c: (len(claimed[c]["claims"]), c))
    real = max(claimed[victim]["claims"])
    planted = re.sub(
        rf"(?<![\w-]){real // 1000},{real % 1000:03d}(?![\d-])"
        if real >= 1000
        else rf"(?<![\w-]){real}(?![\d-])",
        "512",
        text,
        count=1,
    )
    f1, _, _ = compare(truth, claims_in(planted, names))
    check("planted mismatch fails", bool(f1), "a stale figure passed")
    check(
        "planted mismatch names the crate and both values",
        any(victim in m and "512" in m and f"{real:,}" in m for m in f1),
        f"unhelpful message: {f1[:1]}",
    )
    if f1:
        print(f"       planted-mismatch output: {f1[0]}")

    # A crate that prints nothing is NOT COMPARED, never a silent pass.
    blind = {c: (set() if c == victim else truth[c]) for c in names}
    f2, comp2, skip2 = compare(blind, claims_in(planted, names))
    check(
        "a crate printing no MEASURED line is skipped with a reason",
        any(c == victim for c, _ in skip2)
        and not any(m.startswith(victim) for m in f2),
        "it was folded into the pass count",
    )
    check(
        "and the skip does not silence its neighbours",
        len(comp2) == len(comp0) - 1,
        f"compared {len(comp2)}, expected {len(comp0) - 1}",
    )

    # The parser must be able to come up empty, and empty must not read as agreement.
    # {48, 300, 301}, not {300, 301}: `device_id 48 bytes` carries the unit and is a real
    # printed figure. This case asserted {300, 301} until the selftest refuted it, which is
    # the control doing its job on the control's own author. Do not "fix" it back.
    check(
        "parser finds every unit-carrying figure in real output",
        parse_measured(SAMPLE) == {48, 300, 301},
        f"got {sorted(parse_measured(SAMPLE))}",
    )
    check(
        "parser returns nothing when no MEASURED line exists",
        parse_measured(NOISE) == set(),
    )
    # The anti-tearing flag is asserted rather than its symptom, because dropping it
    # degrades the gate silently: torn lines just yield fewer figures, which reads as
    # agreement. The orphaned ` bytes` fragment tearing actually produced must stay inert.
    check(
        "the run is serialised, so concurrent tests cannot tear a MEASURED line",
        "--test-threads=1" in CARGO_CMD,
        f"CARGO_CMD is {CARGO_CMD}",
    )
    check(
        "and the tear artifact itself yields nothing",
        parse_measured("bytes") == set(),
    )
    # A DESCRIPTIVE WORD BETWEEN A FIGURE AND ITS UNIT. This is the lending-health line verbatim,
    # and it parsed to {16, 5602} until the exclusion allowed intervening words: `16` is a count of
    # detail lines, not bytes. It is pinned as the real string rather than a minimised one, because
    # the shape is what the crate actually prints and a reduced fixture would not have caught it.
    check(
        "a figure whose unit sits two words away is not read as bytes",
        parse_measured(
            "MEASURED worst-case lending-health report, 4-byte codepoints: "
            "5602 bytes over 16 detail lines"
        )
        == {5602},
        f"got {sorted(parse_measured('MEASURED x: 5602 bytes over 16 detail lines'))}",
    )
    # OVER-CORRECTION CONTROL for the same widening: a genuine byte figure that merely happens to
    # be followed by other words must still be collected, or the exclusion has eaten real data.
    check(
        "widening the exclusion did not swallow real byte figures",
        parse_measured(
            "MEASURED oracle-publish report: 1930 bytes total, 530 of it fixed prose around the tx"
        )
        == {530, 1930},
    )
    check(
        "non-byte units are not read as byte figures",
        claims_in("payment-watch 4 KB label and 511 B", ["payment-watch"])[
            "payment-watch"
        ]
        == {"claims": [511], "bounds": []},
    )
    check(
        "fixture sizes and dates are not read as figures",
        claims_in(
            "lending-health 5,474 against 6,500 (300-position) 2026-08-19", names
        )["lending-health"]
        == {"claims": [5474], "bounds": [6500]},
        "a fixture size or a date leaked in as a byte figure",
    )
    # The backtracking defect specifically, pinned so the third guard cannot be dropped:
    # with only `(?!-\w)`, `300-position` yields 30 and `200-entry` yields 20.
    check(
        "a hyphenated fixture size yields NO shorter figure by backtracking",
        claims_in("depin-attest (300-position 200-entry 4-byte)", names)["depin-attest"]
        == {"claims": [], "bounds": []},
        f"leaked {claims_in('depin-attest (300-position 200-entry)', names)['depin-attest']}",
    )

    # END TO END, with the cargo step stubbed. A zero-match parse must reach the caller as
    # CANNOT_CHECK; if it ever returned 0 the gate would certify agreement having compared
    # nothing, which is the precise false-green it was built to prevent.
    def drive(stub) -> int:
        saved = (sys.argv, shutil.which, globals()["run_suite"])
        try:
            sys.argv = ["gate"]
            shutil.which = lambda _n: "cargo"
            globals()["run_suite"] = stub
            return main()
        finally:
            sys.argv, shutil.which = saved[0], saved[1]
            globals()["run_suite"] = saved[2]

    print("\n  -- end-to-end, cargo stubbed --")
    rc_silent = drive(lambda crate, root: (set(), None))
    check(
        "suites that print NO figure exit CANNOT_CHECK, never 0",
        rc_silent == CANNOT_CHECK,
        f"rc={rc_silent}",
    )
    rc_broken = drive(lambda crate, root: (set(), "the suite failed (rc=101)"))
    check(
        "a suite that fails to build exits CANNOT_CHECK, never 0",
        rc_broken == CANNOT_CHECK,
        f"rc={rc_broken}",
    )
    rc_good = drive(lambda crate, root: (set(claimed[crate]["claims"]) or {1}, None))
    check(
        "and a healthy stub still reaches a verdict",
        rc_good == 0,
        f"rc={rc_good}",
    )

    print(f"\n{len(failed)} selftest failure(s)" if failed else "\nselftest: all pass")
    return 3 if failed else 0


SAMPLE = """
test attest::tests::worst_case_report_is_bounded ... MEASURED worst-case depin-attest \
report: 300 bytes
MEASURED depin-attest report (4-byte): 301 bytes, device_id 48 bytes / 12 chars
"""
NOISE = "test result: ok. 18 passed; 0 failed\nCompiling depin-attest v0.1.0\n"


if __name__ == "__main__":
    sys.exit(main())
