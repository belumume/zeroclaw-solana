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

IT COULD NOT RUN FOR THE AUDIENCE IT EXISTS TO CONVINCE, and that is what the clone mode
below fixes. The ledger is gitignored, so it is absent from every clone by construction. A
stranger who reproduces this repo therefore got `cannot check: docs/COMPLIANCE-AUDIT.md is
missing`, exit 2 -- the correct refusal, and a check that never runs. `--selftest` was worse:
it needed the ledger too, so a stranger could not even exercise the controls. Measured in a
ledgerless checkout before this: the run exited 2 having compared nothing, and the selftest
exited 2 having run ZERO of its controls. The gate was also wired into NOTHING, and it could
not be, because it would have exited 2 on every CI run for the same reason.

SO THE CLAIM SOURCE FALLS BACK, and the fallback is DERIVED rather than authored:

  ledger present  ->  claims come from the ledger, exactly as before, AND the tracked
                      extract is asserted to still mirror it. Full fidelity, plus a
                      freshness assertion that did not exist before.
  ledger absent   ->  claims come from `docs/proof-bundle/output-ceilings.json`, which IS
                      tracked and therefore present in a clone. The suites still run and
                      are still compared, so a stranger gets a real check.
  neither         ->  CANNOT_CHECK, unchanged. Nothing is ever compared against nothing.

THE OBVIOUS OBJECTION IS THE ONE ABOVE -- a stored file of numbers is exactly the "THIRD
surface drifting on its own schedule" this docstring warns against. The answer is that it is
never hand-maintained and never trusted blind: `--write-extract` derives it from the ledger,
and every run that CAN read the ledger FAILS while the two disagree. The surface able to
detect the drift is the one that gates it. The assertion is keyed to the parsed CLAIMS and
deliberately NOT to the ledger's bytes -- a hash of a 15 KB living document would redden on
every unrelated edit, which is a gate keyed to an implementation detail punishing the correct
change, and it would be routed around within a week.

WHAT THE CLONE RUN CANNOT CATCH, which the working-tree run can. Stated here because a
second mode described as coverage invites the first one to be skipped:

  - LEDGER EDITS ARE INVISIBLE TO IT. It compares the suites against a SNAPSHOT. Publish a
    bogus figure in the ledger and fail to regenerate, and a clone still passes; only a
    checkout with the ledger reddens. The clone therefore catches exactly one direction --
    the CODE moving away from what is published -- which is the direction a stranger
    actually creates by changing a crate and rebuilding.
  - IT CANNOT CHECK THE PROSE. That the ceiling row is still discoverable by shape, and
    still parses to these claims, needs the ledger's text and is unanswerable without it.
  - THE SNAPSHOT IS ONLY AS FRESH AS THE LAST LEDGER-BEARING RUN. Nothing runs this
    automatically yet (see the wiring note below), so that cadence is manual today.
  - EVERY LIMIT OF THE WORKING-TREE RUN STILL APPLIES: a crate printing no `MEASURED` line
    is NOT COMPARED, and a figure that is right by coincidence still passes.

  python3 scripts/verify-output-ceiling-agreement.py            # run the suites, compare
  python3 scripts/verify-output-ceiling-agreement.py --selftest # controls, no cargo needed
  python3 scripts/verify-output-ceiling-agreement.py --check-extract  # freshness only, ~0s
  python3 scripts/verify-output-ceiling-agreement.py --write-extract  # regenerate it

`--check-extract` is the freshness half alone: pure text, no cargo, effectively instant. It
is split out because an artifact whose only freshness check costs a Rust compile is an
artifact whose freshness check does not get run.

Exit: 0 agree, 1 a published figure is not one the suites print OR the extract no longer
mirrors the ledger, 2 could not check (never a pass -- a comparison against nothing is not
agreement, and `0 of 0` is not agreement either), 3 a selftest control failed.

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

BOTH OBJECTIONS ABOVE ARE ABOUT THE FULL RUN, AND NEITHER APPLIES TO `--check-extract`.
That path is pure Python and git, costs no compile, and answers the one question a cheap
cadence most needs answered: is the snapshot every clone checks against still true. So the
wiring this file now deserves is two-tier, and it is left as a follow-up rather than done
here only because `.github/workflows/ci.yml` is being edited concurrently:

  CHEAP TIER -- a `scripts/check-output-ceiling-extract.py` of three lines that imports this
  module and returns `check_extract()`, plus MIN_GATES += 1 in check-all.py. It is
  toolchain-free, so it stays green on any machine, and it is CANNOT_CHECK rather than a
  failure in a clone, which is honest: only a ledger-bearing checkout can answer it.
  FULL TIER -- the whole run in a CI job that already has a Rust toolchain and rust-cache,
  with CARGO_TARGET_DIR pointed at one shared path. In a CI clone it now takes the extract
  branch and produces a real verdict, where before this change it could only have exited 2.
"""

import contextlib
import io
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs" / "COMPLIANCE-AUDIT.md"
# The TRACKED extract of the ledger's ceiling claims. It exists so this gate has an operand
# in a fresh clone, where the gitignored ledger above is absent by construction. It is
# DERIVED, never hand-maintained: `--write-extract` regenerates it from the ledger, and any
# run that can see the ledger FAILS when the two disagree. See extract_drift().
EXTRACT = ROOT / "docs" / "proof-bundle" / "output-ceilings.json"
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


def rel(p: pathlib.Path) -> str:
    """A path for humans, which must never be the thing that crashes a message.

    `Path.relative_to` RAISES for anything outside ROOT, and the controls point LEDGER and
    EXTRACT at a temp directory on purpose, so the bare call turned every pinned-environment
    control into a ValueError traceback. Found by those controls on their first run: the
    gate's logic was right and its reporting could not survive being tested.
    """
    try:
        return p.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return p.as_posix()


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


def canon(claimed: dict[str, dict[str, list]]) -> dict[str, dict[str, list]]:
    """Claims in the only form the verdict can see: deduplicated and ordered.

    compare() already reduces both lists with `sorted(set(...))`, so canonicalising here is
    lossless with respect to the verdict while making the stored extract byte-stable. A
    reordered ledger sentence must not produce a diff in a tracked artifact, or the artifact
    churns for reasons that have nothing to do with the numbers.
    """
    return {
        name: {k: sorted(set(v)) for k, v in sorted(buckets.items())}
        for name, buckets in sorted(claimed.items())
    }


def extract_payload(claimed: dict[str, dict[str, list]]) -> dict:
    """The tracked artifact's content. Self-describing, because a stranger meets it first."""
    return {
        "_": (
            "DERIVED, do not hand-edit. The ceiling figures docs/COMPLIANCE-AUDIT.md "
            "publishes per plugin crate. That ledger is gitignored, so it is absent from "
            "every clone; this file is what scripts/verify-output-ceiling-agreement.py "
            "compares the plugin suites against when the ledger cannot be read. The LEDGER "
            "is authoritative -- regenerate with `--write-extract`, and any run that can "
            "see the ledger fails while the two disagree."
        ),
        "source": rel(LEDGER),
        "crates": claimed,
    }


def load_extract() -> tuple[dict[str, dict[str, list]] | None, str | None]:
    """(claims, reason it could not be read). Never guesses a shape it did not find."""
    if not EXTRACT.is_file():
        return None, (
            f"{rel(EXTRACT)} is missing, and so is the gitignored "
            "ledger, so there is no published claim to compare the suites against. "
            "Regenerate it from a checkout that has the ledger: --write-extract"
        )
    try:
        blob = json.loads(EXTRACT.read_text(encoding="utf-8"))
        crates_in = blob["crates"]
        out = {
            str(name): {
                "claims": [int(v) for v in buckets.get("claims", [])],
                "bounds": [int(v) for v in buckets.get("bounds", [])],
            }
            for name, buckets in crates_in.items()
        }
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return None, (
            f"{rel(EXTRACT)} could not be read as a claim "
            f"extract ({type(exc).__name__}: {exc}). A comparison against nothing is not "
            "agreement, so this is not a pass."
        )
    if not out:
        return None, (
            f"{rel(EXTRACT)} names no crate, so nothing would be "
            "compared. That is a broken or truncated extract, never a clean repo."
        )
    return canon(out), None


def extract_drift(ledger_claims: dict[str, dict[str, list]]) -> list[str]:
    """How the tracked extract differs from the ledger it claims to mirror.

    Only a run that can READ the ledger can answer this, which is exactly why the assertion
    lives here rather than in the clone path: the surface that can detect the drift is the
    one that gates it. Keyed on the parsed CLAIMS and never on the ledger's bytes -- a hash
    of a 15 KB living document would redden on every unrelated edit, which is a gate keyed
    to an implementation detail punishing the correct change, and it would be routed around
    within a week.
    """
    stored, why = load_extract()
    if why:
        return [why]
    problems = []
    for crate in sorted(set(stored) | set(ledger_claims)):
        want, got = ledger_claims.get(crate), stored.get(crate)
        if want is None:
            problems.append(
                f"{crate}: the extract carries it, the ledger no longer names it"
            )
        elif got is None:
            problems.append(
                f"{crate}: the ledger publishes figures for it, the extract has none"
            )
        elif want != got:
            problems.append(
                f"{crate}: the ledger publishes claims {want['claims']} bounds "
                f"{want['bounds']}; the extract carries claims {got['claims']} bounds "
                f"{got['bounds']}"
            )
    return problems


def write_extract() -> int:
    """Regenerate the tracked extract from the ledger. Explicit, never a run's side effect.

    The default run is deliberately READ-ONLY with respect to the tree -- that is why
    CARGO_CMD carries `--locked` -- because other agents work in this repo concurrently and
    a checker that edits what it is checking cannot be run safely beside them. Auto-writing
    here would quietly reverse that, so regeneration is a flag you have to mean.
    """
    if not LEDGER.is_file():
        print(
            f"cannot write: {rel(LEDGER)} is missing. The extract "
            "is DERIVED from the ledger, so it can only be regenerated in a checkout that "
            "has one. It must never be authored by hand.",
            file=sys.stderr,
        )
        return CANNOT_CHECK
    names = crates(ROOT)
    rows = ceiling_lines(LEDGER.read_text(encoding="utf-8"), names)
    if not rows:
        print(
            "cannot write: no line in the ledger both names a plugin and denominates a "
            "figure in bytes. Writing an empty extract would hand every clone a "
            "comparison against nothing.",
            file=sys.stderr,
        )
        return CANNOT_CHECK
    claimed = canon(claims_in("\n".join(rows), names))
    EXTRACT.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" so the artifact does not acquire the platform's line ending: this is a
    # tracked file regenerated on both Windows and CI, and a whole-file ending flip would
    # bury the one number that changed inside a total rewrite.
    with EXTRACT.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(extract_payload(claimed), fh, indent=2, sort_keys=True)
        fh.write("\n")
    n = sum(len(b["claims"]) for b in claimed.values())
    print(
        f"wrote {rel(EXTRACT)}: {n} published figure(s) across "
        f"{len(claimed)} crate(s), from {len(rows)} ceiling-publishing line(s)."
    )
    return 0


def check_extract() -> int:
    """Assert the tracked extract still mirrors the ledger. Pure text: no cargo, ~instant.

    Split out so the freshness half can be run by anything, on any cadence, without paying
    the Rust compile the full run needs. That matters because an artifact whose only
    freshness check is expensive is an artifact whose freshness check does not get run.
    """
    if not LEDGER.is_file():
        print(
            f"cannot check: {rel(LEDGER)} is missing, so there is "
            "nothing to compare the extract against. Only a checkout with the ledger can "
            "answer this; a clone structurally cannot."
        )
        return CANNOT_CHECK
    names = crates(ROOT)
    rows = ceiling_lines(LEDGER.read_text(encoding="utf-8"), names)
    if not rows:
        print("cannot check: the ledger publishes no ceiling line to compare against.")
        return CANNOT_CHECK
    drift = extract_drift(canon(claims_in("\n".join(rows), names)))
    if drift:
        print(
            f"FAIL  {rel(EXTRACT)} no longer mirrors the ledger:\n"
            + "\n".join(f"    {d}" for d in drift)
            + "\n  A clone compares the suites against this file, so while it is stale "
            "every\n  stranger is checking a snapshot instead of what we publish. "
            "Regenerate:\n    python3 scripts/verify-output-ceiling-agreement.py "
            "--write-extract",
            file=sys.stderr,
        )
        return 1
    print(
        f"PASS  the tracked extract mirrors {rel(LEDGER)} across "
        f"{len(names)} crate(s) / {len(rows)} ceiling-publishing line(s)"
    )
    return 0


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


def report(failures, compared, skipped, total, uncov=(), drift=(), absent=()) -> int:
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
    if absent:
        # A crate in plugins/ that the claim source has never heard of. In extract mode this
        # is the shape a STALE extract takes when a plugin is added after it was written, and
        # printing it is what stops a shrinking comparison reading as a steady green.
        print(
            f"  {len(absent)} crate(s) exist in plugins/ but are not named by the claim "
            f"source: {', '.join(sorted(absent))}"
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

    if drift:
        print(
            f"\nFAIL  {rel(EXTRACT)} no longer mirrors the "
            "ledger:\n" + "\n".join(f"    {d}" for d in drift) + "\n"
            "  That file is what a CLONE compares the suites against, because the ledger\n"
            "  is gitignored and absent there. While it is stale every stranger is\n"
            "  checking a snapshot instead of what we publish. Regenerate:\n"
            "    python3 scripts/verify-output-ceiling-agreement.py --write-extract",
            file=sys.stderr,
        )
    if failures:
        print(
            "\nFAIL  the ledger publishes a ceiling figure its own suite does not "
            "produce:\n" + "\n".join(f"    {f}" for f in failures) + "\n"
            "  This file is @-imported, so a wrong figure is re-served as authoritative\n"
            "  every turn, and it is judge-facing. Re-derive the prose from the suites;\n"
            "  the suites are the source of truth, never this document.",
            file=sys.stderr,
        )
    if drift or failures:
        return 1
    if not compared:
        # EVERY crate was skipped. Reachable today: reword the ceiling row so its figures
        # parse as bounds rather than measurements and the gate compares nothing while
        # printing PASS. Measured on this file before the guard existed -- compared 0 of 9,
        # exit 0. A comparison against nothing is not agreement in either direction.
        print(
            f"cannot check: {total} crate(s) were discovered and NONE was compared, so "
            "nothing was verified. `0 of 0` is not agreement; see each reason above."
        )
        return CANNOT_CHECK
    print(
        f"\nPASS  every published ceiling figure is one the suites actually print "
        f"({len(compared)} of {total} crate(s) compared)"
    )
    return 0


def resolve_claims(names: list[str]):
    """(claims, where they came from, extract drift, reason none could be read).

    The ledger when this checkout has one, the tracked extract when it does not. The
    fallback is the whole point: the ledger is gitignored, so in the fresh clone a stranger
    reproduces from, the authoritative source is absent by construction and refusing there
    means the gate never runs for the audience it exists to convince.
    """
    if LEDGER.is_file():
        rows = ceiling_lines(LEDGER.read_text(encoding="utf-8"), names)
        if not rows:
            return (
                None,
                "",
                [],
                f"no line in {rel(LEDGER)} both names a plugin "
                "and denominates a figure in bytes, so there is no published claim to "
                "compare the suites against. Nothing was compared, so this is not a pass.",
            )
        claimed = canon(claims_in("\n".join(rows), names))
        origin = (
            f"{rel(LEDGER)} ({len(rows)} ceiling-publishing line(s)) -- authoritative"
        )
        # Only THIS branch can see both artifacts, so this is the only place the extract's
        # freshness is answerable at all.
        return claimed, origin, extract_drift(claimed), None

    stored, why = load_extract()
    if why:
        return None, "", [], why
    origin = (
        f"{rel(EXTRACT)} ({len(stored)} crate(s)) -- the "
        "authoritative ledger is gitignored and absent from this checkout"
    )
    return stored, origin, [], None


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    if "--write-extract" in sys.argv:
        return write_extract()
    if "--check-extract" in sys.argv:
        return check_extract()

    names = crates(ROOT)
    if not names:
        print("cannot check: no plugins/*/Cargo.toml found, so nothing was measured")
        return CANNOT_CHECK
    claimed, origin, drift, why = resolve_claims(names)
    if why:
        print(f"cannot check: {why}")
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

    print(f"ran {len(names)} plugin suite(s) against claims from {origin}\n")
    return report(
        *compare(measured, claimed),
        total=len(names),
        uncov=uncovered(ROOT, names),
        drift=drift,
        absent=[c for c in names if c not in claimed],
    )


def selftest() -> int:
    """Controls. A gate that has never produced the opposite verdict certifies nothing."""
    failed, ran = [], []

    def check(label: str, ok: bool, detail: str = "") -> None:
        # Counting every control gives the summary a DENOMINATOR. `0 failures` out of a
        # collapsed control set reads exactly like `0 failures` out of a full one, and the
        # count is the only thing that separates them.
        ran.append(label)
        print(f"  {'ok  ' if ok else 'FAIL'} {label}{'' if ok else '  <- ' + detail}")
        if not ok:
            failed.append(label)

    names = crates(ROOT)
    if not names:
        print("cannot selftest: needs plugins/*/Cargo.toml present")
        return CANNOT_CHECK
    # THE CONTROLS MUST RUN WHERE THE NEW CODE PATH RUNS, which is a clone -- and a clone
    # has no ledger, so sourcing the prose only from the ledger made `--selftest` exit
    # CANNOT_CHECK for exactly the audience the clone path was added to serve. Measured
    # before this fallback existed: `--selftest` in a ledgerless checkout printed "cannot
    # selftest" and exited 2. LEDGER_SHAPE is a parser fixture like SAMPLE and NOISE, not a
    # copy of any published number: its figures are deliberately outside every value the
    # suites print, so a control passing against it can never be passing by coincidence.
    prose_from = "the real ledger"
    text = LEDGER.read_text(encoding="utf-8") if LEDGER.is_file() else ""
    if not text:
        prose_from = (
            "LEDGER_SHAPE (no ledger in this checkout: clone, runner or worktree)"
        )
        text = LEDGER_SHAPE
    print(f"  ..  ledger prose sourced from {prose_from}")
    rows = ceiling_lines(text, names)
    check("the ceiling row is discoverable by shape", bool(rows), "found no such line")
    text = "\n".join(rows)
    claimed = canon(claims_in(text, names))

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
    # ASSERT THE SUBSTITUTION APPLIED before trusting what follows. A mutation control whose
    # mutant is byte-identical to the original tests the unmodified code while looking green
    # from every angle; `512` is also a different LENGTH from every real claim, so nothing
    # downstream can match on size alone.
    check(
        "the planted mutation actually changed the text",
        planted != text,
        f"re.sub matched nothing for {real:,}; the control below would test the original",
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
    # EVERY control below pins BOTH artifacts under a temp dir rather than using whichever
    # of them this checkout happens to carry. That is what makes the verdicts identical in
    # the trunk and in a clone -- the two environments the gate now has to work in -- rather
    # than silently exercising a different code path in each.
    def drive(stub, ledger=None, extract=None) -> int:
        saved = (
            sys.argv,
            shutil.which,
            globals()["run_suite"],
            globals()["LEDGER"],
            globals()["EXTRACT"],
        )
        try:
            sys.argv = ["gate"]
            shutil.which = lambda _n: "cargo"
            globals()["run_suite"] = stub
            if ledger is not None:
                globals()["LEDGER"] = ledger
            if extract is not None:
                globals()["EXTRACT"] = extract
            return main()
        finally:
            sys.argv, shutil.which = saved[0], saved[1]
            globals()["run_suite"] = saved[2]
            globals()["LEDGER"], globals()["EXTRACT"] = saved[3], saved[4]

    def with_paths(fn, ledger, extract) -> int:
        saved = (globals()["LEDGER"], globals()["EXTRACT"])
        try:
            globals()["LEDGER"], globals()["EXTRACT"] = ledger, extract
            return fn()
        finally:
            globals()["LEDGER"], globals()["EXTRACT"] = saved

    def dump(path: pathlib.Path, cl: dict) -> None:
        with path.open("w", encoding="utf-8", newline="\n") as fh:
            json.dump(extract_payload(cl), fh, indent=2, sort_keys=True)
            fh.write("\n")

    def copy_of(cl: dict) -> dict:
        return {c: {k: list(v) for k, v in b.items()} for c, b in cl.items()}

    def honest(crate, root):
        """A suite that prints exactly what the pinned claims say it prints.

        Returns run_suite's own (figures, reason-it-could-not-run) shape. A stub that does
        not match the signature it replaces is a bug in the harness that reads as a bug in
        the code under test.
        """
        return set(claimed[crate]["claims"]) or {1}, None

    # 7,654,321 is a DIFFERENT DIGIT LENGTH from every figure the ledger publishes, and the
    # controls assert that rather than assuming it, so no downstream comparison can match on
    # size alone. It is also far outside anything a suite prints, so a mutant can never pass
    # by coincidence.
    PLANT = 7_654_321

    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        pinned = tmp / "ledger.md"
        pinned.write_text(text, encoding="utf-8")
        mirror = tmp / "mirror.json"
        dump(mirror, claimed)
        no_ledger = tmp / "no-such-ledger.md"  # precisely what a fresh clone looks like
        no_extract = tmp / "no-such-extract.json"

        print("\n  -- end-to-end, cargo stubbed, WORKING TREE (ledger present) --")
        rc = drive(lambda c, r: (set(), None), ledger=pinned, extract=mirror)
        check(
            "suites that print NO figure exit CANNOT_CHECK, never 0",
            rc == CANNOT_CHECK,
            f"rc={rc}",
        )
        rc = drive(
            lambda c, r: (set(), "the suite failed (rc=101)"),
            ledger=pinned,
            extract=mirror,
        )
        check(
            "a suite that fails to build exits CANNOT_CHECK, never 0",
            rc == CANNOT_CHECK,
            f"rc={rc}",
        )
        rc = drive(honest, ledger=pinned, extract=mirror)
        check("and a healthy stub still reaches a verdict", rc == 0, f"rc={rc}")

        # THE FRESHNESS ASSERTION, which is what stops the extract becoming the third
        # drifting surface this gate's own docstring warns against. Only a run that can read
        # the ledger can make it, so the surface able to detect the drift is the one that
        # gates it. Without it the extract could rot indefinitely while the trunk stayed
        # green and every clone quietly checked a snapshot.
        stale = tmp / "stale.json"
        drifted = copy_of(claimed)
        v_drift = max(names, key=lambda c: (len(drifted[c]["claims"]), c))
        drifted[v_drift]["claims"] = sorted(set(drifted[v_drift]["claims"]) | {PLANT})
        check(
            "the drift mutation actually changed the claims",
            drifted != claimed,
            "the stale fixture is identical to the fresh one; the control below is inert",
        )
        dump(stale, drifted)
        rc = drive(honest, ledger=pinned, extract=stale)
        check(
            "working tree: a STALE extract FAILS, it is not merely noted",
            rc == 1,
            f"rc={rc}",
        )
        rc = drive(honest, ledger=pinned, extract=no_extract)
        check(
            "working tree: a MISSING extract FAILS (a clone would have nothing to use)",
            rc == 1,
            f"rc={rc}",
        )
        rc = with_paths(check_extract, pinned, mirror)
        check("--check-extract passes on a faithful extract", rc == 0, f"rc={rc}")
        rc = with_paths(check_extract, pinned, stale)
        check("--check-extract fails on a stale one", rc == 1, f"rc={rc}")
        rc = with_paths(check_extract, no_ledger, mirror)
        check(
            "--check-extract is CANNOT_CHECK without a ledger, never a pass",
            rc == CANNOT_CHECK,
            f"rc={rc}",
        )
        rc = with_paths(write_extract, no_ledger, tmp / "would-be.json")
        check(
            "--write-extract refuses to author an extract with no ledger to derive from",
            rc == CANNOT_CHECK and not (tmp / "would-be.json").exists(),
            f"rc={rc}",
        )

        print(
            "\n  -- end-to-end, cargo stubbed, CLONE (no ledger, as it is gitignored) --"
        )
        rc = drive(honest, ledger=no_ledger, extract=mirror)
        check(
            "clone: an honest extract reaches a verdict with no ledger at all",
            rc == 0,
            f"rc={rc}",
        )

        # THE CONTROL THE CLONE PATH HAS TO EARN. A published figure the suites never print
        # must FAIL here exactly as it does in the trunk. A new path that can only ever pass
        # is decoration, and a clean run over it would certify nothing.
        planted_x = tmp / "planted.json"
        pl = copy_of(claimed)
        v_clone = max(
            (c for c in names if pl[c]["claims"]),
            key=lambda c: (len(pl[c]["claims"]), c),
            default="",
        )
        check(
            "clone: the fixture publishes a figure to plant over",
            bool(v_clone),
            "no crate carries a claim, so the control below cannot be built",
        )
        if v_clone:
            was = max(pl[v_clone]["claims"])
            pl[v_clone]["claims"] = sorted(
                (set(pl[v_clone]["claims"]) - {was}) | {PLANT}
            )
            check(
                "clone: the planted mutation applied, and differs in length from the original",
                pl != claimed and len(str(PLANT)) != len(str(was)),
                f"planted {PLANT} over {was}; mutated={pl != claimed}",
            )
            dump(planted_x, pl)
            rc = drive(honest, ledger=no_ledger, extract=planted_x)
            check(
                "clone: a planted disagreement FAILS against the extract",
                rc == 1,
                f"rc={rc}; a stale published figure passed in a clone",
            )

        # THE DENOMINATOR HAS TO NAME WHAT IT LOST. A plugin added after the extract was
        # last regenerated is invisible to it, and the comparison silently covers one crate
        # fewer while still printing PASS -- a shrinking check that reads as a steady green.
        # Asserted on the OUTPUT rather than the exit code, because the exit code is 0 in
        # both the healthy and the degraded case; the message is the only thing that differs.
        short = tmp / "short.json"
        dropped = max(names)
        dump(short, {c: b for c, b in claimed.items() if c != dropped})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = drive(honest, ledger=no_ledger, extract=short)
        said = buf.getvalue()
        check(
            "clone: a crate the extract has never heard of is NAMED, not silently dropped",
            rc == 0 and dropped in said and "not named by the claim source" in said,
            f"rc={rc}; the summary did not name {dropped}",
        )

        rc = drive(honest, ledger=no_ledger, extract=no_extract)
        check(
            "clone: with NEITHER artifact it exits CANNOT_CHECK, never a pass",
            rc == CANNOT_CHECK,
            f"rc={rc}",
        )
        bad = tmp / "bad.json"
        bad.write_text("{ this is not json", encoding="utf-8")
        rc = drive(honest, ledger=no_ledger, extract=bad)
        check(
            "clone: a malformed extract exits CANNOT_CHECK; it neither crashes nor passes",
            rc == CANNOT_CHECK,
            f"rc={rc}",
        )
        # `0 of 0` IS NOT AGREEMENT. report() is shared by both paths, so proving the guard
        # once proves it for both. Before it existed this exact input printed PASS having
        # compared 0 of 9 crates -- measured on this file, not hypothesised.
        empty = tmp / "empty.json"
        dump(empty, {c: {"claims": [], "bounds": [9_000_001]} for c in names})
        rc = drive(honest, ledger=no_ledger, extract=empty)
        check(
            "an extract publishing no measurement exits CANNOT_CHECK, never PASS",
            rc == CANNOT_CHECK,
            f"rc={rc}; `compared 0 of N` was reported as agreement",
        )

    verdict = f"{len(failed)} failure(s)" if failed else "all pass"
    print(
        f"\nselftest: {verdict} across {len(ran)} control(s), prose from {prose_from}"
    )
    return 3 if failed else 0


SAMPLE = """
test attest::tests::worst_case_report_is_bounded ... MEASURED worst-case depin-attest \
report: 300 bytes
MEASURED depin-attest report (4-byte): 301 bytes, device_id 48 bytes / 12 chars
"""
NOISE = "test result: ok. 18 passed; 0 failed\nCompiling depin-attest v0.1.0\n"
# A ceiling row with the real PROSE SHAPE and deliberately unreal FIGURES, used by the
# controls when this checkout has no ledger -- a clone, a CI runner, a fresh worktree. It is
# a parser fixture like SAMPLE and NOISE above, not a copy of anything published: every
# value here sits far outside the range the suites print (their largest is in the thousands),
# so a control passing against it cannot be passing because it collided with a real figure.
# It carries the shapes the parser guards exist for -- a thousands separator, a hyphenated
# fixture size, a date, a bound cue and a non-byte unit -- so the guards are exercised
# everywhere rather than only in a checkout that happens to hold the ledger.
LEDGER_SHAPE = (
    "| Context flooding | MEASURED worst-case ceilings on all NINE plugins. "
    "**ASCII / 4-byte-codepoint worst case against ceiling:** "
    "token-risk-check 7,101 / 7,102 bytes against 9,000 (200-entry flood); "
    "lending-health 7,103 / 7,104 bytes against 9,001 (300-position flood) 2026-08-19; "
    "depin-attest 7,105 bytes over 16 detail lines. All hard-bounded. |"
)


if __name__ == "__main__":
    sys.exit(main())
