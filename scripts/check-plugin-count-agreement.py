#!/usr/bin/env python3
"""Bind the plugin count a reader is TOLD to the number of plugins that exist.

WHY THIS EXISTS. Adding `plugins/x402-pay-build` took the set from eight to nine, and every
instrument that MEASURES the set picked it up unaided: `make_invariants.py` derives from
`git ls-files plugins`, `check-host-compat.sh` globs `plugins/*/`, `check-custody-tier.py` walks the
directory. Not one of them had to be told. The prose did, and nobody told it, so six judge-facing
sentences went on saying eight -- including the write-up's own inventory of what `plugins/` holds.

That asymmetry is the whole point. A derived count self-corrects; a written one is a claim frozen at
the moment someone typed it, and a claim frozen against a set that grows is a claim that becomes
false without anything going red. The counts here were CORRECT when written, which is the property
that makes them dangerous: nothing contradicts them.

WHAT IT ASSERTS. Every count claim on a judge-facing surface that names plugins or components must
equal the number of plugin directories git tracks. Nothing else. It does not read the prose around
the number, and it deliberately cannot tell a good sentence from a bad one.

HISTORY IS NOT DRIFT, and the discriminator is the DOCUMENT rather than the sentence. "We believed
the eight plugins were running" is a true statement about 2026-07 and must survive; a regex cannot
tell that from a live inventory, and this file's own corpus contains both. So the one document whose
entire subject is superseded belief is excluded BY NAME with its reason, rather than the check
guessing at tense. Source comments are out of scope for the same reason: `payment-watch/src/watch.rs`
records "two of the eight plugins had one" as a survey taken at a point in time, and rewriting a
measurement to match today's tree would destroy the record rather than update it.

Exit 0 they agree, 1 a claim disagrees, 2 could not check. A could-not-check is NOT a pass: a
pattern that stopped matching, or a surface list that resolved to nothing, would otherwise report
agreement over an empty scan, which is this repo's most-repeated instrument failure.

  --selftest   drives both directions against a temp tree, plus the over-correction controls
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The surfaces a stranger reads. DECLARED rather than globbed, because the alternative -- every
# tracked .md -- pulls in the transcripts, the incident write-ups and the archived decision docs,
# where a historical count is correct and a complaint would be noise. A declared list can go stale
# by omission, so `surfaces()` refuses to run on a list that has lost a file rather than silently
# checking fewer.
SURFACES = (
    "README.md",
    "QUICKSTART.md",
    "TESTING.md",
    "docs/WRITEUP.md",
    "docs/ONE-PAGER.md",
    "docs/ARGUMENT.md",
    "scripts/check-custody-tier.py",
)

# Excluded by name, with the reason, because its subject IS superseded belief.
HISTORICAL = {"docs/WHAT-WE-GOT-WRONG.md"}

WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
}

# A TOTAL-SET count claim. Two narrowings, and the second was forced by measurement rather than
# designed:
#
#   THE NOUN. The corpus is full of "all eight branches", "all eight wallets" and "eight things this
#   project believed", none of which is a claim about this set. Requiring plugins/components kills
#   all of them. An intervening "plugin"/"tool"/"wasm" is allowed so that "all eight plugin
#   components" matches, since that is TESTING.md's exact phrasing.
#
#   THE TOTALITY MARKER, which the first draft lacked. Run over the real tree that draft returned 15
#   findings and SIX were real: the other nine were SUBSET and SINGULAR references -- "Three plugins
#   are T0 read-only", "the two components", "one WASM tool plugin" -- every one of them correct
#   prose. 40% precision is not a gate, it is a thing people learn to skip. Totality is a semantic
#   property and regex does those badly, so it is read off an explicit marker instead of guessed at.
#
# THE COST, stated rather than discovered later: a total-set claim written WITHOUT a marker ("the
# nine components") is invisible here. That is a convention this gate imposes on six sentences, and
# it is the cheap half of the trade -- "all nine components" is also the clearer sentence, and a
# subset claim can never accidentally acquire the marker.
TOTALITY = r"(?:all|every|each\s+of\s+the|all\s+of\s+the)"
CLAIM = re.compile(
    r"\b" + TOTALITY + r"\s+"
    r"(?P<n>\d{1,3}|" + "|".join(WORDS) + r")\s+"
    r"(?:(?:plugin|tool|wasm|built)\s+)*"
    r"(?P<noun>plugins?|components?)\b",
    re.IGNORECASE,
)


def plugin_count(root: Path) -> int | None:
    """Top-level directories under plugins/, from git's index rather than the filesystem.

    From the INDEX so a stray untracked scratch directory cannot inflate the expected count and
    turn correct prose red -- the false-positive direction, which is the one that gets a gate
    routed around.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "plugins"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    dirs = {
        p.split("/")[1]
        for p in out.stdout.split("\n")
        if p.startswith("plugins/") and p.count("/") >= 2
    }
    return len(dirs) or None


def surfaces(root: Path) -> tuple[list[Path], list[str]]:
    """(readable surface paths, problems). A missing declared surface is a problem, never a skip."""
    found, problems = [], []
    for rel in SURFACES:
        p = root / rel
        if p.is_file():
            found.append(p)
        else:
            problems.append(
                f"declared surface {rel} is missing, so the scan covers less than it claims"
            )
    return found, problems


def claims_in(text: str) -> list[tuple[int, str, int]]:
    """(line number, matched text, asserted count) for every count claim.

    Whitespace is NORMALISED PER LINE only, deliberately. A repo-wide collapse would let a claim
    match across a hard wrap and report a line number pointing at the wrong place; a count and its
    noun sitting on two different lines is rare enough to accept as a known miss, and it is stated
    here rather than discovered later.
    """
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for m in CLAIM.finditer(re.sub(r"\s+", " ", line)):
            raw = m.group("n").lower()
            n = WORDS.get(raw)
            if n is None:
                try:
                    n = int(raw)
                except ValueError:
                    continue
            out.append((i, m.group(0).strip(), n))
    return out


def check(root: Path) -> tuple[int, list[str]]:
    """(exit code, lines to print)."""
    lines: list[str] = []
    want = plugin_count(root)
    if want is None:
        return 2, [
            "cannot check: could not derive the plugin count from git ls-files plugins"
        ]

    paths, problems = surfaces(root)
    if problems:
        return 2, ["cannot check:"] + [f"  - {p}" for p in problems]

    total, bad = 0, []
    for p in paths:
        rel = p.relative_to(root).as_posix()
        if rel in HISTORICAL:  # defence in depth; HISTORICAL is not in SURFACES today
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except Exception as exc:
            return 2, [f"cannot check: {rel} is unreadable ({exc})"]
        for ln, matched, n in claims_in(text):
            total += 1
            if n != want:
                bad.append(f"  {rel}:{ln}  says {matched!r}, but git tracks {want}")

    # A scan that matched NOTHING is a broken pattern wearing a clean verdict. The denominator is
    # printed beside the count for the same reason: `0 findings` and `0 of 0 claims` read
    # identically to a human and mean opposite things.
    if total == 0:
        return 2, [
            f"cannot check: scanned {len(paths)} surface(s) and found ZERO count claims, so the "
            "pattern has stopped matching. Reporting agreement over nothing would be a false green."
        ]

    lines.append(f"plugin directories tracked: {want}")
    lines.append(f"count claims found: {total} across {len(paths)} surface(s)")
    if bad:
        lines.append(f"{len(bad)} claim(s) disagree with the tree:")
        lines.extend(bad)
        lines.append(
            "  fix the prose. Do NOT add a plugin to make a sentence true, and do not silence "
            "this by deleting the number: a surface that states no count is not a surface that "
            "states the right one."
        )
        return 1, lines
    lines.append(f"all {total} claim(s) agree")
    return 0, lines


def selftest() -> int:
    cases, failures = 0, []

    def report(label: str, cond: bool) -> None:
        nonlocal cases
        cases += 1
        if not cond:
            failures.append(label)

    # ---- the pattern, both directions -------------------------------------------------------
    for text, want_n, label in (
        (
            "`plugins/` holds all eight components.",
            8,
            "spelled-out, 'all N components'",
        ),
        ("all eight plugin components in a matrix", 8, "'all N plugin components'"),
        ("compares all four wit files + all 8 components", 8, "digit form"),
        ("every nine plugins", 9, "the 'every' marker"),
        (
            "in three different formats across all eight components: a manifest",
            8,
            "inside a docstring sentence",
        ),
    ):
        got = [n for _, _, n in claims_in(text)]
        report(f"fires: {label}", want_n in got)

    # OVER-CORRECTION CONTROLS. Every string here is REAL PROSE from this repo, and the second
    # group is the measured false-positive set that forced the totality marker: the first draft
    # reddened all of them, which is 9 wrong findings against 6 right ones.
    for text, label in (
        # wrong noun
        (
            "this one through all eight branches from a loopback server",
            "'eight branches'",
        ),
        (
            "THIS TEST DELIBERATELY RENDERS ALL EIGHT: FAKE_WALLETS",
            "'all eight' with no noun",
        ),
        ("Eight things this project believed, and the measurement", "'eight things'"),
        ("all 8 source and artifact digests unchanged", "'8 source ... digests'"),
        ("Two of the eight branches had one.", "a count of branches, not plugins"),
        # SUBSET and SINGULAR claims: correct prose about part of the set, or about one member
        ("Three plugins are T0 read-only:", "a subset claim (README)"),
        ("the two components that read a delegation", "'the two components' (WRITEUP)"),
        ("One component imports the network", "a singular claim (README)"),
        ("the one component that signs nothing", "'the one component' (WRITEUP)"),
        ("only one WASM tool plugin had ever executed", "'one WASM tool plugin'"),
        ("reads the 3 plugin manifests", "'3 plugin manifests' (WRITEUP)"),
        ("audited one component and stopped", "'one component' (check-custody-tier)"),
    ):
        report(f"silent: {label}", claims_in(text) == [])

    # THE STATED CEILING, pinned so it cannot be forgotten or quietly widened. An ELIDED noun
    # ("Six of the eight carry a transcript") is a real claim about this set and this pattern does
    # not see it, because the only way to reach it is to match a bare count, which would also
    # redden every "eight things" and "all eight branches" above. The honest trade is a known miss
    # over a gate that cries wolf, and the remedy is to write the noun: QUICKSTART's copy of that
    # sentence now names the noun, and the total-set sentences carry "all".
    report(
        "CEILING: an elided noun is a known miss, not a silent bug",
        claims_in("Six of the eight carry a captured prompt-injection transcript")
        == [],
    )

    # 'four wit files' must NOT match while '8 components' on the same line DOES. Without this the
    # digit case above passes for the wrong reason -- a pattern matching every number on the line.
    got = sorted(n for _, _, n in claims_in("all four wit files + all 8 components"))
    report(
        "the same line yields the component count and not the wit-file count",
        got == [8],
    )

    # ---- the verdict, both directions -------------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for i in range(3):
            (tmp / "plugins" / f"p{i}" / "src").mkdir(parents=True)
            (tmp / "plugins" / f"p{i}" / "src" / "lib.rs").write_text(
                "", encoding="utf-8"
            )
        subprocess.run(["git", "-C", str(tmp), "init", "-q"], capture_output=True)
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], capture_output=True)

        report("the count derives from the index", plugin_count(tmp) == 3)

        made = []
        for rel in SURFACES:
            p = tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("nothing to count here\n", encoding="utf-8")
            made.append(p)

        # No claims anywhere is CANNOT-CHECK, not a pass.
        rc, out = check(tmp)
        report("a scan with zero claims is cannot-check, not clean", rc == 2)
        report("and it says why", any("ZERO count claims" in ln for ln in out))

        made[0].write_text("`plugins/` holds all three components.\n", encoding="utf-8")
        rc, out = check(tmp)
        report("an agreeing claim passes", rc == 0)

        made[0].write_text("`plugins/` holds all eight components.\n", encoding="utf-8")
        rc, out = check(tmp)
        report("a disagreeing claim FAILS", rc == 1)
        report(
            "the failure names the file, the line and both numbers",
            any("README.md:1" in ln and "eight components" in ln for ln in out),
        )

        # A missing declared surface must be cannot-check. A gate that quietly checks five of six
        # surfaces reports a clean sweep of a set it never covered.
        made[0].write_text("`plugins/` holds all three components.\n", encoding="utf-8")
        moved = made[-1].with_suffix(".moved")
        made[-1].rename(moved)
        rc, out = check(tmp)
        report("a missing declared surface is cannot-check", rc == 2)
        report(
            "and it names the surface it lost",
            any(SURFACES[-1] in ln for ln in out),
        )
        moved.rename(made[-1])

        # CONTROL on the derivation itself: add a plugin and the SAME prose must now fail. Without
        # this, "an agreeing claim passes" is equally true of a checker that agrees with everything.
        (tmp / "plugins" / "p3" / "src").mkdir(parents=True)
        (tmp / "plugins" / "p3" / "src" / "lib.rs").write_text("", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], capture_output=True)
        rc, _ = check(tmp)
        report("prose that was correct FAILS once a plugin is added", rc == 1)

    for f in failures:
        print(f"  FAIL  {f}")
    print(f"selftest: {cases - len(failures)}/{cases}")
    return 0 if not failures else 3


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    rc, lines = check(ROOT)
    for ln in lines:
        print(ln)
    return rc


if __name__ == "__main__":
    sys.exit(main())
