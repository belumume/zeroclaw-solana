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

THE ALWAYS-LOADED SCOPE IS THE SECOND HALF, and without it this gate had a structural blind spot
rather than a gap in its list. Every surface above comes from `git ls-files`, and all five of this
root's always-loaded files are GITIGNORED, so the injected copy -- the one every session reads on
every turn -- was exempt from this check by construction. Measured: this gate printed
`all 6 claim(s) agree` while `docs/COMPLIANCE-AUDIT.md` was telling every session that CI runs
`all 8 components in a matrix` against a matrix of nine. A gate cannot find what it never opens,
however good its pattern is.

That scope is DERIVED from `CLAUDE.local.md`'s own `@`-imports, transitively, rather than listed.
The point of deriving is that the gate's idea of what is always-loaded cannot drift from what a
session actually loads: change an import and the scope follows in the same commit. A hand-written
list would rot exactly the way the prose it checks rots.

DATED RECORDS ARE EXEMPT, and this scope forces a per-CLAIM discriminator where the tracked scope
needed only a per-DOCUMENT one. `HISTORICAL` above works because exactly one tracked document is
wholly about superseded belief. The always-loaded files are dated logs: a notes and a compliance
ledger, both of which preserve superseded text deliberately and label it. Excluding either whole
file would give back the blind spot; excluding neither would report a 2026-07-27 deploy record
("all 8 plugins registered", true then, false now, and rewriting it would destroy the record).

So an always-loaded claim whose OWN LINE carries a history marker is reported and not gated. Two
properties make that honest rather than a loophole. It is narrow -- measured, 23 of 1,422 lines
across the five files carry one -- and it is VISIBLE, printed as a NOTE with the marker that
earned it, so a claim silenced by a stray word is a claim someone can see was silenced. Its
ceiling: in a hard-wrapped document a marker on the neighbouring line does not count, and the
remedy is to write it in the same sentence, which is the same convention TOTALITY already imposes.

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

# The always-loaded tier's entry point. Everything else in that scope is read out of this file's
# own `@`-imports, so the scope is a fact about the tree rather than a claim in this script.
ALWAYS_LOADED_ENTRY = "CLAUDE.local.md"

# A history marker exempts an ALWAYS-LOADED claim on the same line, never a tracked one. The
# tracked scope's behaviour is deliberately unchanged by this widening: loosening it would be a
# second change, and one with no measurement behind it.
HISTORY_MARKER = re.compile(
    r"historical|superseded|no longer the state|kept as provenance|was true (?:then|at the time)"
    r"|dated survey|retracted|provenance, not as state",
    re.IGNORECASE,
)

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


def always_loaded(root: Path) -> tuple[list[Path], list[str], bool]:
    """(paths, problems, entry present) for the always-loaded tier.

    Walked transitively from the entry point, because an import can import. A path that escapes
    the root is a problem rather than a skip: a project entry point cannot reach outside its own
    root by any path form, so one that appears to is a claim about the tree that is not true.

    ABSENT IS NOT BROKEN. A clone, a CI runner and an agent worktree carry none of these files --
    they are gitignored, which is the whole reason this scope had to be added -- so the entry
    point missing means this checkout has no always-loaded tier to scan. That is reported as
    NOT CHECKED by the caller and does not gate. PRESENT-BUT-EMPTY is the opposite case and IS a
    problem: the file is there, the derivation returned nothing, and a scope that collapsed to
    one file while reporting agreement is the false green this gate is built against.
    """
    entry = root / ALWAYS_LOADED_ENTRY
    if not entry.is_file():
        return [], [], False

    found: list[Path] = [entry]
    problems: list[str] = []
    seen = {entry.resolve()}
    queue = [entry]
    while queue:
        cur = queue.pop(0)
        rel_cur = cur.relative_to(root).as_posix()
        try:
            text = cur.read_text(encoding="utf-8")
        except Exception as exc:
            problems.append(f"{rel_cur} is unreadable ({exc})")
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if not line.startswith("@"):
                continue
            raw = line[1:].strip()
            if not raw or any(c.isspace() for c in raw):
                continue
            target = root / raw
            try:
                resolved = target.resolve()
                resolved.relative_to(root.resolve())
            except (ValueError, OSError):
                problems.append(
                    f"{rel_cur}:{i} imports {raw!r}, which resolves outside the root; nothing "
                    f"there is actually loaded, so the scope this names is not the scope in use"
                )
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            if not target.is_file():
                problems.append(
                    f"{rel_cur}:{i} imports {raw!r}, which is not on disk. The import silently "
                    f"loads nothing, so this scope cannot be scanned as declared."
                )
                continue
            found.append(target)
            queue.append(target)

    if len(found) == 1 and not problems:
        problems.append(
            f"{ALWAYS_LOADED_ENTRY} is present and yielded ZERO @-imports, so the derivation has "
            f"stopped matching and the scope collapsed to the entry point alone"
        )
    return found, problems, True


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

    al_paths, al_problems, al_present = always_loaded(root)
    if al_problems:
        return (
            2,
            ["cannot check the always-loaded scope:"]
            + [f"  - {p}" for p in al_problems]
            + [
                "  This scope is derived from the entry point's own @-imports so it cannot drift "
                "from what a session loads. A break in the derivation means the scope no longer "
                "describes that, and agreement reported over it would cover less than it claims."
            ],
        )

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
    #
    # KEYED ON THE TRACKED SCOPE ALONE, deliberately. Those surfaces are DECLARED to carry counts,
    # so zero there means the pattern died. The always-loaded files are derived and may honestly
    # contain no total-set claim on any given day; gating on their zero would turn an ordinary
    # rewrite into a cannot-check, and the pattern's liveness is already proven here.
    if total == 0:
        return 2, [
            f"cannot check: scanned {len(paths)} surface(s) and found ZERO count claims, so the "
            "pattern has stopped matching. Reporting agreement over nothing would be a false green."
        ]

    al_total, al_exempt = 0, []
    for p in al_paths:
        rel = p.relative_to(root).as_posix()
        try:
            text = p.read_text(encoding="utf-8")
        except Exception as exc:
            return 2, [f"cannot check: always-loaded {rel} is unreadable ({exc})"]
        src = text.splitlines()
        for ln, matched, n in claims_in(text):
            al_total += 1
            marker = HISTORY_MARKER.search(re.sub(r"\s+", " ", src[ln - 1]))
            if marker is not None:
                al_exempt.append(
                    f"  {rel}:{ln}  {matched!r} says {n}; not gated, the line calls itself a "
                    f"record ({marker.group(0).lower()!r})"
                )
                continue
            if n != want:
                bad.append(f"  {rel}:{ln}  says {matched!r}, but git tracks {want}")

    lines.append(f"plugin directories tracked: {want}")
    lines.append(f"count claims found: {total} across {len(paths)} tracked surface(s)")
    if al_present:
        lines.append(
            f"always-loaded: {al_total} claim(s) across {len(al_paths)} file(s) derived from "
            f"{ALWAYS_LOADED_ENTRY}'s @-imports, {len(al_exempt)} exempt as dated record(s)"
        )
        lines.extend(al_exempt)
    else:
        lines.append(
            f"always-loaded: NOT CHECKED. No {ALWAYS_LOADED_ENTRY} in this checkout, so the "
            f"always-loaded tier is absent here (it is gitignored, so a clone, a runner and an "
            f"agent worktree all lack it). The verdict below covers the tracked surfaces only."
        )
    if bad:
        lines.append(f"{len(bad)} claim(s) disagree with the tree:")
        lines.extend(bad)
        lines.append(
            "  fix the prose. Do NOT add a plugin to make a sentence true, and do not silence "
            "this by deleting the number: a surface that states no count is not a surface that "
            "states the right one."
        )
        return 1, lines
    gated = total + al_total - len(al_exempt)
    lines.append(f"all {gated} gated claim(s) agree")
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

    # ---- the history marker, both directions ------------------------------------------------
    # Every fire string is a REAL line from this root's always-loaded files; the silent ones are
    # the live claims that must keep being gated. Without the second group the marker could be
    # matching everything, which would hand back the blind spot while looking like a narrowing.
    for text, label in (
        ("Everything below this paragraph is the HISTORICAL record", "'HISTORICAL'"),
        ("it is NO LONGER THE STATE.**", "'no longer the state'"),
        ("kept as provenance, not as state", "'kept as provenance'"),
        (
            "so it is a DATED SURVEY and was true then",
            "'dated survey' / 'was true then'",
        ),
        ("This cell is SUPERSEDED below the first paragraph", "'superseded'"),
    ):
        report(f"marker fires: {label}", HISTORY_MARKER.search(text) is not None)
    for text, label in (
        ("all 8 components in a matrix", "the live CI claim that must stay gated"),
        ("`plugins/` holds all nine components.", "an ordinary inventory line"),
        (
            "history is not drift, and the discriminator is the document",
            "'history' alone",
        ),
        ("RECORD: the count re-measured today", "'record' alone"),
    ):
        report(f"marker silent: {label}", HISTORY_MARKER.search(text) is None)

    # ---- the always-loaded scope --------------------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        # The fixture root is a SUBDIRECTORY of the temp dir, so the escaping-import case below
        # writes its target inside the tree that gets cleaned up rather than beside it.
        tmp = Path(td) / "root"
        tmp.mkdir()
        (tmp / "plugins" / "p0" / "src").mkdir(parents=True)
        (tmp / "plugins" / "p0" / "src" / "lib.rs").write_text("", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp), "init", "-q"], capture_output=True)
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], capture_output=True)
        for rel in SURFACES:
            p = tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("`plugins/` holds all one components.\n", encoding="utf-8")

        entry = tmp / ALWAYS_LOADED_ENTRY
        goal = tmp / ".claude" / "GOAL.md"
        notes = tmp / "NOTES.md"
        goal.parent.mkdir(parents=True, exist_ok=True)

        # ABSENT is not broken, and it is the shape every clone and runner is in.
        rc, out = check(tmp)
        _, _, present = always_loaded(tmp)
        report("no entry point: the scope is absent, not broken", present is False)
        report("and the tracked verdict still passes", rc == 0)
        report(
            "and the output says the tier was NOT CHECKED rather than passing quietly",
            any("NOT CHECKED" in ln for ln in out),
        )

        # PRESENT but yielding nothing is the opposite case: the derivation broke.
        entry.write_text("no imports here at all\n", encoding="utf-8")
        rc, out = check(tmp)
        report("entry point with zero @-imports is cannot-check", rc == 2)
        report(
            "and it says the scope collapsed", any("ZERO @-imports" in ln for ln in out)
        )

        # A named import that is not on disk loads nothing; scanning less than declared is not a
        # pass, for the same reason a missing declared surface is not.
        entry.write_text("@.claude/GOAL.md\n", encoding="utf-8")
        rc, out = check(tmp)
        report("an @-import that is not on disk is cannot-check", rc == 2)
        report("and it names the import it lost", any("GOAL.md" in ln for ln in out))

        # An import that escapes the root cannot be what a session loads.
        entry.write_text("@../outside.md\n", encoding="utf-8")
        (tmp.parent / "outside.md").write_text("all nine plugins\n", encoding="utf-8")
        _, probs, _ = always_loaded(tmp)
        report(
            "an @-import escaping the root is a problem, not a silent skip",
            any("outside the root" in p for p in probs),
        )

        # THE DERIVATION IS TRANSITIVE: an import can import.
        goal.write_text("@NOTES.md\n", encoding="utf-8")
        notes.write_text("nothing here\n", encoding="utf-8")
        entry.write_text("@.claude/GOAL.md\n", encoding="utf-8")
        found, probs, _ = always_loaded(tmp)
        report(
            "the walk is transitive: entry -> GOAL -> NOTES",
            not probs
            and {p.name for p in found} == {"CLAUDE.local.md", "GOAL.md", "NOTES.md"},
        )
        report("a scope with no claims in it is not a failure", check(tmp)[0] == 0)

        # THE CONTROL THIS WIDENING EXISTS FOR. A wrong count in a GITIGNORED always-loaded file,
        # with every tracked surface correct, must go RED. Before the widening this exact tree
        # printed agreement, because `git ls-files` never names the file that is wrong.
        notes.write_text("CI runs all 8 components in a matrix.\n", encoding="utf-8")
        rc, out = check(tmp)
        report("a wrong count in an always-loaded file FAILS", rc == 1)
        report(
            "and the failure names that file, its line and both numbers",
            any(
                "NOTES.md:1" in ln and "8 components" in ln and "tracks 1" in ln
                for ln in out
            ),
        )

        # RESTORE: the same tree with the claim corrected is green again, so the red above came
        # from the claim rather than from the file's mere presence.
        notes.write_text("CI runs all one components in a matrix.\n", encoding="utf-8")
        report("correcting that one claim restores the pass", check(tmp)[0] == 0)

        # OVER-CORRECTION, the direction that gives the blind spot back. A dated record is
        # exempt, and it must be PRINTED as exempt rather than dropped.
        notes.write_text(
            "HISTORICAL record of the 2026-07 deploy: all 8 components registered.\n",
            encoding="utf-8",
        )
        rc, out = check(tmp)
        report("a marked dated record does not gate", rc == 0)
        report(
            "and it is reported rather than silently skipped",
            any("exempt" in ln for ln in out) and any("NOTES.md:1" in ln for ln in out),
        )

        # AND THE MARKER IS NOT A BLANKET: the same wrong claim one line down, unmarked, fires.
        notes.write_text(
            "HISTORICAL record of the 2026-07 deploy.\nCI runs all 8 components today.\n",
            encoding="utf-8",
        )
        report(
            "a marker on a DIFFERENT line does not exempt the claim",
            check(tmp)[0] == 1,
        )

    for f in failures:
        print(f"  FAIL  {f}")
    print(f"selftest: {cases - len(failures)}/{cases}")
    return 0 if not failures else 3


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    # --root exists because the always-loaded tier is GITIGNORED, so it is present in the trunk
    # root and absent from every worktree and clone. Without it, the half of this gate that
    # matters most can only be exercised from one directory on one machine, and a verification
    # nobody else can repeat is an assertion. The mutation controls use it too.
    ap.add_argument(
        "--root",
        default=None,
        help="check this tree instead of the script's own repo root",
    )
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    rc, lines = check(Path(args.root).resolve() if args.root else ROOT)
    for ln in lines:
        print(ln)
    return rc


if __name__ == "__main__":
    sys.exit(main())
