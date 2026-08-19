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

THE OPERATIONAL SCOPE IS THE THIRD, and it closes the same structural hole the always-loaded
scope closed, in the other direction. That scope reached the gitignored files a SESSION loads;
this one reaches the gitignored files a HUMAN reads. `notes/` holds the live-demo runbook, read
aloud off a screen, and `git ls-files` cannot name it, so no derivation built on git could ever
have included it -- the omission was structural, not an oversight. Measured 2026-08-19: a sweep
corrected the certifier score across eight surfaces and left that runbook quoting a stale one,
which is the second occurrence of this shape in this repo (PR #66 was the first).

It is DISCOVERED by glob rather than declared, for the reason the always-loaded scope is derived
rather than listed: there is no `git ls-files` here to keep a declared list honest, so an omission
would be invisible in exactly the way the original defect was.

ABSENT IS NOT BROKEN, exactly as for the always-loaded tier. Every clone, CI runner and agent
worktree lacks `notes/`, so an empty glob reports NOT CHECKED with its denominator and does not
gate. Returning 2 there would paint every non-operator checkout permanently red, and an always-red
gate is one people learn to skip.

IT RIDES THE SAME HISTORY-MARKER EXEMPTION as the always-loaded files, and for the same reason: a
runbook is a dated operational log that preserves superseded and branch-dependent values on
purpose (its own text already records what `origin/main` prints as against this branch). Gating it
strictly would eventually redden a TRUE sentence whose only remedy is deleting a true record,
which is how a gate gets routed around. Stated honestly: no `notes/` claim is exempt today,
because `notes/` carries no count claim at all right now -- the exemption is reached by the
always-loaded files, which is where its control lives. The TRACKED scope's strictness is
unchanged.

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

# The gitignored OPERATIONAL scope: files a human reads, that `git ls-files` structurally cannot
# name. Discovered from the filesystem, absent in every clone. See the docstring.
OPERATIONAL_DIR = "notes"
OPERATIONAL_SUFFIXES = (".md", ".html")
# Gitignored operational files that do NOT live under OPERATIONAL_DIR. Named explicitly
# rather than globbed, because a wildcard over docs/ would pull in the tracked judge-facing
# documents that the always-loaded and tracked scopes already cover, and double-counting a
# claim is its own defect. Each entry earns its place by being gitignored AND carrying a
# count claim: COMPLIANCE-DETAIL.md is the spoke split out of the @-imported hub on
# 2026-08-19, and the split moved four claims out of every scope until it was listed here.
OPERATIONAL_EXTRA = ("docs/COMPLIANCE-DETAIL.md",)

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
    parsed = 0  # @-lines that resolved to a path, self-references included
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
            parsed += 1
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

    # The two ways a scope can collapse to the entry point are reported differently, because the
    # message is the whole diagnostic and one of them would otherwise be false. ZERO parsed lines
    # means the syntax stopped matching. A self-reference parsed fine and simply added nothing.
    if len(found) == 1 and not problems:
        problems.append(
            f"{ALWAYS_LOADED_ENTRY} is present and yielded ZERO @-imports, so the derivation has "
            f"stopped matching and the scope collapsed to the entry point alone"
            if parsed == 0
            else f"{ALWAYS_LOADED_ENTRY} is present and its {parsed} @-import(s) all resolve back "
            f"to itself, so the scope is the entry point alone"
        )
    return found, problems, True


def operational(root: Path) -> tuple[list[Path], bool]:
    """(paths, directory present) for the gitignored operational scope.

    No "problems" channel, unlike `always_loaded`: there is nothing here that can be declared and
    then go missing, because the scope IS whatever the glob finds. A present-but-empty directory
    is therefore not a broken derivation, just a directory with no prose in it, and it reports the
    same way an absent one does -- with its denominator, so the zero is visible either way.
    """
    d = root / OPERATIONAL_DIR
    extra = [root / rel for rel in OPERATIONAL_EXTRA if (root / rel).is_file()]
    if not d.is_dir():
        # The DIRECTORY is absent, which is what the second element reports. The extras are not
        # under it, so they are still returned: dropping them here would make a checkout without
        # notes/ silently stop scanning a file that is sitting right there.
        return extra, False
    found = sorted(
        (
            p
            for suffix in OPERATIONAL_SUFFIXES
            for p in d.glob(f"*{suffix}")
            if p.is_file()
        ),
        key=lambda p: p.name,
    )
    found += [root / rel for rel in OPERATIONAL_EXTRA if (root / rel).is_file()]
    return found, True


def uncovered(root: Path, scanned: set) -> tuple[list[tuple[Path, int]], str | None]:
    """Gitignored prose carrying a count claim that NO scope reads. [(path, claim count)].

    ADVISORY BY DESIGN, and the reason is not timidity. The files this finds are typically
    append-only journals whose historical entries are correct AS history, so gating on them
    would emit findings that are right to ignore, and a gate people learn to ignore is worse
    than no gate. What it buys instead is a number where there was silence.

    IGNORED-NESS IS ESTABLISHED WITH `git check-ignore`, never inferred from the path. A file
    can be missing from the index because it is ignored or because someone simply has not added
    it yet, and only the first is a scope gap; guessing would report a half-written draft as a
    hole in the gate's coverage.

    Scoped to the repo root and docs/ because that is where this project's prose lives. That
    bound is a real limit rather than a claim of completeness: a claim in a gitignored file
    somewhere else is still invisible, and closing that would need a full walk.
    Returns (findings, reason-it-could-not-check). A reason is NOT an empty finding list:
    "I looked and found nothing" and "I could not look" are different facts, and collapsing
    them into [] is the reassuring zero every other scope in this gate refuses to print.
    """
    cand = sorted(
        p
        for pat in ("*.md", "docs/*.md")
        for p in root.glob(pat)
        if p.is_file() and p.resolve() not in {s.resolve() for s in scanned}
    )
    if not cand:
        return [], None
    rels = [p.relative_to(root).as_posix() for p in cand]
    try:
        # -z, so paths come back NUL-separated and VERBATIM. Without it git applies
        # core.quotePath and emits `"docs/caf\303\251.md"` for anything non-ASCII, which no
        # longer equals the path that was passed in -- so the file drops out of the comparison
        # and goes unreported, which is the silent omission this whole check exists to end.
        # -z REQUIRES --stdin ("fatal: -z only makes sense with --stdin"), so the paths go in on
        # stdin NUL-separated rather than as argv. That buys a second thing worth having: argv
        # has a hard length limit, and a repo with many candidates would otherwise fail here.
        r = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "-z", "--stdin"],
            input="\0".join(rels),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as e:
        return [], f"git unavailable ({type(e).__name__})"
    # 0 = some path is ignored, 1 = none is. Anything else (128 = not a repo, a fatal) means
    # the question was never answered, and an empty list would read as a clean zero.
    if r.returncode not in (0, 1):
        why = (r.stderr or "").strip().splitlines()
        return [], (why[-1][:70] if why else f"git check-ignore rc={r.returncode}")
    ignored = {s for s in r.stdout.split("\0") if s}
    found = []
    for p, rel in zip(cand, rels):
        if rel not in ignored:
            continue
        try:
            n = len(claims_in(p.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
        if n:
            # RELATIVE, like every other path this gate prints. An absolute path here would put
            # the operator's home directory into the output of a gate whose sibling exists to
            # keep exactly that out of published surfaces.
            found.append((Path(rel), n))
    return found, None


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

    op_paths, op_present = operational(root)
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

    # ONE loop over both gitignored scopes, deliberately. A second copy of the exemption logic
    # would duplicate the `if marker is not None:` line that the sibling mutation control anchors
    # on, and a `replace(..., 1)` against a duplicated anchor mutates one copy while certifying
    # both. Same reason the scope label is a loop variable rather than two near-identical blocks.
    gitignored = [(p, "always-loaded") for p in al_paths]
    gitignored += [(p, "operational") for p in op_paths]

    al_total, op_total, al_exempt, op_exempt = 0, 0, [], []
    for p, scope in gitignored:
        rel = p.relative_to(root).as_posix()
        try:
            text = p.read_text(encoding="utf-8")
        except Exception as exc:
            return 2, [f"cannot check: {scope} {rel} is unreadable ({exc})"]
        src = text.splitlines()
        for ln, matched, n in claims_in(text):
            if scope == "always-loaded":
                al_total += 1
            else:
                op_total += 1
            marker = HISTORY_MARKER.search(re.sub(r"\s+", " ", src[ln - 1]))
            if marker is not None:
                # Keyed by SCOPE, not by which loop pass produced it. Pooling them made the
                # always-loaded summary claim every exemption and left the operational line
                # reporting none, which is a zero that does not mean what it looks like.
                (al_exempt if scope == "always-loaded" else op_exempt).append(
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
    # BRANCH ON WHAT WAS SCANNED, not on whether the directory exists. Those were the same
    # question until OPERATIONAL_EXTRA arrived, and they are not any more: a checkout with no
    # notes/ can still carry an extra. Keying on op_present printed "0 ... were scanned" directly
    # above a finding for the very file it had just scanned, which is the misleading zero this
    # scope exists to prevent, reproduced by its own summary line.
    # COUNT WHAT WAS FOUND, never the length of the configured tuple. `operational()` filters
    # extras by `.is_file()`, so in the state this scope is written for -- a clone, a runner, a
    # fresh worktree, none of which carry a gitignored file -- the tuple's length asserts a named
    # path contributed when none did. Reporting a scan that did not happen is the same misleading
    # denominator as reporting a zero for one that did.
    n_extra = sum(1 for rel in OPERATIONAL_EXTRA if (root / rel).is_file())
    if op_paths:
        where = f"{OPERATIONAL_DIR}/" if op_present else f"no {OPERATIONAL_DIR}/ here"
        lines.append(
            f"operational: {op_total} claim(s) across {len(op_paths)} gitignored file(s) "
            f"({where} plus {n_extra} of {len(OPERATIONAL_EXTRA)} named path(s)), which "
            f"git ls-files cannot name, {len(op_exempt)} exempt as dated record(s)"
        )
        lines.extend(op_exempt)
    else:
        # An ABSENT directory and a PRESENT but empty one are different facts, and saying "no
        # notes/ in this checkout" about a directory sitting right there is the same shape of
        # false statement this branch exists to avoid on the other side.
        where = (
            f"{OPERATIONAL_DIR}/ is present but holds no matching file"
            if op_present
            else f"no {OPERATIONAL_DIR}/ in this checkout"
        )
        lines.append(
            f"operational: NOT CHECKED. {where}, and none of the "
            f"{len(OPERATIONAL_EXTRA)} named path(s) present, so 0 gitignored operational file(s) "
            f"were scanned. Expected in a clone, a runner and a worktree."
        )
    # THE DENOMINATOR THE SCOPE WAS MISSING. Everything above reports what it read; nothing
    # reported what it never looked at, and that is the shape the last split failed in -- claims
    # moved into a new gitignored file, every scope kept returning a confident total, and the
    # number just went down. Named paths close whichever file someone remembered; this closes the
    # class by making the next one visible the day it appears.
    miss, miss_why = uncovered(root, set(al_paths) | set(op_paths))
    if miss_why:
        # SAY SO. Every other scope here distinguishes "clean" from "could not look", and a
        # denominator that goes quiet on failure is the one thing this block must never be.
        lines.append(
            f"UNCOVERED: NOT CHECKED ({miss_why}), so no gitignored file was tested for a "
            f"claim no scope reads."
        )
    elif miss:
        lines.append(
            f"UNCOVERED: {len(miss)} gitignored file(s) carry a count claim that no scope reads. "
            f"Not gated -- these are usually append-only records whose old entries are correct as "
            f"history -- but a split that lands here is invisible until someone looks:"
        )
        lines.extend(
            f"  {p.as_posix()}  {n} claim(s); add to OPERATIONAL_EXTRA to gate it"
            for p, n in miss
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
    gated = total + al_total + op_total - len(al_exempt) - len(op_exempt)
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

        # A SELF-IMPORT is also a collapsed scope, and it must not borrow the message above: the
        # syntax parsed perfectly, so saying it yielded zero imports would be a false diagnostic.
        entry.write_text(f"@{ALWAYS_LOADED_ENTRY}\n", encoding="utf-8")
        _, probs, _ = always_loaded(tmp)
        report(
            "a self-referential import is reported as such, not as zero imports",
            any("resolve back" in p for p in probs)
            and not any("ZERO @-imports" in p for p in probs),
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

        # ---- THE GITIGNORED OPERATIONAL SCOPE -------------------------------------------------
        # Restore the always-loaded half to green so every verdict below is attributable to the
        # operational scope alone.
        notes.write_text("CI runs all one components in a matrix.\n", encoding="utf-8")
        report(
            "baseline restored to green before the operational cases",
            check(tmp)[0] == 0,
        )

        # ABSENT is the state of every clone and runner. It must be reported, not gated.
        report("no notes/ dir: the scope is absent", operational(tmp) == ([], False))
        rc, out = check(tmp)
        report("and the verdict still passes", rc == 0)
        report(
            "and it says operational was NOT CHECKED",
            any("operational: NOT CHECKED" in ln for ln in out),
        )

        # PRESENT and discovered from the filesystem, by suffix.
        runbook = tmp / OPERATIONAL_DIR / "DEMO-RUNBOOK.md"
        runbook.parent.mkdir(parents=True, exist_ok=True)
        runbook.write_text("nothing to count here\n", encoding="utf-8")
        (tmp / OPERATIONAL_DIR / "scratch.txt").write_text(
            "all 8 plugins\n", encoding="utf-8"
        )
        found, present = operational(tmp)
        report(
            "a present notes/ is discovered, matching suffixes only",
            present and [p.name for p in found] == ["DEMO-RUNBOOK.md"],
        )
        report("a claimless operational file is not a failure", check(tmp)[0] == 0)

        # THE CONTROL THIS SCOPE EXISTS FOR. Every tracked surface correct, the always-loaded
        # tier correct, and a wrong count in the GITIGNORED runbook. Before this scope the same
        # tree printed agreement, because git ls-files never names the file that is wrong.
        runbook.write_text("The demo shows all 8 plugins loaded.\n", encoding="utf-8")
        rc, out = check(tmp)
        report("a wrong count in a gitignored operational file FAILS", rc == 1)
        report(
            "and the failure names that file, its line and both numbers",
            any(
                "DEMO-RUNBOOK.md:1" in ln and "8 plugins" in ln and "tracks 1" in ln
                for ln in out
            ),
        )

        # RESTORE: correcting that one claim is green again, so the red came from the claim and
        # not from the file's mere presence.
        runbook.write_text("The demo shows all one plugins loaded.\n", encoding="utf-8")
        report("correcting the operational claim restores the pass", check(tmp)[0] == 0)

        # THE EXEMPTION REACHES THIS SCOPE TOO, since a runbook records superseded and
        # branch-dependent values on purpose. It must be PRINTED as exempt, never dropped.
        runbook.write_text(
            "SUPERSEDED, kept as provenance: the demo showed all 8 plugins.\n",
            encoding="utf-8",
        )
        rc, out = check(tmp)
        report("a marked record in notes/ does not gate", rc == 0)
        report(
            "and it is reported rather than silently skipped",
            any("exempt" in ln for ln in out)
            and any("DEMO-RUNBOOK.md:1" in ln for ln in out),
        )
        # AND IT IS ATTRIBUTED TO THE RIGHT SCOPE. The assertion above passes on a build that
        # pools both scopes' exemptions into the always-loaded list, because it only asks whether
        # the substring "exempt" appears SOMEWHERE. That pooling made the operational summary
        # report zero exemptions while an operational file had one, which is a zero that does not
        # mean what it reads as -- the exact failure this whole gate exists to prevent. So key on
        # the HEADER, not on the word.
        op_line = next((ln for ln in out if ln.startswith("operational:")), "")
        al_line = next((ln for ln in out if ln.startswith("always-loaded:")), "")
        report(
            "the operational summary counts its OWN exemption",
            "1 exempt" in op_line,
        )
        report(
            # BOTH SCOPES ARE PRESENT HERE, so this discriminates too. `entry` is written earlier
            # in the fixture and never removed, so al_present is True and the real line reads
            # "always-loaded: 1 claim(s) across 3 file(s) ... 0 exempt as dated record(s)".
            # Pooling makes that same line read "1 exempt", so this assertion flips. Measured on
            # the mutant that restores the pooled append: 66/68, and BOTH new cases fail.
            "and the always-loaded summary does not claim it",
            "1 exempt" not in al_line,
        )

        # AND IT IS NOT A BLANKET HERE EITHER.
        runbook.write_text(
            "SUPERSEDED note above.\nThe demo shows all 8 plugins today.\n",
            encoding="utf-8",
        )
        report(
            "an unmarked operational claim one line down still fires",
            check(tmp)[0] == 1,
        )

        # OPERATIONAL_EXTRA: a gitignored file that does NOT live under OPERATIONAL_DIR. This
        # exists because splitting the @-imported compliance hub into a spoke on 2026-08-19 moved
        # four count claims into a file no scope covered, and the gate's total silently fell from
        # 7 to 6 while still reporting "agree". A named-path list is the fix; these cases are what
        # make it load-bearing rather than decorative.
        runbook.write_text("The demo shows all one plugins.\n", encoding="utf-8")
        extra = tmp / OPERATIONAL_EXTRA[0]
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text("The suite ships all 8 plugins.\n", encoding="utf-8")
        rc, out = check(tmp)
        report("a wrong claim in an OPERATIONAL_EXTRA path fires", rc == 1)
        report(
            "and the finding names that path rather than the directory",
            any(OPERATIONAL_EXTRA[0] in ln for ln in out),
        )
        extra.write_text("The suite ships all one plugins.\n", encoding="utf-8")
        report("correcting it restores the pass", check(tmp)[0] == 0)

        # AND IT SURVIVES THE DIRECTORY BEING ABSENT, which is the state of every clone: the extra
        # is not under notes/, so returning [] on a missing directory would silently drop it.
        import shutil as _sh

        _sh.rmtree(tmp / OPERATIONAL_DIR)
        extra.write_text("The suite ships all 8 plugins.\n", encoding="utf-8")
        rc, out = check(tmp)
        report("an extra is still scanned when notes/ is absent", rc == 1)
        op_line = next((ln for ln in out if ln.startswith("operational:")), "")
        report(
            # The case above passed on a build whose summary said "0 ... were scanned" directly
            # above the finding for that same file, because it only ever checked the exit code.
            "and the summary does not claim zero were scanned",
            "0 gitignored operational file(s) were scanned" not in op_line,
        )
        report(
            "and it says the directory is absent rather than implying it is present",
            f"no {OPERATIONAL_DIR}/ here" in op_line,
        )

        # THE SUMMARY COUNTS WHAT IT FOUND, not the length of the tuple. This is the state every
        # clone, runner and fresh worktree is in -- the gitignored extra simply is not there --
        # and the old text asserted a named path had been scanned in exactly that state.
        extra.unlink()
        (tmp / OPERATIONAL_DIR).mkdir(exist_ok=True)
        runbook.write_text("The demo shows all one plugins.\n", encoding="utf-8")
        rc, out = check(tmp)
        op_line = next((ln for ln in out if ln.startswith("operational:")), "")
        report(
            "an absent named path is reported as 0 found",
            "0 of 1 named path(s)" in op_line,
        )
        report("and the run is still green", rc == 0)

        # A PRESENT-BUT-EMPTY directory is a third state, and it used to borrow the absent one's
        # sentence -- claiming there is no notes/ here while notes/ sits in the tree.
        runbook.unlink()
        rc, out = check(tmp)
        op_line = next((ln for ln in out if ln.startswith("operational:")), "")
        report(
            "an empty notes/ is not described as absent",
            f"no {OPERATIONAL_DIR}/ in this checkout" not in op_line,
        )
        report(
            "and it says so in its own words",
            "present but holds no matching" in op_line,
        )

        # THE UNCOVERED DENOMINATOR. A gitignored file carrying a claim that no scope reads is
        # the shape the last split failed in, and it must be NAMED rather than silently omitted.
        (tmp / ".gitignore").write_text("docs/JOURNAL.md\n", encoding="utf-8")
        (tmp / "docs").mkdir(exist_ok=True)
        (tmp / "docs" / "JOURNAL.md").write_text(
            "Shipped all 8 plugins today.\n", encoding="utf-8"
        )
        rc, out = check(tmp)
        report(
            "an uncovered gitignored claim is named",
            any("docs/JOURNAL.md" in ln for ln in out),
        )
        report("and it does NOT gate the run", rc == 0)
        # OVER-CORRECTION CONTROL: a TRACKED file with the same claim must not be reported as
        # uncovered, or the denominator becomes noise that gets ignored.
        (tmp / "docs" / "TRACKED.md").write_text(
            "Shipped all 8 plugins today.\n", encoding="utf-8"
        )
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], capture_output=True)
        _, out = check(tmp)
        report(
            "a tracked file is not reported as uncovered",
            not any("docs/TRACKED.md" in ln for ln in out),
        )

        # A NON-ASCII NAME MUST NOT VANISH. git quotes such paths by default
        # (`"docs/caf\303\251.md"`), which no longer equals the path handed in, so the file drops
        # out of the comparison and is silently omitted from the very list that exists to stop
        # things being silently omitted.
        (tmp / ".gitignore").write_text(
            "docs/JOURNAL.md\ndocs/café.md\n", encoding="utf-8"
        )
        (tmp / "docs" / "café.md").write_text(
            "Shipped all 8 plugins today.\n", encoding="utf-8"
        )
        _, out = check(tmp)
        report(
            "a gitignored non-ASCII filename is still named",
            any("café.md" in ln for ln in out),
        )

        # COULD NOT LOOK IS NOT FOUND NOTHING. Outside a git repo the question is unanswerable,
        # and the answer must be a reason rather than an empty list that reads as clean.
        with tempfile.TemporaryDirectory() as nogit:
            ng = Path(nogit)
            (ng / "docs").mkdir()
            (ng / "docs" / "X.md").write_text("all 8 plugins\n", encoding="utf-8")
            miss_ng, why_ng = uncovered(ng, set())
            report("uncovered() outside a repo gives a reason", bool(why_ng))
            report("and returns no findings alongside it", miss_ng == [])

        # RESTORE, so a case appended after this block inherits a green tree rather than the
        # wreckage of this one. The block above this one did not, and that is a trap for whoever
        # writes the next case rather than a property anyone chose.
        (tmp / "docs" / "café.md").unlink()
        (tmp / "docs" / "JOURNAL.md").unlink()
        (tmp / "docs" / "TRACKED.md").unlink()
        (tmp / ".gitignore").unlink()
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text("The suite ships all one plugins.\n", encoding="utf-8")
        runbook.write_text("The demo shows all one plugins.\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], capture_output=True)
        report("the fixture is green again for whatever comes next", check(tmp)[0] == 0)

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
