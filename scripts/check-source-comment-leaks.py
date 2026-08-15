#!/usr/bin/env python3
"""Tracked source must not name things only an insider can resolve.

THE GAP THIS CLOSES, and it is the repo's own written rule going unimplemented. The project's
hygiene notes say plainly that source COMMENTS carry the same leak risk as code and must be
audited too. Nothing implemented it: every slop and leak gate lists four prose suffixes
(`.md`, `.markdown`, `.mdx`, `.html`) and none of them is `.py`. So a whole file type was
green by never being looked at, which downstream is indistinguishable from being clean.

Five live leaks sat on the default branch when this was written, every one readable by anyone
who clones: an unsourced statistic from a private corpus, a reference to work being done by
agents, a cross-session coordination protocol with a private channel directory, an internal
planning-document reference, and an internal demo-beat number.

WHY THESE MARKERS AND NOT MORE. Measured over 151 tracked `.py` files across both repo roots
before any of this was written, and the measurement REMOVED two candidates that looked
obvious:

  demo beat numbers ......... 15 hits, and most are functional identifiers such as a test case
                              literally named "beat1-tampered". A gate flagging working code
                              teaches the next reader to route around it.
  "the operator's" .......... 16 hits, and nearly all describe a privacy BEHAVIOUR the code
                              implements, for example suppressing a home path from output.
                              There the subject is the system, which is the side that must
                              survive; cutting it would remove an explanation and leave the
                              behaviour unexplained.

What remains is the narrow set that names a private artifact, a private channel, or the
process that produced the work. Each measured 0 or 1 hits, so this gate is quiet by
construction rather than by hope.

HONEST CEILING, so its existence is never read as coverage:
  - It matches fixed markers. Novel internal vocabulary nobody has coined yet is invisible.
  - It scans the whole file rather than parsing comments, because at these markers' measured
    rate the distinction changes nothing and a parser adds a failure mode. A marker inside a
    string that reaches a user is a leak too, so whole-file is the safer error.
  - It cannot judge whether an unfamiliar noun is internal. That stays a human call.
  - It does NOT carry the prose slop patterns. Those are tuned for documents, and a code file
    legitimately says things a document would not.
  - TWO OF THE FIVE ORIGINAL LEAKS HAVE NO MARKER HERE, stated because a gate that catches
    three of five and reports OK is the failure this file exists to name. The unsourced
    statistic is the sharpest of the five and is not mechanically decidable: telling a cited
    number from an uncited one needs judgement about what the source would even be. The demo
    beat number is the rejected class above. Both were fixed by hand and neither is defended
    by anything that runs, so a reviewer is still the only check on them.

Verified in both directions against a real state, not only against probes: run over
`git show origin/main:<path>` for the four files that carried the original leaks it reports 5
findings, and over the same files at HEAD it reports 0.

Exit codes follow the house convention: 0 ok, 1 finding, 2 could-not-check.
"""

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# Each names a private artifact, a private channel, or how the work was produced.
MARKERS = [
    (
        "internal plan reference",
        r"\bPLAN\s+(?:Part|part|§)\s*\d+",
        "PLAN Part 10 owns them.",
    ),
    (
        "private sync channel",
        r"\.zcx-sync\b",
        "per the PROTOCOL in the .zcx-sync/ channel beside this checkout",
    ),
    (
        "work attributed to agents",
        r"\b(?:measured|written|produced|checked|verified)\s+by\s+(?:an?\s+)?agents?\b",
        "Durations below were measured by agents that ran each command.",
    ),
    (
        "internal document reference",
        r"\b(?:PROTOCOL|HANDOFF|SUBMISSION-HANDOFF|TASK-MIRROR|OPERATOR-INBOX)\.md\b",
        "see HANDOFF.md for the current state",
    ),
    (
        "cross-branch coordination rule",
        r"\b(?:this|the)\s+(?:branch|worktree)\s+must not\b",
        "and this branch must not write there",
    ),
    (
        "working-session reference",
        r"\b(?:per|after|during)\s+(?:a\s+)?(?:compaction|session\s*\d+)\b",
        "restated after a compaction",
    ),
    (
        "internal task number",
        r"\btask\s*#\d+",
        "tracked as task #42",
    ),
    (
        "crediting the checker that caught it",
        r"\b(?:an?\s+)?(?:audit|guard|checker|gate)\s+caught\s+(?:it|this|that)\b",
        "the identifier gate caught it here on the first run",
    ),
]

# Deliberately NOT markers. Measured and rejected; kept here so a later pass does not add them
# back as an obvious improvement. Each is asserted as a must-NOT-fire case in the selftest.
REJECTED = [
    'CASES = {"beat1-tampered": ("0.39", TAMPERED, UNPAID_RE)}',
    "# without this the operator's home path is printed with no flag",
    "# the full cwd, which on this machine puts the operator's username on screen",
]


def tracked_python():
    """Every tracked .py except this file.

    THE EXCLUSION IS STRUCTURAL, NOT A CARVE-OUT FOR CONVENIENCE. A prohibition has to name
    what it forbids, so this file necessarily contains one instance of every marker, in its
    pattern list and again in the probe beside each one. Scanning itself, it reported 9
    findings against a tree that was otherwise clean, which is the shape where a checker pins
    its own verdict to red forever and gets disabled rather than read.

    It is exactly ONE file wide. Everything else is scanned, and the selftest asserts that a
    marker planted in any other file still fires, so this cannot quietly become a way to
    silence real findings.
    """
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "*.py"],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        return None
    here = pathlib.Path(__file__).resolve()
    return [
        REPO / f
        for f in out.stdout.split()
        if (REPO / f).is_file() and (REPO / f).resolve() != here
    ]


def scan(text):
    """Return [(label, matched_text)] for every marker present."""
    found = []
    for label, pattern, _probe in MARKERS:
        for m in re.finditer(pattern, text):
            found.append((label, m.group(0)))
    return found


def selftest():
    bad = 0
    print("must FIRE, one probe per marker so each is proven independently:")
    for label, pattern, probe in MARKERS:
        ok = bool(re.search(pattern, probe))
        print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
        if not ok:
            bad += 1

    print("\nmust NOT fire, the two candidates measurement rejected:")
    for sample in REJECTED:
        hits = scan(sample)
        ok = not hits
        print(f"  {'ok  ' if ok else 'FAIL'}  {sample[:66]}")
        if not ok:
            bad += 1
            print(f"        fired: {hits}")

    # The self-exclusion must be exactly one file wide, or it becomes a way to silence real
    # findings. Two assertions: this file is out of the scanned set, and every other tracked
    # file is still in it.
    print("\nthe self-exclusion is one file wide, not a blanket:")
    files = tracked_python()
    here = pathlib.Path(__file__).resolve()
    if files is None:
        print("  FAIL  could not enumerate tracked files")
        bad += 1
        scanned = 0
    else:
        scanned = len(files)
        excluded_self = here not in {f.resolve() for f in files}
        print(f"  {'ok  ' if excluded_self else 'FAIL'}  this checker is not scanned")
        bad += 0 if excluded_self else 1
        others = scanned > 20
        print(
            f"  {'ok  ' if others else 'FAIL'}  {scanned} other tracked file(s) still scanned"
        )
        bad += 0 if others else 1

    # And a marker planted in a DIFFERENT file must still be found, which is what proves the
    # exclusion did not quietly widen.
    planted = "# tracked as task #42 in the internal list\n"
    found = bool(scan(planted))
    print(f"  {'ok  ' if found else 'FAIL'}  a marker in any other file still fires")
    bad += 0 if found else 1

    total = len(MARKERS) + len(REJECTED) + 3
    print(
        f"\n{'OK' if not bad else 'FAILED'}  {total - bad}/{total}; each marker fires on its"
    )
    print(
        "    own probe, neither rejected class fires, and the self-exclusion is bounded."
    )
    return 1 if bad else 0


def main():
    if "--selftest" in sys.argv:
        return selftest()

    files = tracked_python()
    if files is None:
        print("NOT CHECKED: git ls-files failed, so the file set is unknown.")
        print("  Exits 2 rather than 0: a scan that does not know what to scan has")
        print("  established nothing.")
        return 2
    if not files:
        print(
            "NOT CHECKED: no tracked .py files found, which is not a plausible clean result."
        )
        return 2

    findings = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for label, hit in scan(text):
            line = text[: text.find(hit)].count("\n") + 1
            findings.append((path.relative_to(REPO), line, label, hit))

    print(
        f"scanned {len(files)} tracked .py file(s) for {len(MARKERS)} internal markers"
    )

    if not findings:
        print("\nOK  no tracked source names a private artifact, channel, or process.")
        return 0

    for rel, line, label, hit in findings:
        print(f"\nFINDING  {rel}:{line}  {label}")
        print(f"         {hit!r}")
        print("         A stranger cloning this repo reads this and cannot resolve it.")
        print("         Keep the technical fact; drop the internal reference.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
