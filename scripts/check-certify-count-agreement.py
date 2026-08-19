#!/usr/bin/env python3
"""Assert every doc that quotes the fail-closed certifier's score still quotes the right one.

WHY THIS EXISTS. `scripts/certify_publish_tx.py` prints `N/N cases correct`, one positive control
plus N-1 refused injection shapes. Six judge-facing surfaces quote that score in prose. When a
sixth case was added, every one of them kept saying `5/5` and "four injection shapes", and nothing
noticed: the script's own self-test passes at any N, CI only checks its exit code, and `demo/take.py`
asserts on the substring "cases correct" without the number, which is correct of it and blind here.

The worst of the six was QUICKSTART, which tells a stranger the literal string the command prints.
A reader following the reproduce path saw `6/6` against a doc promising `5/5` on their first
command, which is the cheapest possible way to lose them.

HOW IT DECIDES. The score is RUN, never restated: this executes the certifier and parses its total
out of stdout, so editing the certifier makes this gate say so rather than comparing docs against a
number someone once believed. Docs are then checked in both forms they use, the numeric `N/N cases
correct` and the spelled-out injection count, which is the total minus the one positive control.

OFFLINE. The certifier builds and inspects transaction bytes in memory and touches no network, so
an RPC outage cannot redden a gate about prose.

SELF-EXCLUSION is exactly one file wide: this checker has to contain the patterns it forbids in
order to search for them, and its own docstring quotes the stale `5/5` to explain the incident.
Every other tracked file is in scope, which the self-test pins.

HONEST CEILING, three of them. It only reads the surfaces named in SURFACES, so a doc that quotes
the score and is not on that list is invisible. It cannot tell a live claim from a historical one,
which is why `docs/HANDOFF-ARCHIVE.md` is deliberately absent: that file records what was true at
the time. And it only matches the PHRASINGS below, so a rewording slips past: `SHAPES` needs
"N injection/injected shapes" and `REFUSALS` needs a trailing "are", so "Five refusals total" is
not caught. That last constraint is load-bearing rather than laziness, and the comment on REFUSALS
says which real sentence it protects.

HOW SURFACES MUST BE BUILT. From TWO greps, because neither tool can see the other's scope.

  1. THE TRACKED SCOPE, with NO PATHSPEC. An extension filter such as
     `git grep ... -- '*.md' '*.py' '*.yml'` cannot see `index.html` whatever it holds, and
     `index.html` is one of the submission form's five links, so scoping the search drops a
     judge-facing surface without saying so. `check-doc-slop.py` guards the same `.html`
     omission.

         git grep -nE '[0-9]+/[0-9]+ cases correct|(four|five|[0-9]+) inject(ion|ed) shapes?'

  2. THE GITIGNORED OPERATIONAL SCOPE, which `git grep` CANNOT SEE AT ALL. This half is why the
     section was rewritten. `git grep` reads the INDEX, so a gitignored file is not filtered out
     of the results, it is absent from the corpus -- the command above returns a clean zero over
     it forever, and a filter that narrows an instrument makes its zero mean "I did not look"
     while it reads as "nothing is there". `notes/` is gitignored and holds the runbook a human
     reads ALOUD during a live demo. It sat outside every count gate in this repo until
     2026-08-19, when a sweep corrected this score across eight surfaces and left the runbook
     quoting a stale one. Reach it with a plain recursive grep, which reads the filesystem
     rather than the index:

         grep -rnE '[0-9]+/[0-9]+ cases correct|(four|five|[0-9]+) inject(ion|ed) shapes?' notes/

     Step 2 is the only one of the two that resolves `notes/`. Do NOT "simplify" it to
     `git grep --no-index --exclude-standard`: `--exclude-standard` re-applies .gitignore and
     hides the exact files step 2 exists to find. Unscoped `git grep --no-index` does work and
     is unusable here, because it also walks `.compound-tmp/` and other agents' worktrees.

OPTIONAL SURFACES ARE ABSENT EVERYWHERE BUT THE OPERATOR'S TRUNK. `notes/` is gitignored, so a
clone, a CI runner and an agent worktree all lack it. An empty operational scope is therefore
reported as NOT CHECKED with its denominator and does NOT gate; a missing REQUIRED surface stays
a failure, because a tracked doc that vanished means this gate is quietly covering less than it
says. Returning 2 for the absent case would paint every non-operator checkout permanently red,
and a gate that is always red is one people learn to skip.

Exit codes follow the house convention: 0 agree, 1 a real disagreement, 2 could not check.

Run: python3 scripts/check-certify-count-agreement.py
     python3 scripts/check-certify-count-agreement.py --selftest
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CERTIFIER = ROOT / "scripts" / "certify_publish_tx.py"

# From an UNSCOPED git grep (see the docstring on why the pathspec mattered). A surface that
# quotes the score belongs here; one that merely runs the command does not. The certifier itself
# is on the list because its own docstring and self-test comment described four shapes while it
# printed six, so the source of truth was misdescribing itself.
SURFACES = [
    "QUICKSTART.md",
    "README.md",
    "index.html",
    "docs/ONE-PAGER.md",
    "docs/ARGUMENT.md",
    "demo/take.py",
    "scripts/certify_publish_tx.py",
    ".github/workflows/ci.yml",
]

# THE GITIGNORED OPERATIONAL SCOPE. `notes/` holds the live-demo runbook, which quotes this score
# three times and is read ALOUD off a screen. It is gitignored, so `git ls-files` and `git grep`
# cannot see it and the list above could never have been derived to include it -- the omission was
# structural rather than an oversight, which is why the fix is a second scope and not a ninth entry.
#
# DISCOVERED BY GLOB, not declared. A declared entry fixes the one file that bit; a glob covers the
# next runbook someone writes, and this scope has no `git ls-files` to keep a declared list honest,
# so a stale omission here would be invisible in exactly the way the original defect was. Today it
# resolves to three files, of which DEMO-RUNBOOK.md is the one carrying claims.
#
# ABSENT IS NOT BROKEN. Every clone, CI runner and agent worktree lacks `notes/` by construction, so
# an empty glob is reported as NOT CHECKED with its denominator and does not gate. The tracked list
# above keeps the opposite rule: a REQUIRED surface that vanished is still a failure.
OPERATIONAL_DIR = "notes"
OPERATIONAL_GLOB = "*.md"

SCORE = re.compile(r"(\d+)\s*/\s*(\d+)\s+cases correct")
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
}
_N = r"(one|two|three|four|five|six|seven|eight|nine|ten|\d+)"
SHAPES = re.compile(rf"\b{_N}\s+(?:inject(?:ion|ed)\s+shapes?)", re.IGNORECASE)
# QUICKSTART states the count TWICE in one sentence: "five injected shapes ... The five refusals
# are ...". Guarding only the first lets a future bump update one and miss the other, which is the
# same half-corrected shape this gate exists to prevent.
# `\s+are` is load-bearing rather than incidental. Without it this matches ONE-PAGER's "at least
# one refusal and at least one acceptance", which counts a replay control's outcomes and has
# nothing to do with the certifier. Pinned as a must-not-fire case below.
REFUSALS = re.compile(rf"\b{_N}\s+refusals?\s+are\b", re.IGNORECASE)

CANNOT_CHECK = 2


def spoken(n: str) -> int | None:
    """A count written as a word or a digit, as an int."""
    return int(n) if n.isdigit() else WORDS.get(n.lower())


def operational(root: pathlib.Path) -> list[str]:
    """Gitignored operational surfaces present in THIS checkout, as repo-relative paths.

    Returns [] when the directory is absent, which is the normal state of every clone and runner.
    The caller must print that zero rather than swallowing it: an empty scope and a clean scope
    read identically otherwise, and that is the failure this whole scope exists to answer for.
    """
    d = root / OPERATIONAL_DIR
    if not d.is_dir():
        return []
    return sorted(
        p.relative_to(root).as_posix() for p in d.glob(OPERATIONAL_GLOB) if p.is_file()
    )


def certifier_total(path: pathlib.Path) -> int | None:
    """Run the certifier and read its own total out of stdout. Never restate it."""
    try:
        r = subprocess.run(
            [sys.executable, str(path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except Exception:
        return None
    m = None
    for m in SCORE.finditer(r.stdout or ""):
        pass  # the LAST score line is the summary
    if not m:
        return None
    passed, total = int(m.group(1)), int(m.group(2))
    return total if passed == total else None


def scan(root: pathlib.Path, surfaces: list[str], total: int) -> list[str]:
    """Every disagreement, as file:line strings."""
    bad: list[str] = []
    shapes = total - 1  # one positive control, the rest are refusals
    for rel in surfaces:
        p = root / rel
        if not p.is_file():
            bad.append(f"{rel}: listed as a surface and missing from the tree")
            continue
        for n, line in enumerate(
            p.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            for m in SCORE.finditer(line):
                if int(m.group(2)) != total:
                    bad.append(
                        f"{rel}:{n}: quotes '{m.group(0)}' but the certifier prints {total}/{total}"
                    )
            for pat in (SHAPES, REFUSALS):
                for m in pat.finditer(line):
                    got = spoken(m.group(1))
                    if got is not None and got != shapes:
                        bad.append(
                            f"{rel}:{n}: says '{m.group(0)}' but the certifier refuses {shapes}"
                        )
    return bad


def selftest() -> int:
    import tempfile

    cases, failures = 0, []

    def check(name, got, want):
        nonlocal cases
        cases += 1
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        (tmp / "docs").mkdir()

        # A fake certifier, so the self-test does not depend on the real one's current score.
        fake = tmp / "fake_certifier.py"
        fake.write_text(
            "print('self-test:')\nprint('  [OK ] a')\nprint()\nprint('7/7 cases correct')\n",
            encoding="utf-8",
        )
        check(
            "the total is READ from the script, not restated", certifier_total(fake), 7
        )

        # A certifier that FAILS must yield no total rather than a misleading one.
        red = tmp / "red_certifier.py"
        red.write_text("print('3/7 cases correct')\n", encoding="utf-8")
        check("a failing certifier yields no total", certifier_total(red), None)

        (tmp / "agree.md").write_text(
            "prints `7/7 cases correct` over six injection shapes\n", encoding="utf-8"
        )
        check("an agreeing surface is silent", scan(tmp, ["agree.md"], 7), [])

        (tmp / "stale_num.md").write_text(
            "it prints `5/5 cases correct`\n", encoding="utf-8"
        )
        got = scan(tmp, ["stale_num.md"], 7)
        check("a stale NUMERIC score fires", len(got), 1)
        check(
            "and it names the file and line",
            got and got[0].startswith("stale_num.md:1:"),
            True,
        )

        (tmp / "stale_word.md").write_text(
            "puts four injection shapes through it\n", encoding="utf-8"
        )
        check(
            "a stale SPELLED-OUT count fires", len(scan(tmp, ["stale_word.md"], 7)), 1
        )

        (tmp / "stale_digit.md").write_text(
            "4 injected shapes are refused\n", encoding="utf-8"
        )
        check("a stale DIGIT count fires", len(scan(tmp, ["stale_digit.md"], 7)), 1)

        # Review finding: QUICKSTART states the count TWICE in one sentence and only the first was
        # guarded. A half-corrected sentence must fire on the half that is still wrong.
        (tmp / "half.md").write_text(
            "six injection shapes, and prints `7/7 cases correct`. The four refusals are ...\n",
            encoding="utf-8",
        )
        got = scan(tmp, ["half.md"], 7)
        check("a half-corrected sentence fires on the stale half", len(got), 1)
        check(
            "and it names the refusals clause", bool(got) and "refusals" in got[0], True
        )

        # OVER-CORRECTION CONTROL for REFUSALS, verbatim from docs/ONE-PAGER.md: dropping the
        # trailing "are" makes this count a replay control's outcomes rather than the certifier's,
        # and it fired on the real tree when the pattern was briefly widened.
        (tmp / "replay.md").write_text(
            "requiring at least one refusal **and** at least one acceptance, so a dead program\n",
            encoding="utf-8",
        )
        check(
            "a refusal COUNT about something else is ignored",
            scan(tmp, ["replay.md"], 7),
            [],
        )

        # An .html surface must be scanned like any other: an extension pathspec cannot see
        # index.html at all, and index.html is a judge-facing surface, so SURFACES has to come
        # from an unscoped grep for this case to be reachable.
        (tmp / "page.html").write_text(
            "<pre># four injection shapes, all refused</pre>\n", encoding="utf-8"
        )
        check("an .html surface is scanned", len(scan(tmp, ["page.html"], 7)), 1)

        # OVER-CORRECTION CONTROL: the corrected wording must be SILENT, or the gate would flag the
        # very text its own message tells an author to write.
        (tmp / "fixed.md").write_text(
            "prints `7/7 cases correct`. The six refusals are ...\nsix injection shapes\n",
            encoding="utf-8",
        )
        check("the CORRECTED wording does not fire", scan(tmp, ["fixed.md"], 7), [])

        # An unrelated ratio must not be mistaken for the score.
        (tmp / "other.md").write_text(
            "the panel scored 5/5 and 10/10 static\n", encoding="utf-8"
        )
        check("an unrelated ratio is ignored", scan(tmp, ["other.md"], 7), [])

        (tmp / "docs" / "x.md").write_text("ok\n", encoding="utf-8")
        check("a missing surface is reported", len(scan(tmp, ["docs/gone.md"], 7)), 1)

        # ---- THE GITIGNORED OPERATIONAL SCOPE ------------------------------------------------
        # ABSENT is the normal state of a clone and must yield an empty scope rather than a
        # problem. Without this case, "the tracked surfaces agree" would be equally true of a
        # gate that hard-failed every CI run.
        check("no notes/ dir yields an empty scope", operational(tmp), [])

        (tmp / OPERATIONAL_DIR).mkdir()
        (tmp / OPERATIONAL_DIR / "DEMO-RUNBOOK.md").write_text(
            "| `certify_publish_tx.py` | rc 0, **`7/7 cases correct`** | six injection shapes |\n",
            encoding="utf-8",
        )
        (tmp / OPERATIONAL_DIR / "OTHER.md").write_text("no counts\n", encoding="utf-8")
        (tmp / OPERATIONAL_DIR / "ignored.txt").write_text(
            "5/5 cases correct\n", encoding="utf-8"
        )
        check(
            "a present notes/ is DISCOVERED by glob, .md only",
            operational(tmp),
            ["notes/DEMO-RUNBOOK.md", "notes/OTHER.md"],
        )
        check(
            "an AGREEING operational surface is silent",
            scan(tmp, operational(tmp), 7),
            [],
        )

        # THE CONTROL THIS SCOPE EXISTS FOR. A stale score in a GITIGNORED file, with every
        # tracked surface correct, must fire and name that file. Before this scope the same tree
        # printed a clean PASS, because no git-based derivation can name a file git does not track.
        (tmp / OPERATIONAL_DIR / "DEMO-RUNBOOK.md").write_text(
            "| `certify_publish_tx.py` | rc 0, **`5/5 cases correct`** | four injection shapes |\n",
            encoding="utf-8",
        )
        got = scan(tmp, operational(tmp), 7)
        check("a stale score in a gitignored operational file FIRES", len(got), 2)
        check(
            "and it names that file",
            bool(got) and got[0].startswith("notes/DEMO-RUNBOOK.md:1:"),
            True,
        )

    # The real tree must agree, which is the case a regression breaks. The operational scope is
    # included so the runbook is covered here too, and skipped silently where it does not exist.
    total = certifier_total(CERTIFIER)
    check("the real certifier reports a total", total is not None, True)
    if total:
        check(
            "every real surface agrees",
            scan(ROOT, SURFACES + operational(ROOT), total),
            [],
        )

    for f in failures:
        print(f"  FAIL  {f}")
    print(f"selftest: {cases - len(failures)}/{cases}")
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    if not CERTIFIER.is_file():
        print(f"cannot check: {CERTIFIER} is missing")
        return CANNOT_CHECK
    total = certifier_total(CERTIFIER)
    if total is None:
        print(
            "cannot check: the certifier did not print a passing 'N/N cases correct' line, so "
            "there is no score to compare the docs against. Run it directly and read why."
        )
        return CANNOT_CHECK

    ops = operational(ROOT)
    bad = scan(ROOT, SURFACES + ops, total)
    print(
        f"certifier prints {total}/{total}, so {total - 1} injection shape(s) are refused"
    )
    for rel in SURFACES + ops:
        hits = [b for b in bad if b.startswith(rel + ":")]
        print(f"  {'FAIL' if hits else 'ok  '} {rel}")
    if ops:
        print(
            f"  ({len(ops)} of those are gitignored operational surface(s) under "
            f"{OPERATIONAL_DIR}/, invisible to git grep)"
        )
    else:
        print(
            f"  NOT CHECKED: no {OPERATIONAL_DIR}/ in this checkout, so 0 gitignored "
            f"operational surface(s) were scanned. Expected in a clone, a CI runner and an "
            f"agent worktree, where that directory does not exist."
        )
    if bad:
        print(
            "\nFAIL  a doc quotes a score the certifier does not print:\n"
            + "\n".join(f"    {b}" for b in bad)
            + "\n  These are read by strangers following the reproduce path, so a wrong score is\n"
            "  visible on their first command. Fix the prose; the script is the source of truth.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nPASS  {len(SURFACES) + len(ops)} surface(s) quote the certifier's real score"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
