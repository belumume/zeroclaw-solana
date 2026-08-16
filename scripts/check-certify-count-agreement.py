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

HONEST CEILING. It only reads the surfaces named in SURFACES. A doc that quotes the score and is
not on that list is invisible, so the list is derived from a repo-wide grep rather than memory, and
widening it is one line. It also cannot tell a live claim from a historical one, which is why
`docs/HANDOFF-ARCHIVE.md` is deliberately absent: that file records what was true at the time.

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

# Derived from `git grep -nE '[0-9]+/[0-9]+ cases correct|injection shapes'` rather than recalled.
# A surface that quotes the score belongs here; one that merely runs the command does not.
SURFACES = [
    "QUICKSTART.md",
    "README.md",
    "docs/ONE-PAGER.md",
    "demo/take.py",
    ".github/workflows/ci.yml",
]

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
SHAPES = re.compile(
    r"\b(one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+"
    r"(?:inject(?:ion|ed)\s+shapes?)",
    re.IGNORECASE,
)

CANNOT_CHECK = 2


def spoken(n: str) -> int | None:
    """A count written as a word or a digit, as an int."""
    return int(n) if n.isdigit() else WORDS.get(n.lower())


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
            for m in SHAPES.finditer(line):
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

    # The real tree must agree, which is the case a regression breaks.
    total = certifier_total(CERTIFIER)
    check("the real certifier reports a total", total is not None, True)
    if total:
        check("every real surface agrees", scan(ROOT, SURFACES, total), [])

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

    bad = scan(ROOT, SURFACES, total)
    print(
        f"certifier prints {total}/{total}, so {total - 1} injection shape(s) are refused"
    )
    for rel in SURFACES:
        hits = [b for b in bad if b.startswith(rel + ":")]
        print(f"  {'FAIL' if hits else 'ok  '} {rel}")
    if bad:
        print(
            "\nFAIL  a doc quotes a score the certifier does not print:\n"
            + "\n".join(f"    {b}" for b in bad)
            + "\n  These are read by strangers following the reproduce path, so a wrong score is\n"
            "  visible on their first command. Fix the prose; the script is the source of truth.",
            file=sys.stderr,
        )
        return 1

    print(f"\nPASS  {len(SURFACES)} surface(s) quote the certifier's real score")
    return 0


if __name__ == "__main__":
    sys.exit(main())
