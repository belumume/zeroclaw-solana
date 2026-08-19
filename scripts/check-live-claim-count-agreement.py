#!/usr/bin/env python3
"""Bind the claim counts a reader is TOLD to the counts `verify-proof.py` can actually print.

WHY THIS EXISTS. Three judge-facing surfaces carried the identical comment
`# 10 static + 4 live claims, stdlib only`, and the write-up carried the same claim spelled out in
words. The live half was false: `verify-proof.py` derives its live total as
`3 + (1 if ledger_gates else 0) + (1 if selfcheck_gates else 0)`, so it reaches five, and a fresh
clone printed `5/5 live claims verified`. The repo's own captured terminal cast had been showing a
denominator of five for as long as the prose said four, and nothing compared the two.

That asymmetry is the point. The script DERIVES its totals, so they follow the code with nobody
told. The prose is a number someone typed on a day when it was right, and a typed number does not
know the code moved. Nothing goes red, because nothing was comparing them.

WHAT IT ASSERTS. Every count claim of the form `<N> static` or `<N> live claim(s)` on a prose
surface must equal the corresponding CEILING derived from `verify-proof.py` itself. Nothing else.
It does not read the sentence around the number and deliberately cannot tell good prose from bad.

HOW THE SURFACE LIST MUST BE BUILT, and the half that was missing until 2026-08-19. `git ls-files`
was the whole derivation, and it reads the INDEX, so a GITIGNORED file is not filtered out of the
results -- it is absent from the corpus, and the scan returns a clean zero over it forever. That is
the worst shape a zero can take, because it is byte-identical to "nothing is wrong there".
`notes/` is gitignored and holds the runbook a human reads ALOUD during a live demo; it quotes the
static count four times and no count gate in this repo could see it. A sweep corrected these counts
across the tracked surfaces and left the runbook behind, for the second time in this repo's history
(PR #66 was the first).

So the scope is TWO derivations, because neither tool can see the other's half:

    git grep -nE '[0-9]+ +(static|live claim)'        # tracked; NO extension pathspec
    grep  -rnE '[0-9]+ +(static|live claim)' notes/   # gitignored; reads the filesystem

Only the second resolves `notes/`. Do NOT reach for
`git grep --no-index --exclude-standard`: `--exclude-standard` re-applies .gitignore and hides the
exact files the second command exists to find. Unscoped `git grep --no-index` does work and is
unusable, because it also walks `.compound-tmp/` and every other agent's worktree.

THE OPERATIONAL SCOPE IS DISCOVERED, NOT DECLARED, and it does not gate when absent. A glob covers
the next runbook someone writes; a declared list could go stale by omission with no `git ls-files`
to keep it honest, which is the failure that produced this scope. Every clone, CI runner and agent
worktree lacks `notes/`, so an empty glob prints NOT CHECKED with its denominator and leaves the
exit code alone. Returning 2 there would paint every non-operator checkout permanently red, and a
gate that is always red is a gate people learn to skip.

WHY A CEILING RATHER THAN A CURRENT VALUE. The live total is conditional by construction, and the
script's own comment explains that a constant there "would either overstate today or need
remembering later". A doc that names one exact live count is therefore wrong in the other two
states. A doc that names the CEILING is true in all of them, because the printed denominator can
never exceed it, and it moves only when someone edits the script. So the prose says `up to 5` and
this gate binds that 5 to the code. The static total has no condition on it at all, so it is bound
as a plain equality.

THE CEILING IS PARSED, NOT RUN. Running the script would report today's RUNTIME denominator, which
depends on what a remote box happens to be serving, and would need the network. This reads the
source with `ast`: it counts the `ACCOUNTS` and `TXS` literals for the static side, and for the
live side takes the LARGER branch of each conditional, which is the total over every combination
of its conditions. Taking the true branch instead would be right only while every optional claim
happens to be written `1 if cond else 0`. Offline, deterministic, and it fails loudly rather than
guessing if either shape stops resolving.

THE WORD "one" IS NOT A COUNT, and this is the one carve-out. Measured over the tracked prose
corpus, the pattern hits 13 times: 12 are real count claims and the 13th is `README.md`'s image
description saying "including one live claim that failed on the day it was captured", which is
ordinary English rather than a total. Excluding the WORD `one` while keeping the DIGIT `1` removes
it and cannot hide a real disagreement, because the live expression's base term is a literal 3, so
a ceiling of one is unreachable without editing that constant, and any such edit would flag every
surface anyway. A selftest case pins both halves.

ORDINALS ARE NOT CARDINALS. `TESTING.md` calls the ledger check "a fourth live claim", an ordinal
describing its position, and that is true and must survive. Word-boundary matching on cardinals
leaves it alone, since `fourth` is not `four`. A selftest case pins it.

SOURCE COMMENTS ARE OUT OF SCOPE, for the same reason the sibling plugin-count gate excludes them:
a comment recording what a check counted at a point in time is a measurement, and rewriting it to
match today would destroy the record rather than update it.

NO DOCUMENT IS EXEMPT, and the exemption list is deliberately empty rather than speculative. The
measured corpus contains no dated record quoting these counts. If one ever appears the gate fires
loudly and someone adds it here on purpose, which is better than shipping an exemption path that
has never been exercised.

Exit 0 they agree, 1 a claim disagrees, 2 could not check. A could-not-check is NOT a pass. A
derivation that stopped resolving, or a scan that matched nothing, would otherwise report agreement
over an empty measurement, which is this repo's most-repeated instrument failure.

  --selftest   drives both directions against a temp tree, plus the over-correction controls
               and a mutation control proving the detector is load-bearing
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = "scripts/verify-proof.py"

# Cardinals only, and `one` is excluded with its reason in the docstring above. Ordinals are
# absent by construction: `fourth` never matches `\bfour\b`.
CARDINALS = {
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
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
}
_NUM = r"(\d+|" + "|".join(CARDINALS) + r")"
PAT_STATIC = re.compile(r"\b" + _NUM + r"\s+static\b", re.I)
PAT_LIVE = re.compile(r"\b" + _NUM + r"\s+live\s+claim", re.I)

# A discovery walk that matches nothing reports a clean sweep. Floor it well below the measured
# 13 so ordinary editing does not trip it, but high enough that a broken scan cannot pass.
#
# KEYED ON THE TRACKED SCOPE ALONE. The operational scope is absent from every clone, so folding it
# into the floor would turn "this is a CI runner" into "the pattern died", which is a false
# cannot-check on a healthy tree. The pattern's liveness is proven by the tracked half either way.
CLAIM_FLOOR = 6

# The gitignored operational scope. See the docstring: `git ls-files` is structurally blind to it,
# so it is discovered from the filesystem instead. Suffixes mirror the tracked scope's `*.md`
# `*.html` so the two halves police the same kinds of file.
OPERATIONAL_DIR = "notes"
OPERATIONAL_SUFFIXES = (".md", ".html")


def _value(token: str) -> int:
    return int(token) if token.isdigit() else CARDINALS[token.lower()]


class DerivationError(Exception):
    """The verifier's shape stopped resolving. Never downgrade this to a pass."""


def _ceiling(node: ast.AST) -> int:
    """Largest value the expression can take over every combination of its conditions."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.IfExp):
        # Take the LARGER branch rather than the true one. Reading `node.body` would be
        # right for today's `1 if ledger_gates else 0` and would silently UNDER-count an
        # inverted `0 if ledger_gates else 1`, which is the worst direction: a ceiling too
        # low makes correct prose look wrong, and the gate would not raise, because the
        # shape is one it recognises. `max` needs no assumption about which way it is
        # written and is the actual ceiling of a conditional either way.
        return max(_ceiling(node.body), _ceiling(node.orelse))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _ceiling(node.left) + _ceiling(node.right)
    raise DerivationError(
        "live_total is no longer a sum of integers and conditionals; this gate cannot "
        f"derive a ceiling from `{ast.unparse(node)}` and must not guess"
    )


def derive_ceilings(source: str) -> tuple[int, int]:
    """Read the verifier's own source for the two ceilings. Raises rather than guessing."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        raise DerivationError(f"{VERIFIER} does not parse: {e}") from e

    lists: dict[str, int] = {}
    live: ast.AST | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if target.id in ("ACCOUNTS", "TXS") and isinstance(
            node.value, (ast.List, ast.Tuple)
        ):
            lists[target.id] = len(node.value.elts)
        if target.id == "live_total":
            live = node.value

    missing = [n for n in ("ACCOUNTS", "TXS") if n not in lists]
    if missing:
        raise DerivationError(
            f"{VERIFIER} no longer defines {' and '.join(missing)} as a module-level list, "
            "so the static ceiling cannot be derived"
        )
    if live is None:
        raise DerivationError(
            f"{VERIFIER} no longer assigns `live_total`, so the live ceiling cannot be derived"
        )
    return lists["ACCOUNTS"] + lists["TXS"], _ceiling(live)


def _surfaces(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "*.md", "*.html"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return sorted(p for p in out if p.strip())


def _operational(root: Path) -> list[str]:
    """Gitignored operational prose present in THIS checkout, as repo-relative paths.

    `git ls-files` above cannot return these at all, so without this the runbook a human reads
    aloud during the demo is outside the gate. Returns [] where the directory is absent, which is
    the state of every clone and runner; the caller prints that zero rather than swallowing it.
    """
    d = root / OPERATIONAL_DIR
    if not d.is_dir():
        return []
    return sorted(
        p.relative_to(root).as_posix()
        for suffix in OPERATIONAL_SUFFIXES
        for p in d.glob(f"*{suffix}")
        if p.is_file()
    )


def check(root: Path) -> tuple[int, list[str]]:
    lines: list[str] = []
    verifier = root / VERIFIER
    if not verifier.is_file():
        return 2, [f"FAIL  {VERIFIER} is missing; nothing to derive the ceilings from."]
    try:
        static_ceiling, live_ceiling = derive_ceilings(
            verifier.read_text(encoding="utf-8")
        )
    except DerivationError as e:
        return 2, [f"FAIL  could not derive ceilings: {e}"]

    lines.append(
        f"derived from {VERIFIER}: static {static_ceiling}, live ceiling {live_ceiling} "
        "(the largest total the live expression can reach)"
    )

    tracked = _surfaces(root)
    ops = _operational(root)

    disagree: list[str] = []
    seen = 0
    tracked_seen = 0
    for rel in tracked + ops:
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for kind, pattern, want in (
                ("static", PAT_STATIC, static_ceiling),
                ("live", PAT_LIVE, live_ceiling),
            ):
                for match in pattern.finditer(line):
                    seen += 1
                    if rel in tracked:
                        tracked_seen += 1
                    got = _value(match.group(1))
                    if got != want:
                        disagree.append(
                            f"  {rel}:{lineno}  says {kind} {got}, "
                            f"the script reaches {want}\n      {line.strip()[:110]}"
                        )

    # The floor reads the TRACKED count only, per the note on CLAIM_FLOOR.
    if tracked_seen < CLAIM_FLOOR:
        lines.append(
            f"FAIL  found only {tracked_seen} claim(s) across {len(tracked)} tracked prose "
            f"file(s), expected at least {CLAIM_FLOOR}."
        )
        lines.append(
            "      The scan is broken, so a clean result here would mean nothing."
        )
        return 2, lines

    lines.append(
        f"scanned {len(tracked)} tracked prose file(s); {seen} claim(s) checked"
    )
    if ops:
        lines.append(
            f"plus {len(ops)} gitignored operational file(s) under {OPERATIONAL_DIR}/, "
            f"carrying {seen - tracked_seen} of those claim(s). git ls-files cannot see these."
        )
    else:
        lines.append(
            f"NOT CHECKED: no {OPERATIONAL_DIR}/ in this checkout, so 0 gitignored operational "
            f"file(s) were scanned. Expected in a clone, a CI runner and an agent worktree."
        )
    if disagree:
        lines.append("\nFAIL  claim(s) disagree with the script:\n")
        lines.extend(disagree)
        lines.append(
            "\n  The script derives its totals and the prose does not, so the prose is what "
            'drifted.\n  A live count is conditional: state the ceiling ("up to N") rather '
            "than one state's value."
        )
        return 1, lines
    lines.append(f"\nok    all {seen} claim(s) agree with {VERIFIER}")
    return 0, lines


# ----------------------------------------------------------------------------------------
# Controls. Both directions, because a gate that only ever goes green proves nothing, and a
# narrowing that only ever goes red has disabled itself.
# ----------------------------------------------------------------------------------------

VERIFIER_FIXTURE = """\
ACCOUNTS = [1, 2, 3, 4, 5, 6]
TXS = [1, 2, 3, 4]

def main():
    live_total = 3 + (1 if ledger_gates else 0) + (1 if selfcheck_gates else 0)
"""


def _fixture(
    tmp: Path,
    docs: dict[str, str],
    verifier: str = VERIFIER_FIXTURE,
    ignored: dict[str, str] | None = None,
) -> None:
    """Build a fixture repo. `ignored` files are written under a real .gitignore entry.

    They must be GENUINELY gitignored rather than merely untracked, or the operational-scope
    cases below would pass for the wrong reason: `git ls-files` would still miss an untracked
    file, so the case could not tell a working second scope from an accident of staging.
    """
    (tmp / "scripts").mkdir(parents=True, exist_ok=True)
    (tmp / VERIFIER).write_text(verifier, encoding="utf-8")
    for name, body in docs.items():
        (tmp / name).write_text(body, encoding="utf-8")
    if ignored:
        (tmp / ".gitignore").write_text(f"{OPERATIONAL_DIR}/\n", encoding="utf-8")
        for name, body in ignored.items():
            p = tmp / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)


def _agreeing_docs(live: str = "up to 5") -> dict[str, str]:
    # Eight claims, comfortably over CLAIM_FLOOR, spread over digits and words.
    return {
        "a.md": (
            f"python3 scripts/verify-proof.py   # 10 static + {live} live claims\n"
            "It prints 10/10 static claims when the record holds.\n"
        ),
        "b.md": (
            "checks ten static and up to five live claims with stdlib only.\n"
            "All ten static claims stay green.\n"
        ),
        "c.html": (
            "<pre># 10 static + up to 5 live claims, stdlib only</pre>\n"
            "<p>ending in 10/10 static claims</p>\n"
        ),
    }


def selftest() -> int:
    failures: list[str] = []
    cases = 0

    def report(name: str, ok: bool) -> None:
        nonlocal cases
        cases += 1
        if not ok:
            failures.append(name)

    def run(tmp: Path) -> tuple[int, list[str]]:
        return check(tmp)

    # 1. The derivation itself, against the real script rather than only a fixture.
    real = ROOT / VERIFIER
    if real.is_file():
        try:
            s, live = derive_ceilings(real.read_text(encoding="utf-8"))
            report("derives 10 static from the real verifier", s == 10)
            report("derives a live ceiling of 5 from the real verifier", live == 5)
        except DerivationError:
            report("derives ceilings from the real verifier", False)
            report("derives a live ceiling from the real verifier", False)

    # 2. An agreeing corpus passes.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        _fixture(tmp, _agreeing_docs())
        rc, out = run(tmp)
        report("an agreeing corpus passes", rc == 0)
        report(
            "and it says how many claims it checked",
            any("9 claim(s) agree" in x for x in out),
        )

    # 3. MUST FIRE: a live count naming one state rather than the ceiling.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        _fixture(tmp, _agreeing_docs(live="4"))
        rc, out = run(tmp)
        report("a live count of 4 against a ceiling of 5 fails", rc == 1)
        report("and it names the file and line", any("a.md:1" in x for x in out))

    # 4. MUST FIRE in words too. A gate blind to spelled-out numbers would have missed the
    #    write-up, which is the surface the brief itself did not list.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        docs = _agreeing_docs()
        docs["b.md"] = "checks ten static and four live claims with stdlib only.\n"
        _fixture(tmp, docs)
        report("a spelled-out live count of four fails", run(tmp)[0] == 1)

    # 5. MUST FIRE on the static side, so the two halves are independently load-bearing.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        docs = _agreeing_docs()
        docs["a.md"] = (
            "python3 scripts/verify-proof.py   # 9 static + up to 5 live claims\n"
        )
        _fixture(tmp, docs)
        report("a static count of 9 against 10 fails", run(tmp)[0] == 1)

    # 6. The ceiling FOLLOWS the script. Same prose, a verifier with a third optional claim,
    #    and the prose that was right becomes wrong. This is the property the gate exists for.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        grown = VERIFIER_FIXTURE.replace(
            "live_total = 3 + (1 if ledger_gates else 0) + (1 if selfcheck_gates else 0)",
            "live_total = 3 + (1 if a else 0) + (1 if b else 0) + (1 if c else 0)",
        )
        assert "if c else" in grown, "case 6 mutation did not apply"
        _fixture(tmp, _agreeing_docs(), verifier=grown)
        rc, out = run(tmp)
        report("a sixth optional claim makes the unchanged prose fail", rc == 1)
        report(
            "and the derived ceiling reports as 6",
            any("live ceiling 6" in x for x in out),
        )

    # 6b. AN INVERTED CONDITIONAL still derives the same ceiling. Reading only the true branch
    #     would return 4 here and make correct prose look wrong, without raising, because the
    #     shape is one the deriver recognises. Raised in review on this PR.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        inverted = VERIFIER_FIXTURE.replace(
            "(1 if selfcheck_gates else 0)", "(0 if selfcheck_gates else 1)"
        )
        assert "(0 if selfcheck_gates else 1)" in inverted, (
            "case 6b mutation did not apply"
        )
        _fixture(tmp, _agreeing_docs(), verifier=inverted)
        rc, out = run(tmp)
        report("an inverted conditional still derives a ceiling of 5", rc == 0)
        report(
            "and it is not under-counted as 4",
            any("live ceiling 5" in x for x in out),
        )

    # 7. OVER-CORRECTION: the word "one" is ordinary English, not a total. This is the single
    #    measured false positive, verbatim from README.md's image description.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        docs = _agreeing_docs()
        docs["d.md"] = (
            "A real, unedited run of verify-proof.py from a fresh clone of this repo, "
            "including one live claim that failed on the day it was captured.\n"
        )
        _fixture(tmp, docs)
        report('the word "one" as an article does not fire', run(tmp)[0] == 0)

    # 8. AND THE CARVE-OUT IS NOT A HOLE: the digit 1 still fires.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        docs = _agreeing_docs()
        docs["d.md"] = "the check covers 1 live claim in total\n"
        _fixture(tmp, docs)
        report("the digit 1 still fires", run(tmp)[0] == 1)

    # 9. OVER-CORRECTION: an ordinal describes a position, not a total. Verbatim from TESTING.md.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        docs = _agreeing_docs()
        docs["d.md"] = "verify-proof.py gates on them as a fourth live claim.\n"
        _fixture(tmp, docs)
        report("an ordinal does not fire", run(tmp)[0] == 0)

    # 10. COULD-NOT-CHECK is not a pass, in both of its shapes.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        broken = VERIFIER_FIXTURE.replace("ACCOUNTS = [1, 2, 3, 4, 5, 6]", "pass")
        assert "ACCOUNTS" not in broken, "case 10 mutation did not apply"
        _fixture(tmp, _agreeing_docs(), verifier=broken)
        rc, out = run(tmp)
        report("a verifier without ACCOUNTS exits 2, not 0", rc == 2)
        report("and it says why", any("ACCOUNTS" in x for x in out))

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        _fixture(tmp, {"a.md": "no counts here at all\n"})
        report("an empty scan exits 2, not 0", run(tmp)[0] == 2)

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        opaque = VERIFIER_FIXTURE.replace(
            "live_total = 3 + (1 if ledger_gates else 0) + (1 if selfcheck_gates else 0)",
            "live_total = len(whatever)",
        )
        assert "len(whatever)" in opaque, "case 10c mutation did not apply"
        _fixture(tmp, _agreeing_docs(), verifier=opaque)
        report("an underivable live_total exits 2, not 0", run(tmp)[0] == 2)

    # 10b. THE GITIGNORED OPERATIONAL SCOPE, all four directions.
    #
    #      ABSENT is the state of every clone and runner: NOT CHECKED, and it must not gate.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        _fixture(tmp, _agreeing_docs())
        rc, out = run(tmp)
        report("no notes/ dir: the operational scope is empty", _operational(tmp) == [])
        report("and the verdict still passes", rc == 0)
        report(
            "and it says NOT CHECKED rather than passing quietly",
            any("NOT CHECKED" in x for x in out),
        )

    #      PRESENT and agreeing: discovered, counted, silent. `git ls-files` must still not see
    #      it, or this case proves nothing about the second scope.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        _fixture(
            tmp,
            _agreeing_docs(),
            ignored={
                f"{OPERATIONAL_DIR}/DEMO-RUNBOOK.md": "rc 0, **10/10 static + 5/5 live**\n",
                f"{OPERATIONAL_DIR}/OTHER.md": "no counts here\n",
            },
        )
        report(
            "the fixture's notes/ really is invisible to git ls-files",
            not any(x.startswith(OPERATIONAL_DIR + "/") for x in _surfaces(tmp)),
        )
        report(
            "and it IS discovered from the filesystem",
            _operational(tmp)
            == [
                f"{OPERATIONAL_DIR}/DEMO-RUNBOOK.md",
                f"{OPERATIONAL_DIR}/OTHER.md",
            ],
        )
        rc, out = run(tmp)
        report("an agreeing operational file passes", rc == 0)
        report(
            "and its claims are reported with a denominator",
            any(
                f"2 gitignored operational file(s) under {OPERATIONAL_DIR}/" in x
                for x in out
            ),
        )

    #      THE CONTROL THE SCOPE EXISTS FOR: every TRACKED surface correct, the gitignored one
    #      wrong. Before this scope that tree printed a clean pass, because no git-based
    #      derivation can name a file git does not track.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        _fixture(
            tmp,
            _agreeing_docs(),
            ignored={
                f"{OPERATIONAL_DIR}/DEMO-RUNBOOK.md": "rc 0, **9/9 static + 4 live claims**\n"
            },
        )
        rc, out = run(tmp)
        report("a wrong count in a GITIGNORED operational file FAILS", rc == 1)
        report(
            "and the failure names that file and its line",
            any(f"{OPERATIONAL_DIR}/DEMO-RUNBOOK.md:1" in x for x in out),
        )

    #      AND THE FLOOR DOES NOT COUNT IT. An operational file full of claims must not let a
    #      dead tracked scan pass the floor, which would hand back the false green.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        _fixture(
            tmp,
            {"a.md": "no counts here at all\n"},
            ignored={
                f"{OPERATIONAL_DIR}/DEMO-RUNBOOK.md": (
                    "10 static, 10 static, 10 static, 10 static, 10 static, 10 static, 10 static\n"
                )
            },
        )
        report("operational claims cannot satisfy the tracked floor", run(tmp)[0] == 2)

    # 11. MUTATION CONTROL. Disable the comparison in a copy of this file, drive the real gate
    #     at a planted disagreement, and require the verdict to flip. Without this, every case
    #     above is consistent with a detector that never ran. The substitution is asserted so a
    #     stale anchor fails loudly instead of certifying an unmodified gate, and the
    #     replacement keeps the anchor's indentation so the mutant still compiles.
    src = Path(__file__).read_text(encoding="utf-8")
    anchor = "                    if got != want:"
    report("the mutation anchor is present in this file", anchor in src)
    if anchor in src:
        mutant_src = src.replace(anchor, "                    if False:", 1)
        report("the mutation changed the source", mutant_src != src)
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            mutant = tmp / "mutant.py"
            mutant.write_text(mutant_src, encoding="utf-8")
            fixture = tmp / "tree"
            fixture.mkdir()
            docs = _agreeing_docs(live="4")
            _fixture(fixture, docs)
            real_rc, _ = check(fixture)
            report("the planted disagreement fails the real gate", real_rc == 1)
            proc = subprocess.run(
                [sys.executable, str(mutant), "--root", str(fixture)],
                capture_output=True,
                text=True,
            )
            report("the mutant compiles and runs", "Traceback" not in proc.stderr)
            report("the mutant no longer detects it", proc.returncode == 0)

    for f in failures:
        print(f"  FAIL  {f}")
    print(f"selftest: {cases - len(failures)}/{cases}")
    return 0 if not failures else 3


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Bind stated claim counts to verify-proof.py."
    )
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument(
        "--root",
        default=None,
        help="check this tree instead of the script's own repo root",
    )
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    rc, lines = check(Path(args.root).resolve() if args.root else ROOT)
    for line in lines:
        print(line)
    return rc


if __name__ == "__main__":
    sys.exit(main())
