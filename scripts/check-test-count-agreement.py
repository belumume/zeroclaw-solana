#!/usr/bin/env python3
"""Bind every test count a tracked doc PUBLISHES to a number cargo actually prints.

WHY THIS EXISTS. `verify-output-ceiling-agreement.py` gates the BYTE figures, 9 of 9, and
nothing gated a TEST COUNT. Measured on 2026-08-20 against `origin/main`: QUICKSTART
published `127 tests` for `crates/solana-core` and `61 tests` for `x402-feed-gate` while
the suites print 150 and 77, README and TESTING repeated the 127, and
`plugins/x402-pay-build/README.md` published `57 host tests` against a real 70. Five wrong
figures on four judge-facing surfaces, every one of them on the ungated axis.

THE ASYMMETRY IS THE POINT, and it is the same one the plugin-count gate names. A count
that is DERIVED self-corrects when a test lands; a count that was TYPED is frozen at the
moment someone typed it. Adding a test is the most routine act in this repo and it
silently falsifies prose nothing checks. The figures above were correct when written,
which is exactly the property that makes them dangerous: nothing contradicts them.

WHAT IT ASSERTS, in one sentence: every integer a tracked doc presents as a test count
must be a number some cargo invocation in this repo actually produces.

IT IS KEYED ON THE INVARIANT, NOT ON A PHRASING, and that is deliberate rather than
incidental. A gate keyed to one sentence punishes the correct change: rewording
"# 127 tests, ~30s" into "the core suite runs 127 tests" would report the requirement as
newly failing, and the diff that turns it green would live in the gate. So the trigger is
the DENOMINATOR -- an integer denominated in `tests` -- and the verdict is set membership
against what the toolchain prints. Rephrasing the sentence around a correct number changes
nothing; a stale 127 fails in every phrasing, because no cargo invocation yields it. The
selftest pins both halves: one number in three different wordings, all passing, and one
wrong number in the same three wordings, all failing.

BOTH SIDES ARE DERIVED. Crates come from `git ls-files '*Cargo.toml'` filtered to real
`[package]` manifests, docs from `git ls-files '*.md'`, and the accepted numbers from
running the suites. This file holds no copy of any count. A gate carrying the expected
values would be a third surface drifting on its own schedule, which is the defect it
exists to catch wearing a different hat.

WHAT COUNTS AS ACCEPTED, per crate: every per-target figure the harness prints, and their
SUM. Both are legitimate things to publish -- `x402-feed-gate/README.md` quotes 77 (the
sum) and names its 30 and 47 parts in the same sentence, and `crates/solana-core` is
published as 150 while TESTING quotes its 23-property target alone.

ATTRIBUTION, strictest first, because a tighter attribution is a stricter check:
  1. a claim whose LINE names exactly one crate is checked against THAT crate;
  2. otherwise a claim inside `<crate>/README.md` is checked against that crate;
  3. otherwise it is checked against the union over every crate.
Rule 3 is the weakest and it is what caught `README.md`'s bare `# 127 tests, four suites`,
which names no crate. Naming two or more crates on one line falls back to the union rather
than guessing, because a cross-crate sentence is exactly where a guess would redden
correct prose.

`--test-threads=1` AND `--locked` ARE BOTH LOAD-BEARING. `--locked` makes this READ-ONLY
with respect to the tree: without it `cargo test` may rewrite Cargo.lock, and a checker
that edits the repo it is checking cannot be run safely beside other work. `--test-threads=1`
matches the sibling gate for the same anti-tearing reason -- interleaved harness output
yields FEWER parsed lines, and fewer lines means a smaller accepted set, which reddens a
correct doc rather than greening a wrong one, so the failure is loud but it is still wrong.

WHAT IT CANNOT DO, stated here because a gate described as coverage invites the prose
beside it to be deleted.
  - It cannot tell a figure's MEANING, only its value. Three crates print 23, so an
    unattributed `23 tests` passes whichever crate it meant. The union's size is printed
    on every run so that this ceiling is a number rather than a worry.
  - It does not detect a SINGULAR `1 test`. The plural is required because `cargo test`,
    `--test-threads=1` and `ZEROCLAW_DEVNET_PROOF=1 cargo test` are pervasive in these
    docs and every one of them puts a digit next to a singular `test`. A crate with
    exactly one test is the price; a gate that reddens on `--test-threads=1` is worse,
    because it gets routed around.
  - It reads the FIRST figure of a compound phrase. `77 gate tests, 30 lib + 47 bin`
    gates the 77 and lets the parts through.
  - Its scope is TRACKED docs. The gitignored always-loaded tier publishes test counts
    too, and is not covered here; `check-plugin-count-agreement.py` carries the machinery
    for that scope. `docs/DEMO-STORYBOARD.md` is deliberately frozen to an already
    recorded video and is outside this scope BY CONSTRUCTION rather than by exclusion,
    being untracked since aa29698.
  - It proves how many tests RAN, not that the right ones exist.
  - A suite that fails to build or fails outright is reported as NOT COMPARED, never
    folded into a pass.

COST, and why the shape of this gate bounds it. Cargo dominates the runtime, so the gate
runs the suites for the crates a doc actually makes a claim about, and reaches for the
rest only when some claim names no crate and the union is therefore needed. With no test
count published anywhere it runs cargo zero times. Set CARGO_TARGET_DIR to one shared path
before running it, so the common dependency tree compiles once rather than per crate.

  python3 scripts/check-test-count-agreement.py             # run the suites, compare
  python3 scripts/check-test-count-agreement.py --selftest  # controls, no cargo needed

Exit: 0 agree, 1 a published figure is not one the toolchain prints, 2 could not check
(never a pass -- a comparison against nothing is not agreement), 3 a selftest control
failed. 3 is outside the gate's own vocabulary on purpose, so a failing control can never
be read as a disagreeing claim.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CANNOT_CHECK = 2
SELFTEST_FAILED = 3

CARGO_CMD = ["cargo", "test", "--locked", "--", "--test-threads=1"]

# A count DENOMINATED IN TESTS. Each guard was earned by a real line in this corpus:
#   `(?<![\w.,-])`      stops `127` being read out of `127.0.0.1:8899`, which appears five
#                       times in QUICKSTART and TESTING, and stops `024` out of `1,024`.
#   `(?!\d)`            stops the match backtracking to a shorter prefix of a longer number.
#   the optional word   admits `77 gate tests` and `57 host tests` without admitting
#                       arbitrary distance between the number and its unit.
#   plural `tests`      stops `ZEROCLAW_DEVNET_PROOF=1 cargo test` and `--test-threads=1`,
#                       where the intervening word would otherwise be `cargo`. See the
#                       docstring for the singular blind spot this buys.
CLAIM = re.compile(
    r"(?<![\w.,-])(\d[\d,]*)(?!\d)(?:[ \t]+[A-Za-z][\w-]*)?[ \t]+tests\b", re.IGNORECASE
)
# The harness's own summary line, which these READMEs embed verbatim as transcripts. It is
# the most direct claim of all: a pasted `test result:` is a quotation of the toolchain, so
# a stale one is a quotation of a toolchain that no longer exists. Anchored on `passed` so
# the `0 failed`, `0 ignored`, `0 measured` and `0 filtered out` of the same line are not
# read as counts.
RESULT = re.compile(r"test result:\s*\w+\.\s*(\d[\d,]*)\s+passed\b", re.IGNORECASE)
# What the harness prints per target. `ok` is not required: a FAILED target still reports a
# passed count, and rejecting the run happens on the exit code instead, where it belongs.
HARNESS = re.compile(r"^test result:\s*\w+\.\s*(\d+)\s+passed\b", re.MULTILINE)
PKG_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"', re.MULTILINE)


def _git(root: pathlib.Path, *args: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    return [line.strip() for line in out.split("\n") if line.strip()]


def crates(root: pathlib.Path) -> dict[str, str]:
    """Tracked crate directories mapped to their package name.

    A manifest with no `[package]` is a workspace root, which builds its members and has no
    tests of its own, so including it would add an empty accepted set under a name a doc
    might plausibly mention.
    """
    found: dict[str, str] = {}
    for rel in _git(root, "ls-files", "*Cargo.toml"):
        p = root / rel
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "[package]" not in text:
            continue
        head = text.split("[package]", 1)[1]
        m = PKG_NAME.search(head)
        if m:
            found[str(pathlib.PurePosixPath(rel).parent)] = m.group(1)
    return found


def docs(root: pathlib.Path) -> list[str]:
    return _git(root, "ls-files", "*.md")


def claims_in(text: str) -> list[tuple[int, int, str]]:
    """Every (line number, value, kind) this document presents as a test count."""
    out: list[tuple[int, int, str]] = []
    for lineno, line in enumerate(text.split("\n"), 1):
        for m in RESULT.finditer(line):
            out.append((lineno, int(m.group(1).replace(",", "")), "harness line"))
        for m in CLAIM.finditer(line):
            out.append((lineno, int(m.group(1).replace(",", "")), "prose"))
    return out


def _token(name: str) -> re.Pattern:
    # `/` is in the lookbehind so the package name `solana-core` does not also match inside
    # the directory `crates/solana-core`; the directory token covers that line already, and
    # counting both would still resolve to one crate but for the wrong reason.
    return re.compile(r"(?<![\w/-])" + re.escape(name) + r"(?![\w-])")


def attribute(doc_rel: str, line: str, known: dict[str, str]) -> str | None:
    """Which crate a claim is about, or None when it is about no single crate."""
    named = {
        d for d, n in known.items() if _token(d).search(line) or _token(n).search(line)
    }
    if len(named) == 1:
        return named.pop()
    if len(named) > 1:
        return None
    parent = str(pathlib.PurePosixPath(doc_rel).parent)
    if pathlib.PurePosixPath(doc_rel).name.lower() == "readme.md" and parent in known:
        return parent
    return None


def run_suite(rel: str, root: pathlib.Path) -> tuple[list[int], str | None]:
    """Run one crate's tests and return the per-target counts, or a reason it could not.

    The cargo-presence check lives HERE rather than in `check()` because `check()` is
    provider-agnostic by design: putting a toolchain probe in it would make `--selftest`,
    which injects its counts, refuse to run on a machine with no Rust. That machine is not
    hypothetical -- it is the toolchain-free `publish-gates` job, which is where the
    controls run.
    """
    if shutil.which("cargo") is None:
        return (
            [],
            "cargo is not on PATH, so the suite that PRODUCES these counts cannot run",
        )
    try:
        r = subprocess.run(
            CARGO_CMD,
            cwd=str(root / rel),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"cargo did not run ({exc})"
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or ["no output"]
        return [], f"the suite failed (rc={r.returncode}): {tail[0][:90]}"
    counts = [int(x) for x in HARNESS.findall((r.stdout or "") + (r.stderr or ""))]
    if not counts:
        return [], "the suite printed no `test result:` line, so nothing was measured"
    return counts, None


def accepted(counts: list[int]) -> set[int]:
    """Per-target figures and their sum. Both are honest things for a doc to publish."""
    return set(counts) | {sum(counts)}


def check(root: pathlib.Path, provider) -> tuple[int, list[str]]:
    """provider(rel) -> (per-target counts, reason it could not be measured)."""
    lines: list[str] = []
    known = crates(root)
    if not known:
        return CANNOT_CHECK, ["cannot check: no tracked [package] manifest was found"]
    all_docs = docs(root)
    if not all_docs:
        return CANNOT_CHECK, ["cannot check: no tracked .md document was found"]

    found: list[tuple[str, int, int, str, str | None]] = []
    for rel in all_docs:
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        by_line = text.split("\n")
        for lineno, value, kind in claims_in(text):
            line = by_line[lineno - 1]
            found.append((rel, lineno, value, kind, attribute(rel, line, known)))

    scanned_docs = {rel for rel, *_ in found}
    if not found:
        lines.append(
            f"0 test-count claim(s) found across {len(all_docs)} tracked doc(s); "
            f"{len(known)} crate(s) known, 0 suite(s) run"
        )
        return 0, lines

    # Cost is bounded by the CLAIM surface. The union is only needed when some claim names
    # no crate, and only then does every crate have to be run.
    needed = {c for *_, c in found if c}
    if any(c is None for *_, c in found):
        needed = set(known)

    measured: dict[str, list[int]] = {}
    broken: list[str] = []
    for rel in sorted(needed):
        counts, why = provider(rel)
        if why:
            broken.append(f"{rel}: {why}")
        else:
            measured[rel] = counts
    union: set[int] = set()
    for counts in measured.values():
        union |= accepted(counts)
    # THE UNION IS ONLY SOUND WHEN IT IS COMPLETE, and this is the half that decides whether
    # a broken crate voids everything or only its own claims. An unattributed claim is judged
    # by ABSENCE from the union, so a union missing a crate can report a correct figure as
    # absent -- a false FAILURE, which is the direction that gets a gate disabled. An
    # attributed claim is judged against its OWN crate and is unaffected by a sibling that
    # would not build. So a crate that fails costs exactly its own attributed claims plus
    # the whole unattributed class, and costs the rest of the run nothing.
    #
    # This is what lets the gate be useful on a host that cannot build every crate. Measured:
    # on this project's Windows host `differential-fuzz` and the e2e crates pull `openssl-sys`
    # through `solana-sdk`, which MinGW cannot satisfy, so a rule that voided the run on any
    # broken crate would make the gate permanently CANNOT_CHECK off the runner.
    union_complete = not broken and set(known) <= set(measured)

    failures: list[str] = []
    skipped: list[str] = []
    compared = 0
    for rel, lineno, value, kind, crate in sorted(found):
        where = f"  {rel}:{lineno}  {kind} claims {value} tests"
        if crate:
            if crate not in measured:
                skipped.append(f"{where}, but {crate} produced no counts")
                continue
            compared += 1
            if value not in accepted(measured[crate]):
                failures.append(
                    f"{where}, but {crate} prints {sorted(set(measured[crate]))} "
                    f"(sum {sum(measured[crate])})"
                )
        else:
            if not union_complete:
                skipped.append(
                    f"{where}, and names no crate, so only the union could judge it; "
                    f"{len(known) - len(measured)} crate(s) are missing from that union"
                )
                continue
            compared += 1
            if value not in union:
                failures.append(
                    f"{where}, but no crate in this repo prints it "
                    f"(union over {len(measured)} crate(s))"
                )

    lines.append(
        f"{len(found)} test-count claim(s) across {len(scanned_docs)} of {len(all_docs)} "
        f"tracked doc(s); {compared} compared, {len(skipped)} not compared; "
        f"{len(measured)} of {len(known)} crate(s) measured; "
        f"the accepted union holds {len(union)} distinct value(s)"
    )
    for b in broken:
        lines.append(f"  NOT MEASURED  {b}")
    for s in skipped:
        lines.append(f"  NOT COMPARED{s}")
    if compared == 0:
        lines.insert(
            0,
            "cannot check: no published test count could be compared against a suite. "
            "A comparison against nothing is not a pass.",
        )
        return CANNOT_CHECK, lines
    if failures:
        lines.append("FAIL  a published test count is not one the toolchain prints:")
        lines.extend(failures)
        return 1, lines
    lines.append("all published test counts are values the toolchain prints")
    return 0, lines


# ---------------------------------------------------------------------------------------
# selftest


def _fixture(tmp: pathlib.Path, docs_map: dict[str, str]) -> pathlib.Path:
    root = tmp
    (root / "fx").mkdir(parents=True, exist_ok=True)
    (root / "fx" / "Cargo.toml").write_text(
        '[package]\nname = "fx-crate"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    (root / "other").mkdir(parents=True, exist_ok=True)
    (root / "other" / "Cargo.toml").write_text(
        '[package]\nname = "other-crate"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    for rel, body in docs_map.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    for args in (
        ("init", "-q"),
        ("config", "user.email", "s@e.invalid"),
        ("config", "user.name", "selftest"),
        ("add", "-A"),
    ):
        subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
        )
    return root


# fx-crate prints 7 and 4, so 7, 4 and 11 are accepted and 12 is not.
# other-crate prints 5, so the union is {4, 5, 7, 11}.
FX_COUNTS = {"fx": [7, 4], "other": [5]}


def _provider(rel: str):
    return (FX_COUNTS.get(rel, []), None if rel in FX_COUNTS else "unknown crate")


def _run(docs_map: dict[str, str], provider=_provider) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as td:
        root = _fixture(pathlib.Path(td), docs_map)
        rc, lines = check(root, provider)
        return rc, "\n".join(lines)


def selftest() -> int:
    failures: list[str] = []
    cases = 0

    def report(label: str, cond: bool) -> None:
        nonlocal cases
        cases += 1
        if not cond:
            failures.append(label)

    # THE CONTROL PAIR. A clean run cannot be told from a detector that cannot detect, so a
    # correct figure must PASS in the same shape a wrong one FAILS.
    report(
        "correct crate total passes",
        _run({"fx/README.md": "runs 11 tests here\n"})[0] == 0,
    )
    report(
        "planted wrong total fails",
        _run({"fx/README.md": "runs 12 tests here\n"})[0] == 1,
    )
    report(
        "a per-target figure passes",
        _run({"fx/README.md": "runs 7 tests here\n"})[0] == 0,
    )
    report(
        "a figure from the OTHER crate fails when attributed",
        _run({"fx/README.md": "runs 5 tests here\n"})[0] == 1,
    )

    # WORDING-AGNOSTICISM, pinned in both directions. This is the property the gate is FOR,
    # so it is asserted rather than argued: three phrasings of one number, all passing, and
    # the same three phrasings of a wrong number, all failing. A gate keyed to a sentence
    # would pass some of these and fail others.
    wordings = (
        "cargo test --locked   # 11 tests, ~30s, no network\n",
        "The suite in `fx` runs 11 tests today.\n",
        "running 11 tests\n",
    )
    for i, w in enumerate(wordings):
        report(
            f"wording {i} of a correct number passes", _run({"fx/README.md": w})[0] == 0
        )
        bad = w.replace("11", "12")
        report(
            f"wording {i} of a wrong number fails", _run({"fx/README.md": bad})[0] == 1
        )

    # The embedded harness transcript is a quotation of the toolchain and is gated as one.
    report(
        "a stale pasted harness line fails",
        _run({"fx/README.md": "test result: ok. 12 passed; 0 failed; 0 ignored\n"})[0]
        == 1,
    )
    report(
        "a current pasted harness line passes",
        _run({"fx/README.md": "test result: ok. 7 passed; 0 failed; 0 ignored\n"})[0]
        == 0,
    )
    report(
        "the 0 failed of a harness line is not read as a count",
        "0 tests"
        not in _run({"fx/README.md": "test result: ok. 7 passed; 0 failed\n"})[1],
    )

    # ATTRIBUTION. Rule 1 beats rule 2, and rule 3 is the fallback that caught the bare
    # `# 127 tests, four suites` in the real corpus.
    report(
        "a line naming another crate is checked against THAT crate",
        _run({"fx/README.md": "the other-crate suite runs 5 tests\n"})[0] == 0,
    )
    report(
        "an unattributed figure in the union passes",
        _run({"docs/free.md": "the repo runs 5 tests in that layer\n"})[0] == 0,
    )
    report(
        "an unattributed figure outside the union fails",
        _run({"docs/free.md": "the repo runs 12 tests in that layer\n"})[0] == 1,
    )
    report(
        "two crates named on one line falls back to the union rather than guessing",
        _run({"docs/free.md": "fx-crate and other-crate together run 12 tests\n"})[0]
        == 1,
    )

    # MUST NOT FIRE. Every line below is real syntax from this repo's docs, and each one
    # puts a digit next to the word test. A gate that reddens on these gets routed around.
    quiet = (
        "run `cargo test --locked -- --nocapture --test-threads=1` to see it\n",
        "ZEROCLAW_DEVNET_PROOF=1 cargo test --test devnet_live -- --nocapture\n",
        "serves on 127.0.0.1 port 8899, self-refreshing\n",
        "cargo test --test properties   # 23 properties, 1024 cases each\n",
        "cd differential-fuzz && cargo run --release   # self-test, then 20k\n",
        "zeroclaw skills test solana-pay      # 3/3\n",
        "measured by a test that prints the figure: 1,355 bytes for the report\n",
        "`--test-threads=1` is load-bearing. The default parallel harness tears output\n",
    )
    for i, q in enumerate(quiet):
        rc, out = _run({"docs/free.md": q})
        report(f"must-not-fire {i}: {q.strip()[:44]}", rc == 0 and "claims" not in out)

    # A comparison against nothing is not a pass, in either shape.
    report(
        "a suite that will not run is CANNOT_CHECK, not a pass",
        _run({"fx/README.md": "runs 11 tests\n"}, lambda rel: ([], "boom"))[0]
        == CANNOT_CHECK,
    )

    # DEGRADATION, and the pair is the whole point: a crate that will not build must cost its
    # own claims and the unattributed class, and must cost an unrelated attributed claim
    # NOTHING. Without the first half the gate is dead on any host missing a toolchain; without
    # the second it reports a correct figure as absent from a union that was never complete.
    def half_broken(rel: str):
        return (
            ([], "openssl-sys will not build here")
            if rel == "other"
            else _provider(rel)
        )

    report(
        "a broken sibling does not void an attributed claim",
        _run({"fx/README.md": "runs 11 tests\n"}, half_broken)[0] == 0,
    )
    report(
        "and that attributed claim is still GATED, not skipped",
        _run({"fx/README.md": "runs 12 tests\n"}, half_broken)[0] == 1,
    )
    rc, out = _run({"docs/free.md": "the layer runs 5 tests\n"}, half_broken)
    report(
        "an unattributed claim degrades to NOT COMPARED when the union is incomplete",
        rc == CANNOT_CHECK and "NOT COMPARED" in out,
    )
    rc, out = _run({"docs/free.md": "the layer runs 999 tests\n"}, half_broken)
    report(
        "and an incomplete union never manufactures a failure",
        rc == CANNOT_CHECK and "FAIL" not in out,
    )
    report(
        "the same figure with a complete union DOES fail",
        _run({"docs/free.md": "the layer runs 999 tests\n"})[0] == 1,
    )
    # The real provider's own preflight, driven directly. Going through `check()` here would
    # only re-test the branch above; what needs pinning is that `run_suite` REFUSES rather
    # than shelling out to a cargo that is not there.
    saved = shutil.which
    try:
        shutil.which = lambda _n: None
        counts, why = run_suite("fx", pathlib.Path("."))
        report(
            "no cargo on PATH refuses",
            counts == [] and why is not None and "PATH" in why,
        )
    finally:
        shutil.which = saved
    # The over-correction half. A preflight that refused unconditionally would satisfy the
    # case above, so with cargo present the call must get PAST it and fail for some other
    # reason -- here a directory that is no crate at all.
    if shutil.which("cargo") is not None:
        with tempfile.TemporaryDirectory() as td:
            _, why = run_suite(".", pathlib.Path(td))
            report(
                "with cargo present the preflight is passed, not short-circuited",
                why is not None and "PATH" not in why,
            )

    # A DENOMINATOR, so a zero can be told from a broken read.
    rc, out = _run({"docs/free.md": "nothing numeric about the suite here\n"})
    report("no claims still prints a denominator", rc == 0 and "tracked doc(s)" in out)
    rc, out = _run({"fx/README.md": "runs 11 tests\n"})
    report(
        "a compared run prints its denominators",
        "of 2 crate(s)" in out and "of 1 tracked doc(s)" in out,
    )

    # The harness parser, against real cargo output rather than a paraphrase of it. The
    # counts below are what `crates/solana-core` printed on 2026-08-20.
    real = (
        "test result: ok. 119 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.55s\n"
        "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s\n"
        "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.58s\n"
        "test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.15s\n"
        "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
    )
    parsed = [int(x) for x in HARNESS.findall(real)]
    report(
        "real harness output parses to its five targets", parsed == [119, 3, 5, 23, 0]
    )
    report("and their sum is the published total", sum(parsed) == 150)
    report(
        "a FAILED target still yields its passed count, so rc decides, not the word ok",
        HARNESS.findall("test result: FAILED. 9 passed; 2 failed\n") == ["9"],
    )

    print(f"selftest: {cases - len(failures)}/{cases}")
    for f in failures:
        print(f"  FAIL  {f}")
    return SELFTEST_FAILED if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--root", default=str(ROOT))
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    root = pathlib.Path(args.root).resolve()
    rc, lines = check(root, lambda rel: run_suite(rel, root))
    for line in lines:
        print(line)
    return rc


if __name__ == "__main__":
    sys.exit(main())
