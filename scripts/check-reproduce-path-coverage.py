#!/usr/bin/env python3
"""Every reproduce command a document PUBLISHES must be exercised by some workflow.

WHY THIS EXISTS, and why it is not check-crate-build-coverage with a wider net.

`e2e-allowance` was referenced by zero of the seven workflows while four published documents
pointed a stranger at it. It was found by hand, by enumerating `git ls-files '*package.json'`.
The sibling gate could not have found it and never will: its docstring opens "Every tracked
crate must be BUILT", it enumerates tracked `Cargo.toml`, and a Node script is invisible to a
crate walk BY CONSTRUCTION. The fix that shipped for `e2e-allowance` was a hand-written CI step,
which closes one instance and leaves the enumerator that missed it unchanged.

The same enumeration, run once more, found `scripts/x402-validator` in exactly that state:
published as a reproduce command in six tracked documents, referenced by no workflow at all.
Finding the same shape twice by hand is the argument for doing it mechanically.

SO THE SUBJECT HERE IS THE PUBLISHED COMMAND, not the crate. A document that tells a reader to
run something is a promise that the something still runs, and the only thing that can keep that
promise is a job on a runner.

THE SEAM WITH regression-gate.yml's scope floor, which is the closest existing thing and is NOT
this. That step asks whether every tracked `scripts/check-*.py` GATE is invoked or declared. Its
subject is the gate inventory; this file's subject is the PUBLISHED COMMAND, whatever shape it
has and wherever it lives, which is how `e2e-allowance/demo.js` and a `.mjs` under
`scripts/x402-validator/` fall outside it. Where they overlap, this file defers: the two gates
that step declares are repeated verbatim in EXCLUDED below rather than re-decided here.

THE SEAM WITH check-crate-build-coverage, stated so neither gate silently drops a class.
Cargo invocations are ITS half and are deliberately skipped here: it already resolves workspace
roots, matrix entries and cache `workspaces:` keys, which this file does not model. This half is
everything a document tells you to run that is NOT cargo, addressed by its INTERPRETER:
`node`, `python`/`python3`, `bash`/`sh`. Together they cover every runnable form the docs use.

RESOLVING THE PATH IS THE HARD PART, because the published form is frequently relative. Most
references to the entry point this gate was built for are written
`cd scripts/x402-validator && ... node validate-challenge.mjs`, so a literal-path scan resolves
NOTHING for them and reports the corpus clean. Commands are therefore read in REGIONS -- a
fenced block, or a single line outside one -- with `cd` tracked left to right inside the region,
exactly as a shell would. A path is accepted when the cd-joined form is tracked, and falls back
to the literal form when that is tracked instead, because documents mix repo-root-relative paths
into a block that has already changed directory. Written without that fallback first, and it
silently lost eight real entry points to mis-resolution.

THE TWO-LEG CHECK, and the second leg is what stops this being a list of guesses.

Being named nowhere is ONE leg. A thing can still be reached TRANSITIVELY, through a harness or
meta-runner that CI invokes under the HARNESS's name, and that is the stronger wiring rather
than the weaker one: a harness that runs a pristine baseline before judging mutants proves the
gate can fail, where a direct step proves only that it passed. So a candidate is reported only
when BOTH legs fail: no workflow names it, AND nothing a workflow names reaches it.

REACHABILITY IS A CLOSURE, NOT ONE HOP, because the real chains here are longer than one. The
measured example: ci.yml runs `scripts/test_demo_preflight.py`, which drives
`scripts/demo-preflight.py`, which shells out to `sanitizer-microworld/check_page.py`. A one-hop
leg reports the last two as unexercised while CI has been running them all along. Measured, the
one-hop form produced seven such false findings, and a gate whose findings are mostly false gets
routed around.

THREE EDGE FORMS, each earned by a real reference in this tree rather than imagined:
  exec       `run([sys.executable, str(REPO / "scripts" / "check-all.py")])`
  literal    `SCRIPT = Path(__file__).with_name("pay_link.py")`   -- a path built, then run
  import     `import pre_export_gate as g`                        -- no extension at all

COMMENTS ARE STRIPPED FROM DRIVERS TOO, not only from workflows, and that single rule is what
keeps the broader edge forms honest. Measured: the loose version reported
`scripts/qr_live_server.py` as reached "via check-doc-links.py", whose only reference to it is a
COMMENT explaining what the check deliberately does not cover. A comment cannot run anything.

EXACT TOKENS, NEVER SUBSTRINGS. Filenames nest, so a substring matcher over-reports membership
and fails toward CLEAN. `scripts/thing.py.bak` must not cover `scripts/thing.py`.

DECLARED EXCLUSIONS carry a reason and are themselves audited. An exclusion naming a path that
is no longer published, or that has since been wired, is reported as STALE rather than silently
honoured -- otherwise the allowlist becomes the place findings go to die.

WHAT THIS DOES NOT CLAIM, stated because a gate described as coverage invites the prose beside
it to be deleted.

A TRANSITIVE EDGE IS EVIDENCE, NOT A VERDICT. Reachability here is static, and a runtime STUB
breaks a chain that every static reading says is live. The measured case is in this tree: ci.yml
runs `demo/test_pre_export_gate.py`, which imports `demo/pre_export_gate.py`, which shells out to
`scripts/check-all.py` -- and the test replaces that call with a lambda whose own message reads
"stubbed: check-all.py not re-run here". Every edge is real; the last one never fires. That is
why a declared exclusion outranks an inferred edge and only a DIRECT reference retires one.

IT ALSO CANNOT SAY THE EXERCISE IS MEANINGFUL. A job that runs a command's `--selftest` covers
its detector rather than its whole behaviour. Naming a command is where this gate stops.

EXIT CODES. 0 every published reproduce command is exercised. 1 at least one is not. 2 could not
check, which is a distinct state on purpose: an unreadable corpus reporting 0 findings is
byte-identical to a clean one, and only one of those is a measurement.

Run: python3 scripts/check-reproduce-path-coverage.py [--selftest]
"""

from __future__ import annotations

import pathlib
import posixpath
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
CANNOT_CHECK = 2

# Floors. Below either of these the WALK is broken, and a clean result would mean nothing rather
# than nothing being wrong. No live totals in these comments: the corpus figure belongs in the
# summary line, which reprints it every run, and a comment naming today's count is exactly the
# stale denominator this class of gate exists to catch.
MIN_DOCS = 20
MIN_ENTRY_POINTS = 15

# Interpreters that make a path RUNNABLE. `cargo` is deliberately absent; see the seam note above.
INTERPRETER = r"(?:node|python3?|bash|sh)"
SCRIPT_SUFFIX = r"(?:js|mjs|cjs|py|sh)"

# `node --check foo.js` puts flags between the interpreter and the path.
RUN = re.compile(
    r"(?<![\w./-])" + INTERPRETER + r"\s+(?:-[\w-]+\s+)*"
    r"((?:\.{1,2}/|[\w.\-]+/)*[\w.\-]+\." + SCRIPT_SUFFIX + r")(?![\w])"
)
CD = re.compile(r"(?<![\w./-])cd\s+((?:\.{1,2}/|[\w.\-]+/)*[\w.\-]+)")

# --- the three edge forms, one pattern each -----------------------------------------------
# TWO STRENGTHS, because a bare interpreter name means different things in different files.
#
# In a shell script or a workflow, `python3 foo.py` IS the invocation and there is nothing else
# to look for. Inside PYTHON source it is usually a STRING: `demo/take.py` is a demo-recording
# script whose lines include `"python demo/chain_history.py",` as data to be typed on screen.
# Measured, treating that as an invocation swept in two commands nothing runs, one of which
# needs a live RPC. So Python drivers must show a real call.
EXEC_STRONG = re.compile(
    r"(?:subprocess|Popen|check_call|check_output|sys\.executable|execFile|execSync"
    r"|spawn|runpy|\brun\s*\()"
)
EXEC_SHELL = re.compile(r"(?<![\w./-])" + INTERPRETER + r"\s")
SHELL_DRIVER = (".sh", ".yml", ".yaml")
BARE_PATH = re.compile(r"(?:[\w.\-]+/)*[\w.\-]+\." + SCRIPT_SUFFIX + r"(?![\w])")
QUOTED = re.compile(r"['\"]((?:[\w.\-]+/)*[\w.\-]+\." + SCRIPT_SUFFIX + r")['\"]")
IMPORTED = re.compile(r"^\s*(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import\s)")

# A QUOTED filename alone is far too weak, because this tree is full of files that carry
# filenames as DATA: an exclusion list entry `"demo/take.py",`, a fixture keyed by
# `{"scripts/qr_live_server.py": ...}`. Both were measured creating false edges. So a quoted name
# counts only where the line is visibly BUILDING A PATH or executing, and never where the line
# only READS the file. That last clause matters on its own: `(ROOT / "scripts" /
# "feed_heartbeat.py").read_text()` is a real dependency and is NOT an exercise of the published
# command, which is the distinction this gate is about.
# `ROOT` and `REPO` must be in a JOIN, not merely present. A bare `\bROOT\b` matched inside a
# fixture's payload string (`{"scripts/qr_live_server.py": ' ROOT = "/home/ubuntu/zc"'}`) and
# turned a test's own test data into an edge.
PATH_BUILD = re.compile(
    r"__file__|with_name|joinpath|os\.path\.join|\bPath\s*\(|\b(?:ROOT|REPO)\s*/"
)
READ_ONLY = re.compile(r"read_text|read_bytes|readlines|\bopen\s*\(|\.read\s*\(")

DOC_SUFFIX = (".md", ".markdown", ".txt", ".rst")
DRIVER_SUFFIX = (".py", ".sh", ".js", ".mjs", ".cjs", ".yml", ".yaml", ".toml")

# DYNAMIC DISPATCH IS DELIBERATELY NOT MODELLED, and that is a measurement rather than a gap.
#
# `check-all.py` discovers its gates with `git ls-files 'scripts/check-*.py'` and RUNS each.
# `check-correction-traces.py` uses `git ls-files '*.py'` and READS each. Those two lines are
# structurally identical -- same call, same argument shape -- and differ only in the pattern
# and the intent, so no regex separates them. Inferring the edge anyway failed toward CLEAN:
# the two scanners produced 121 edges each and swept in four commands nothing runs.
#
# A DECLARED dispatcher was then built and measured INERT: expanding check-all.py's pattern
# changed no verdict on this corpus, because everything it discovers is already reached by a
# named test harness, and check-all.py is itself declared never-run below, so its dispatch
# cannot contribute coverage at all. It was removed rather than kept as a mechanism nothing
# exercises. The gate inventory it would have modelled belongs to regression-gate.yml.

# DECLARED EXCLUSIONS. Each is a measured reason, not a judgement, and each is audited for
# staleness below. The bar is that the command CANNOT run on a runner, never that wiring it
# would be inconvenient.
EXCLUDED: dict[str, str] = {
    "demo/chain_history.py": (
        "derives its whole output from a live RPC response at run time, by design, so that the "
        "printed line cannot go stale. With the network removed there is nothing left to check."
    ),
    "scripts/consume_feed_once.py": (
        "signs and submits a real devnet transaction against the live ARM feed. It needs a "
        "funded key and a live cluster, which is the shape this repo keeps out of a publicly "
        "triggerable workflow."
    ),
    "scripts/feed_heartbeat.py": (
        "polls the deployed feed account over RPC and reports how long ago it last published. "
        "Its whole output is the live chain's state; offline it has nothing to report."
    ),
    "scripts/qr_live_server.py": (
        "starts a long-lived local HTTP server for a human to point a phone at. It does not "
        "terminate, so there is no exit code for a job to read."
    ),
    # These two are not this gate's judgement. regression-gate.yml's scope-floor step already
    # declares both, by name and with its own reasons, in the workflow that owns that decision.
    # Repeating the declaration here rather than inferring coverage keeps the two agreeing.
    "scripts/check-all.py": (
        "declared in regression-gate.yml as the local aggregate runner rather than a gate: "
        "running it on a runner would pull check-doc-links.py, which fetches external URLs, "
        "onto a required job. The gates it discovers are individually invoked by ci.yml."
    ),
    "scripts/check-config-drift.py": (
        "declared in regression-gate.yml: it compares against ~/.zeroclaw/config.toml, which no "
        "runner has, and self-reports exit 2 rather than passing vacuously."
    ),
}


def git(*args: str) -> list[str] | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return [p for p in out.split("\n") if p.strip()]


def read(rel: str) -> str:
    try:
        return (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def strip_comments(txt: str) -> str:
    """Drop whole-line comments, in both the YAML and the C-family form.

    A comment cannot run anything. This is not cosmetic in either direction: the sibling gate
    once counted a COMMENT mentioning `onchain` as coverage, and here the loose edge forms would
    count a comment explaining what a check does NOT cover as evidence that it does.
    """
    out = []
    for line in txt.split("\n"):
        s = line.lstrip()
        if s.startswith("#") or s.startswith("//"):
            continue
        out.append(line)
    return "\n".join(out)


def regions(txt: str) -> list[str]:
    """A fenced block is one region; every other line is its own.

    Scope matters because `cd` is sticky. Treating the whole document as one region would carry a
    `cd` from an unrelated block into every command below it; treating every line separately
    would lose the two-line form where the `cd` and the command are on consecutive lines.
    """
    out: list[str] = []
    cur: list[str] = []
    fenced = False
    for line in txt.split("\n"):
        if line.lstrip().startswith("```"):
            if fenced:
                out.append("\n".join(cur))
                cur = []
            fenced = not fenced
            continue
        if fenced:
            cur.append(line)
        else:
            out.append(line)
    if cur:
        out.append("\n".join(cur))
    return out


def commands_in(text: str, tracked: set[str]) -> set[str]:
    """Tracked scripts this ONE document tells a reader to run.

    Both the live walk and the selftest call this, so the suite cannot exercise a resolver
    production never uses. That divergence is not hypothetical: the sibling gate's selftest
    threaded workspace roots that `main` did not, and the two paths disagreed by two crates.
    """
    found: set[str] = set()
    for region in regions(text):
        events = [(m.start(), "cd", m.group(1)) for m in CD.finditer(region)]
        events += [(m.start(), "run", m.group(1)) for m in RUN.finditer(region)]
        cwd = ""
        for _, kind, val in sorted(events):
            if kind == "cd":
                cwd = posixpath.normpath(posixpath.join(cwd, val))
                if cwd.startswith("..") or cwd == ".":
                    cwd = ""
                continue
            literal = posixpath.normpath(val)
            joined = posixpath.normpath(posixpath.join(cwd, val)) if cwd else None
            cand = joined if (joined and joined in tracked) else literal
            if cand in tracked:
                found.add(cand)
    return found


def entry_points(docs: list[str], tracked: set[str]) -> dict[str, set[str]]:
    """Every published reproduce command, mapped to the documents that publish it."""
    found: dict[str, set[str]] = {}
    for doc in docs:
        for cmd in commands_in(read(doc), tracked):
            found.setdefault(cmd, set()).add(doc)
    return found


def token_named(haystack: str, token: str) -> bool:
    """An EXACT path token.

    Filenames nest, so a substring match fails toward CLEAN. The trailing bound rejects a longer
    EXTENSION (`scripts/thing.py.bak` must not cover `scripts/thing.py`) while still allowing a
    path that ends a sentence.
    """
    return bool(
        re.search(
            r"(?<![\w/.-])" + re.escape(token) + r"(?![\w-]|\.[A-Za-z0-9])", haystack
        )
    )


def resolve(token: str, driver: str, tracked: set[str]) -> str | None:
    """A reference inside a driver, resolved to a tracked path.

    Tried nearest-first: relative to the driver's own directory, which is what
    `Path(__file__).with_name(...)` means; then as a repo-root path; then by basename, and only
    when that basename is UNIQUE. An ambiguous basename resolving to several files would fail
    toward COVERED, which is the direction that hides findings.
    """
    here = posixpath.join(posixpath.dirname(driver), token)
    here = posixpath.normpath(here)
    if here in tracked:
        return here
    flat = posixpath.normpath(token)
    if flat in tracked:
        return flat
    base = posixpath.basename(token)
    hits = [t for t in tracked if posixpath.basename(t) == base]
    return hits[0] if len(hits) == 1 else None


def invoked(driver: str, text: str, tracked: set[str]) -> set[str]:
    """Tracked paths this driver actually RUNS, by any of the four edge forms."""
    out: set[str] = set()
    for line in strip_comments(text).split("\n"):
        if READ_ONLY.search(line):
            # Reading a file is a dependency on its SOURCE, never an exercise of its command.
            continue
        runs = bool(EXEC_STRONG.search(line)) or (
            driver.endswith(SHELL_DRIVER) and bool(EXEC_SHELL.search(line))
        )
        if runs or PATH_BUILD.search(line):
            for m in QUOTED.finditer(line):
                got = resolve(m.group(1), driver, tracked)
                if got:
                    out.add(got)
        if runs:
            for m in BARE_PATH.finditer(line):
                got = resolve(m.group(0), driver, tracked)
                if got:
                    out.add(got)
        m = IMPORTED.match(line)
        if m:
            stem = (m.group(1) or m.group(2)).split(".")[-1]
            hits = [t for t in tracked if posixpath.basename(t) == stem + ".py"]
            if len(hits) == 1:
                out.add(hits[0])
    out.discard(driver)
    return out


def reachable(wf_text: str, drivers: dict[str, str], tracked: set[str]) -> set[str]:
    """Everything CI reaches: the drivers a workflow names, plus their transitive closure."""
    wf = strip_comments(wf_text)
    # FULL PATHS ONLY. Seeding on a bare basename manufactured coverage: `regression-gate.yml`
    # carries a Python dict inside a `run:` block whose KEYS are gate basenames, one of which is
    # `"check-all.py"`, and that dict is the workflow declaring which gates it deliberately does
    # NOT run. Matching the basename there seeded the aggregate runner as if CI invoked it, and
    # everything it dispatches inherited the same false coverage.
    frontier = {p for p in drivers if token_named(wf, p)}
    seen = set(frontier)
    while frontier:
        nxt: set[str] = set()
        for p in frontier:
            for target in invoked(p, drivers.get(p, ""), tracked):
                if target not in seen:
                    seen.add(target)
                    nxt.add(target)
        frontier = nxt
    return seen


def classify(
    eps: dict[str, set[str]], wf_text: str, drivers: dict[str, str], tracked: set[str]
) -> tuple[list[str], list[str], list[str]]:
    """Split entry points into (named directly, reached transitively, unwired)."""
    wf = strip_comments(wf_text)
    reach = reachable(wf_text, drivers, tracked)
    direct, transitive, unwired = [], [], []
    for ep in sorted(eps):
        if token_named(wf, ep):
            direct.append(ep)
        elif ep in reach:
            transitive.append(ep)
        else:
            unwired.append(ep)
    return direct, transitive, unwired


def load_corpus() -> tuple[list[str], set[str], str, dict[str, str]] | None:
    tracked_list = git("ls-files")
    if tracked_list is None:
        return None
    tracked = {p for p in tracked_list if "node_modules/" not in p}
    docs = sorted(p for p in tracked if p.endswith(DOC_SUFFIX))
    if not WORKFLOWS.is_dir():
        return None
    wf_files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    if not wf_files:
        return None
    wf_text = "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in wf_files
    )
    drivers = {
        p: read(p)
        for p in tracked
        if p.endswith(DRIVER_SUFFIX) and not p.startswith(".github/workflows/")
    }
    return docs, tracked, wf_text, drivers


def one_job(body: str) -> str:
    return "jobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n" + body


def selftest() -> int:
    corpus = load_corpus()
    if corpus is None:
        print("selftest: cannot run, corpus unavailable (git or .github/workflows)")
        return CANNOT_CHECK
    docs, tracked, wf_text, drivers = corpus
    cases, failures = 0, []

    def check(name: str, got, want):
        nonlocal cases
        cases += 1
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    # THE LIVE CORPUS, which is the only case that can go red on a real regression.
    eps = entry_points(docs, tracked)
    _, live_transitive, unwired = classify(eps, wf_text, drivers, tracked)
    check(
        "the live tree has every published reproduce command exercised",
        [u for u in unwired if u not in EXCLUDED],
        [],
    )
    check("doc discovery clears its floor", len(docs) >= MIN_DOCS, True)
    check("entry-point discovery clears its floor", len(eps) >= MIN_ENTRY_POINTS, True)
    # REAL-CORPUS CALIBRATION for the resolver: the published form for the entry point this gate
    # was built for is cd-relative in every document, and a literal-path scan resolves none of it.
    check(
        "the cd-relative entry point resolves against the real corpus",
        "scripts/x402-validator/validate-challenge.mjs" in eps,
        True,
    )
    # REAL-CORPUS CALIBRATION for the closure. If it degenerated to naming-only, every one of
    # these would report unexercised and the gate would be a wall of false findings.
    check(
        "a multi-level chain through a driving harness is reached",
        "sanitizer-microworld/check_page.py" in live_transitive,
        True,
    )

    # RESOLUTION, on synthetic documents through the production resolver.
    fake = {"a/b/run.mjs", "top.py"}
    check(
        "a cd-relative command resolves against its region",
        commands_in("cd a/b && node run.mjs", fake),
        {"a/b/run.mjs"},
    )
    check(
        "the two-line form inside one fence resolves too",
        commands_in("```\ncd a/b\nnode run.mjs\n```", fake),
        {"a/b/run.mjs"},
    )
    check(
        "a repo-root path after a cd still resolves, via the literal fallback",
        commands_in("cd a/b && python3 top.py", fake),
        {"top.py"},
    )
    # OVER-CORRECTION CONTROL for that fallback: an untracked path must resolve to NOTHING, or
    # the fallback would manufacture an entry point out of any word ending in .py.
    check(
        "an untracked path is not an entry point",
        commands_in("python3 nowhere/absent.py", fake),
        set(),
    )
    # A `cd` is scoped to its region. Outside a fence every line stands alone, so this must not
    # resolve; without the scoping one stray cd would re-point every command below it.
    check(
        "a cd on its own line does not leak to the next unfenced line",
        commands_in("cd a/b\nnode run.mjs", fake),
        set(),
    )

    # LEG ONE.
    one = {"scripts/thing.py": {"README.md"}}
    tr = {"scripts/thing.py", "scripts/harness.py"}
    check(
        "a path named by a workflow is direct",
        classify(one, one_job("      - run: python3 scripts/thing.py\n"), {}, tr)[0],
        ["scripts/thing.py"],
    )
    check(
        "a path named nowhere is unwired",
        classify(one, one_job("      - run: echo hi\n"), {}, tr)[2],
        ["scripts/thing.py"],
    )
    # OVER-CORRECTION CONTROL for the token bound: a LONGER extension must not cover it. Without
    # this the matcher could be loosened to a bare `in` and every case above still passes.
    check(
        "a longer path containing this one does not cover it",
        classify(one, one_job("      - run: python3 scripts/thing.py.bak\n"), {}, tr)[
            2
        ],
        ["scripts/thing.py"],
    )
    # A COMMENT CANNOT RUN ANYTHING, on the workflow side.
    check(
        "a workflow comment naming the path does not cover it",
        classify(one, "jobs:\n  x:\n    # python3 scripts/thing.py one day\n", {}, tr)[
            2
        ],
        ["scripts/thing.py"],
    )

    # LEG TWO, one form per edge, each over the same named harness.
    named = one_job("      - run: python3 scripts/harness.py\n")
    for label, body in [
        ("exec", "subprocess.run([sys.executable, 'scripts/thing.py'])"),
        ("literal", "SCRIPT = Path(__file__).with_name('thing.py')"),
        ("import", "import thing"),
    ]:
        check(
            f"the {label} edge reaches it through a harness the workflow names",
            classify(one, named, {"scripts/harness.py": body}, tr)[1],
            ["scripts/thing.py"],
        )
    # THE SCANNER CONTROL, which is why dynamic dispatch is declared instead of inferred. The
    # harness globs and READS every .py; that must create no edge at all. Inferring an edge
    # from a bare `ls-files` call sweeps in commands that nothing actually runs.
    check(
        "a harness that globs and reads does not reach what it reads",
        classify(
            one,
            named,
            {"scripts/harness.py": "subprocess.run(['git', 'ls-files', '*.py'])"},
            tr,
        )[2],
        ["scripts/thing.py"],
    )
    # READING A FILE IS A DEPENDENCY ON ITS SOURCE, NOT AN EXERCISE OF ITS COMMAND. The measured
    # case: check-feed-decoders.py does `(ROOT / "scripts" / "feed_heartbeat.py").read_text()` to
    # derive byte offsets from that script's source. Every path-building signal is present and
    # the command is never run, so without this guard a source-reader lends coverage.
    check(
        "a harness that only READS the target's source does not reach it",
        classify(
            one,
            named,
            {"scripts/harness.py": "src = (ROOT / 'scripts' / 'thing.py').read_text()"},
            tr,
        )[2],
        ["scripts/thing.py"],
    )
    # OVER-CORRECTION CONTROL for that scanner case, differing in ONE feature: the same named
    # driver, running the target instead of globbing past it. Without this the scanner case
    # would pass on a leg-two that had stopped working entirely.
    check(
        "the same harness RUNNING it does reach it",
        classify(
            one,
            named,
            {"scripts/harness.py": "subprocess.run(['python3', 'scripts/thing.py'])"},
            tr,
        )[1],
        ["scripts/thing.py"],
    )
    # OVER-CORRECTION CONTROL, differing in ONE feature: the same named driver, MENTIONING the
    # target in a comment instead of running it. This is the measured false transitive.
    check(
        "a driver that only mentions it in a comment does not count",
        classify(one, named, {"scripts/harness.py": "# see thing.py"}, tr)[2],
        ["scripts/thing.py"],
    )
    # And a driver that invokes it but which NO workflow names cannot launder coverage either.
    check(
        "an invoking driver nothing names does not count",
        classify(
            one,
            one_job("      - run: echo hi\n"),
            {"scripts/harness.py": "subprocess.run(['python3', 'scripts/thing.py'])"},
            tr,
        )[2],
        ["scripts/thing.py"],
    )
    # THE CLOSURE ITSELF, which one hop cannot do: workflow -> a -> b -> thing.
    check(
        "a two-hop chain is still reached",
        classify(
            one,
            one_job("      - run: python3 scripts/a.py\n"),
            {
                "scripts/a.py": "subprocess.run(['python3', 'scripts/b.py'])",
                "scripts/b.py": "subprocess.run(['python3', 'scripts/thing.py'])",
            },
            {"scripts/thing.py", "scripts/a.py", "scripts/b.py"},
        )[1],
        ["scripts/thing.py"],
    )

    for f in failures:
        print(f"  FAIL  {f}")
    print(f"selftest: {cases - len(failures)}/{cases}")
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    corpus = load_corpus()
    if corpus is None:
        print(
            "cannot check: git could not list files, or no workflows under .github/workflows"
        )
        return CANNOT_CHECK
    docs, tracked, wf_text, drivers = corpus

    if len(docs) < MIN_DOCS:
        print(
            f"cannot check: found {len(docs)} document(s), below the floor of {MIN_DOCS}. "
            f"The walk is broken, so a clean result would mean nothing."
        )
        return CANNOT_CHECK

    eps = entry_points(docs, tracked)
    if len(eps) < MIN_ENTRY_POINTS:
        print(
            f"cannot check: resolved {len(eps)} published reproduce command(s) from "
            f"{len(docs)} document(s), below the floor of {MIN_ENTRY_POINTS}. Command "
            f"resolution is broken, so every entry point would read as absent at once."
        )
        return CANNOT_CHECK

    direct, transitive, unwired = classify(eps, wf_text, drivers, tracked)

    # THE ALLOWLIST IS AUDITED TOO. A declared exclusion that is no longer published, or that has
    # since been wired, is a finding: otherwise this dict is where findings go to die.
    # A DECLARATION OUTRANKS AN INFERRED EDGE, and only a DIRECT reference retires it.
    #
    # Static reachability cannot see a runtime stub, and this tree contains the exact case:
    # ci.yml runs demo/test_pre_export_gate.py, which imports demo/pre_export_gate.py, which
    # shells out to scripts/check-all.py -- and the test replaces that call with
    # `lambda: (0, "stubbed: check-all.py not re-run here")`. Every edge in that chain is real
    # and the last one never fires. So a transitive edge is EVIDENCE, never a verdict, and it
    # must not be allowed to retire a declaration a human wrote after checking. A direct `run:`
    # line is unambiguous and does retire one.
    stale = []
    for path in EXCLUDED:
        if path not in eps:
            stale.append(f"{path}: no document publishes it as a command any more")
        elif path in direct:
            stale.append(
                f"{path}: a workflow now names it directly, so the exclusion is obsolete"
            )

    findings = [u for u in unwired if u not in EXCLUDED]
    transitive = [t for t in transitive if t not in EXCLUDED]

    print(
        f"{len(eps)} published reproduce command(s) resolved from {len(docs)} tracked "
        f"document(s): {len(direct)} named directly by a workflow, {len(transitive)} reached "
        f"through a harness a workflow names, {len(EXCLUDED)} declared, "
        f"{len(findings)} unexercised"
    )
    for ep in transitive:
        print(f"  transitive  {ep}")

    if stale:
        print("\nFAIL  the declared-exclusion list has drifted from the corpus:\n")
        for s in stale:
            print(f"  - {s}")
        return 1

    if findings:
        print(
            f"\nFAIL  {len(findings)} of {len(eps)} published reproduce command(s) are "
            f"exercised by no workflow, directly or through a harness:\n"
        )
        for f in findings:
            print(f"  - {f}   published by: {', '.join(sorted(eps[f]))}")
        print(
            "\n      A document telling a reader to run something is a promise that it still"
            "\n      runs, and only a job on a runner can keep it. Add a step that exercises"
            "\n      the command, or declare it in EXCLUDED with the measured reason it cannot"
            "\n      run on a runner. Being named by a document is what is being audited here,"
            "\n      so it is not evidence of coverage."
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
