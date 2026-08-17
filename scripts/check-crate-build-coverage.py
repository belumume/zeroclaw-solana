#!/usr/bin/env python3
"""Every tracked crate must be BUILT by some workflow, not merely formatted by one.

WHY THIS EXISTS. `e2e-track-a` stopped compiling on 2026-07-26, when `compose_report` gained a
parameter and a caller was left behind, and it was found on 2026-08-16. Twenty-one days, on a
reproduce path a stranger is pointed at, and the last touch to the broken file in between was a
repo-wide rustfmt pass that swept it, reformatted it and reported success.

That is the shape worth gating. A formatter gate iterating every tracked crate creates the
APPEARANCE of coverage over crates nothing compiles, which is worse than no coverage: a green check
against a crate reads as the crate being fine. Formatting is not compiling.

Enumerating the class rather than the instance found two more: `onchain/programs/zeroclaw-oracle`
and `onchain/programs/consumer-example`, the deployed on-chain programs, which QUICKSTART tells a
reader to `anchor build` and which no workflow referenced. They compiled, so nothing was broken;
they were one signature change away from the same silent breakage.

WHAT COUNTS AS COVERED. Two conditions, and the first is the one this gate exists for.

FIRST, THE JOB HAS TO COMPILE. A reference only counts when it sits in a workflow job that runs at
least one command producing an object file: `cargo build|test|check|clippy|run|bench`, `anchor
build|test`, `cargo-build-sbf`, `wasm-pack build`, `cross build`. Everything else a workflow does to
a crate reads it without compiling it. `cargo deny` walks a dependency graph, `cargo fmt` parses
source, `cargo audit` reads a lockfile, `cargo metadata` prints a manifest. A compile error survives
all four. The list is a positive one rather than a denylist on purpose: a tool nobody here
anticipated should default to NOT counting.

That condition was absent until 2026-08-17, and its absence reproduced this file's own founding
failure with a different tool in the role. `x402-feed-gate` counted as covered on the strength of a
single line: a matrix entry in the `supply-chain` job, which runs `cargo-deny-action`. No step
anywhere compiled it. Its 57 tests had never run on a runner, and neither had the build script
merged into it that same day. The gate reported it green and printed the word `referenced`, which is
what the summary line actually asserted while the docstring above claimed BUILT.

SECOND, THE REFERENCE ITSELF, in three forms because the repo addresses its crates in three ways. A
compiling job covers a crate when it names the crate's DIRECTORY (`working-directory: e2e-track-a`,
a cache `workspaces:` entry); or names the WORKSPACE ROOT it belongs to, since building a workspace
builds its members, which is how the two on-chain programs are reached; or lists its basename as a
bare MATRIX ENTRY (`- depin-attest` under `plugin:`), which is how the plugin matrix addresses its
nine.

Each form is bounded, and the bounds were earned by the selftest failing on the first run rather
than reasoned out in advance. Comment lines are stripped, because a plain substring match counted
`onchain` as covered on the strength of a COMMENT mentioning it. Path matches are bounded on both
sides, so `onchain` does not match `onchain-extras` while `crates/solana-core/Cargo.toml` still
matches. And only real `[workspace]` roots cover their children: treating any ancestor as covering
would let the bare string `plugins` cover every plugin at once and gut the check.

WHAT THIS DOES NOT CLAIM. That the compilation is meaningful, or that the crate a job names is the
crate that job compiles. Attribution is per JOB, not per STEP, so a job that compiled crate A while
merely denying crate B would lend coverage to both. No such job exists here, and the selftest pins
the real corpus in both directions, but the bound is real and belongs stated rather than implied.
Step-level attribution would have to resolve matrix interpolation per step, matching
`plugins/${{ matrix.plugin }}` against nine bare matrix values, which is a heavier instrument than
the defect it would catch.

EXIT CODES. 0 every tracked crate is built. 1 at least one is not. 2 could not check, which now
includes a job split that found fewer compiling jobs than the floor, since a broken split would
report every crate uncovered at once.

Run: python3 scripts/check-crate-build-coverage.py [--selftest]
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

# Below this the discovery walk is broken and a clean result would mean nothing. Same reasoning as
# check-all's floor and the fmt job's. 17 crates carried a [package] when this was written.
MIN_CRATES = 15
CANNOT_CHECK = 2

# Below this the JOB SPLIT is broken rather than the crate walk, and the two fail in opposite
# directions: a broken crate walk reports everything clean, a broken job split reports every crate
# uncovered at once. Every crate failing simultaneously is not a set of findings, so that is
# reported as a cannot-check instead.
#
# NO LIVE TOTALS IN THIS COMMENT, deliberately. The floor is a fixed bar well under the corpus, and
# the corpus figure belongs in the summary line, which reprints it every run. A comment naming
# today's counts is the stale denominator this whole file exists to catch, and the one that stood
# here was written a commit before a compiling job was added, so it shipped already wrong.
MIN_COMPILING_JOBS = 4

# A job running one of these produces an object file, so a compile error cannot survive it. The
# reasoning for the positive list, and for what is deliberately absent from it, is in the docstring.
COMPILING_COMMAND = re.compile(
    r"(?<![\w-])(?:"
    r"cargo(?:\s+\+\S+)?\s+(?:build|test|check|clippy|run|bench|nextest|rustc|miri)"
    r"|cargo-build-sbf"
    r"|anchor\s+(?:build|test)"
    r"|wasm-pack\s+build"
    r"|cross\s+(?:build|test|check)"
    r")(?![\w-])"
)

# A job key is the only thing in a workflow at exactly two spaces of indent under `jobs:`. A `run: |`
# block cannot be mistaken for one: its lines sit far deeper, and this requires the key to be alone
# on its line.
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_.\-]+):\s*$")


def tracked_manifests() -> list[str] | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "*Cargo.toml"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return [p for p in out.split("\n") if p.strip()]


def crate_dirs(manifests: list[str]) -> list[str]:
    """Directories of tracked manifests that declare a [package].

    A virtual workspace manifest has no crate to build, so it is not a finding.
    """
    dirs = []
    for rel in manifests:
        try:
            txt = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if re.search(r"(?m)^\s*\[package\]", txt):
            dirs.append(str(pathlib.PurePosixPath(rel).parent))
    return sorted(set(dirs))


def workflow_text() -> str | None:
    if not WORKFLOWS.is_dir():
        return None
    parts = [
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    ]
    return "\n".join(parts) if parts else None


def strip_comments(wf: str) -> str:
    """Drop YAML comment lines. A comment cannot build anything.

    This is not cosmetic. A plain substring match counted `onchain` as covered because a COMMENT
    mentioned it, which the selftest's prose control caught on the first run.
    """
    out = []
    for line in wf.split("\n"):
        s = line.lstrip()
        if s.startswith("#"):
            continue
        out.append(line.split(" #", 1)[0] if " #" in line else line)
    return "\n".join(out)


def job_bodies(wf_nc: str) -> list[tuple[str, str]]:
    """Every job in the workflow text, as (name, body).

    JOB is the right granularity, and a matrix is what settles it. `- depin-attest` and the
    `plugins/${{ matrix.plugin }}` that consumes it are only ever in the same scope at job level,
    because `strategy.matrix` is job-scoped and every step runs once per matrix value.

    SEVERAL `jobs:` MAPS, because the input is every workflow file concatenated. A top-level key
    closes the current map and the scan then looks for the next one, rather than stopping. Written
    the other way first, and it silently parsed ci.yml alone: `host-drift.yml`'s plugin build
    dropped out of the buildable corpus, and the summary's job total counted ci.yml's jobs rather
    than the corpus. Nothing went red, because the crates that job builds are covered elsewhere
    too. The DENOMINATOR in the summary line is the only thing that showed it, which is the
    argument for printing it. The selftest pins a string unique to a LATER file's compiling job,
    so the totals here do not have to be restated as jobs are added.
    """
    out: list[tuple[str, str]] = []
    name: str | None = None
    cur: list[str] = []
    in_jobs = False

    def close():
        nonlocal name, cur
        if name is not None:
            out.append((name, "\n".join(cur)))
        name, cur = None, []

    for line in wf_nc.split("\n"):
        if not in_jobs:
            in_jobs = bool(re.match(r"^jobs:\s*$", line))
            continue
        if line and not line[0].isspace():
            close()
            in_jobs = bool(re.match(r"^jobs:\s*$", line))
            continue
        m = JOB_KEY.match(line)
        if m:
            close()
            name, cur = m.group(1), []
            continue
        if name is not None:
            cur.append(line)
    close()
    return out


def compiling_jobs(wf: str) -> list[tuple[str, str]]:
    """The jobs that run at least one compiling command, comments already stripped."""
    return [
        (n, b) for n, b in job_bodies(strip_comments(wf)) if COMPILING_COMMAND.search(b)
    ]


def buildable_text(wf: str) -> str:
    """The only part of a workflow corpus that can turn source into an object file.

    Everything outside this is a job that reads crates without compiling them, and a reference
    there is what let a crate nothing built report green for as long as the deny matrix listed it.
    """
    return "\n".join(b for _, b in compiling_jobs(wf))


def names_path(wf_nc: str, path: str) -> bool:
    """Does the workflow reference this exact directory as a path token?

    Bounded on both sides so `onchain` does not match `onchain-extras`, while still matching
    `crates/solana-core/Cargo.toml`, where a slash legitimately follows.
    """
    return bool(re.search(rf"(?<![\w/-]){re.escape(path)}(?![\w-])", wf_nc))


def workspace_roots() -> set[str]:
    """Directories whose Cargo.toml declares a [workspace].

    Building a workspace builds its members, so a member is covered when its ROOT is named. Only
    real workspace roots count: treating any ancestor as covering would let the string `plugins`
    cover every plugin at once and gut the check.
    """
    roots = set()
    for rel in tracked_manifests() or []:
        try:
            txt = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if re.search(r"(?m)^\s*\[workspace\]", txt):
            roots.add(str(pathlib.PurePosixPath(rel).parent))
    return roots


def is_covered(crate_dir: str, wf: str, roots: set[str] | None = None) -> bool:
    wf_nc = strip_comments(wf)
    if names_path(wf_nc, crate_dir):
        return True
    for r in roots or ():
        if r != crate_dir and crate_dir.startswith(r + "/") and names_path(wf_nc, r):
            return True
    # A bare matrix entry, anchored to its own list item so a short basename cannot match prose.
    base = crate_dir.rsplit("/", 1)[-1]
    return bool(re.search(rf"(?m)^\s*-\s*{re.escape(base)}\s*$", wf_nc))


def audit(wf: str, dirs: list[str], roots: set[str] | None = None) -> list[str]:
    """Crates no compiling job names. Takes RAW workflow text, in both callers.

    The narrowing lives here rather than in `main`, so the selftest cannot exercise a looser
    pipeline than production does. That divergence is not hypothetical: workspace roots were once
    threaded in the selftest and not in `main`, and the two paths disagreed by two crates.
    """
    build = buildable_text(wf)
    return [d for d in dirs if not is_covered(d, build, roots)]


def selftest() -> int:
    wf = workflow_text()
    if wf is None:
        # Declared through a seam rather than allowed to crash: a selftest that dies on a missing
        # corpus is indistinguishable from one that never ran.
        print("selftest: cannot run, no workflows found under .github/workflows")
        return CANNOT_CHECK
    dirs = crate_dirs(tracked_manifests() or [])
    cases, failures = 0, []

    def check(name: str, got, want):
        nonlocal cases
        cases += 1
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    # Every synthetic case is a whole workflow rather than a fragment, because `audit` now begins
    # by splitting jobs. A bare fragment would carry no job at all and every case would trivially
    # report uncovered, which is a suite agreeing with itself rather than testing anything.
    def one_job(name: str, body: str) -> str:
        return f"jobs:\n  {name}:\n    runs-on: ubuntu-latest\n{body}"

    compiles = (
        "    steps:\n"
        "      - working-directory: e2e-track-a\n"
        "        run: cargo check --locked\n"
    )
    # The incident verbatim: the one line that made `x402-feed-gate` read as covered.
    deny_only = one_job(
        "supply-chain",
        "    strategy:\n"
        "      matrix:\n"
        "        manifest:\n"
        "          - x402-feed-gate\n"
        "    steps:\n"
        "      - uses: EmbarkStudios/cargo-deny-action@v2\n"
        "        with:\n"
        "          command: check advisories licenses sources\n"
        "          manifest-path: ${{ matrix.manifest }}/Cargo.toml\n",
    )

    # The real corpus must be clean, which is the only case that can go red on a real regression.
    roots = workspace_roots()
    check("the live tree has every tracked crate built", audit(wf, dirs, roots), [])
    check("discovery finds at least the floor", len(dirs) >= MIN_CRATES, True)
    check(
        "the job split finds at least the floor of compiling jobs",
        len(compiling_jobs(wf)) >= MIN_COMPILING_JOBS,
        True,
    )

    # REAL-CORPUS CALIBRATION, both directions, because the narrowing's own failure is silent. If
    # the job split degenerates to a no-op it returns the whole corpus, every case below still
    # passes, and the gate is quietly back to counting a deny matrix as a build.
    live_build = buildable_text(wf)
    check(
        "the deny job's text is excluded from the buildable corpus",
        "cargo-deny-action" in live_build,
        False,
    )
    check(
        "the plugin build's text is included in the buildable corpus",
        "cargo build --target wasm32-wasip2" in live_build,
        True,
    )
    # EVERY workflow file, not just the first. The corpus arrives concatenated, and a scan that
    # stops at the first top-level key after `jobs:` parses ci.yml and silently drops the rest.
    # This line is unique to host-drift.yml's compiling job.
    check(
        "a compiling job in a LATER workflow file is included too",
        "for m in plugins/*/manifest.toml" in live_build,
        True,
    )

    # CONTROL. A crate nothing references must fire, or a clean result above proves nothing.
    check(
        "an unreferenced crate is reported",
        audit(one_job("core", compiles), ["some/crate-nothing-builds"]),
        ["some/crate-nothing-builds"],
    )
    # Both coverage forms, so neither can rot silently into the other's job.
    check(
        "a directory named in a compiling job counts as covered",
        audit(one_job("core", compiles), ["e2e-track-a"]),
        [],
    )
    check(
        "a bare matrix entry in a compiling job counts as covered",
        audit(
            one_job(
                "plugins",
                "    strategy:\n"
                "      matrix:\n"
                "        plugin:\n"
                "          - depin-attest\n"
                "    steps:\n"
                "      - working-directory: plugins/${{ matrix.plugin }}\n"
                "        run: cargo build --release --locked\n",
            ),
            ["plugins/depin-attest"],
        ),
        [],
    )
    # THE NARROWING. A crate named only by a job that reads its dependency graph is NOT built.
    check(
        "a crate named only by a cargo-deny job is not covered",
        audit(deny_only, ["x402-feed-gate"]),
        ["x402-feed-gate"],
    )
    # OVER-CORRECTION CONTROL for that narrowing, differing from it in one feature only: the same
    # job, the same matrix entry, plus a step that compiles. Without this, the narrowing could have
    # disabled coverage for every matrix-addressed crate in the repo and the case above would still
    # pass. The live-tree case is the same control at corpus scale.
    check(
        "the same matrix entry beside a compiling step IS covered",
        audit(
            deny_only + "      - working-directory: x402-feed-gate\n"
            "        run: cargo test --locked\n",
            ["x402-feed-gate"],
        ),
        [],
    )
    # This file's founding scenario, now assertable: a formatter sweeping every tracked crate is
    # exactly what reported success over `e2e-track-a` for 21 days while it did not compile.
    check(
        "a crate named only by a rustfmt job is not covered",
        audit(
            one_job(
                "fmt",
                "    steps:\n"
                "      - working-directory: e2e-track-a\n"
                "        run: cargo fmt --check\n",
            ),
            ["e2e-track-a"],
        ),
        ["e2e-track-a"],
    )
    # OVER-CORRECTION CONTROL for the anchored matcher: the basename appearing in PROSE, rather
    # than as a list item, must NOT count. Without this the matcher could be loosened to a bare
    # substring and every case above would still pass.
    check(
        "a basename mentioned in prose does not count as covered",
        audit(
            one_job(
                "core", compiles + "      # we should probably build onchain one day\n"
            ),
            ["onchain"],
        ),
        ["onchain"],
    )
    check(
        "a basename inside a longer word does not count",
        audit(one_job("core", compiles + "          - onchain-extras\n"), ["onchain"]),
        ["onchain"],
    )

    for f in failures:
        print(f"  FAIL  {f}")
    print(f"selftest: {cases - len(failures)}/{cases}")
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    manifests = tracked_manifests()
    if manifests is None:
        print("cannot check: git could not list tracked files")
        return CANNOT_CHECK
    wf = workflow_text()
    if wf is None:
        print("cannot check: no workflows found under .github/workflows")
        return CANNOT_CHECK

    dirs = crate_dirs(manifests)
    if len(dirs) < MIN_CRATES:
        print(
            f"cannot check: discovery found {len(dirs)} crate(s), below the floor of "
            f"{MIN_CRATES}. The walk is broken, so a clean result would mean nothing."
        )
        return CANNOT_CHECK

    total_jobs = len(job_bodies(strip_comments(wf)))
    building = len(compiling_jobs(wf))
    if building < MIN_COMPILING_JOBS:
        print(
            f"cannot check: the job split found {building} compiling job(s) of {total_jobs}, "
            f"below the floor of {MIN_COMPILING_JOBS}. Every crate would report uncovered, "
            f"which is a broken split rather than 17 findings."
        )
        return CANNOT_CHECK

    # Workspace roots MUST be threaded here, not just in the selftest. They were not, and the two
    # paths disagreed: the selftest reported the tree clean while a live run reported two crates
    # uncovered. A suite exercising a call shape production never uses is a suite testing nothing.
    uncovered = audit(wf, dirs, workspace_roots())
    if uncovered:
        print(
            f"FAIL  {len(uncovered)} of {len(dirs)} tracked crate(s) are named by no workflow "
            f"job that compiles:\n"
        )
        for d in uncovered:
            print(f"  - {d}")
        print(
            "\n      Being named by a job that only READS a crate is not being built. cargo deny"
            "\n      walks a dependency graph, cargo fmt parses source, cargo audit reads a"
            "\n      lockfile; a compile error survives all three while they stay green. Add the"
            "\n      crate to a job that runs cargo build, test or check, or drop the crate."
        )
        return 1

    print(
        f"all {len(dirs)} tracked crate(s) with a [package] are named by one of the {building} "
        f"workflow job(s) that compile, of {total_jobs} job(s) total"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
