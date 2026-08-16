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

WHAT COUNTS AS COVERED, in three forms because the repo addresses its crates in three ways. A crate
is covered when some workflow names its DIRECTORY (`working-directory: e2e-track-a`,
`manifest-path`, a cache `workspaces:` entry); or names the WORKSPACE ROOT it belongs to, since
building a workspace builds its members, which is how the two on-chain programs are reached; or
lists its basename as a bare MATRIX ENTRY (`- depin-attest` under `plugin:`), which is how the
plugin matrix addresses its nine.

Each form is bounded, and the bounds were earned by the selftest failing on the first run rather
than reasoned out in advance. Comment lines are stripped, because a plain substring match counted
`onchain` as covered on the strength of a COMMENT mentioning it. Path matches are bounded on both
sides, so `onchain` does not match `onchain-extras` while `crates/solana-core/Cargo.toml` still
matches. And only real `[workspace]` roots cover their children: treating any ancestor as covering
would let the bare string `plugins` cover every plugin at once and gut the check.

WHAT THIS DOES NOT CLAIM. That the build is meaningful, or that a referenced crate is compiled
rather than merely cached or formatted. It answers one question, "does any workflow name this
crate at all", which is the question that was answered NO four times.

EXIT CODES. 0 every tracked crate is referenced. 1 at least one is not. 2 could not check.

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
    return [d for d in dirs if not is_covered(d, wf, roots)]


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

    # The real corpus must be clean, which is the only case that can go red on a real regression.
    roots = workspace_roots()
    check(
        "the live tree has every tracked crate referenced", audit(wf, dirs, roots), []
    )
    check("discovery finds at least the floor", len(dirs) >= MIN_CRATES, True)

    # CONTROL. A crate nothing references must fire, or a clean result above proves nothing.
    check(
        "an unreferenced crate is reported",
        audit(wf, ["some/crate-nothing-builds"]),
        ["some/crate-nothing-builds"],
    )
    # Both coverage forms, so neither can rot silently into the other's job.
    check(
        "a directory named in a workflow counts as covered",
        audit("working-directory: e2e-track-a", ["e2e-track-a"]),
        [],
    )
    check(
        "a bare matrix entry counts as covered",
        audit("        plugin:\n          - depin-attest\n", ["plugins/depin-attest"]),
        [],
    )
    # OVER-CORRECTION CONTROL for the anchored matcher: the basename appearing in PROSE, rather
    # than as a list item, must NOT count. Without this the matcher could be loosened to a bare
    # substring and every case above would still pass.
    check(
        "a basename mentioned in prose does not count as covered",
        audit("# we should probably build onchain one day\n", ["onchain"]),
        ["onchain"],
    )
    check(
        "a basename inside a longer word does not count",
        audit("          - onchain-extras\n", ["onchain"]),
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

    # Workspace roots MUST be threaded here, not just in the selftest. They were not, and the two
    # paths disagreed: the selftest reported the tree clean while a live run reported two crates
    # uncovered. A suite exercising a call shape production never uses is a suite testing nothing.
    uncovered = audit(wf, dirs, workspace_roots())
    if uncovered:
        print(
            f"FAIL  {len(uncovered)} of {len(dirs)} tracked crate(s) are built by no workflow:\n"
        )
        for d in uncovered:
            print(f"  - {d}")
        print(
            "\n      A crate nothing compiles can break silently for weeks, and a repo-wide"
            "\n      formatter sweeping it reports success while it does. Add it to a workflow,"
            "\n      or drop the crate."
        )
        return 1

    print(
        f"all {len(dirs)} tracked crate(s) with a [package] are referenced by a workflow"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
