#!/usr/bin/env python3
"""Report where the two working roots disagree on an UNTRACKED internal document.

WHY A SECOND GATE RATHER THAN A WIDENING OF check-root-divergence.py. That gate reads
`git ls-files`, so it can only ever see TRACKED paths. The internal documents the two roots
share -- the hookify rules, the memory scope, the always-loaded entry points, the listing
captures -- are gitignored by design, so `git ls-files` never names them and no instrument in
this repo has ever compared them. 14 such files exist in both roots as this is written, 10 of them
identical and 4 declared below. THAT NUMBER MOVES, by hours rather than by months: one of the
fourteen was created while this file was being written. So read the count off the gate's own first
output line rather than from here. The population is enumerated at run time and never listed,
which is why a new shared document joins with no edit to this file.

THE POLARITY IS THE OPPOSITE OF THE TRACKED GATE'S, and that is the whole reason this is a
separate file rather than a third pass in that one. There, a difference is usually an unmerged
branch: it is expected, it self-resolves on merge, so the default is INFO and only declared
MUST_MATCH paths fail. Here there is no merge. An untracked file is not on any branch, so a
divergence between the roots will NEVER resolve itself and no future event will surface it. The
default is therefore FAIL, and the exceptions are declared below one at a time.

DECLARED DIVERGENCES ARE THE DESIGN, not a loosening. Some of these files are SUPPOSED to differ:
each root's always-loaded entry point must load THAT root's state, and a gate demanding they
match would be red on day one, which is the failure mode where a check gets learned around and
then ignored on the day it is finally right. Every entry in DECLARED carries the reason it earned
its place, and a declared path that turns out to AGREE is reported too, so a stale entry gets
retired rather than quietly protecting nothing.

SCOPE IS THE INTERNAL-DOCUMENT ZONE: root-level files, `docs/`, and `.claude/`. That is the zone
the snapshot tooling already derived for these documents, and it is not arbitrary. Widening it to
`.tools/` was considered and DECLINED with the measurement: the trunk holds ~190 scratch files
there against the other root's 14, exactly ONE name is shared (`fetch-listing.py`), and that one
is genuinely divergent -- so widening buys one real finding and ships a gate that is red the
moment it lands, for a fix that belongs in its own change. The divergence is recorded rather than
enforced. Revisit if `.tools/` ever stops being scratch.

ONLY PATHS PRESENT AND UNTRACKED IN BOTH ROOTS ARE COMPARED. A document that exists in one root
only is not drift, it is scope: the trunk carries ~219 internal files in this zone and the other
root ~59, and reporting the 250-odd non-overlapping ones would bury the handful that can actually
disagree. A path untracked in one root and TRACKED in the other is reported separately, because
that is how a shared document silently stops being shared.

THE OTHER ROOT IS OPTIONAL, and its absence is exit 2 rather than exit 0. A clone has one root, so
there is nothing to compare and this is not a pass; `check-all.py` reads exit 2 as `n/a` and keeps
it out of the pass count, which is the whole point of that code. Point it elsewhere with
ZC_OTHER_ROOT.

DELIBERATELY NOT WIRED INTO ci.yml, for the same reason as its sibling: a runner clones one root,
so it could only ever report not-applicable, and a step that can only skip is a green check
asserting nothing. Its control, `scripts/test_check_untracked_root_divergence.py`, builds its own
synthetic pair in a temp directory and IS in CI.

Exit 0 agree or all divergences declared, 1 an undeclared divergence, 2 could not check.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OTHER = pathlib.Path(
    os.environ.get("ZC_OTHER_ROOT", str(ROOT.parent / "zeroclaw-submission"))
)

# Root-level files plus these directories. See the docstring for why `.tools/` is not here.
ZONE_DIRS = ("docs", ".claude")

# Agent worktrees live under `.claude/` and are whole checkouts of this repo. Walking them would
# compare a worktree's tree against the other root's and report hundreds of phantom paths.
SKIP_PREFIXES = (".claude/worktrees/",)

# Below this the walk found too little to have come from a real pair of roots, so a clean result
# would mean nothing. Ten of the fourteen shared documents are stable agent config and a hardlink
# that change rarely, so a count this low means the walk broke rather than that they went away.
MIN_SHARED = 6

# DECLARED DIVERGENCES. Each entry is a path that is EXPECTED to differ, with the reason. A path
# not listed here that differs FAILS, because untracked files never merge and nothing else will
# ever surface the difference.
#
# `.claude/MANDATE.md` IS DELIBERATELY ABSENT FROM THIS LIST, and adding it would remove a
# detector rather than silence a false positive. The two roots share one inode for it, so while
# the hardlink is healthy it is byte-identical by construction and this gate is silent about it
# for free. If the link ever breaks the two paths drift apart and the gate reports it as an
# ordinary undeclared divergence, which makes this a second and independent guard on a failure
# whose only other check runs at SessionStart.
#
# THE BREAK IS INVISIBLE TO ANY CHEAP PRE-FILTER, which is why the comparison below is borrowed
# whole rather than short-circuited on size or mtime. An in-place append keeps the link; an atomic
# write-then-rename silently breaks it, and the Edit tool does the latter. In the measured break
# both paths held the SAME NUMBER OF BYTES with different content, so a size or mtime comparison
# reports healthy. Do not add one as an optimisation.
DECLARED = {
    "CLAUDE.local.md": (
        "Per-root always-loaded entry point. Each root imports ITS OWN goal, handoff and "
        "compliance ledger, so a session in either loads that root's state. Making them match "
        "would break whichever root lost its imports."
    ),
    ".claude/GOAL.md": (
        "Per-root goal. The trunk's is the whole-project goal; the other root's is scoped to the "
        "submission branch's work. never_idle resolves a goal nearest-scope-first, so each root's "
        "driver must see its own or it drives toward the wrong objective."
    ),
    "docs/listing-verbatim.json": (
        "Machine-captured snapshot of an external page, not a hand-written document. The two "
        "copies were captured 11 days apart against a schema that changed underneath them: "
        "measured, 45 of 45 SHARED keys are identical, upstream dropped 23 fields and added 1, "
        "so the listing text itself has not moved. Freshness is owned per root by the "
        "session-start tripwire that re-runs the capture, not by cross-root parity -- and any "
        "re-capture in either root re-diverges the pair on the header alone, which would make a "
        "byte gate here red by construction."
    ),
    "docs/LISTING-VERBATIM.md": (
        "The rendered half of the same capture, diverging for the same reason and by the same "
        "amount: the capture timestamp in its header and the one metadata line the schema change "
        "renamed. Its body is byte-identical across the roots."
    ),
}


def _load_same():
    """Reuse check-root-divergence.py's comparison rather than restating it.

    That function already encodes two corrections earned by running the sibling gate: line
    endings are not content under `core.autocrlf`, and JSON is compared parsed so a
    serialisation-only difference is not reported as data drift. Both apply identically here.
    Copying the ten lines would give this repo two definitions to keep in step, which is the
    duplication it has already had to build a separate agreement gate for.
    """
    sib = ROOT / "scripts" / "check-root-divergence.py"
    spec = importlib.util.spec_from_file_location("_zc_root_divergence", sib)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return getattr(mod, "same", None)


def tracked(root: pathlib.Path) -> set[str] | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return {p for p in out.split("\n") if p.strip()}


def zone_files(root: pathlib.Path) -> dict[str, pathlib.Path]:
    """Every file in the internal-document zone, keyed by its path relative to the root."""
    found: dict[str, pathlib.Path] = {}
    try:
        for p in root.iterdir():
            if p.is_file():
                found[p.name] = p
    except OSError:
        return found
    for d in ZONE_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            rel = p.relative_to(root).as_posix()
            if rel.startswith(SKIP_PREFIXES):
                continue
            if p.is_file():
                found[rel] = p
    return found


def main() -> int:
    if not (OTHER / ".git").exists():
        print(
            f"CANNOT CHECK  the second root is not present at {OTHER}; a clone has one root, so "
            f"there is nothing to compare. Set ZC_OTHER_ROOT to point elsewhere."
        )
        return 2

    same = _load_same()
    if same is None:
        print(
            "CANNOT CHECK  could not load the comparison from scripts/check-root-divergence.py; "
            "nothing was compared"
        )
        return 2

    mine_tracked, theirs_tracked = tracked(ROOT), tracked(OTHER)
    if mine_tracked is None or theirs_tracked is None:
        print("CANNOT CHECK  git could not list one of the roots; nothing was compared")
        return 2

    mine_all, theirs_all = zone_files(ROOT), zone_files(OTHER)
    mine_un = {k: v for k, v in mine_all.items() if k not in mine_tracked}
    theirs_un = {k: v for k, v in theirs_all.items() if k not in theirs_tracked}

    shared = sorted(set(mine_un) & set(theirs_un))
    if len(shared) < MIN_SHARED:
        print(
            f"CANNOT CHECK  only {len(shared)} shared untracked document(s) in the zone, expected "
            f"at least {MIN_SHARED}. The walk found too little to have come from a real pair of "
            f"roots, so a clean result here would mean nothing."
        )
        return 2

    # A shared document that became tracked on ONE side is no longer shared internal state, and
    # nothing else in this repo would say so. Not gating: committing a document is a legitimate
    # decision, and the other root's copy simply stops being the same object.
    now_tracked = sorted(
        (set(mine_un) & set(theirs_all) & theirs_tracked)
        | (set(theirs_un) & set(mine_all) & mine_tracked)
    )

    undeclared, declared_diff, declared_agree, unreadable = [], [], [], []
    for rel in shared:
        try:
            differs = not same(mine_un[rel], theirs_un[rel])
        except Exception as exc:
            unreadable.append(f"{rel} ({type(exc).__name__})")
            continue
        if differs:
            (declared_diff if rel in DECLARED else undeclared).append(rel)
        elif rel in DECLARED:
            declared_agree.append(rel)

    print(
        f"  {len(shared)} shared untracked document(s) compared, "
        f"{len(declared_diff) + len(undeclared)} diverge "
        f"({len(undeclared)} undeclared)"
    )
    if unreadable:
        print(f"  {len(unreadable)} could not be read: {', '.join(unreadable[:4])}")

    if now_tracked:
        print(
            f"  INFO  {len(now_tracked)} document(s) untracked in one root and TRACKED in the "
            f"other. Not gating, but they have stopped being shared internal state:"
        )
        for rel in now_tracked:
            print(f"          {rel}")

    if declared_diff:
        print(f"  INFO  {len(declared_diff)} declared divergence(s). Not gating:")
        for rel in declared_diff:
            print(f"          {rel}")
            print(f"            {DECLARED[rel]}")

    if declared_agree:
        print(
            f"  NOTE  {len(declared_agree)} declared divergence(s) currently AGREE. The entry may "
            f"be retirable, or the difference may simply not have been made yet:"
        )
        for rel in declared_agree:
            print(f"          {rel}")

    if undeclared:
        print("FAIL  an undeclared internal document differs between the roots:")
        for rel in undeclared:
            print(f"        {rel}")
        print(
            "      These files are untracked, so no merge will ever reconcile them and nothing"
        )
        print(
            "      else in this repo compares them. Sync the two copies, or add the path to"
        )
        print("      DECLARED with the reason it is supposed to differ.")
        return 1

    print("PASS  no undeclared internal document differs between the two roots")
    return 0


if __name__ == "__main__":
    sys.exit(main())
