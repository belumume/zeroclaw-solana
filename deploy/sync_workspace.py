#!/usr/bin/env python3
"""Copy the deployed files onto the box, using the SAME map the checker verifies against.

WHY THIS EXISTS. `deploy/deploy-targets.json` declares where each artifact belongs on the box.
`make_invariants.py` reads it to build the manifest, `box_selfcheck.py` verifies against that
manifest, and until this script landed NOTHING READ IT TO COPY ANYTHING. Re-derive:
`rg -l 'deploy-targets\\.json' --glob '*.{py,sh,md,yml}'` returned five files and every one of them
READ the map to check or to generate.

So the map said what should be on the box, the self-check confirmed whether it was, and files got
there by hand. Drift was therefore guaranteed rather than accidental, and invisible until the
self-check went live on 2026-08-16 and immediately reported twelve differing files. The proof it
had accumulated rather than appeared: `gen_qr.py` and `TEST.sh` had not changed in the repo since
before the box's previous deploy and drifted anyway, because only `pay_link.py` was ever copied.

IT IMPORTS `resolve_map` RATHER THAN REIMPLEMENTING IT, and that is the point. A second
implementation of the src-to-dst rules would be a second thing to keep in step, and the failure it
would produce is the worst kind: files copied where the checker does not look, so the deploy
reports success and the verdict stays red with no path between the two. One function, both callers.

DRY RUN BY DEFAULT. With no flag this changes nothing and prints what differs. `--apply` backs up
every file it is about to overwrite, with its sha, before writing.

WHAT IT DELIBERATELY DOES NOT DO. Decide whether the repo is right. A file differing on a live box
can be a deliberate local change, and this cannot tell that from staleness, so `--apply` is a
declaration by the operator that the repo is the source of truth for the mapped paths. It touches
nothing outside the map.

Run ON THE BOX, from a checkout of this repo:
    python3 deploy/sync_workspace.py                 # dry run
    python3 deploy/sync_workspace.py --apply
    python3 deploy/sync_workspace.py --selftest
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from make_invariants import resolve_map, sha256_file  # noqa: E402

# Resolved EXACTLY as box_selfcheck.py:69 resolves it. If these two ever disagree the sync writes
# to a tree nothing verifies, which is the failure this whole script exists to remove.
ZC = Path(os.environ.get("ZEROCLAW_HOME", str(Path.home() / ".zeroclaw")))
TARGETS = HERE / "deploy-targets.json"

# Below this the map resolved to almost nothing, which means a prefix was renamed rather than the
# tree being small. Same floor reasoning as check-all and the fmt job. 19 pairs when written.
MIN_PAIRS = 12
CANNOT_CHECK = 2

SAME, DIFFERS, ABSENT = "same", "differs", "absent-on-box"


def sha(p: Path) -> str:
    """The generator's own streaming hash, so the two never disagree on what a file hashes to."""
    return sha256_file(p)


def classify(
    pairs: list[tuple[str, str]], root: Path, zc: Path
) -> list[tuple[str, str, str]]:
    """(repo_rel, box_rel, state) for every mapped file."""
    out = []
    for repo_rel, box_rel in pairs:
        src, dst = root / repo_rel, zc / box_rel
        if not src.is_file():
            continue  # resolve_map lists tracked files; a missing one is the map's problem, not ours
        if not dst.is_file():
            out.append((repo_rel, box_rel, ABSENT))
        elif sha(src) == sha(dst):
            out.append((repo_rel, box_rel, SAME))
        else:
            out.append((repo_rel, box_rel, DIFFERS))
    return out


def apply_one(src: Path, dst: Path, stamp: str) -> str:
    """Copy src over dst, backing dst up first. Returns a line describing what happened."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    note = ""
    if dst.is_file():
        backup = dst.with_name(f"{dst.name}.bak-{stamp}")
        shutil.copy2(dst, backup)
        note = f" (was {sha(dst)[:12]}, backed up as {backup.name})"
    shutil.copyfile(src, dst)
    # Read the RESULT back rather than trusting copyfile's silence.
    got = sha(dst)
    ok = "OK" if got == sha(src) else "MISMATCH AFTER WRITE"
    return f"  {ok}  {dst} -> {got[:12]}{note}"


def selftest() -> int:
    """Drive classify and apply_one against a temporary tree, both directions."""
    cases, failures = 0, []

    def check(name, got, want):
        nonlocal cases
        cases += 1
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo, box = tmp / "repo", tmp / "box"
        (repo / "d").mkdir(parents=True)
        (box / "d").mkdir(parents=True)
        (repo / "d" / "same.txt").write_text("x", encoding="utf-8")
        (box / "d" / "same.txt").write_text("x", encoding="utf-8")
        (repo / "d" / "diff.txt").write_text("new", encoding="utf-8")
        (box / "d" / "diff.txt").write_text("old", encoding="utf-8")
        (repo / "d" / "new.txt").write_text("fresh", encoding="utf-8")
        pairs = [
            ("d/same.txt", "d/same.txt"),
            ("d/diff.txt", "d/diff.txt"),
            ("d/new.txt", "d/new.txt"),
        ]

        states = {b: s for _, b, s in classify(pairs, repo, box)}
        check("an identical file is SAME", states["d/same.txt"], SAME)
        check("a changed file is DIFFERS", states["d/diff.txt"], DIFFERS)
        check("a file missing on the box is ABSENT", states["d/new.txt"], ABSENT)

        # apply, then re-classify: everything must become SAME, and the old bytes must survive.
        stamp = "TEST"
        for repo_rel, box_rel, st in classify(pairs, repo, box):
            if st != SAME:
                apply_one(repo / repo_rel, box / box_rel, stamp)
        after = {b: s for _, b, s in classify(pairs, repo, box)}
        check("apply converges every file to SAME", sorted(set(after.values())), [SAME])
        check(
            "the overwritten file's old bytes are preserved",
            (box / "d" / f"diff.txt.bak-{stamp}").read_text(encoding="utf-8"),
            "old",
        )
        check(
            "a file absent on the box needs no backup",
            (box / "d" / f"new.txt.bak-{stamp}").exists(),
            False,
        )
        # CONTROL: with nothing copied, a differing file must still report DIFFERS, or the
        # convergence above would prove only that classify says SAME to everything.
        (repo / "d" / "diff.txt").write_text("newer still", encoding="utf-8")
        check(
            "a fresh divergence is detected after a successful sync",
            {b: s for _, b, s in classify(pairs, repo, box)}["d/diff.txt"],
            DIFFERS,
        )

    for f in failures:
        print(f"  FAIL  {f}")
    print(f"selftest: {cases - len(failures)}/{cases}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--apply", action="store_true", help="write the changes (default is a dry run)"
    )
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    if not TARGETS.is_file():
        print(f"cannot check: {TARGETS} is missing")
        return CANNOT_CHECK
    targets = json.loads(TARGETS.read_text(encoding="utf-8"))
    pairs, problems = resolve_map(ROOT, targets)
    if problems:
        print(
            f"REFUSING: the map has {len(problems)} problem(s), so it cannot be trusted to place files:"
        )
        for p in problems:
            print(f"  - {p}")
        return 1
    if len(pairs) < MIN_PAIRS:
        print(
            f"cannot check: the map resolved to {len(pairs)} file(s), below the floor of "
            f"{MIN_PAIRS}. A prefix was probably renamed, and copying against a broken map is "
            f"worse than not copying."
        )
        return CANNOT_CHECK
    # EXISTENCE IS NOT ENOUGH, measured on the dev laptop: `~/.zeroclaw` was there as an empty
    # leftover, so a bare is_dir() passed and `--apply` would have CREATED a convincing fake
    # deployment tree on a machine that is not the box. A real deployment carries the daemon's
    # config; an empty directory does not.
    if ZC.is_dir() and not (ZC / "config.toml").is_file():
        print(
            f"cannot check: {ZC} has no config.toml, so this is not a live deployment. Refusing "
            f"rather than populating a directory that only looks like one."
        )
        return CANNOT_CHECK
    if not ZC.is_dir():
        print(
            f"cannot check: {ZC} is not a directory, so this is not the box (or ZEROCLAW_HOME is unset)"
        )
        return CANNOT_CHECK

    rows = classify(pairs, ROOT, ZC)
    todo = [r for r in rows if r[2] != SAME]
    print(f"map resolves {len(pairs)} file(s) under {ZC}")
    print(f"  {sum(1 for r in rows if r[2] == SAME)} already match")
    for repo_rel, box_rel, st in todo:
        print(f"  {st.upper():<13} {box_rel}   <- {repo_rel}")

    if not todo:
        print("\nnothing to do: every mapped file on the box matches the repo")
        return 0
    if not args.apply:
        print(
            f"\nDRY RUN. {len(todo)} file(s) would change. Re-run with --apply to write them."
        )
        return 0

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    print(f"\n-- applying, backups suffixed .bak-{stamp}")
    bad = 0
    for repo_rel, box_rel, _ in todo:
        line = apply_one(ROOT / repo_rel, ZC / box_rel, stamp)
        print(line)
        if "MISMATCH" in line:
            bad += 1

    after = [r for r in classify(pairs, ROOT, ZC) if r[2] != SAME]
    if after or bad:
        print(f"\nFAIL  {len(after)} file(s) still differ after the copy")
        return 1
    print(f"\nall {len(pairs)} mapped file(s) now match the repo")
    print("Verify from OUTSIDE rather than from this exit code:")
    print("  python3 deploy/box_selfcheck.py   then re-fetch /selfcheck")
    return 0


if __name__ == "__main__":
    sys.exit(main())
