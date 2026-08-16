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

from make_invariants import git, git_ls, resolve_map, sha256_file  # noqa: E402

# Resolved EXACTLY as box_selfcheck.py:69 resolves it. If these two ever disagree the sync writes
# to a tree nothing verifies, which is the failure this whole script exists to remove.
ZC = Path(os.environ.get("ZEROCLAW_HOME", str(Path.home() / ".zeroclaw")))
TARGETS = HERE / "deploy-targets.json"

# THE THREE ARTIFACTS THE MAP CANNOT CARRY, each for a different structural reason, and every one
# of them established the box's IDENTITY rather than its content -- which is why all three could be
# stale while the manifest check compared 19 files and reported all match.
#
#   SHOP-INVARIANTS.json  the checker's INPUT. Generated rather than tracked, and `resolve_map`
#                         lists tracked files only, so no map entry can ever reach it. It was
#                         copied by hand, and `grep -rn 'SHOP-INVARIANTS' --include=*.md` returned
#                         ZERO hits repo-wide: the documented install path generates it into
#                         deploy/ and never moves it, so following QUICKSTART literally produced a
#                         box whose checker could not find its input.
#
#   DEPLOYED_SHA          the version label the served verdict carries and `scripts/verify-proof.py`
#                         prints as the provenance of a drift claim. It had NO PRODUCER: the only
#                         two references to it anywhere in the repo were both the reader. A
#                         hand-typed string verified by nothing, describing what a stranger is told
#                         is running. It is written here, by the step that actually copies the
#                         bytes, so it records a deploy that happened rather than a memory.
#
#   the unit FILES        every map `dst` is relative to ZEROCLAW_HOME and units install under
#                         ~/.config/systemd/user, so the map's grammar cannot address them at all.
#                         Measured: PR #74 edited zc-announce.service to add ZC_CHANNEL and no
#                         automated path carries that edit to the box, while the `services` check
#                         still reports "all healthy" because the OLD unit is loaded and active. A
#                         unit-file edit is invisible to every check we have.
#
# Overridable so the selftest can drive the real code paths against a temp tree instead of
# asserting on a reimplementation of them.
SYSTEMD_DIR = Path(
    os.environ.get("ZC_SYSTEMD_DIR", str(Path.home() / ".config" / "systemd" / "user"))
)
INVARIANTS_NAME = "SHOP-INVARIANTS.json"
DEPLOYED_SHA_NAME = "DEPLOYED_SHA"
UNIT_SUFFIXES = ("*.service", "*.timer")

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


def head_sha(root: Path) -> tuple[str, bool]:
    """(commit, dirty) for the checkout being deployed FROM."""
    _, out = git(root, "rev-parse", "HEAD")
    _, dirty = git(root, "status", "--porcelain")
    return out.strip() or "unknown", bool(dirty.strip())


def unit_pairs(root: Path) -> list[tuple[str, str]]:
    """(repo_rel, unit filename) for every tracked systemd unit under deploy/.

    DERIVED rather than declared, for the same reason the file map is: a unit added to git should
    appear here without anyone remembering to list it. deploy-targets.json's `units` key is a
    different thing and must not be reused -- it names units that must be RUNNING, most of which
    have no file in this repo at all. Measured at the time of writing, the two sets overlap by
    exactly one of six: the repo tracks zc-announce.{service,timer} and zc-selfcheck.{service,timer},
    while the checked list is zc-shop.service, zc-feed.{timer,service}, x402-feed-gate.service,
    x402-tunnel.service and zc-announce.timer. Deploying against the checked list would have tried
    to place five files that do not exist and skipped three that do.
    """
    out: list[tuple[str, str]] = []
    for rel in git_ls(root, *[f"deploy/{s}" for s in UNIT_SUFFIXES]):
        out.append((rel, Path(rel).name))
    return sorted(set(out))


def manifest_refusal(inv: Path, sha: str) -> str | None:
    """None when the manifest was generated from `sha`; otherwise why it must not be placed.

    THIS IS THE COHERENCE GUARD, and it is the one that makes the other three writes safe. Placing
    files from one commit beside a manifest generated from another produces a box whose checker
    compares fresh bytes against stale hashes, and the resulting verdict is not merely wrong, it is
    UNINTERPRETABLE: a DRIFTED report no longer distinguishes "the box is behind" from "the manifest
    is behind", which is exactly the ambiguity a drift gate exists to remove. Refusing here means
    the files, the hashes and the recorded sha on the box always describe one single commit.
    """
    if not inv.is_file():
        return (
            f"{inv.name} has not been generated. Run `python3 deploy/make_invariants.py` first; "
            "without it the checker has no input and reports that it cannot read its manifest."
        )
    try:
        got = json.loads(inv.read_text(encoding="utf-8")).get("repo_commit")
    except Exception as exc:
        return f"{inv.name} is not readable JSON ({exc}), so its provenance cannot be established"
    if got != sha:
        return (
            f"{inv.name} was generated from {str(got)[:12]} but this checkout is at {sha[:12]}, so "
            "placing both would leave the box comparing one commit's files against another's "
            "hashes. Re-run `python3 deploy/make_invariants.py`."
        )
    return None


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
        # Read DEFENSIVELY. This raised rather than reported when a mutation control gutted
        # classify: with nothing ever applied the backup is absent, and a suite that dies on an
        # exception cannot tell "the assertion failed" from "the harness could not start", which
        # is the one distinction a mutation control depends on.
        bak = box / "d" / f"diff.txt.bak-{stamp}"
        check(
            "the overwritten file's old bytes are preserved",
            bak.read_text(encoding="utf-8") if bak.is_file() else "(no backup written)",
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

    # ------------------------------------------------------------------------------------
    # THE COHERENCE GUARD. Every case here is paired with its opposite, because a refusal
    # function that refuses everything and one that refuses nothing both look correct from a
    # single-direction test, and only one of them is a guard.
    # ------------------------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        inv = tmp / INVARIANTS_NAME

        inv.write_text(json.dumps({"repo_commit": "a" * 40}), encoding="utf-8")
        check(
            "a manifest generated from THIS commit is accepted",
            manifest_refusal(inv, "a" * 40),
            None,
        )
        # CONTROL. Without this the case above proves only that the function returns None.
        got = manifest_refusal(inv, "b" * 40)
        check(
            "a manifest from a DIFFERENT commit is refused",
            bool(got) and "was generated from" in got,
            True,
        )
        check(
            "the refusal names both commits so the operator can see the split",
            bool(got) and "aaaaaaaaaaaa" in got and "bbbbbbbbbbbb" in got,
            True,
        )
        got = manifest_refusal(tmp / "absent.json", "a" * 40)
        check(
            "an ungenerated manifest is refused rather than skipped",
            bool(got) and "make_invariants" in got,
            True,
        )
        inv.write_text("{not json", encoding="utf-8")
        check(
            "an unparseable manifest is refused rather than treated as coherent",
            bool(manifest_refusal(inv, "a" * 40)),
            True,
        )
        # A manifest with NO repo_commit must refuse too: `.get` returning None against a real
        # sha is a mismatch, and reading that as "no claim, so fine" would accept any manifest
        # written by something other than the generator.
        inv.write_text(json.dumps({"files": {}}), encoding="utf-8")
        check(
            "a manifest with no repo_commit at all is refused",
            bool(manifest_refusal(inv, "a" * 40)),
            True,
        )

    # ------------------------------------------------------------------------------------
    # UNIT FILES. The copy half is exercised here; the systemctl half cannot be and is printed
    # rather than claimed. Driven against a systemd dir that is NOT the box root, because the
    # whole reason units were unreachable is that they live outside ZEROCLAW_HOME.
    # ------------------------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        repo, sysd = tmp / "repo", tmp / "sysd"
        (repo / "deploy").mkdir(parents=True)
        sysd.mkdir()
        (repo / "deploy" / "a.service").write_text("[Service]\nnew\n", encoding="utf-8")
        (repo / "deploy" / "a.timer").write_text("[Timer]\nsame\n", encoding="utf-8")
        (sysd / "a.service").write_text("[Service]\nold\n", encoding="utf-8")
        (sysd / "a.timer").write_text("[Timer]\nsame\n", encoding="utf-8")
        upairs = [("deploy/a.service", "a.service"), ("deploy/a.timer", "a.timer")]

        states = {u: s for _, u, s in classify(upairs, repo, sysd)}
        check("an edited unit file is DIFFERS", states["a.service"], DIFFERS)
        check("an unchanged unit file is SAME", states["a.timer"], SAME)

        for repo_rel, unit_rel, st in classify(upairs, repo, sysd):
            if st != SAME:
                apply_one(repo / repo_rel, sysd / unit_rel, "TEST")
        check(
            "applying converges every unit file",
            sorted({s for _, _, s in classify(upairs, repo, sysd)}),
            [SAME],
        )
        ubak = sysd / "a.service.bak-TEST"
        check(
            "the replaced unit's old bytes survive as a backup",
            ubak.read_text(encoding="utf-8")
            if ubak.is_file()
            else "(no backup written)",
            "[Service]\nold\n",
        )
        # CONTROL. Convergence above would be equally true of a classify that says SAME to
        # everything, which is the exact defect that let a unit edit sit unlanded while the
        # services check reported healthy.
        (repo / "deploy" / "a.service").write_text(
            "[Service]\nnewer\n", encoding="utf-8"
        )
        check(
            "a unit edited AFTER a clean sync is still detected",
            {u: s for _, u, s in classify(upairs, repo, sysd)}["a.service"],
            DIFFERS,
        )

    # ------------------------------------------------------------------------------------
    # unit_pairs derives from git rather than from deploy-targets.json's `units` key. Driven
    # against the REAL repo, because the bug being guarded is a set-membership one and a
    # synthetic tree cannot exhibit it.
    # ------------------------------------------------------------------------------------
    derived = {u for _, u in unit_pairs(ROOT)}
    check(
        "every tracked unit file is derived, none missed",
        derived,
        {
            "zc-announce.service",
            "zc-announce.timer",
            "zc-selfcheck.service",
            "zc-selfcheck.timer",
        },
    )
    # CONTROL for the set the deployer must NOT have used. deploy-targets.json's `units` names
    # what must be RUNNING; five of its six entries have no file in this repo, so deploying
    # against it would place nothing and skip three real files.
    try:
        checked = {
            u["unit"]
            for u in json.loads(TARGETS.read_text(encoding="utf-8")).get("units", [])
        }
        check(
            "the checked-units set is NOT the deployable set, so the two must stay distinct",
            len(derived & checked) < len(derived),
            True,
        )
    except Exception as exc:  # pragma: no cover - only if the map is unreadable
        failures.append(f"could not read the units key for the control: {exc}")
        cases += 1

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
    ap.add_argument(
        "--allow-dirty",
        action="store_true",
        help="deploy from a dirty tree, recording the sha with a -dirty suffix on the box",
    )
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

    # WHICH COMMIT IS BEING DEPLOYED. Everything below is anchored to this one answer, so that the
    # mapped files, the manifest's hashes and the sha recorded on the box cannot describe three
    # different states. A dirty tree has no honest answer: the bytes about to be copied are not any
    # commit, so the sha would be a claim the box cannot support. Refusing by default and recording
    # `-dirty` under an explicit flag follows the generator's own --allow-stale-binaries idiom:
    # the escape hatch turns the dishonesty into a FACT ON THE BOX rather than a silent lie.
    sha, dirty = head_sha(ROOT)
    if dirty and not args.allow_dirty:
        print(
            f"REFUSING: the working tree is dirty, so the bytes about to be copied are not "
            f"{sha[:12]} or any other commit, and {DEPLOYED_SHA_NAME} would name a commit the box "
            f"does not carry. Commit first, or pass --allow-dirty to record {sha[:12]}-dirty."
        )
        return 1
    recorded_sha = f"{sha}-dirty" if dirty else sha

    refusal = manifest_refusal(HERE / INVARIANTS_NAME, sha)
    if refusal:
        print(f"REFUSING: {refusal}")
        return 1

    # The manifest rides through the SAME classify/apply path as everything else rather than a
    # bespoke copy, so it inherits the backup, the read-back and the convergence check for free.
    file_pairs = list(pairs) + [(f"{HERE.name}/{INVARIANTS_NAME}", INVARIANTS_NAME)]
    rows = classify(file_pairs, ROOT, ZC)
    urows = classify(unit_pairs(ROOT), ROOT, SYSTEMD_DIR)
    todo = [r for r in rows if r[2] != SAME]
    utodo = [r for r in urows if r[2] != SAME]

    try:
        sha_on_box = (ZC / DEPLOYED_SHA_NAME).read_text(encoding="utf-8").strip()
    except Exception:
        sha_on_box = ""
    sha_todo = sha_on_box != recorded_sha

    print(f"deploying {recorded_sha[:12]}")
    print(f"map resolves {len(file_pairs)} file(s) under {ZC}")
    print(f"  {sum(1 for r in rows if r[2] == SAME)} already match")
    for repo_rel, box_rel, st in todo:
        print(f"  {st.upper():<13} {box_rel}   <- {repo_rel}")
    print(f"{len(urows)} tracked unit file(s) under {SYSTEMD_DIR}")
    for repo_rel, unit_rel, st in utodo:
        print(f"  {st.upper():<13} {unit_rel}   <- {repo_rel}")
    if sha_todo:
        print(
            f"  {'STALE' if sha_on_box else 'ABSENT':<13} {DEPLOYED_SHA_NAME}   "
            f"<- {sha_on_box or '(nothing)'}"
        )

    if not (todo or utodo or sha_todo):
        print("\nnothing to do: the box already matches this commit")
        return 0
    if not args.apply:
        print(
            f"\nDRY RUN. {len(todo)} mapped file(s), {len(utodo)} unit file(s) and "
            f"{int(sha_todo)} version marker would change. Re-run with --apply to write them."
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
    for repo_rel, unit_rel, _ in utodo:
        line = apply_one(ROOT / repo_rel, SYSTEMD_DIR / unit_rel, stamp)
        print(line)
        if "MISMATCH" in line:
            bad += 1

    # Written LAST, so the box never claims a commit whose files failed to land.
    if not bad:
        (ZC / DEPLOYED_SHA_NAME).write_text(recorded_sha + "\n", encoding="utf-8")
        print(f"  OK  {ZC / DEPLOYED_SHA_NAME} -> {recorded_sha}")

    after = [r for r in classify(file_pairs, ROOT, ZC) if r[2] != SAME]
    uafter = [r for r in classify(unit_pairs(ROOT), ROOT, SYSTEMD_DIR) if r[2] != SAME]
    if after or uafter or bad:
        print(f"\nFAIL  {len(after) + len(uafter)} file(s) still differ after the copy")
        return 1
    print(
        f"\nall {len(file_pairs)} mapped and {len(urows)} unit file(s) now match {sha[:12]}"
    )

    # NEVER CLAIM THE RELOAD RAN. Copying a unit file changes nothing until systemd re-reads it,
    # and a copied-but-unloaded unit is the worst state available: the file on disk says one thing
    # and the running daemon does another, which is precisely how a PR #74 unit edit could sit
    # unlanded while the services check reported "all healthy". These are printed rather than
    # executed because this script cannot verify a systemctl on a box it is not running on.
    if utodo:
        print("\nUnit files changed. They are INERT until systemd reloads them:")
        print("  systemctl --user daemon-reload")
        for _, unit_rel, _ in utodo:
            if unit_rel.endswith(".timer"):
                print(f"  systemctl --user enable --now {unit_rel}")
        print("  systemctl --user restart zc-announce.service   # if its unit changed")
    print("Verify from OUTSIDE rather than from this exit code:")
    print("  python3 deploy/box_selfcheck.py   then re-fetch /selfcheck")
    return 0


if __name__ == "__main__":
    sys.exit(main())
