#!/usr/bin/env python3
"""Refuse an open PR whose merge would not apply cleanly or would rewind main's work.

WHAT A MERGE ACTUALLY DOES, which this gate got wrong for its whole life. Merging is a THREE-WAY
merge against the merge base, not the application of a two-dot delta. For a path the branch never
touched, the merge keeps main's side; for a path only the branch touched, it keeps the branch's;
where both touched the same region it CONFLICTS rather than silently picking one. So a branch being
behind main deletes nothing by itself.

WHY THAT MATTERED. This gate asserted `two-dot deletions == three-dot deletions` and called any
excess a revert. That difference is PURE BEHIND-NESS: it is a fact about how far main has moved and
carries no information about the branch. Feeding an older main tip in as the head -- an object with
zero commits of its own, which cannot revert anything by construction -- reproduces the gate's own
two published control figures exactly, 2547 and 9207 deletions, with the branches removed entirely.
Both historical cases merge CLEAN at every baseline. So the old assertion fired on every
behind branch and never on a revert, and both of its positive controls were false.

WHAT IS ASSERTED NOW, against the real merge result rather than a proxy for it. `git merge-tree
--write-tree <main> <head>` performs the three-way merge with no checkout and writes the resulting
tree. Three outcomes, and they are different facts:

  CONFLICT  merge-tree exits non-zero. The branch cannot be merged as-is. A finding.
  REWIND    a path in the merged tree carries a blob that main's own history has SUPERSEDED, so
            merging sets that file back to a version already replaced. A finding.
  BEHIND    main is not an ancestor of the head. A WARNING and never a refusal: CI green on a
            stale branch was measured against an old main, which is worth reporting and is not
            a reason to block.

REWIND IS REACHABLE AND WAS MEASURED, so this is not a hypothetical branch. A commit whose content
sets a file back to an earlier blob merges CLEAN and silently discards main's newer version; the
selftest plants exactly that and requires it to fire. Note the shape the old gate could never have
seen even in principle: when the branch already contains main, the merge base IS main, the two-dot
and three-dot diffs are identical, and the old assertion was silent by construction.

DELIBERATELY NOT A FINDING: the merged tree lacking a file main has. Measured, an ordinary PR that
removes a file produces exactly that, so flagging it is noise on every deletion. The dangerous
version of it is not silent anyway -- a branch deleting a file main modified after the fork
CONFLICTS, which the first outcome above already catches.

THE FIX when REWIND or CONFLICT fires. Merge `origin/main` INTO the branch, which makes main an
ancestor, surfaces any conflict as a conflict, and removes the hazard by construction:

    git checkout -b tmp origin/<branch> && git merge origin/main
    git push origin tmp:<branch> && git checkout - && git branch -D tmp

(The throwaway branch is because agent worktrees may hold the branch checked out, and
`git worktree remove/prune` is forbidden in this repo.)

Exit 0 clean, 1 a real finding, 2 cannot-check (no network, no gh, not a repo), 3 control-dead
(selftest only: an anchor no longer resolves, so the run proves nothing). Cannot-check is NOT a
pass and says so, because a gate that reports clean when it never ran is worse than no gate.

Self-test: `--selftest` is hermetic -- no network, and no dependence on today's main, so its
signal cannot drift. It PLANTS a revert and requires it to fire, plants a modify/delete and
requires a conflict, plants an unrelated history and requires that to read as failed rather than
as a conflict, and requires silence on three behind-but-clean branches and on the trivial
negative.
The two tagged commits are still controls, but for the opposite property they were bought for:
they must now be SILENT, because neither of them reverts anything.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

CANNOT_CHECK = 2
CONTROL_DEAD = 3

ZERO = "0" * 40

# Fixed ancestor pair for the planted controls. Both are ancestors of main, so main's own history
# keeps them alive and no tag is needed. The selftest ASSERTS the ancestry and the file choice
# rather than trusting these, and reports control-dead if either stops holding.
PLANT_OLD = "768d738"
PLANT_NEW = "8af55c9"

# Real branches that are BEHIND and revert nothing. They are the over-correction control: the old
# gate fired on both, and firing on either again means the rewrite has regressed to measuring
# behind-ness. Kept alive by tags control/base-freshness-register-device and
# control/base-freshness-pay-page; deleting either tag disarms this control.
SILENT_CASES = [
    ("8af55c9", "0e1cf92", "fix/register-device-requires-device-signature"),
    ("8af55c9", "c4650bb", "fix/pay-page-requires-reference"),
    (PLANT_NEW, PLANT_OLD, "an older main tip as head (zero commits of its own)"),
]

# A branch touching more paths than this gets its rewind scan capped, and the cap is REPORTED
# rather than silently applied, so a partial scan cannot read as a clean one.
MAX_PATHS = 400


def run_bytes(
    args: list[str], env_extra: dict | None = None, stdin: bytes | None = None
):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    p = subprocess.run(args, capture_output=True, env=env, input=stdin)
    return p.returncode, p.stdout, p.stderr


def run(args: list[str], env_extra: dict | None = None, stdin: bytes | None = None):
    rc, out, err = run_bytes(args, env_extra, stdin)
    return rc, out.decode("utf-8", "replace").strip()


OID = re.compile(r"^[0-9a-f]{40}$")


def merged_tree(base: str, head: str) -> tuple[str, str | None, str]:
    """The real three-way merge result: ("clean", tree, raw), ("conflict", None, raw), or
    ("failed", None, reason).

    ONLY THE FIRST LINE IS THE TREE. On a conflicting pair merge-tree still writes a tree and then
    prints the conflicted stages past the OID, so feeding the whole output to `git diff` fails
    naming a path nobody typed.

    THE FAILED STATE IS NOT A CONFLICT, and collapsing the two would be the worse error of the
    pair. A merge-tree that cannot run at all -- unrelated histories, a git too old for
    --write-tree -- would otherwise be reported as a content conflict, which is a false FAILURE,
    and a false failure on a required gate is what teaches people to wave the gate through.
    """
    rc, out, err = run_bytes(["git", "merge-tree", "--write-tree", base, head])
    text = out.decode("utf-8", "replace").strip()
    first = text.splitlines()[0].strip() if text else ""
    if not OID.match(first):
        reason = err.decode("utf-8", "replace").strip() or "merge-tree wrote no tree"
        return "failed", None, reason
    return ("clean" if rc == 0 else "conflict"), first, text


def conflicted_paths(raw: str) -> list[str]:
    seen = []
    for line in raw.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1] not in seen:
            seen.append(parts[1])
    return seen


def superseded_blobs(ref: str, path: str) -> set[str]:
    """Every blob this path has ever carried on `ref`'s history.

    --abbrev=40 is load-bearing: `--raw` abbreviates by default, and a 7-character comparison is
    both fragile across repo sizes and open to collision.
    """
    rc, out = run(
        [
            "git",
            "log",
            "--format=%H",
            "--raw",
            "--abbrev=40",
            "--no-renames",
            ref,
            "--",
            path,
        ]
    )
    blobs = set()
    if rc != 0:
        return blobs
    for line in out.splitlines():
        if not line.startswith(":"):
            continue
        fields = line.split()
        if len(fields) >= 4:
            blobs.add(fields[2])
            blobs.add(fields[3])
    blobs.discard(ZERO)
    return blobs


def rewinds(base: str, tree: str) -> tuple[list[tuple[str, str, str]], bool]:
    """Paths where the merged tree carries a blob main's history has already superseded."""
    rc, out = run(
        ["git", "diff", "--raw", "--abbrev=40", "--no-renames", base + "^{tree}", tree]
    )
    if rc != 0:
        return [], False
    changed = []
    for line in out.splitlines():
        if not line.startswith(":"):
            continue
        parts = line.split("\t")
        meta = parts[0].split()
        if len(parts) < 2 or len(meta) < 4:
            continue
        old_blob, new_blob, path = meta[2], meta[3], parts[1]
        # A merged tree that ADDS a path, or that lacks one main has, is not a rewind. The second
        # is an ordinary PR deletion; its dangerous form conflicts instead of merging silently.
        if old_blob == ZERO or new_blob == ZERO:
            continue
        changed.append((path, old_blob, new_blob))
    capped = len(changed) > MAX_PATHS
    found = []
    for path, main_blob, merged_blob in changed[:MAX_PATHS]:
        if merged_blob in superseded_blobs(base, path):
            found.append((path, main_blob, merged_blob))
    return found, capped


def _base_state(r: dict) -> str:
    """How the branch sits against the base, without letting a diverged branch read as behind."""
    if not r["behind"]:
        return "up to date"
    if r.get("ahead"):
        return f"behind {r['behind']}, ahead {r['ahead']}"
    return f"behind {r['behind']}"


def assess(base: str, head: str) -> dict | None:
    if run(["git", "rev-parse", "--verify", "--quiet", base + "^{commit}"])[0] != 0:
        return None
    if run(["git", "rev-parse", "--verify", "--quiet", head + "^{commit}"])[0] != 0:
        return None
    state, tree, raw = merged_tree(base, head)
    behind, ahead = 0, 0
    if run(["git", "merge-base", "--is-ancestor", base, head])[0] != 0:
        # Both sides, because "behind by N" alone reads as "only behind" and a DIVERGED branch
        # is the commoner shape here. Left is what base has and head lacks; right is the branch's
        # own commits.
        rc, out = run(
            ["git", "rev-list", "--left-right", "--count", f"{base}...{head}"]
        )
        parts = out.split()
        if rc == 0 and len(parts) == 2 and all(x.isdigit() for x in parts):
            behind, ahead = int(parts[0]), int(parts[1])
    if state == "failed":
        return {"failed": raw, "behind": behind, "ahead": ahead}
    if state == "conflict":
        return {
            "conflict": True,
            "paths": conflicted_paths(raw),
            "behind": behind,
            "ahead": ahead,
        }
    found, capped = rewinds(base, tree)
    return {
        "conflict": False,
        "behind": behind,
        "ahead": ahead,
        "rewinds": found,
        "capped": capped,
    }


# --------------------------------------------------------------------------- selftest plumbing


def _blob_of(ref: str, path: str) -> str | None:
    rc, out = run(["git", "rev-parse", "--verify", "--quiet", f"{ref}:{path}"])
    return out if rc == 0 else None


def _plant(base: str, path: str, blob: str | None, message: str) -> str | None:
    """Build a commit on `base` with one path set to `blob` (None deletes it).

    Pure plumbing on a throwaway index: no checkout, no branch, and the working tree -- which is
    shared with other sessions here -- is never touched. It writes loose objects that no ref
    points at, which git collects on its own.
    """
    index = tempfile.mktemp(suffix=".idx")
    env = {"GIT_INDEX_FILE": index}
    try:
        if run(["git", "read-tree", base], env)[0] != 0:
            return None
        if blob is None:
            run(["git", "update-index", "--force-remove", path], env)
        elif run(
            ["git", "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}"],
            env,
        )[0]:
            return None
        rc, tree = run(["git", "write-tree"], env)
        if rc != 0:
            return None
        env2 = dict(env)
        env2.update(
            {
                "GIT_AUTHOR_NAME": "selftest",
                "GIT_AUTHOR_EMAIL": "selftest@invalid",
                "GIT_COMMITTER_NAME": "selftest",
                "GIT_COMMITTER_EMAIL": "selftest@invalid",
                "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
            }
        )
        rc, commit = run(["git", "commit-tree", tree, "-p", base, "-m", message], env2)
        return commit if rc == 0 else None
    finally:
        if os.path.exists(index):
            os.unlink(index)


def _plant_orphan(message: str) -> str | None:
    """A commit with no parent, so it shares no history with anything."""
    index = tempfile.mktemp(suffix=".idx")
    env = {"GIT_INDEX_FILE": index}
    try:
        rc, blob = run(["git", "hash-object", "-w", "--stdin"], env, b"orphan\n")
        if rc != 0:
            return None
        if run(
            ["git", "update-index", "--add", "--cacheinfo", f"100644,{blob},ORPHAN"],
            env,
        )[0]:
            return None
        rc, tree = run(["git", "write-tree"], env)
        if rc != 0:
            return None
        env2 = dict(env)
        env2.update(
            {
                "GIT_AUTHOR_NAME": "selftest",
                "GIT_AUTHOR_EMAIL": "selftest@invalid",
                "GIT_COMMITTER_NAME": "selftest",
                "GIT_COMMITTER_EMAIL": "selftest@invalid",
                "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
            }
        )
        rc, commit = run(["git", "commit-tree", tree, "-m", message], env2)
        return commit if rc == 0 else None
    finally:
        if os.path.exists(index):
            os.unlink(index)


def _pick_rewindable_path(old: str, new: str) -> tuple[str | None, str | None]:
    """A path whose blob genuinely DIFFERS between the two anchors.

    Picking any other path makes the planted revert a no-op that the merge discards, and the
    control then passes having tested nothing.
    """
    rc, out = run(["git", "diff", "--name-only", "--no-renames", old, new])
    if rc != 0:
        return None, None
    for path in out.splitlines():
        old_blob, new_blob = _blob_of(old, path), _blob_of(new, path)
        if old_blob and new_blob and old_blob != new_blob:
            return path, old_blob
    return None, None


def selftest() -> int:
    print(
        "SELFTEST: hermetic. Plants a revert and a conflict, and requires silence on branches"
    )
    print("that are merely behind. No network, and no dependence on today's main.\n")

    for ref in (PLANT_OLD, PLANT_NEW):
        if run(["git", "rev-parse", "--verify", "--quiet", ref + "^{commit}"])[0] != 0:
            print(
                f"CONTROL DEAD: anchor {ref} does not resolve; this run proves nothing."
            )
            return CONTROL_DEAD
    if run(["git", "merge-base", "--is-ancestor", PLANT_OLD, PLANT_NEW])[0] != 0:
        print(f"CONTROL DEAD: {PLANT_OLD} is no longer an ancestor of {PLANT_NEW}.")
        return CONTROL_DEAD

    path, old_blob = _pick_rewindable_path(PLANT_OLD, PLANT_NEW)
    if not path:
        print(f"CONTROL DEAD: no path differs between {PLANT_OLD} and {PLANT_NEW}.")
        return CONTROL_DEAD
    print(
        f"  anchor pair {PLANT_OLD}..{PLANT_NEW}, rewinding {path} to its older blob\n"
    )

    ok = True

    # 1. A PLANTED REVERT MUST FIRE. Built on PLANT_NEW, so the merge base is PLANT_NEW and the
    #    merge is always clean: what is under test is the rewind detector, never the conflict path.
    planted = _plant(PLANT_NEW, path, old_blob, "planted revert")
    if planted is None:
        print("CONTROL DEAD: could not build the planted revert commit.")
        return CONTROL_DEAD
    r = assess(PLANT_NEW, planted)
    fired = bool(
        r and not r.get("conflict") and not r.get("failed") and r.get("rewinds")
    )
    print(
        f"  {'FIRED  ' if fired else 'SILENT '} planted revert of {path}  (must FIRE)"
    )
    ok = ok and fired

    # 2. A PLANTED CONFLICT MUST BE SEEN AS ONE, so that branch is proven live too. Deleting on
    #    the branch a path main modified after the fork is the modify/delete conflict, and it is
    #    deterministic where a content clobber is not: planting the NEWER blob on the older side
    #    leaves both sides carrying the identical change, which git merges trivially and in
    #    silence. That draft passed review and was caught only by running it.
    older_side = _plant(PLANT_OLD, path, None, "planted modify/delete conflict")
    conflicted = False
    if older_side:
        r2 = assess(PLANT_NEW, older_side)
        conflicted = bool(r2 and r2.get("conflict"))
    print(
        f"  {'CONFLICT' if conflicted else 'MISSED  '} planted delete of {path}  (must CONFLICT)"
    )
    ok = ok and conflicted

    # 3. BEHIND BUT CLEAN MUST BE SILENT. This is the property the rewrite exists to restore, and
    #    the first two entries are the very commits the old gate mis-reported as reverts.
    for base, head, label in SILENT_CASES:
        r = assess(base, head)
        if r is None:
            print(f"  CONTROL DEAD  {head} or {base} does not resolve  ({label})")
            return CONTROL_DEAD
        if r.get("failed"):
            print(
                f"  CONTROL DEAD  merge-tree could not run for {head}: {r['failed'][:60]}"
            )
            return CONTROL_DEAD
        if r.get("conflict"):
            print(f"  FIRED   {head} reports CONFLICT  ({label})  (must be SILENT)")
            ok = False
            continue
        silent = not r["rewinds"]
        print(
            f"  {'SILENT ' if silent else 'FIRED  '} {head} {_base_state(r)}, "
            f"{len(r['rewinds'])} rewind(s)  ({label})  (must be SILENT)"
        )
        ok = ok and silent

    # 4. AN UNCOMPUTABLE MERGE MUST REPORT FAILED, not conflict and not clean. Without this the
    #    two could be collapsed and a tooling failure would ship as a content finding, which is a
    #    false FAILURE -- the direction that gets a required gate waved through rather than fixed.
    orphan = _plant_orphan("planted unrelated history")
    r = assess(PLANT_NEW, orphan) if orphan else None
    failed_ok = bool(r and r.get("failed") and not r.get("conflict"))
    print(
        f"  {'FAILED  ' if failed_ok else 'MISREAD '} planted unrelated history  "
        "(must report FAILED, not CONFLICT)"
    )
    ok = ok and failed_ok

    # 5. The trivial negative. Cheap, and it catches a detector that fires on everything.
    r = assess(PLANT_NEW, PLANT_NEW)
    trivial = bool(
        r
        and not r.get("conflict")
        and not r.get("failed")
        and not r.get("rewinds")
        and r["behind"] == 0
    )
    print(
        f"  {'SILENT ' if trivial else 'FIRED  '} {PLANT_NEW} against itself  (must be SILENT)"
    )
    ok = ok and trivial

    print(
        "\nSELFTEST "
        + (
            "PASS: fires on a planted revert, sees a planted conflict, reads an\n"
            "         uncomputable merge as failed rather than as a conflict, and is\n"
            "         silent on three behind-but-clean branches and on the trivial negative."
            if ok
            else "FAIL: the detector is not discriminating."
        )
    )
    return 0 if ok else 1


# --------------------------------------------------------------------------------- live mode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--selftest", action="store_true", help="run the hermetic planted controls"
    )
    ap.add_argument(
        "--pr",
        type=int,
        default=None,
        help="check ONLY this pull request rather than every open one. NOTHING calls "
        "this today: the required gate here may not touch a live third party, and this "
        "reads the GitHub API. It exists so that a future per-PR check fails the branch "
        "actually at fault instead of reddening every open PR because a sibling has a "
        "stale base.",
    )
    ap.add_argument("--base", default="origin/main")
    args = ap.parse_args()

    if run(["git", "rev-parse", "--git-dir"])[0] != 0:
        print("cannot check: not a git repository")
        return CANNOT_CHECK
    if args.selftest:
        return selftest()

    if run(["gh", "--version"])[0] != 0:
        print("cannot check: gh is unavailable, so open PRs cannot be enumerated")
        return CANNOT_CHECK

    # A CI checkout is shallow by default, and on a shallow clone every branch ref fails to
    # resolve, so the walk would compare nothing and report a clean tree. Deepen first.
    if run(["git", "rev-parse", "--is-shallow-repository"])[1] == "true":
        run(["git", "fetch", "--unshallow", "--quiet", "origin"])
    run(["git", "fetch", "origin", "--quiet"])

    if args.pr is not None:
        rc, out = run(
            [
                "gh",
                "pr",
                "view",
                str(args.pr),
                "--json",
                "number,title,headRefName,state",
            ]
        )
        if rc != 0:
            print(f"cannot check: could not read PR #{args.pr} (network or auth)")
            return CANNOT_CHECK
        one = json.loads(out) if out else None
        if one and one.get("state") and one["state"] != "OPEN":
            print(f"PASS  PR #{args.pr} is {one['state']}, not open; nothing to merge")
            return 0
        prs = [one] if one else []
    else:
        rc, out = run(
            [
                "gh",
                "pr",
                "list",
                "--state",
                "open",
                "--json",
                "number,title,headRefName",
            ]
        )
        if rc != 0:
            print("cannot check: could not list open PRs (network or auth)")
            return CANNOT_CHECK
        prs = json.loads(out or "[]")
    if not prs:
        print("PASS  no pull request to check")
        return 0

    findings, behind_only, checked = [], [], 0
    for pr in prs:
        head = f"origin/{pr['headRefName']}"
        r = assess(args.base, head)
        if r is None:
            print(f"  note: #{pr['number']} head ref did not resolve locally; skipped")
            continue
        if r.get("failed"):
            # Not a conflict and not clean: the merge could not be computed at all, so this
            # PR is uncompared and must not be counted toward the denominator below.
            print(
                f"  note: #{pr['number']} merge-tree could not run: {r['failed'][:70]}"
            )
            continue
        checked += 1
        # The two signals are printed apart, because only one of them is a refusal.
        base_state = _base_state(r)
        if r["conflict"]:
            verdict = f"CONFLICT in {len(r['paths'])} path(s)"
        elif r["rewinds"]:
            verdict = f"WOULD REWIND {len(r['rewinds'])} file(s)"
        else:
            verdict = "merges clean"
        print(
            f"  #{pr['number']:<5} {base_state:<20} {verdict:<28} {pr['headRefName']}"
        )
        if r.get("capped"):
            print(
                f"         note: rewind scan capped at {MAX_PATHS} paths; this scan is partial"
            )
        if r["conflict"] or r.get("rewinds"):
            findings.append((pr, r))
        elif r["behind"]:
            behind_only.append((pr, r))

    # Denominator, so a broken enumeration cannot read as a clean tree.
    print(f"\n  compared {checked} of {len(prs)} open PR(s)")
    if checked == 0:
        print("cannot check: no open PR head resolved locally")
        return CANNOT_CHECK

    for pr, r in behind_only:
        print(
            f"  WARNING  #{pr['number']} is {_base_state(r)} against {args.base}. It merges clean "
            "and rewinds nothing, so this is not a refusal: it only means the green checks on it "
            "were measured against an older main."
        )

    if not findings:
        print("PASS  every open PR merges cleanly and rewinds nothing main has")
        return 0

    print(f"\n{len(findings)} PR(s) cannot be merged as they stand:\n")
    for pr, r in findings:
        print(f"  #{pr['number']} {pr['title']}")
        if r["conflict"]:
            print("    the three-way merge CONFLICTS in:")
            for path in r["paths"][:10]:
                print(f"      {path}")
        for path, main_blob, merged_blob in r.get("rewinds", [])[:10]:
            print(
                f"    {path} would be set back to {merged_blob[:8]}, a version main's history "
                f"already superseded (main has {main_blob[:8]})"
            )
        print(
            f"    fix: git checkout -b tmp origin/{pr['headRefName']} && git merge origin/main"
        )
        print(
            f"         git push origin tmp:{pr['headRefName']} && git checkout - && git branch -D tmp"
        )
    print(
        "\nFAIL  merging the above would conflict, or would rewind work already on main."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
