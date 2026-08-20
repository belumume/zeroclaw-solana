#!/usr/bin/env python3
"""Refuse an open PR whose merge would silently REVERT work already on main.

THE HAZARD, which no review and no size cap catches. GitHub displays a PR as a THREE-dot diff
(`main...branch`), computed from the merge base. When the branch forked before an earlier squash
merge, main is no longer an ancestor, and the three-dot view keeps reading as pure additions while
the TWO-dot content delta (`main branch`) deletes everything that landed in between and that the
branch happens to touch. Merging applies the two-dot delta.

A revert and an edit are the same shape in a diff, so a reviewer sees a plausible small change per
file. A per-file size cap is blind to it too: it measures MAGNITUDE, and this is a defect of
DIRECTION. One reverted line fits inside any budget.

THE ASSERTION, which needs no threshold: for each open PR, the two-dot deletion count must EQUAL
the three-dot deletion count. Any excess is exactly the work that merging would undo. Being behind
main is not itself a finding; a branch can be behind and revert nothing, and this reports that as
clean.

THE FIX when it fires is never to retarget. Merge `origin/main` INTO the branch, which makes main
an ancestor and removes the hazard by construction:

    git checkout -b tmp origin/<branch> && git merge origin/main
    git push origin tmp:<branch> && git checkout - && git branch -D tmp

(The throwaway branch is because agent worktrees may hold the branch checked out, and
`git worktree remove/prune` is forbidden in this repo.)

Exit 0 clean, 1 a real finding, 2 cannot-check (no network, no gh, not a repo). Cannot-check is
NOT a pass and says so, because a gate that reports clean when it never ran is worse than no gate.

Self-test: `--selftest` replays the two real pre-fix commits from 2026-08-20, when #109 and #110
each carried thousands of reverted lines, and requires the detector to FIRE on both. Without that,
a clean run today is indistinguishable from a detector that cannot detect.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

CANNOT_CHECK = 2

# Real pre-fix heads, kept as the positive control. Both were CLEAN/MERGEABLE on GitHub and both
# would have reverted work already on main. If either stops being reachable the self-test says so
# rather than passing quietly.
CONTROL_CASES = [
    ("0e1cf92", "fix/register-device-requires-device-signature (pre-fix head)"),
    ("c4650bb", "fix/pay-page-requires-reference (pre-fix head)"),
]


def run(args: list[str], check: bool = False) -> tuple[int, str]:
    p = subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if check and p.returncode != 0:
        raise RuntimeError(
            f"{' '.join(args)} -> rc={p.returncode}: {p.stderr.strip()[:200]}"
        )
    return p.returncode, p.stdout.strip()


def deletions(base: str, head: str, three_dot: bool) -> int | None:
    """Deleted-line count for one diff form, or None if the refs will not resolve."""
    sep = "..." if three_dot else ".."
    spec = f"{base}{sep}{head}" if three_dot else None
    args = (
        ["git", "diff", "--numstat", spec]
        if spec
        else ["git", "diff", "--numstat", base, head]
    )
    rc, out = run(args)
    if rc != 0:
        return None
    total = 0
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1].isdigit():
            total += int(parts[1])
    return total


def assess(base: str, head: str) -> dict | None:
    """Compare the two diff forms for one branch. None if the refs do not resolve."""
    three = deletions(base, head, three_dot=True)
    two = deletions(base, head, three_dot=False)
    if three is None or two is None:
        return None
    rc, _ = run(["git", "merge-base", "--is-ancestor", base, head])
    return {
        "head": head,
        "base_is_ancestor": rc == 0,
        "displayed_deletions": three,
        "real_deletions": two,
        "would_revert": max(0, two - three),
    }


def selftest() -> int:
    print("SELFTEST: the detector must FIRE on two real pre-fix heads.\n")
    run(["git", "fetch", "origin", "--quiet"])
    ok = True
    for sha, label in CONTROL_CASES:
        r = assess("origin/main", sha)
        if r is None:
            print(f"  UNRESOLVED  {sha}  {label}")
            print(
                "              the control commit is gone, so this proves nothing. NOT a pass."
            )
            ok = False
            continue
        fired = r["would_revert"] > 0
        print(
            f"  {'FIRED  ' if fired else 'SILENT '} {sha}  {label}\n"
            f"              displayed {r['displayed_deletions']} deletions, "
            f"real {r['real_deletions']}, would revert {r['would_revert']}"
        )
        if not fired:
            ok = False

    # Negative control: main against itself must be silent, or the detector fires on everything.
    r = assess("origin/main", "origin/main")
    neg_ok = r is not None and r["would_revert"] == 0
    print(
        f"  {'SILENT ' if neg_ok else 'FIRED  '} origin/main vs itself (must be SILENT)"
    )
    ok = ok and neg_ok

    print(
        "\nSELFTEST "
        + (
            "PASS: fires on both real cases and is silent on the negative control."
            if ok
            else "FAIL: the detector is not discriminating."
        )
    )
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--selftest", action="store_true", help="replay the real pre-fix cases"
    )
    ap.add_argument(
        "--pr",
        type=int,
        default=None,
        help="check ONLY this pull request. CI passes the PR under test, so a required "
        "check fails the branch actually at fault rather than reddening every open PR "
        "because a sibling happens to have a stale base.",
    )
    ap.add_argument("--base", default="origin/main")
    args = ap.parse_args()

    if run(["git", "rev-parse", "--git-dir"])[0] != 0:
        print("cannot check: not a git repository")
        return CANNOT_CHECK
    if args.selftest:
        return selftest()

    rc, _ = run(["gh", "--version"])
    if rc != 0:
        print("cannot check: gh is unavailable, so open PRs cannot be enumerated")
        return CANNOT_CHECK

    # A CI checkout is shallow by default, and on a shallow clone every branch ref fails to
    # resolve, so the walk would compare nothing and report a clean tree. Deepen first.
    if run(["git", "rev-parse", "--is-shallow-repository"])[1].strip() == "true":
        run(["git", "fetch", "--unshallow", "--quiet", "origin"])
    run(["git", "fetch", "origin", "--quiet"])
    if args.pr is not None:
        rc, out = run(["gh", "pr", "view", str(args.pr), "--json", "number,title,headRefName"])
        if rc != 0:
            print(f"cannot check: could not read PR #{args.pr} (network or auth)")
            return CANNOT_CHECK
        prs = [json.loads(out)] if out else []
    else:
        rc, out = run(
            ["gh", "pr", "list", "--state", "open", "--json", "number,title,headRefName"]
        )
        if rc != 0:
            print("cannot check: could not list open PRs (network or auth)")
            return CANNOT_CHECK
        prs = json.loads(out or "[]")
    if not prs:
        print("PASS  no pull request to check")
        return 0

    findings, checked = [], 0
    for pr in prs:
        r = assess(args.base, f"origin/{pr['headRefName']}")
        if r is None:
            print(f"  note: #{pr['number']} head ref did not resolve locally; skipped")
            continue
        checked += 1
        state = "ancestor" if r["base_is_ancestor"] else "STALE BASE"
        print(
            f"  #{pr['number']:<5} {state:<11} displayed {r['displayed_deletions']:>5} del, "
            f"real {r['real_deletions']:>5} del  {pr['headRefName']}"
        )
        if r["would_revert"] > 0:
            findings.append((pr, r))

    # Denominator, so a broken enumeration cannot read as a clean tree.
    print(f"\n  compared {checked} of {len(prs)} open PR(s)")
    if checked == 0:
        print("cannot check: no open PR head resolved locally")
        return CANNOT_CHECK

    if not findings:
        print("PASS  every open PR's real delta matches what it displays")
        return 0

    print(f"\n{len(findings)} PR(s) would REVERT work already on main:\n")
    for pr, r in findings:
        print(f"  #{pr['number']} {pr['title']}")
        print(
            f"    branch {pr['headRefName']} would delete {r['would_revert']} line(s) that main has"
        )
        print(
            f"    fix: git checkout -b tmp origin/{pr['headRefName']} && git merge origin/main"
        )
        print(
            f"         git push origin tmp:{pr['headRefName']} && git checkout - && git branch -D tmp"
        )
    print(
        "\nFAIL  merging any of the above applies its two-dot delta, reverting the excess."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
