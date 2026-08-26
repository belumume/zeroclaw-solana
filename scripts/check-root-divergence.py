#!/usr/bin/env python3
"""Report where the two working roots disagree on a file they both track.

WHY A GATE AND NOT A POINTER, because the obvious fix is the wrong one and was measured to be.
The two roots track ~262 files in common, so a session working in either is looking at almost the
same tree and IGNORANCE IS NOT THE FAILURE. What bites is SILENT DIVERGENCE: a fix lands in one
copy and the other keeps serving the old content with nothing to indicate it. A pointer warns
about a problem nobody has; this reports the one everybody has.

NOT A HARD FAILURE BY DEFAULT, and that is deliberate. Two live branches SHOULD diverge while work
is in flight, so a gate that reddens on any difference would redden permanently and get ignored,
which is worse than no gate. It fails ONLY on paths declared MUST_MATCH: the proof bundles, the
gates, and the CI workflows, where a difference between roots means one of them is enforcing or
proving something the other is not.

SEMANTIC COMPARISON WHERE THE FORMAT ALLOWS IT. `docs/proof-bundle/mainnet-transactions.json`
differs by 42 bytes across the roots and is IDENTICAL DATA: three transactions each, parsed-equal.
A byte diff reports that as a divergent proof bundle, which is the most alarming thing this could
say and would be false. JSON is compared parsed; everything else by bytes.

THE OTHER ROOT IS OPTIONAL. A clone has one root, so its absence is a SKIP with a stated reason and
**exit 2**, never a failure and never a silent pass. Point it elsewhere with ZC_OTHER_ROOT.

That exit code was 0 until 2026-08-17, and the sentence above was already the right standard while
the code missed it: the PROSE said "not applicable rather than clean" and the EXIT CODE said pass.
`check-all.py` reserves 2 for could-not-check and reads everything else as a verdict, so on every
clone this gate was counted as a passing comparison having compared nothing. Found by running it
beside its untracked-file sibling in a fresh clone: identical condition, `rc=0` here and `rc=2`
there. Same class as the defect #77 removed from check-all's own summary line.

DELIBERATELY NOT WIRED INTO ci.yml, and the reason is that same optionality. A GitHub runner clones
exactly one root, so this would SKIP on every run: a step that can only ever skip is a green check
asserting nothing, which is the shape this repo has already had to remove twice. It is discovered by
`check-all.py` instead, which runs on a machine that has both roots. If the pair is ever mirrored
onto a runner, wiring it in becomes correct and this paragraph is the thing to revisit.

Its control, `scripts/test_check_root_divergence.py`, is NOT subject to that: it builds its own
synthetic pair of roots in a temp directory and is hermetic, so it belongs in CI even though the
gate itself does not.

Exit 0 agree or not-applicable, 1 a MUST_MATCH path diverged, 2 could not check.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OTHER = pathlib.Path(
    os.environ.get("ZC_OTHER_ROOT", str(ROOT.parent / "zeroclaw-submission"))
)

# A difference here means one root enforces, proves or ships something the other does not.
MUST_MATCH = (
    "docs/proof-bundle/",
    "scripts/check-",
    "scripts/verify_proof_offline.py",
    ".github/workflows/",
)

# Below this the intersection is too small to have come from a real pair of roots, so a clean
# result would mean nothing. Same reasoning as check-all's discovery floor.
MIN_SHARED = 150


def git_files(root: pathlib.Path) -> set[str] | None:
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


def same(a: pathlib.Path, b: pathlib.Path) -> bool:
    ab, bb = a.read_bytes(), b.read_bytes()
    if ab == bb:
        return True

    # LINE ENDINGS ARE NOT CONTENT, and this was found by running the gate rather than by
    # reasoning about it. `scripts/check-host-compat.sh` reported as divergent across the roots
    # while being IDENTICAL: 228 CR in one checkout and 0 in the other, a byte delta of exactly
    # 228, equal the moment endings are normalised. Under `core.autocrlf` the same blob is two
    # different byte sequences in two working copies, so a byte comparison between working trees
    # measures the checkout rather than the file. Same class as the JSON case below, and it would
    # have produced a permanent false FAIL on a must-match path.
    if ab.replace(b"\r\n", b"\n") == bb.replace(b"\r\n", b"\n"):
        return True

    # Parsed equality for JSON, so a serialisation-only difference is not reported as data drift.
    if a.suffix == ".json":
        try:
            return json.loads(ab.decode("utf-8")) == json.loads(bb.decode("utf-8"))
        except Exception:
            return False
    return False


def _norm(b: bytes) -> bytes:
    return b.replace(b"\r\n", b"\n")


def other_is_behind(rel: str) -> bool:
    """True when the other root's content is one of THIS root's OWN earlier versions.

    WHY THIS EXISTS, and it is not a loosening. Two working roots on two live branches differ on
    a must-match path for two reasons that look identical byte-for-byte and have opposite
    remedies. Real DRIFT means someone changed one root and not the other and the difference will
    persist; that is what this gate is for. BEHIND means this root is simply ahead on an unmerged
    branch, which is the normal state of every branch that touches `.github/workflows/` or
    `scripts/check-*`, and there the implied remedy is actively harmful: syncing would copy
    unmerged, unreviewed CI into the other root.

    Without this, the gate was RED BY CONSTRUCTION for the whole life of such a branch, which is
    the failure mode where a check gets learned around and then ignored when it is finally right.

    The discriminator is exact rather than heuristic: if the other root's bytes equal some commit
    of ours for that same path, that content came from here and they are behind. If it appears
    nowhere in our history, the two genuinely diverged and the gate still fails.

    Line endings are normalised for the same reason `same()` normalises them: under
    `core.autocrlf` our stored blob is LF and their checkout is CRLF, so a raw hash comparison
    would report every CRLF file as diverged and defeat the whole check.

    `git ls-tree` plus `git cat-file blob` is used rather than the `<rev>:<path>` colon form,
    which MSYS mangles when the rev contains a slash and the path begins with a dot, exactly the
    shape of `.github/workflows/ci.yml`.
    """
    try:
        target = _norm((OTHER / rel).read_bytes())
    except OSError:
        return False
    try:
        revs = subprocess.run(
            ["git", "-C", str(ROOT), "rev-list", "--all", "--max-count=200", "--", rel],
            capture_output=True,
            check=True,
        ).stdout.split()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

    seen: set[bytes] = set()
    for rev in revs:
        entry = subprocess.run(
            ["git", "-C", str(ROOT), "ls-tree", rev.decode(), "--", rel],
            capture_output=True,
        ).stdout.split()
        if len(entry) < 3:
            continue
        blob = entry[2]
        if blob in seen:
            continue
        seen.add(blob)
        got = subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "blob", blob.decode()],
            capture_output=True,
        )
        if got.returncode == 0 and _norm(got.stdout) == target:
            return True
    return False


def main() -> int:
    if not (OTHER / ".git").exists():
        print(
            f"CANNOT CHECK  the second root is not present at {OTHER}; a clone has one root, so "
            f"this is not applicable rather than clean. Set ZC_OTHER_ROOT to point elsewhere."
        )
        # 2, not 0. `check-all.py` reserves 2 for could-not-check and reads every other code as a
        # verdict, so returning 0 here counted this as a passing comparison of nothing on every
        # clone. The printed word was always honest; the exit code was not.
        return 2

    mine, theirs = git_files(ROOT), git_files(OTHER)
    if mine is None or theirs is None:
        print("CANNOT CHECK  git could not list one of the roots; nothing was compared")
        return 2

    shared = sorted(mine & theirs)
    if len(shared) < MIN_SHARED:
        print(
            f"FAIL  only {len(shared)} shared path(s), expected at least {MIN_SHARED}. "
            f"The intersection is too small to have come from a real pair of roots, so a clean "
            f"result here would mean nothing."
        )
        return 2

    diverged, unreadable = [], []
    for rel in shared:
        a, b = ROOT / rel, OTHER / rel
        if not (a.is_file() and b.is_file()):
            unreadable.append(rel)
            continue
        try:
            if not same(a, b):
                diverged.append(rel)
        except Exception as exc:
            unreadable.append(f"{rel} ({type(exc).__name__})")

    must_match = [r for r in diverged if r.startswith(MUST_MATCH)]
    behind = [r for r in must_match if other_is_behind(r)]
    blocking = [r for r in must_match if r not in behind]
    informational = [r for r in diverged if r not in must_match]

    print(
        f"  {len(shared)} shared path(s) compared, {len(diverged)} diverge "
        f"({len(blocking)} on a must-match path)"
    )
    if unreadable:
        print(f"  {len(unreadable)} could not be read: {', '.join(unreadable[:4])}")

    if behind:
        print(
            f"  INFO  {len(behind)} must-match path(s) where THIS root is ahead and the other"
        )
        print(
            "        root's content is one of our own earlier versions. That is an unmerged"
        )
        print(
            "        branch, not drift, and it syncs when the branch merges. Not gating:"
        )
        for r in behind:
            print(f"          {r}")

    if informational:
        print(
            f"  INFO  {len(informational)} in-flight difference(s), which two live branches are"
        )
        print("        expected to have. Not gating:")
        for r in informational[:12]:
            print(f"          {r}")
        if len(informational) > 12:
            print(f"          ... and {len(informational) - 12} more")

    if blocking:
        print("FAIL  a must-match path differs between the roots:")
        for r in blocking:
            print(f"        {r}")
        print(
            "      These are the paths where a difference means one root enforces, proves or"
        )
        print(
            "      ships something the other does not. Sync them, or move the path out of"
        )
        print("      MUST_MATCH with a reason.")
        return 1

    print("PASS  no must-match path differs between the two roots")
    return 0


if __name__ == "__main__":
    sys.exit(main())
