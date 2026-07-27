"""Find gitignored scripts that shadow a tracked one. (stdlib only)

    python3 scripts/check-shadowed-scripts.py

Exit 0 = no shadow found. 1 = at least one shadow. 2 = could not verify.

This exists because of a specific failure, twice in one day. A harness backing a testing claim
was written into an ignored directory, where a reader can neither run it nor read it. It was
ported to `scripts/`, and the ignored original was left behind. Within hours the two had
diverged, because only the tracked copy got hardened.

Remembering the lesson demonstrably did not prevent the second occurrence, so this is the
mechanical version. A gitignored script whose body substantially overlaps a tracked one is
either dead weight that will drift, or the real implementation hiding from the reader. Both are
worth knowing about before a submission.

BOTH SCOPES ARE DERIVED, AND THAT IS A FIX RATHER THAN A STYLE CHOICE
---------------------------------------------------------------------
Until 2026-07-27 this gate carried two hand-written lists, and each one was narrower than the
surface the gate claims to cover, which is the shape that reports green about the part it can see
and says nothing about the rest.

The ignored side was `[".tools"]`, scanned one level deep. Measured against this tree that saw
112 of 271 gitignored scripts. It missed 150 sitting at the repo root, 8 in three other ignored
directories, and one under `.tools/yt-corpus/` that the non-recursive walk could not reach even
though its parent was listed. It is now every gitignored file git reports, at any depth, so a
directory nobody has created yet is in scope on the day it appears.

The tracked side was `("scripts/", "skills/")`, which left two tracked scripts unprotectable. One
of them is `webshop-pay/build.py`, whose own drift incident is the canonical case for this gate:
the generator had fallen behind the artifact it generates, and one run would have reverted four
fixes including the pinned merchant address that stops a customer paying a wallet the shop does
not own. A gate built to catch a drifting second copy could not see the file this repo has
already watched drift. It is now every tracked script, because a reader receives exactly the
tracked tree and every file in it is worth protecting.

Vendored and build output is excluded by directory name. That is an enumeration, and it is the
correct kind: it names what is not ours rather than guessing where ours lives, so a new directory
of our own is included by default instead of waiting for someone to remember it.

WHAT DEGENERATE LOOKS LIKE, AND WHY IT IS NOT ZERO
--------------------------------------------------
A gate that cannot read its inputs must not print what a gate that read them prints. `git
ls-files` returning nothing after a failed invocation used to produce "no gitignored script
shadows a tracked one (0 tracked scanned)", which is the reassuring sentence rather than the
alarm. Both git calls are now checked, the tracked derivation is checked against a canary, and a
comparison with nothing on the tracked side exits 2.

An EMPTY ignored side is not degenerate. A fresh clone and a CI runner have no ignored files at
all, and that is the correct state rather than a broken derivation, so the discrimination is on
whether the command SUCCEEDED and not on whether it found anything.
"""

import io
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

SCRIPT_EXT = (".sh", ".py")

# Not ours. Naming what to exclude keeps the derivation open: a directory we add later is in
# scope without an edit, which is the property the old prefix list did not have.
NOT_OURS = {"target", "node_modules", ".git", ".venv", "venv"}

# NOT the scope. Two tracked scripts that must survive the derivation, kept as a floor: a
# derivation that stops returning them has broken, and a broken derivation reports a clean tree.
# `webshop-pay/build.py` is here specifically because it was outside the old scope, so if the
# tracked side is ever re-narrowed to a directory prefix this refuses to run rather than going
# quietly blind again. Renaming either file is a deliberate edit here, not a surprise.
CANARY = ("scripts/check-repo-paths.py", "webshop-pay/build.py")

MIN_LINES = 6
OVERLAP = 0.5


def meaningful(path):
    """Non-blank, non-comment lines. Comments differ freely between copies and are not signal."""
    try:
        raw = io.open(path, encoding="utf-8", errors="replace").read().replace("\r", "")
    except OSError:
        return set()
    out = set()
    for line in raw.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.add(s)
    return out


def git(*args):
    """Raises rather than returning a short list, because a short list reads as a clean tree."""
    r = subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()[:200]}")
    return [p for p in r.stdout.splitlines() if p]


def ours(paths):
    return [
        p
        for p in paths
        if p.endswith(SCRIPT_EXT) and not (set(p.split("/")) & NOT_OURS)
    ]


def tracked_scripts():
    """Every script a cloner receives."""
    scripts = ours(git("ls-files"))
    missing = [c for c in CANARY if c not in scripts]
    if missing:
        raise RuntimeError(f"derivation lost known scripts: {', '.join(missing)}")
    return scripts


def ignored_scripts():
    """Every script on disk that a cloner does NOT receive, at any depth.

    Legitimately empty in a fresh clone, so the caller reads the count rather than treating
    zero as a fault.
    """
    return ours(git("ls-files", "--others", "--ignored", "--exclude-standard"))


def main():
    try:
        tracked_paths = tracked_scripts()
        ignored_paths = ignored_scripts()
    except Exception as exc:
        print(f"CANNOT VERIFY  {exc}")
        return 2

    tracked = {p: meaningful(REPO / p) for p in tracked_paths}
    tracked = {p: s for p, s in tracked.items() if len(s) >= MIN_LINES}

    if not tracked:
        print(
            f"CANNOT VERIFY  {len(tracked_paths)} tracked script(s) found, none with "
            f"{MIN_LINES}+ meaningful lines, so nothing was compared against"
        )
        return 2

    for c in CANARY:
        if c not in tracked:
            print(
                f"CANNOT VERIFY  canary {c} is tracked but was dropped before comparison, "
                f"so being in scope did not make it protected"
            )
            return 2

    shadows = []
    scanned = 0
    for path in sorted(ignored_paths):
        body = meaningful(REPO / path)
        if len(body) < MIN_LINES:
            continue
        scanned += 1
        for tpath, tbody in tracked.items():
            shared = len(body & tbody)
            if shared >= OVERLAP * len(body):
                shadows.append((path, tpath, shared, len(body), body == tbody))

    coverage = (
        f"{scanned} ignored script(s) compared against {len(tracked)} tracked "
        f"({len(ignored_paths)} ignored and {len(tracked_paths)} tracked found; the rest are "
        f"under {MIN_LINES} meaningful lines)"
    )

    if not shadows:
        print("no gitignored script shadows a tracked one")
        print(coverage)
        return 0

    print(f"{len(shadows)} shadowed script(s):\n")
    for ign, tr, shared, total, identical in shadows:
        state = (
            "IDENTICAL, dead weight" if identical else "DIVERGED, the dangerous case"
        )
        print(f"  {ign}")
        print(f"    shadows {tr}  ({shared}/{total} lines shared, {state})")
    print()
    print(coverage)
    print(
        "\nDecide per case: delete the ignored copy if the tracked one supersedes it, or\n"
        "port what is missing. A diverged pair means only one of them got the last fix."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
