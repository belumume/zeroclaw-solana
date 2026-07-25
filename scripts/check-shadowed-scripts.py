"""Find gitignored scripts that shadow a tracked one.

This exists because of a specific failure, twice in one day. A harness backing a testing claim
was written into an ignored directory, where a reader can neither run it nor read it. It was
ported to `scripts/`, and the ignored original was left behind. Within hours the two had
diverged, because only the tracked copy got hardened.

Remembering the lesson demonstrably did not prevent the second occurrence, so this is the
mechanical version. A gitignored script whose body substantially overlaps a tracked one is
either dead weight that will drift, or the real implementation hiding from the reader. Both are
worth knowing about before a submission.

Exit 0 = clean, 1 = shadows found. Deliberately advisory about WHICH copy is right; that is a
judgement call, and a tool that guesses it would be wrong often enough to get muted.
"""

import io
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IGNORED_DIRS = [".tools"]
TRACKED_GLOBS = ("scripts/", "skills/")
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


def tracked_files():
    r = subprocess.run(
        ["git", "-C", REPO, "ls-files"], capture_output=True, text=True, timeout=60
    )
    return [
        p
        for p in r.stdout.splitlines()
        if p.startswith(TRACKED_GLOBS) and p.endswith((".sh", ".py"))
    ]


def main():
    tracked = {p: meaningful(os.path.join(REPO, p)) for p in tracked_files()}
    tracked = {p: s for p, s in tracked.items() if len(s) >= MIN_LINES}

    shadows = []
    for d in IGNORED_DIRS:
        base = os.path.join(REPO, d)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if not name.endswith((".sh", ".py")):
                continue
            path = os.path.join(base, name)
            body = meaningful(path)
            if len(body) < MIN_LINES:
                continue
            for tpath, tbody in tracked.items():
                shared = len(body & tbody)
                if shared >= OVERLAP * len(body):
                    identical = body == tbody
                    shadows.append((f"{d}/{name}", tpath, shared, len(body), identical))

    if not shadows:
        print(
            f"no gitignored script shadows a tracked one ({len(tracked)} tracked scanned)"
        )
        return 0

    print(f"{len(shadows)} shadowed script(s):\n")
    for ign, tr, shared, total, identical in shadows:
        state = (
            "IDENTICAL, dead weight" if identical else "DIVERGED, the dangerous case"
        )
        print(f"  {ign}")
        print(f"    shadows {tr}  ({shared}/{total} lines shared, {state})")
    print(
        "\nDecide per case: delete the ignored copy if the tracked one supersedes it, or\n"
        "port what is missing. A diverged pair means only one of them got the last fix."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
