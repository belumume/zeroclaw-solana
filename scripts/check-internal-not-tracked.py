#!/usr/bin/env python3
"""Refuse to ship a file that declares itself internal.

WHY THIS EXISTS. Internal working docs reaching the public tree is the most-repeated defect in this
repository's history: caught and reverted across eleven separate commits on nine separate dates,
every time by someone noticing rather than by anything checking. A defect that recurs eleven times
is not an attention problem, and the eleven fixes are evidence the reviews work and the absence of a
gate does not.

THE SIGNAL IS THE FILE'S OWN DECLARATION, which is what makes this cheap and deterministic. Internal
artifacts here already announce themselves in their first lines: `audience: internal` frontmatter,
`public: false`, or a NEVER PUBLISH banner. `.gitignore` is supposed to keep them out, but a
gitignore entry is a claim about a path while this is a claim about the CONTENT, and the two drift
whenever a file is renamed, moved, or created in a directory nobody thought to ignore.

WHAT IT DOES NOT DO. It cannot judge whether an UNMARKED file should have been internal, so it is a
floor rather than a ceiling. A doc carrying home paths and internal reasoning with no marker sails
through, and `check-repo-paths` and `check-identifier-leaks` are what cover that ground.

Exit 0 clean, 1 when a marked file is tracked. Auto-enrols: `check-all.py` discovers gates from
git's index, so committing this file adds it to the suite with no list to edit.

Self-test: `python3 scripts/check-internal-not-tracked.py --selftest`
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Read only the head: a marker is a declaration, and declarations go at the top. Reading whole files
# would also match prose that merely DISCUSSES the markers, including this docstring.
HEAD_BYTES = 400

# The leading class allows the characters a marker sits behind in a SOURCE file: a Python docstring
# opens with three quotes, a shell comment with #, a JS block with /* or *. A bare \s* anchor misses
# every one of those, which this gate's own selftest caught before it shipped.
_LEAD = r"""^[\s#/*"'-]*"""

MARKERS = [
    ("frontmatter-audience", _LEAD + r"audience:\s*internal\b"),
    ("frontmatter-public", _LEAD + r"public:\s*false\b"),
    ("never-publish-banner", r"\bNEVER\s+PUBLISH\b"),
    ("internal-only-banner", r"\binternal only\b"),
]

TEXTUAL = (".md", ".txt", ".py", ".json", ".toml", ".yml", ".yaml", ".sh")


def scan(paths, reader):
    """Return [(path, marker_name)]. `reader` is injected so the control can drive it with
    synthetic content and never needs a file on disk, let alone a tracked one."""
    found = []
    for p in paths:
        if not p.lower().endswith(TEXTUAL):
            continue
        head = reader(p)
        if head is None:
            continue
        for name, pat in MARKERS:
            if re.search(pat, head, re.I | re.M):
                found.append((p, name))
                break
    return found


def read_head(rel):
    try:
        return (ROOT / rel).read_text(encoding="utf-8", errors="replace")[:HEAD_BYTES]
    except Exception:
        return None


def tracked():
    r = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return r.stdout.split()


def selftest():
    """Both directions. A gate only proven to stay quiet has not been proven at all."""
    planted = {
        "docs/FAKE-INTERNAL.md": "---\naudience: internal\n---\nbody",
        "docs/FAKE-PUBLIC.md": "# A normal public document\n\nIt mentions audience and publishing.",
        "notes/FAKE-BANNER.txt": "NEVER PUBLISH: working notes",
        "src/FAKE-CODE.py": '"""public: false"""\n',
        "assets/logo.png": "audience: internal",  # non-textual, must be skipped
    }
    hits = dict(scan(list(planted), lambda p: planted[p]))
    checks = [
        ("frontmatter marker fires", "docs/FAKE-INTERNAL.md" in hits),
        ("banner marker fires", "notes/FAKE-BANNER.txt" in hits),
        ("public:false in code fires", "src/FAKE-CODE.py" in hits),
        ("ordinary doc stays silent", "docs/FAKE-PUBLIC.md" not in hits),
        ("non-textual skipped", "assets/logo.png" not in hits),
    ]
    ok = True
    for label, passed in checks:
        print(f"  {'ok  ' if passed else 'FAIL'} {label}")
        ok &= passed
    print("selftest passed" if ok else "SELFTEST FAILED")
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()

    paths = tracked()
    if not paths:
        print(
            "FAIL  git ls-files returned nothing; the walk is broken, so a clean result "
            "here would mean nothing.",
            file=sys.stderr,
        )
        return 2

    found = scan(paths, read_head)
    if not found:
        print(f"OK  {len(paths)} tracked file(s); none declares itself internal.")
        return 0

    print(
        f"{len(found)} tracked file(s) declare themselves internal:\n", file=sys.stderr
    )
    for p, marker in found:
        print(f"  {p}  [{marker}]", file=sys.stderr)
    print(
        "\nEach is either genuinely internal, in which case gitignore it and "
        "`git rm --cached` it, or the marker is wrong and should go.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
