#!/usr/bin/env python3
"""A tracked document nobody can REACH is shipped and invisible.

WHY THIS EXISTS, and both halves were found the same day. A one-pager was written, committed
and pushed while linked from nothing, so the only way to it was guessing the filename. Testing
that led to the real defect: the write-up's section titled "Reproducibility (links)" contained
NO LINKS, against a brief that asks that exact section for links to config, SOPs, skills and
code. Both SOP files were tracked, shipped in every clone, and reachable from nowhere. Every
sentence in that section was true, which is why nothing looked wrong.

That is the shape worth gating. A missing file errors. An unreachable file does not: it
exists, it reads correctly, and it passes every check that looks AT it rather than FOR it.

REACHABILITY IS NOT "IS IT LINKED", and the naive version of this check is actively harmful.
Written that way it called 21 of 32 documents unreachable, nearly all falsely, because a
reader also arrives by:
  - a link to the containing DIRECTORY, which is how the transcripts are reached
  - GitHub rendering README.md when someone browses into any folder
Reporting that raw number would have been a fabricated finding, and "fixing" it would have
added 19 pointless links.

A second bug in the same checker kept reporting the SOPs as orphaned AFTER they were linked,
because the resolver did not normalise a parent-directory segment, so `docs/../sops/x.md`
never matched `sops/x.md`. Both corrections are why this ships with controls rather than
confidence.

ACCEPTED orphans are DECLARED with their reason below, never silently skipped, because an
undocumented omission cannot be told apart from an oversight.

Run: python3 scripts/check-doc-reachability.py
"""

import pathlib
import posixpath
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MIN_DOCS = 10  # a walk finding fewer than this is broken, not clean

ACCEPTED = {
    "docs/upstream/whatsapp-policy-fail-open.md": "a filed upstream report; its canonical home is the GitHub issue, which the write-up links",
    "wit/VERSIONING.md": "reference for anyone editing the vendored WIT; reached from that directory, not from prose",
}


def tracked_docs():
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "*.md"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    return [f for f in out.split("\n") if f.strip()]


def collect_links(docs):
    """Every link target any tracked doc points at, split into files and directories."""
    files, dirs = set(), set()
    for rel in docs:
        p = ROOT / rel
        if not p.exists():
            continue
        base = pathlib.PurePosixPath(rel).parent
        for m in re.findall(
            r"\]\(([^)]+)\)", p.read_text(encoding="utf-8", errors="replace")
        ):
            t = m.split("#")[0].strip()
            if not t or t.startswith(("http", "mailto", "<")):
                continue
            # normpath is load-bearing: without it a ../ link never matches its target
            t = (
                posixpath.normpath(str(base / t))
                if not t.startswith("/")
                else t.lstrip("/")
            )
            t = t.replace("\\", "/")
            if t.endswith(".md"):
                files.add(t)
            elif t.endswith("/") or "." not in pathlib.PurePosixPath(t).name:
                dirs.add(t.rstrip("/"))
    return files, dirs


def why_reachable(rel, files, dirs):
    if rel == "README.md":
        return "the repository front page"
    if rel in files:
        return "linked directly"
    d = str(pathlib.PurePosixPath(rel).parent)
    if d in dirs:
        return f"its directory {d}/ is linked"
    if pathlib.PurePosixPath(rel).name == "README.md":
        return "rendered when a reader browses its directory"
    for ld in dirs:
        if rel.startswith(ld + "/"):
            return f"under linked directory {ld}/"
    return None


def main() -> int:
    docs = tracked_docs()
    if len(docs) < MIN_DOCS:
        print(
            f"FAIL  walk found {len(docs)} tracked document(s); expected at least {MIN_DOCS}."
        )
        print(
            "      The discovery step is broken, so a clean result would mean nothing."
        )
        return 2

    # An exception list is itself a claim, and it rots. An ACCEPTED entry naming an untracked
    # path pre-excuses a document that does not exist, so if one is ever added there it is
    # exempt by an entry nobody remembers writing. That is this gate's own thesis, one level up.
    stale = [rel for rel in sorted(ACCEPTED) if rel not in set(docs)]
    if stale:
        print(
            f"\n{len(stale)} ACCEPTED entr(ies) name a document that is not tracked:\n"
        )
        for rel in stale:
            print(f"  ?  {rel}")
        print(
            "\n      Remove the entry, or track the document it names. An exception for a path\n"
            "      nobody tracks silently exempts whatever is added there later."
        )
        return 1

    files, dirs = collect_links(docs)
    orphans = [r for r in sorted(docs) if why_reachable(r, files, dirs) is None]
    undeclared = [r for r in orphans if r not in ACCEPTED]

    print(
        f"walked {len(docs)} tracked document(s); "
        f"{len(files)} file link(s), {len(dirs)} directory link(s)"
    )

    for rel, reason in sorted(ACCEPTED.items()):
        if rel in orphans:
            print(f"  accepted  {rel}\n            {reason}")

    if not undeclared:
        print("\nPASS  every tracked document is reachable, or declared with a reason")
        return 0

    print(
        f"\n{len(undeclared)} document(s) reachable by nobody who does not know the filename:\n"
    )
    for rel in undeclared:
        print(f"  {rel}")
    print(
        "\nA tracked document nothing routes to is shipped and invisible. Link it from a surface a\n"
        "reader actually reaches, or add it to ACCEPTED with the reason it needs no link. Do not\n"
        "delete it to clear the gate: the file is not the problem, its unreachability is."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
