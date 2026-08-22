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


def tracked_docs(root: pathlib.Path = ROOT):
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "*.md"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    return [f for f in out.split("\n") if f.strip()]


def collect_links(docs, root: pathlib.Path = ROOT):
    """Every link target any tracked doc points at, split into files and directories."""
    files, dirs = set(), set()
    for rel in docs:
        p = root / rel
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


def main(
    root: pathlib.Path = ROOT, accepted: dict | None = None, min_docs: int = MIN_DOCS
) -> int:
    accepted = ACCEPTED if accepted is None else accepted
    docs = tracked_docs(root)
    if len(docs) < min_docs:
        print(
            f"FAIL  walk found {len(docs)} tracked document(s); expected at least {min_docs}."
        )
        print(
            "      The discovery step is broken, so a clean result would mean nothing."
        )
        return 2

    # An exception list is itself a claim, and it rots. An ACCEPTED entry naming an untracked
    # path pre-excuses a document that does not exist, so if one is ever added there it is
    # exempt by an entry nobody remembers writing. That is this gate's own thesis, one level up.
    stale = [rel for rel in sorted(accepted) if rel not in set(docs)]
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

    files, dirs = collect_links(docs, root)
    orphans = [r for r in sorted(docs) if why_reachable(r, files, dirs) is None]
    undeclared = [r for r in orphans if r not in accepted]

    print(
        f"walked {len(docs)} tracked document(s); "
        f"{len(files)} file link(s), {len(dirs)} directory link(s)"
    )

    for rel, reason in sorted(accepted.items()):
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


def selftest() -> int:
    """Make the docstring's "ships with controls rather than confidence" true.

    It was not. Until 2026-08-22 this file asserted controls and had none: no --selftest, no
    sibling test, no mutation script. That is worse than a silent gap, because the claim
    discourages the next auditor from looking.

    The cases are the regressions that actually happened, not invented ones. Two of them are
    the FALSE-POSITIVE direction, which matters more here than the false-negative: the naive
    version of this check called 21 of 32 documents unreachable and "fixing" that would have
    added 19 pointless links. A control set that only proves the gate can FAIL would have
    passed the naive version too.

    Every case runs against a throwaway git repo in a temp dir. The real tree is never written,
    and the last assertion proves it rather than intending it.
    """
    import hashlib
    import shutil
    import subprocess as sp
    import tempfile

    real = sorted(ROOT.glob("*.md"))
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in real}
    cases: list[tuple[str, int, int]] = []
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="doc-reach-selftest-"))

    def fixture(files: dict[str, str]) -> pathlib.Path:
        """A real git repo, because tracked_docs shells out to `git ls-files`."""
        d = pathlib.Path(tempfile.mkdtemp(dir=tmp))
        for rel, body in files.items():
            f = d / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body, encoding="utf-8", newline="")
        for cmd in (["init", "-q"], ["add", "-A"]):
            sp.run(["git", "-C", str(d)] + cmd, capture_output=True, check=False)
        return d

    # A hub linking everything, plus filler so the MIN_DOCS floor is not what is being tested.
    def with_filler(extra: dict[str, str], hub_links: str = "") -> dict[str, str]:
        files = {"README.md": "# hub\n" + hub_links}
        for i in range(12):
            files[f"filler{i}.md"] = "# f\n"
            files["README.md"] += f"[f]( filler{i}.md )\n".replace(" ", "")
        files.update(extra)
        return files

    try:
        # 1. THE REAL TREE PASSES. Over-correction control: without it, a gate that failed on
        #    everything would satisfy every must-fail case below.
        cases.append(("the real tree passes", 0, main()))

        # 2. A genuinely unreachable doc must FAIL. This is the defect the gate exists for.
        d = fixture(with_filler({"docs/orphan.md": "# nobody links me\n"}))
        cases.append(("planted unreachable doc", 1, main(d, {}, 5)))

        # 3. Reachable ONLY through a ../ segment must PASS. This is the resolver bug that kept
        #    reporting the SOPs orphaned AFTER they were linked.
        d = fixture(
            with_filler(
                {
                    "docs/hub.md": "# h\n[sop](../sops/x.md)\n",
                    "sops/x.md": "# sop\n",
                },
                hub_links="[d](docs/hub.md)\n",
            )
        )
        cases.append(("reachable only via a ../ link", 0, main(d, {}, 5)))

        # 4. Reachable ONLY because its DIRECTORY is linked must PASS. This is the route whose
        #    absence produced the 21-of-32 false report.
        d = fixture(
            with_filler(
                {"transcripts/a.md": "# t\n"}, hub_links="[dir](transcripts/)\n"
            )
        )
        cases.append(("reachable only via a linked directory", 0, main(d, {}, 5)))

        # 4b. DEEPER than the linked directory, which only the prefix loop can satisfy. Case 4
        #    alone cannot distinguish the two directory routes: for a doc whose IMMEDIATE parent
        #    is linked, both the exact-parent branch and the prefix loop match, so removing
        #    either one leaves the other covering it and the mutation escapes. Measured exactly
        #    that -- remove either alone and the suite still passed; remove both and case 4
        #    failed. This fixture links `docs/` and buries the doc one level below it, so the
        #    parent `docs/sub` is NOT in dirs and only the prefix loop can reach it.
        #    (The exact-parent branch stays subsumed by construction: if a parent is linked the
        #    prefix loop matches too. It is a fast path, not a distinct route, so it has no
        #    fixture of its own and a mutation removing it is equivalent rather than escaped.)
        d = fixture(
            with_filler({"docs/sub/deep.md": "# deep\n"}, hub_links="[dir](docs/)\n")
        )
        cases.append(("reachable only by the prefix route", 0, main(d, {}, 5)))

        # 5. A nested README is rendered when a reader browses in, so it needs no link.
        d = fixture(with_filler({"sub/README.md": "# nested\n"}))
        cases.append(("nested README needs no link", 0, main(d, {}, 5)))

        # 6. An ACCEPTED entry naming an UNTRACKED path must be reported, because it pre-excuses
        #    whatever is added there later. The gate's own thesis, one level up.
        d = fixture(with_filler({}))
        cases.append(
            ("ACCEPTED names an untracked path", 1, main(d, {"ghost.md": "why"}, 5))
        )

        # 7. Too few docs is rc=2, a THIRD state. Folding it into pass would report clean over a
        #    broken walk; folding it into fail would read as a real finding.
        d = fixture({"only.md": "# one\n"})
        cases.append(("below the discovery floor", 2, main(d, {}, 10)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in real}
    untouched = before == after

    failed = [c for c in cases if c[1] != c[2]]
    print(
        f"\n  selftest: {len(cases) - len(failed)}/{len(cases)} cases behaved as required"
    )
    for name, want, got in cases:
        print(
            f"    {'ok  ' if want == got else 'FAIL'} {name}: wanted rc={want}, got rc={got}"
        )
    print(
        f"    {'ok  ' if untouched else 'FAIL'} real tree unwritten "
        f"({len(real)} top-level doc(s) digested before and after)"
    )
    if failed or not untouched:
        return 1
    print("\nPASS  the gate produces all three verdicts on known inputs")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(selftest())
    sys.exit(main())
