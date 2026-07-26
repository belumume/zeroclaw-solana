"""Pre-publication audit: does every repo path a tracked doc names actually ship?

The repo has never been pushed, so the first public clone is the first time anyone
sees the tracked tree as a whole. A judge following a citation into a file that is
gitignored gets a dead link, and that reads as carelessness on the one axis where
carelessness is most expensive.

Reports only. Nothing here mutates the tree.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def tracked():
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return set(out.stdout.split("\n")) - {""}


# A repo-relative path inside backticks or a markdown link. Deliberately narrow:
# it must carry a directory separator or a known extension, so prose like `enum`
# or `0x12c` is not mistaken for a file.
PATH_RE = re.compile(
    r"[`(\[]([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:py|rs|toml|md|yml|yaml|json|sh|wit|html))[`)\]]"
)

SKIP_PREFIX = ("http", "https", "www.", "target/", "node_modules/")


# A reference on a line that attributes it elsewhere is a CITATION, not a link into
# this repo. Without this the checker flags every mention of the host's source or the
# audited program's source, which is most of what these docs legitimately cite.
FOREIGN = re.compile(
    r"audited program|upstream|the host|host'?s own|zeroclaw-labs|solana-foundation|"
    r"solana-program|reference implementation|their\s",
    re.IGNORECASE,
)


def main():
    files = tracked()
    # Bare filenames are how docs usually refer to a file whose full path is obvious
    # from context. Matching those against tracked basenames removes the single
    # largest source of noise: the first run flagged Cargo.toml, ci.yml, pay_link.py
    # and five others that all ship, purely because the doc named them without a path.
    basenames = {Path(f).name for f in files}
    docs = [f for f in files if f.endswith(".md")]
    missing = {}

    for doc in docs:
        p = ROOT / doc
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").split("\n")
        except Exception:
            continue
        # A doc filed under docs/upstream/ is about someone else's code by definition.
        if doc.startswith("docs/upstream/"):
            continue
        for i, line in enumerate(lines):
            # Look at the previous line too: attribution routinely wraps, which is how
            # "the audited program's\n`helpers/transfer_data.rs`" slipped through a
            # strictly per-line check.
            window = line + " " + (lines[i - 1] if i else "")
            if FOREIGN.search(window):
                continue
            for m in PATH_RE.finditer(line):
                ref = m.group(1)
                if ref.startswith(SKIP_PREFIX) or ref in files:
                    continue
                # crates/zeroclaw-* is the host's crate namespace. Ours is
                # crates/solana-core, so this distinguishes rather than blanket-skips.
                if ref.startswith("crates/zeroclaw-"):
                    continue
                # Named without a path and owned by the operator rather than the repo.
                if ref in ("config.toml", "manifest.toml"):
                    continue
                if Path(ref).name in basenames:
                    continue
                sibling = str(Path(doc).parent / ref).replace("\\", "/").lstrip("./")
                if sibling in files:
                    continue
                # Reaching here means: named as a repo path, not attributed elsewhere,
                # and nothing by that name ships. On disk but untracked is the worse
                # case, since it looks fine locally and breaks only in a clone.
                on_disk = (ROOT / ref).exists() or (ROOT / sibling).exists()
                missing.setdefault(doc, []).append(
                    (ref, "untracked" if on_disk else "absent")
                )

    if not missing:
        print("PASS  every repo path named by a tracked doc is itself tracked")
        return 0

    total = sum(len(v) for v in missing.values())
    print(
        f"{total} reference(s) across {len(missing)} doc(s) will not resolve in a clone:\n"
    )
    for doc in sorted(missing):
        print(f"  {doc}")
        for ref, why in sorted(set(missing[doc])):
            print(f"      {why:9s} {ref}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
