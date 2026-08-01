"""Every clickable transaction link is backed by bytes this repo actually holds.

Public devnet RPC retains roughly four days. The submission deadline and the judging date are two
weeks apart, so every explorer link here is dead well before anyone clicks it. That is why the
offline proof bundle exists: it moves the evidence into the repo, where nobody else's retention
policy governs it.

The gap that leaves, and the one this gate closes, is a link to a transaction whose bytes were
never captured. It renders identically to a link that is fully backed. It passes every other
check in this repo. And it degrades on a schedule set by someone else, silently, into a dead end
a judge finds by clicking it.

So the rule is one line: a clickable `explorer.solana.com/tx/<signature>` in a tracked markdown
file must resolve to a `CAPTURED` entry in ANY bundle under docs/proof-bundle/, which are
discovered by glob rather than named. Naming one file here was correct while devnet was the only
cluster and became a false red the moment a second bundle landed, reporting captured signatures as
missing and telling the reader to capture bytes that already existed one file over.

TWO REMEDIES, AND BOTH ARE CORRECT ANSWERS
------------------------------------------
Capture the bytes, which is the answer whenever the transaction is still being served:

    python scripts/capture-proof-bundle.py <signature>

Or de-link it. A signature in backticks with no URL reads as history rather than as an offer of
evidence, which is what a pruned transaction honestly is. `plugins/depin-attest/README.md` is the
worked example: it names the signature, states plainly that it no longer resolves, and points at
what is checkable instead.

WHY THERE IS NO PROSE ESCAPE HATCH
----------------------------------
The obvious softer rule is to allow a dead link when the surrounding text labels it as dead. Two
reasons not to. Judging whether prose adequately labels a link is semantic, and semantic matching
in this repo's own measurements runs far below the accuracy a gate needs to stay trusted. More to
the point, the remedy costs one edit and produces a better artifact, so an escape hatch would only
ever be used to keep something that should not be kept. A row in `docs/DEVNET-PROOF.md` carried
exactly that shape: prose in the adjacent column already said "pruned before capture" while the
signature stayed clickable, so the label was accurate and the link was still a dead end.

SCOPE, AND WHAT IT DELIBERATELY DOES NOT COVER
----------------------------------------------
Scope is derived from `git ls-files`, never hand-maintained, because a hand-maintained list is how
the first dead link reached a judge-facing README: the sibling link checker enumerated six
documents and the plugin READMEs were not among them. Tracked is the right boundary because a
reader receives exactly the tracked tree.

Not covered: explorer `/address/` links, because accounts persist rather than being pruned;
signatures mentioned outside a URL, which are the labelled-history form this gate exists to steer
toward; and links in non-markdown files. No network is used, so this says nothing about whether a
captured transaction is still being served, which is `check-doc-links.py`'s job.

Exit 0 = every linked transaction is backed. 1 = at least one is not. 2 = could not verify.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# EVERY bundle, discovered rather than named. This was one hardcoded path to
# devnet-transactions.json, which was correct while devnet was the only cluster and became a FALSE
# RED the moment mainnet-transactions.json landed: three captured mainnet signatures reported as
# "not in the bundle at all", and the script's own remedy told the reader to capture bytes that
# were already captured one file over. A hand-named scope cannot see a file added later, which is
# the whole reason the tracked-markdown scope above is derived from git rather than listed.
BUNDLE_DIR = REPO / "docs" / "proof-bundle"
BUNDLE_GLOB = "*-transactions.json"

TX_LINK = re.compile(r"explorer\.solana\.com/tx/([1-9A-HJ-NP-Za-km-z]{32,})")


def tracked_markdown():
    """Every markdown file a cloner receives. Raises if git cannot answer."""
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "*.md"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if out.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {out.stderr.strip()[:200]}")
    return [p for p in out.stdout.splitlines() if p]


def main():
    # Everything below this line fails to 2 rather than to 0. A gate that cannot do its job must
    # not report the same thing as a gate that did its job and found nothing, because those are
    # indistinguishable downstream and only one of them is good news.
    try:
        docs = tracked_markdown()
    except Exception as exc:
        print(f"CANNOT VERIFY  {exc}")
        return 2
    if not docs:
        print(
            "CANNOT VERIFY  no tracked markdown found; scope derivation returned nothing"
        )
        return 2

    bundle_files = sorted(BUNDLE_DIR.glob(BUNDLE_GLOB))
    if not bundle_files:
        print(
            f"CANNOT VERIFY  no {BUNDLE_GLOB} under {BUNDLE_DIR.relative_to(REPO)}; "
            "bundle discovery returned nothing"
        )
        return 2

    captured = set()
    bundle = {}  # merged entries, so a non-captured status can still be reported by name
    for bf in bundle_files:
        try:
            txs = json.loads(bf.read_text(encoding="utf-8")).get("transactions", {})
        except Exception as exc:
            print(f"CANNOT VERIFY  cannot read {bf.relative_to(REPO)}: {exc}")
            return 2
        for sig, entry in txs.items():
            # A CAPTURED entry anywhere wins. One bundle recording a signature as pruned must not
            # mask another holding its real bytes, which is the direction that loses evidence.
            if entry.get("status") == "CAPTURED" or sig not in bundle:
                bundle[sig] = entry
        captured |= {s for s, e in txs.items() if e.get("status") == "CAPTURED"}

    # Name what was actually read, so a bundle that stops being discovered is visible rather than
    # silently shrinking the set every signature is checked against.
    print(
        f"checking against {len(captured)} captured signature(s) across "
        f"{len(bundle_files)} bundle(s): {', '.join(b.name for b in bundle_files)}"
    )
    if not captured:
        print(
            "CANNOT VERIFY  bundles hold no captured transactions; nothing to check against"
        )
        return 2

    # signature -> documents linking it
    linked = {}
    for doc in docs:
        try:
            text = (REPO / doc).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in TX_LINK.finditer(text):
            linked.setdefault(m.group(1), set()).add(doc)

    # A clean result has to mean the parser ran. This repo links transactions by construction, so
    # zero matches means the regex, the scope, or the tree changed under the gate rather than that
    # everything is fine. Reporting that as PASS is the exact vacuous-green this file exists to
    # prevent one level down.
    if not linked:
        print(
            "CANNOT VERIFY  no explorer transaction links found in any tracked markdown.\n"
            "               This repo publishes them, so treat a zero here as a broken gate."
        )
        return 2

    findings = []
    for sig in sorted(linked):
        where = ", ".join(sorted(linked[sig]))
        if sig in captured:
            print(f"PASS  bytes held        {sig[:16]}..  {where}")
        else:
            status = bundle.get(sig, {}).get("status", "not in the bundle at all")
            print(f"FAIL  {status:<18} {sig[:16]}..  {where}")
            findings.append((sig, status, where))

    print()
    print(
        f"{len(linked)} linked transaction(s) across {len(docs)} tracked document(s), "
        f"{len(captured)} captured in the bundle"
    )

    if findings:
        print(f"\n{len(findings)} link(s) offer evidence this repo does not hold:\n")
        for sig, status, where in findings:
            print(f"  {sig}")
            print(f"      {status}, linked from {where}")
        print(
            "\nEither capture the bytes while the endpoint still serves them:\n"
            "    python scripts/capture-proof-bundle.py <signature>\n"
            "or de-link it, leaving the signature in backticks as history. See\n"
            "plugins/depin-attest/README.md for the wording that does this honestly."
        )
        return 1

    print("Every linked transaction is backed by captured bytes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
