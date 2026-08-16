#!/usr/bin/env python3
"""Compare the CONTENT the box is running against the content on main. (stdlib only)

    python3 scripts/check-deploy-content-staleness.py [--sha <deployed sha>] [--ref <ref>]

Exit 0 = every deployed path matches. 1 = at least one has drifted. 2 = could not verify.

WHY THIS EXISTS, and it is the gap the whole gate set shares rather than one gate's oversight.
`deploy/box_selfcheck.py` states its own scope in its docstring: "every tracked file
byte-identical to THE COMMIT IT WAS DEPLOYED FROM". The hashes it compares against are baked
into SHOP-INVARIANTS.json by `deploy/make_invariants.py` at deploy time, so the box compares
itself to a snapshot of itself. A box that has not been deployed for ten days reports a green
manifest, because it does match the thing it was deployed from. Nothing anywhere asks the other
question: has main moved since?

Measured on 2026-08-16. The box reported `deployed_sha 4e65a5ca` (2026-08-06) with
"19 file(s) compared; all match", and of the 14 files the deploy map places there, 4 had drifted
and 4 had never been deployed at all. The drifted set included `pay_link.py`, the last code that
runs before a customer is asked for money, which on the box carried neither the order-value band
nor the quote binding nor the fetched exchange rate. The repo had all three. Every gate was
green, and the money-path hardening the repo documents as shipped was not running.

WHY IT COMPARES CONTENT RATHER THAN COMMITS, which is the whole design. Merges to main are
squashed, so a deploy from a branch head produces a `deployed_sha` that main NEVER CONTAINS. A
gate asserting `deployed_sha` is an ancestor of main would therefore be red immediately after a
perfect deploy, which is the false red that stops a gate being believed. Two commits with
identical content for a path are the same deploy for this gate's purpose, whatever their shas.

SCOPE IS DERIVED from `deploy/deploy-targets.json`, never listed here. That file is already the
single source for both the deployer and the box checker, so a path added to it joins this gate
the same day. A hand list here would cover the paths someone remembered.

THE POSITIVE CONTROL IS INLINE, because a zero here is ambiguous in the dangerous direction. If
this gate resolved the wrong ref, or read an empty tree, or was handed a sha whose tree does not
contain the project, EVERY path would compare as different and it would print a long confident
list of drift that is really one broken lookup. So a run in which NOTHING matches is reported as
CANNOT VERIFY rather than as a finding. The count is always emitted with its denominator for the
same reason: "8 drifted" and "8 drifted of 14, 6 matching" are different claims, and only the
second one demonstrates the comparison can return both answers.

BOTH SIDES ARE READ AS GIT BLOBS, never from the working tree. Under `core.autocrlf` the working
copy of a tracked file is CRLF while its blob is LF, so a comparison with one side from disk
manufactures a mismatch on every line of every file. Reading both sides through git removes the
translation from the comparison instead of trying to undo it.

WHAT THIS DOES NOT CHECK, stated rather than implied. It compares the paths the deploy map
places, so a file the box runs that nobody mapped is invisible to it, exactly as it is invisible
to the box checker. It says nothing about the host BINARY's vintage, which is a separate artifact
with its own age and is the thing that actually gates upstream capabilities. And it trusts the
box's own report of which sha it was deployed from: a box that misreports that number is checked
against the wrong baseline, though `box_selfcheck`'s manifest going green against the same
snapshot is independent corroboration that the number describes the files.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGETS = ROOT / "deploy" / "deploy-targets.json"
DEFAULT_SELFCHECK = "https://x402.perfpilot.dev/selfcheck"
CANNOT_CHECK = 2


def git(*args: str) -> tuple[int, str]:
    r = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return r.returncode, r.stdout


def blob_at(ref: str, path: str) -> bytes | None:
    """The bytes of `path` at `ref`, or None when the path is absent there.

    `git ls-tree` then `git cat-file` rather than the `<ref>:<path>` colon form, which MSYS
    rewrites when the ref carries a slash and the path starts with a dot. The mapped paths do
    not currently start with a dot and `origin/main` does carry a slash, so the failing shape is
    one mapped `.github/` entry away rather than impossible.
    """
    rc, out = git("ls-tree", ref, "--", path)
    if rc != 0 or not out.strip():
        return None
    fields = out.split()
    if len(fields) < 3:
        return None
    r = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "blob", fields[2]], capture_output=True
    )
    return r.stdout if r.returncode == 0 else None


def resolve_current_ref(explicit: str | None) -> str | None:
    """The ref standing for "what should be deployed".

    Prefers the default branch over HEAD on purpose. A feature branch that edits a mapped file
    is not yet deployable, so comparing the box against HEAD would redden this gate for every
    such branch and teach people that its red means nothing.
    """
    for candidate in ([explicit] if explicit else []) + ["origin/main", "main", "HEAD"]:
        rc, out = git("rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}")
        if rc == 0 and out.strip():
            return candidate
    return None


def mapped_paths(ref: str) -> list[str]:
    """Every file the deploy map places on the box, enumerated from `ref`'s tree.

    An entry's `include` is either `**`, meaning the whole subtree, or one filename, which is
    how the map narrows `skills/solana-pay/scripts` to just `pay_link.py`.
    """
    spec = json.loads(TARGETS.read_text(encoding="utf-8"))
    found: set[str] = set()
    for entry in spec.get("map", []):
        src, include = entry.get("src", ""), entry.get("include", "**")
        rc, out = git("ls-tree", "-r", "--name-only", ref, "--", src + "/")
        if rc != 0:
            continue
        for path in out.split("\n"):
            path = path.strip()
            if not path:
                continue
            if include == "**" or path.rsplit("/", 1)[-1] == include:
                found.add(path)
    return sorted(found)


def fetch_deployed_sha(url: str) -> tuple[str | None, str]:
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (check-deploy-content-staleness)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            payload = json.loads(r.read(65536).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return None, f"the self-check endpoint answered HTTP {e.code}"
    # Named rather than caught broadly, so a bug in this file surfaces as a traceback instead
    # of being reported as the box being unreachable. Every arm below is a real transport or
    # payload failure: no route, no DNS, a TLS refusal, a timeout, or a body that is not JSON.
    except (urllib.error.URLError, OSError, ValueError, UnicodeDecodeError) as e:
        return None, f"the self-check endpoint is unreachable ({type(e).__name__})"
    sha = payload.get("deployed_sha")
    if not isinstance(sha, str) or len(sha) < 7:
        return None, f"the self-check payload carries no usable deployed_sha ({sha!r})"

    # IS THAT NUMBER CORROBORATED. `deployed_sha` used to be served from a hand-maintained
    # `DEPLOYED_SHA` file that no code writes, so it named whatever a human last typed rather
    # than the commit the box's own hashes were generated from. Measured 2026-08-16: it was
    # nine days stale while the manifest beside it was green. A box serving
    # `deployed_sha_source` has the fixed checker and the value is the generated one; a box
    # without that field predates the fix and its baseline is the operator's memory.
    return sha, baseline_note(payload.get("deployed_sha_source"))


def baseline_note(source: object) -> str:
    """How much the reported commit is worth, as a sentence printed above the verdict.

    Pure and separate from the fetch so it can be driven by the controls: the note decides how a
    reader weighs the drift list, which makes it part of the verdict rather than decoration.
    """
    if source == "repo_commit":
        return (
            "baseline CORROBORATED: the box reports this as the commit its own hashes were "
            "generated from"
        )
    if isinstance(source, str):
        return f"BASELINE UNCORROBORATED: the box reports its source as {source!r}"
    return (
        "BASELINE UNCORROBORATED: this box predates `deployed_sha_source`, so the commit below "
        "is a hand-maintained label rather than the one its hashes belong to. A label left "
        "BEHIND over-reports drift, which is the safe direction; a label advanced without a "
        "deploy would under-report it, which is not."
    )


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--sha", help="deployed sha, instead of asking the box")
    ap.add_argument("--ref", help="ref standing for what should be deployed")
    ap.add_argument("--url", default=DEFAULT_SELFCHECK)
    args = ap.parse_args()

    if not TARGETS.is_file():
        print(f"CANNOT VERIFY  no deploy map at {TARGETS.relative_to(ROOT)}")
        return CANNOT_CHECK

    current = resolve_current_ref(args.ref)
    if current is None:
        print("CANNOT VERIFY  no ref resolves for what should be deployed")
        return CANNOT_CHECK

    if args.sha:
        deployed, note = args.sha, "baseline supplied on the command line"
    else:
        deployed, note = fetch_deployed_sha(args.url)
    if deployed is None:
        print(f"CANNOT VERIFY  {note}")
        return CANNOT_CHECK
    print(f"baseline: {note}")

    rc, kind = git("cat-file", "-t", deployed)
    if rc != 0 or kind.strip() != "commit":
        print(
            f"CANNOT VERIFY  the box reports deployed_sha {deployed[:12]}, which this clone "
            f"cannot resolve to a commit. Fetch it before reading this gate; a missing commit "
            f"would otherwise compare as total drift."
        )
        return CANNOT_CHECK

    paths = mapped_paths(current)
    if not paths:
        print(
            f"CANNOT VERIFY  the deploy map enumerated 0 file(s) at {current}, so there was "
            f"nothing to compare and a clean result would mean nothing."
        )
        return CANNOT_CHECK

    matched, drifted, undeployed = [], [], []
    for path in paths:
        want = blob_at(current, path)
        got = blob_at(deployed, path)
        if want is None:
            continue
        if got is None:
            undeployed.append(path)
        elif got == want:
            matched.append(path)
        else:
            drifted.append(path)

    total = len(matched) + len(drifted) + len(undeployed)
    print(
        f"deployed_sha {deployed[:12]} vs {current}: "
        f"{len(matched)} match, {len(drifted)} drifted, {len(undeployed)} never deployed, "
        f"of {total} mapped file(s)"
    )

    # The inline positive control. Nothing matching is what a wrong ref, an empty tree or a sha
    # from an unrelated project all look like, and each of those prints a full drift list that
    # reads exactly like a real finding.
    if total and not matched:
        print(
            "CANNOT VERIFY  not one mapped file matched. That is the signature of a broken "
            "lookup rather than of a box that shares no file with main, so this run proves "
            "nothing about the deploy."
        )
        return CANNOT_CHECK

    if not drifted and not undeployed:
        print(f"PASS  the box is running the same content as {current}")
        return 0

    for path in drifted:
        print(f"  DRIFTED         {path}")
    for path in undeployed:
        print(f"  NEVER DEPLOYED  {path}")
    print(
        f"\nFAIL  {len(drifted) + len(undeployed)} of {total} mapped file(s) on the box are "
        f"not what {current} says they should be.\n"
        "      This is a finding about the BOX, not about this repo: the fix is a deploy, and\n"
        "      nothing in the tree should be changed to make it green. Until it lands, every\n"
        "      guard those files carry is documented and not running, and the box's own\n"
        "      self-check stays green because it compares the box to the commit it was\n"
        "      deployed from rather than to this one."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
