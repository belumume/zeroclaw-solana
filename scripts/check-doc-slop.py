#!/usr/bin/env python3
"""Gate: tracked markdown carries none of the AI-slop markers this repo claims to be free of.

WHY THIS IS TRACKED, when a checker for it already existed. The compliance ledger asserts
slop-cleanliness across the judge-facing documents, and the only checker lived in `.tools/`,
which `.gitignore` line 28 ignores wholesale. A clone therefore received the claim and no way
to check it. No CI job ran it either: this repo gated rustfmt across all 16 tracked crates and
gated nothing on prose. That is the shape of a control that is claimed, asserted, and enforced
by no runtime path, which is the defect class this project filed ten times upstream.

SCOPE IS DISCOVERED, never hand-listed. `git ls-files` over the markdown suffixes is the source
of truth, for the same reason the `fmt` job derives its crate list: a document added later joins
no hand-written list by itself, and that is precisely how a gate's real scope drifts below the
surface it advertises while every run keeps printing green.

THE THREE EXEMPTIONS. Each is a NARROWING, so each is stated as a condition a machine evaluates,
never as a judgement about intent. An escape whose condition needs semantic reading collapses to
firing always or never, and in the failing direction it exempts the exact class the gate exists
to catch.

  1. FENCED CODE BLOCKS. Command output and config samples are quoted material; rewriting a
     command to please a prose checker changes what the reader is told to run. An unbalanced
     fence is REFUSED rather than tolerated, because an unclosed fence silently exempts the whole
     tail of a document and the run still looks clean.

  2. BLOCKQUOTE LINES. `docs/transcripts/injection-refund-redirect.md` is the prompt-injection
     evidence the brief requires, and its six em-dashes are all inside `>` lines, which are the
     agent's recorded replies. Editing them would falsify the evidence. This is the case most
     worth getting right: the transcript's value is that it is a verbatim record.

  3. VENDORED INTERFACE DOCS, by explicit path, and BOUNDED rather than skipped. `wit/VERSIONING.md`
     and `wit/v0/README.md` are upstream-authored. Verified rather than assumed: both were fetched
     from zeroclaw-labs/zeroclaw and carry the identical marker counts (6 and 2 em-dashes, 4 and 0
     rightwards arrows), while the only local divergence is prose about the three `@unstable`
     feature gates, which contains no marker at all.

     A blanket path skip would be the wrong shape here. It would leave the gate silent if someone
     later edited those files and added slop, which is an exemption that disables the gate for a
     whole file. Instead each vendored path carries the marker counts present in the upstream copy,
     and anything ABOVE that baseline is ours and is reported. The exemption covers the inherited
     text and nothing else.

EXIT CODES, matching the sibling gates in this directory:
  0  scanned, nothing found
  1  slop found in tracked prose
  2  the gate could not do its job (floor breached, unbalanced fence, git unreadable)

Two and zero must never be the same number. A gate that could not read its inputs and a gate that
read them and found nothing are indistinguishable downstream, and only one of them is good news.

Run: python3 scripts/check-doc-slop.py
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

CLEAN = 0
FOUND = 1
CANNOT = 2

# A FLOOR, not a target. The repo tracked 29 markdown documents when this gate was written.
# Adding documents is fine and raises the real count; a run that discovers FEWER than this has a
# broken discovery step, and without the floor it would print a perfect result over nothing.
EXPECTED_MIN_DOCS = 30

# WAS markdown-only, and that made every "N/N documents are clean" statement a claim about
# markdown rather than about the judge-facing set. index.html is the GitHub Pages landing page and
# one of the submission form's five links, and this gate had never scanned it -- the word "html"
# appeared nowhere in this file. A gate whose scope is narrower than the surface it reports on does
# not merely miss things, it reports green about the part it can see and says nothing about the
# rest, which downstream is indistinguishable from covering everything.
PROSE_SUFFIXES = (".md", ".markdown", ".mdx", ".html")

# Upstream-authored, vendored verbatim. Values are the marker counts present in the upstream copy
# at zeroclaw-labs/zeroclaw, measured rather than estimated. Anything above these is local and is
# reported. Reason is carried beside the path so a reader never has to guess why it is listed.
#
# THESE ARE POST-EXEMPTION COUNTS, which is the basis the comparison actually uses, and getting that
# wrong is not a rounding error, it is slack the gate hands to the next person who adds slop.
# rogue_unicode here was originally 4, taken from the RAW file, while two of those four arrows sit
# inside a fenced block that the exemption blanks before counting. The gate therefore compared a
# post-exemption 2 against a declared 4 and would have absorbed the first TWO rogue characters added
# to that file in silence. A baseline must be measured through the same pipeline that will later be
# compared against it, or the difference between the two bases is free slop.
VENDORED_BASELINE = {
    "wit/VERSIONING.md": {
        "reason": "upstream zeroclaw-labs/zeroclaw wit/VERSIONING.md, vendored in the initial commit",
        "counts": {"em_dashes": 6, "rogue_unicode": 2},
    },
    "wit/v0/README.md": {
        "reason": "upstream zeroclaw-labs/zeroclaw wit/v0/README.md, vendored in the initial commit",
        "counts": {"em_dashes": 2},
    },
}

FLAGGED_VOCAB = [
    "actionable",
    "comprehensive",
    "subsequent",
    "leverage",
    "delve",
    "tapestry",
    "facilitate",
    "utilize",
    "enhance",
    "streamline",
    "robust",
]

# Kept as codepoints so this file stays ASCII and cannot itself trip a reviewer's eye, and so
# printing never crashes on a cp1252 console.
ROGUE_UNICODE = [
    "→",  # rightwards arrow
    "•",  # bullet
    "★",  # black star
    "◆",  # black diamond
    "●",  # black circle
    "▸",  # black right-pointing small triangle
    "‣",  # triangular bullet
    "⟶",  # long rightwards arrow
    "⇒",  # rightwards double arrow
    "※",  # reference mark
    "◊",  # lozenge
]

EM_DASH = "—"

# These mirror .tools/slop_check.py exactly, so the 25-clean / 4-flagged baseline measured with
# that helper transfers to this gate unchanged. Tightening any of them is a WIDENING and would
# need its own controls plus a re-measurement of every document, so it is deliberately not done
# here. One known looseness is recorded rather than silently fixed: `\benhance\b` does not match
# "enhanced", because the trailing letter removes the word boundary.
#
# A SECOND looseness, recorded 2026-08-04 because a clean run on this check is easy to read as
# more than it is. `negative_contrast` matches ONE form, "not just X but Y". It does NOT match
# the two commoner ones, "X, not Y" and "X rather than Y", so a document reported clean here may
# still carry them, and a blind review of ONE-PAGER.md found three that this gate passed.
#
# That is deliberate rather than pending. Both missing forms are ordinary technical English and
# carry real information most of the time: this very file says "recorded rather than silently
# fixed" and "REFUSED rather than tolerated", and the corpus is full of "verified rather than
# assumed". A pattern broad enough to catch the slop would flag all of those, and a gate that
# cries wolf gets routed around, which is worse than no gate. Whether a contrast carries
# information or manufactures emphasis is a judgement, and judgement is the one thing a
# deterministic check must not be asked for. Read the prose; do not widen this.
CHECKS = [
    ("em_dashes", re.escape(EM_DASH), 0),
    ("rogue_unicode", "[" + "".join(re.escape(c) for c in ROGUE_UNICODE) + "]", 0),
    ("flagged_vocab", r"\b(?:" + "|".join(FLAGGED_VOCAB) + r")\b", re.I),
    (
        "templated_openers",
        r"\b(in this (section|paper|article|report)|this section (presents|describes|introduces)|"
        r"we (present|propose|introduce) a (novel|new|comprehensive|robust))",
        re.I,
    ),
    (
        "ai_hedging",
        r"\b(to the best of our knowledge|it should be noted that|"
        r"it is (worth|important) (to )?not(e|ing) that|various approaches have been proposed)\b",
        re.I,
    ),
    (
        "unverifiable_certainty",
        r"\b(it is well[- ]known that|it has been (shown|demonstrated) that|as widely recognized)\b",
        re.I,
    ),
    (
        "reflex_openers",
        r"^\s*(Yes|Certainly|Absolutely|Of course|Great question)[,!:]",
        re.M,
    ),
    ("negative_contrast", r"\bnot just \w+ but\b", re.I),
    (
        "empty_closers",
        r"\b(hope this helps|happy to discuss|let me know if you have questions|"
        r"looking forward to|don'?t hesitate)\b",
        re.I,
    ),
    ("adr_ids", r"\b(?:ADR|DECISION|RFC-INT)-?\d+\b", 0),
    # The digit in the lookbehind excludes ISO-8601 timestamps, where the date and time join on a
    # literal T; the trailing guard excludes a bare clock time for the same reason.
    ("task_ids", r"(?<![A-Za-z0-9])T\d{2,4}\b(?!:)", 0),
    ("file_line_cites", r"\b[a-zA-Z_][a-zA-Z0-9_]*\.py:\d+", 0),
    (
        "session_refs",
        r"\b(?:per|after|pre-?|post-?)\s*(?:session\s*\d+|compact(?:ion)?)",
        re.I,
    ),
    (
        "process_revealing",
        r"\b(verified empirically|one-time approved|across multiple sessions)\b",
        re.I,
    ),
]

FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})")
BLOCKQUOTE = re.compile(r"^ {0,3}>")


def repo_root(cwd=None):
    """Resolve the work tree root, so the gate answers the same way from any subdirectory."""
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if out.returncode != 0:
        return None
    return Path(out.stdout.strip())


def discover_docs(root):
    """Every tracked markdown path, from the index rather than from a hand-written list."""
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if out.returncode != 0:
        return None
    docs = [
        line.strip()
        for line in out.stdout.splitlines()
        if line.strip().lower().endswith(PROSE_SUFFIXES)
    ]
    return sorted(docs)


def blank_exempt_regions(text):
    """Blank fenced code and blockquote lines, keeping line count so numbers stay true.

    Returns (blanked_text, unclosed_fence_line). A non-None second value means a fence opened and
    never closed, so everything after it was exempted; the caller refuses the run rather than
    reporting a clean result over an unknown amount of skipped prose.
    """
    lines = text.split("\n")
    out = []
    fence_char = None
    fence_len = 0
    fence_line = 0
    for idx, line in enumerate(lines, start=1):
        if fence_char is None:
            opened = FENCE_OPEN.match(line)
            if opened:
                marker = opened.group(1)
                fence_char, fence_len, fence_line = marker[0], len(marker), idx
                out.append("")
                continue
            if BLOCKQUOTE.match(line):
                out.append("")
                continue
            out.append(line)
        else:
            closer = re.compile(
                r"^ {0,3}" + re.escape(fence_char) + "{" + str(fence_len) + r",}\s*$"
            )
            if closer.match(line):
                fence_char = None
            out.append("")
    return "\n".join(out), (fence_line if fence_char is not None else None)


def scan_text(text):
    """Run every check over already-exempted text. Returns {check: [line numbers]}."""
    found = {}
    for name, pattern, flags in CHECKS:
        lines = [
            text.count("\n", 0, m.start()) + 1
            for m in re.finditer(pattern, text, flags)
        ]
        if lines:
            found[name] = lines
    return found


def scan_doc(root, rel):
    """Scan one document. Returns (findings, unclosed_fence_line, read_error)."""
    path = root / rel
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {}, None, str(exc)
    blanked, unclosed = blank_exempt_regions(raw)
    found = scan_text(blanked)
    baseline = VENDORED_BASELINE.get(rel.replace("\\", "/"))
    if baseline:
        allowed = baseline["counts"]
        trimmed = {}
        for check, lines in found.items():
            budget = allowed.get(check, 0)
            excess = lines[budget:]
            if excess:
                trimmed[check] = excess
        found = trimmed
    return found, unclosed, None


def run(root, docs=None, min_docs=EXPECTED_MIN_DOCS):
    """Returns (exit_code, report_lines)."""
    report = []
    if docs is None:
        docs = discover_docs(root)
    if docs is None:
        return CANNOT, ["git ls-files failed; scope could not be derived"]

    unreadable = []
    unbalanced = []
    dirty = {}
    for rel in docs:
        found, unclosed, err = scan_doc(root, rel)
        if err:
            unreadable.append((rel, err))
            continue
        if unclosed is not None:
            unbalanced.append((rel, unclosed))
        if found:
            dirty[rel] = found

    for rel in sorted(VENDORED_BASELINE):
        if rel not in docs:
            unreadable.append(
                (rel, "listed as vendored but not tracked; baseline is dead")
            )

    for rel, err in unreadable:
        report.append(f"CANNOT READ  {rel}: {err}")
    for rel, line in unbalanced:
        report.append(
            f"UNBALANCED FENCE  {rel}:{line} opened and never closed, "
            f"so the rest of the document was exempted"
        )
    for rel in sorted(dirty):
        for check in sorted(dirty[rel]):
            lines = dirty[rel][check]
            shown = ", ".join(str(n) for n in lines[:6])
            more = "" if len(lines) <= 6 else f" (+{len(lines) - 6} more)"
            report.append(f"SLOP  {rel}: {check} x{len(lines)} at line {shown}{more}")

    scanned = len(docs)
    if scanned < min_docs:
        report.append(
            f"FLOOR  discovered {scanned} tracked prose documents, expected at least "
            f"{min_docs}. Refusing to report a result over a scope this small."
        )
        report.append(
            f"{scanned}/{scanned} scanned, but the discovery step is not trustworthy"
        )
        return CANNOT, report

    if unreadable or unbalanced:
        report.append(
            f"{scanned} documents discovered; the gate could not scan all of them"
        )
        return CANNOT, report

    if dirty:
        report.append(
            f"{scanned - len(dirty)}/{scanned} tracked prose documents are clean"
        )
        report.append(
            f"{len(dirty)} carry slop markers outside code fences and blockquotes"
        )
        return FOUND, report

    exempt = len(VENDORED_BASELINE)
    report.append(f"{scanned}/{scanned} tracked prose documents are clean")
    report.append(
        f"fenced code and blockquote lines exempted throughout; "
        f"{exempt} vendored paths bounded by their upstream marker counts"
    )
    return CLEAN, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--min-docs",
        type=int,
        default=EXPECTED_MIN_DOCS,
        help="floor on discovered documents; the control suite raises or lowers it to drive "
        "the branch, CI never passes it",
    )
    args = parser.parse_args(argv)

    root = repo_root()
    if root is None:
        print("CANNOT: not inside a git work tree", file=sys.stderr)
        return CANNOT

    code, report = run(root, min_docs=args.min_docs)
    for line in report:
        print(line.encode("ascii", "backslashreplace").decode("ascii"))
    return code


if __name__ == "__main__":
    sys.exit(main())
