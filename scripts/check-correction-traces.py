"""Correction traces on judge-facing surfaces: the edit process leaking into the artifact.

A published document carries its CURRENT claims. It does not narrate that a claim used to be
different, when it was fixed, or who caught it. Nobody reading a blog post, a paper or a bounty
submission asked for the review history, and a reader who sees one wonders what else moved.

THE LINE THIS ENFORCES, because the two are easy to conflate and only one is a defect:

  PRODUCT-LEVEL HONESTY  -> KEEP. It is scored, and this listing scores it at 25%.
      "That ARM box is a rented VM."
      "The reading comes from a weather API, not a physical probe."
      "The original justification for that demotion was wrong: the real failure is a
       well-formed URL carrying somebody else's recipient."
    These are facts about the ARTIFACT that a reader needs to evaluate it. The last one
    discloses a reasoning error about the SECURITY MODEL, which is exactly what the
    custody axis asks for.

  EDITORIAL PROCESS      -> CUT. Nobody asked.
      "This paragraph previously read ..."
      "The same query on 2026-08-04 returned fourteen, so ..."
      "Corrected 2026-08-06 after an audit found ..."
      "This row was first written as ..."
    These are facts about the DOCUMENT'S HISTORY. They serve the author, not the reader.

The discriminator is the SUBJECT: if the sentence's subject is the text itself (a paragraph, a
row, a claim, a figure, an earlier version) rather than the system being described, it is a trace.

Usage:  python .tools/check-correction-traces.py [--all]
        --all also prints the spans it deliberately allowed, so the carve-outs stay auditable.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The surfaces a judge reaches from the submission. Internal files are excluded on purpose:
# the handoff and the ledgers SHOULD carry correction history, that is their whole job.
JUDGE_FACING = [
    "README.md",
    "TESTING.md",
    "QUICKSTART.md",
    "index.html",
    "docs/WRITEUP.md",
    "docs/ONE-PAGER.md",
    "docs/HOST-SECURITY-AUDIT.md",
    "docs/DECISIONS.md",
    "docs/DEVNET-PROOF.md",
]

TRACE = [
    (
        "previously-read",
        r"\b(?:this|the)\s+(?:paragraph|sentence|section|row|line|page|figure|table|claim|number|count|README|write-?up)\s+"
        r"(?:previously|originally|once|formerly|used to)\s+(?:read|said|stated|claimed)\b",
    ),
    (
        "earlier-version",
        r"\ban earlier (?:version|draft|pass|revision) (?:of this|said|read|claimed)\b",
    ),
    ("corrected-on", r"\b(?:CORRECTED|Corrected|corrected)\s+\d{4}-\d{2}-\d{2}\b"),
    ("retracted-on", r"\b(?:RETRACTED|Retracted|retracted)\s+\d{4}-\d{2}-\d{2}\b"),
    (
        "was-first-written",
        r"\b(?:was|were)\s+(?:first|initially|originally)\s+(?:written|recorded|stated|filed)\s+as\b",
    ),
    ("this-row-said", r"\b(?:this|that)\s+row\s+(?:said|read|carried|previously)\b"),
    (
        "an-audit-found",
        r"\ban (?:audit|auditor|review|reviewer|agent|lens|panel)\s+(?:found|caught|flagged|pointed out|reported)\b",
    ),
    (
        "i-had-written",
        r"\bI\s+(?:had\s+)?(?:wrote|written|claimed|asserted|recorded)\s+(?:that|this|it)\b",
    ),
    (
        "we-corrected",
        r"\bwe\s+(?:corrected|fixed|retracted|reworded|rewrote)\s+(?:this|that|it|the (?:claim|figure|number|wording))\b",
    ),
    (
        "session-ref",
        r"\b(?:per|after|during|in)\s+(?:session\s*\d+|the\s+\w+\s+session|a\s+compaction|compaction)\b",
    ),
    (
        "the-old-number",
        r"\bthe\s+(?:old|previous|former|stale)\s+(?:number|figure|count|value|wording|claim)\b",
    ),
    ("used-to-say", r"\bused to (?:say|read|claim|state)\b"),
]

# One probe per pattern, so each is proven to fire on its own rather than riding on a sibling.
# Every probe is written sentence-initial and capitalised, which is how a real trace appears and
# is exactly the shape the case-sensitive matcher used to miss.
CONTROL_SAMPLES = {
    "previously-read": "This paragraph previously read something weaker.",
    "earlier-version": "An earlier draft said the opposite.",
    "corrected-on": "CORRECTED 2026-08-14 after the figure moved.",
    "retracted-on": "Retracted 2026-08-14 once the premise failed.",
    "was-first-written": "The count was originally written as nine.",
    "this-row-said": "This row said the feed had stopped.",
    "an-audit-found": "An audit found the citation was dead.",
    "i-had-written": "I had claimed that the gap only grows.",
    "we-corrected": "We corrected the figure after the sweep.",
    "session-ref": "After a compaction the number was restated.",
    "the-old-number": "The old figure understated the interruption.",
    "used-to-say": "It used to say the device was live.",
}

# Spans that MATCH a pattern above and are deliberately kept, each with the reason.
# A carve-out is only legitimate when the sentence is about the SYSTEM, not about the document.
ALLOW = [
    (
        "docs/WRITEUP.md",
        "The original justification for that demotion was wrong",
        "product-level: discloses a reasoning error in the SECURITY MODEL, which the custody axis "
        "explicitly scores. The subject is the design decision, not the document.",
    ),
]


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def allowed(path: str, window: str) -> str | None:
    for a_path, a_span, why in ALLOW:
        if a_path == path and a_span in window:
            return why
    return None


def main() -> int:
    show_all = "--all" in sys.argv
    findings, waived, missing = [], [], []

    for rel in JUDGE_FACING:
        p = REPO / rel
        if not p.exists():
            missing.append(rel)
            continue
        text = normalise(p.read_text(encoding="utf-8", errors="replace"))
        for name, pat in TRACE:
            # CASE-INSENSITIVE, because every pattern here begins with a lowercase determiner
            # ("this paragraph", "an earlier draft") while a real trace is almost always
            # sentence-initial and capitalised. Matching case-sensitively made the most common
            # form of the defect structurally invisible.
            for m in re.finditer(pat, text, re.I):
                lo = max(0, m.start() - 110)
                window = text[lo : m.end() + 110]
                why = allowed(rel, window)
                (waived if why else findings).append((rel, name, window.strip(), why))

    if missing:
        print(f"NOTE: {len(missing)} listed surface(s) absent: {', '.join(missing)}")

    # A checker that can never fail is not a checker. Prove EVERY pattern fires.
    #
    # An any() across all patterns is not a control: one healthy pattern certifies eleven dead
    # ones, and the sample below happens to match a different pattern than the one it appears to
    # test. Each pattern now carries its own probe and each is asserted individually.
    for name, pat in TRACE:
        probe = CONTROL_SAMPLES.get(name)
        if probe is None:
            print(
                f"FAIL  pattern {name!r} has no positive control; "
                f"an untested pattern cannot be trusted to fire.",
                file=sys.stderr,
            )
            return 2
        if not re.search(pat, normalise(probe), re.I):
            print(
                f"FAIL  positive control for {name!r} did not fire; that pattern is dead.",
                file=sys.stderr,
            )
            return 2

    print(
        f"scanned {len(JUDGE_FACING) - len(missing)} judge-facing surface(s); "
        f"positive control fires"
    )

    if show_all and waived:
        print(f"\ndeliberately allowed ({len(waived)}):")
        for rel, name, window, why in waived:
            print(f"  {rel} [{name}]\n     ...{window[:150]}...\n     KEPT: {why}")

    if not findings:
        print("\nOK  no correction traces on judge-facing surfaces.")
        return 0

    print(
        f"\n{len(findings)} correction trace(s) — the edit process leaking into the artifact:\n"
    )
    for rel, name, window, _ in findings:
        print(f"  {rel} [{name}]")
        print(f"     ...{window[:190]}...\n")
    print("Each is either a PRODUCT fact (rewrite so its subject is the system) or")
    print("EDITORIAL history (cut it; the handoff is where that belongs).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
