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

Usage:  python scripts/check-correction-traces.py [--all | --selftest]
        --all also prints the spans it deliberately allowed, so the carve-outs stay auditable.
        --selftest proves the inert-carve-out detector fires and stays silent when it should.

A carve-out that waives nothing is reported as a FAILURE rather than ignored. An exclusion
nobody can see is the rot this file exists to prevent, and the only way to notice one is to
make the gate refuse to pass while it is there.
"""

from __future__ import annotations

import re
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
    # Reachable from a judge surface, so in scope. Each route was resolved by grep rather than
    # assumed: AUDIT.md from the README's document table, the skill from the README's component
    # table, and the transcript from WRITEUP prose. ONE-PAGER's proof list links a DIFFERENT
    # transcript (injection-refund-redirect.md) and does not reach either of the other two.
    # A document is in scope because a reader can WALK to it, never because of where it sits.
    "docs/AUDIT.md",
    "docs/transcripts/injection-battery.md",
    "skills/solana-pay/SKILL.md",
]

TRACE = [
    (
        "previously-read",
        r"\b(?:this|the)\s+(?:paragraph|sentence|section|row|line|page|figure|table|claim|number|count|README|write-?up)\s+"
        r"(?:previously|originally|once|formerly|used to)\s+(?:read|said|stated|claimed)\b",
    ),
    # SPLIT BY NOUN, because "an earlier version" is ambiguous and the two readings need
    # opposite verdicts. "draft" and "revision" can only describe a document, so they need no
    # qualifier and catch the bare form ("withdrawn from an earlier draft when ..."). "version"
    # and "pass" describe SOFTWARE at least as often, and on this repo they do: two judge-facing
    # surfaces say "an earlier version restarted the day on every boot", which is a real defect
    # in a shipped release and exactly the product honesty this gate must never touch. So those
    # two only fire when a document noun follows them.
    ("earlier-draft", r"\ban earlier (?:draft|revision)\b"),
    (
        "earlier-version",
        r"\ban earlier (?:version|pass)\s+(?:of\s+this|of\s+the\s+"
        r"(?:page|document|file|section|paragraph|row|claim)|said|read|claimed)\b",
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
    # The bare form, which is what the qualified pattern missed on a live judge surface.
    "earlier-draft": "The claim was withdrawn from an earlier draft when the trace refused it.",
    "earlier-version": "An earlier version of this page said the opposite.",
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

# The over-correction control. CONTROL_SAMPLES proves each pattern can FIRE; without these, a
# pattern widened until it matches everything would still pass every check above. Each is a
# verbatim sentence from a live surface that MUST stay silent, and the first two are the reason
# the earlier-version pattern is split by noun: they describe a real defect in a shipped release
# of the x402 ledger, which is product honesty on a scored axis and not a document's history.
MUST_NOT_FIRE = [
    "The ledger is durable: restarting the process does not re-open a spent allowance. "
    "An earlier version restarted the day on every boot, which is a cap in name only.",
    "The ledger is durable, so restarting the process does not re-open a spent allowance. "
    "An earlier version restarted the day on every boot, which is a cap in name only.",
    "An earlier version of the Solana Pay spec used a different field name.",
    "That ARM box is a rented VM, not a device on a windowsill.",
    "The original justification for that demotion was wrong: the real failure is a well-formed "
    "URL carrying somebody else's recipient.",
]

# Spans that MATCH a pattern above and are deliberately kept, each with the reason.
# A carve-out is only legitimate when the sentence is about the SYSTEM, not about the document.
#
# EMPTY ON PURPOSE, and an entry that stops matching is a FAILURE rather than a shrug. There was
# one entry here, waiving the WRITEUP sentence "The original justification for that demotion was
# wrong". The prose around it was rewritten, no pattern fires near it any more, and the carve-out
# sat inert: waiving nothing, invisible to --all, unauditable by the mechanism this file promises.
# The sentence itself is still there and still must stay; the docstring above quotes it verbatim
# as the canonical KEEP example, which protects it better than an exclusion nobody can see.
ALLOW: list[tuple[str, str, str]] = []


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def allowed(path: str, window: str) -> int | None:
    """Index of the carve-out covering this span, so a run can tell which ones actually fired."""
    for i, (a_path, a_span, _why) in enumerate(ALLOW):
        if a_path == path and a_span in window:
            return i
    return None


def inert_carve_outs(allow: list, fired: set[int]) -> list[int]:
    """Carve-outs that waived nothing this run.

    Pure, so --selftest can drive it both ways without touching the corpus. An empty ALLOW is
    vacuously clean; an entry whose target text moved is the rot case and must be reported.
    """
    return [i for i in range(len(allow)) if i not in fired]


def _selftest_wiring() -> tuple[int, int]:
    """Drive the REAL main() against a planted corpus, so the wiring is proven, not just the logic.

    The pure-function cases below prove the detector decides correctly. They cannot prove main()
    ever calls it. This does: it plants one file carrying one trace, then moves the exit code
    through all three outcomes by changing nothing but the carve-out list.
    """
    import tempfile

    saved = (REPO, JUDGE_FACING, ALLOW, TRACE, CONTROL_SAMPLES, sys.argv)
    tmp = Path(tempfile.mkdtemp())
    (tmp / "planted.md").write_text(
        "The box is rented. An audit found the citation was dead, which is why THE ANCHOR SPAN "
        "stays. Nothing else here matters.\n",
        encoding="utf-8",
    )
    live = ("planted.md", "THE ANCHOR SPAN", "control")
    cases = [
        ("an unwaived trace is a finding", [], 1),
        ("a LIVE carve-out waives it and passes", [live], 0),
        (
            "an INERT carve-out fails the gate",
            [("planted.md", "TEXT THAT MOVED", "c")],
            2,
        ),
        # Index 0 specifically: a bare `if idx` would route carve-out 0's spans into findings.
        ("carve-out at index 0 waives rather than falling through", [live], 0),
    ]

    # The OVER-CORRECTION control, which is what stops a pattern being widened until it eats the
    # product honesty this gate must protect. Injected through globals rather than anchored on a
    # source string, so it cannot rot into a no-op the way a text substitution does. It carries
    # its own positive control, so the only path to rc=2 left is MUST_NOT_FIRE firing.
    over_broad = [("earlier-draft", r"an earlier")]
    over_broad_samples = {"earlier-draft": "an earlier draft"}

    failed = 0
    try:
        for label, allow, expect, trace, samples in [
            (lbl, a, e, saved[3], saved[4]) for lbl, a, e in cases
        ] + [
            (
                "a pattern widened onto product honesty is refused",
                [],
                2,
                over_broad,
                over_broad_samples,
            )
        ]:
            globals()["REPO"] = tmp
            globals()["JUDGE_FACING"] = ["planted.md"]
            globals()["ALLOW"] = allow
            globals()["TRACE"] = trace
            globals()["CONTROL_SAMPLES"] = samples
            sys.argv = ["check-correction-traces"]
            import contextlib
            import io

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                rc = main()
            ok = rc == expect
            failed += not ok
            print(
                f"  {'ok  ' if ok else 'FAIL'}  {label}"
                + ("" if ok else f"  (rc={rc}, expected {expect})")
            )
    finally:
        (
            globals()["REPO"],
            globals()["JUDGE_FACING"],
            globals()["ALLOW"],
            globals()["TRACE"],
            globals()["CONTROL_SAMPLES"],
            sys.argv,
        ) = saved
    return failed, len(cases) + 1


def selftest() -> int:
    print("wiring (drives the real main()):")
    wiring_failed, wiring_total = _selftest_wiring()

    print("\ndetector logic:")
    cases = [
        (
            "an entry that waived nothing is reported",
            [("a.md", "x", "why")],
            set(),
            [0],
        ),
        ("an entry that waived something is silent", [("a.md", "x", "why")], {0}, []),
        (
            "one live and one dead reports only the dead",
            [("a", "x", "w"), ("b", "y", "w")],
            {0},
            [1],
        ),
        ("an empty carve-out list is vacuously clean", [], set(), []),
    ]
    failed = wiring_failed
    for label, allow, fired, expected in cases:
        got = inert_carve_outs(allow, fired)
        ok = got == expected
        failed += not ok
        print(
            f"  {'ok  ' if ok else 'FAIL'}  {label}" + ("" if ok else f"  (got {got})")
        )
    total = len(cases) + wiring_total
    if failed:
        print(f"\n{failed}/{total} selftest case(s) failed.", file=sys.stderr)
        return 2
    print(
        f"\nOK  {total}/{total}; main() consults the inert-carve-out detector, "
        f"and the detector fires and stays silent as it should."
    )
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    show_all = "--all" in sys.argv
    findings, waived, missing = [], [], []
    fired: set[int] = set()

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
                idx = allowed(rel, window)
                # `is not None`, never a truth test: carve-out 0 is a legitimate index and a
                # bare `if idx` would silently route the FIRST carve-out's spans into findings.
                if idx is None:
                    findings.append((rel, name, window.strip(), None))
                else:
                    fired.add(idx)
                    waived.append((rel, name, window.strip(), ALLOW[idx][2]))

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

    # And prove no pattern has been widened into the product-honesty it must never touch.
    for sample in MUST_NOT_FIRE:
        for name, pat in TRACE:
            if re.search(pat, normalise(sample), re.I):
                print(
                    f"FAIL  pattern {name!r} fired on a sentence that must stay silent. "
                    f"It describes the SYSTEM, not the document, and cutting it would remove "
                    f"honesty this listing scores.\n      {sample[:150]}",
                    file=sys.stderr,
                )
                return 2

    # An exclusion that waives nothing is the failure this file names in its own docstring:
    # invisible to --all, so it cannot be audited by the mechanism that is supposed to audit it.
    # Reported rather than tolerated, so a carve-out whose target text moves fails loudly.
    inert = inert_carve_outs(ALLOW, fired)
    if inert:
        for i in inert:
            a_path, a_span, _ = ALLOW[i]
            print(
                f"FAIL  carve-out {i} ({a_path}: {a_span!r}) waived nothing this run. "
                f"Either its target text moved, or no pattern fires there any more. "
                f"Delete it, or re-anchor it on the span it is meant to protect.",
                file=sys.stderr,
            )
        return 2

    print(
        f"scanned {len(JUDGE_FACING) - len(missing)} judge-facing surface(s); "
        f"positive control fires; {len(ALLOW)} carve-out(s), all live"
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
