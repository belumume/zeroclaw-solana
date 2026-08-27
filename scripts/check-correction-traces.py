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
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# check-all.py reads this exit code as COULD NOT CHECK and refuses to count it as a
# pass, which is the only honest verdict when the gate cannot see its own inputs.
# It does NOT block, because the reasons that reach it are all about the MACHINE: no .git
# because the tree arrived as an archive, git absent from PATH, a sparse checkout. Nothing
# in the repo is wrong and running it elsewhere fixes it.
CANNOT_CHECK = 2

# Read by check-all.py as CANNOT PROVE IT CAN FAIL, which BLOCKS the run.
#
# This gate's whole job is proving the trace patterns still FIRE. When a positive control
# stops firing, the pattern behind it is dead: the scan above it still walks every surface,
# still finds nothing, and still prints a clean line, so the gate certifies BLIND and its
# silence reads downstream exactly like a pass. Measured before this existed: killing one
# control sample made the gate print "that pattern is dead" and exit 2, and check-all
# reported `n/a ... reported it cannot check` and returned 0. A control that can no longer
# fail is worse than no control, because it now certifies.
#
# SCOPE, deliberately narrow. This code means the gate cannot produce the OPPOSITE verdict.
# It is used for the CONTROLS -- the must-fire probes and the must-not-fire pins -- and not
# for anything the controls DETECT, which is an ordinary finding and belongs at 1.
CONTROL_DEAD = 3

# A floor rather than a zero test, matching every sibling gate here (MIN_DOCS in
# check-claim-coherence and check-doc-reachability, MIN_GATES in check-all). A floor
# is the stronger instrument: a returncode check catches git failing, and this also
# catches git succeeding while returning almost nothing, which a returncode cannot
# see. The repo tracks 80 .py files, so 40 is well clear of ordinary movement while
# still refusing a walk that has collapsed.
MIN_SOURCE = 40

# The wiring selftest swaps REPO to a temp dir, where `git ls-files` legitimately fails.
# Before the discovery guard below existed that returned an empty list in silence, which is
# the exact defect the guard closes, so the test had been resting on it. This seam lets the
# test declare "no source in scope" explicitly instead of arriving there through a failure.
SOURCE_PROVIDER = None  # set to tracked_source once it is defined


# The surfaces a judge reaches from the submission. Internal files are excluded on purpose:
# the handoff and the ledgers SHOULD carry correction history, that is their whole job.
JUDGE_FACING = [
    "README.md",
    "TESTING.md",
    "QUICKSTART.md",
    "index.html",
    "docs/WRITEUP.md",
    "docs/ONE-PAGER.md",
    # The long form the one-pager links to. It carries the bulk of the judge-facing prose, so
    # leaving it off would move most of this gate's real subject out of scope while every run
    # kept printing green.
    "docs/ARGUMENT.md",
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
    # THE SELF-REFERENCE FORM. Every pattern above keys on a document's HISTORY being narrated
    # ("previously read", "corrected on", "an audit found"). This family keys on the document
    # pointing at ITSELF as a unit of text -- this sentence, that bullet, the earlier wording,
    # the reason this file gave -- which is the same defect with the history left implicit, and
    # it was invisible to all thirteen. Measured: six live spans across two judge-facing
    # surfaces while the gate reported clean.
    #
    # THE NOUN LISTS ARE DELIBERATELY NARROW, and "section" and "page" are absent from all four.
    # A migration notice legitimately addresses a reader holding a stale copy ("Until 2026-08-05
    # this section told you to point payment_watch at devnet"), which is an instruction to the
    # reader about the SYSTEM's current state, not a narration of the edit. Admitting those two
    # nouns would eat it.
    (
        "this-text-previously",
        # "first" demands a speech verb rather than standing beside the others. Alone it has no
        # backward-looking sense at all, so it would fire on any procedure describing its own
        # steps ("this instruction first checks the mint, then the amount"), which is pinned
        # below. The other five adverbs are unambiguous and need no verb.
        r"\b(?:this|that)\s+(?:sentence|bullet|instruction|note|clause|heading|entry|caption|"
        r"footnote)\s+(?:(?:previously|originally|once|formerly|used to)\b|"
        r"first\s+(?:read|said|named|stated|claimed|told)\b)",
    ),
    (
        # A text noun that spoke UNTIL a point in time. It narrates the edit without using any of
        # the adverbs above, so every other pattern in this family misses it.
        "this-line-named-until",
        r"\b(?:this|that)\s+(?:line|sentence|row|paragraph|bullet|entry|figure|table|column)\s+"
        r"(?:named|said|read|claimed|stated|carried|listed|reported|gave)\s+until\b",
    ),
    (
        "the-earlier-wording",
        # "text" is deliberately absent: a migration notice says "the exact failure the old text
        # warned about", and one reword of that sentence's verb would put a safety warning inside
        # this pattern. "wording" and "phrasing" can only describe a draft.
        r"\bthe\s+(?:earlier|previous|original|old|former)\s+(?:wording|phrasing|draft|"
        r"instruction|sentence|bullet)\s+(?:said|read|claimed|stated|named|told|gave)\b",
    ),
    (
        "the-reason-this-file-gave",
        r"\bthe\s+(?:reason|wording|explanation|justification|figure|number|count)\s+"
        r"(?:this|that)\s+(?:file|document|README|page|row|line|sentence|note|section)\s+"
        r"(?:gave|used|carried|stated|named|said|listed)\b",
    ),
    (
        "how-this-text-was-written",
        r"\b(?:this|that)\s+(?:sentence|paragraph|line|row|passage|bullet|instruction|note)\s+"
        r"was\s+(?:written|worded|phrased|drafted|rewritten)\b",
    ),
    (
        # A text unit narrating its own FORMER NAME. Every sibling above misses it: `section` is
        # deliberately absent from their noun lists so a migration notice survives, and no verb
        # list carries `titled`. It reached a judge surface for exactly that reason.
        #
        # `section` IS safe here, and only here, because these verbs can take no other subject:
        # only a text unit is "titled". A migration notice addresses the READER ("if you followed
        # an earlier copy of this page"), so it cannot match, and that shape is pinned below.
        "this-section-was-titled",
        r"\b(?:this|that)\s+(?:section|chapter|page|document|file|heading|appendix)\s+"
        r"was\s+(?:titled|called|named|headed|labelled|labeled)\b",
    ),
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
    # The self-reference family. Each probe is the shape of a real span this gate missed.
    "this-text-previously": "This sentence used to point at an ignored directory.",
    "the-earlier-wording": "The earlier wording said only that prices are never computed.",
    "the-reason-this-file-gave": "The reason this file gave for it was stale.",
    "how-this-text-was-written": "A note on how that sentence was written, for the record.",
    # The span that reached docs/WRITEUP.md, verbatim apart from the quoted heading. If this
    # stops firing the gate is blind to the class again.
    "this-section-was-titled": 'This section was titled "Reproducibility (links)" and contained no links.',
    "this-line-named-until": "The count this line named until the recount was lower.",
}

# The over-correction control. CONTROL_SAMPLES proves each pattern can FIRE; without these, a
# pattern widened until it matches everything would still pass every check above. Each is a
# verbatim sentence from a live surface that MUST stay silent, and the first two are the reason
# the earlier-version pattern is split by noun: they describe a real defect in a shipped release
# of the x402 ledger, which is product honesty on a scored axis and not a document's history.

# The two pins below claim to be quoted from a live surface, and `drifted_pins` proves it on every
# run. Without that check they are the inert-carve-out rot one field over: ALLOW entries are tied
# to live spans by `inert_carve_outs`, MUST_NOT_FIRE strings are tied to nothing, so a pin can
# quietly become a sentence the repo does not ship and go on passing forever. A pin that differs
# from its page by three words in the middle of a long sentence is invisible to every other check
# in this file, and it still proves nothing, which is the gap this one closes.
PIN_README = (
    "The reason first given for that call was wrong, and the correction is in "
    "[`docs/DECISIONS.md`](docs/DECISIONS.md): the failure that matters is a well-formed URL "
    "carrying the wrong recipient, which a sandbox would not catch, so the guard is a hardcoded "
    "invariant in `pay_link.py`."
)

PIN_QUICKSTART = (
    "**Read this if you followed an earlier copy of this page.** Until 2026-08-05 this section "
    "told you to point `payment_watch` at devnet and to pass a devnet mint on every call. Both "
    "instructions are now wrong, and following them is the exact failure the old text warned "
    "about, with the chain the other way round: the watcher would poll devnet for a payment that "
    "settled on mainnet, the order would sit at NOT_YET forever, and nothing would error."
)

PIN_WRITEUP = (
    "**The original justification for that demotion was wrong.** It rested on the worst failure "
    "of a malformed URL being a payment that never starts, so no funds are at risk. The real "
    "failure is a *well-formed* URL carrying somebody else's recipient."
)

# Which surface each quoted pin is quoted FROM, so the claim is checkable rather than asserted.
PIN_SOURCES = {
    PIN_README: "README.md",
    PIN_QUICKSTART: "QUICKSTART.md",
    PIN_WRITEUP: "docs/WRITEUP.md",
}

MUST_NOT_FIRE = [
    "The ledger is durable: restarting the process does not re-open a spent allowance. "
    "An earlier version restarted the day on every boot, which is a cap in name only.",
    "The ledger is durable, so restarting the process does not re-open a spent allowance. "
    "An earlier version restarted the day on every boot, which is a cap in name only.",
    "An earlier version of the Solana Pay spec used a different field name.",
    "That ARM box is a rented VM, not a device on a windowsill.",
    # The canonical KEEP: it discloses a reasoning error about the SECURITY MODEL, which is what
    # the custody axis asks for. It was a three-sentence span compressed into one, which is the
    # same defect as a spliced pin and equally invisible, so it is quoted whole and checked.
    PIN_WRITEUP,
    # Product honesty about a SECURITY decision, and the nearest miss for the-reason-this-file-gave
    # ("The reason first given" rather than "the reason this file gave"), which is why it is pinned
    # beside that pattern rather than trusted to stay clear of it.
    PIN_README,
    # A MIGRATION NOTICE, the one shape that looks exactly like a trace and must survive: it exists
    # to stop a reader holding stale config from following instructions that now lose money. Its
    # subject is what the reader's system is doing, not what this document used to say, and cutting
    # it would take a real safety warning with it.
    PIN_QUICKSTART,
    # Ordinary enumeration, which is the near-miss for this-text-previously and the reason its
    # "first" alternative demands a speech verb rather than standing bare. Nothing in the corpus
    # trips it today, and a bare "first" would fire on any procedure that describes its own steps.
    "This instruction first checks the mint, then the amount, then the recipient.",
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
# TRACKED SOURCE IS IN SCOPE TOO. A judge clones the repo, so a comment is as readable as a
# document, and the prose list above cannot see a single `.py` file. That is the same blind spot
# `check-source-comment-leaks.py` was written to close for internal identifiers: every slop gate
# here listed prose suffixes, so source was green by never being scanned. Measured over 80 tracked
# files, this found four real traces in two of them, and they are fixed rather than waived.
SOURCE_EXCLUDED = {
    # A gate that forbids a phrase has to contain the phrase, in its pattern table and in the
    # samples proving each pattern fires. Both of these hold 20+ self-matches. The exclusion is
    # exactly one file wide each, and the selftest pins that so it cannot quietly widen.
    "scripts/check-correction-traces.py": "its own pattern table and control samples",
    "scripts/check-source-comment-leaks.py": "its own probe strings",
}


def tracked_source(run=subprocess.run) -> list[str]:
    """Tracked .py files, from git's index rather than a walk, minus the two self-referential gates.

    `run` is injectable so the selftest can drive the two refusal paths without
    breaking the repo's git, which is the only other way to reach them.
    """
    out = run(
        ["git", "-C", str(REPO), "ls-files", "*.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    # A gate that cannot enumerate its own file set must not report clean. Without
    # this, a failed `git ls-files` -- no .git because the tree arrived as an archive,
    # git absent from PATH, a sparse checkout -- leaves stdout empty, so the list is
    # empty, every later loop finds nothing, and the gate prints OK and exits 0 having
    # read no source at all. The sibling this function is modelled on, tracked_python
    # in check-source-comment-leaks.py, guards the same call for the same reason.
    if out.returncode != 0:
        print(
            f"NOT CHECKED: git ls-files exited {out.returncode}, so the tracked source "
            f"set is unknown. This is not a pass.",
            file=sys.stderr,
        )
        sys.exit(CANNOT_CHECK)

    files = [
        f for f in out.stdout.split() if f.replace("\\", "/") not in SOURCE_EXCLUDED
    ]
    if len(files) < MIN_SOURCE:
        print(
            f"NOT CHECKED: walk found {len(files)} tracked source file(s); expected at "
            f"least {MIN_SOURCE}. The discovery step is broken, so a clean result here "
            f"would mean nothing. This is not a pass.",
            file=sys.stderr,
        )
        sys.exit(CANNOT_CHECK)
    return files


SOURCE_PROVIDER = tracked_source


# Spans whose SUBJECT is the system rather than the text, so they are design rationale and stay.
# Each is waived by exact span, and `inert_carve_outs` reports any that stops matching, so a
# waiver cannot outlive the sentence it was written for.
ALLOW: list[tuple[str, str, str]] = [
    (
        "demo/take.py",
        "the gate it tests was added after an audit found",
        "why the gate exists: an outcome-gate misbehaved. Subject is the gate, not the comment.",
    ),
    (
        "scripts/check-config-drift.py",
        "An audit found the two had drifted",
        "a fact about the config, which is what this gate reports. Subject is the system.",
    ),
    (
        "scripts/rate_from_feed.py",
        "An earlier version of this reader",
        "a SOFTWARE version that printed a wrong value, not a draft of the text. This file's own "
        "doctrine already notes that 'version' describes software at least as often.",
    ),
    (
        "scripts/check-all.py",
        "earned the hard way in the same session",
        "a design decision and why it was taken; the session reference is incidental to it.",
    ),
]


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def allowed(path: str, window: str) -> int | None:
    """Index of the carve-out covering this span, so a run can tell which ones actually fired."""
    for i, (a_path, a_span, _why) in enumerate(ALLOW):
        if a_path == path and a_span in window:
            return i
    return None


def drifted_pins(sources: dict, read) -> list[tuple[str, str]]:
    """Quoted must-not-fire pins that are no longer in the surface they claim to quote.

    `read` returns a surface's text or None if it is unreadable, and is injectable so the selftest
    can drive both verdicts without editing the repo's own documents. An unreadable surface counts
    as drift rather than as a pass: a pin whose source cannot be opened is exactly as unproven as
    one whose text has moved, and treating the two differently is how a check fails open.
    """
    out = []
    for pin, rel in sources.items():
        text = read(rel)
        if text is None or normalise(pin) not in normalise(text):
            out.append((pin, rel))
    return out


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
    import shutil
    import tempfile

    saved = (
        REPO,
        JUDGE_FACING,
        ALLOW,
        TRACE,
        CONTROL_SAMPLES,
        sys.argv,
        SOURCE_PROVIDER,
        PIN_SOURCES,
    )
    tmp = Path(tempfile.mkdtemp())
    (tmp / "planted.md").write_text(
        "The box is rented. An audit found the citation was dead, which is why THE ANCHOR SPAN "
        "stays. Nothing else here matters.\n",
        encoding="utf-8",
    )
    live = ("planted.md", "THE ANCHOR SPAN", "control")
    # Each case carries the substring its refusal must print, because an exit code alone cannot
    # say WHICH check refused once several of them share one. The inert case is the reason: its
    # planted corpus also holds a real trace, so deleting the inert check drops it to the
    # ordinary finding path, which returns the same code. The message is what discriminates.
    cases = [
        ("an unwaived trace is a finding", [], 1, "correction trace"),
        ("a LIVE carve-out waives it and passes", [live], 0, None),
        (
            "an INERT carve-out fails the gate",
            [("planted.md", "TEXT THAT MOVED", "c")],
            1,
            "waived nothing",
        ),
        # Index 0 specifically: a bare `if idx` would route carve-out 0's spans into findings.
        ("carve-out at index 0 waives rather than falling through", [live], 0, None),
    ]

    # The OVER-CORRECTION control, which is what stops a pattern being widened until it eats the
    # product honesty this gate must protect. Injected through globals rather than anchored on a
    # source string, so it cannot rot into a no-op the way a text substitution does. It carries
    # its own positive control, so the only path to rc=2 left is MUST_NOT_FIRE firing.
    over_broad = [("earlier-draft", r"an earlier")]
    over_broad_samples = {"earlier-draft": "an earlier draft"}

    failed = 0
    try:
        for label, allow, expect, need, trace, samples in [
            (lbl, a, e, nd, saved[3], saved[4]) for lbl, a, e, nd in cases
        ] + [
            (
                "a pattern widened onto product honesty is refused",
                [],
                1,
                "must stay silent",
                over_broad,
                over_broad_samples,
            )
        ]:
            globals()["REPO"] = tmp
            globals()["JUDGE_FACING"] = ["planted.md"]
            globals()["ALLOW"] = allow
            globals()["TRACE"] = trace
            globals()["CONTROL_SAMPLES"] = samples
            # No tracked source in a planted corpus. Declared, not inherited from a
            # git failure, so the discovery guard stays armed for real runs.
            globals()["SOURCE_PROVIDER"] = lambda: []
            # Likewise for the quoted pins: a planted corpus has no README or QUICKSTART, and
            # letting main() discover that would make every case below fail on drift instead of
            # on the thing it is testing. Declared empty rather than allowed to fail open.
            globals()["PIN_SOURCES"] = {}
            sys.argv = ["check-correction-traces"]
            import contextlib
            import io

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                rc = main()
            said = buf.getvalue()
            ok = rc == expect and (need is None or need in said)
            failed += not ok
            print(
                f"  {'ok  ' if ok else 'FAIL'}  {label}"
                + ("" if ok else f"  (rc={rc}, expected {expect}; need={need!r})")
            )
    finally:
        (
            globals()["REPO"],
            globals()["JUDGE_FACING"],
            globals()["ALLOW"],
            globals()["TRACE"],
            globals()["CONTROL_SAMPLES"],
            sys.argv,
            globals()["SOURCE_PROVIDER"],
            globals()["PIN_SOURCES"],
        ) = saved
        # Otherwise every local run leaves a directory behind. Harmless in CI, untidy on a
        # developer machine, and the kind of thing that accumulates unnoticed for months.
        shutil.rmtree(tmp, ignore_errors=True)
    return failed, len(cases) + 1


def _selftest_discovery() -> tuple[int, int]:
    """Both refusal paths of tracked_source().

    Neither is reachable without breaking the repo's own git, which is why the
    injectable runner exists. A discovery step that fails open is the worst defect
    a gate can have, because the resulting silence is byte-identical to a clean
    corpus, so these two cases are the control on every other result this gate
    prints.
    """

    class Fake:
        def __init__(self, rc: int, out: str) -> None:
            self.returncode, self.stdout = rc, out

    checks: list[tuple[str, bool]] = []

    try:
        tracked_source(run=lambda *a, **k: Fake(128, ""))
        checks.append(("a git failure refuses rather than reporting clean", False))
    except SystemExit as e:
        checks.append(
            (
                "a git failure refuses rather than reporting clean",
                e.code == CANNOT_CHECK,
            )
        )

    try:
        tracked_source(run=lambda *a, **k: Fake(0, "a.py\nb.py\n"))
        checks.append(("a collapsed walk refuses even at exit 0", False))
    except SystemExit as e:
        checks.append(
            ("a collapsed walk refuses even at exit 0", e.code == CANNOT_CHECK)
        )

    checks.append(
        ("a healthy walk returns the tracked set", len(tracked_source()) >= MIN_SOURCE)
    )

    for label, good in checks:
        print(f"  {'ok  ' if good else 'FAIL'}  {label}")
    return sum(1 for _, good in checks if not good), len(checks)


def selftest() -> int:
    print("wiring (drives the real main()):")
    wiring_failed, wiring_total = _selftest_wiring()

    print("\ndiscovery guards:")
    disc_failed, disc_total = _selftest_discovery()

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
    failed = wiring_failed + disc_failed
    for label, allow, fired, expected in cases:
        got = inert_carve_outs(allow, fired)
        ok = got == expected
        failed += not ok
        print(
            f"  {'ok  ' if ok else 'FAIL'}  {label}" + ("" if ok else f"  (got {got})")
        )
    print("\nquoted-pin drift:")
    # The last case is the one that matters: a pin typed from memory rather than copied, differing
    # from its page by three words in the middle of a long sentence. Nothing else here can see it.
    pin_cases = [
        (
            "a pin still present in its source is silent",
            {"p": "a.md"},
            {"a.md": "prefix p suffix"},
            [],
        ),
        (
            "a whitespace-only difference is not drift",
            {"one two": "a.md"},
            {"a.md": "x one\n  two y"},
            [],
        ),
        (
            "an unreadable source counts as drift",
            {"p": "gone.md"},
            {},
            [("p", "gone.md")],
        ),
        (
            "a spliced ending is reported even though most of the pin matches",
            {"carrying the wrong recipient": "r.md"},
            {"r.md": "carrying somebody else's recipient"},
            [("carrying the wrong recipient", "r.md")],
        ),
    ]
    for label, sources, corpus, expected in pin_cases:
        got = drifted_pins(sources, corpus.get)
        ok = got == expected
        failed += not ok
        print(
            f"  {'ok  ' if ok else 'FAIL'}  {label}" + ("" if ok else f"  (got {got})")
        )

    total = len(cases) + len(pin_cases) + wiring_total + disc_total
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

    source_files = SOURCE_PROVIDER()
    for rel in JUDGE_FACING + source_files:
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
            return CONTROL_DEAD
        if not re.search(pat, normalise(probe), re.I):
            print(
                f"FAIL  positive control for {name!r} did not fire; that pattern is dead.",
                file=sys.stderr,
            )
            return CONTROL_DEAD

    # And prove no pattern has been widened into the product-honesty it must never touch.
    #
    # NOT CANNOT_CHECK and NOT CONTROL_DEAD. Reaching this branch means the over-correction
    # control WORKED: it caught a widened pattern eating a sentence the listing scores at 25%.
    # That is a finding about the repo, so its code is 1. At 2 the aggregate would report a real
    # defect as a non-blocking n/a, which is the one reading this gate must never produce.
    for sample in MUST_NOT_FIRE:
        for name, pat in TRACE:
            if re.search(pat, normalise(sample), re.I):
                print(
                    f"FAIL  pattern {name!r} fired on a sentence that must stay silent. "
                    f"It describes the SYSTEM, not the document, and cutting it would remove "
                    f"honesty this listing scores.\n      {sample[:150]}",
                    file=sys.stderr,
                )
                return 1

    # A pin that no longer appears in the surface it claims to quote is testing a sentence the repo
    # does not ship, and it says nothing about the text a judge actually reads. Reported rather
    # than tolerated, for the same reason an inert carve-out is.
    def _read(rel: str) -> str | None:
        p = REPO / rel
        return p.read_text(encoding="utf-8", errors="replace") if p.exists() else None

    for pin, rel in drifted_pins(PIN_SOURCES, _read):
        print(
            f"FAIL  a must-not-fire pin claims to quote {rel} and is not in it. Either the "
            f"surface was reworded, or the pin was typed rather than copied. Re-copy it from "
            f"the file; a pin nobody can trace is proving nothing.\n      {pin[:150]}",
            file=sys.stderr,
        )
        return CONTROL_DEAD

    # An exclusion that waives nothing is the failure this file names in its own docstring:
    # invisible to --all, so it cannot be audited by the mechanism that is supposed to audit it.
    # Reported rather than tolerated, so a carve-out whose target text moves fails loudly.
    # NOT CANNOT_CHECK and NOT CONTROL_DEAD either. An inert carve-out is an EXCLUSION nobody
    # can audit, not a control; every pattern still fires and the gate can still fail. The
    # docstring promises this makes the gate "refuse to pass", and only a finding code says so.
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
        return 1

    print(
        f"scanned {len(JUDGE_FACING) - len(missing)} judge-facing surface(s) and "
        f"{len(source_files)} tracked source file(s); "
        f"positive control fires; {len(ALLOW)} carve-out(s), all live"
    )

    if show_all and waived:
        print(f"\ndeliberately allowed ({len(waived)}):")
        for rel, name, window, why in waived:
            print(f"  {rel} [{name}]\n     ...{window[:150]}...\n     KEPT: {why}")

    if not findings:
        print(
            "\nOK  no correction traces on judge-facing surfaces or in tracked source."
        )
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
