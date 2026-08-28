#!/usr/bin/env python3
"""The published copy of the response-path sanitizer must not drift from canonical.

WHAT IS VENDORED AND WHY IT CANNOT SIMPLY BE A DEPENDENCY. The registry plugin
`solana-pay-request` carries a copy of `crates/solana-core/src/sanitize.rs` at
`plugins/solana-pay-request/src/solana_core/sanitize.rs`. A registry plugin is built from its
own directory alone, so a path dependency pointing outside that directory cannot resolve and
an unpublished crate cannot be named as a version dependency. Copying is the only route.

WHY THIS OUTRANKS AN ORDINARY VENDORED-COPY NIT. That file IS the response-path prompt
injection defence, and the copy is the one a stranger installs. A fix that lands here and not
there makes a security control look present while it is stale. Nothing compared the two:
measured before this file existed, 0 of 93 scripts under `scripts/` referenced `solana_core`,
against 7 for `solana-core` and 13 for `sanitize` as controls, so the zero was a measurement
rather than a failed read.

THE DIVERGENCE IS NOT HYPOTHETICAL. It already happened, in the module doc, and the edit was
CORRECT: four lines that ranked other authors' work were replaced with a claim that stands on
its own. That edit MUST NOT BE REVERTED. See ACCEPTED_REPLACEMENT below.

HOW THE ACCEPTED DIFFERENCE IS HANDLED, and why this is not an allowlist. An allowlist keyed
to the old bytes would break the first time anyone rewords the paragraph, and a file-level
skip would be a silencer. Instead the difference is DECLARED AS A TRANSFORM: the published
copy is defined as canonical with one module-doc paragraph replaced. The gate applies that
transform and compares the RESULT. The replaced paragraph never reaches the comparison, so
the accepted difference is silent BY CONSTRUCTION rather than by exception.

The paragraph is located by a structural anchor (the last module-doc paragraph before the
first doc heading), not by its text, so rewording it upstream does not break the transform.

TWO PINS, BECAUSE THE TWO DRIFTS NEED DIFFERENT ANSWERS:

  PIN_PUBLISHED_SHA .... sha256 of the transform's output. Moves when canonical changes
                         ANYWHERE OUTSIDE the replaced paragraph. This is the loud case: the
                         published copy is stale and must be regenerated. Measured across the
                         file's four commits, the region outside the paragraph changed in 3
                         of 3 changes after the initial commit, so this is the half that
                         actually moves.
  PIN_CANON_REGION_SHA . sha256 of the canonical paragraph being replaced. Moves only when
                         that paragraph is reworded upstream, which does not make the copy
                         stale but does mean a human should re-read whether the replacement
                         still restates it fairly. Measured 0 changes in 3 commits, so this
                         is expected to be quiet.

THE PIN IS MEASURED, NOT ASSERTED. PIN_PUBLISHED_SHA was taken by applying the transform to
canonical and confirming the result is byte-identical to the file actually served at
PUBLISHED_URL, fetched over the network by two independent routes.

PREVENTION AS WELL AS DETECTION. `--emit` prints the exact content the published copy should
have, so re-vendoring is a copy of a generated artifact rather than a hand edit. The generator
and the gate are the SAME function in the SAME file: two scripts that agree today and drift
later is the failure this repo has already paid for once.

HONEST CEILING, so a green run is never read as more than it is:
  - The default mode compares canonical against a PIN, not against the published copy. It
    therefore catches canonical moving and CANNOT see a hand edit made directly to the
    published copy. `--live` covers that and needs the network, so it belongs in a
    never-required job.
  - It covers `sanitize.rs` only. `pubkey.rs` in the same vendored directory is a DELIBERATE
    REDUCTION to the base58 codec, documented in its own header, so a byte comparison is
    structurally the wrong instrument for it and none is attempted. A weaker property, that
    every retained item matches canonical, is real and is not built here.
  - It cannot tell a good replacement paragraph from a bad one. That stays a human call. The
    anchor is positional, so a paragraph inserted upstream between the replaced one and the
    heading retargets it; both pins move in that case and the selftest pins it, but the human
    reading the verdict is the one who has to notice WHICH paragraph is now being replaced.
  - The published copy's own provenance note claims the sanitizer is verbatim. It is not, by
    the four lines above. That is a finding for whoever owns the registry submission, and it
    is deliberately NOT gated here: keying a check on another repository's prose is how a gate
    starts failing on a correct reword.

Exit codes follow the house convention: 0 ok, 1 finding, 2 could-not-check. `--selftest` exits
3 when any control fails, which is the repo's selftest-failure code and the slot `check-all.py`
reads as a dead control.
"""

import argparse
import hashlib
import pathlib
import sys
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
CANONICAL_REL = "crates/solana-core/src/sanitize.rs"

PUBLISHED_URL = (
    "https://raw.githubusercontent.com/belumume/zeroclaw-plugins/"
    "add-solana-pay-request/plugins/solana-pay-request/src/solana_core/sanitize.rs"
)

# The structural anchor. The replaced paragraph is the last module-doc paragraph before this
# heading. Anchoring on structure rather than on the paragraph's own words is what lets an
# upstream reword be reported instead of crashing the transform.
ANCHOR = "//! # Why not a blocklist"

# The accepted difference, in full. Canonical's version of this paragraph ranked every other
# plugin in the field as undefended, which is an unverifiable claim about other authors' work.
# The replacement makes the same point about THIS module without it. Do not revert this.
ACCEPTED_REPLACEMENT = [
    "//! Argument validation is the better-covered half of this problem: a caller",
    "//! cannot pass a malicious `rpc_url`. The response path is the half this",
    "//! module exists for, covering the data a tool fetches from chain and hands",
    "//! back to the model.",
]

PIN_PUBLISHED_SHA = "f8df0c9443a70750bab0f67a5b609c09fd823d03f7426820b16cfbd1fdeda9fc"
PIN_CANON_REGION_SHA = (
    "3aa211bb8aea5564e11513f88d0bec183b08732f86c45c2ca29718b41eaee04a"
)

OK, FINDING, CANNOT_CHECK, CONTROL_DEAD = 0, 1, 2, 3


class AnchorMissing(Exception):
    """The module-doc structure changed, so the transform cannot be derived."""


def norm(text):
    """Compare TEXT, never bytes. A checkout under a different line-ending setting would
    otherwise manufacture a difference on every line of a file that is in fact identical."""
    return text.replace("\r\n", "\n")


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def locate_region(lines):
    """Half-open (start, end) of the module-doc paragraph above the first doc heading."""
    anchor_at = None
    for i, line in enumerate(lines):
        if line.strip() == ANCHOR:
            anchor_at = i
            break
    if anchor_at is None:
        raise AnchorMissing(f"no line equal to {ANCHOR!r}")
    j = anchor_at - 1
    while j >= 0 and lines[j].strip() == "//!":
        j -= 1
    end = j + 1
    while j >= 0 and lines[j].startswith("//!") and lines[j].strip() != "//!":
        j -= 1
    start = j + 1
    if start >= end:
        raise AnchorMissing("no doc paragraph precedes the first doc heading")
    return start, end


def derive(canonical_text):
    """(published_text, canonical_region_text) for a given canonical source."""
    lines = norm(canonical_text).split("\n")
    start, end = locate_region(lines)
    region = "\n".join(lines[start:end])
    published = "\n".join(lines[:start] + list(ACCEPTED_REPLACEMENT) + lines[end:])
    return published, region


def offline_verdict(canonical_text):
    """Has canonical moved since the published copy was generated from it?"""
    notes = []
    try:
        published, region = derive(canonical_text)
    except AnchorMissing as exc:
        return FINDING, [
            f"CANNOT DERIVE the vendoring transform: {exc}.",
            "The module-doc structure changed. Re-derive the transform by hand and re-pin;",
            "do not widen the anchor until you have read what actually moved.",
        ]

    got_published, got_region = sha(published), sha(region)
    code = OK

    if got_published != PIN_PUBLISHED_SHA:
        code = FINDING
        notes += [
            "STALE: canonical changed outside the replaced paragraph, so the published copy",
            "no longer matches it. The response-path sanitizer a stranger installs is behind.",
            f"  expected {PIN_PUBLISHED_SHA}",
            f"  derived  {got_published}",
            "  regenerate:  python scripts/check-vendored-sanitize-agreement.py --emit",
            f"  then re-pin PIN_PUBLISHED_SHA to {got_published}",
        ]

    if got_region != PIN_CANON_REGION_SHA:
        if code == OK:
            code = FINDING
        notes += [
            "DOC REWORD: the paragraph this transform replaces is not the one it was",
            "pinned to. The published copy is NOT stale for this reason alone.",
            "Before re-pinning, establish WHICH paragraph the anchor now targets. A new",
            "paragraph inserted upstream between the old one and the heading moves the",
            "anchor onto the new one, and the replacement would then stand in for the",
            "wrong paragraph. Then re-read whether it still restates that paragraph fairly.",
            f"  expected {PIN_CANON_REGION_SHA}",
            f"  derived  {got_region}",
        ]

    if code == OK:
        notes.append(
            "canonical and the published copy agree, modulo the one declared doc paragraph"
        )
    return code, notes


def live_verdict(canonical_text, fetched_text):
    """Compare the ACTUAL published bytes against what canonical says they should be.

    `fetched_text` of None means the copy could not be read, which is COULD-NOT-CHECK and
    never a pass. Folding an unreachable host in with a real mismatch would make one signal
    mean two things whose remedies are opposite.
    """
    if fetched_text is None:
        return CANNOT_CHECK, [
            "could not read the published copy; nothing was compared",
            f"  {PUBLISHED_URL}",
        ]
    try:
        published, _ = derive(canonical_text)
    except AnchorMissing as exc:
        return FINDING, [f"CANNOT DERIVE the vendoring transform: {exc}"]

    actual = norm(fetched_text)
    if actual == published:
        return OK, ["the published copy is byte-identical to what canonical derives"]

    want = published.split("\n")
    have = actual.split("\n")
    first = next(
        (
            i
            for i in range(max(len(want), len(have)))
            if want[i : i + 1] != have[i : i + 1]
        ),
        None,
    )
    return FINDING, [
        "HAND EDIT: the published copy differs from what canonical derives.",
        "This is not the accepted doc paragraph, which the transform already absorbs.",
        f"  first difference at line {None if first is None else first + 1}",
        f"  canonical derives: {want[first] if first is not None and first < len(want) else '<absent>'!r}",
        f"  published has:     {have[first] if first is not None and first < len(have) else '<absent>'!r}",
    ]


def fetch_published(timeout=25):
    """The published bytes, or None. Python's own TLS stack, because the platform curl here
    fails its revocation check against every https host."""
    try:
        request = urllib.request.Request(
            PUBLISHED_URL, headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            return response.read().decode("utf-8")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError):
        return None


def read_canonical():
    path = REPO / CANONICAL_REL
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- selftest


def _mutate_logic(canonical_text):
    """Change a LOGIC line, outside the replaced paragraph. Must FIRE."""
    lines = norm(canonical_text).split("\n")
    start, end = locate_region(lines)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if i >= end and stripped and not stripped.startswith("//"):
            lines[i] = line + "  // planted"
            return "\n".join(lines)
    raise AssertionError("fixture: found no code line after the doc block")


def _mutate_doc_region(canonical_text):
    """Reword the replaced paragraph only. Must produce the DOC verdict, not STALE."""
    lines = norm(canonical_text).split("\n")
    start, end = locate_region(lines)
    lines[start:end] = ["//! Reworded upstream, saying the same thing differently."]
    return "\n".join(lines)


def _insert_paragraph_before_anchor(canonical_text):
    """A NEW doc paragraph lands between the replaced one and the heading, upstream.

    The anchor is positional, so it follows the insertion onto the new paragraph. Both pins
    move, which is why this is doubly detected rather than silent, and it is pinned here so a
    later narrowing of the anchor cannot quietly lose the case.
    """
    lines = norm(canonical_text).split("\n")
    _, end = locate_region(lines)
    inserted = [
        "//!",
        "//! A paragraph added upstream, between the old one and the heading.",
    ]
    return "\n".join(lines[:end] + inserted + lines[end:])


def _remove_anchor(canonical_text):
    return norm(canonical_text).replace(ANCHOR, "//! # Rationale")


def selftest():
    canonical = read_canonical()
    if canonical is None:
        print(f"CONTROL DEAD: {CANONICAL_REL} is absent, so nothing could be exercised")
        return CONTROL_DEAD

    cases = []

    def case(name, got, want, detail=""):
        cases.append(
            (name, got == want, f"{name}: got {got}, want {want} {detail}".rstrip())
        )

    # 1. MUST BE SILENT. The real tree carries the real accepted difference, and the pin was
    #    measured against the file actually served. A pass here is a claim about reality.
    code, _ = offline_verdict(canonical)
    case("real tree is silent (accepted doc difference absorbed)", code, OK)

    # 2. MUST FIRE, and loudly: a logic line moved.
    code, notes = offline_verdict(_mutate_logic(canonical))
    case("planted LOGIC change fires", code, FINDING)
    cases.append(
        (
            "planted LOGIC change is reported as STALE",
            any(n.startswith("STALE:") for n in notes),
            "planted LOGIC change is reported as STALE",
        )
    )
    cases.append(
        (
            "planted LOGIC change is NOT reported as a doc reword",
            not any(n.startswith("DOC REWORD:") for n in notes),
            "planted LOGIC change is NOT reported as a doc reword",
        )
    )

    # 3. THE DISCRIMINATION PROOF. Same file, a one-line edit inside the replaced paragraph
    #    instead of outside it, and the verdict must be the OTHER one. Without this, a gate
    #    that simply fires on everything would pass case 2.
    code, notes = offline_verdict(_mutate_doc_region(canonical))
    case("reworded DOC paragraph fires", code, FINDING)
    cases.append(
        (
            "reworded DOC paragraph is NOT reported as STALE",
            not any(n.startswith("STALE:") for n in notes),
            "reworded DOC paragraph is NOT reported as STALE",
        )
    )
    cases.append(
        (
            "reworded DOC paragraph is reported as a doc reword",
            any(n.startswith("DOC REWORD:") for n in notes),
            "reworded DOC paragraph is reported as a doc reword",
        )
    )

    # 4. A broken anchor must be a finding, never a silent pass.
    code, notes = offline_verdict(_remove_anchor(canonical))
    case("missing anchor is a finding", code, FINDING)
    cases.append(
        (
            "missing anchor says the transform could not be derived",
            any("CANNOT DERIVE" in n for n in notes),
            "missing anchor says the transform could not be derived",
        )
    )

    # 4b. An upstream INSERTION moves the anchor onto a paragraph the replacement was never
    #     written for. BOTH pins must move: the region pin because the targeted paragraph is a
    #     different one, and the published pin because the paragraph the replacement stands in
    #     for now survives into the derived copy. Either alone would be enough to catch it;
    #     requiring both is what stops a future anchor change making this silent.
    inserted = _insert_paragraph_before_anchor(canonical)
    code, notes = offline_verdict(inserted)
    case("inserted upstream paragraph fires", code, FINDING)
    cases.append(
        (
            "inserted upstream paragraph moves BOTH pins",
            any(n.startswith("STALE:") for n in notes)
            and any(n.startswith("DOC REWORD:") for n in notes),
            "inserted upstream paragraph moves BOTH pins",
        )
    )

    # 5. The live comparator, exercised offline against fixtures.
    published, _ = derive(canonical)
    code, _ = live_verdict(canonical, published)
    case("live: a faithful published copy agrees", code, OK)

    code, notes = live_verdict(canonical, published.replace("pub fn", "pub  fn", 1))
    case("live: a hand-edited published copy fires", code, FINDING)
    cases.append(
        (
            "live: a hand edit is named as a hand edit",
            any(n.startswith("HAND EDIT:") for n in notes),
            "live: a hand edit is named as a hand edit",
        )
    )

    # 6. Unreachable must be COULD-NOT-CHECK, never a pass and never a mismatch.
    code, _ = live_verdict(canonical, None)
    case("live: unreachable is could-not-check", code, CANNOT_CHECK)

    # 7. Line endings must not manufacture a difference.
    code, _ = live_verdict(canonical, published.replace("\n", "\r\n"))
    case("live: a CRLF copy still agrees", code, OK)

    # 8. The emitted artifact is what the gate pins, so the generator cannot drift from it.
    cases.append(
        (
            "--emit output is the pinned content",
            sha(derive(canonical)[0]) == PIN_PUBLISHED_SHA,
            "--emit output is the pinned content",
        )
    )

    failed = [message for _, ok, message in cases if not ok]
    for _, ok, message in cases:
        print(f"  {'ok  ' if ok else 'FAIL'}  {message}")
    print(f"selftest: {len(cases) - len(failed)}/{len(cases)}")
    return CONTROL_DEAD if failed else OK


# --------------------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument(
        "--emit",
        action="store_true",
        help="print the content the published copy should have, and exit",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="also read the published copy over the network and compare it",
    )
    parser.add_argument("--selftest", action="store_true", help="run the controls")
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    canonical = read_canonical()
    if canonical is None:
        print(f"COULD NOT CHECK: {CANONICAL_REL} not found under {REPO}")
        return CANNOT_CHECK

    if args.emit:
        try:
            published, _ = derive(canonical)
        except AnchorMissing as exc:
            print(f"COULD NOT EMIT: {exc}", file=sys.stderr)
            return FINDING
        sys.stdout.write(published)
        return OK

    code, notes = offline_verdict(canonical)
    label = {OK: "OK", FINDING: "FINDING", CANNOT_CHECK: "COULD NOT CHECK"}[code]
    print(f"[{label}] vendored sanitizer vs canonical {CANONICAL_REL}")
    for note in notes:
        print(f"  {note}")

    if args.live:
        live_code, live_notes = live_verdict(canonical, fetch_published())
        live_label = {OK: "OK", FINDING: "FINDING", CANNOT_CHECK: "COULD NOT CHECK"}[
            live_code
        ]
        print(f"[{live_label}] published copy at the registry submission")
        for note in live_notes:
            print(f"  {note}")
        if live_code != OK and code == OK:
            code = live_code

    return code


if __name__ == "__main__":
    sys.exit(main())
