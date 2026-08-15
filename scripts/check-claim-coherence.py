#!/usr/bin/env python3
"""Flag a script that the docs credit with a RUNTIME role while nothing invokes it.

THE CLASS, which is wider than any one file: a change lands on one surface and another
surface keeps asserting the old thing. Nothing errors. The stale assertion reads as
authoritative precisely because prose cannot fail a test, and the reader believes it.

The slice this gate makes checkable is the one that costs most on a judged repo. A
document says a script guards, certifies, verifies or enforces something at runtime; the
script is real, tracked and well tested; and NOTHING CALLS IT. The claim is then a
description of a library, and this project's own thesis is that a control which is claimed
and enforced by no runtime path is worse than an absent one, because an absent control is
visible while an inert one lets the reader believe they are protected.

WHY IT IS SHAPED THIS WAY, since the obvious version is useless. A bare "is this script
mentioned in a doc" check fires on every script in the repo. The discriminant is the VERB:
only a claim of a runtime ROLE needs a caller. A doc telling a reader to run something
manually is an instruction, not a runtime claim, and a self-test invoked by CI is already
wired. So the gate keys on role language, then looks for ANY caller, then accepts an
explicit disclosure as a third way to be honest.

THREE WAYS TO SATISFY IT, and the third is the point:
  1. something invokes the script (CI, another tracked script, a tracked unit file);
  2. the doc tells the reader to run it themselves, so it is an instruction;
  3. the doc DISCLOSES that the wiring is operator-side and not provable from the repo.
The third exists because the honest answer to an unverifiable claim is to say so, not to
delete the claim and not to assert it harder.

FAILS LOUD on a broken walk: a discovery step that silently finds nothing would otherwise
print a clean result over an empty set, which is the same false-green this gate exists to
catch, one level up.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A claim of a RUNTIME role. Not "run this", not "see this" -- an assertion that the thing
# acts, continuously, on its own. These verbs are what turn a mention into a claim.
ROLE_VERBS = re.compile(
    r"\b(certifie?s|guards?|enforces?|refuses?|gates?|blocks?|verifies|validates?|"
    r"re-derives?|bounds?|prevents?|rejects?)\b",
    re.IGNORECASE,
)


def instructed(para, name):
    """Is the doc telling the reader to run THIS script?

    PER-SCRIPT, not per-paragraph, and that distinction is the whole gate. The first
    version tested the paragraph, so one instructed script exempted every script named
    beside it, and the incident this gate was built for was skipped: a certifier credited
    with a runtime role sat in the same paragraph as a self-test the reader is told to
    run. The gate passed its live corpus while being structurally unable to catch its own
    motivating case. Its control caught that; re-reading it never would have.
    """
    esc = re.escape(name)
    return (
        re.search(r"python3?\s+scripts/" + esc, para, re.I) is not None
        or re.search(r"run\s+`?scripts/" + esc, para, re.I) is not None
    )


# Retained for reference only; superseded by instructed() above, which is per-script.
_UNUSED_INSTRUCTION = re.compile(
    r"(python3?\s+scripts/|`scripts/[\w.-]+`\s*\)|run\s+`?scripts/)", re.I
)

# An explicit admission that the wiring lives outside the repo.
DISCLOSURE = re.compile(
    r"(operator-side|not prove|does NOT prove|unverified deployment|cannot confirm|"
    r"outside this (tree|repo)|not a file in this tree)",
    re.IGNORECASE,
)

# WIDENED 2026-08-15. This matched `scripts/` only, so a doc could credit a `deploy/` or
# `demo/` script with a runtime role nothing invokes and this gate stayed silent. That is
# exactly what happened: a README sentence claimed the x402 gate's /health endpoint runs
# deploy/box_selfcheck.py, when /health shells `systemctl --user is-active` and never touches
# it. A reviewer caught what this was structurally unable to see.
#
# The capture group keeps only the basename so the rest of the module is unchanged; the
# directory is matched but not captured.
SCRIPT_REF = re.compile(r"(scripts|deploy|demo)/([\w.-]+\.(?:py|sh))")
MIN_DOCS = 10  # floor: a walk finding fewer than this is broken, not clean


def git(*args):
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout


def callers_of(script_name, tracked):
    """Anything that INVOKES this script: CI, another script, a unit file."""
    hits = []
    for rel in tracked:
        if rel.endswith(".md") or rel.endswith(script_name):
            continue
        p = ROOT / rel
        try:
            body = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if script_name in body:
            hits.append(rel)
    return hits


def main() -> int:
    tracked = [f for f in git("ls-files").split("\n") if f]
    docs = [f for f in tracked if f.endswith(".md")]
    if len(docs) < MIN_DOCS:
        print(
            f"FAIL  walk found {len(docs)} tracked doc(s); expected at least {MIN_DOCS}. "
            "The discovery step is broken, so a clean result here would mean nothing."
        )
        return 2

    findings = []
    for rel in docs:
        try:
            text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        paras = re.split(r"\n\s*\n", text)
        for i, para in enumerate(paras):
            names = set(SCRIPT_REF.findall(para))
            if not names:
                continue
            if not ROLE_VERBS.search(para):
                continue  # a mention, not a runtime claim
            # THE DISCLOSURE WINDOW IS THE CLAIM'S PARAGRAPH PLUS THE NEXT TWO, because that is
            # how a reader meets it. Scoped to the single paragraph, this reported a claim whose
            # disclosure sat in the very next one -- and the only ways to satisfy it would have
            # been to move prose to please the instrument, or to delete a correct gate. Neither
            # is a fix. Forward-only on purpose: a disclosure BEFORE a claim does not condition
            # a reader who has not reached it yet, and widening backwards would let an unrelated
            # earlier caveat silence a later claim.
            if any(DISCLOSURE.search(p) for p in paras[i : i + 3]):
                continue  # honest about the unverifiable wiring, here or immediately after
            for d, name in names:
                if not (ROOT / d / name).exists():
                    continue
                if instructed(para, name):
                    continue  # the reader is told to run THIS one
                if callers_of(name, tracked):
                    continue  # something invokes it
                findings.append((rel, f"{d}/{name}", " ".join(para.split())[:110]))

    print(
        f"surfaces read: {len(docs)} tracked document(s), {len(tracked)} tracked file(s)"
    )
    if not findings:
        print(
            "PASS  every script a doc credits with a runtime role is invoked, "
            "instructed, or honestly disclosed"
        )
        return 0

    print(f"\n{len(findings)} claim(s) with no runtime path and no disclosure:\n")
    for rel, name, quote in findings:
        print(f"  {rel}  ->  {name}")
        print(f"      {quote}")
    print(
        "\nA doc crediting a script with a runtime role, where nothing invokes it, describes a\n"
        "library rather than a defense. Fix it one of three ways: wire a caller, reword it as an\n"
        "instruction the reader runs, or disclose plainly that the wiring is operator-side and\n"
        "not provable from this repo. The third is honest; asserting it harder is not."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
