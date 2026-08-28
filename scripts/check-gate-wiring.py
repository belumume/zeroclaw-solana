#!/usr/bin/env python3
"""Every tracked gate must be INVOKED by a workflow, or declared here with a reason.

WHY THIS EXISTS. PR #142 added demo/verify_click_time_settlement_check.py, a real gate on the
money path, and wired it into no workflow. A reviewer caught it. Had the review missed it, the
check would have run only when someone remembered, and it would never have gated a merge, so a
later change deleting the guard line it exists to catch would have been reported clean by a green
CI. That PR fixed its own instance. The next new gate under demo/ had the identical gap waiting.

A PER-FILE STEP FIXES THE INSTANCE AND LEAVES THE CLASS OPEN, which is the whole argument for a
discovery floor: a gate added next week joins `git ls-files` automatically and joins CI never.

TWO FAMILIES, because the repo keeps gates in two places and only one of them was floored.
scripts/check-*.py has been covered since 2026-08-19, by a Python heredoc inlined in
regression-gate.yml. demo/ had nothing. This file is that heredoc, promoted to a real gate and
widened to cover both, rather than a second floor standing beside the first. Two floors for one
property drift, and the drift is invisible because each is green against its own scope.

WHAT PROMOTION BUYS, and it is the reason this is a file rather than one more line of YAML. An
inline floor cannot be run locally, cannot carry a selftest, and cannot be shown to FAIL. By this
repo's own standard a check nobody has watched go red is not evidence, it is a hypothesis that
reports green. The selftest below drives the real corpus in both directions and plants a synthetic
orphan that MUST fire.

THREE STATES, not two, and the third exists because two were not enough. A gate is INVOKED when a
workflow names its path; DECLARED when EXCLUDED carries a reason it is not invoked; or
HARNESS-COVERED when no workflow names it but a control harness that CI does run drives it. The
third was added after the floor was found to be silent about two real gates, demo/pre_export_gate.py
and scripts/replay_allowance_probe.py, both driven end to end by harnesses ci.yml runs. Neither was
exposed; the summary line simply counted neither, so it understated its own coverage. The long note
above HARNESS_COVERED gives the measurements for why that state is declared rather than inferred,
and why an EXCLUDED row would have been false and inert.

WHAT COUNTS AS INVOKED. The gate's tracked path appears in some workflow file, with YAML COMMENTS
STRIPPED FIRST. Comments are stripped because a gate merely discussed in a comment is not run by
it, and the inline floor this replaces matched raw text, so prose counted as wiring. That lesson is
not hypothetical here: check-crate-build-coverage.py learned it when a plain substring match
counted a crate as covered on the strength of a comment naming it. Measured on the live tree, the
strengthening moves exactly one file, scripts/check-all.py, which is declared below anyway.

WHAT THIS DOES NOT CLAIM. That the invocation is meaningful, that the step runs on a required job,
or that the job is reachable on any given event. Matching is per CORPUS, not per job, so a gate
named only inside a manually dispatched job counts as wired. Resolving that would mean modelling
event triggers, path filters and `if:` conditions per step, which is a heavier instrument than the
defect it would catch. The bound is real and belongs stated rather than implied.

NOR DOES IT SEE MODES. Matching is on the PATH, so a gate whose `--selftest` is wired reads as
invoked even when its main comparison runs nowhere. That is deliberate and it is load-bearing for
two entries here: `demo/check_wit_parity.py` and `scripts/verify-output-ceiling-agreement.py` both
have hermetic control modes that a runner can execute and main modes that need a second checkout or
a toolchain, and wiring the half that can run is the right outcome rather than a dodge. But a
future gate could hide a genuinely unrun main mode behind a wired selftest, and this floor would
not notice. Whether the wired mode is the one worth running stays a judgement for review.

EXIT CODES, the repo's protocol. 0 every tracked gate is invoked, declared, or harness-covered
with both legs holding. 1 at least one is none of those, OR a declared harness pairing no longer
holds, which is a finding rather than a skip precisely so this state cannot rot into a silencer.
2 could not check, which covers a missing workflow directory, a git failure, and a discovery walk
returning fewer files than its floor, since a broken walk reports every gate clean at once and a
clean result would mean nothing.

Run: python3 scripts/check-gate-wiring.py [--selftest]
"""

from __future__ import annotations

import contextlib
import io
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

CANNOT_CHECK = 2

# The families, each with the globs git is asked for and the floor below which the walk is broken
# rather than the repo clean. NO LIVE TOTALS IN THESE COMMENTS, deliberately: a floor is a fixed bar
# well under the corpus, and the corpus figure belongs in the summary line, which reprints it every
# run. A comment naming today's count is the stale denominator this file exists to catch, and
# check-all.py's equivalent constant has drifted below its own rule several separate times.
FAMILIES: dict[str, tuple[tuple[str, ...], int]] = {
    # scripts/check-all.py itself is the local aggregate runner and is declared below.
    "scripts": (
        (
            "scripts/check-*.py",
            "scripts/check-*.sh",
            "scripts/verify*.py",
            "scripts/verify*.sh",
            "scripts/mutation-*.py",
            "scripts/mutation-*.sh",
            "scripts/test_*.py",
            "scripts/test_*.sh",
        ),
        60,
    ),
    # verify* catches both spellings the repo uses, verify_foo.py and verify-foo.py.
    "demo": (
        (
            "demo/verify*.py",
            "demo/verify*.sh",
            "demo/test_*.py",
            "demo/test_*.sh",
            "demo/check_*.py",
            "demo/check_*.sh",
        ),
        10,
    ),
}
# EVERY CONVENTION IS PAIRED .py AND .sh, and the second half of each pair is why this list moved
# again. The comment below records the globs being a GUESS about naming; they were also a guess
# about EXTENSION, and that one was invisible for the same reason. Measured before widening: the
# walk was python-only, so scripts/check-host-compat.sh and five mutation controls written in
# shell were outside the corpus entirely. All six are real gates, all six are invoked, and the
# floor said nothing about any of them. Widening found NO new orphans, which is the expected
# shape for a REPORTING gap: nothing was exposed, the report was simply narrower than its own
# summary line claimed. No corpus totals in this comment, per the rule a few lines above: the live
# figure is reprinted by the summary line on every run, and that is the only copy that cannot go
# stale.
#
# mutation-* REPLACES mutation-check-* for the same reason one notch further out: the -check-
# spelling excluded scripts/mutation-certify-x402.py by construction, and it is a mutation control
# like the rest of them.
# The demo .sh globs match nothing today and are deliberate: an empty glob costs one line and
# closes the extension gap for that family before it opens, and the family floor still trips if
# the walk as a whole breaks.
#
# THE SCRIPTS FLOOR MOVED 40 -> 60 WITH THE WIDENING, and leaving it would have weakened a
# protection that already existed. Measured: the scripts walk is 77 across eight globs, of which
# check-*.py and check-*.sh are 37. Deleting that pair left exactly 40, and `40 < floor` is False
# at the boundary, so 37 gates would have left the corpus in silence. The same deletion tripped
# CANNOT CHECK before the widening. Raising the numerator without raising the denominator is how a
# floor stops being one. A control below proves 60 actually trips on that deletion, because an
# unproven threshold is a number rather than a bar.
#
# WHAT A FLOOR STILL CANNOT DO, since 60 is not magic. It catches a walk that collapses and it
# catches the deletion of a LARGE convention. Deleting both halves of a small one, verify*.{py,sh}
# at five, leaves 72 and trips nothing. The per-glob pairing control below catches deleting either
# half alone; deleting both halves of a small convention is the residual, and it is named here
# rather than implied. The demo floor is unchanged at 10: that walk is 17 and its largest pair is
# 12, so a pair deletion leaves 5 and already trips.
# THE GLOB LIST IS THE WHOLE CLAIM, and the first version of this file got it wrong in a way worth
# recording, because the failure is this gate's own subject matter. It globbed `scripts/check-*.py`
# and `demo/{verify*,test_*}.py`, which are the conventions its author happened to notice, and
# called the result a floor over "every tracked gate". The repo names gates four other ways.
#
# Two reviewers caught it independently, from different ends: one found
# scripts/verify-output-ceiling-agreement.py, the other demo/check_wit_parity.py. Widening to the
# conventions the repo actually uses surfaced FOUR orphans rather than the two named, and every one
# is a real gate with its own controls. So the narrow globs were not a cosmetic gap: they let this
# file claim a class was closed while four instances of that exact class sat open, which is worse
# than not having claimed it.
#
# The lesson for anyone adding a fifth convention: a name-based discovery walk encodes a GUESS
# about how other people name things, and the guess is invisible because everything it does find
# looks correct. Re-derive the corpus rather than trusting this list:
#   git ls-files 'scripts/*.py' 'demo/*.py' | grep -vE '<the globs above>'
# and read what falls out, asking of each whether it is a gate or a producer.

# Declared, each with the reason it is not invoked by a workflow. Inherited from the inline floor
# in regression-gate.yml, with one row dropped and one added, both noted below. Neither changes a
# scripts/ verdict: the dropped row named a gate that is invoked anyway.
#
# THE BAR FOR AN ENTRY IS A REASON THAT SURVIVES DISAGREEMENT, not a reason that makes this gate
# green. An entry added to silence the check is the same defect one level up, and this repo has
# already had to fix that shape more than once.
EXCLUDED: dict[str, str] = {
    # check-doc-links.py IS NOT LISTED, and the absence is deliberate rather than an oversight.
    # The heredoc this file replaces declared it, and that row had gone dead: the gate IS invoked,
    # by regression-gate.yml's own live-smoke job, which runs it and converts its exit 2 into a
    # warning. The entry was excusing a gate that already passed on its own merit. A dead row is
    # not free, because an exclusion suppresses the check for that path permanently: had the
    # live-smoke invocation ever been deleted, this floor would have gone on reporting green over
    # a genuinely orphaned checker. Dropping it changes no verdict today and closes that trapdoor.
    # The redundancy control in the selftest now fails any entry that drifts into the same state.
    "scripts/check-config-drift.py": "compares against the box's own config.toml, which no runner has; it self-reports exit 2 "
    "(cannot check) rather than passing vacuously.",
    "scripts/check-all.py": "the local aggregate runner, not a gate; it would pull check-doc-links.py onto the runner.",
    "scripts/check-root-divergence.py": "compares the two WORKING ROOTS, and a runner clones exactly one, so it would SKIP on "
    "every run. A step that can only ever skip is a green check asserting nothing. Its "
    "control, test_check_root_divergence.py, builds its own synthetic pair in a temp dir and "
    "DOES run in ci.yml, so the checker's behaviour is verified on a runner even though the "
    "checker cannot run there.",
    "scripts/check-untracked-root-divergence.py": "same reason one layer down: it compares the UNTRACKED internal documents the two working "
    "roots share, and a runner clones one root and none of those gitignored documents, so it "
    "would report not-applicable on every run. Its control, "
    "test_check_untracked_root_divergence.py, builds its own synthetic pair in a temp dir and "
    "DOES run in ci.yml, with both mutation controls.",
    # NEW ENTRY, 2026-08-27, and the reason is the file's OWN rather than one invented to reach a
    # green. verify_qr_in_encoded_cut.py carries a paragraph headed "DELIBERATELY NOT WIRED INTO
    # ci.yml", written before this floor existed, whose argument is that a CI gate earns its place
    # by catching a REGRESSION and its subject cannot regress: the cut is a shipped, frozen
    # artifact, and the gate becomes live only if the video is replaced.
    #
    # TWO THINGS MEASURED HERE THAT THE FILE DOES NOT STATE, both of which strengthen the case
    # rather than weaken it. It needs cv2, numpy, PIL, pyzbar and ffmpeg, and it guards NONE of
    # them: the cv2 import sits inside decode_both with no ImportError handling, so on a runner
    # missing any one of them it raises and exits 1, which this repo reads as a FINDING ABOUT THE
    # VIDEO. Wiring it without provisioning all five would therefore manufacture a false finding
    # against a judged artifact, in the alarming direction.
    #
    # AND THE COST IS SMALLER THAN THE FILE'S OWN NOTE IMPLIES, which is recorded here because it
    # is the fact most likely to change this decision later and it would otherwise have to be
    # rediscovered. Run against the shipped cut it takes 18 SECONDS and passes: 4 frames decoded
    # by both readers against 121 where both correctly stayed silent, so its negative control is
    # live. Of the five dependencies, regression-gate.yml already installs FOUR for its sibling
    # verify_qr_scannable.py, and ci.yml already installs ffmpeg elsewhere, so the gap is one apt
    # line rather than a new toolchain. What survives all of that is the file's PRIMARY argument,
    # which none of these measurements touches: a frozen artifact cannot regress, so 18 seconds of
    # re-answering a settled question catches nothing on an ordinary push.
    #
    # WHAT RETIRES THIS ENTRY: the video changing. Its answer cannot move for any other reason. If
    # the shipped cut under docs/assets is replaced, wire this gate behind a paths filter on that
    # file, in a job that installs all five dependencies. The figures above are what that costs.
    "demo/verify_qr_in_encoded_cut.py": "its subject is a frozen shipped artifact that cannot regress, so a per-push run "
    "re-answers a settled question; it also needs cv2, numpy, PIL, pyzbar and ffmpeg and "
    "guards none of them, so an under-provisioned job would exit 1 and read as a finding "
    "about the video. Retired the moment the video is replaced; see the note above.",
}


# A THIRD STATE, because the two this file had are both wrong for a real and recurring shape:
# a gate no workflow NAMES, whose behaviour a control harness that CI DOES run drives end to end.
# demo/pre_export_gate.py is driven by demo/test_pre_export_gate.py, and
# scripts/replay_allowance_probe.py by scripts/test_replay_allowance_probe.py. Both harnesses run
# in ci.yml. Both gates were invisible here, so the summary line understated coverage by counting
# neither.
#
# WHY NOT AN EXCLUDED ROW, which is the cheap answer and the wrong one. EXCLUDED means "no
# workflow invokes this, and here is why that is acceptable". These gates ARE covered, so the row
# would be false on its face. Worse, it would be inert: an exclusion suppresses this check for
# that path PERMANENTLY, so if the harness were later dropped from CI the floor would go on
# reporting green over a gate that had become genuinely orphaned. That is not a hypothetical
# objection, it is the exact trapdoor documented against check-doc-links.py a few lines above,
# whose inherited row was dropped for having drifted into that state. The redundancy control in
# the selftest catches it only for DIRECT invocation, so a transitively covered gate parked in
# EXCLUDED would sail past the one control aimed at this shape.
#
# WHY NOT INFER IT, which is the general answer and is refuted by measurement rather than by
# preference. Inference would have to key on the harness naming the gate, and on this corpus that
# signal is decoupled from the driving in BOTH directions:
#
#   FALSE NEGATIVE. scripts/test_replay_allowance_probe.py drives the probe by joining path
#   fragments, ROOT / "scripts" / "replay_allowance_probe.py", then injecting sys.argv. The
#   literal tracked path appears in that file exactly once, in its DOCSTRING. So a path matcher
#   scores it covered on the strength of prose, which is the precise defect strip_comments()
#   exists to prevent, reintroduced one level up. Rename the file without touching the docstring
#   and the inference inverts.
#
#   FALSE POSITIVE, and this is the direction that silences. scripts/check-reproduce-path-
#   coverage.py runs in CI and carries its own EXCLUDED dict: six tracked paths whose entire
#   documented meaning is that they CANNOT run on a runner. An inference that reads "a CI-run
#   file names this path" as coverage marks all six covered, including scripts/check-all.py and
#   scripts/check-config-drift.py, which THIS file already declares unwired for cause. The model
#   would contradict the list sitting above it.
#
# Driving is also not one mechanism. Four measured pairings drive four different ways: a python
# import, a pathlib fragment join plus sys.argv, a shell dirname-relative exec, and a subprocess
# argv. Recognising all four, while separating them from a mention in a data table, is a semantic
# question, and a checker that guesses wrong here fails toward silence.
#
# SO THE PAIRING IS DECLARED AND THE LEGS ARE CHECKED. A human states which harness drives the
# gate and how; the checker re-derives, on every run, that the harness is still invoked by a
# workflow, that it still names the gate, and that the gate has not since been wired directly.
# Any leg failing is a FINDING, exit 1, not a skip. That is the whole difference from EXCLUDED:
# this state can go red.
#
# HONEST CEILING, and both legs are weaker than they look.
#
# THE NAMES-THE-GATE LEG is a staleness tripwire against a rename or a repoint. It is NOT proof
# that the harness still DRIVES the gate: it can be satisfied by a docstring, for the same reason
# the inference above is unsound. Worse than that, and worth stating plainly because this repo's
# naming convention nearly guarantees it, the leg tests whether the gate's STEM appears anywhere in
# the harness, and for three of the four pairings the harness's own FILENAME contains that stem.
# A harness gutted of its drive but keeping its name and its header comment still passes.
# demo-preflight escapes only by an accident of hyphen against underscore. So the leg catches a
# repoint and a rename and essentially nothing else.
#
# THE IS-INVOKED LEG inherits the whole INVOKED state's bound: matching is a substring test over
# the workflow corpus, per corpus rather than per job, so a harness named only inside a step that
# can never run, under `if: false` or behind a paths filter that never matches, verifies silently.
# Neither shape exists in this repo today, and both were driven to confirm the gap is real rather
# than theoretical.
#
# What rules out fiction at declaration time is the reason text, which must name the mechanism and
# is length-checked at 60 rather than EXCLUDED's 40, because a reason here has to say HOW the
# harness drives the gate while an exclusion only has to say why nothing runs it. Proving the drive
# would mean running the harness, which is a heavier instrument than this floor.
HARNESS_COVERED: dict[str, tuple[str, str]] = {
    "demo/pre_export_gate.py": (
        "demo/test_pre_export_gate.py",
        "the harness drives it as a module, `import pre_export_gate as g`, and exercises the "
        "gate's checks in both directions, so what CI runs proves this gate can FAIL rather "
        "than only that it executes.",
    ),
    "scripts/replay_allowance_probe.py": (
        "scripts/test_replay_allowance_probe.py",
        "the harness builds the probe's path from fragments, ROOT / scripts / the filename, and "
        "drives main() through injected sys.argv with a stubbed rpc, in every direction the "
        "probe can go. The literal path is nowhere in the harness outside its docstring, which "
        "is why this pairing has to be declared rather than inferred.",
    ),
    "scripts/demo-preflight.py": (
        "scripts/test_demo_preflight.py",
        "the harness resolves the script under ROOT and drives it to prove it can report RED and "
        "can tell the two kinds of red apart; scripts/mutation-check-demo-preflight.py drives it "
        "again as a mutation control, and both run in CI.",
    ),
    "scripts/whatsapp_posture_guard.sh": (
        "scripts/test_whatsapp_posture_guard.sh",
        "the harness execs the guard by a dirname-relative path and asserts it refuses a "
        "fail-open posture as well as accepting a good one, which is the property the guard is "
        "wired into the shop unit's ExecStartPre to enforce.",
    ),
}


def verify_harness(
    wf_nc: str,
    tracked: set[str],
    mapping: dict[str, tuple[str, str]] | None = None,
) -> list[str]:
    """Both legs of every declared pairing, re-derived on every run.

    Returns the problems, so the caller can treat them as findings. A declared pairing whose
    harness has fallen out of CI is a gate that has quietly become orphaned, and reporting it as
    covered would be the silencing failure this state exists to avoid.

    `mapping` defaults to production's HARNESS_COVERED and exists so the controls can drive THIS
    function against planted pairings rather than a copy of its logic. A selftest that reimplements
    the rule it is checking agrees with itself and proves nothing.
    """
    problems: list[str] = []
    for gate, (harness, _why) in sorted(
        (HARNESS_COVERED if mapping is None else mapping).items()
    ):
        if gate not in tracked:
            problems.append(gate + ": declared harness-covered but not tracked in git.")
            continue
        if harness not in tracked:
            problems.append(
                gate + ": its declared harness " + harness + " is not tracked in git."
            )
            continue
        if gate in wf_nc:
            problems.append(
                gate
                + ": a workflow now invokes it directly, so this entry excuses nothing and"
                + " would suppress the check for it. Delete the entry."
            )
        if harness not in wf_nc:
            problems.append(
                gate
                + ": its harness "
                + harness
                + " is invoked by no workflow, so the coverage this entry claims does not"
                + " exist and the gate is orphaned."
            )
        try:
            body = (ROOT / harness).read_text(encoding="utf-8", errors="replace")
        except OSError:
            problems.append(gate + ": its harness " + harness + " could not be read.")
            continue
        if pathlib.Path(gate).stem not in body:
            problems.append(
                gate
                + ": its harness "
                + harness
                + " no longer names it, so the pairing has gone stale."
            )
    return problems


def git_ls(globs: tuple[str, ...]) -> list[str] | None:
    """Tracked paths for these globs, from git's own index rather than a hand list."""
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", *globs],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None
    return sorted(p.strip() for p in out.split("\n") if p.strip())


def strip_comments(text: str) -> str:
    """Drop YAML comment lines and trailing comments. A comment invokes nothing.

    Not cosmetic, and not theoretical: the inline floor this replaces matched RAW text, so a gate
    named only in a comment read as wired. See the docstring for the sibling gate that learned it.
    """
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("#"):
            continue
        out.append(line.split(" #", 1)[0] if " #" in line else line)
    return "\n".join(out)


def workflow_text() -> str | None:
    """Every workflow file concatenated, or None when there is nothing to read."""
    if not WORKFLOWS.is_dir():
        return None
    parts = [
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    ]
    return "\n".join(parts) if parts else None


def fold_declared(walk: list[str], family: str) -> list[str]:
    """The family's corpus: its convention walk, plus the gates declared harness-covered.

    Shared by main() and the selftest deliberately. The declared gates are exactly the paths no
    naming convention reaches, so a walk can never find them and a count taken before the fold
    understates coverage by however many are declared. Keeping the fold in main() alone let a
    mutation delete it with the whole suite still green, since every selftest row audits the raw
    walk. Two paths that disagree is a suite agreeing with itself.
    """
    return sorted(
        set(walk) | {g for g in HARNESS_COVERED if g.startswith(family + "/")}
    )


def audit(wf: str, paths: list[str]) -> list[str]:
    """Tracked gate paths that no workflow invokes, comments already out of the way.

    The narrowing lives HERE rather than in main(), so the selftest cannot exercise a looser
    pipeline than production does. Two paths that disagree is a suite agreeing with itself.
    """
    wf_nc = strip_comments(wf)
    return [
        p
        for p in paths
        if p not in EXCLUDED and p not in HARNESS_COVERED and p not in wf_nc
    ]


def main() -> int:
    wf = workflow_text()
    if wf is None:
        print("CANNOT CHECK: no workflow files found under .github/workflows.")
        return CANNOT_CHECK

    tracked_all = git_ls(("*",))
    if tracked_all is None:
        print("CANNOT CHECK: git ls-files failed for the tracked-path walk.")
        return CANNOT_CHECK
    tracked_set = set(tracked_all)

    scanned_total = 0
    orphans: list[str] = []
    lines: list[str] = []
    declared_seen: list[str] = []
    harness_seen: list[str] = []

    for family, (globs, floor) in FAMILIES.items():
        paths = git_ls(globs)
        if paths is None:
            print(f"CANNOT CHECK: git ls-files failed for the {family} family.")
            return CANNOT_CHECK
        # THE FLOOR IS CHECKED ON THE GLOB WALK ALONE, before the declared gates are folded in.
        # A hand-written list cannot vouch for a walk that has stopped reading, and adding to the
        # count first would let four declarations paper over a discovery that returned nothing.
        if len(paths) < floor:
            print(
                f"CANNOT CHECK: the {family} walk found {len(paths)} gate(s), expected at "
                f"least {floor}."
            )
            print(
                "      The walk is broken, so a clean result here would mean nothing."
            )
            return CANNOT_CHECK

        # Declared harness-covered gates join the corpus HERE, so they are counted rather than
        # invisible. The declaration is the discovery: these are the paths no naming convention
        # reaches, which is why widening a glob could never have found them.
        paths = fold_declared(paths, family)
        declared = [p for p in paths if p in EXCLUDED]
        harnessed = [p for p in paths if p in HARNESS_COVERED]
        family_orphans = audit(wf, paths)
        scanned_total += len(paths)
        orphans.extend(family_orphans)
        declared_seen.extend(declared)
        harness_seen.extend(harnessed)
        lines.append(
            f"  {family:<8} {len(paths):>3} scanned, "
            f"{len(paths) - len(declared) - len(harnessed) - len(family_orphans):>3} invoked, "
            f"{len(harnessed):>2} harness-covered, "
            f"{len(declared):>2} declared, {len(family_orphans):>2} unwired"
        )

    # THE DENOMINATOR, printed unconditionally. A bare "0 unwired" is equally consistent with a
    # healthy tree and a walk that read nothing, and only the count it was measured over separates
    # them.
    print(f"gate wiring: {scanned_total} tracked gate(s) scanned")
    for line in lines:
        print(line)
    for path in sorted(harness_seen):
        print(f"  cover {path}  <- {HARNESS_COVERED[path][0]}")
    for path in sorted(declared_seen):
        print(f"  skip  {path}")

    # BOTH FAILURE CLASSES ARE REPORTED, and the earlier shape returned on the first. Review
    # called that a reasonable prioritisation; it costs a round trip, because a run carrying a
    # broken pairing AND a genuine orphan printed only the pairing, and the orphan surfaced only
    # after someone had fixed the pairing and run again. Worse than the delay, a finding list that
    # silently stops at its first class reads as complete. Neither class is more urgent than the
    # other and printing both costs nothing.
    harness_problems = verify_harness(strip_comments(wf), tracked_set)

    if harness_problems:
        print("\nFAIL  declared harness coverage that does not hold:\n")
        for problem in harness_problems:
            print(f"    {problem}")
        print(
            "\n  A declared pairing is re-derived every run precisely so it cannot rot into a\n"
            "  silencer. Fix the wiring, or remove the entry and let the gate be reported."
        )

    if orphans:
        print("\nFAIL  gate(s) tracked in git but invoked by no workflow:\n")
        for path in sorted(orphans):
            print(f"    {path}")
        print(
            "\n  Each runs only when someone remembers, so it gates no merge and a change\n"
            "  deleting what it checks would be reported clean. Invoke it in a workflow, or\n"
            "  add it to EXCLUDED in this file with the reason it is not wired."
        )

    if harness_problems or orphans:
        return 1

    print(
        f"\nok    all {scanned_total} tracked gate(s) invoked, harness-covered, or declared"
    )
    return 0


def selftest() -> int:
    """Controls. A gate that has only ever passed has not been shown to read anything.

    The real corpus is exercised in BOTH directions: it must be clean, and a planted orphan must
    fire through the same audit() production calls.
    """
    wf = workflow_text()
    if wf is None:
        # Declared through a seam rather than allowed to crash: a selftest that dies on a missing
        # corpus is indistinguishable from one that never ran.
        print("selftest: cannot run, no workflows found under .github/workflows")
        return CANNOT_CHECK

    cases = 0
    failures: list[str] = []

    def check(name: str, got, want) -> None:
        nonlocal cases
        cases += 1
        if got == want:
            print(f"  PASS  {name}")
        else:
            failures.append(f"{name}: got {got!r}, want {want!r}")
            print(f"  FAIL  {name}: got {got!r}, want {want!r}")

    print("real corpus, both directions:")
    for family, (globs, floor) in FAMILIES.items():
        paths = git_ls(globs)
        check(
            f"the {family} walk clears its floor",
            (paths is not None) and len(paths) >= floor,
            True,
        )
        check(
            f"the live tree has every {family} gate invoked, harness-covered, or declared",
            audit(wf, paths or []),
            [],
        )

    # THE CONTROL THAT MAKES THE ROWS ABOVE MEAN ANYTHING. A path nothing names must fire.
    print("\nmust-fire controls:")
    check(
        "a gate no workflow names is reported",
        audit(wf, ["demo/verify_nothing_names_this.py"]),
        ["demo/verify_nothing_names_this.py"],
    )
    check(
        "an unwired gate is still reported alongside wired siblings",
        audit(
            wf, ["demo/verify_wallet_picker.py", "demo/verify_nothing_names_this.py"]
        ),
        ["demo/verify_nothing_names_this.py"],
    )

    print("\nmust-not-fire controls:")
    check(
        "a gate a workflow invokes is not reported",
        audit(wf, ["demo/verify_wallet_picker.py"]),
        [],
    )
    check(
        "a declared gate is not reported",
        audit(wf, ["demo/verify_qr_in_encoded_cut.py"]),
        [],
    )

    # COMMENT STRIPPING, both directions, because its own failure is silent: if strip_comments
    # degenerated to the identity function every case above would still pass and the gate would be
    # quietly back to counting prose as wiring.
    print("\ncomment stripping:")
    commented_only = "jobs:\n  x:\n    steps:\n      # run demo/verify_only_in_a_comment.py one day\n"
    check(
        "a gate named ONLY in a comment is reported",
        audit(commented_only, ["demo/verify_only_in_a_comment.py"]),
        ["demo/verify_only_in_a_comment.py"],
    )
    real_step = (
        "jobs:\n  x:\n    steps:\n      - run: python3 demo/verify_really_run.py\n"
    )
    check(
        "a gate named in a real run step is not reported",
        audit(real_step, ["demo/verify_really_run.py"]),
        [],
    )
    check(
        "a trailing comment is stripped too",
        audit(
            "jobs:\n  x:\n    steps:\n      - run: true # demo/verify_trailing.py\n",
            ["demo/verify_trailing.py"],
        ),
        ["demo/verify_trailing.py"],
    )

    # EVERY DECLARED ENTRY MUST CARRY A REASON. An empty string would pass the audit above while
    # documenting nothing, which is the silencer shape this gate exists to prevent.
    print("\nevery declared exclusion carries a reason:")
    check(
        "no EXCLUDED entry has an empty or trivial reason",
        sorted(p for p, why in EXCLUDED.items() if len(why.strip()) < 40),
        [],
    )
    # And every declared entry must actually be tracked, or the list is accumulating dead rows that
    # would silently cover a future file of the same name.
    tracked_all = git_ls(("*",)) or []
    check(
        "every EXCLUDED entry is a tracked path",
        sorted(p for p in EXCLUDED if p not in set(tracked_all)),
        [],
    )
    check(
        "every HARNESS_COVERED gate and harness is a tracked path",
        sorted(
            p
            for g, (h, _w) in HARNESS_COVERED.items()
            for p in (g, h)
            if p not in set(tracked_all)
        ),
        [],
    )
    # NO REDUNDANT ENTRIES. An exclusion for a gate that a workflow already invokes excuses
    # something that passes anyway, and it is not harmless: the exclusion suppresses this check
    # for that path permanently, so if the invocation were later deleted the floor would keep
    # reporting green over a real orphan. One inherited entry was in exactly that state when this
    # file was written, which is why the control exists rather than the habit.
    wf_nc = strip_comments(wf)
    check(
        "no EXCLUDED entry is redundant with a real invocation",
        sorted(p for p in EXCLUDED if p in wf_nc),
        [],
    )

    # HARNESS COVERAGE. The state exists so a transitively covered gate is neither invisible nor
    # falsely reported, and the whole argument for it over an EXCLUDED row is that it CAN GO RED.
    # These are the over-correction controls that prove it does: each plants a pairing that has
    # decayed in one specific way, and each must fire. Without them the new state is exactly the
    # silencer it was written to avoid.
    def legs(problems: list[str]) -> list[str]:
        """Which LEG each problem came from, so a control pins the leg and not the path.

        Written after the redundancy control fired two problems on one planted pairing: the gate
        was wired directly AND the harness did not name it. Keyed on the path, that control passed
        while being unable to distinguish the leg under test from its neighbour, so it would have
        stayed green with the redundancy leg removed.
        """
        tags = {
            "invokes it directly": "redundant",
            "is invoked by no workflow": "harness-unwired",
            "no longer names it": "stale-pairing",
            "declared harness-covered but not tracked": "gate-untracked",
            "is not tracked in git": "harness-untracked",
            "could not be read": "harness-unreadable",
        }
        out = []
        for problem in problems:
            out.append(
                next(
                    (tag for needle, tag in tags.items() if needle in problem),
                    "UNTAGGED:" + problem,
                )
            )
        return sorted(out)

    # DISCOVERY INVARIANTS. Both were established by widening the walk, and the mutation matrix
    # showed both were unprotected: reverting the widening left the suite fully green, because a
    # denominator nothing asserts is a denominator that can be quietly reduced. These assert the
    # PROPERTY rather than today's filenames, so they survive a gate being renamed or retired and
    # still go red if the walk narrows.
    print("\ndiscovery invariants:")
    # PER CONVENTION, not per family. The first version of this control asked only whether a
    # family carried SOME .sh glob, and the mutation that drops scripts/check-*.sh left three
    # other .sh globs standing, so the control stayed green while one convention had gone
    # python-only again. Pair each glob with its sibling in the other extension and the mutation
    # reddens, which is the difference between a control and an ornament.
    check(
        "every convention glob is paired across .py and .sh, so no single one can go back",
        sorted(
            g
            for globs, _f in FAMILIES.values()
            for g in globs
            if g[:-3] + (".sh" if g.endswith(".py") else ".py") not in globs
        ),
        [],
    )
    corpus_all: set[str] = set()
    for family, (globs, _floor) in FAMILIES.items():
        corpus_all |= set(fold_declared(git_ls(globs) or [], family))
    check(
        "every declared harness-covered gate is inside the corpus main() scans",
        sorted(g for g in HARNESS_COVERED if g not in corpus_all),
        [],
    )

    print("\nharness coverage, must-not-fire:")
    tracked_set = set(tracked_all)
    check(
        "the live tree's declared pairings all hold",
        verify_harness(wf_nc, tracked_set),
        [],
    )
    check(
        "a harness-covered gate is not reported as an orphan",
        audit(wf, ["demo/pre_export_gate.py"]),
        [],
    )

    print("\nharness coverage, must-fire:")
    # The harness itself falls out of CI. This is the decay an EXCLUDED row could never catch:
    # the gate becomes genuinely orphaned and the entry would go on excusing it.
    check(
        "a pairing whose harness no workflow invokes is reported",
        legs(
            verify_harness(
                "jobs:\n  x:\n    steps:\n      - run: true\n",
                tracked_set,
                {
                    "demo/pre_export_gate.py": (
                        "demo/test_pre_export_gate.py",
                        "planted: the harness is not named by this synthetic corpus.",
                    )
                },
            )
        ),
        ["harness-unwired"],
    )
    # The pairing is repointed at a harness that has nothing to do with the gate. CONTROL for the
    # fixture: scripts/check-all.py names pre_export_gate 0 times, while the real harness names it
    # 3, so the check is reading the body rather than always firing.
    check(
        "a pairing whose harness no longer names the gate is reported",
        legs(
            verify_harness(
                "jobs:\n  x:\n    steps:\n      - run: python3 scripts/check-all.py\n",
                tracked_set,
                {
                    "demo/pre_export_gate.py": (
                        "scripts/check-all.py",
                        "planted: a wired harness that does not name this gate.",
                    )
                },
            )
        ),
        ["stale-pairing"],
    )
    # Redundancy, the same trapdoor the EXCLUDED control guards, at this state instead. A gate CI
    # invokes directly needs no entry, and leaving one suppresses the check for it permanently.
    check(
        "a pairing for a gate a workflow already invokes directly is reported",
        legs(
            verify_harness(
                "jobs:\n  x:\n    steps:\n"
                "      - run: python3 demo/pre_export_gate.py\n"
                "      - run: python3 demo/test_pre_export_gate.py\n",
                tracked_set,
                {
                    "demo/pre_export_gate.py": (
                        "demo/test_pre_export_gate.py",
                        "planted: the gate is wired directly, so this entry excuses nothing.",
                    )
                },
            )
        ),
        ["redundant"],
    )
    check(
        "a pairing naming an untracked gate is reported",
        legs(
            verify_harness(
                wf_nc,
                tracked_set,
                {
                    "demo/verify_nothing_names_this.py": (
                        "demo/test_pre_export_gate.py",
                        "planted: the gate does not exist.",
                    )
                },
            )
        ),
        ["gate-untracked"],
    )
    check(
        "a pairing naming an untracked harness is reported",
        legs(
            verify_harness(
                wf_nc,
                tracked_set,
                {
                    "demo/pre_export_gate.py": (
                        "demo/test_nothing_here.py",
                        "planted: the harness does not exist.",
                    )
                },
            )
        ),
        ["harness-untracked"],
    )
    # EVERY DECLARED PAIRING CARRIES A REASON THAT NAMES THE MECHANISM. The reason is what rules
    # out fiction at declaration time, since the mechanical legs cannot prove the harness DRIVES
    # the gate. An entry with a thin reason is an assertion wearing a declaration's clothes.
    # ALL SIX LEGS, not one. The earlier fixture passed an empty tracked set, so both planted
    # pairings short-circuited on the untracked-gate branch and the control drove a single leg
    # while its name claimed it drove every one. The tracked set is a parameter, so it can name a
    # path that does not exist on disk, which is what reaches the unreadable branch.
    all_legs = legs(
        verify_harness(
            "jobs:\n  x:\n    steps:\n"
            "      - run: python3 demo/pre_export_gate.py\n"
            "      - run: python3 demo/test_pre_export_gate.py\n"
            "      - run: python3 no/such/harness.py\n",
            {
                "demo/pre_export_gate.py",
                "demo/test_pre_export_gate.py",
                "scripts/check-all.py",
                "scripts/demo-preflight.py",
                "scripts/replay_allowance_probe.py",
                "no/such/harness.py",
            },
            {
                # redundant: the gate is wired directly, and the harness names it
                "demo/pre_export_gate.py": ("demo/test_pre_export_gate.py", "planted"),
                # gate-untracked
                "demo/verify_nothing_names_this.py": (
                    "demo/test_pre_export_gate.py",
                    "planted",
                ),
                # harness-untracked
                "scripts/demo-preflight.py": ("scripts/test_absent.py", "planted"),
                # harness-unwired AND stale-pairing, from one unwired unrelated harness
                "scripts/replay_allowance_probe.py": (
                    "scripts/check-all.py",
                    "planted",
                ),
            },
        )
    ) + legs(
        # harness-unreadable: tracked by the fixture, absent from disk, and wired
        verify_harness(
            "jobs:\n  x:\n    steps:\n      - run: python3 no/such/harness.py\n",
            {"demo/pre_export_gate.py", "no/such/harness.py"},
            {"demo/pre_export_gate.py": ("no/such/harness.py", "planted")},
        )
    )
    check(
        "no leg the verifier emits goes untagged, so no control passes on an unread message",
        [t for t in all_legs if t.startswith("UNTAGGED")],
        [],
    )
    check(
        "the tagger fixture drives every leg the verifier can emit",
        sorted(set(all_legs)),
        [
            "gate-untracked",
            "harness-unreadable",
            "harness-untracked",
            "harness-unwired",
            "redundant",
            "stale-pairing",
        ],
    )
    check(
        "no HARNESS_COVERED entry has a thin reason",
        sorted(g for g, (_h, why) in HARNESS_COVERED.items() if len(why.strip()) < 60),
        [],
    )
    # And the two declared states must stay disjoint: a path in both would be excused twice, and
    # whichever check ran second would never be reached.
    check(
        "no path is both EXCLUDED and HARNESS_COVERED",
        sorted(set(EXCLUDED) & set(HARNESS_COVERED)),
        [],
    )

    # F1, AND IT IS THE ONE THE REST OF THIS SUITE COULD NOT SEE. Every control above calls
    # verify_harness DIRECTLY, so all of them keep passing while main() consults it never.
    # Measured before this control existed: replacing main()'s call with an empty list left the
    # suite at 27 of 27 and main at rc 0, which means the entire third state could be deleted from
    # production with everything green. The PR's whole argument is that this state can go red, and
    # nothing demonstrated that the PROGRAM can, only that the FUNCTION can. These two drive
    # main() itself, through the module-level map production actually reads.
    print("\nmain() end to end, through the map production reads:")

    def main_run(
        mapping: dict[str, tuple[str, str]] | None = None,
        drop_excluded: str | None = None,
    ) -> tuple[int, str]:
        """Drive main() through the module-level maps production reads, and capture both.

        Swapping the globals rather than passing arguments is deliberate: main() reads them, so a
        control that took a parameter would exercise a path production does not have.
        """
        saved_h, saved_e = dict(HARNESS_COVERED), dict(EXCLUDED)
        if mapping is not None:
            HARNESS_COVERED.clear()
            HARNESS_COVERED.update(mapping)
        if drop_excluded is not None:
            EXCLUDED.pop(drop_excluded, None)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = main()
            return rc, buf.getvalue()
        finally:
            HARNESS_COVERED.clear()
            HARNESS_COVERED.update(saved_h)
            EXCLUDED.clear()
            EXCLUDED.update(saved_e)

    def main_rc(mapping: dict[str, tuple[str, str]] | None) -> int:
        return main_run(mapping)[0]

    check("main() returns 0 on the live tree", main_rc(None), 0)
    check(
        "main() itself returns 1 when a declared pairing has decayed",
        main_rc(
            {
                "demo/pre_export_gate.py": (
                    "scripts/check-all.py",
                    "planted: a harness no workflow invokes, which does not name this gate.",
                )
            }
        ),
        1,
    )

    # BOTH FAILURE CLASSES IN ONE RUN. Restoring the early return after the harness block left the
    # whole suite green, because every other control drives one class at a time. Plant both at
    # once: a decayed pairing, and an orphan made by dropping a declared gate's exclusion. A run
    # that stops at the first class reads as a complete finding list, so the report is the thing
    # under test here rather than the exit code, which was right either way.
    both_rc, both_out = main_run(
        {
            "demo/pre_export_gate.py": (
                "scripts/check-all.py",
                "planted: an unwired harness that does not name this gate.",
            )
        },
        drop_excluded="scripts/check-all.py",
    )
    check("a run carrying both failure classes exits 1", both_rc, 1)
    check(
        "and reports BOTH, rather than stopping at the first",
        sorted(
            tag
            for tag, needle in (
                ("harness", "declared harness coverage that does not hold"),
                ("orphans", "tracked in git but invoked by no workflow"),
            )
            if needle in both_out
        ),
        ["harness", "orphans"],
    )

    # THE FLOOR IS A NUMBER UNTIL SOMETHING TRIPS IT. This drives the real walk minus the largest
    # convention pair and requires the family to fall under its floor, which is what makes 60 a
    # bar rather than a constant nobody has tested.
    print("\nthe floor still bites after the widening:")
    scripts_globs, scripts_floor = FAMILIES["scripts"]
    without_check = tuple(
        g for g in scripts_globs if not g.startswith("scripts/check-")
    )
    remaining = git_ls(without_check) or []
    check(
        "dropping the largest scripts convention pair falls under the floor",
        len(remaining) < scripts_floor,
        True,
    )
    check(
        "and the full walk clears it, so the floor is not simply unreachable",
        len(git_ls(scripts_globs) or []) >= scripts_floor,
        True,
    )

    print(f"\n{cases - len(failures)} of {cases} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
