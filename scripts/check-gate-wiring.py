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

EXIT CODES, the repo's protocol. 0 every tracked gate is invoked or declared. 1 at least one is
neither. 2 could not check, which covers a missing workflow directory, a git failure, and a
discovery walk returning fewer files than its floor, since a broken walk reports every gate clean
at once and a clean result would mean nothing.

Run: python3 scripts/check-gate-wiring.py [--selftest]
"""

from __future__ import annotations

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
            "scripts/verify*.py",
            "scripts/mutation-check-*.py",
            "scripts/test_*.py",
        ),
        40,
    ),
    # verify* catches both spellings the repo uses, verify_foo.py and verify-foo.py.
    "demo": (("demo/verify*.py", "demo/test_*.py", "demo/check_*.py"), 10),
}
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


def audit(wf: str, paths: list[str]) -> list[str]:
    """Tracked gate paths that no workflow invokes, comments already out of the way.

    The narrowing lives HERE rather than in main(), so the selftest cannot exercise a looser
    pipeline than production does. Two paths that disagree is a suite agreeing with itself.
    """
    wf_nc = strip_comments(wf)
    return [p for p in paths if p not in EXCLUDED and p not in wf_nc]


def main() -> int:
    wf = workflow_text()
    if wf is None:
        print("CANNOT CHECK: no workflow files found under .github/workflows.")
        return CANNOT_CHECK

    scanned_total = 0
    orphans: list[str] = []
    lines: list[str] = []
    declared_seen: list[str] = []

    for family, (globs, floor) in FAMILIES.items():
        paths = git_ls(globs)
        if paths is None:
            print(f"CANNOT CHECK: git ls-files failed for the {family} family.")
            return CANNOT_CHECK
        if len(paths) < floor:
            print(
                f"CANNOT CHECK: the {family} walk found {len(paths)} gate(s), expected at "
                f"least {floor}."
            )
            print(
                "      The walk is broken, so a clean result here would mean nothing."
            )
            return CANNOT_CHECK

        declared = [p for p in paths if p in EXCLUDED]
        family_orphans = audit(wf, paths)
        scanned_total += len(paths)
        orphans.extend(family_orphans)
        declared_seen.extend(declared)
        lines.append(
            f"  {family:<8} {len(paths):>3} scanned, "
            f"{len(paths) - len(declared) - len(family_orphans):>3} invoked, "
            f"{len(declared):>2} declared, {len(family_orphans):>2} unwired"
        )

    # THE DENOMINATOR, printed unconditionally. A bare "0 unwired" is equally consistent with a
    # healthy tree and a walk that read nothing, and only the count it was measured over separates
    # them.
    print(f"gate wiring: {scanned_total} tracked gate(s) scanned")
    for line in lines:
        print(line)
    for path in sorted(declared_seen):
        print(f"  skip  {path}")

    if orphans:
        print("\nFAIL  gate(s) tracked in git but invoked by no workflow:\n")
        for path in sorted(orphans):
            print(f"    {path}")
        print(
            "\n  Each runs only when someone remembers, so it gates no merge and a change\n"
            "  deleting what it checks would be reported clean. Invoke it in a workflow, or\n"
            "  add it to EXCLUDED in this file with the reason it is not wired."
        )
        return 1

    print(f"\nok    all {scanned_total} tracked gate(s) invoked or declared")
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
            f"the live tree has every {family} gate invoked or declared",
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
    tracked_all = set(git_ls(("*",)) or [])
    check(
        "every EXCLUDED entry is a tracked path",
        sorted(p for p in EXCLUDED if p not in tracked_all),
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

    print(f"\n{cases - len(failures)} of {cases} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
