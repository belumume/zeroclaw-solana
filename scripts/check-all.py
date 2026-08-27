#!/usr/bin/env python3
"""Run EVERY publish gate, so which gates ran stops depending on what someone typed.

WHY THIS EXISTS. The one-pager, a judge-facing deliverable, was committed and pushed with
two em-dashes in it. Four gates were run before that commit and the slop gate was not one
of them, so the check that would have caught it reported nothing and looked exactly like a
check that passed. That is not a one-off: three different ad-hoc subsets were run in a
single session, each chosen by hand, none of them complete.

SCOPE IS DISCOVERED, NOT LISTED, and that decision was earned the hard way in the same
session: a checker written minutes earlier hardcoded which shapes were valid and produced
72 false positives, every one a correct file. A hand-written list here would rot the same
way, because a gate added later joins no list by itself.

THE FLOOR IS THE POINT. A discovery step that silently finds nothing would run zero gates
and report a clean sweep, which is the exact false-green this whole file exists to prevent.
Fewer gates than the floor is a broken walk, not a healthy repo, and it exits non-zero.

Gates needing network or a live host are declared below WITH their reason rather than
quietly omitted, because an undocumented omission is indistinguishable from an oversight.

A GATE THAT CANNOT CHECK MEANS TWO OPPOSITE THINGS, and one signal cannot carry both.
"this machine lacks a resource" is nobody's defect and must not redden a developer's run.
"my positive control is dead" is a defect in the repo, and a gate that can no longer
demonstrate it can FAIL has stopped being evidence: it certifies blind, and everything
downstream reads its silence as a pass. Folded together, the second hides behind the
first. So they are separate exit codes with separate buckets and separate arithmetic --
see CANNOT_CHECK and CONTROL_DEAD below.

Run: python3 scripts/check-all.py
"""

import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
MIN_GATES = 35  # below this the discovery walk is broken; see the docstring.
# Raised from 33 to 35 on 2026-08-27, and the raise is TWO units for two separate reasons, stated
# apart so neither hides inside the other. One unit is check-gate-wiring.py joining, which is the
# ordinary case this rule exists for. The other is drift that was already here: discovery returned
# 34 against a floor of 33 before that gate was written, so the constant was slack by one on
# arrival and one more gate could have vanished unnoticed. That is the FOURTH time this number has
# fallen behind its own rule, which is worth reading as a fact about hand-maintained constants
# rather than about the people maintaining them. Re-derive rather than trusting this number:
#   git ls-files 'scripts/check-*.py' | wc -l   ->  one MORE than this, check-all.py being excluded
# Raised from 32 to 33 on 2026-08-27: check-reproduce-path-coverage landed on this branch and
# the floor was not raised with it, leaving it slack by one against a tracked set of 34. A floor
# slack by one detects nothing, which is this file's own stated argument, and this is the THIRD
# time the same drift has happened here.
# Raised from 31 to 32 on 2026-08-20 when check-test-count-agreement joined, per this file's own
# rule two lines down. That gate is the only one here that needs a Rust toolchain: with cargo on
# PATH it RUNS the suites and is by some distance the slowest gate in this walk, and without cargo
# it self-reports exit 2 and costs nothing. It is deliberately NOT in EXCLUDED below, because that
# list is for gates that cannot say so themselves, and this one can. Export a shared
# CARGO_TARGET_DIR before running check-all if you want it to reuse an existing build.
# Raised from 30 to 31 on 2026-08-20 when check-pr-base-freshness joined, per this file's own
# rule two lines down: the floor is one BELOW the tracked count, and a floor slack by one
# detects nothing.
# Raised from 27 to 30 on 2026-08-19 because the constant had drifted three below the rule stated
# two lines down, which is the only rule this floor has. The tracked set was 31 and discovery
# returned 30 while the floor read 27, so three gates could vanish and the walk would still look
# healthy -- and by this file's own argument a floor slack by five "cannot detect a discovery
# break, which is the only thing it exists to catch". Re-derive rather than trusting this number:
#   git ls-files 'scripts/check-*.py' | wc -l   ->  one MORE than this, check-all.py being excluded
# Raised from 25 to 27 by TWO gates landing in parallel: check-untracked-root-divergence on main,
# and check-plugin-count-agreement on this branch. Each side independently wrote 26, which is the
# arithmetic a merge cannot do for you: taking either side verbatim leaves the floor slack by one
# against a tree that now has both, and a floor slack by one detects nothing.
# Raised from 7 when check-correction-traces joined. A floor slack by five gates cannot detect
# a discovery break, which is the only thing it exists to catch. The number is what discovery
# RETURNS, which excludes check-all.py itself, so it is one below the tracked file count.

# Declared exclusions, each with the reason it cannot run unattended on a clean machine.
# Only what CANNOT self-report. A gate that can tell us it is unrunnable does so with exit 2,
# which is read below, so it does not belong in a hand-maintained list. check-config-drift was
# listed here until 2026-08-04 on a reason I asserted without testing; the reason turned out to
# be true, and the listing was still the wrong mechanism.
EXCLUDED = {
    "check-host-compat.sh": "not a .py gate; clones upstream, belongs in host-drift.yml on a schedule",
}

# The verdict protocol every discovered gate speaks. 0 passes, 1 is a finding about the
# subject, and anything not named here stays a FAILURE, which is the safe default: a code
# nobody has taught this file about reddens rather than being waved through.
CANNOT_CHECK = 2  # the gate ran and reported it had nothing to compare; not a finding
# ENVIRONMENT is the whole of CANNOT_CHECK's meaning: a resource THIS MACHINE lacks (the
# box's config, a Rust toolchain, a browser). Remedy is to run it elsewhere, nothing in the
# repo is wrong, so it does not block.
CONTROL_DEAD = 3
# The gate ran and reported that it can no longer produce the OPPOSITE verdict: a positive
# control that stopped firing, a probe that was never registered, a must-not-fire pin quoting
# a sentence the repo no longer ships. Remedy is a fix IN THE REPO, and no machine will make
# it evidence again, so it BLOCKS. A gate reaches this bucket only by choosing this code
# deliberately -- there is no prose to match and no list to join, so it cannot be entered by
# accident. 3 extends the contiguous 0/1/2 protocol and is unused by any gate's main() today;
# the repo's other 3s are selftest-only failure codes, which are blocking anyway, so a leak
# from one would mislabel a red rather than manufacture a green.
#
# HONEST CEILING, because this file must not oversell itself. Nothing here can promote a
# gate whose control dies and which still exits 2 -- the discrimination lives in the gate,
# and the code it returns is the gate author's claim about its own state.


def discover():
    """Every tracked check-*.py, from git's own index rather than a hand list."""
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "scripts/check-*.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout
    names = sorted(pathlib.Path(p).name for p in out.split("\n") if p.strip())
    return [n for n in names if n != "check-all.py"]


def verdict_line(r) -> str:
    """The gate's own words for a refusal, from whichever stream it used.

    Gates split this by habit: check-config-drift explains itself on stdout, and
    check-correction-traces writes every refusal to stderr. Reading stdout alone printed
    the fallback for the second kind, so the one line saying WHY a gate refused -- the whole
    value of the row -- was dropped for exactly the gates whose refusal matters most.
    """
    for stream in (r.stdout, r.stderr):
        text = (stream or "").strip()
        if text:
            return text.split("\n")[0][:74]
    return ""


def main() -> int:
    gates = discover()
    if len(gates) < MIN_GATES:
        print(
            f"FAIL  discovery found {len(gates)} gate(s); expected at least {MIN_GATES}."
        )
        print("      The walk is broken, so a clean result here would mean nothing.")
        return 2

    runnable = [g for g in gates if g not in EXCLUDED]
    print(f"running {len(runnable)} gate(s), {len(EXCLUDED)} declared-excluded\n")

    failures = []
    not_checked = []
    blocked = []
    for g in runnable:
        t0 = time.time()
        r = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / g)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT),
        )
        dt = time.time() - t0
        if r.returncode in (CANNOT_CHECK, CONTROL_DEAD):
            why = verdict_line(r)
            # The two refusals part here, and this branch is the whole discrimination: the
            # mutation control in test_check_all.py neutralises exactly this line and requires
            # a dead control to go back to reporting a clean run.
            if r.returncode == CONTROL_DEAD:
                # Not a finding about the subject, and not a pass either. The gate is saying
                # it cannot demonstrate it can fail, so its silence is worth nothing.
                print(f"  DEAD {g:<28} {why or 'cannot prove it can fail'}")
                blocked.append((g, (r.stdout or "") + (r.stderr or "")))
            else:
                # The gate ran and said it had nothing to compare. That is not a finding, and
                # treating it as one is how a suite trains people to ignore reds.
                print(f"  n/a  {g:<28} {why or 'reported it cannot check'}")
                not_checked.append(g)
            continue
        mark = "ok  " if r.returncode == 0 else "FAIL"
        print(f"  {mark} {g:<28} rc={r.returncode}  {dt:5.1f}s")
        if r.returncode != 0:
            failures.append((g, r.returncode, (r.stdout or r.stderr or "").strip()))

    for g, reason in sorted(EXCLUDED.items()):
        print(f"  skip {g:<28} {reason}")

    # Printed BEFORE the failures block and never instead of it: a run can hold both, and
    # hiding either behind the other is the same one-signal-two-meanings defect one level up.
    if blocked:
        print(
            f"\n{len(blocked)} gate(s) CANNOT DEMONSTRATE THEY CAN FAIL, so a clean "
            f"result from them is not evidence:\n"
        )
        for g, out in blocked:
            print(f"  --- {g} (rc={CONTROL_DEAD}) ---")
            for line in out.strip().split("\n")[-12:]:
                print(f"    {line}")

    if failures:
        print(f"\n{len(failures)} gate(s) FAILED:\n")
        for g, rc, out in failures:
            print(f"  --- {g} (rc={rc}) ---")
            for line in out.split("\n")[-12:]:
                print(f"    {line}")
        return 1

    # A gate that could not run is not a passing gate. Folding it into the pass count is the
    # false-green this repo argues against everywhere else, and it read "all 11 pass" on a
    # machine where one gate never ran. A gate whose CONTROL is dead is not a passing gate
    # either, and it comes out of the same numerator for the same reason.
    checked = len(runnable) - len(not_checked) - len(blocked)
    caveats = []
    if not_checked:
        caveats.append(
            f"{len(not_checked)} COULD NOT CHECK and is NOT a pass: {', '.join(not_checked)}"
        )
    if blocked:
        caveats.append(
            f"{len(blocked)} CANNOT PROVE IT CAN FAIL and BLOCKS this run: "
            f"{', '.join(g for g, _ in blocked)}"
        )
    if caveats:
        print(f"\n{checked} of {len(runnable)} gate(s) pass. " + " ".join(caveats))
    else:
        print(f"\nall {checked} gate(s) pass")
    # 2, matching the discovery-floor refusal above: this run's verdict is not trustworthy,
    # which is a different statement from 1, where a gate found something real.
    return 2 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
