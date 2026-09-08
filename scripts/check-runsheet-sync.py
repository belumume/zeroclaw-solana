#!/usr/bin/env python3
"""Assert the PUBLISHED run sheet and the source notes agree on every load-bearing demo fact.

WHY THIS EXISTS: the notes live in the repo and the run sheet is a published HTML page held
outside it, so a repo-wide grep is structurally blind to the page. Twice on 2026-08-26 a
correction landed in notes/DEMO-SCRIPT.md and not on the page he actually reads live.

THREE STATES, never two. A missing page is CANNOT_CHECK (rc=2), not a pass and not a failure:
folding "I could not look" into either verdict is how a green run stops meaning anything.

Run:  python scripts/check-runsheet-sync.py [path-to-run-sheet.html]
      rc=0 agree | rc=1 DISAGREE | rc=2 CANNOT CHECK

DELIBERATELY UNTRACKED. Do not "fix" that by committing it. Both files it reads, notes/
DEMO-SCRIPT.md and notes/JUDGE-DRILL.md, are gitignored, so a tracked copy would be a script no
clone can run, which is the reachability defect this repo guards against, pointed the other way.
It also compares against a private published page whose URL is not repo content.

THE CONSEQUENCE, since untracked means unbacked: it lives on one disk in a working tree several
sessions share, and nothing that discards a working tree names the untracked files it removes.
A byte-identical copy is kept under the internal snapshot tree, refreshed whenever the fact list
changes. If you edit the FACTS, refresh that copy in the same pass.
"""
import sys, re, os, glob, tempfile, pathlib

# (label, must appear in notes, must appear in page) -- the facts a wrong value would cost the demo
FACTS = [
    ("phone balance",        "0.807130",                 "0.807130"),
    ("stale balance gone",   None,                       "!0.207130"),
    ("spine fallback",       "verify_proof_offline.py",  "verify_proof_offline.py"),
    ("clock ambiguity",      "01:00Z",                   "00:00Z"),
    ("mention trap",         "mention span",             "mention entity"),
    ("RECUSADO armed",       "NOT SHOWING",              "not showing it"),
    ("Q5 chain claim gone",  "!cannot exceed what the chain allows",
                             "!cannot exceed what the chain allows"),
    # ADDED after this list passed 7/7 while THREE whole questions were absent from the page.
    # A fact list that does not name a thing cannot notice the thing going missing.
    ("Q10 use-case",         "Who actually uses this",   "Who actually uses this"),
    ("Q11 rival",            "zeroclaw-x402",            "zeroclaw-x402"),
    ("Q11 whole field",      "govscan",                  "govscan"),
    ("Q12 upstream",         "contribute anything upstream", "contribute anything upstream"),
    ("answer budget",        "40 SECONDS",               "40 seconds"),
    # ADDED after a live round trip showed the docs named the WRONG rate source and an
    # understated latency, while this check still reported 12/12.
    ("rate source BCB PTAX", "BCB PTAX",                 "BCB PTAX"),
    # Assert on the BAD CLAIM, not on the token: both files must QUOTE "a named ECB rate" in a
    # do-not-say line, so an absence check on the token can never pass. A prohibition has to
    # name what it forbids.
    ("wrong claim retired",  "!settles USDC at a named ECB", "!settles USDC at a named ECB"),
    ("latency measured",     "+10 seconds",              "+10 seconds"),
    # STRUCTURAL, added 2026-08-27. A fact list cannot notice a STRUCTURE it does not name.
    # This gate passed 15 of 15 while the published page still carried a FIVE-beat script and the
    # notes had been restructured to SEVEN, plus a revocation answer and a base-rate correction the
    # page had none of. Three times today a gate has certified something blind; pinning the shape
    # is what stops this one doing it a fourth time.
    ("beat 7 exists",        "BEAT 7",                   "BEAT 7"),
    ("beat 4 DePIN",         "BEAT 4",                   "BEAT 4"),
    ("revocation answer",    "revokeDelegation",         "revokeDelegation"),
    ("base rate present",    "2.9% per day",             "2.9% per day"),
    ("old 5-beat gone",      "!1:15 - 2:25",             "!1:15 - 2:25"),
    # Added after a cold read found beat 7 telling him to cut the wifi while screen-sharing,
    # and three places that describe an artifact the document never supplies.
    ("wifi warning",         "DO NOT TOUCH THE WIFI",    "DO NOT TOUCH THE WIFI"),
    ("wifi instruction gone","!genuinely off",           "!genuinely off"),
    # keyed on a lowercase phrase, not the heading: the heading renders title-case on the
    # page, so an uppercase pattern reported it ABSENT while it was there three times.
    ("beat 6 pay URL",       "WiLHJ%3Famount%3D0.25",    "WiLHJ%3Famount%3D0.25"),
    ("beat 6 refused URL",   "WiLHK%3Famount%3D0.25",    "WiLHK%3Famount%3D0.25"),
    ("beat 1 fallback URL",  "cFQrCuRAMe3xBPxFX8YtFE9", "cFQrCuRAMe3xBPxFX8YtFE9"),
    ("telegram artifact",    "zeroclaw_shop_bot",        "zeroclaw_shop_bot"),
    # The order-value control IS deployed. Two SPOKEN clauses said otherwise and survived a task
    # closure, because the needle used to verify that closure was a string from ARGUMENT.md that
    # had never been in the drill. A true zero for a string that was never there.
    ("order value deployed",  "both are live",            "both are live"),
    ("stale not-deployed gone","!not yet on the deployed node","!not yet on the deployed node"),
]

def snapshot_note():
    """Report whether the insurance copy of THIS file has drifted.

    It NEVER changes the verdict. Whether a backup is current and whether the notes and the page
    agree are different questions, and folding one into the other is how a check starts meaning
    two things. This prints a line and nothing else.

    It exists because this file is deliberately untracked, so the snapshot is its only other copy,
    and a refresh discipline written in a docstring decays with nobody noticing. Both sides are
    read with carriage returns stripped: one side CRLF and the other LF would manufacture a
    permanent false drift, which is the failure that makes a warning get ignored.
    """
    # NEWEST dated directory, never a pinned one. A hardcoded date goes stale the day someone
    # makes the next one, and this would then report NO SNAPSHOT forever against a copy that
    # exists. A warning that cries wolf is worse than no warning, because it gets learned around.
    dirs = sorted(glob.glob(os.path.join(os.path.expanduser("~"), "DEV",
                                         "zeroclaw-internal-snapshot", "at-risk-*")))
    if not dirs:
        return "  note: NO snapshot directory. This file is untracked and would be single-copy."
    snap = os.path.join(dirs[-1], os.path.basename(__file__))
    def norm(path):
        return pathlib.Path(path).read_text(encoding="utf-8").replace(chr(13), "")
    try:
        drifted = norm(__file__) != norm(snap)
    except OSError:
        return "  note: NO snapshot copy found. This file is untracked and would be single-copy."
    if drifted:
        return "  note: the snapshot copy has DRIFTED. Refresh it; it is this file only backup."
    return None


def find_page(argv):
    if len(argv) > 1:
        return pathlib.Path(argv[1])
    # DERIVED, never written out. An absolute path under a home directory names its owner, which
    # the repo identifier gate refuses, and it is wrong on any other machine. RUNSHEET_DIR
    # overrides; otherwise the platform temp dir, which is where the scratchpad actually lives.
    root = os.environ.get("RUNSHEET_DIR") or os.path.join(tempfile.gettempdir(), "claude")
    hits = glob.glob(os.path.join(root, "**", "scratchpad", "run-sheet.html"), recursive=True)
    return pathlib.Path(max(hits, key=lambda p: pathlib.Path(p).stat().st_mtime)) if hits else None

def main():
    # The PAGE merges the run sheet and the drill, so the notes side is BOTH files. Comparing
    # against only one made the check report a real page as missing content it never held.
    sources = [pathlib.Path("notes/DEMO-SCRIPT.md"), pathlib.Path("notes/JUDGE-DRILL.md")]
    missing = [str(s) for s in sources if not s.exists()]
    page = find_page(sys.argv)
    if missing:
        print("CANNOT CHECK: not found: %s (wrong cwd?)" % ", ".join(missing)); return 2
    if page is None or not page.exists():
        print("CANNOT CHECK: run-sheet.html not found. Pass its path as argv[1]."); return 2

    nt = chr(10).join(s.read_text(encoding="utf-8") for s in sources)
    pt = page.read_text(encoding="utf-8")
    print("notes %d B (%s)   page %s (%d B)"
          % (len(nt), " + ".join(s.name for s in sources), page.name, len(pt)))

    def holds(text, spec):
        if spec is None:
            return True, "n/a"
        if spec.startswith("!"):
            n = text.count(spec[1:])
            return n == 0, "absent" if n == 0 else "PRESENT x%d" % n
        n = text.count(spec)
        return n > 0, "x%d" % n if n else "MISSING"

    # THE FACT LIST CANNOT SEE CONTENT IT DOES NOT NAME, which is how this gate certified a
    # five-beat page against seven-beat notes, and later reported 28 of 28 while three new
    # definitions sat in the notes and not on the page. Adding a fact per edit does not close
    # that: the next unnamed edit is invisible again. The page is DERIVED from the notes, so
    # the structural question is whether it was rebuilt AFTER they last changed. mtime is the
    # right instrument for exactly that question and for nothing else here.
    newest = max(s.stat().st_mtime for s in sources)
    if newest > page.stat().st_mtime:
        print("  FAIL page-is-behind      the notes changed after the page was built")
        bad_stale = 1
    else:
        bad_stale = 0

    note = snapshot_note()
    if note:
        print(note)

    bad = bad_stale
    for label, ns, ps in FACTS:
        ok_n, dn = holds(nt, ns)
        ok_p, dp = holds(pt, ps)
        ok = ok_n and ok_p
        bad += not ok
        print("  %-4s %-22s notes:%-12s page:%s" % ("ok" if ok else "FAIL", label, dn, dp))

    # CONTROL: a fact that is in neither must be reported absent, or the matcher proves nothing
    ctrl_n = nt.count("ZZ-control-never-present")
    ctrl_p = pt.count("ZZ-control-never-present")
    print("  CONTROL absent-in-both: notes=%d page=%d (both must be 0)" % (ctrl_n, ctrl_p))
    if ctrl_n or ctrl_p:
        print("CANNOT CHECK: control string present, matcher is unsound"); return 2

    facts_bad = bad - bad_stale
    print("%s: %d of %d facts agree%s"
          % ("DISAGREE" if bad else "AGREE", len(FACTS) - facts_bad, len(FACTS),
             "  (and the page is BEHIND the notes)" if bad_stale else ""))
    return 1 if bad else 0

sys.exit(main())
