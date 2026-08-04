#!/usr/bin/env python3
"""Controls for check-claim-coherence.py.

Every sibling gate in scripts/ ships a test_check_*.py that drives it in BOTH directions.
This one did not, which is the same defect the gate itself detects: a control that exists
and that nothing invokes. It was driven by hand when it was written; hand-driving proves
the gate worked ONCE, on a tree that has since changed, and leaves nothing that fails when
someone edits the detector.

The cases are the incidents verbatim rather than minimised repros, so the suite dies loudly
if the gate stops catching what it was built for.

Run: python3 scripts/test_check_claim_coherence.py
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "check-claim-coherence.py"

passed = 0
failed = 0


def check(name, got, want):
    global passed, failed
    ok = got == want
    passed += ok
    failed += not ok
    print(
        f"  {'ok  ' if ok else 'FAIL'} {name}"
        + ("" if ok else f"   got={got!r} want={want!r}")
    )


def load():
    """Import the gate as a module so its helpers can be driven directly."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("cc", GATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


m = load()

# --- 1. THE MOTIVATING INCIDENT, verbatim ----------------------------------------------
# A certifier credited with a runtime role, in the same paragraph as a self-test the reader
# is TOLD to run. The first version of this gate exempted the whole paragraph because ONE
# script in it was instructed, so it could not catch the case it was built for while passing
# its live corpus. If this case stops firing, the gate is dead.
PARA = (
    "*Where the intent is fixed, nothing asks a human.* The DePIN publish path may express "
    "exactly one intent, so `scripts/broadcast_certified.py` re-derives that intent from the "
    "exact serialized bytes and refuses everything else. Its self-test is the attack, run four "
    "ways (`python3 scripts/certify_publish_tx.py`)."
)
check(
    "incident: the INSTRUCTED script is exempt",
    m.instructed(PARA, "certify_publish_tx.py"),
    True,
)
check(
    "incident: its NEIGHBOUR is NOT exempt",
    m.instructed(PARA, "broadcast_certified.py"),
    False,
)

# --- 2. the role-verb discriminator ----------------------------------------------------
# A bare mention is not a runtime claim. Without this the gate fires on every script in the
# repo and gets learned around, which is worse than not existing.
check(
    "a role verb is detected", bool(m.ROLE_VERBS.search("it certifies the bytes")), True
)
check(
    "a bare mention is not a claim",
    bool(m.ROLE_VERBS.search("see scripts/foo.py for details")),
    False,
)

# --- 3. disclosure is the third honest resolution ---------------------------------------
check(
    "operator-side discloses",
    bool(m.DISCLOSURE.search("the wiring is operator-side")),
    True,
)
check(
    "does NOT prove discloses",
    bool(m.DISCLOSURE.search("what it does NOT prove is the wiring")),
    True,
)
check(
    "unrelated prose does not",
    bool(m.DISCLOSURE.search("the feed publishes on a schedule")),
    False,
)

# --- 4. per-script instruction forms ----------------------------------------------------
check("python3 form", m.instructed("run `python3 scripts/x.py` now", "x.py"), True)
check("run form", m.instructed("run `scripts/x.py`", "x.py"), True)
check(
    "a different script's instruction does not exempt",
    m.instructed("run `python3 scripts/a.py`", "b.py"),
    False,
)

# --- 5. THE FLOOR: a broken discovery walk must REFUSE, not report clean -----------------
# A walk that silently finds nothing would print a perfect result over an empty set, which
# is the false-green this gate exists to catch, one level up.
src = GATE.read_text(encoding="utf-8")
mutant = ROOT / "scripts" / ".test_cc_mutant.py"
try:
    assert "MIN_DOCS = 10" in src, "floor constant moved; this control is stale"
    mutant.write_text(
        src.replace("MIN_DOCS = 10", "MIN_DOCS = 99999", 1),
        encoding="utf-8",
        newline="",
    )
    r = subprocess.run(
        [sys.executable, str(mutant)], capture_output=True, text=True, cwd=str(ROOT)
    )
    check("floor refuses a broken walk (rc=2)", r.returncode, 2)
finally:
    if mutant.exists():
        mutant.unlink()

# --- 6. the gate is CLEAN on the real corpus --------------------------------------------
r = subprocess.run(
    [sys.executable, str(GATE)], capture_output=True, text=True, cwd=str(ROOT)
)
check("live corpus is clean (rc=0)", r.returncode, 0)
check(
    "it reports how many surfaces it read",
    bool(re.search(r"surfaces read: \d+ tracked", r.stdout)),
    True,
)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
