"""Controls for check-doc-links.py's SKIP classification, in BOTH directions.

This gate was the only one of the five with no suite, which is how the loopback defect
survived: a permanently-red job was scheduled onto the judging window and read as a known
residual rather than as a bug.

The loopback case is not merely "always red". It is NON-DETERMINISTIC, which is worse,
because the outcome depends on unrelated local state. QUICKSTART's
`ssh -L 8899:127.0.0.1:8899` illustration went red on CI and would go GREEN on a reader's
machine running the local validator or `scripts/qr_live_server.py`, both of which
QUICKSTART itself tells them to start. A check that reports on the runner rather than on
the documentation is not a check.

One direction alone proves nothing. Must-skip alone passes for a classifier that skips
every URL, which would silently stop checking real links. So every skip case is paired
with a near-miss that must still be CHECKED, differing only in the discriminating feature.

Case 1 is the incident URL verbatim from QUICKSTART.md. If it stops being skipped, the
gate is back to reporting on whoever ran it.

Run: python scripts/test_check_doc_links.py
"""

import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "check-doc-links.py"

spec = importlib.util.spec_from_file_location("cdl", GATE)
cdl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cdl)

passed = failed = 0


def check(name, cond, detail: object = ""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def classify(url):
    """Mirror main()'s branch order. Returns the skip reason, or None to mean CHECKED."""
    if cdl.ABBREVIATED.search(url):
        return "shortened in prose"
    if cdl.REDACTED_QUERY.search(url):
        return "secret removed on purpose"
    if cdl.LOOPBACK.search(url):
        return "loopback illustration"
    return None


print("check-doc-links SKIP classification")

# --- MUST SKIP: loopback ------------------------------------------------------------
# Case 1 is the incident, verbatim from QUICKSTART.md's ssh -L illustration.
check(
    "1  INCIDENT: the QUICKSTART loopback URL is skipped",
    classify("http://127.0.0.1:8899") == "loopback illustration",
    classify("http://127.0.0.1:8899"),
)
for u in (
    "http://localhost:8899",
    "http://127.0.0.1:3000/health",
    "https://localhost",
    "http://[::1]:8080",
    "http://0.0.0.0:9000",
    "http://LocalHost:8899",  # case-insensitivity is deliberate
):
    check(
        f"1x loopback skipped: {u}", classify(u) == "loopback illustration", classify(u)
    )

# --- MUST STILL BE CHECKED: near-misses that differ only in the discriminator --------
# Without these, a classifier that skipped everything would pass the block above.
for u in (
    "https://github.com/belumume/zeroclaw-solana",
    "https://api.devnet.solana.com",
    "http://127.0.0.1.example.com/x",  # loopback-looking HOST PREFIX, not loopback
    "https://localhost.attacker.test/path",  # localhost as a subdomain label
    "https://example.com/127.0.0.1",  # loopback only in the PATH
):
    check(f"2  still checked: {u}", classify(u) is None, classify(u))

# --- The other two classes must be unaffected by the new branch ----------------------
check(
    "3a abbreviated still skipped",
    classify("https://explorer.solana.com/tx/5ss8…") == "shortened in prose",
    classify("https://explorer.solana.com/tx/5ss8…"),
)
check(
    "3b redacted still skipped",
    classify("https://api.example.com/v1?key=REDACTED") == "secret removed on purpose",
    classify("https://api.example.com/v1?key=REDACTED"),
)

# --- MUTATION CONTROL: neuter LOOPBACK; case 1 must stop being skipped ---------------
# Targets the regex literal rather than the word, because the word also appears in the
# module docstring and in comments, and replacing one of those yields a mutant that is
# behaviourally identical to the real gate, so the control could not fail.
src = GATE.read_text(encoding="utf-8")
ANCHOR = 'r"^https?://(?:127\\.0\\.0\\.1|localhost'
assert ANCHOR in src, "mutation target is stale; this control would test nothing"
mutant_src = src.replace(ANCHOR, 'r"^https?://(?:127\\.0\\.0\\.2|localhostX', 1)
assert mutant_src != src, "mutation did not apply"

mpath = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / ".mutant-doc-links.py"
mpath.write_text(mutant_src, encoding="utf-8")
try:
    mspec = importlib.util.spec_from_file_location("cdl_mutant", mpath)
    mmod = importlib.util.module_from_spec(mspec)
    mspec.loader.exec_module(mmod)
    check(
        "4  mutation control: with LOOPBACK broken, the incident URL is no longer skipped",
        not mmod.LOOPBACK.search("http://127.0.0.1:8899"),
        "mutant still skipped it, so the control proves nothing",
    )
finally:
    mpath.unlink(missing_ok=True)

# --- The live QUICKSTART really does contain the incident URL ------------------------
# Pins the case to reality: if QUICKSTART stops carrying it, case 1 is guarding a shape
# the repo no longer has, and this suite should say so rather than passing quietly.
qs = (HERE.parent / "QUICKSTART.md").read_text(encoding="utf-8")
check(
    "5  QUICKSTART still carries the loopback illustration this case exists for",
    bool(re.search(r"127\.0\.0\.1:8899", qs)),
    "not found; case 1 may now be guarding nothing",
)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
