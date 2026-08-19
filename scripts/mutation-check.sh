#!/usr/bin/env bash
# Prove the property suite can FAIL. Portable: no absolute paths, run from anywhere
# in the repo.
#
#   ./scripts/mutation-check.sh
#
# Exit 0 = the properties caught the injected defect (the suite discriminates).
# Exit 1 = the properties passed a knowingly broken decoder (the suite is decorative).
#
# WHY
# ---
# "19 properties, 1024 cases each, all passing" is the kind of number that reads as
# rigour and proves nothing on its own: a suite that has never failed is
# indistinguishable from one that cannot fail. TESTING.md makes that argument, so
# the harness backing it has to be runnable by whoever is reading it. This lives in
# scripts/ rather than the ignored tools directory for exactly that reason.
#
# THE DEFECT INJECTED
# -------------------
# The durable nonce is read from the authority's byte range instead of its own. It
# is the precise footgun nonce.rs documents, and the reason it is worth choosing:
# every field still decodes, the struct is still populated, lengths are still
# correct, and a test asserting only "decode succeeded" stays green. Only a property
# comparing the decoded value against what was encoded notices.
set -uo pipefail

# Prefer git for the repo root: it is correct no matter where this script is invoked
# from, or copied to. Fall back to the script's own location for a clone without git.
REPO="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "${REPO:-}" ] || [ ! -d "$REPO/crates/solana-core" ]; then
  REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
CRATE="$REPO/crates/solana-core"
TARGET="$CRATE/src/nonce.rs"
BACKUP="$(mktemp)"

command -v cargo >/dev/null 2>&1 || { echo "cargo not on PATH"; exit 2; }
[ -f "$TARGET" ] || { echo "cannot find $TARGET"; exit 2; }

cd "$CRATE" || exit 2
cp "$TARGET" "$BACKUP"
# Restore on ANY exit path, including a failed cargo run or an interrupt. Leaving a
# mutated source behind would be worse than not running this at all.
trap 'cp "$BACKUP" "$TARGET"; rm -f "$BACKUP"' EXIT INT TERM

ORIG='durable_nonce: data[40..72].try_into().expect("bounds checked"),'
MUT='durable_nonce: data[8..40].try_into().expect("bounds checked"),'

if ! grep -qF "$ORIG" "$TARGET"; then
  echo "mutation target not found in nonce.rs."
  echo "The line this harness mutates has moved or changed. Fix the harness rather"
  echo "than deleting it: an unrunnable mutation check is the claim it was written"
  echo "to support, unsupported."
  exit 2
fi

echo "=== injecting: durable_nonce reads the AUTHORITY byte range ==="
python3 - "$TARGET" "$ORIG" "$MUT" <<'PY'
import pathlib, sys
p, old, new = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
t = p.read_text(encoding="utf-8")
assert old in t, "mutation target vanished between grep and write"
p.write_text(t.replace(old, new, 1), encoding="utf-8")
print("  mutated")
PY
[ $? -eq 0 ] || { echo "could not mutate"; exit 2; }

echo
echo "=== the suite MUST fail now ==="
set +e
MUTANT_OUT="$(cargo test --test properties --locked 2>&1)"
MUTANT_RC=$?
set -e
printf '%s\n' "$MUTANT_OUT" | tail -14

cp "$BACKUP" "$TARGET"
echo
echo "=== reverted; the clean run must pass again ==="
set +e
CLEAN_OUT="$(cargo test --test properties --locked 2>&1)"
CLEAN_RC=$?
set -e
printf '%s\n' "$CLEAN_OUT" | tail -4

# A NON-ZERO EXIT IS NOT A CAUGHT MUTANT, and conflating the two is how a control
# silently stops working. A mutation that fails to COMPILE also exits non-zero -- 101,
# with the test harness never running at all -- and so does a cargo that cannot resolve
# the lockfile, or a missing toolchain. Read as "caught", every one of those makes this
# script report "the suite discriminates" on a day the suite never ran, which is the
# exact false green it exists to prevent. So require the harness to have RUN and
# REPORTED: cargo prints "test result: FAILED" only when tests executed and failed.
mutant_reported_failures() {
  printf '%s' "$MUTANT_OUT" | grep -qE '^test result: FAILED'
}
clean_reported_pass() {
  printf '%s' "$CLEAN_OUT" | grep -qE '^test result: ok'
}

echo
if [ "$MUTANT_RC" -eq 0 ]; then
  echo "VERDICT: the properties PASSED a knowingly broken decoder."
  echo "The suite is decorative. Its green result means nothing until this fails."
  exit 1
fi
if ! mutant_reported_failures; then
  echo "VERDICT: INCONCLUSIVE. The mutant run exited $MUTANT_RC but never printed a"
  echo "'test result: FAILED' line, so the test harness did not run to a verdict."
  echo "That is a CRASH (most likely the mutated source did not compile), not a catch."
  printf '%s\n' "$MUTANT_OUT" | grep -E '^error(\[|:)' | head -3 | sed 's/^/  /'
  exit 2
fi
if [ "$CLEAN_RC" -ne 0 ] || ! clean_reported_pass; then
  echo "VERDICT: the suite fails even on clean source (exit $CLEAN_RC)."
  echo "The mutation result proves nothing, because the baseline is already red."
  exit 1
fi
echo "VERDICT: properties CAUGHT the injected defect (exit $MUTANT_RC, harness reported"
echo "FAILED) and pass clean. The suite discriminates; its green carries information."
