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
cargo test --test properties --locked 2>&1 | tail -14
MUTANT_RC=${PIPESTATUS[0]}
set -e

cp "$BACKUP" "$TARGET"
echo
echo "=== reverted; the clean run must pass again ==="
set +e
cargo test --test properties --locked 2>&1 | tail -4
CLEAN_RC=${PIPESTATUS[0]}
set -e

echo
if [ "$MUTANT_RC" -eq 0 ]; then
  echo "VERDICT: the properties PASSED a knowingly broken decoder."
  echo "The suite is decorative. Its green result means nothing until this fails."
  exit 1
fi
if [ "$CLEAN_RC" -ne 0 ]; then
  echo "VERDICT: the suite fails even on clean source (exit $CLEAN_RC)."
  echo "The mutation result proves nothing, because the baseline is already red."
  exit 1
fi
echo "VERDICT: properties CAUGHT the injected defect (exit $MUTANT_RC) and pass clean."
echo "The suite discriminates. Its green result carries information."
