#!/usr/bin/env bash
# Negative control for tests/exhaustive.rs.
#
# A green exhaustive suite proves the loop RAN (the count assertions cover that). It does not
# prove the assertions can FAIL. So: inject a defect that a real attacker would want, and
# require the suite to go red. Restores the source on every exit path.
set -u

# Same resolution as scripts/mutation-check.sh: git first, script location as the
# fallback, so this still works from a copy outside a checkout.
REPO="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "$REPO" ]; then
  REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
SRC="$REPO/crates/solana-core/src/mint.rs"
BAK="$SRC.mutbak"

cd "$REPO/crates/solana-core" || exit 2
cp "$SRC" "$BAK"
trap 'cp "$BAK" "$SRC"; rm -f "$BAK"; echo "[restored source]"' EXIT INT TERM

echo "=== baseline must be GREEN before a mutation means anything ==="
cargo test --release --test exhaustive 2>&1 | grep -E "^test result"
base=${PIPESTATUS[0]}
if [ "$base" -ne 0 ]; then
  echo "BASELINE RED. A mutation result would be meaningless. Aborting."
  exit 2
fi

echo
echo "=== MUTATION 1: a permanent delegate that also answers to discriminant 13 ==="
echo "    (an attacker crafting 13 would be reported as carrying a delegate it does not have,"
echo "     and more importantly the same bug shape in reverse hides a real one)"
sed -i 's|        self.extension(EXT_PERMANENT_DELEGATE)|        self.extension(EXT_PERMANENT_DELEGATE).or_else(\|\| self.extension(13))|' "$SRC"
if grep -q "or_else" "$SRC"; then
  cargo test --release --test exhaustive 2>&1 | grep -E "^test result|panicked at|fired for discriminant" | head -4
  m1=${PIPESTATUS[0]}
  echo "mutant-1 exit=$m1  (MUST be non-zero)"
else
  echo "MUTATION DID NOT APPLY -- the sed pattern missed; treat as inconclusive."
  m1=0
fi

cp "$BAK" "$SRC"

echo
echo "=== MUTATION 2: silently drop unknown extensions instead of keeping them raw ==="
echo "    (this is the one that would make an unknown discriminant invisible to a caller)"
sed -i 's|            extensions.push(RawExtension {|            if !matches!(discriminant, 1 \| 3 \| 6 \| 12 \| 14 \| 26) { i = end; continue; }\n            extensions.push(RawExtension {|' "$SRC"
if grep -q "matches!(discriminant" "$SRC"; then
  cargo test --release --test exhaustive 2>&1 | grep -E "^test result|panicked at" | head -3
  m2=${PIPESTATUS[0]}
  echo "mutant-2 exit=$m2  (MUST be non-zero)"
else
  echo "MUTATION DID NOT APPLY -- the sed pattern missed; treat as inconclusive."
  m2=0
fi

echo
if [ "$m1" -ne 0 ] && [ "$m2" -ne 0 ]; then
  echo "RESULT: both planted defects were caught. The suite has discriminative power."
else
  echo "RESULT: a planted defect SURVIVED. The suite is weaker than its green implies."
  exit 1
fi
