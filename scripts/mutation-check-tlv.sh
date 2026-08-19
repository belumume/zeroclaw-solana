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

# A NON-ZERO EXIT IS NOT A CAUGHT MUTANT. A `sed`-injected mutation that fails to
# COMPILE exits non-zero with the test harness never running, and the old comparison
# below (`m1 -ne 0 && m2 -ne 0`) read that as proof the suite discriminates. Both
# mutations here are type-level edits to Rust source, so a compile error is the MOST
# likely way for them to go wrong, which made this control's green the least
# trustworthy exactly where it mattered. Every verdict now requires cargo to have RUN
# and REPORTED: "test result: FAILED" for a mutant, "test result: ok" for the baseline.
ran_and_failed() { printf '%s' "$1" | grep -qE '^test result: FAILED'; }

echo "=== baseline must be GREEN before a mutation means anything ==="
base_out="$(cargo test --release --test exhaustive 2>&1)"
base=$?
printf '%s\n' "$base_out" | grep -E "^test result"
if [ "$base" -ne 0 ] || ! printf '%s' "$base_out" | grep -qE '^test result: ok'; then
  echo "BASELINE RED (exit $base). A mutation result would be meaningless. Aborting."
  printf '%s\n' "$base_out" | grep -E '^error(\[|:)' | head -3 | sed 's/^/  /'
  exit 2
fi

echo
echo "=== MUTATION 1: a permanent delegate that also answers to discriminant 13 ==="
echo "    (an attacker crafting 13 would be reported as carrying a delegate it does not have,"
echo "     and more importantly the same bug shape in reverse hides a real one)"
sed -i 's|        self.extension(EXT_PERMANENT_DELEGATE)|        self.extension(EXT_PERMANENT_DELEGATE).or_else(\|\| self.extension(13))|' "$SRC"
m1_crashed=0
if grep -q "or_else" "$SRC"; then
  m1_out="$(cargo test --release --test exhaustive 2>&1)"
  m1=$?
  printf '%s\n' "$m1_out" | grep -E "^test result|panicked at|fired for discriminant" | head -4
  if [ "$m1" -ne 0 ] && ! ran_and_failed "$m1_out"; then
    m1_crashed=1
    echo "mutant-1 exit=$m1 but NO 'test result: FAILED' -- the harness never ran."
    printf '%s\n' "$m1_out" | grep -E '^error(\[|:)' | head -3 | sed 's/^/  /'
  else
    echo "mutant-1 exit=$m1  (MUST be non-zero AND have reported FAILED)"
  fi
else
  echo "MUTATION DID NOT APPLY -- the sed pattern missed; treat as inconclusive."
  m1=0
fi

cp "$BAK" "$SRC"

echo
echo "=== MUTATION 2: silently drop unknown extensions instead of keeping them raw ==="
echo "    (this is the one that would make an unknown discriminant invisible to a caller)"
sed -i 's|            extensions.push(RawExtension {|            if !matches!(discriminant, 1 \| 3 \| 6 \| 12 \| 14 \| 26) { i = end; continue; }\n            extensions.push(RawExtension {|' "$SRC"
m2_crashed=0
if grep -q "matches!(discriminant" "$SRC"; then
  m2_out="$(cargo test --release --test exhaustive 2>&1)"
  m2=$?
  printf '%s\n' "$m2_out" | grep -E "^test result|panicked at" | head -3
  if [ "$m2" -ne 0 ] && ! ran_and_failed "$m2_out"; then
    m2_crashed=1
    echo "mutant-2 exit=$m2 but NO 'test result: FAILED' -- the harness never ran."
    printf '%s\n' "$m2_out" | grep -E '^error(\[|:)' | head -3 | sed 's/^/  /'
  else
    echo "mutant-2 exit=$m2  (MUST be non-zero AND have reported FAILED)"
  fi
else
  echo "MUTATION DID NOT APPLY -- the sed pattern missed; treat as inconclusive."
  m2=0
fi

echo
if [ "$m1_crashed" -eq 1 ] || [ "$m2_crashed" -eq 1 ]; then
  echo "RESULT: INCONCLUSIVE. A mutant exited non-zero WITHOUT the harness reaching a"
  echo "verdict, which is a crash (almost certainly a compile error), not a catch."
  echo "This control proves nothing about the suite until the mutation compiles."
  exit 2
fi
if [ "$m1" -ne 0 ] && [ "$m2" -ne 0 ]; then
  echo "RESULT: both planted defects were caught, each with the harness reporting"
  echo "FAILED. The suite has discriminative power."
else
  echo "RESULT: a planted defect SURVIVED. The suite is weaker than its green implies."
  exit 1
fi
