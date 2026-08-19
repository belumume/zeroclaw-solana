#!/usr/bin/env bash
# Prove that test_check_shadowed_scripts.py actually gates check-shadowed-scripts.py.
#
# Ten green cases prove the suite ran. They do not prove the suite can fail, and this gate spent
# its whole life printing a clean line while looking at 112 of 271 gitignored scripts, so "it
# passes" is exactly the evidence that was already available and already worthless.
#
# Each mutant plants one half of the pre-fix scope back into a COPY and requires the suite to go
# red. The suite takes the gate path as its first argument, so nothing here touches the real one.
#
#   1. both scopes hardcoded again  -> the pre-fix gate; every widened case must fail
#   2. tracked scope re-narrowed    -> the canonical case leaves scope; the canary must refuse
#   3. ignored scope re-narrowed    -> one directory, one level; root and depth must fail
#   4. the refusal layer blinded    -> a broken instrument must not print the clean sentence
#
# Mutant 4 is the one worth having. A gate that reports clean when it could not read its inputs
# is indistinguishable downstream from one that read them, and only one of those is good news.
#
# Exit 0 only if the unmutated gate passes the suite AND every mutant is refused by it.

set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/check-shadowed-scripts.py"
SUITE="$HERE/test_check_shadowed_scripts.py"

if [ ! -f "$GATE" ] || [ ! -f "$SUITE" ]; then
  echo "FAIL  run this from inside a checkout; gate or suite not found"
  exit 2
fi

# CI runners ship python3; Git Bash on Windows often only has python. Resolve rather than
# assume, because guessing wrong makes this fail as a missing command and read as a real finding.
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "FAIL  no python interpreter on PATH"
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0

echo "=== control: the unmutated gate must PASS its own suite ==="
if $PY "$SUITE" "$GATE" >"$WORK/clean.log" 2>&1; then
  tail -1 "$WORK/clean.log"
  echo "PASS  unmutated gate passes all cases"
else
  echo "FAIL  unmutated gate does not pass its suite; nothing below is interpretable"
  cat "$WORK/clean.log"
  exit 1
fi

# $1 = label, then pairs of find/replace strings.
check_mutant() {
  local label="$1"; shift
  local mut="$WORK/mutant.py"
  $PY - "$GATE" "$mut" "$@" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
pairs = sys.argv[3:]
text = open(src, encoding="utf-8").read()
for find, repl in zip(pairs[0::2], pairs[1::2]):
    if find not in text:
        sys.exit("MUTATION TARGET NOT FOUND: " + find[:70])
    text = text.replace(find, repl, 1)
open(dst, "w", encoding="utf-8").write(text)
PY
  if [ $? -ne 0 ]; then
    echo "FAIL  [$label] could not plant the mutation (target text moved?)"
    fail=1
    return
  fi

  local out rc
  out="$($PY "$SUITE" "$mut" 2>&1)"
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "FAIL  [$label] the suite still passed; these cases do not gate the scope"
    fail=1
    return
  fi
  # A non-zero exit alone cannot tell CAUGHT from CRASHED. The mutation edits Python
  # source, so a mutant that no longer parses raises SyntaxError, the suite dies before
  # asserting anything, and a bare `rc != 0` reads that as the cases gating correctly.
  # The suite prints a "  FAIL" line per red case; require at least one.
  if ! printf '%s' "$out" | grep -q '^  FAIL'; then
    echo "FAIL  [$label] suite exited $rc but named no failing case -- that is a CRASH"
    echo "      (the mutant likely does not import), not a caught mutation."
    printf '%s\n' "$out" | tail -4 | sed 's/^/        /'
    fail=1
    return
  fi
  echo "PASS  [$label] refused (suite exit $rc, with a named failing case)"
  printf '%s\n' "$out" | grep '^  FAIL' | sed 's/^  FAIL/        red:/'
  printf '%s\n' "$out" | tail -1 | sed 's/^/        /'
}

NARROW_TRACKED_FIND='    scripts = ours(git("ls-files"))'
NARROW_TRACKED_REPL='    scripts = [p for p in ours(git("ls-files")) if p.startswith(("scripts/", "skills/"))]'

NARROW_IGNORED_FIND='    return ours(git("ls-files", "--others", "--ignored", "--exclude-standard"))'
NARROW_IGNORED_REPL='    every = ours(git("ls-files", "--others", "--ignored", "--exclude-standard"))
    return [p for p in every if p.startswith(".tools/") and p.count("/") == 1]'

BLIND_RAISE_FIND='    if r.returncode != 0:
        raise RuntimeError(f"git {'"'"' '"'"'.join(args)} failed: {r.stderr.strip()[:200]}")'
BLIND_RAISE_REPL='    if False:
        raise RuntimeError(f"git {'"'"' '"'"'.join(args)} failed: {r.stderr.strip()[:200]}")'

BLIND_CANARY_FIND='    missing = [c for c in CANARY if c not in scripts]'
BLIND_CANARY_REPL='    missing = []'

BLIND_FLOOR_FIND='    if not tracked:'
BLIND_FLOOR_REPL='    if False:'

BLIND_COMPARED_FIND='        if c not in tracked:'
BLIND_COMPARED_REPL='        if False:'

echo
echo "=== mutant 1: both scopes hardcoded again, which is the pre-fix gate ==="
check_mutant "pre-fix-scope" \
  "$NARROW_TRACKED_FIND" "$NARROW_TRACKED_REPL" \
  "$NARROW_IGNORED_FIND" "$NARROW_IGNORED_REPL"

echo
echo "=== mutant 2: tracked scope back to two directory prefixes ==="
check_mutant "narrow-tracked" "$NARROW_TRACKED_FIND" "$NARROW_TRACKED_REPL"

echo
echo "=== mutant 3: ignored scope back to one directory, one level deep ==="
check_mutant "narrow-ignored" "$NARROW_IGNORED_FIND" "$NARROW_IGNORED_REPL"

echo
echo "=== mutant 4: every refusal blinded, so a broken read prints the clean sentence ==="
check_mutant "blind-refusals" \
  "$BLIND_RAISE_FIND" "$BLIND_RAISE_REPL" \
  "$BLIND_CANARY_FIND" "$BLIND_CANARY_REPL" \
  "$BLIND_FLOOR_FIND" "$BLIND_FLOOR_REPL" \
  "$BLIND_COMPARED_FIND" "$BLIND_COMPARED_REPL"

echo
if [ $fail -ne 0 ]; then
  echo "FAIL  at least one mutant survived the suite"
  exit 1
fi
echo "PASS  every mutant was refused by the suite"
exit 0
