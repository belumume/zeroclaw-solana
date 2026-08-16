#!/usr/bin/env bash
# Proves the identifier-leak controls can FAIL.
#
# 18/18 green says the suite agrees with the gate. It does not say the suite would notice
# the gate breaking, and those are different claims. This neuters one detector at a time
# and requires the suite to go red for each, so a green result upstream means the
# detectors are load-bearing rather than that the cases happen to agree.
#
# Each mutation asserts its own substitution APPLIED before running, because a mutation
# string that silently stops matching produces a mutant byte-identical to the real gate,
# and the control then passes while testing nothing.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$REPO/scripts/check-identifier-leaks.py"
SUITE="$REPO/scripts/test_check_identifier_leaks.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0

mutate() {
  local name="$1" needle="$2" replacement="$3"
  local mutant="$TMP/mutant.py"
  cp "$GATE" "$mutant"

  if ! grep -qF -- "$needle" "$mutant"; then
    printf '  FAIL  %s\n        the mutation anchor no longer exists in the gate:\n        %s\n' \
           "$name" "$needle"
    printf '        A stale anchor makes this control pass while changing nothing.\n'
    fail=$((fail+1))
    return
  fi

  python - "$mutant" "$needle" "$replacement" <<'PY'
import sys
p, needle, repl = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(p, encoding="utf-8").read()
assert needle in src, "anchor vanished between grep and rewrite"
open(p, "w", encoding="utf-8").write(src.replace(needle, repl, 1))
PY

  if cmp -s "$GATE" "$mutant"; then
    printf '  FAIL  %s\n        mutant is byte-identical to the gate; nothing was changed.\n' "$name"
    fail=$((fail+1))
    return
  fi

  if python "$SUITE" "$mutant" >/dev/null 2>&1; then
    printf '  FAIL  %s\n        suite still PASSED against a gate with this detector removed.\n' "$name"
    fail=$((fail+1))
  else
    printf '  PASS  %s (suite went red, so the detector is load-bearing)\n' "$name"
  fi
}

echo "mutation controls for check-identifier-leaks.py"
echo

# 1. The home-path detector, which is incident 1.
mutate "home-path detection removed" \
       "            if account.lower() in ROLE_ACCOUNTS:" \
       "            if True:"

# 2. The commit-identity detector, which is incident 2 and the surface a scrub misses.
mutate "commit-identity detection removed" \
       "            bad.setdefault(addr, set()).add(sha[:9])" \
       "            pass"

# 3. The e-mail detector in tracked content. The anchor carries BOTH allowlists because the two
#    scans were made consistent: the exact-address list was consulted in commit metadata and not
#    here, so one string meant two different things depending on which surface carried it.
mutate "tracked-content e-mail detection removed" \
       "        if addr.lower() in IMPERSONAL_EXACT or IMPERSONAL_EMAIL.search(addr):" \
       "        if True:"

# 4. The discovery floor. Removing it must break the FLOOR case specifically.
mutate "tracked-file floor removed" \
       "    if len(files) < MIN_TRACKED:" \
       "    if False:"

echo
if [ "$fail" -eq 0 ]; then
  echo "RESULT: all 4 mutations were caught by the suite."
  exit 0
fi
echo "RESULT: $fail mutation(s) went unnoticed. The suite is not proving what it claims."
exit 1
