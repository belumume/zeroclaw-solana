#!/usr/bin/env bash
# Proves the identifier-leak controls can FAIL.
#
# A green suite says the suite agrees with the gate. It does not say the suite would notice
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

# 5. The whole history-blob surface. Silencing it must break INCIDENT 5, which is the case
#    where the tree is clean and only a history blob carries the identifier.
#
#    ANCHORED ON THE PREFILTER, deliberately. The obvious anchor is the ACCEPTED_HISTORY
#    membership test, and it is wrong: flipping it to `if True` makes the reporting loop
#    raise KeyError on an unregistered sha, and a CRASH exits non-zero, which is the same
#    code a real finding produces. The must-fire cases then still match their expected rc
#    and the mutation reads as caught while having tested nothing. Silencing the prefilter
#    is what a broken detector actually looks like: no findings, no crash.
mutate "history-blob scan silenced" \
       "        if not any(rx.search(body) for rx in _PREFILTER):" \
       "        if True:"

# 6. The history floor, which is what a SHALLOW clone trips. Without it a depth-1 checkout
#    scans a handful of blobs and prints a PASS about a history it never read.
mutate "history-blob floor removed" \
       "    if len(blobs) < MIN_HISTORY_BLOBS:" \
       "    if False:"

# 7. The accepted-register DRIFT guard. This is the one hole a bare content-addressed key
#    would leave: a blob cannot change, so a changed finding count means a detector was
#    widened and that blob is cleared under a rule that no longer describes it. Neutering
#    the comparison must break the case that registers a deliberately wrong count.
mutate "accepted-register drift guard removed" \
       "        if n != ACCEPTED_HISTORY[sha][\"findings\"]" \
       "        if False"

# 8. The clone-reachability SCOPE. Widening it to the raw object store must break a case,
#    because the store holds unreachable blobs a clone never receives -- reporting those is
#    a false finding, which is the direction that gets a real gate loosened.
mutate "clone-reachability scope widened to every local ref" \
       "    if refs:" \
       "    if False:"

echo
if [ "$fail" -eq 0 ]; then
  echo "RESULT: all 8 mutations were caught by the suite."
  exit 0
fi
echo "RESULT: $fail mutation(s) went unnoticed. The suite is not proving what it claims."
exit 1
