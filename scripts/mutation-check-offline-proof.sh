#!/usr/bin/env bash
# Prove that scripts/verify_proof_offline.py's self-test controls actually gate the run.
#
# A verifier that has never rejected anything has not been shown to work. This harness plants a
# defect in a COPY of the verifier and requires the copy to refuse. Three mutants, each attacking a
# different control:
#
#   1. ed25519_verify always returns True   -> the tamper controls must catch it
#   2. the sha256 digest comparison is blinded -> the digest control must catch it
#   3. a tamper control mutates nothing      -> the "control actually perturbed something"
#                                               assertion must catch it
#
# Mutant 3 is the one worth having. A control that silently perturbs nothing passes for the wrong
# reason and reports coverage it does not have, which is exactly how a broken control ships green.
#
# Exit 0 only if the unmutated script passes AND every mutant is refused.

set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SRC="$REPO/scripts/verify_proof_offline.py"
BUNDLE="$REPO/docs/proof-bundle/devnet-transactions.json"

if [ ! -f "$SRC" ] || [ ! -f "$BUNDLE" ]; then
  echo "FAIL  run this from inside a checkout; verifier or bundle not found"
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

echo "=== control: the unmutated verifier must PASS ==="
if $PY "$SRC" --bundle "$BUNDLE" >"$WORK/clean.log" 2>&1; then
  echo "PASS  unmutated verifier exits 0"
else
  echo "FAIL  unmutated verifier did not pass; nothing below is interpretable"
  cat "$WORK/clean.log"
  exit 1
fi

# $1 = label, $2 = python expression replaced, $3 = replacement, $4 = expected marker in output
check_mutant() {
  local label="$1" find="$2" repl="$3" marker="$4"
  local mut="$WORK/mutant.py"
  $PY - "$SRC" "$mut" "$find" "$repl" <<'PY'
import sys
src, dst, find, repl = sys.argv[1:5]
text = open(src, encoding="utf-8").read()
if find not in text:
    sys.exit("MUTATION TARGET NOT FOUND: " + find)
open(dst, "w", encoding="utf-8").write(text.replace(find, repl, 1))
PY
  if [ $? -ne 0 ]; then
    echo "FAIL  [$label] could not plant the mutation (target text moved?)"
    fail=1
    return
  fi

  local out rc
  out="$($PY "$mut" --bundle "$BUNDLE" 2>&1)"
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "FAIL  [$label] mutant PASSED; the control does not gate"
    fail=1
    return
  fi
  if ! printf '%s' "$out" | grep -q "$marker"; then
    echo "FAIL  [$label] mutant was refused but not by the expected control"
    echo "      wanted marker: $marker"
    printf '%s\n' "$out" | tail -5
    fail=1
    return
  fi
  echo "PASS  [$label] refused (exit $rc)"
  printf '%s\n' "$out" | grep -m1 "$marker" | sed 's/^/        /'
}

echo
echo "=== mutant 1: ed25519_verify always returns True ==="
check_mutant "always-verify" \
  '    if len(signature) != 64 or len(public_key) != 32:
        return False' \
  '    return True
    if len(signature) != 64 or len(public_key) != 32:
        return False' \
  "NEGATIVE CONTROL FAILED"

echo
echo "=== mutant 2: digest_matches always agrees ==="
# Targets the SHARED helper, which is the only thing a control can cover. An earlier version of
# this mutant blinded the self-test's own comparison instead and passed, because disabling a
# control that then has nothing to catch is not a failure. That miss is why digest_matches exists.
check_mutant "blind-digest" \
  '    return hashlib.sha256(raw).hexdigest() == recorded' \
  '    return True' \
  "NEGATIVE CONTROL FAILED"

echo
echo "=== mutant 3: a tamper control mutates nothing ==="
check_mutant "no-op-tamper" \
  '    tampered_msg[-1] ^= 0x01' \
  '    tampered_msg[-1] ^= 0x00' \
  "CONTROL INVALID"

echo
if [ $fail -ne 0 ]; then
  echo "FAIL  at least one mutant was not refused"
  exit 1
fi
echo "PASS  every mutant was refused by the control that names it"
exit 0
