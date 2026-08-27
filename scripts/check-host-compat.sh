#!/usr/bin/env bash
# Will this repo's plugins actually work on YOUR host build?
#
# Component-model interfaces match NOMINALLY, so one enum variant that upstream added
# after we vendored `wit/v0` makes the whole interface a different type and every plugin
# fails to REGISTER, while `cargo build` and every test still pass. `wit/v0` is marked
# experimental and unfrozen upstream, so this WILL happen again to somebody.
#
# Run this against your host clone BEFORE the demo rather than finding out live:
#
#   ./scripts/check-host-compat.sh /path/to/zeroclaw
#
# Exits non-zero on any failure and prints the exact fix. Nothing here needs the host to
# be running, and nothing writes to your tree.
set -uo pipefail

# `strings X | grep -q Y` is a trap under pipefail: grep exits on the first match, strings
# takes SIGPIPE, and the pipeline reports FAILURE on a successful match. Count instead.
#
# SUBSTRING matching is CORRECT for the two host-binary probes below and WRONG for the enum
# variants, so the two matchers are separate on purpose. `wasmtime` and `wacore` are crate names
# that legitimately appear INSIDE longer strings (paths, symbol names, panic messages), and
# anchoring them would break a check that works. Do not "fix" this one to match the other.
has() { [ "$(strings "$1" 2>/dev/null | grep -c -- "$2" || true)" -gt 0 ]; }

# ANCHORED, because a plugin-action variant is a WHOLE NAME in the component's name section and
# never a fragment of a longer word. `has()` read `read` out of `[method]input-stream.blocking-read`
# and `write` out of half a dozen unrelated messages, so an unrelated binary scored as carrying
# variants it has never heard of. MEASURED 2026-08-27 over the 38 real variants: `has()` reported 7
# of 38 "present" in tar.exe and 5 in grep.exe. That is not a wholesale false clean -- a stale wasm
# still fails on the rest -- but this section exists to catch ONE newly added variant, and a new
# variant called `list`, `get`, `run` or `poll` would read as present on an artifact that predates it.
#
# The name section stores each variant as its own length-prefixed string, so `strings` emits it
# either alone on a line or packed against its neighbours with a TAB between (observed: a real
# component prints `disconnect<TAB>reconnect`). Splitting on whitespace and requiring an EXACT FIELD
# is therefore the artifact's own form. Measured against both directions before it shipped:
#   all 38 variants still found in all 10 built components  (no over-correction)
#   tar.exe 7 -> 1, grep.exe 5 -> 4                          (fragments no longer count)
# A whole-LINE match (`grep -x`) was tried first and is WRONG: it reports `disconnect` and
# `reconnect` missing from every real component, because they share a line.
carries_variant() {
  [ "$(strings "$1" 2>/dev/null | tr -s ' \t' '\n' | grep -cxF -- "$2" || true)" -gt 0 ]
}

HOST="${1:-}"
# ZC_REPO lets this run from a copy (a CRLF-stripped temp file on Windows, for instance)
# without resolving the repo root to wherever the copy happens to live.
REPO="${ZC_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# EXIT CODES ARE THIS REPO'S SHARED VOCABULARY, not a failure count. `exit "$fail"` returned the
# NUMBER of findings, so two findings exited 2 and three exited 3 -- which `check-all.py` reads as
# CANNOT_CHECK and CONTROL_DEAD respectively (see its constants of the same name). A script whose
# busiest failures impersonate "I could not look" and "my control is dead" is worse than one that
# always exits 1, because both of those are states a caller is entitled to treat as non-findings.
#
# The three states are genuinely different questions and one counter cannot carry them:
#   FINDING      something is wrong with the tree. Fix the tree.
#   CANNOT_CHECK the comparison never happened. Nothing here is evidence in either direction.
#   CONTROL_DEAD the derivation that makes a clean result meaningful has broken, so every PASS
#                printed above it is unearned. Fix the script or the host layout, not the tree.
OK=0
FINDING=1
CANNOT_CHECK=2
CONTROL_DEAD=3
fail=0
cannot=0
dead=0
ok()   { printf '  PASS  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
# Labelled distinctly from FAIL on the console too. A reader triaging a red needs to know whether
# to go and fix something or to go and build something, and "FAIL" answers neither.
cant() { printf '  CANNOT CHECK  %s\n' "$1"; cannot=$((cannot+1)); }
dead() { printf '  CONTROL DEAD  %s\n' "$1"; dead=$((dead+1)); }
fix()  { printf '        fix: %s\n' "$1"; }

# ---------------------------------------------------------------------------------------------
# --selftest: prove this script can go RED, on a hermetic fixture, before anyone trusts a green.
#
# Three of the defects below shipped GREEN against a host that would fail to load every plugin,
# which is the whole argument for this block: a check nobody has watched fail is a hypothesis.
# Each case plants ONE defect into a throwaway tree and requires the stated exit code, and the
# first case is an OVER-CORRECTION CONTROL on a healthy tree -- without it, a change that reddens
# everything would score a perfect run.
#
# The fixture is generated rather than copied from wit/v0 so the cases stay stable when the real
# interfaces change, and so the selftest cannot pass by accident on the repo's own layout. The
# `.wasm` files are plain text: `has()` reads them with `strings`, which does not care.
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

_st_tree() { # $1=dir  $2=extra world member lines  $3=variants the fake component carries
             # $4=OPTIONAL enum body, one `    name,` line per variant; defaults to alpha+bravo.
             #    Parameterised so the variant-derivation cases can degrade the enum itself without
             #    touching the cases that only care about the world.
  rm -rf "$1"; mkdir -p "$1/wit/v0" "$1/plugins/demo"
  printf 'interface logging {\n  enum plugin-action {\n%b  }\n}\n' "${4:-    alpha,\n    bravo,\n}" \
                                                                                         > "$1/wit/v0/logging.wit"
  printf 'interface types {\n  type json-string = string;\n}\n'                          > "$1/wit/v0/types.wit"
  printf 'interface plugin-info {\n  use types.{json-string};\n}\n'                      > "$1/wit/v0/plugin-info.wit"
  printf 'interface tool {\n  use types.{json-string};\n}\n'                             > "$1/wit/v0/tool.wit"
  # `%b` and not `%s`: printf expands escapes in the FORMAT, never in a `%s` ARGUMENT, so `%s`
  # wrote a literal backslash-n and left the planted member sharing a line with the closing brace.
  # The cases still passed, which is the point -- a fixture that is not the shape it claims can
  # pass for the wrong reason today and void the whole suite the day the parser changes.
  printf 'world tool-plugin {\n    import logging;\n    export plugin-info;\n    export tool;\n%b}\n' "$2" \
                                                                                         > "$1/wit/v0/world.wit"
  printf '%s\n' "$3" > "$1/plugins/demo/demo.wasm"
}

_st_run() { # $1=repo $2=host -> ST_OUT, ST_RC
  ST_OUT="$(ZC_REPO="$1" ZC_SKIP_HOST_BINARY=1 bash "$SELF" "$2" 2>&1)"
  ST_RC=$?
}
_st_rc() { # $1=label $2=expected
  st_cases=$((st_cases+1))
  if [ "$ST_RC" = "$2" ]; then printf '  ok    %s (exit %s)\n' "$1" "$2"
  else printf '  FAIL  %s: expected exit %s, got %s\n' "$1" "$2" "$ST_RC"; st_fail=$((st_fail+1)); fi
}
_st_has() { # $1=label $2=needle
  st_cases=$((st_cases+1))
  case "$ST_OUT" in *"$2"*) printf '  ok    %s\n' "$1" ;;
    *) printf '  FAIL  %s: output never said %s\n' "$1" "$2"; st_fail=$((st_fail+1)) ;; esac
}
_st_lacks() { # $1=label $2=needle
  st_cases=$((st_cases+1))
  case "$ST_OUT" in *"$2"*) printf '  FAIL  %s: output still says %s\n' "$1" "$2"; st_fail=$((st_fail+1)) ;;
    *) printf '  ok    %s\n' "$1" ;; esac
}

selftest() {
  st_cases=0
  st_fail=0
  st_root="$(mktemp -d)" || { echo "selftest: cannot run, mktemp failed"; return "$CANNOT_CHECK"; }
  trap 'rm -rf "$st_root"' EXIT
  R="$st_root/repo"; H="$st_root/host"

  # 1. OVER-CORRECTION CONTROL. A healthy tree must stay green, or every RED below is worthless.
  _st_tree "$R" "" "alpha bravo"; _st_tree "$H" "" "alpha bravo"
  _st_run "$R" "$H"
  _st_rc    "healthy host is green" 0
  _st_has   "healthy host reports the resolved denominator" "resolved 3 of 3 world members"
  _st_lacks "healthy host raises no unresolved member" "could not be resolved"

  # 2. UNRESOLVABLE WORLD MEMBER. Qualified so iface_file's non-recursive glob cannot reach it.
  #    Planted in BOTH trees on purpose: if only the host carried it the world file itself would
  #    differ and the ordinary byte-diff would catch it, which is not the defect under test.
  _st_tree "$R" "    export zeroclaw:plugin/secrets@0.1.0;\n" "alpha bravo"
  _st_tree "$H" "    export zeroclaw:plugin/secrets@0.1.0;\n" "alpha bravo"
  _st_run "$R" "$H"
  _st_rc  "unresolvable world member is a finding" 1
  _st_has "unresolvable member is counted" "resolved 3 of 4 world members"
  _st_has "unresolvable member is named in full" "zeroclaw:plugin/secrets@0.1.0"
  # 2b. THE SAME MEMBER, RESOLVED. Mirror of case 2: once the resolver CAN reach a qualified
  #     member it stops being unresolved and starts being described, and the description is where
  #     the name used to be truncated at the last colon. The fixture declares the interface under
  #     its qualified name, which no real .wit does -- it is the shape a WIDENED `iface_file`
  #     produces, and widening is what this script's own fix line for case 2 recommends. Nothing
  #     reaches this through an ordinary host today, which is why it is pinned rather than left to
  #     be rediscovered by whoever follows that advice.
  _st_tree "$R" "    export zeroclaw:plugin/secrets@0.1.0;
" "alpha bravo"
  _st_tree "$H" "    export zeroclaw:plugin/secrets@0.1.0;
" "alpha bravo"
  printf 'interface zeroclaw:plugin/secrets@0.1.0 {
  get: func() -> string;
}
' > "$H/wit/v0/secrets.wit"
  _st_run "$R" "$H"
  _st_rc  "a resolved qualified member is a finding" 1
  _st_has "a resolved qualified member is counted" "resolved 4 of 4 world members"
  _st_has "a resolved qualified member is named in full" "exported interface(s): zeroclaw:plugin/secrets@0.1.0"

  # 3. REACHED ONLY THROUGH `use`. The kind is unestablished, so the reassuring import wording
  #    must not appear. This is the case that shipped "no rebuild is required today" for an
  #    interface the EXPORTED tool interface depends on.
  _st_tree "$R" "" "alpha bravo"; _st_tree "$H" "" "alpha bravo"
  rm -f "$R/wit/v0/types.wit"
  _st_run "$R" "$H"
  _st_rc    "use-reached member we do not vendor is a finding" 1
  _st_has   "use-reached member reports an unestablished kind" "could NOT be established"
  _st_has   "use-reached member names who uses it" "used by:"
  _st_lacks "use-reached member never claims a rebuild is unnecessary" "no rebuild is required today"

  # 3b. OVER-CORRECTION CONTROL for 3: a genuine IMPORT must still get the no-rebuild wording,
  #     or the narrowing above has simply made every missing member sound like a break.
  _st_tree "$R" "" "alpha bravo"; _st_tree "$H" "    import secrets;\n" "alpha bravo"
  printf 'interface secrets {\n  get: func() -> string;\n}\n' > "$H/wit/v0/secrets.wit"
  _st_run "$R" "$H"
  _st_rc  "genuine import we do not vendor is a finding" 1
  _st_has "genuine import keeps the no-rebuild wording" "no rebuild is required today"

  # 4. STALE WASM. The component predates a variant the host now declares: builds fine, fails at
  #    load. Checking the artifact rather than the source is the only way to see it.
  _st_tree "$R" "" "alpha"; _st_tree "$H" "" "alpha bravo"
  _st_run "$R" "$H"
  _st_rc  "stale component missing a variant is a finding" 1
  _st_has "stale component is named with the variant it lacks" "is MISSING: bravo"

  # 5. EXIT-CODE VOCABULARY. `exit "$fail"` returned a COUNT, so two findings exited 2 and three
  #    exited 3 -- the codes this repo reads as CANNOT_CHECK and CONTROL_DEAD. Each state now has
  #    to be reachable and distinct, and two findings must not impersonate a cannot-check.
  _st_tree "$R" "" "alpha bravo"; _st_tree "$H" "" "alpha bravo"
  printf 'interface types {\n  type json-string = string;\n  DRIFT\n}\n' > "$H/wit/v0/types.wit"
  printf 'interface tool {\n  use types.{json-string};\n  DRIFT\n}\n'    > "$H/wit/v0/tool.wit"
  _st_run "$R" "$H"
  _st_rc  "two findings exit 1, not 2" 1
  _st_has "two findings are counted as findings" "findings=2"

  _st_tree "$R" "" "alpha bravo"; _st_tree "$H" "" "alpha bravo"
  rm -f "$R/plugins/demo/demo.wasm"
  _st_run "$R" "$H"
  _st_rc  "nothing built is a cannot-check, not a finding" "$CANNOT_CHECK"
  _st_has "nothing built says so in the verdict" "INCONCLUSIVE"

  _st_tree "$R" "" "alpha bravo"; _st_tree "$H" "" "alpha bravo"
  printf 'world tool-plugin {\n    import logging;\n    export plugin-info;\n}\n' > "$H/wit/v0/world.wit"
  _st_run "$R" "$H"
  _st_rc  "a lost floor file is control-dead, not a finding" "$CONTROL_DEAD"
  _st_has "control-dead says nothing above is evidence" "CONTROL DEAD"

  # 7. ONE FILE, BOTH KINDS. A .wit can declare several interfaces, and a world can import one of
  #    them and export another out of that same file. The comparison loop walks FILES, so the file
  #    got ONE verdict -- whichever kind parsed first -- and an unsatisfied EXPORT was reported as
  #    "our WIT is behind" with "no rebuild is required today". Planted in BOTH worlds so the
  #    ordinary byte-diff on world.wit stays quiet and the kind verdict is the only thing under test.
  _st_tree "$R" "    import secrets;\n    export vault-export;\n" "alpha bravo"
  _st_tree "$H" "    import secrets;\n    export vault-export;\n" "alpha bravo"
  printf 'interface secrets {\n  get: func() -> string;\n}\ninterface vault-export {\n  dump: func() -> string;\n}\n' \
    > "$H/wit/v0/secrets.wit"
  _st_run "$R" "$H"
  _st_rc    "a file carrying both kinds is a finding" 1
  _st_has   "the export decides the verdict for a mixed file" "is EXPORTED by the host's tool-plugin world"
  _st_has   "the mixed file names its exported interface" "exported interface(s): vault-export"
  _st_has   "the mixed file discloses the import it also carries" "also supplies import(s): secrets"
  _st_lacks "a mixed file never gets the no-rebuild wording" "no rebuild is required today"

  # 8. A FLOOR ON THE VARIANT DERIVATION, asymmetric with the world floor until now: only the EMPTY
  #    list was caught, so a derivation returning a HANDFUL ran the whole loop and printed a PASS
  #    per component. An enum of one variant is not a discriminating check, and the components were
  #    measured against a needle list that is not the enum, so this is CONTROL_DEAD, not a finding.
  #    Degraded in BOTH trees, so the relative floor cannot fire and the absolute one is under test.
  _st_tree "$R" "" "alpha bravo" "    alpha,\n"
  _st_tree "$H" "" "alpha bravo" "    alpha,\n"
  _st_run "$R" "$H"
  _st_rc    "a collapsed variant derivation is control-dead, not a pass" "$CONTROL_DEAD"
  _st_has   "a collapsed derivation says the parse broke" "the parse has broken"
  _st_lacks "a collapsed derivation prints no unearned component PASS" "carries all"

  # 8b. THE RELATIVE HALF of that floor, EXERCISED ALONE. Upstream flattens most of the enum onto
  #     one line, so the capture returns three names where our vendored copy still yields eight.
  #     THREE, not one, on purpose: the first draft of this case derived a single variant, which the
  #     ABSOLUTE floor also catches, so it passed with the relative half deleted and proved nothing.
  #     A case that cannot fail alone is not a case. The byte-diff fires here too and is a real
  #     finding; CONTROL_DEAD outranks it deliberately, because a finding count printed under a
  #     broken parse invites fixing N things and trusting the rest.
  _st_tree "$R" "" "alpha bravo charlie" \
    "    alpha,\n    bravo,\n    charlie,\n    delta,\n    echo,\n    foxtrot,\n    golf,\n    hotel,\n"
  _st_tree "$H" "" "alpha bravo charlie" "    alpha,\n    bravo,\n    charlie, delta, echo, foxtrot, golf, hotel,\n"
  _st_run "$R" "$H"
  _st_rc  "a collapse against our vendored count is control-dead" "$CONTROL_DEAD"
  _st_has "the relative floor reports both magnitudes" "returned 3 variant(s) against the 8 we vendor"

  # 9. THE VARIANT MATCHER IS ANCHORED. `has()` is a substring match, so a component carrying
  #    `alphabet` scored as carrying the variant `alpha`. Measured over the 38 real variants, that
  #    read 7 of 38 as present in tar.exe. This section exists to catch ONE newly added variant, so
  #    a new short name landing inside an unrelated string is the whole failure mode.
  _st_tree "$R" "" "alphabet bravo"; _st_tree "$H" "" "alphabet bravo"
  _st_run "$R" "$H"
  _st_rc  "a variant present only as a fragment is a finding" 1
  _st_has "the fragment-only variant is named as missing" "is MISSING: alpha"

  # 9b. OVER-CORRECTION CONTROL for 9, and the reason a whole-LINE match was rejected: real
  #     components pack neighbouring variants onto one `strings` line separated by a TAB, so an
  #     exact-line matcher reports them missing from every plugin. A tab-separated pair must pass.
  _st_tree "$R" "" "$(printf 'alpha\tbravo')"; _st_tree "$H" "" "$(printf 'alpha\tbravo')"
  _st_run "$R" "$H"
  _st_rc  "tab-packed variants still count as present" 0
  _st_has "tab-packed variants report the newest declared" "newest declared: alpha bravo"

  # 9c. THE MATCHER'S OWN CONTROL, which is what stops a future loosening from printing a full set
  #     of unearned PASS lines. The needle is derived (longest variant, first and last character
  #     removed), so it is a fragment of a real variant and never a variant.
  _st_tree "$R" "" "alpha bravo"; _st_tree "$H" "" "alpha bravo"
  _st_run "$R" "$H"
  _st_has "the anchoring control runs and passes" "anchoring control:"
  _st_has "the anchoring control names its derived needle" "\"lph\" is present as a fragment"

  # 6. The one output line a machine consumes: host-drift.yml parses it to scope its triage, and
  #    reads an empty parse as CANNOT CHECK. Reword it there and the workflow silently degrades.
  _st_tree "$R" "" "alpha bravo"; _st_tree "$H" "" "alpha bravo"
  _st_run "$R" "$H"
  _st_has "the world-members line host-drift.yml parses is intact" "world members (derived from the host):"

  printf 'selftest: %s/%s\n' "$((st_cases - st_fail))" "$st_cases"
  [ "$st_fail" -eq 0 ] && return "$OK"
  return "$FINDING"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi

if [ -z "$HOST" ] || [ ! -d "$HOST" ]; then
  echo "usage: $0 /path/to/zeroclaw-host-clone" >&2
  # Already the right code by luck rather than by choice; named now so it stays that way. No host
  # was supplied, so nothing was compared, which is CANNOT_CHECK and not a finding about the tree.
  exit "$CANNOT_CHECK"
fi

echo "repo: $REPO"
echo "host: $HOST"
echo ""

# 1. The tool-plugin world must be identical. Only the files in our world matter; drift in
#    channel/memory/sockets/ws-client cannot affect a tool plugin, so comparing the whole
#    directory would produce noise that trains people to ignore this check.
#
#    That membership used to be four filenames written here by hand. It was correct by
#    definition on the day it was written, which is the property that makes it dangerous:
#    nothing ever contradicts it, so it goes stale in silence the moment upstream adds an
#    interface to the world. The world is machine-readable, so it is read instead.
#
#    It is derived from the HOST'S copy on purpose. Deriving from ours would reproduce the
#    exact staleness this whole script exists to catch, since a world member we have never
#    heard of is invisible in our own tree. Reading the authority means a newly-added
#    interface arrives as a finding rather than as silence.
echo "wit/v0 tool-plugin world (the one that silently breaks registration)"

# file basename -> the kind the world uses it with, in the host's tree.
#
# ONE .wit CAN DECLARE SEVERAL INTERFACES, and a world can IMPORT one of them and EXPORT another
# from that same file. This returned the FIRST pair it found, and the comparison loop below walks
# FILES, so a file carrying both was reported once, under whichever kind happened to be parsed
# first. DRIVEN 2026-08-27: a host declaring `interface secrets` and `interface vault-export` in
# one `secrets.wit`, with `import secrets;` and `export vault-export;` in the world, printed a
# single FAIL reading "is IMPORTED ... our WIT is behind" and "no rebuild is required today". The
# EXPORTED half is a genuine instantiation break -- looked up ON the component and simply absent --
# and it was invisible, reported as benign drift.
#
# EXPORT WINS, because the two kinds are not equal in consequence: an unsatisfied export breaks
# registration on every plugin, an import we do not vendor only means our WIT is behind. Reporting
# the weaker of the two is the reassuring direction, which is the one that ships.
world_kind() {
  _k=unknown
  for _p in $KINDMAP; do
    case "$_p" in "$1="*)
      _v="${_p#*=}"
      [ "$_v" = export ] && { printf 'export'; return; }
      _k="$_v" ;;
    esac
  done
  printf '%s' "$_k"
}

# The interface NAMES a file contributes to the world under one kind. `world_kind` collapses a
# mixed file to its strongest kind, which is the right verdict and loses the detail a reader needs
# to act: which interface is the break and which is merely drift.
#
# STRIP THE KEY, NOT EVERYTHING UP TO THE LAST COLON. An IFACES entry is `file=kind:member`, and
# a member can itself carry colons (`zeroclaw:plugin/secrets@0.1.0`), so `${_p##*:}` printed the
# fragment after the LAST one and named the interface something the host never wrote. That is the
# same defect the member capture above already fixes for the unresolved path, with the same
# consequence: a reader greps for a name that appears nowhere and concludes the tool is confused.
#
# It is not reachable through an ordinary host today, because `iface_file` resolves a member by
# grepping for a bare `interface <name> {` and a qualified name never matches, so such a member
# lands in UNRESOLVED instead and is reported in full. It becomes reachable the moment anyone
# widens that resolver -- which is exactly what this script's own fix line tells a reader to do.
# On every name without a colon the two forms are byte-identical, so this changes no verdict
# reachable today and removes the trap the widening would arm.
world_ifaces() { # $1=file basename  $2=import|export
  for _p in $IFACES; do
    case "$_p" in "$1=$2:"*) printf ' %s' "${_p#"$1=$2:"}" ;; esac
  done
}

iface_file() {
  basename "$(grep -lE "^[[:space:]]*interface[[:space:]]+$1[[:space:]]*\{" \
               "$HOST"/wit/v0/*.wit 2>/dev/null | head -1)" 2>/dev/null
}

seed="$(grep -lE "^[[:space:]]*world[[:space:]]+tool-plugin[[:space:]]*\{" \
        "$HOST"/wit/v0/*.wit 2>/dev/null | head -1)"
WORLD=""
KINDMAP=""
IFACES=""
PARSED=0
RESOLVED=0
UNRESOLVED=""
if [ -n "$seed" ]; then
  WORLD="$(basename "$seed")"
  # Capture the member up to the `;` rather than as a bare `[a-z][a-z0-9-]*`. A fully-qualified
  # member (`export zeroclaw:plugin/secrets@0.1.0;`) matched the bare form as the single word
  # `zeroclaw`, so the name carried into the resolver, and into any message about it, was not the
  # name in the file. Reporting an unresolved member by a name the host never used sends the
  # reader looking for the wrong thing.
  members="$(sed -n "/^[[:space:]]*world[[:space:]]\+tool-plugin[[:space:]]*{/,/^[[:space:]]*}/p" "$seed" \
             | grep -oE "^[[:space:]]*(import|export)[[:space:]]+[^;]*" \
             | awk '{print $1 ":" $2}')"
  for mk in $members; do
    k="${mk%%:*}"
    m="${mk#*:}"
    PARSED=$((PARSED+1))
    g="$(iface_file "$m")"
    if [ -n "$g" ]; then
      RESOLVED=$((RESOLVED+1))
      WORLD="$WORLD $g"
      # EVERY pair is appended, never overwritten: `world_kind` resolves the precedence at lookup
      # time so a file that appears twice under two kinds keeps both facts.
      KINDMAP="$KINDMAP $g=$k"
      IFACES="$IFACES $g=$k:$m"
    else
      # A DROPPED MEMBER USED TO BE INVISIBLE. `iface_file` returns empty whenever its
      # non-recursive `$HOST/wit/v0/*.wit` grep misses -- a qualified name, an interface upstream
      # moved into a subdirectory or a dep package, a renamed file -- and the member was then
      # skipped with no counter, no note and no FAIL. The floor below only asserts that four
      # files are PRESENT, never that every member RESOLVED, so the run printed a PASS per
      # surviving member and COMPATIBLE, having never compared the dropped one at all. An
      # unresolved EXPORT is precisely the case that breaks every plugin's registration, so the
      # silence was in the reassuring direction.
      UNRESOLVED="$UNRESOLVED $k:$m"
    fi
  done
  # `types` reaches the world through `use types.{json-string}` inside the members rather
  # than through the world body, so a members-only read would drop the file every other
  # interface depends on. Two passes settle this graph; a third is cheap insurance.
  for _ in 1 2 3; do
    more=""
    for f in $WORLD; do
      for n in $(grep -oE "use[[:space:]]+[a-z][a-z0-9-]*\." "$HOST/wit/v0/$f" 2>/dev/null \
                 | awk '{print $2}' | tr -d '.'); do
        g="$(iface_file "$n")"
        [ -n "$g" ] && more="$more $g"
      done
    done
    WORLD="$(printf '%s %s\n' "$WORLD" "$more" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')"
  done
fi

# The four this enumerated by hand until 2026-07-27, kept as a floor rather than as the scope.
# A derivation that stops returning them has broken, and a broken derivation that returns two
# files would compare two files and print PASS, which is the reassuring sentence rather than
# the alarm.
for c in logging.wit tool.wit plugin-info.wit types.wit; do
  case " $WORLD " in
    *" $c "*) ;;
    *)
      # NOT a finding about the tree. The floor is this section's POSITIVE CONTROL: it is the only
      # thing establishing that the derivation can still see the world at all, and losing it means
      # every PASS this section would have printed is unearned. It also blanks WORLD, so the
      # comparison below does not run and there is nothing left here that could be a finding.
      dead "world derivation lost $c, so it cannot be trusted about the rest"
      fix "check that $HOST/wit/v0 still declares 'world tool-plugin' and its interfaces"
      WORLD=""
      break
      ;;
  esac
done

[ -n "$WORLD" ] && echo "  world members (derived from the host): $WORLD"

# THE DENOMINATOR, printed every run including the clean one. Without it a run that resolved four
# of five members is byte-indistinguishable from one that resolved five of five: both print a PASS
# per file it did compare and then COMPATIBLE. The gap is the whole signal, so a zero here has to
# be readable as a measurement rather than as an absence.
if [ -n "$seed" ]; then
  echo "  resolved $RESOLVED of $PARSED world members"
fi
# Reported only while the floor control is intact. When the derivation is broken wholesale the
# CONTROL DEAD above is the finding, and adding a per-member FAIL underneath it would invite
# someone to go and fix members in a run where nothing was trustworthy anyway.
if [ -n "$WORLD" ] && [ "$RESOLVED" -lt "$PARSED" ]; then
  bad "$((PARSED - RESOLVED)) world member(s) could not be resolved to a .wit file and were NEVER compared"
  for _um in $UNRESOLVED; do
    printf '        unresolved: %s %s\n' "${_um%%:*}" "${_um#*:}"
  done
  printf '        an unresolved EXPORT breaks registration on every plugin and is invisible locally\n'
  fix "find where $HOST declares these (they may be qualified, in a subdirectory, or in a dep package) and vendor them, or widen iface_file to reach them"
fi
for f in $WORLD; do
  ours="$REPO/wit/v0/$f"
  theirs="$HOST/wit/v0/$f"
  if [ ! -f "$theirs" ]; then
    bad "$f missing from the host clone"
    fix "check the host path, or the host moved wit/v0"
    continue
  fi
  if [ ! -f "$ours" ]; then
    # WHICH WAY THE INTERFACE POINTS DECIDES THE CONSEQUENCE, so the world's own
    # import/export kind is carried here rather than assumed.
    # THREE outcomes, not two. The `else` here used to carry BOTH import and unknown, and that is
    # the reassuring branch: it prints "our WIT is behind" and "no rebuild is required today".
    # `types.wit` reaches the world only through the transitive `use` pass below, so it is never
    # added to KINDMAP and `world_kind` returns `unknown` for it -- and `types.wit` is `use`d by
    # the EXPORTED `tool` interface, where a nominal change to one of its types makes the exported
    # interface a different type and every plugin fails to register. So the one member that
    # reliably lands in this branch is the one for which "no rebuild is required" is exactly wrong.
    # Unknown now says it is unknown, per this script's own stated contract that an
    # unestablished kind takes the conservative wording.
    _k="$(world_kind "$f")"
    case "$_k" in
    export)
      # The host REQUIRES this FROM the component. A plugin that does not export it cannot
      # instantiate, and nothing local can observe that.
      bad "$f is EXPORTED by the host's tool-plugin world and we do not vendor it"
      printf '        exported interface(s):%s\n' "$(world_ifaces "$f" export)"
      _imp="$(world_ifaces "$f" import)"
      # Say so explicitly when one file carries both. Otherwise a reader who greps the world for
      # this filename finds an `import` line, concludes the export verdict is wrong, and downgrades
      # a break to drift by hand -- which is the same mistake this branch was making by itself.
      [ -n "$_imp" ] && printf '        the SAME file also supplies import(s):%s -- the export decides the consequence\n' "$_imp"
      fix "copy $theirs into $REPO/wit/v0/$f, then rebuild every plugin"
      ;;
    import)
      # The host OFFERS this TO the component. A component that imports a SUBSET of what the
      # host offers still instantiates, so this is drift rather than a break: our vendored WIT
      # is behind, and a plugin that wanted this interface could not build against what we have.
      bad "$f is IMPORTED by the host's tool-plugin world and we do not vendor it: our WIT is behind"
      fix "copy $theirs into $REPO/wit/v0/$f when a plugin needs it; no rebuild is required today"
      ;;
    *)
      # Reached through `use` from another member rather than named in the world body, so the
      # world says nothing about which way it points. Naming its users is cheap and turns the
      # hedge into evidence a reader can act on, without pretending to have resolved the kind.
      _users=""
      for _u in $WORLD; do
        grep -qE "use[[:space:]]+${f%.wit}\." "$HOST/wit/v0/$_u" 2>/dev/null && _users="$_users $_u"
      done
      bad "$f is in the host's tool-plugin world but its import/export kind could NOT be established"
      printf '        it is reached through `use` from another member, not named in the world body\n'
      printf '        used by:%s\n' "${_users:- (no user found, which is itself suspicious)}"
      printf '        if ANY exported interface uses it, this IS a break and needs a rebuild\n'
      fix "copy $theirs into $REPO/wit/v0/$f, then rebuild every plugin unless you have checked that no exported interface uses it"
      ;;
    esac
    continue
  fi
  if diff -q <(tr -d '\r' < "$ours") <(tr -d '\r' < "$theirs") >/dev/null 2>&1; then
    ok "$f identical"
  else
    bad "$f DIFFERS from the host"
    echo "        ---- host has that we do not ----"
    diff <(tr -d '\r' < "$ours") <(tr -d '\r' < "$theirs") | grep '^>' | head -8 | sed 's/^/        /'
    fix "copy the host's $f into $REPO/wit/v0/$f, then rebuild every plugin"
  fi
done

# 2. Every built component must actually carry the current enum variants. A stale wasm
#    left in target/ from before a wit sync looks fine and fails at load, so check the
#    artifact rather than the source.
echo ""
echo "built components carry the host's plugin-action variants"
_derive_variants() { # $1=path to a logging.wit
  sed -n '/enum plugin-action/,/}/p' "$1" 2>/dev/null \
    | grep -oE '^[[:space:]]+[a-z][a-z0-9-]*' | tr -d ' ' | grep -v '^enum$'
}
VARIANTS="$(_derive_variants "$HOST/wit/v0/logging.wit")"
VCOUNT=$(printf '%s' "$VARIANTS" | wc -w)
# OUR vendored copy, read ONLY as a MAGNITUDE reference and never as the scope. Deriving the scope
# from our own tree would reproduce the exact staleness this script exists to catch, which is why
# the world derivation reads the host; a count, though, is a positive control the host-side parse
# has to clear, and we already carry a known-good enum to compare its SIZE against.
OCOUNT=$(printf '%s' "$(_derive_variants "$REPO/wit/v0/logging.wit")" | wc -w)
if [ -z "$VARIANTS" ]; then
  # The needle list came back empty, so every match below would have searched for NOTHING and
  # reported every component clean. That is the uncalibrated zero, not a finding: nothing about
  # our components was measured either way.
  cant "could not read plugin-action variants from the host, so no component was measured"
  fix "check that $HOST/wit/v0/logging.wit still declares 'enum plugin-action'"
elif [ "$VCOUNT" -lt 2 ] || { [ "$OCOUNT" -gt 0 ] && [ $((VCOUNT * 2)) -lt "$OCOUNT" ]; }; then
  # A FLOOR ON THE DERIVATION, the same shape the world floor above uses and for the same reason.
  # Only the EMPTY case was caught, and empty is the easy half: a derivation that returns a HANDFUL
  # still runs the whole loop and prints a PASS per component, which is the reassuring sentence
  # rather than the alarm. DRIVEN 2026-08-27: with the host's variants reformatted onto one line --
  # `alpha, bravo, charlie,` -- the `^[[:space:]]+[a-z]` capture returned exactly ONE name and the
  # section printed "PASS demo.wasm carries all 1 variants" and exited 0.
  #
  # CONTROL_DEAD and not FINDING, matching the world floor: the components were measured against a
  # needle list that is not the enum, so every PASS printed here would be unearned. Nothing is wrong
  # with the tree; the parse is wrong.
  #
  # TWO floors, because one of them cannot see the case that matters most.
  #   RELATIVE  fewer than half of what our own vendored copy yields. Not a pinned number, because
  #             a pinned one is the stale-list defect this file argues against everywhere else. It
  #             trips on a COLLAPSE and stays quiet for ordinary churn: upstream removing a variant
  #             leaves 37 against 38 and is caught by the byte-diff above, where it belongs.
  #   ABSOLUTE  fewer than two, full stop. The relative floor is blind when BOTH copies parse the
  #             same degraded way -- reformat the enum on both sides and 1 against 1 clears the
  #             ratio -- and a one-needle search is not a discriminating check whatever it is
  #             measured against. Not a version fact and so not a stale pin: an enum with fewer than
  #             two variants is degenerate by definition.
  dead "host plugin-action derivation returned $VCOUNT variant(s) against the $OCOUNT we vendor, so the parse has broken"
  fix "check that $HOST/wit/v0/logging.wit still declares 'enum plugin-action' one variant per line"
else
  found_any=0
  # The LAST-DECLARED variants, derived from the enum's own order rather than listed. WIT enums are
  # ordered and variants are appended, so the tail is the newest -- and the newest is the entire
  # reason this section exists, since the drift that bit us three times was upstream ADDING one.
  # Naming them in the verdict is what makes a green here readable: "carries all 38" says nothing
  # about whether the one that matters was among them.
  NEWEST="$(printf '%s\n' $VARIANTS | tail -3 | tr '\n' ' ')"
  for wasm in "$REPO"/plugins/*/*.wasm "$REPO"/plugins/*/target/wasm32-wasip2/release/*.wasm; do
    [ -f "$wasm" ] || continue
    found_any=1
    missing=""
    for v in $VARIANTS; do
        carries_variant "$wasm" "$v" || missing="$missing $v"
    done
    name="$(basename "$wasm")"
    if [ -z "$missing" ]; then
      ok "$name carries all $VCOUNT variants (newest declared:$(printf ' %s' $NEWEST))"
    else
      bad "$name is MISSING:$missing"
      # Which ones are missing decides how alarming this is. A component missing the NEWEST variant
      # is the known drift shape -- built before an upstream addition -- and a rebuild fixes it. A
      # component missing an OLD variant means something else is wrong with the artifact.
      _mn=""
      for v in $missing; do
        case " $NEWEST " in *" $v "*) _mn="$_mn $v" ;; esac
      done
      [ -n "$_mn" ] && printf '        among them the newest declared:%s -- this is the upstream-added-a-variant shape\n' "$_mn"
      fix "rebuild it: cargo build --target wasm32-wasip2 --release"
    fi
  done

  # THE MATCHER'S OWN POSITIVE CONTROL. Everything above is a list of needles and a matcher, and a
  # matcher loose enough to say yes to anything prints a full set of PASS lines against an artifact
  # that carries nothing. `has()` was that loose: it read `read` out of `blocking-read`, so an
  # unrelated binary scored 7 of 38.
  #
  # The needle is DERIVED: the longest declared variant with its first and last character removed.
  # That string is a substring of a real variant and is not itself a variant, so it MUST match under
  # a substring matcher and MUST NOT match under an anchored one. If it matches here, the anchoring
  # has been lost and every PASS above is unearned -- which is CONTROL_DEAD, not a finding about any
  # component. Derived rather than written down so it cannot go stale when the enum changes.
  _lv="$(printf '%s\n' $VARIANTS | awk '{ if (length($0) > length(m)) m = $0 } END { print m }')"
  _needle="${_lv#?}"; _needle="${_needle%?}"
  if [ "${#_needle}" -lt 3 ]; then
    printf '  note  anchoring control skipped: longest variant "%s" is too short to derive a needle\n' "$_lv"
  else
    _probe=""
    for w in "$REPO"/plugins/*/*.wasm "$REPO"/plugins/*/target/wasm32-wasip2/release/*.wasm; do
      [ -f "$w" ] && has "$w" "$_lv" && { _probe="$w"; break; }
    done
    if [ -z "$_probe" ]; then
      # Not a failure: with no component carrying the longest variant there is nothing to prove the
      # anchoring against, and the loop above has already said so in its own terms.
      printf '  note  anchoring control could not run: no built component carries "%s"\n' "$_lv"
    elif carries_variant "$_probe" "$_needle"; then
      dead "the variant matcher accepted \"$_needle\", which is a fragment of \"$_lv\" and not a variant"
      fix "carries_variant() has lost its anchoring; every PASS above matched fragments, not names"
    else
      ok "anchoring control: \"$_needle\" is present as a fragment and correctly NOT counted"
    fi
  fi
  # Coverage, stated explicitly. Passing on 3 of 8 plugins while staying silent about the
  # other 5 would read as full confidence, which is the failure this whole script exists
  # to prevent one level up.
  total_dirs=$(find "$REPO/plugins" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
  # Count the plugin DIRECTORIES that have a built component, globbing BOTH layouts, because
  # the verification loop above globs both and cargo only ever writes the second
  # (plugins/<name>/target/wasm32-wasip2/release/<name>.wasm, as QUICKSTART states). This
  # counter globbed the first layout alone, so it returned 0 on every real build and the
  # script could never reach COMPATIBLE, while printing PASS lines for individual plugins
  # directly above. A counter whose job is to stop passing-while-silent from reading as full
  # confidence must not itself be blind to where the artifacts land. Both the loop and this
  # count now walk the same directories, so they cannot drift apart again.
  checked=$(
    for d in "$REPO"/plugins/*/; do
      [ -d "$d" ] || continue
      for w in "$d"*.wasm "$d"target/wasm32-wasip2/release/*.wasm; do
        if [ -f "$w" ]; then basename "${d%/}"; break; fi
      done
    done | sort -u | wc -l
  )
  echo "  coverage: $checked of $total_dirs plugin directories have a built component"
  # BOTH of these are CANNOT_CHECK and neither is a finding, and the sentences say so themselves:
  # "NOTHING was actually verified" and "were NOT checked" are the definition of the state. An
  # unbuilt component is not a defect in the component; it is an absence of evidence about it, and
  # the remedy is a build rather than a fix. Classing them together also removes an inconsistency
  # that would otherwise ship: no-wasm-at-all reading as cannot-check while some-wasm-missing read
  # as a finding, when both mean the same thing about the same components.
  if [ "$found_any" -eq 0 ]; then
    cant "no built .wasm found, so NOTHING was actually verified here"
    fix "cargo build --target wasm32-wasip2 --release in each plugin, then re-run"
  elif [ "$checked" -lt "$total_dirs" ]; then
    cant "$((total_dirs - checked)) plugin(s) have no built component and were NOT checked"
    fix "build the rest before trusting a COMPATIBLE verdict"
  fi
fi

# 3. Feature flags. Two of the three fail loudly; whatsapp-web fails in total silence,
#    which is why it gets its own check with a marker that is only present when linked.
echo ""
echo "host binary features"
BIN="$HOST/target/release/zeroclaw"
if [ -n "${ZC_SKIP_HOST_BINARY:-}" ]; then
  # CI drift-watching clones the host for its `wit/` only, because building the host
  # to check three feature flags costs more than it buys on every scheduled run. The
  # skip is announced rather than silently passed: a check you cannot see is skipped
  # is worse than one that failed, and the verdict below is downgraded to match.
  skipped=1
  printf '  SKIP  host binary checks (ZC_SKIP_HOST_BINARY set; WIT parity above is unaffected)\n'
elif [ ! -f "$BIN" ]; then
  bad "no release binary at $BIN"
  fix "cargo build --release --features plugins-wasm,plugins-wasm-cranelift,whatsapp-web"
else
  ok "release binary present ($(date -u -r "$BIN" +%FT%TZ))"
  if has "$BIN" wasmtime; then
    ok "wasm runtime linked"
  else
    bad "no wasm runtime in the binary"
    fix "rebuild with --features plugins-wasm,plugins-wasm-cranelift"
  fi
  # `wacore` links only under whatsapp-web. Do NOT grep for `whatsapp`: the cloud-API
  # channel and the config schema compile unconditionally and match on a host that has
  # no web channel at all.
  if has "$BIN" wacore; then
    ok "whatsapp-web linked (needed only for the WhatsApp shop)"
  else
    bad "whatsapp-web NOT linked, so [channels.whatsapp.*] will parse and never run"
    fix "rebuild adding ,whatsapp-web to --features"
  fi
fi

echo ""
# All three counts, every run, including the zeros. A bare "0 findings" is equally consistent with
# a clean tree and with a run that measured nothing, and printing the other two denominators beside
# it is what separates those.
echo "counts: findings=$fail cannot-check=$cannot control-dead=$dead"
#
# Severity order, most severe first, because one process gets one exit code:
#   CONTROL_DEAD outranks everything. A dead control means the PASS lines above are unearned, so
#                reporting a finding count instead would invite someone to fix N things and believe
#                the rest was verified.
#   FINDING      outranks cannot-check. Something is definitely wrong; the unmeasured parts can
#                wait behind it.
#   CANNOT_CHECK last, and deliberately NOT triggered by ZC_SKIP_HOST_BINARY. That skip is a
#                caller's announced scope choice, already downgraded to WIT-COMPATIBLE in the
#                verdict below; treating it as a cannot-check would exit non-zero on every
#                scheduled drift run, which reddens a canary permanently and teaches people to
#                ignore it.
if [ "$dead" -gt 0 ]; then
  echo "CONTROL DEAD: $dead control(s) broke, so nothing above is evidence. Fix the check, not the tree."
  exit "$CONTROL_DEAD"
elif [ "$fail" -gt 0 ]; then
  echo "NOT COMPATIBLE: $fail check(s) failed. Fix them before demoing."
  exit "$FINDING"
elif [ "$cannot" -gt 0 ]; then
  echo "INCONCLUSIVE: $cannot check(s) could not run, so COMPATIBLE was not established."
  exit "$CANNOT_CHECK"
elif [ -n "${skipped:-}" ]; then
  echo "WIT-COMPATIBLE: the interfaces match. Host binary features were NOT checked."
  exit "$OK"
else
  echo "COMPATIBLE: this host will load and register these plugins."
  exit "$OK"
fi
