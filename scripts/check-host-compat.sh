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
has() { [ "$(strings "$1" 2>/dev/null | grep -c -- "$2" || true)" -gt 0 ]; }

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
  rm -rf "$1"; mkdir -p "$1/wit/v0" "$1/plugins/demo"
  printf 'interface logging {\n  enum plugin-action {\n    alpha,\n    bravo,\n  }\n}\n' > "$1/wit/v0/logging.wit"
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

# interface name -> the basename of the .wit declaring it, in the host's tree
world_kind() {
  for _p in $KINDMAP; do
    case "$_p" in "$1="*) printf '%s' "${_p#*=}"; return ;; esac
  done
  printf 'unknown'
}

iface_file() {
  basename "$(grep -lE "^[[:space:]]*interface[[:space:]]+$1[[:space:]]*\{" \
               "$HOST"/wit/v0/*.wit 2>/dev/null | head -1)" 2>/dev/null
}

seed="$(grep -lE "^[[:space:]]*world[[:space:]]+tool-plugin[[:space:]]*\{" \
        "$HOST"/wit/v0/*.wit 2>/dev/null | head -1)"
WORLD=""
KINDMAP=""
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
      KINDMAP="$KINDMAP $g=$k"
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
VARIANTS="$(sed -n '/enum plugin-action/,/}/p' "$HOST/wit/v0/logging.wit" 2>/dev/null \
           | grep -oE '^[[:space:]]+[a-z][a-z0-9-]*' | tr -d ' ' | grep -v '^enum$')"
if [ -z "$VARIANTS" ]; then
  # The needle list came back empty, so every `has` below would have searched for NOTHING and
  # reported every component clean. That is the uncalibrated zero, not a finding: nothing about
  # our components was measured either way.
  cant "could not read plugin-action variants from the host, so no component was measured"
  fix "check that $HOST/wit/v0/logging.wit still declares 'enum plugin-action'"
else
  found_any=0
  for wasm in "$REPO"/plugins/*/*.wasm "$REPO"/plugins/*/target/wasm32-wasip2/release/*.wasm; do
    [ -f "$wasm" ] || continue
    found_any=1
    missing=""
    for v in $VARIANTS; do
        has "$wasm" "$v" || missing="$missing $v"
    done
    name="$(basename "$wasm")"
    if [ -z "$missing" ]; then
      ok "$name carries all $(echo "$VARIANTS" | wc -w) variants"
    else
      bad "$name is MISSING:$missing"
      fix "rebuild it: cargo build --target wasm32-wasip2 --release"
    fi
  done
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
