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
fail=0
ok()  { printf '  PASS  %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
fix() { printf '        fix: %s\n' "$1"; }

if [ -z "$HOST" ] || [ ! -d "$HOST" ]; then
  echo "usage: $0 /path/to/zeroclaw-host-clone" >&2
  exit 2
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
if [ -n "$seed" ]; then
  WORLD="$(basename "$seed")"
  members="$(sed -n "/^[[:space:]]*world[[:space:]]\+tool-plugin[[:space:]]*{/,/^[[:space:]]*}/p" "$seed" \
             | grep -oE "^[[:space:]]*(import|export)[[:space:]]+[a-z][a-z0-9-]*" \
             | awk '{print $1 ":" $2}')"
  for mk in $members; do
    k="${mk%%:*}"
    m="${mk#*:}"
    g="$(iface_file "$m")"
    if [ -n "$g" ]; then
      WORLD="$WORLD $g"
      KINDMAP="$KINDMAP $g=$k"
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
      bad "world derivation lost $c, so it cannot be trusted about the rest"
      fix "check that $HOST/wit/v0 still declares 'world tool-plugin' and its interfaces"
      WORLD=""
      break
      ;;
  esac
done

[ -n "$WORLD" ] && echo "  world members (derived from the host): $WORLD"
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
    _k="$(world_kind "$f")"
    if [ "$_k" = "export" ]; then
      # The host REQUIRES this FROM the component. A plugin that does not export it cannot
      # instantiate, and nothing local can observe that.
      bad "$f is EXPORTED by the host's tool-plugin world and we do not vendor it"
      fix "copy $theirs into $REPO/wit/v0/$f, then rebuild every plugin"
    else
      # The host OFFERS this TO the component. A component that imports a SUBSET of what the
      # host offers still instantiates, so this is drift rather than a break: our vendored WIT
      # is behind, and a plugin that wanted this interface could not build against what we have.
      bad "$f is in the host's tool-plugin world ($_k) and we do not vendor it: our WIT is behind"
      fix "copy $theirs into $REPO/wit/v0/$f when a plugin needs it; no rebuild is required today"
    fi
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
  bad "could not read plugin-action variants from the host"
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
  if [ "$found_any" -eq 0 ]; then
    bad "no built .wasm found, so NOTHING was actually verified here"
    fix "cargo build --target wasm32-wasip2 --release in each plugin, then re-run"
  elif [ "$checked" -lt "$total_dirs" ]; then
    bad "$((total_dirs - checked)) plugin(s) have no built component and were NOT checked"
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
if [ "$fail" -eq 0 ] && [ -n "${skipped:-}" ]; then
  echo "WIT-COMPATIBLE: the interfaces match. Host binary features were NOT checked."
elif [ "$fail" -eq 0 ]; then
  echo "COMPATIBLE: this host will load and register these plugins."
else
  echo "NOT COMPATIBLE: $fail check(s) failed. Fix them before demoing."
fi
exit "$fail"
