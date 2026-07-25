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

# 1. The tool-plugin world must be identical. Only these four files are in our world;
#    drift in channel/memory/sockets/ws-client cannot affect a tool plugin, so comparing
#    the whole directory would produce noise that trains people to ignore this check.
echo "wit/v0 tool-plugin world (the one that silently breaks registration)"
WORLD="logging.wit tool.wit plugin-info.wit types.wit"
for f in $WORLD; do
  ours="$REPO/wit/v0/$f"
  theirs="$HOST/wit/v0/$f"
  if [ ! -f "$theirs" ]; then
    bad "$f missing from the host clone"
    fix "check the host path, or the host moved wit/v0"
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
  checked=$(printf '%s\n' "$REPO"/plugins/*/*.wasm 2>/dev/null \
            | while read -r w; do [ -f "$w" ] && basename "$w"; done | sort -u | wc -l)
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
