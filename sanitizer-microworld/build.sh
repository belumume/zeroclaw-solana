#!/usr/bin/env sh
# Rebuild index.html from source. Portable on purpose: no absolute paths and no assumption
# about which machine this is, because the point of the artifact is that a stranger can
# regenerate it rather than take the committed bytes on trust.
#
# Regeneration is byte-identical. If index.html changes after running this and src/lib.rs
# did not, something is wrong and the diff is the finding.
set -eu
cd "$(dirname "$0")"

echo "== host tests first, so the wasm is only trusted after the ABI is =="
cargo test --release

echo
echo "== wasm target =="
rustup target add wasm32-unknown-unknown

echo
echo "== build =="
cargo build --release --target wasm32-unknown-unknown

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
WASM="$TARGET_DIR/wasm32-unknown-unknown/release/sanitizer_microworld.wasm"
if [ ! -f "$WASM" ]; then
  echo "no artifact at $WASM" >&2
  exit 1
fi
cp "$WASM" ./sanitizer.wasm
echo "wasm: $(wc -c < ./sanitizer.wasm) bytes"

echo
echo "== inline the wasm and write the page =="
python3 build_page.py

echo
echo "== structural check: the script block must parse =="
python3 check_page.py
