# Sanitizer microworld

Open [`sanitizer.html`](sanitizer.html) and try to get something past the defense.

It runs the actual `sanitize_onchain` from `crates/solana-core`, compiled to wasm and
base64-embedded in the page. No server, no network, no build step to look at it: double-click
the file. If the sanitizer changes, rebuilding the page changes what you see, and if the page
ever disagreed with the Rust tests one of them would be wrong.

The reason this exists rather than another paragraph: a defense you can operate is a different
kind of evidence from a defense described. Type a right-to-left override into the middle of a
word, set the cap to zero, paste forty kilobytes, and watch the counters.

## It shows a case it does not catch, on purpose

The preset called **Framing the flag misses** is obvious injection framing that survives
untouched with the advisory flag reading `no`. That is correct behaviour, not a gap, and the
page says so: `injection_suspected` matches a short list of known phrasings, never drops
anything, and is not the defense. That text is indistinguishable from a token genuinely named
that way, and stripping it would corrupt legitimate names, exactly as homoglyphs are preserved
rather than rewritten.

The defense is the two things visibly working next to it: removing the characters that hide
payloads, and a hard cap so a 40 KB name cannot flood a context window. Plus the plugin
rendering the field as quoted untrusted data.

A microworld that only demonstrates wins teaches the wrong model of what it is looking at.

## Rebuilding

```
cd microworld/sanitizer-wasm
cargo test                                            # the shim must match the library
cargo build --target wasm32-unknown-unknown --release  # needs: rustup target add wasm32-unknown-unknown
cd .. && python3 build.py <path-to>/sanitizer_wasm.wasm
```

The shim adds no logic. It marshals a string in, calls the library, and marshals JSON out. One
of its two tests asserts its output matches calling `sanitize_onchain` directly, so it cannot
quietly become a second implementation that agrees with the documentation instead of the code.
