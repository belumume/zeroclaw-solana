# zeroclaw-solana

Solana-native tool plugins for [ZeroClaw](https://github.com/zeroclaw-labs), built on a
shared, host-testable core. The plugins let an agent read on-chain risk and sign a
bounded, replay-proof attestation, with a safety posture that treats both the arguments
coming in and the on-chain data coming back as untrusted.

## The plugins

| Plugin | Does | Custody |
|---|---|---|
| [`token-risk-check`](plugins/token-risk-check) | Grades an SPL / Token-2022 mint RED / AMBER / GREEN from its extensions and authorities, corroborated by RugCheck | T0 read-only |
| [`lending-health`](plugins/lending-health) | Reports a wallet's Kamino Lend liquidation health (Safe / Warning / Critical / Liquidatable) | T0 read-only |
| [`depin-attest`](plugins/depin-attest) | Signs and broadcasts a replay-proof on-chain attestation of a physical DePIN sensor reading, fronted by a durable nonce | T2 scoped session key |

## Custody ladder

The plugins sit at deliberate points on a custody ladder, so the safety bar rises only where
signing does:

- **T0 (read-only)**: holds no keys, builds no transaction. `token-risk-check` and
  `lending-health`. The only outward actions are HTTPS reads.
- **T2 (scoped session key)**: `depin-attest`. It signs with a session key the operator
  injects through jailed config, holds no user wallet, and can only ever emit one
  transaction shape (advance-nonce plus a sanitized memo). Its replay resistance is enforced
  by consensus through a durable nonce, demonstrated on live devnet in its README.

## Shared safety: sanitize the data coming back

On-chain data is attacker-influenceable. A token name, a market symbol, a memo, or a
RugCheck string can carry control characters, bidi overrides, or zero-width bytes designed to
change how whatever reads it behaves. `solana-core`'s sanitizer runs every such value through
a fixed cleanup and length cap before it enters a string an agent will read, and that coverage
extends past the obvious data fields to the response paths that are easy to miss: JSON-RPC
error messages, HTTP error bodies, and serde parse errors are attacker-influenceable too, so
each is capped and stripped on the way to the agent rather than reaching its context raw. Each
plugin carries a test that feeds it a hostile name or symbol and asserts the sanitized result.
This sits on top of the standard argument-side defenses (base58 validation before any RPC call,
`serde(deny_unknown_fields)`, https-only overrides), not instead of them.

A runnable demonstration lives in `crates/solana-core/examples/injection_demo.rs`
(`cargo run --example injection_demo`): a 40 KB hostile token name carrying a bidi override, a
zero-width space, and injection framing comes out stripped, length-capped, and labeled untrusted
on both the data path and the error path.

## solana-core

The plugins depend by path on `crates/solana-core`, a pure-Rust core with no wasm dependency.
It is host-testable with `cargo test` and compiles clean to `wasm32-wasip2`. It carries the
base58 codec and PDA/ATA derivation (validated differentially against `solana-program`), the
JSON-RPC transport seam and client, SPL / Token-2022 mint decoding, the compact-u16 codec,
instruction builders, legacy and v0 message compile and serialize (byte-validated against
`solana-program` fixtures), durable-nonce decoding, deterministic ed25519 signing (RFC 8032
anchored), and the response-path sanitizer. It ships **71 host tests**.

## Build and test

Each plugin is its own workspace. The core and every plugin build to `wasm32-wasip2` and are
host-tested with mocked RPC and no live network, which is the deterministic merge gate:

```
rustup target add wasm32-wasip2

# core
cd crates/solana-core && cargo test --locked

# each plugin
cd plugins/<name>
cargo test --lib                                   # host tests, no wasm, no network
cargo build --target wasm32-wasip2 --release       # the shipped component
```

`depin-attest` additionally has gated live-devnet integration tests
(`ZEROCLAW_DEVNET_PROOF=1`) that broadcast the real attestation to devnet. They are not part
of the normal test run, which uses mocked RPC only.

## Layout

```
crates/solana-core/     shared, host-testable Solana core
plugins/
  token-risk-check/     T0 mint risk grader
  lending-health/       T0 liquidation-health reader
  depin-attest/         T2 durable-nonce attestation signer
wit/                    the tool-plugin WIT world
```

## License

MIT. See [`LICENSE`](LICENSE).
