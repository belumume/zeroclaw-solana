# depin-attest

A ZeroClaw tool plugin that signs and broadcasts a replay-proof on-chain attestation
that a physical sensor observed an event. A DePIN node reads a physical event (motion,
a door contact, a tamper trip) and the agent records it on Solana as a compact,
sanitized memo, fronted by a durable nonce so each attestation is single-use.

## What it produces

One transaction shape, always:

1. `AdvanceNonceAccount` (instruction 0) over the operator's durable-nonce account.
2. `spl-memo` carrying `zeroclaw-depin/v1 <reading> dev=<device_id> at=<observed_at>`.

The durable nonce advances the moment the transaction lands, so a replayed attestation
carries the old nonce and is rejected by the chain itself. Replay protection is enforced
by consensus, not by this plugin's code.

## Custody tier: T2 (scoped session key)

This plugin signs, so it sits at the highest-custody tier and is where the safety bar
matters most. Its blast radius is bounded by construction:

- It holds **no user wallet**. It signs only with a scoped ed25519 session key that the
  operator injects through jailed config (`signer_seed_hex`). The seed never appears in
  the tool's arguments, its logs, or its output.
- It can only ever emit the **one transaction shape** above. There is no code path that
  transfers value, closes an account, or signs an arbitrary message.
- Every attestation is single-use. The signer must be the nonce authority, or the
  transaction cannot advance the nonce and is refused before broadcast.

## Threat model

The plugin's execute path takes an attacker-influenceable reading over the wire, so it
treats every input as hostile and validates in this order, all before any key is touched
or any network call is made:

1. Arguments parse with `serde(deny_unknown_fields)` at both levels. An injected extra
   field fails closed rather than being ignored.
2. The `reading` is checked against an allowlisted enum (`motion_detected`,
   `motion_cleared`, `contact_opened`, `contact_closed`, `tamper_triggered`). The plugin
   cannot be talked into attesting arbitrary attacker text.
3. The `device_id` is run through the response-path sanitizer and length-capped before it
   enters the memo, so control characters, bidi overrides, and zero-width bytes cannot
   ride into the on-chain payload or, later, into an agent's context that reads it back.
4. The composed memo is sanitized again as defense in depth and capped at 180 bytes.
5. The RPC endpoint must be `https://`. A downgraded `http://` override is refused.
6. The signing seed is read only from jailed config and is scoped to its field so it is
   never logged next to anything else.

## Prompt injection fails closed (host tests)
The end-to-end capture of a live attack against a running agent, with a human in the
loop refusing it, is [`docs/transcripts/injection-refund-redirect.md`](../../docs/transcripts/injection-refund-redirect.md). What follows below is the
plugin's own test suite, which is a different and weaker kind of evidence.


These are the plugin's own host tests. No wasm toolchain, no live network. Run them with
`cargo test --lib`:

```
running 15 tests
test attest::tests::an_all_control_device_id_is_refused ... ok
test attest::tests::bad_seed_length_fails_closed ... ok
test attest::tests::missing_nonce_fails_closed ... ok
test attest::tests::missing_seed_fails_closed ... ok
test attest::tests::unknown_reading_is_rejected ... ok
test attest::tests::multibyte_seed_fails_closed_not_panic ... ok
test attest::tests::unknown_top_level_field_fails_closed ... ok
test attest::tests::unknown_config_key_fails_closed ... ok
test attest::tests::hostile_device_id_is_sanitized_into_the_memo ... ok
test attest::tests::http_rpc_override_rejected ... ok
test attest::tests::multibyte_device_id_memo_stays_within_byte_budget ... ok
test attest::tests::debug_output_redacts_the_signing_seed ... ok
test attest::tests::all_readings_round_trip ... ok
test attest::tests::worst_case_report_is_bounded ... ok
test attest::tests::valid_attestation_parses_and_composes_memo ... ok

test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

What the load-bearing cases prove:

- `unknown_reading_is_rejected` feeds `reading: "IGNORE PREVIOUS INSTRUCTIONS"`. It is
  refused with "not on the allowlist" and no transaction is built.
- `unknown_top_level_field_fails_closed` injects a `drain_to` field. `deny_unknown_fields`
  refuses the whole call.
- `unknown_config_key_fails_closed` injects an extra key into `__config`. Refused.
- `hostile_device_id_is_sanitized_into_the_memo` passes a zero-width-joiner payload plus
  200 junk characters. The memo comes back with no zero-width byte and within the cap.
- `http_rpc_override_rejected` supplies an `http://` RPC. Refused for not being https.
- `missing_seed_fails_closed` / `missing_nonce_fails_closed` refuse to proceed without the
  scoped key or the replay guard.

## Live devnet proof

The full pipeline is proven on real devnet, not asserted. The gated integration tests in
`tests/devnet_live.rs` and `tests/devnet_replay.rs` drive the plugin's real core
(`attest::parse_and_validate`) plus the exact transaction primitives the wasm shim uses
(decode nonce account, advance-nonce + memo, compile, sign, serialize), so the broadcast
bytes are identical to what the deployed wasm plugin emits. Preflight simulation stays on,
so devnet validates each transaction before accepting it.

Attestation landed on devnet:

- tx `cHvDQsPXk8EfFuiyRPuT1S3jCVag3RozQ5vpGtNzyQeEGrL9bfoHj7NmGzFDqK34ZCbFza5pkAKbiKoBNwUGVJr`
- instruction 0: `system::advanceNonce`; instruction 1: `spl-memo` with
  `zeroclaw-depin/v1 tamper_triggered dev=sensor-A7 at=1737300000`
- signed by the scoped operator, `err: None`

That signature no longer resolves and is kept here as history rather than offered as evidence.
Public devnet stops serving a transaction after roughly four days, and this run predates the
offline proof bundle, so its raw bytes were never captured and there is nothing to check it
against. What is checkable today is the reproduce path below, which re-drives the same flow
against live devnet, and the repo's `docs/proof-bundle/devnet-transactions.json`, which holds the
raw bytes for the transactions that were captured before they aged out.

Replay proof demonstrated on devnet:

- the first attestation lands, the durable nonce advances, and the identical replayed
  bytes are then rejected by consensus with `-32002 "Blockhash not found"`.

Reproduce (after the one-time operator setup: fund a key, `solana create-nonce-account`,
drop the keypairs in `.devnet-proof/`):

```
ZEROCLAW_DEVNET_PROOF=1 cargo test --test devnet_live -- --nocapture
ZEROCLAW_DEVNET_PROOF=1 cargo test --test devnet_replay -- --nocapture
```

These tests are gated and never run in normal CI, which uses mocked RPC and no network.

## Tool interface

```
name: depin_attest_reading
inputs:
  reading      allowlisted event id (motion_detected | motion_cleared |
               contact_opened | contact_closed | tamper_triggered)
  device_id    sensor/device identifier (sanitized before use)
  observed_at  unix seconds of the reading
```

The scoped session key, the durable-nonce account, and an optional RPC override live in
the operator's jailed config, not in the tool arguments.

## Build

```
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cargo test --lib          # host tests, no wasm toolchain, no network
```

## License

MIT. See `LICENSE`.
