# oracle-publish

A ZeroClaw tool plugin that turns a physical device's sensor reading into an on-chain,
program-consumable oracle feed. The device itself co-signs the reading, so the feed
carries verifiable provenance: the chain verifies the registered device key's signature
over the value, instead of taking the agent's word for it.

Where `depin-attest` writes a bare memo (an attestation a human reads back), this
publishes into a typed, program-owned `DeviceFeed` PDA that downstream Solana programs
CPI-read like a Pyth or Switchboard feed: freshness-gated, sequence-guarded, and
owner-checked. The repo ships that downstream consumer too, so "consumable" is proven
rather than claimed.

## What it produces

One transaction shape, always, returned as a **base64 partial transaction** (the plugin
broadcasts nothing itself):

1. `AdvanceNonceAccount` (instruction 0) over the agent session key's durable-nonce
   account.
2. `zeroclaw_oracle::publish_reading(value, scale, unit, sequence, observed_at,
   feed_kind)` with the **device as a read-only required signer**. Its ed25519
   signature is already attached at index 1.

The fee-payer signature slot (index 0) is left empty. The host completes it with the
agent's capped session key and broadcasts. The device never pays; the payer never
forges a reading.

## Two independent replay guards

1. **Consensus-level**: the durable nonce advances when the transaction lands, so the
   identical bytes replayed are rejected by the chain itself.
2. **Program-level**: `publish_reading` requires `sequence` to strictly exceed the
   feed's stored sequence, so a stale or re-signed old reading is rejected by the
   program even under a fresh nonce.

Both rejections are demonstrated live on devnet below.

## Custody tier: T1 (fund-less partial signing)

This plugin holds **no wallet and moves no funds**:

- The only key it touches is the **device seed**, a scoped identity key that signs
  readings and nothing else. It arrives through jailed config (`signer_seed_hex`),
  never through tool arguments, and the argument struct deliberately has no `Debug`
  while the validated struct redacts the seed, so it cannot leak into logs or output.
- The output is a **partial transaction**: the fee-payer slot is empty, so the plugin
  output cannot be broadcast by anyone who does not hold the agent's session key.
- The transaction can only ever be the one shape above. There is no code path that
  transfers value, closes an account, or signs arbitrary bytes with the device key.
- The plugin verifies on-chain that the durable nonce's **authority equals the agent
  session key** before compiling, so it cannot be pointed at someone else's nonce
  account to burn their replay guard.

## Threat model

`execute` takes attacker-influenceable arguments, so everything is validated fail-closed
**before any key material is touched or any network call is made**:

1. Arguments parse with `serde(deny_unknown_fields)` at both levels; an injected extra
   field refuses the whole call.
2. `feed_kind` must be on the allowlist (`temperature_c`, `humidity_pct`, `energy_kwh`,
   `pressure_hpa`, `co2_ppm`, `motion_count`, `generic_scaled`); the plugin cannot be
   talked into publishing an arbitrary attacker-defined feed.
3. The reading is **range-gated per kind** (humidity 0-100%, pressure 800-1200 hPa,
   temperature -100 to 200 C, ...), so a prompt-injected value cannot publish an
   absurd magnitude a downstream consumer might act on.
4. `scale` must be in `-9..=0`; `unit` is run through the response-path sanitizer and
   byte-capped to 12 before it enters the on-chain account.
5. The RPC endpoint must be `https://`; a downgraded override is refused.
6. The device seed must be exactly 32 bytes of hex; anything else (including multibyte
   Unicode) fails closed without panicking.

On-chain, the program enforces the other half: only the registered device key may write
to its feed (`Signer` plus key equality), the sequence must strictly increase, the
`feed_kind` must match registration, and the consumer refuses feeds older than its
freshness window.

**Upgrade authority**: the devnet deployment is upgradeable by a single operator key.
That is a development posture, kept during the bounty window for iteration; in
production the authority moves to a multisig or is burned (`solana program
set-upgrade-authority --final`), making the programs immutable. Both programs embed a
machine-readable `security.txt` (neodyme standard) with contact and policy, visible on
explorers.

## Prompt injection fails closed (real transcript)

These are the plugin's own host tests, with no wasm toolchain and no network. Run them
with `cargo test --lib`:

```
running 17 tests
test publish::tests::humidity_over_100_rejected ... ok
test publish::tests::bad_scale_rejected ... ok
test publish::tests::multibyte_seed_fails_closed_not_panic ... ok
test publish::tests::missing_seed_fails_closed ... ok
test publish::tests::out_of_range_value_is_rejected ... ok
test publish::tests::unknown_feed_kind_is_rejected ... ok
test publish::tests::unknown_config_key_fails_closed ... ok
test publish::tests::unknown_top_level_field_fails_closed ... ok
test publish::tests::build_instructions_puts_advance_nonce_first ... ok
test publish::tests::debug_output_redacts_the_device_seed ... ok
test publish::tests::valid_reading_parses_and_derives_everything ... ok
test publish::tests::http_rpc_override_rejected ... ok
test publish::tests::hostile_unit_is_sanitized_and_capped ... ok
test publish::tests::instruction_data_has_discriminator_and_exact_layout ... ok
test publish::tests::negative_temperature_in_range_ok ... ok
test publish::tests::missing_mandatory_pubkeys_fail_closed ... ok
test publish::tests::device_signs_index_one_payer_slot_left_empty ... ok

test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

What the load-bearing cases prove:

- `unknown_feed_kind_is_rejected` / `out_of_range_value_is_rejected` /
  `humidity_over_100_rejected`: injected kinds and absurd magnitudes are refused before
  any transaction exists.
- `unknown_top_level_field_fails_closed` / `unknown_config_key_fails_closed`: a
  smuggled extra field anywhere refuses the whole call.
- `hostile_unit_is_sanitized_and_capped`: zero-width and bidi payloads in `unit` come
  back stripped and within the 12-byte cap.
- `device_signs_index_one_payer_slot_left_empty`: the partial-signing shape is pinned.
  The device signature verifies at index 1; the fee-payer slot stays empty at index 0.
- `debug_output_redacts_the_device_seed`: the seed cannot ride out through Debug
  formatting.
- `instruction_data_has_discriminator_and_exact_layout`: the Anchor instruction bytes
  are known-answer-validated, so the plugin cannot drift from the on-chain program.

## Live devnet proof (end-to-end, judge-clickable)

The full flow ran against **devnet** via the `e2e-localnet` harness, which reuses the
plugin's real `publish::compile_and_device_sign`, so the bytes proven on-chain are
exactly the bytes the wasm plugin emits. A successful submit is also byte-validation:
the partial transaction bincode-deserializes as a real `solana_sdk::Transaction`,
accepts the host's fee-payer signature, and is accepted by consensus.

Programs (Anchor IDLs published on-chain, so the explorer decodes every instruction;
both embed `security.txt`):

- oracle `EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn`
  https://explorer.solana.com/address/EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn?cluster=devnet
- consumer `B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt`
  https://explorer.solana.com/address/B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt?cluster=devnet

The demo run (feed PDA `CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU`):

1. `register_device` bound the device key to its feed PDA.
2. `publish_reading` seq=7 (21.37 C), device-signed, host-completed, **landed**:
   tx `31cev4tXLWcr21Xz4Zfu9ADTGZPUWyLqtMV3wBewF3cX4aVKCPK41N1WLhGeyU52uPahRXvFZEUVntaTiTrdd3nB`
3. The same seq=7 re-published under a fresh nonce was **rejected by the program**
   with `custom program error 0x1771` (`StaleSequence`), and the feed was unchanged.
4. seq=8 landed (the guard is strictly `>`):
   tx `1rVKsoo1gg6fyxKuVmqsv1bn1VqtXT3nQrtb3vUTg3jVYXTbGhtGMq9p3wCTmqdyaZLEp8iQKxS2ikx4aNB4bFR`
5. The consumer program read the typed feed, checked freshness, and acted:
   tx `3XYa1HYNEZUTuNwjqH6mMyRpw7pqhs7GykPRmmbjVz7K48F8XxCt8egmPrLAmeJMnB97hbg4KmvPFST6M9uaE5yx`

Reproduce against a local validator (or devnet with `E2E_RPC`/`E2E_FUNDER`):

```
cd e2e-localnet && cargo run --bin e2e
```

## Tool interface

```
name: oracle_publish_reading
inputs:
  feed_kind    allowlisted feed id (temperature_c | humidity_pct | energy_kwh |
               pressure_hpa | co2_ppm | motion_count | generic_scaled)
  value        fixed-point mantissa; real value = value * 10^scale
  scale        fixed-point exponent, -9..=0
  unit         short unit label (sanitized, <=12 bytes)
  observed_at  unix seconds of the reading
  sequence     strictly-increasing per-feed sequence
```

The device seed, the durable-nonce account, the oracle program id, and the agent
session pubkey live in the operator's jailed config, not in the tool arguments.

## Config keys (jailed `config_read` section)

```
signer_seed_hex       32-byte hex seed of the DEVICE identity key (signs readings only)
nonce_account         base58 address of the durable-nonce account (replay guard)
oracle_program_id     base58 address of the deployed zeroclaw_oracle program
agent_session_pubkey  base58 pubkey of the agent's capped session key (fee payer;
                      must be the nonce authority)
rpc_url               optional https-only Solana RPC override (defaults to devnet)
```

## Build

```
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cargo test --lib          # host tests, no wasm toolchain, no network
```

The on-chain programs live in `onchain/` (an isolated Anchor 0.31 workspace); build
with `anchor build` and a pinned `Cargo.lock` (committed, `--locked`-reproducible).

## License

MIT. See `LICENSE`.
