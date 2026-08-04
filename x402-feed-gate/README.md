# x402-feed-gate: the DePIN node that pays for itself

A machine paywall that lets a ZeroClaw DePIN node **sell its own device-signed on-chain
feed, per request** over [x402](https://docs.x402.org). A client (an agent or a human)
asks the node for a reading; the node answers `HTTP 402` with a price menu; the client pays a
stablecoin transfer on Solana; the node verifies the payment *from the transaction bytes*,
settles it, and serves the reading. The node earns money for the data it already publishes.

This is the machine-commerce deepening of the DePIN talking node: use case 1 publishes a
device-signed feed on-chain; this gate turns that feed into a revenue stream an autonomous
buyer can consume with no human in the loop, and no trusted intermediary.

## What it does, concretely

```
GET /reading                       -> 402 + { accepts: [1 reading, day pass], extra.memo: <nonce> }
GET /reading  (X-PAYMENT: <signed>) -> 200 + { paid, settlement: <sig>, reading: {...} }
                                        + header X-Payment-Response: <base64 receipt>
GET /price                          -> the 402 challenge alone
GET /health                         -> { gate, shop: {unit, active, state, trace_age_seconds},
                                          ledger: {daily_cap_atomic_units, restored_sales_at_startup,
                                                   unparseable_lines_skipped, redeemed_nonces,
                                                   tracked_payer_days, settled_atomic_units,
                                                   lock_healthy}, proves }
```

The `accepts` array is the x402 tiered price menu, a single reading and a day-pass, in one round trip. The `extra.memo` nonce must be echoed by the payment, binding it to this
exact challenge.

## Custody tier: **T0 / T1, no keys held, cannot move funds**

The gate holds **no private key** beyond a public receiving wallet *address*, and never signs
anything. Its entire job is to **recognise** a payment the client already signed to us:

1. Decode the client's signed transaction (`solana-core::tx_decode`, adversarial-safe).
2. Confirm it contains a `TransferChecked` of at least the price, in our mint, to **our**
   associated token account (`solana-core::token::find_payment`).
3. Confirm it carries the challenge nonce as a Memo (`has_memo`), replay binding.
4. Enforce a single-use nonce and an **in-code per-payer daily cap** before broadcasting.
5. Simulate, broadcast, and confirm via Solana RPC; only then serve the reading.

Because the client is the fee payer and signs their own transfer, **no facilitator is
required** (contrast the gasless x402 SVM scheme, where a facilitator co-signs). Verification
is pure HTTP plus Solana JSON-RPC.

## Threat model

| Attack | Defence |
|---|---|
| Pay the attacker's account, claim it's ours | `find_payment` checks the destination is our derived ATA for our mint; wrong-destination and wrong-mint both fail closed |
| Underpay | amount must be `>=` the single price AND match a menu tier exactly |
| Replay a valid payment to read repeatedly | the payment's Memo nonce is single-use in the ledger; a replayed signed transaction is refused `NonceReused` |
| Reuse one payment against a different request | the Memo nonce binds the payment to the challenge that issued it |
| Drain via many small buys | per-payer per-day cap enforced in code, independent of the protocol |
| Restart the gate to reset the cap | the ledger is rebuilt at startup from the earnings log, so spend and redeemed nonces survive a restart. This one mattered: the unit is `Restart=always`, so before the rebuild a crash loop handed every payer a fresh full allowance and nothing in the output would have shown it. Honest scope: the rebuild replays what SETTLED, so a payment that passed the cap check and then failed to broadcast is not restored, which is the accurate direction rather than the lenient one. Checkable without shell access: `/health` serves `ledger.restored_sales_at_startup`, so a non-zero value on a node that has sold something is this process having rebuilt the ledger rather than reopened every allowance. Counts and sums only, never payers or nonces, since that endpoint is public |
| Malformed / adversarial `X-PAYMENT` bytes | every decode path is bounds-checked and fails closed (no panics); `tx_decode` rejects truncation, trailing bytes, oversized counts, and v0 address-table lookups |
| Prompt-inject the agent into paying out | **not applicable**: the gate has no key and no spend path; it is receive-only |
| A lying or compromised RPC endpoint | **Not defended. Stated because it is the one trust this gate does not remove.** Every check above reads the CONTENTS of a transaction while trusting that the endpoint describes the chain at all. The gate talks to ONE RPC (`X402_RPC_URL`) to simulate, broadcast and confirm, so an endpoint that fabricates a confirmation gets the reading served and a sale written to the earnings ledger for a payment that never landed. `payment-watch` closes this same shape with an optional `corroborating_rpc_urls` that makes an independent endpoint re-derive the payment from its own copy of the chain; the gate has no equivalent, so choosing the endpoint is the operator's judgement and not something this code can check. What bounds the damage is what the gate can lose: it holds no key, so the worst case is a reading served free and a wrong ledger line, never funds leaving |

There is no LLM in this process and no key to compromise. The earning node cannot be talked
into losing money because it cannot send money.

## Live devnet proof

Run end-to-end against devnet with a real token transfer:
- 402 challenge issued with a two-tier menu and a fresh nonce.
- A reference client (`examples/pay_client.rs`) builds + signs a `TransferChecked` + Memo
  paying the gate.
- The gate verified the bytes, simulated, broadcast, and **confirmed on-chain**, then served
  the feed reading (sequence + value) plus an `X-Payment-Response` receipt.
- Settlement transaction `EkBmoDknDryQpDtD6hnLoCdhhRjAo3Vmn15VmkQi7niqYHnK5XYL8FpxLabDiQ2S2QuTdD3vsTXMSra72LXgApE`
  (slot 479305550, `err: None`); the seller ATA `6L348RziHrFG1TELfCNUTUPQjBLziYn5JatxsQoY4ekD`
  received 1.000000 devnet USDC.
- A replayed payment was refused `NonceReused` (HTTP 402, with a fresh challenge offered).
- Driven 2026-07-27 against the gate running under `systemd --user` on the ARM node, with the
  buyer signing on a separate machine, so this is a remote purchase and not a self-payment.

The asset is Circle's devnet USDC mint `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`, so the
settlement path is exercised against the token a real buyer would hold rather than against a
stand-in. The gate reads the mint from `X402_MINT` and hardcodes nothing, so the same binary
points at mainnet USDC by config.

Whoever runs public devnet sets its retention and has changed it once inside a week (measured
twice in `../docs/DEVNET-PROOF.md`), so the explorer link above is the perishable half of this
proof and not the durable one. The raw bytes are captured in
`../docs/proof-bundle/devnet-transactions.json`, and `python ../scripts/verify_proof_offline.py`
re-verifies the signature and decodes the payment with no network at all. The HTTP half has no
on-chain representation, because a refusal is a response rather than a transaction, so the full
exchange (the 402 challenge, the receipt, the earnings ledger line, and the refused replay) is
recorded in `../docs/proof-bundle/x402-purchase-and-replay.md`.

## Configuration

All via environment (see `src/main.rs` for the full list):

```
X402_SELLER_WALLET   base58 wallet that receives payment (required)
X402_MINT            base58 stablecoin mint (required)
X402_FEED_PDA        base58 feed account to read + serve (required)
X402_RPC_URL         Solana RPC (default https://api.devnet.solana.com)
X402_NETWORK         x402 network string (default solana-devnet)
X402_PORT            listen port (default 4577)
X402_PRICE_SINGLE    atomic units for one reading (default 1000000 = 1 USDC)
X402_PRICE_DAYPASS   atomic units for a day pass (default 5000000)
X402_DAILY_CAP       per-payer atomic-unit daily cap (default 20000000)
```

## Build & test

```
cargo test                         # 21 gate tests (verification, cap logic, ledger restart, /health)
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo build --release --example pay_client
```

The verification, price-menu, nonce, and daily-cap logic all live in `src/lib.rs` as pure
functions with no network dependency, so the whole policy is unit-tested. `src/main.rs` wires
them to `tiny_http` and a real RPC endpoint. The transaction-decode and token-introspection
primitives are byte-validated in `solana-core` against the real `compile`/sign path.

## Where the agent comes in

The gate is host-side infrastructure. The ZeroClaw agent's role is to **announce the node's
earnings** in its channel: the talking node reports what it sold and to whom, via the
evening-reconciliation SOP pattern. The node speaks, and now it also earns.

## Layering (why this is a plugin-adjacent Tier-3 build, not a skill)

Parsing an untrusted signed transaction, deriving ATAs, and enforcing a spend cap in code is
exactly the "bounded code inside the sandbox" the ladder reserves for Tier 3. It reuses
`solana-core` (the same byte-validated primitives the wasm plugins use) as a native `rlib`,
which is what the crate's dual `crate-type` was for. A skill could not safely verify a
payment; this must be code.

MIT licensed. Part of the ZeroClaw Solana suite.
