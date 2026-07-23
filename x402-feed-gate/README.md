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
GET /health                         -> {"ok":true}
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
| Malformed / adversarial `X-PAYMENT` bytes | every decode path is bounds-checked and fails closed (no panics); `tx_decode` rejects truncation, trailing bytes, oversized counts, and v0 address-table lookups |
| Prompt-inject the agent into paying out | **not applicable**: the gate has no key and no spend path; it is receive-only |

There is no LLM in this process and no key to compromise. The earning node cannot be talked
into losing money because it cannot send money.

## Live devnet proof

Run end-to-end against devnet with a real token transfer:
- 402 challenge issued with a two-tier menu and a fresh nonce.
- A reference client (`examples/pay_client.rs`) builds + signs a `TransferChecked` + Memo
  paying the gate.
- The gate verified the bytes, simulated, broadcast, and **confirmed on-chain**, then served
  the feed reading (sequence + value) plus an `X-Payment-Response` receipt.
- Settlement transaction `5ss8wKQo5rqXeLTdQGoWjz6jLNgycT9vCKzj7iZs4viXsexeN573gy9oZ6fgNGrBjfahQ9Zcc84fz9nF4F6Gpudc`
  (slot 478350917, `err: None`); the seller ATA received the tokens.
- A replayed payment was refused `NonceReused`.

(The demo used a purpose-created 6-decimal devnet mint so the whole settlement path is
exercised without depending on acquiring a specific USDC balance; the code is
mint-agnostic; point it at devnet/mainnet USDC by config.)

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
cargo test                         # 10 gate tests (pure verification + cap logic)
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
