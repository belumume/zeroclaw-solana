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
GET /reading                       -> 402 + { x402Version: 2, resource: {...},
                                              accepts: [1 reading] }
                                        + header PAYMENT-REQUIRED: <base64 of that body>
GET /reading  (PAYMENT-SIGNATURE: <signed>) -> 200 + { paid, settlement: <sig>, reading: {...} }
                                        + headers PAYMENT-RESPONSE / X-Payment-Response
GET /price                          -> the 402 challenge alone
GET /health                         -> { gate: {build_commit, build_commit_source},
                                          shop: {unit, active, state, trace_age_seconds},
                                          receipts: {log_readable, lines_scanned, records_found,
                                                     delivery: {status, ...}, stale_after_seconds},
                                          ledger: {daily_cap_atomic_units, restored_sales_at_startup,
                                                   unparseable_lines_skipped, redeemed_nonces,
                                                   tracked_payer_days, settled_atomic_units,
                                                   lock_healthy}, proves }
GET /selfcheck                      -> the box self-check verdict verbatim (deployed_sha, ok,
                                          checks, ...) plus age_seconds, served_at, and
                                          gate_build_commit / gate_build_commit_source /
                                          gate_build_proves; 503 when no verdict exists
```

### Which commit is which

Two different commits are published and they answer two different questions.

`deployed_sha`, on `/selfcheck`, comes from the verdict `deploy/box_selfcheck.py` writes on the
box. It names the commit the WORKSPACE deploy was generated from: the config, skills and SOPs
listed in `deploy/deploy-targets.json`.

`build_commit`, on both routes, is baked into this binary at compile time by `build.rs`. It names
the commit THIS PROCESS was compiled from. The binary is deliberately not in that deploy file map,
for the same reason the nine plugins are not, so the two values move independently and a difference
between them is ordinary rather than a fault. Before this field existed, a reader comparing
`deployed_sha` against a repository was checking the deploy while believing they were checking the
gate, and nothing on the box could tell them otherwise.

Read `build_commit_source` before comparing anything:

| source | meaning |
|---|---|
| `git` | read from the repository, with everything this binary compiles committed. A bare 40-character sha |
| `git-dirty` | read from the repository, with an uncommitted change to something this binary compiles. The value carries a `-dirty` suffix, because HEAD does not name the code that was built and an equality check must not quietly pass. Judged over this crate and its path dependency rather than the whole monorepo, so an uncommitted demo script does not label an untouched binary as divergent |
| `env` | `X402_GATE_BUILD_COMMIT` was set at build time and taken verbatim. The route for a build with no repository attached, a tarball or a container over a copied tree. An assertion by whoever built, not an observation |
| `unavailable` | no git, no repository, no override. The commit is the literal string `unknown`, which is neither hex nor 40 characters and so cannot be mistaken for one |

A missing git never fails the build, and the value is never an empty string: `""` reads as
present-and-fine to a consumer and as absent to a human, so the two would disagree about one byte.

The `accepts` array is the x402 price menu. It offers ONE tier, a single reading. A day-pass tier was withdrawn because nothing ever granted it: the flag was recorded and logged, no code path read it, and the nonce burns on the first request, so a buyer paid five times the price for identical service. `verify_x_payment` still ACCEPTS the day-pass amount so a client holding a cached challenge is served rather than refused; it simply buys what the single read buys. Each row's `extra.memo` nonce must be echoed by the payment as a Memo
instruction, binding it to this exact challenge.

### Spec conformance, and the one place we knowingly diverge

The challenge is
[x402 **v2**](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md).
Both wire-name generations are accepted on the request side
(`PAYMENT-SIGNATURE`, and v1's `X-PAYMENT`) so a spec-current client and every existing payer of
this gate both work. Verified by parsing a live challenge with the published reference validator
rather than by reading the spec:

```bash
cd ../scripts/x402-validator && npm ci --silent && node validate-challenge.mjs
```

That replaced a one-liner which fetched `127.0.0.1:4577` and printed a bare `true`. Two
things were wrong with it and both matter more than the brevity it bought. It never
exercised the PUBLIC endpoint, so it could not tell you what a payer receives. And it had
no failing case, so a `true` proved only that the code ran: a validator never shown to
reject anything has not been shown to work. The tracked version pins the grader, ships the
pre-cutover body as a control that MUST be rejected, and reads `resource.url` on its own
because the schema accepts a `localhost` value and therefore cannot tell you that field is
reachable.

The nonce is also still mirrored at the top level as `extra.memo`. That is not a v2 field and a
spec client ignores it; it stays because clients written against this gate read it there, and the
reference schemas declare no `.strict()`, so unknown keys are stripped rather than rejected.

**Divergence, stated rather than papered over:** the upstream
[SVM `exact` scheme](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_svm.md) also
lists `extra.feePayer`, the sponsor that adds the transaction's final signature. This gate has no
sponsor. The client is its own fee payer and signs completely; we hold no key to co-sign with,
which is the same property the custody section below rests on. Naming a `feePayer` we cannot sign
as would be false, and would strand an honest client waiting for a signature that never arrives.

## Custody tier: **T0 / T1, no keys held, cannot move funds**

The gate holds **no private key** beyond a public receiving wallet *address*, and never signs
anything. Its entire job is to **recognise** a payment the client already signed to us:

1. Decode the client's signed transaction (`solana-core::tx_decode`, adversarial-safe).
2. **Verify every signature the message declares, against the message bytes**
   (`solana-core::verify_declared_signatures`). Decoding proves the header is
   self-consistent; it says nothing about whether anyone signed. Every step below reads
   identities out of the signer prefix, so this runs first or they are reading whatever
   the sender chose to write there.
3. Confirm it contains a `TransferChecked` of at least the price, in our mint, to **our**
   associated token account, whose **authority signed** (`solana-core::token::find_payment`).
4. Confirm it carries the nonce as a Memo (`has_memo`). The nonce comes out of the
   payment's own memo, and what binds it is step 2 plus step 5: the memo is inside the
   signed message, so it cannot be varied without the signing key, and the ledger burns it
   once.
5. **Reserve** the single-use nonce and the room under the **in-code per-payer daily cap**,
   before broadcasting. Deciding and taking happen in one critical section, so two requests
   cannot both be told there is room while a settlement sits between the check and the write.
6. Simulate, broadcast, and confirm via Solana RPC.
7. **Confirm the reservation only once settlement succeeded**, and **release** it if the
   broadcast failed. The ledger records money that moved, never money that was attempted;
   only then is the reading served.

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
| Restart the gate to reset the cap | the ledger is rebuilt at startup from the earnings log, so spend and redeemed nonces survive a restart. This one mattered: the unit is `Restart=always`, so before the rebuild a crash loop handed every payer a fresh full allowance and nothing in the output would have shown it. Scope: the rebuild replays what SETTLED, and so does the live ledger, because a payment that fails to broadcast has its reservation released. The two hold the same set, which is what makes the restart a rebuild rather than an approximation. Checkable without shell access: `/health` serves `ledger.restored_sales_at_startup`, so a non-zero value on a node that has sold something is this process having rebuilt the ledger rather than reopened every allowance. Counts and sums only, never payers or nonces, since that endpoint is public |
| Forge a payment "from" someone else, to burn their daily cap | every declared signature is verified against the message bytes before anything else reads the message, so naming a victim in the signer prefix costs an attacker their key rather than 64 arbitrary bytes. Refused `BadSignature`, before any broadcast |
| Exhaust a stranger's cap with payments that never settle | the ledger is written in two phases: a reservation held across settlement, confirmed on success and released on failure. A payment that does not settle consumes no cap, burns no nonce, and adds nothing to the total `/health` publishes |
| Malformed / adversarial `X-PAYMENT` bytes | every decode path is bounds-checked and fails closed (no panics); `tx_decode` rejects truncation, trailing bytes, oversized counts, and v0 address-table lookups |
| Prompt-inject the agent into paying out | **not applicable**: the gate has no key and no spend path; it is receive-only |
| A lying or compromised RPC endpoint | **Not defended. Stated because it is the one trust this gate does not remove.** Every check above reads the CONTENTS of a transaction while trusting that the endpoint describes the chain at all. The gate talks to ONE RPC (`X402_RPC_URL`) to simulate, broadcast and confirm, so an endpoint that fabricates a confirmation gets the reading served and a sale written to the earnings ledger for a payment that never landed. `payment-watch` closes this same shape with an optional `corroborating_rpc_urls` that makes an independent endpoint re-derive the payment from its own copy of the chain; the gate has no equivalent, so choosing the endpoint is the operator's judgement and not something this code can check. What bounds the damage is what the gate can lose: it holds no key, so the worst case is a reading served free and a wrong ledger line, never funds leaving |

There is no LLM in this process and no key to compromise. The earning node cannot be talked
into losing money because it cannot send money.

## Live devnet proof

Run end-to-end against devnet with a real token transfer:
- 402 challenge issued with a single-tier menu and a fresh nonce.
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
X402_READ_RPC_URL    RPC used ONLY to read the feed being sold.
                     Default: X402_RPC_URL
X402_SETTLE_RPC_URL  RPC used ONLY to simulate/broadcast/confirm the buyer's
                     payment -- the endpoint real money moves over.
                     Default: X402_RPC_URL
                     Reading the goods and settling the money are separate
                     concerns and can honestly sit on different clusters: this
                     gate has settled mainnet USDC while serving a devnet
                     reading. Point them apart only deliberately, and match
                     X402_MINT and X402_NETWORK to the SETTLE cluster.
X402_NETWORK         CAIP-2 network id, which x402 v2 requires
                     (default solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 = devnet;
                      mainnet is solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp)
X402_RESOURCE_URL    absolute URL of the resource sold, for the required
                     `resource` object. Defaults to the loopback bind, path
                     /reading on X402_PORT. Set this on a deployment: behind a
                     proxy the gate cannot see its own public origin.
X402_PORT            listen port (default 4577)
X402_PRICE_SINGLE    atomic units for one reading (default 1000000 = 1 USDC)
X402_PRICE_DAYPASS   accepted-for-cached-clients only (default 5000000). Read and honoured by
                     verify_x_payment, but NOT advertised in the menu, because the tier it named
                     was never granted. Setting it changes what an old client may pay, not what
                     any client is offered.
X402_DAILY_CAP       per-payer atomic-unit daily cap (default 20000000)
```

## Build & test

```
cargo test                         # 57 gate tests, 20 lib + 37 bin (verification, cap logic,
                                   #   ledger restart, /health, /selfcheck, build provenance,
                                   #   x402 v2 wire conformance)
                                   # re-derive: cargo test 2>&1 | grep '^test result'
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
