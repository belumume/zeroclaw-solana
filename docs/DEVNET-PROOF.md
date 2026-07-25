# Live devnet proof (clickable on-chain evidence)

Every claim below is a public Solana **devnet** transaction or account. Click any link; no
account of ours needs to be trusted, and nothing here is a secret (operator keypairs stay
local). Set the explorer cluster to **devnet**.

## On-chain programs (DePIN oracle)
| Program | Address | Explorer |
|---|---|---|
| `zeroclaw_oracle` | `EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn` | https://explorer.solana.com/address/EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn?cluster=devnet |
| `consumer_example` | `B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt` | https://explorer.solana.com/address/B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt?cluster=devnet |
| Device feed PDA (agent-driven, historical) | `CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU` | https://explorer.solana.com/address/CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU?cluster=devnet |
| Device feed PDA (deterministic, LLM-free, live) | `3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K` | https://explorer.solana.com/address/3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K?cluster=devnet |

Both programs carry an on-chain **Anchor IDL** (so the explorer decodes the instructions, not
"Unknown") and an embedded **security.txt**:
- oracle IDL account `DRaviitdm5rojHS7YGTQxG8Ho26g8PdAdqodWoLaaKtJ`
- consumer IDL account `GHrkqYsBWp55eJCZg3vgYzGvoQELDUfu2kRQqpBn7tr8`

## The DePIN feed has been publishing on a schedule (the "yours, running" proof)
Each is a device-signed `publish_reading` landing a new monotonic sequence on the feed PDA.
The feed account stores only the LATEST reading, so the *sequence history* is the ledger:

| UTC | seq | value | Settlement tx |
|---|---|---|---|
| 2026-07-23T02:42Z | 10 | 29.0C | [2pgdXYAS…](https://explorer.solana.com/tx/2pgdXYASpLxcSKuBBzxWnHRWKVZiJbdzpu4SCrjeznL1ptJc1iNcT8ste79Goti14MadKZHvo1rsNMVemmAbEBH?cluster=devnet) |
| 2026-07-23T06:28Z | 11 | 36.2C | [29iMd5HU…](https://explorer.solana.com/tx/29iMd5HUCDqizFNsSiAXKRquoZoTwGyHvoyh5iamAJZqPh6oWKfyUvZFbNxXk4cYJsnPnrjBRYfrdsjSnACrWh6D?cluster=devnet) |
| 2026-07-23T06:30Z | 12 | 36.8C | [24iLczeW…](https://explorer.solana.com/tx/24iLczeWeaiN6LEpfgjZd4wLdneJ8Ym4UjJHHbop3f6YFzD3SaF6fJ1vg32nmnpD2tWs6Mk5DvJnBBn5945rD1XH?cluster=devnet) |
| 2026-07-23T08:44Z | 13 | 41.1C | [2j9emSvs…](https://explorer.solana.com/tx/2j9emSvsWHKyTEGVT3iLik9XGxpQkLLqAhLLQqjgkVEQx2QPHJQnxqzKLMqxCtCjnsdne276aFH4z76Z3CdJah5E?cluster=devnet) |
| 2026-07-23T14:44Z | 14 | 39.4C | [5qTeyv2u…](https://explorer.solana.com/tx/5qTeyv2uFpvTPgxGj9WNoSsMhEq2HSPpPo3ydjoT1adrM93fAZo23zNJisRyoC1x4e52h3PjjkBPpFzQmF8WSNeY?cluster=devnet) |
| 2026-07-23T20:32Z | 15 | 31.3C | [4F3Ywdhu…](https://explorer.solana.com/tx/4F3YwdhuDF2Zj1Lh5aX7LUWekLbEV7rQiBmN23kUcC9k3K4cYifrePnN7AcQ9oY7LvQ9ZgmvuuL8CJYX912UjNd6?cluster=devnet) |
| 2026-07-24T05:54Z | 16 | 33.0C | [5en2Zott…](https://explorer.solana.com/tx/5en2ZottTbPEgcpywBp4qxxPtEgcT75Eh3Ej79L1cL7P3CcbWKXqtQJ5GtDw9QPwmWyH8pc1E4yBzC2a9FV5XjKR?cluster=devnet) |
| 2026-07-24T05:56Z | 17 | 33.0C | [agHTsrz1…](https://explorer.solana.com/tx/agHTsrz1Z6XhFjKN2g9DxFjJP363He2rHByvDN7r6KUDurzxxxcdj4LcfTA6AQpNsFk4cYqjk9k4kHfwgxWRFQd?cluster=devnet) |

(The device signs each reading inside the wasm sandbox; the host completes the fee-payer slot
and broadcasts. Replay of a signed publish is refused on-chain by the strictly-increasing
sequence guard, error `0x1771 = StaleSequence`.)

## The x402 earning-node settled a real paid read (machine commerce)
The node sold one reading over x402: a 402 challenge, a client-signed stablecoin payment, and
on-chain settlement before the reading was served.

- Settlement tx `5ss8wKQo5rqXeLTdQGoWjz6jLNgycT9vCKzj7iZs4viXsexeN573gy9oZ6fgNGrBjfahQ9Zcc84fz9nF4F6Gpudc`
  (slot 478350917, `err: None`):
  https://explorer.solana.com/tx/5ss8wKQo5rqXeLTdQGoWjz6jLNgycT9vCKzj7iZs4viXsexeN573gy9oZ6fgNGrBjfahQ9Zcc84fz9nF4F6Gpudc?cluster=devnet
- A replayed payment was refused `NonceReused` (the payment's memo nonce is single-use).
- Public parties: buyer `EDPAQadqVyf3MVgwuqxtDfxg6Fq1f3mECfUumYZJjhwS`, seller receiving wallet
  `C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ`, demo mint
  `6Anrqvy3BvG2QvK9k6sGvRYndFwiSudw2JMnDMhbdAK` (a purpose-created 6-decimal devnet mint so the
  full settlement path runs without needing a specific USDC balance; the code is mint-agnostic).

## The shop terminal took a real payment (Track A, reference-threaded)
The full shop flow ran end to end on devnet with the real plugin logic (no reimplementation): a
Solana Pay request with a fresh reference, an UNSIGNED transfer the agent builds (T1, it never
holds a broadcast-ready transaction), the host signs and broadcasts, and payment_watch detects
settlement by matching the reference. A second check with a different reference correctly returns
NOT_YET, so a payment is confirmed only from the on-chain match, never the customer's say-so.

- Transfer tx `4kDo6NCcAxSe3BSTtQ4onTASenxRWr2miagweVway3RnDMLG7drv6NkTdV7eRtTSDcNXURy2ESpKcqkk2jG9sYqS`
  (payment_watch verdict PAID, reference matched, memo invoice-e2e-1):
  https://explorer.solana.com/tx/4kDo6NCcAxSe3BSTtQ4onTASenxRWr2miagweVway3RnDMLG7drv6NkTdV7eRtTSDcNXURy2ESpKcqkk2jG9sYqS?cluster=devnet
- Reference key (threaded through all three steps) `6xZC4vUpTheLKK5dv14ktbJusTN9RUeeYCaJyeZq4A11`:
  https://explorer.solana.com/address/6xZC4vUpTheLKK5dv14ktbJusTN9RUeeYCaJyeZq4A11?cluster=devnet
- Reproduce: `E2E_RPC=https://api.devnet.solana.com E2E_FUNDER=<operator.json> cargo run --release`
  in `e2e-track-a/` reruns the whole flow against live devnet.

## The on-chain allowance cap rejects an over-cap agent spend (custody)
The audited Solana Foundation Allowances program (`De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44`)
bounds a COMPLYING agent, not just a refusing model. On devnet the agent's session key (the
delegatee `GAMDhBVB1LgQpcQpTUMEuS8Jg1czQAeaPHfCN8CDz7Qq`) was given a fixed delegation capped at 5 tokens, then it SIGNED two transfers.
The program, not the plugin and not the LLM, enforced the cap: the within-cap transfer settled and
the over-cap transfer was rejected on-chain.

- Fixed delegation created, cap 5 tokens, delegation PDA `4bJBr62YFrnQLxVW9m4Qv5GuUv9hv8LzbiGebyBhnEfu`:
  https://explorer.solana.com/tx/3eeM43DgvcJqrkUAk1xtwbVygkd4YDbCgmqmVyvoM6QoiRREB2TAq1yDzJKmxoLJedwbrsSgT6fpTqB8h3HYmMXW?cluster=devnet
- WITHIN cap (5 tokens) SUCCEEDED:
  https://explorer.solana.com/tx/5qyr7jJi8zb6SjZjnA2QT5C9nuZYgSw6raAefjmWnDDMf3JRgkQX19zssE57EpFSHVCCPfbj5qyxcYSQcfEq9W3Z?cluster=devnet
- OVER cap (10 tokens) REJECTED by the SF Allowances program, landed as a failed tx with
  `custom program error 0x12c` (InstructionError Custom 300):
  https://explorer.solana.com/tx/3TLSrfWVYdC3hSiAWnyyd7T694bLJQDtdJYQ64EWUsBNDehGc6Kq1veR7xa8Y1BiMdpvfFm3N1dKjDrXF3BEq2ps?cluster=devnet
- Reproduce: `cd e2e-allowance && npm install && E2E_FUNDER=<operator.json> node demo.js` (devnet)
  reruns the whole create-delegation then within-cap-then-over-cap flow.

## How to re-verify
Two ways, no account of ours needed:
- **One command, no install:** `python3 scripts/verify-proof.py` (stdlib only) queries devnet and
  prints PASS/FAIL for every claim above (programs executable, feed PDA owner, and each tx's exact
  success or rejection), exiting non-zero if any fails. A clean run prints `8/8 claims verified`.
- **By hand:** open any link above with the explorer cluster set to devnet. The programs are
  executable (owner `BPFLoaderUpgradeable`), the feed PDA decodes via the on-chain IDL, and the
  settlement tx shows the TransferChecked to the seller's associated token account.
