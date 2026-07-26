# Live devnet proof (clickable on-chain evidence)

Every claim below is a public Solana **devnet** transaction or account. Click any link; no
account of ours needs to be trusted, and nothing here is a secret (operator keypairs stay
local). Set the explorer cluster to **devnet**.

## On-chain programs (DePIN oracle)
| Program | Address | Explorer |
|---|---|---|
| `zeroclaw_oracle` | `EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn` | https://explorer.solana.com/address/EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn?cluster=devnet |
| `consumer_example` | `B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt` | https://explorer.solana.com/address/B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt?cluster=devnet |
| Device feed PDA (**ARM node, node-born key, 24/7**) | `JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg` | https://explorer.solana.com/address/JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg?cluster=devnet |
| Device feed PDA (deterministic, LLM-free, laptop-hosted) | `3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K` | https://explorer.solana.com/address/3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K?cluster=devnet |
| Device feed PDA (agent-driven, historical) | `CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU` | https://explorer.solana.com/address/CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU?cluster=devnet |

The first of those three is the one that matters for "yours, running." Its device keypair was
generated **on the ARM node itself** with `openssl rand -hex 32` and has never left that box,
so this workstation cannot produce a signature for that feed. A `systemd --user` timer with
lingering enabled publishes on a schedule with no laptop in the loop.

That was a deliberate reversal, and it is worth stating because the easier path was
available. The first plan was to copy this workstation's existing device seed to the node so
the new feed would inherit the old one's sequence history. That would have made "the device
signs its own readings" architecturally true and literally false, and anyone reading the
deploy path could see the seed had travelled. The arithmetic also did not support the excuse:
at one reading every twenty minutes a fresh feed accrues roughly 936 readings by the
submission date. So the node generated its own seed instead, the transported copy was
shredded unused, and that copy was never the key behind this feed. The second feed is the deterministic publisher hosted on this
laptop, which predates the node and is therefore only as continuous as the laptop is awake;
`scripts/verify-proof.py` reports its actual state rather than this page asserting one, and
distinguishes a machine that was away from a publisher that ran and failed; the third is the original agent-driven proof, kept because its sequence
history is the earliest evidence and deliberately marked historical rather than quietly
dropped.

Both programs carry an on-chain **Anchor IDL** (so the explorer decodes the instructions, not
"Unknown") and an embedded **security.txt**:
- oracle IDL account `DRaviitdm5rojHS7YGTQxG8Ho26g8PdAdqodWoLaaKtJ`
- consumer IDL account `GHrkqYsBWp55eJCZg3vgYzGvoQELDUfu2kRQqpBn7tr8`

## The DePIN feed is publishing on a schedule (the "yours, running" proof)

These are consecutive device-signed `publish_reading` transactions on the **ARM node-born
feed** `JEtuZk…` — the feed whose key was generated on the node and has never left it. The
feed account stores only the LATEST reading, so the *sequence history* is the ledger.

| UTC | Interval | Result | Settlement tx |
|---|---|---|---|
| 2026-07-25T14:06Z | — | ok | [3MhyEGJo…](https://explorer.solana.com/tx/3MhyEGJo4AgCMoRtsM5nGspF5wXnDVQjRyzzmffKvztHg2Adu5fLnfpF4cP9ZmQumkWnA4xxxFGEnPZTATXZY3KD?cluster=devnet) |
| 2026-07-25T14:26Z | 20.5 min | ok | [5UEd5BnQ…](https://explorer.solana.com/tx/5UEd5BnQUxb42LWJYmEgdvJb2Sk6dJeuJAx7HVcFiS9T2sSEZzJczyzTSKvPtWvVYTi5u6WAqVUKLgJbMRqJzYtk?cluster=devnet) |
| 2026-07-25T14:47Z | 20.5 min | ok | [2RMiDsP6…](https://explorer.solana.com/tx/2RMiDsP6thht2eYQivBEudydjmrATYmfScrrjNLink7nCA3W7uULzknF2iFL37ZZNmZZCGn6fzihdLb2FayA8bV1?cluster=devnet) |
| 2026-07-25T15:07Z | 20.5 min | ok | [3vnbatzq…](https://explorer.solana.com/tx/3vnbatzqHuUDEiovrS97RBGDjbV9J9mjqbwCiiqGRzJgUANGUhyAZKqPsN4GSBMT3vzJmTfLUXUpkR7eQ9Tqa2JY?cluster=devnet) |
| 2026-07-25T15:28Z | 20.5 min | ok | [4F8w5Hby…](https://explorer.solana.com/tx/4F8w5HbyaYA6Rd9b9sUW4FhGMpDgyDZi6cf768UUESfQA3AavhDdMPFqUqDLBAtePiKohkaoRqcQAiKYrQABUugh?cluster=devnet) |
| 2026-07-25T15:48Z | 20.5 min | ok | [5kBkui9R…](https://explorer.solana.com/tx/5kBkui9Rwmwm5hJhHo3g1pFJtott3Ci21T3HxAYjNS596grchtndWLWBNT5hV5FqNkKQTyEPwthhdrLyuxJd14kw?cluster=devnet) |

The interval column is the point. Every gap is 20.5 minutes to the tenth of a minute, which is
a timer running unattended on a box in Jeddah, not a person remembering to publish.

Do not take the head of the feed from this file, because any sequence number written here is
stale within twenty minutes of being written. Read it live:

```
python3 scripts/verify-proof.py
```

It prints the current reading, sequence and age, and exits non-zero if the feed has gone quiet.

Two honesty notes about this table, because both were wrong here until an audit caught them:

- These rows deliberately come from `JEtuZk…`, **not** from `CfWaZA…`. An earlier version of
  this section proved "yours, running" using the agent-driven feed, which the table above marks
  historical and which has not published in over a day. A document cannot cite a dead feed as
  evidence of a live one.
- The cadence is 20 minutes. Earlier rows here showed gaps of two to nine hours, which was the
  irregular hand-run era before the timer existed, presented under a heading that claimed a
  schedule.

(The device signs each reading inside the wasm sandbox; the host completes the fee-payer slot
and broadcasts. Replay of a signed publish is refused on-chain by the strictly-increasing
sequence guard, error `0x1771 = StaleSequence`.)

### Historical: the agent-driven feed `CfWaZA…`
Kept because it is the earliest evidence the oracle path worked end to end, and dropping it
quietly would be worse than labelling it. It is **not** the "yours, running" proof and is no
longer publishing.

| UTC | seq | value | Settlement tx |
|---|---|---|---|
| 2026-07-23T02:42Z | 10 | 29.0C | [2pgdXYAS…](https://explorer.solana.com/tx/2pgdXYASpLxcSKuBBzxWnHRWKVZiJbdzpu4SCrjeznL1ptJc1iNcT8ste79Goti14MadKZHvo1rsNMVemmAbEBH?cluster=devnet) |
| 2026-07-23T08:44Z | 13 | 41.1C | [2j9emSvs…](https://explorer.solana.com/tx/2j9emSvsWHKyTEGVT3iLik9XGxpQkLLqAhLLQqjgkVEQx2QPHJQnxqzKLMqxCtCjnsdne276aFH4z76Z3CdJah5E?cluster=devnet) |
| 2026-07-24T05:56Z | 17 | 33.0C | [agHTsrz1…](https://explorer.solana.com/tx/agHTsrz1Z6XhFjKN2g9DxFjJP363He2rHByvDN7r6KUDurzxxxcdj4LcfTA6AQpNsFk4cYqjk9k4kHfwgxWRFQd?cluster=devnet) |

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
settlement. That last step is a conjunction, not a lookup: the reference must appear, AND the
amount must match exactly, AND the mint must match, AND the destination must be ours. A payment
that satisfies three of the four is not PAID. A second check with a different reference correctly
returns NOT_YET, so a payment is confirmed only from the on-chain match, never the customer's
say-so.

- Transfer tx `4kDo6NCcAxSe3BSTtQ4onTASenxRWr2miagweVway3RnDMLG7drv6NkTdV7eRtTSDcNXURy2ESpKcqkk2jG9sYqS`
  (payment_watch verdict PAID on all four of reference, amount, mint and destination; memo invoice-e2e-1):
  https://explorer.solana.com/tx/4kDo6NCcAxSe3BSTtQ4onTASenxRWr2miagweVway3RnDMLG7drv6NkTdV7eRtTSDcNXURy2ESpKcqkk2jG9sYqS?cluster=devnet
- Reference key (threaded through all three steps) `6xZC4vUpTheLKK5dv14ktbJusTN9RUeeYCaJyeZq4A11`.

  **Opening this in the explorer shows "account not found", and that is the correct result.**
  A Solana Pay reference is a fresh keypair used only as a read-only marker in the account
  list; it is never funded, so it never becomes an account. Anyone checking it with
  `getAccountInfo` gets null, which looks like a broken link and is actually the mechanism
  working.

  What resolves it is the signature index, which is also exactly what `payment-watch` polls:

  ```
  curl -s https://api.devnet.solana.com -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress",
         "params":["6xZC4vUpTheLKK5dv14ktbJusTN9RUeeYCaJyeZq4A11",{"limit":10}]}'
  ```

  That returns exactly one transaction, `4kDo6NCc...` above, which is the point: a reference
  generated for one order appears in one settlement and nowhere else, so matching on it ties
  a specific payment to a specific invoice without the merchant address having to be unique
  per order.
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
  success or rejection), exiting non-zero if any fails. A clean run prints `10/10 static claims`
and `1/1 live claims`, split deliberately: the static ten are deployed program state and
immutable devnet history, so they stay green whether or not anything of ours is switched on.
Only the live one answers "is the node publishing right now". Prove that gate works rather
than trusting it: `MAX_FEED_AGE_MIN=0 python3 scripts/verify-proof.py` turns the live check red
and exits 1 while all ten static claims stay green.
- **By hand:** open any link above with the explorer cluster set to devnet. The programs are
  executable (owner `BPFLoaderUpgradeable`), the feed PDA decodes via the on-chain IDL, and the
  settlement tx shows the TransferChecked to the seller's associated token account.
