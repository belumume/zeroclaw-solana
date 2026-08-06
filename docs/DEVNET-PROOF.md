# Live devnet proof (clickable on-chain evidence)

Every claim below is a public Solana **devnet** transaction or account. Nothing here is a secret;
operator keypairs stay local. Set the explorer cluster to **devnet**.

## Read this before clicking: the links are a convenience, the bundle is the proof

Public devnet retention is not a window you can plan against, and this file has now measured it
twice and got two different answers. On 2026-07-27 the oldest signature here still being served
had a block time of 2026-07-23 22:59, and everything older returned nothing, including via
`getSignatureStatuses` with `searchTransactionHistory`. On 2026-08-01 all **sixteen** signatures
in the bundle were served again, including four the earlier pass had been unable to reach and
had recorded as pruned, and the oldest of the sixteen had landed **11.4 days** earlier.

Both measurements were taken the same way, against `api.devnet.solana.com`, and the second one
was gated on controls: three well-formed signatures that were never broadcast returned nothing on
the same run, so the endpoint was answering rather than agreeing with everything it was asked.

Read that as the endpoint currently serving more history than it did, not as a durability
guarantee. Whoever runs it sets the policy, they have changed it once inside a week, and they can
change it back without telling anyone. That is why nothing here depends on a link.

**The evidence lives in this repo instead.** `docs/proof-bundle/devnet-transactions.json` carries,
for every transaction still retrievable at capture time, the raw base64 bytes, slot, block time,
sha256 digest and length. Verify all of it with no network at all:

```
python3 scripts/verify_proof_offline.py --verbose
```

It recomputes each digest, splits the signatures from the serialized message, verifies every
ed25519 signature against the message and the matching account key, and decodes every instruction so
you see what each transaction did rather than trusting a caption. Standard library only, so a fresh
clone runs it with no install step.

A signature that verifies against a public key proves the holder of that private key signed exactly
those bytes. That holds whether or not any RPC still answers, which is a stronger claim than a link.

The instruction names are derived, not asserted. An Anchor instruction is identified by recomputing
`sha256("global:<name>")[:8]` and matching it against the discriminator present in the bytes, so
`publish_reading` below is a decode result. Anything the decoder cannot name from the bytes prints
as unrecognized rather than receiving a plausible label.

**Current result: every captured transaction verifies, controls pass, exit 0.** The script prints
the count it verified rather than this page asserting one; run it and read the number off the run.
As of 2026-08-05 it reports **28 devnet** (plus 3 mainnet in the second bundle). **This paragraph
said 16 until then, and 16 was the count before the bundle grew on 2026-08-01.** That is the worst
possible sentence in this document to be stale, because it is the one whose whole move is "do not
believe me, run the command", and a reader who took the invitation got 28 against a stated 16 on
their first try. The count is now dated rather than asserted flat, and the honest instruction is to
re-derive it: `python scripts/verify_proof_offline.py`. The bundle previously held 12, with four
signatures recorded as `ALREADY_PRUNED` because the
endpoint would not serve them when the bundle was built. On 2026-08-01 it served all four, so they
were captured and now verify like the rest. Nothing was overwritten to do it: the capture refuses
to replace bytes it already holds, which is what keeps a later retry from turning real evidence
into a pruned marker.

The script gates itself on negative controls and refuses to report anything unless each behaves: a
flipped message byte, a flipped signature byte and a flipped transaction byte must each be rejected,
and every control asserts it actually perturbed what it claims to perturb. A checker that has never
failed on bad input has not been shown to work, and a control that silently perturbs nothing passes
for the wrong reason.

That the controls can fail is itself checkable, because a self-test nobody has broken is another
untested claim:

```
bash scripts/mutation-check-offline-proof.sh
```

It plants three defects in a copy of the verifier and requires each to be refused by the control
that names it. Writing it found a real gap: the digest control tested the hash function directly
while the per-transaction loop compared separately, so a broken comparison there was uncovered until
both were routed through one shared function.

A link below that returns nothing is therefore expected, not a broken claim. Check it offline.

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

## A second program read the live feed on chain (the feed is consumable, not a memo)

A feed only earns the word oracle if some *other* program can read it, check its provenance and
its freshness, and act. `consumer_example` does that, and this is the transaction where it did
it against the feed the rest of this page is about.

`4CRapo3AEFBFLh7Y7byJR9XDYZEa95MEioUQMzUhJVxTB9HaDTRtX2X47pVgxaSu8KNfYsPyugeQ6FjN8hBzi54L`
at slot 481442353, 2026-08-05T18:09:00Z, `err: None`, 5,000 lamports, 1,809 compute units.

The call was `act_on_feed(threshold=4000, max_age_secs=1800)` against
`JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg`, and the program emitted `ActionTaken` with
`value=4130 scale=-2 threshold=4000 crossed=true`, carrying the publishing device
`6RfiDnqZRZeDj9qiNJjoVbMQxtbLkfzHLgayTCDLDKKu`. In the units the feed declares that is 41.30 °C
read against a 40.00 °C threshold, so the consumer crossed and acted, on a reading 1,045 seconds
old inside a 30-minute freshness window.

Three things in that sentence are enforced by the chain rather than asserted here. The feed
argument is typed `Account<DeviceFeed>`, so a look-alike account owned by anything other than
`EFCRmE5w…` is rejected before the body runs. The value the consumer acted on was signed by the
device key, which was generated on the ARM node and has never left it. And the freshness gate is
load-bearing rather than decorative, which is checkable in one command and costs nothing:

```
python scripts/consume_feed_once.py --threshold 4000 --max-age 0     # refuses
python scripts/consume_feed_once.py --threshold 4000 --max-age 1800  # accepts
```

The first simulates to `Custom: 6000`, `StaleFeed`, `0x1770`. The second simulates clean. Both
are simulations, so neither costs anything or needs a funded key; `--send` is what broadcasts.
A gate that has only ever been observed passing has not been shown to work, which is why the
refusing direction is the one written down first.

**Honest scope.** Before this transaction the deployed consumer had read the *historical*
`CfWaZA…` feed once, on 2026-07-21, four days before the ARM feed existed. So the consumability
argument was sound and had never been exercised against the feed it was being made about. It has
now, and the bytes are in `docs/proof-bundle/devnet-transactions.json` rather than behind an
explorer link that devnet retention deletes before anyone reads this.

## The DePIN feed is publishing on a schedule (the "yours, running" proof)

These are consecutive device-signed `publish_reading` transactions on the **ARM node-born
feed** `JEtuZk…`, the feed whose key was generated on the node and has never left it. The
feed account stores only the LATEST reading, so the *sequence history* is the ledger.

| UTC | Interval | Result | Settlement tx |
|---|---|---|---|
| 2026-07-25T14:06Z | n/a | ok | [3MhyEGJo…](https://explorer.solana.com/tx/3MhyEGJo4AgCMoRtsM5nGspF5wXnDVQjRyzzmffKvztHg2Adu5fLnfpF4cP9ZmQumkWnA4xxxFGEnPZTATXZY3KD?cluster=devnet) |
| 2026-07-25T14:26Z | 20.5 min | ok | [5UEd5BnQ…](https://explorer.solana.com/tx/5UEd5BnQUxb42LWJYmEgdvJb2Sk6dJeuJAx7HVcFiS9T2sSEZzJczyzTSKvPtWvVYTi5u6WAqVUKLgJbMRqJzYtk?cluster=devnet) |
| 2026-07-25T14:47Z | 20.5 min | ok | [2RMiDsP6…](https://explorer.solana.com/tx/2RMiDsP6thht2eYQivBEudydjmrATYmfScrrjNLink7nCA3W7uULzknF2iFL37ZZNmZZCGn6fzihdLb2FayA8bV1?cluster=devnet) |
| 2026-07-25T15:07Z | 20.5 min | ok | [3vnbatzq…](https://explorer.solana.com/tx/3vnbatzqHuUDEiovrS97RBGDjbV9J9mjqbwCiiqGRzJgUANGUhyAZKqPsN4GSBMT3vzJmTfLUXUpkR7eQ9Tqa2JY?cluster=devnet) |
| 2026-07-25T15:28Z | 20.5 min | ok | [4F8w5Hby…](https://explorer.solana.com/tx/4F8w5HbyaYA6Rd9b9sUW4FhGMpDgyDZi6cf768UUESfQA3AavhDdMPFqUqDLBAtePiKohkaoRqcQAiKYrQABUugh?cluster=devnet) |
| 2026-07-25T15:48Z | 20.5 min | ok | [5kBkui9R…](https://explorer.solana.com/tx/5kBkui9Rwmwm5hJhHo3g1pFJtott3Ci21T3HxAYjNS596grchtndWLWBNT5hV5FqNkKQTyEPwthhdrLyuxJd14kw?cluster=devnet) |

The interval column is the point. Every gap is 20.5 minutes to the tenth of a minute, which is
a timer running unattended on a box in Jeddah, not a person remembering to publish.

**All six rows are captured, so the cadence outlives the links.** Decoded from the raw bytes with
no network, the sequence numbers are consecutive and the readings are real, which is the same
evidence the table above asserts:

```
        ix1  zeroclaw_oracle: publish_reading seq=30 value=41.70C observed_at=1784988366 feed_kind=0
        ix1  zeroclaw_oracle: publish_reading seq=31 value=41.70C observed_at=1784989596 feed_kind=0
        ix1  zeroclaw_oracle: publish_reading seq=32 value=41.50C observed_at=1784990826 feed_kind=0
        ix1  zeroclaw_oracle: publish_reading seq=33 value=41.30C observed_at=1784992056 feed_kind=0
        ix1  zeroclaw_oracle: publish_reading seq=34 value=41.20C observed_at=1784993286 feed_kind=0
        ix1  zeroclaw_oracle: publish_reading seq=35 value=40.70C observed_at=1784994516 feed_kind=0
```

Each of those transactions carries `AdvanceNonceAccount` as its first instruction, which is the
durable-nonce replay guard, and the sequence rises strictly. Both are visible in the decode rather
than taken on trust. The `observed_at` values are 1230 seconds apart, matching the 20.5 minute
column above to the second.

Do not take the head of the feed from this file, because any sequence number written here is
stale within twenty minutes of being written. Read it live:

```
python3 scripts/verify-proof.py
```

It prints the current reading, sequence and age, and exits non-zero if the feed has gone quiet.

Two honesty notes about this table, because both were wrong here until an audit caught them:

- These rows deliberately come from `JEtuZk…`, **not** from `CfWaZA…`. An earlier version of
  this section proved "yours, running" using the agent-driven feed, which the table above marks
  historical and whose last transaction landed **2026-07-24 13:47:28Z**. A document cannot cite a
  dead feed as evidence of a live one. This bullet read "has not published in over a day" until
  2026-08-05, which was true when written and understated the gap roughly tenfold by the time
  anyone read it, in the one sentence whose job is calling out dead evidence. A relative duration
  in a document that outlives the day it was written is a claim that rots on its own; the absolute
  timestamp does not. Re-derive with `getSignaturesForAddress` on that feed rather than trusting
  this line.
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

| UTC | seq | value | Settlement tx | Offline status |
|---|---|---|---|---|
| 2026-07-23T02:42Z | 10 | 29.0C | [2pgdXYAS…](https://explorer.solana.com/tx/2pgdXYASpLxcSKuBBzxWnHRWKVZiJbdzpu4SCrjeznL1ptJc1iNcT8ste79Goti14MadKZHvo1rsNMVemmAbEBH?cluster=devnet) | captured, verifies |
| 2026-07-23T08:44Z | 13 | 41.1C | [2j9emSvs…](https://explorer.solana.com/tx/2j9emSvsWHKyTEGVT3iLik9XGxpQkLLqAhLLQqjgkVEQx2QPHJQnxqzKLMqxCtCjnsdne276aFH4z76Z3CdJah5E?cluster=devnet) | captured, verifies |
| 2026-07-24T05:56Z | 17 | 33.0C | [agHTsrz1…](https://explorer.solana.com/tx/agHTsrz1Z6XhFjKN2g9DxFjJP363He2rHByvDN7r6KUDurzxxxcdj4LcfTA6AQpNsFk4cYqjk9k4kHfwgxWRFQd?cluster=devnet) | captured, verifies |

**All three decode to exactly what their rows claim**, so every row here can be checked rather
than believed: seq 10 at 29.00C, seq 13 at 41.10C, seq 17 at 33.00C, each read out of the signed
bytes by `scripts/verify_proof_offline.py` rather than copied from a note.

The first two spent four days recorded as lost. The bundle was built after the endpoint had
stopped serving them, so they carried `ALREADY_PRUNED`, no offline check could prove them, and
they were printed as plain text rather than as links, because a link to a transaction whose bytes
nobody holds hands a reader a dead end dressed as a proof. On 2026-08-01 a retry found the
endpoint serving both, captured them, and they are linked here now under the same rule that kept
them unlinked before: a signature is offered as a link only once its bytes are held.
`scripts/check-proof-links.py` enforces that rule mechanically across every tracked document, so
the distinction cannot quietly erode the next time a row is added.

The recovery is the part worth keeping. A transport failure and a permanent loss land in the same
column and are indistinguishable afterwards, so a row saying a transaction is gone is really
saying nobody has asked again lately. Asking again costs one command:
`scripts/capture-proof-bundle.py --refresh` re-requests everything not yet captured and refuses to
overwrite bytes it already holds, so running it can only add evidence.

## The x402 earning-node settled a real paid read (machine commerce)
The node sold one reading over x402: a 402 challenge, a client-signed stablecoin payment, and
on-chain settlement before the reading was served.

Re-driven 2026-07-27 against the gate running on the ARM node, and the payment is now in real
Circle devnet USDC rather than the purpose-created mint the earlier run used, so the settlement
path is exercised end to end against the asset a real buyer would hold.

- Settlement tx `EkBmoDknDryQpDtD6hnLoCdhhRjAo3Vmn15VmkQi7niqYHnK5XYL8FpxLabDiQ2S2QuTdD3vsTXMSra72LXgApE`
  (slot 479305550, `err: None`, 390 bytes):
  https://explorer.solana.com/tx/EkBmoDknDryQpDtD6hnLoCdhhRjAo3Vmn15VmkQi7niqYHnK5XYL8FpxLabDiQ2S2QuTdD3vsTXMSra72LXgApE?cluster=devnet
- The reading served in exchange came from the node's own feed `JEtuZkcRze…` at sequence 177.
- Replaying the identical `X-PAYMENT` header was refused with HTTP 402 and
  `"rejected":"NonceReused"`, because the payment's memo nonce is single-use. The refusal offers a
  fresh challenge rather than failing silently. That refusal is a response and not a transaction,
  so it has no on-chain representation and no signature to look up. The full HTTP exchange that
  carries it, the 402 challenge with both price tiers, the receipt header, the served reading, the
  refused replay, and the earnings ledger line, is recorded verbatim in
  `docs/proof-bundle/x402-purchase-and-replay.md`.
- Public parties: buyer `E36NJ7FvFSQxegFemCEL76GrBVUcVSEWvihne5WFxBdf`, seller receiving wallet
  `C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ` (receiving ATA
  `6L348RziHrFG1TELfCNUTUPQjBLziYn5JatxsQoY4ekD`), asset
  `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU` (devnet USDC, 6 decimals), price 1.000000 USDC.
- The buyer signed on a separate machine from the node, so the settlement is a genuine remote
  purchase rather than the seller paying itself.
- These bytes are captured in `docs/proof-bundle/devnet-transactions.json`, so the claim survives
  the explorer link expiring. `python3 scripts/verify_proof_offline.py` re-verifies the ed25519
  signature and decodes the payment with no network at all:

  ```
  PASS  EkBmoDknDryQpDtD..  slot=479305550  sigs 1/1 verified  succeeded
          ix0  ComputeBudget: SetComputeUnitLimit 50000
          ix1  ComputeBudget: SetComputeUnitPrice 1 microlamports
          ix2  SPL Token: TransferChecked 1.000000 (raw 1000000, 6 dp)
          ix3  SPL Memo: Memo "x402-18c632a32e04eb24-1"
  ```

  The price and the single-use memo nonce are both in the bytes. That nonce is what makes the
  replayed header refusable, so the mechanism is legible offline rather than only in the narration
  above.

## The shop terminal took a real payment (Track A, reference-threaded)
The full shop flow ran end to end on devnet with the real plugin logic (no reimplementation): a
Solana Pay request with a fresh reference, an UNSIGNED transfer the agent builds (T1, it never
holds a broadcast-ready transaction), the host signs and broadcasts, and payment_watch detects
settlement. That last step is a conjunction, not a lookup: the reference must appear, AND the
amount must match exactly, AND the asset must match, AND the destination must be ours. A payment
that satisfies three of the four is not PAID. A second check with a different reference correctly
returns NOT_YET, so a payment is confirmed only from the on-chain match, never the customer's
say-so.

The asset term is deliberately not written as "mint" here, because this particular settlement is a
native SOL transfer and native SOL has no mint. `payment-watch` treats the asset as either a
specific SPL or Token-2022 mint, checked through the token-balance deltas, or native lamports,
checked through the account lamport delta. Earlier wording here said "mint" for all four cases,
which is right for a stablecoin payment and wrong for this one. Decoding the captured bytes is what
exposed the imprecision.

- Transfer tx `4kDo6NCcAxSe3BSTtQ4onTASenxRWr2miagweVway3RnDMLG7drv6NkTdV7eRtTSDcNXURy2ESpKcqkk2jG9sYqS`
  (payment_watch verdict PAID on all four of reference, amount, asset and destination; memo invoice-e2e-1):
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

**The captured bytes carry the reference mechanism, not just the payment.** Decoded offline:

```
PASS  4kDo6NCcAxSe3BST..  slot=478425564  sigs 1/1 verified  succeeded
        ix0  System: Transfer 0.001000000 SOL
        ix1  SPL Memo: Memo "invoice-e2e-1"
```

The transfer instruction carries three accounts: sender, recipient, and
`6xZC4vUpTheLKK5dv14ktbJusTN9RUeeYCaJyeZq4A11`, the reference. That third account is read-only and
never funded, which is why the explorer shows nothing for it while the transaction that mentions it
is exactly the one `payment-watch` finds. `python3 scripts/verify_proof_offline.py --verbose` prints
the account list so the marker can be checked against the invoice without any RPC.

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
  `custom program error 0x12c` (InstructionError Custom 300). This one opens on a red failed
  transaction, and that is the result to look for: the agent's own key signed it and the audited
  program still refused it. The bullet above is the control that tells a refusal apart from a key
  that simply does not work:
  https://explorer.solana.com/tx/3TLSrfWVYdC3hSiAWnyyd7T694bLJQDtdJYQ64EWUsBNDehGc6Kq1veR7xa8Y1BiMdpvfFm3N1dKjDrXF3BEq2ps?cluster=devnet
- Reproduce: `cd e2e-allowance && npm install && E2E_FUNDER=<operator.json> node demo.js` (devnet)
  reruns the whole create-delegation then within-cap-then-over-cap flow.

**Primary evidence is the captured bundle, not the three links above.** This is the claim that
carries the most weight here, and it is the one that survives the links expiring intact. The raw
bytes decode to the whole argument, cap and both amounts and the on-chain refusal, with no RPC:

```
PASS  3eeM43DgvcJqrkUA..  slot=478432691  sigs 1/1 verified  succeeded
        ix0  SF Allowances: createFixedDelegation cap=5000000 raw units (nonce 1)
PASS  5qyr7jJi8zb6SjZj..  slot=478432693  sigs 2/2 verified  succeeded
        ix0  SF Allowances: transferFixed amount=5000000 raw units
PASS  3TLSrfWVYdC3hSiA..  slot=478432696  sigs 2/2 verified  FAILED ON CHAIN: {"InstructionError": [0, {"Custom": 300}]}
        ix0  SF Allowances: transferFixed amount=10000000 raw units
```

Read it in order: a cap of 5,000,000 base units was set, a transfer of exactly that settled, and a
transfer of twice that was refused by the program with `Custom: 300`. The delegatee signed all
three, so the rejection came from the audited program rather than from our plugin declining to
build the transaction. Reproduce with `python3 scripts/verify_proof_offline.py`.

**What `0x12c` means, and why a replay today returns it at any amount.** Custom error 300 is
`AmountExceedsLimit`, "Transfer amount exceeds delegation limit", declared in the
solana-foundation program's own `program/src/errors.rs` and in its published IDL. The full
citation, the pinned upstream quote and the reason the code is 300 rather than an Anchor 6000-range
value are in [`MAINNET-PROOF.md`](MAINNET-PROOF.md), which is the canonical explanation for both
clusters. It also covers the trap a reader hits when re-sending this captured message with a
different amount: a fixed delegation carries a remaining balance, this devnet run spent its entire
5,000,000 cap in the within-cap transfer, so the delegation's remaining allowance is now zero and
every non-zero replay is refused with the same 300. Check that here rather than taking it on trust:

```
python3 scripts/replay_allowance_probe.py --bundle docs/proof-bundle/devnet-transactions.json
```

## How to re-verify
Three ways, no account of ours needed. The first needs no network and is the one that still works
after the links expire, so it is listed first deliberately:

- **Offline, from the repo alone:** `python3 scripts/verify_proof_offline.py --verbose` recomputes
  every digest, verifies every ed25519 signature against the exact serialized message, and decodes
  every instruction. Standard library only, no RPC, no install. Prove its controls can fail with
  `bash scripts/mutation-check-offline-proof.sh`, which plants three defects in a copy and requires
  each to be refused. Both run in CI on every push to main and every pull request, so neither
  depends on anyone remembering to run them.
- **One command, no install:** `python3 scripts/verify-proof.py` (stdlib only) queries devnet and
  prints PASS/FAIL for every claim above (programs executable, feed PDA owner, and each tx's exact
  success or rejection), exiting non-zero if any fails. A clean run prints `10/10 static claims`
and every live claim it could gate, split deliberately: the static ten are deployed program state
and immutable devnet history, so they stay green whether or not anything of ours is switched on.
The live ones answer whether the node is publishing right now, whether the pay page is reachable,
whether the shop daemon is alive, and whether the x402 gate rebuilt its spend ledger across a
restart, which are independent systems rather than one. That count is DERIVED from what actually
gated rather than pinned, so it reads 4 once the node serves the ledger block and 3 until then,
and a claim reporting PENDING is never counted as verified. A number written here instead would
either overstate today or need remembering later, which is how this sentence came to say two when
the verifier had printed four for some time.

**The demo video will show SMALLER numbers than a run today, and that is the point.** It is a
recording, so every frame is a snapshot of the moment it was captured. The verifier beat was
re-shot on 2026-08-01 and shows ten static claims, four live ones, and the feed at sequence 539.
The heartbeat beat earlier in the cut is an older take and shows sequence 80. Running the verifier
now returns a sequence above both, because the node did not stop when the camera did. If any two of
those agreed exactly it would mean nothing had been running in between. Do not reconcile them;
check the live one, and treat the gap between them as the evidence.

The CLAIM COUNT is the one number where a gap is not evidence but staleness, because it measures
what the verifier can check rather than how long the node has run. The beat was re-shot for exactly
that reason: it showed two live claims against a verifier that derives four, which understated the
system on the axis this document exists to support. Raising the caption alone was refused, since
the terminal in frame printed the old count and a caption disagreeing with the output beneath it is
worse than the understatement.

Prove that gate works rather
than trusting it: `MAX_FEED_AGE_MIN=0 python3 scripts/verify-proof.py` turns the live check red
and exits 1 while all ten static claims stay green.
- **By hand:** open any link above with the explorer cluster set to devnet. The programs are
  executable (owner `BPFLoaderUpgradeable`), the feed PDA decodes via the on-chain IDL, and the
  settlement tx shows the TransferChecked to the seller's associated token account.
