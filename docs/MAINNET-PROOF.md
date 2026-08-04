# Mainnet proof: the custody rejection holds with real value

The custody claim this project rests on is that the **program** bounds the agent, not the plugin
and not the model. That was proven on devnet first. This page is the same proof on mainnet, moving
real USDC, because a rejection that costs nothing is a weaker claim than a rejection that does.

Kept separate from [`DEVNET-PROOF.md`](DEVNET-PROOF.md) deliberately. Evidence from one cluster
does not belong in another cluster's page, and the capture tool now refuses to write two clusters
into one bundle for the same reason.

## What ran

A delegation was created against the audited Solana Foundation
[Allowances program](https://explorer.solana.com/address/De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44)
`De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44`, capped at **0.5 USDC**. A freshly generated agent
session key then signed two spends. Nothing about the program is ours: it is deployed, executable,
owned by the BPF upgradeable loader, and audited by Cantina and Spearbit.

| Step | Amount | Result | Transaction |
|---|---|---|---|
| Create delegation | cap 0.5 USDC | settled | [`3bwaCTgF…`](https://explorer.solana.com/tx/3bwaCTgF77pGeTNWWf22FkCHKLdjjEWU3Za67j6QewTqbQYE4sbWowWEN6bcVcpQQskDLx3ianyjVNtSss2ACTXj) |
| Within cap | 0.4 USDC | **settled**, value moved | [`5sHLcD1v…`](https://explorer.solana.com/tx/5sHLcD1vZNgPzaEbn1qGWd8a1RwiYxJnVF3i29uf8V7oirVbX9TUmkyrTEdAPSoXciqt3qywPAmXU4pwQ1wXakD4) |
| Over cap | 1.0 USDC | **refused on chain**, `custom program error 0x12c` | [`4nbuXbWK…`](https://explorer.solana.com/tx/4nbuXbWKc8Q2YiKbPnjmTyarGroaB5oT3j8iiwhU95e5H2pRn8MorGraqZaDregWmf5BwedHwaiTQo9Ff81dc9G4) |

The within-cap transfer moved `-0.400000` from the operator and `+0.400000` to the receiver,
readable in the transaction's own token balances. The agent session key signed the over-cap spend
willingly. The chain is what stopped it.

## Why the over amount is 1.0 and not something larger

If the over-cap attempt also exceeds the token balance, it can be refused for insufficient funds,
and a rejection for the wrong reason proves nothing about the cap. The operator held 2.186 USDC, so
0.4 plus 1.0 stays inside the balance and the **only** reason to refuse the second spend is the
cap. The harness enforces this rather than trusting it: it refuses to start when the balance is
below within-plus-over, and it asserts the failure is custom error 300 before reporting success,
exiting non-zero on any other error. A run that failed for the wrong reason cannot be published
from it.

## What `0x12c` is, sourced to the program rather than asserted here

The program is not ours, so its error codes are not ours to define. `De1egAFMk...` is the
solana-foundation subscriptions and allowances delegation program, and its source is public at
[solana-foundation/subscriptions](https://github.com/solana-foundation/subscriptions). Error 300
decimal is `0x12c`. Its name and message are declared in that repository's `program/src/errors.rs`,
quoted here from [pinned commit `debb4f7`](https://github.com/solana-foundation/subscriptions/blob/debb4f75ff7571218b39de3b633074dd843e70db/program/src/errors.rs)
so the quotation cannot drift when upstream moves:

```rust
// --- Fixed delegation errors (300--399) ---
#[error("Transfer amount exceeds delegation limit")]
AmountExceedsLimit = 300,
```

The same file converts that enum to the number seen on chain, with no offset arithmetic in between:

```rust
impl From<SubscriptionsError> for ProgramError {
    fn from(e: SubscriptionsError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
```

That is why the code reads 300 rather than the 6000-and-above a reader used to Anchor might expect.
Anchor reserves user error codes from `ERROR_CODE_OFFSET = 6000`, and this program is not an Anchor
program at all: it imports `pinocchio::error::ProgramError` and generates its IDL with Codama, so
its error values are plain enum discriminants handed straight to `ProgramError::Custom` with no
offset added. The published IDL carries the identical entry, and one command prints it:

```
python3 -c 'import json,urllib.request as u; print([e for e in json.load(u.urlopen("https://raw.githubusercontent.com/solana-foundation/subscriptions/main/idl/subscriptions.json"))["program"]["errors"] if e["code"]==300])'
```

```
[{'code': 300, 'kind': 'errorNode', 'message': 'Transfer amount exceeds delegation limit', 'name': 'amountExceedsLimit'}]
```

One scope note, because 300 is narrower than a general over-the-allowance code: it sits in the
fixed-delegation band, 300 to 399. A recurring delegation that overdraws its period raises 400,
`amountExceedsPeriodLimit`. The refusal captured above is a `transferFixed` pull against a fixed
delegation, which is the case 300 covers.

## Why replaying the captured message returns 300 at every amount you try

Checking this page the obvious way, by taking the captured over-cap transaction, changing the
amount and simulating it, returns `Custom: 300` for every amount you are likely to pick, including
the 0.4 USDC that settled here on 2026-08-01. That reads as a program refusing everything, or as a
capture gone stale. It is neither, and the commands below settle it.

A fixed delegation carries a remaining balance, and the settled transfer already debited it. The
cap was 500,000 base units, the within-cap spend took 400,000, and 100,000 remain. Every replay
above 100,000 exceeds the remaining limit and earns the same refusal, for the same reason, as the
original. The delegation account is still live, still program-owned, and does not expire until
2026-08-31:

```
solana account HVVeimGq8VD4CuBgrvqWsgQV1GRVhfVNYQxJxTocUNY9 --url https://api.mainnet-beta.solana.com
```

Its data ends in two little-endian u64 fields, the remaining allowance then the expiry:
`a086010000000000` is 100,000 base units, and `9e9e956a00000000` is 1788190366, which is
2026-08-31T15:32:46Z.

Where the refusal starts is measurable, so this repository measures it instead of arguing it:

```
python3 scripts/replay_allowance_probe.py
```

The probe reads the remaining allowance off the account, then replays the captured message either
side of it with `sigVerify` off. Nothing is signed and nothing is broadcast, and the discarded
agent session key is not needed. Its output on 2026-08-04:

| replayed amount | simulated result |
|---|---|
| 1,000,000, the captured over-cap amount | refused 300 |
| 100,001 | refused 300 |
| 100,000, exactly the remaining allowance | accepted |
| 1 | accepted |

A program that had stopped working would refuse all four. A check that had stopped checking would
accept all four. The probe requires both outcomes to appear before it reports a boundary and exits
non-zero otherwise, and `scripts/test_replay_allowance_probe.py` plants each of those wrong worlds
to confirm it can fail. Run the same probe with
`--bundle docs/proof-bundle/devnet-transactions.json` and it reports a remaining allowance of zero,
because that run spent its whole 5,000,000 cap in one within-cap transfer, so every non-zero replay
there is refused. That is the same arithmetic seen at its other end.

## Verify it without trusting this page

The raw transaction bytes are captured in
[`proof-bundle/mainnet-transactions.json`](proof-bundle/mainnet-transactions.json) and verify with
no network at all:

```
python3 scripts/verify_proof_offline.py --bundle docs/proof-bundle/mainnet-transactions.json
```

The `--bundle` argument narrows the run to this page's claims. It is no longer required: with no
argument the verifier reads EVERY bundle and prints `all 2 bundles verified offline`, which covers
this page and the devnet one together. This paragraph said the argument was required and that a
bare run "tells you nothing about this page" until 2026-08-04, which was true of an earlier
default and had become the opposite of the truth: a reader following the one-pager's bare command
would have been told their run proved nothing, about the very claims it had just verified. Expect
`all 3 captured transactions verify offline`, with the over-cap entry reported as
`FAILED ON CHAIN: {"InstructionError": [0, {"Custom": 300}]}` rather than as a verification
failure. Its signatures are valid; the program refused it, which is the point. The verifier also
runs a negative control on itself first, confirming a decoy Anchor method name yields a different
discriminator, so a pass means the decoder is discriminating rather than agreeing with everything.

Explorer links are a convenience. The bundle is the proof, and it does not depend on anyone else's
retention policy. Mainnet history is not pruned, so the links above should outlive the links in the
devnet page, but the bundle is what the claim rests on either way.

## Reproduce it

```
cd e2e-allowance && npm install
E2E_FUNDER=<your keypair.json> \
E2E_RPC=https://api.mainnet-beta.solana.com \
E2E_CLUSTER=mainnet \
E2E_MINT=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v \
E2E_RECEIVER=<an address whose key you hold> \
E2E_CAP=500000 E2E_WITHIN=400000 E2E_OVER=1000000 \
node demo.js
```

`E2E_RECEIVER` is required on any cluster other than devnet, and the harness refuses to run
without it. The devnet default generates a receiver keypair and discards it, which is free there
and would permanently destroy the transferred amount on a live cluster.

## What is deliberately NOT on mainnet

The DePIN feed and its consumer program stay on devnet. Deploying both costs about 2.73 SOL in
rent, against 0.0059 SOL for everything on this page, and it would buy a second copy of a proof
that already verifies offline. The feed's value is its sequence history, which devnet already
carries. That is a decision on the merits rather than a budget limit, and it is recorded so a
reader does not have to guess.

Total cost of this page: **0.005895 SOL**. Rent is a refundable deposit proportional to account
size, not a fee, so most of that is recoverable by closing the accounts.
