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
