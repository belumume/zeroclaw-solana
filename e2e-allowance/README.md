# e2e-allowance: the on-chain cap bounds a complying agent

The injection transcript shows the model **refusing** a malicious refund. This harness proves the
other half of the custody claim: even if a compromised model **complies**, the audited on-chain
program stops it. No plugin logic and no LLM is trusted here; the Solana Foundation Allowances
program (`De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44`, deployed on devnet) enforces the cap.

## What it does (live devnet)
1. Creates an SPL mint + operator/receiver token accounts, funds the operator.
2. `initSubscriptionAuthority`, then `createFixedDelegation` capped at **5 tokens**, with the
   delegatee set to a fresh **agent session key**.
3. The agent session key **signs** two spends:
   - within the cap (5 tokens) -> **succeeds**
   - over the cap (10 tokens) -> **rejected on-chain** by the program (`custom program error 0x12c`),
     landed as a failed transaction so it is clickable on the explorer.

## Run
```
npm install
E2E_FUNDER=/path/to/devnet-keypair.json node demo.js
```
The funder needs a little devnet SOL (`solana airdrop 1 <addr> --url devnet`). Optional `E2E_RPC`
overrides the cluster (default `https://api.devnet.solana.com`). The script prints the three
explorer links.

## Reference proof
A recorded run (create / within-cap / over-cap-rejected) is linked in `docs/DEVNET-PROOF.md`.
