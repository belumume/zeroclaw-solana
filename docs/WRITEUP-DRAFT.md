---
audience: internal
---

# Showcase write-up DRAFT v1 (structure = the revised brief's required elements, verbatim order)

> Status: full draft for the wasm-pains + custody sections; skeletons elsewhere get filled as
> the remaining assets land (SOP graph, BRL touch, Pi arrival). Secrets redacted throughout.

## What it does
Two use cases, one suite, both running daily since July 23:
1. **The DePIN talking node** — a device (Raspberry Pi; interim host) that measures its
   environment, signs each reading with its own key inside a wasm sandbox, and publishes a
   typed on-chain feed another program consumes — and you can message it on Telegram to ask
   what it saw and why a reading was refused.
2. **The shop terminal** — a merchant's ZeroClaw on Telegram and WhatsApp: payment requests
   via Solana Pay (skill), settlement verified on-chain (plugin), refunds human-approved and
   bounded by the audited on-chain Allowances program even under full prompt compromise.

## Who it's for
The node: anyone putting a sensor's word on-chain — DePIN operators, environmental telemetry,
proof-of-physical-work — without trusting the host machine's LLM with a spend key. The
terminal: a small merchant who wants "charge table 4, 25 USDC" to just work, with the
blast radius of a hacked agent capped by on-chain math, not vibes.

## Which ZeroClaw features it uses (stock first, per the ladder)
- Stock binary: channels (Telegram, WhatsApp Web), skills, SOPs with cron triggers +
  human-approval checkpoints, memory, the daemon + gateway, `security status` posture.
- One skill: `solana-pay` (URL + reference construction — string work, deliberately NOT wasm).
- Wasm plugins only where the ladder demands bounded code (below).
- Source-built host with `--features plugins-wasm,plugins-wasm-cranelift` — the exact bar the
  brief says judges score Tier-3 against.

## What we had to build (and what fought us)
**Plugins (Tier 3, each genuinely bounded code):** oracle-publish (device-key ed25519 signing,
durable nonce, range/kind/sequence fail-closed gates), payment-watch (reference-threaded RPC
verification through the OWASP-LLM01 response sanitizer), spl-transfer-build (unsigned
transfers surviving approval queues via durable nonces), allowance-spend-build (spends under
the audited SF Allowances program), depin-attest, token-risk-check, lending-health,
solana-pay-request — plus `solana-core`, a wasm32-wasip2 core crate (legacy + v0 tx, durable
nonce, PDA/ATA, Anchor discriminators, Token-2022 decode, two-signer partial signing,
byte-validated against solana-sdk fixtures, now 99 host tests including a verifier-side
transaction decoder and TransferChecked introspection) proven by all eight plugins.

**The x402 earning-node (`x402-feed-gate`), the frontier piece.** The DePIN node does not just
publish its feed, it SELLS it. A client asks for a reading; the node answers HTTP 402 with a
price menu; the client pays a stablecoin transfer on Solana and signs it themselves; the node
verifies the payment from the transaction bytes, settles it, and serves the reading. Custody
is T0/T1: the node holds no key but its public receiving address and cannot move funds, only
recognise a payment made to it, so there is nothing to prompt-inject into paying out. Because
the client is the fee payer, no facilitator is required and verification is pure Solana RPC. An
in-code per-payer daily cap bounds it. Proven end to end on devnet: a 402 challenge, a signed
payment, on-chain settlement, the reading served, and a replayed payment refused. This is the
machine-commerce direction the brief names as open territory, a device that pays for its own gas.

**What fought us on wasm32-wasip2 (the honest list):**
1. `--features plugins-wasm` alone is a trap: the runtime integrates but no JIT backend
   ships, so every plugin loads as discovered-but-unregistered ("failed to load code").
   The working invocation is `plugins-wasm,plugins-wasm-cranelift`.
2. The component boundary was where the budget went, as the brief predicted — WIT vendoring
   (wit/v0 pinned), shaped outputs to survive "judges will count tokens," and no sockets
   (waki blocking wasi:http only).
3. The host's jails bit us four separate times, and each bite is a feature: agent cron
   refused our own scheduler wrapper (bash not allowlisted, path outside the jail);
   script-bearing skills are deny-by-default (`skills.allow_scripts` opt-in); channel turns
   run workspace-jailed, so a skill referencing its own directory breaks — tools the agent
   runs must live in the workspace; and the outbound leak detector redacted our payment URLs,
   because its entropy heuristic cannot distinguish a secret from a public base58 address.
   The surgical posture: `security.leak_detection.high_entropy_tokens = false` (deterministic
   credential patterns stay on). A Solana-aware allowlist (base58 pubkey shape) upstream
   would let addresses through while keeping entropy protection — we'd propose it after
   judging.
4. Streaming modes have correctness consequences, not just UX: in `partial` mode the final
   segment replaces the draft, which silently ate the payment URL mid-conversation.
   `multi_message` is the shop-correct mode — the link lands as its own permanent message.
5. Durable nonces end-to-end: AdvanceNonceAccount ordering, one-nonce-one-inflight (parallel
   approvals need a nonce account each), and the read-back race (`sendTransaction` returns at
   processed; read at confirmed).

## Custody tier + threat model
Declared per component and defended in each README with a prompt-injection transcript:
- T0 reads auto-run (an RPC key at most).
- T1 build: unsigned transactions and device-co-signed readings; the device key can only
  sign readings (kind allowlist, range gates, monotonic sequence, deny_unknown_fields);
  the session key only pays fees. No spend path exists in code.
- Spends: human checkpoint + the on-chain Allowances cap: "the on-chain audited allowance,
  not the plugin, not the LLM, bounds the agent." Use-case-level prompt-injection transcript
  (a message impersonating the owner tries to redirect a 25 USDC refund to an attacker wallet
  with "no approval needed"; the agent refuses and the attacker address enters zero tool
  calls): `docs/transcripts/injection-refund-redirect.md`. Three layers hold, none talk-past-
  able by a message: the refusal, the unsigned-build-needs-approval gate, the on-chain cap.
- Third-party trust declared: none held; RPC endpoints and open-meteo are read-only inputs;
  no MCP servers in the loop.

## Reproducibility (links)
`QUICKSTART.md` reproduces both use cases from a clean machine in an evening: source-build
features, plugin install layout, agent/risk-profile config, channel wiring including the
pairing gates, the config posture (auto-approve set, multi_message, the leak-detection knob and
why, workspace tools/, source-build features), skill + SOP install, cron, and the x402 node.
It ends with a sharp-edges troubleshooting table where every row is a real cost we paid.
Secrets are the operator's own; no secret of ours is needed at any step.

## Links
Repo (plugins + solana-core + onchain programs + skills + e2e harnesses): [repo URL]
Live devnet: oracle `EFCRmE5w...`, consumer `B2scuv95...`, feed `CfWaZAQ9...` (seq history =
the daily-runs ledger), IDLs on-chain, security.txt embedded.
