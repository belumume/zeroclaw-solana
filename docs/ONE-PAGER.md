# ZeroClaw on Solana: an agent bounded by the chain, and a node that pays its own gas

**Two things run, both self-hosted, both auditable by a stranger in an evening.** A DePIN node that
signs its own sensor readings on-chain and *sells* them per request, and a merchant terminal that
takes an order in Portuguese and settles in USDC. Every claim below is checkable with one command
or one link. Nothing here is a screenshot of something that used to work.

---

## What it does, and who it is for

**A device that earns.** An ARM node publishes device-signed readings to a Solana feed on a
schedule, and gates the same feed behind x402: a machine that wants the reading pays for it,
per request, and the node covers its own gas. That is the whole loop. Nobody subsidises the
hardware.

**A shop that takes money without holding keys.** A merchant agent on Telegram and WhatsApp
quotes an order in BRL at a stated ECB rate, issues a Solana Pay link, and marks it paid only
when four things agree: the reference, the exact amount, the exact mint, and the watched
destination. A payment in a token the payer minted themselves does not qualify.

Built for a small operator who wants an agent touching money without handing it a signing key.

---

## The custody argument, which is the part that does not depend on trusting us

An approval prompt is not a boundary. The sentence a human reads before approving was written
by the model, so influencing the model influences the description. An attacker needs no key,
only an operator who reads one plausible sentence and says yes.

Two answers, and neither requires the operator to read correctly:

**Where intent is fixed, nothing asks.** The publish path can express exactly one intent, so the
exact serialized bytes are re-derived and anything else is refused. Its self-test *is* the attack,
run four ways, on every push.

**Where intent varies, the chain refuses.** Spends are bounded by an audited on-chain program, not
by the plugin and not by the model. Demonstrated on **mainnet**, not asserted: a delegated session
key signed an over-cap transfer and the program rejected it with custom error `0x12c`; a within-cap
transfer by the same key settled normally. Both are captured as raw bytes in the repo and verify
**offline, with no network and no dependencies**.

Custody tier is declared per component: T0 reads run automatically, T1 emits an unsigned
transaction a human approves. **No component holds a fund-signing key.**

---

## Reproduce every claim above, in three commands

```bash
git clone https://github.com/belumume/zeroclaw-solana && cd zeroclaw-solana
python3 scripts/verify-proof.py           # 10 static + 4 live claims, stdlib only
python3 scripts/verify_proof_offline.py   # the custody proofs, no network at all
python3 scripts/certify_publish_tx.py     # four injection shapes, all refused
```

No install step, no venv, no credentials. The offline verifier refuses to report at all if its
own positive control stops passing, so a green result cannot come from a broken checker.

---

## What we are not claiming

The certifier's **mechanism** is proven and CI-gated; its **wiring** to the live scheduler is
operator-side configuration and is not provable from this repo. Corroborating a payment across
independent RPC endpoints moves trust to the configured set rather than removing it, and endpoints
sharing an operator or an upstream fail together. The DePIN feed runs on devnet by choice, since
duplicating an already-offline-verifiable proof on mainnet costs about 2.73 SOL in rent.

These are stated here rather than found by a reviewer, because a control that is claimed and
enforced by no runtime path is worse than an absent one: an absent control is visible, an inert
one lets you believe you are protected.

---

## Craft, briefly

Sixteen crates, formatted and clippy-clean at `-D warnings` on host and wasm. Two Kani proofs on
the shortvec decoder, one covering all 16,777,216 three-byte inputs. A differential fuzzer graded
against solana-sdk's own deserializer rather than invariants we chose. Ten security defects found
in the host and reported upstream, one escalated to a private advisory. Every gate ships a control
proving it can fail, because zero findings is also what a broken detector prints.

**Repo:** https://github.com/belumume/zeroclaw-solana
**Write-up:** https://github.com/belumume/zeroclaw-solana/blob/main/docs/WRITEUP.md
