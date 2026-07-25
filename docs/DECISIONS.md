# Decisions, and what they cost

Each entry records what was chosen, what was rejected, and the evidence that decided it.
The rejected options matter more than the chosen ones: anyone can justify what they built,
and the interesting question is what a reviewer would have built instead and why it is worse
here. Several of these went the other way at first and were reversed by evidence, which is
recorded rather than tidied away.

## 1. Custody stops at Tier 1, and the cap is enforced on chain

**Chosen.** The agent never holds a key that can move funds. It emits an unsigned
transaction a human approves, and spends are additionally bounded by the Solana Foundation
Allowances program, which is audited by Cantina and Spearbit. The delegatee is the agent's
session key, and the cap is enforced by that program rather than by our code.

**Rejected: a Tier 2 fund-holding session key.** It is the obvious way to make a demo feel
autonomous, and it moves the trust boundary onto our own code. The brief says Tier 0 and
Tier 1 are the sweet spot, and a fund-signing agent would mean the strongest custody claim
in the submission depended on code written for a hackathon.

**Rejected: hand-rolled spend caps.** A cap implemented in our plugin is enforced only while
our plugin is the thing doing the spending. An attacker who reaches the key directly ignores
it entirely. The audited program does not have that property, because it is the spending
authority.

**Rejected: a novel on-chain PolicyVault with program allowlisting.** This was the plan, and
it was killed by evidence rather than effort. A source-level check found Swig wallet already
ships on-chain program allowlisting for session authorities, with spend caps and per-window
recurring limits, and MagicBlock session tokens already scope a session key to one target
program. The remaining gap was thin, a single vault combining period cap, payee allowlist and
program allowlist, and competing with audited wallet infrastructure on their own ground for a
thin difference fails the obvious reviewer question: why not just use Swig.

**Consequence.** The custody story is demonstrated rather than asserted: an over-cap transfer
signed by the agent's own session key is rejected on chain with custom error 0x12c. The cost
is that the agent cannot spend unattended, which is the correct trade for money.

## 2. A plugin was demoted to a skill, and the reasoning is the point

**Chosen.** `solana-pay-request` builds a payment URL. That is string construction, so it
became a skill. It stays in the tree as evidence of the reasoning rather than being deleted.

**Rejected: keeping it as a wasm plugin.** It worked as a plugin and there was every
incentive to leave it there, because a larger plugin count looks like more work. The brief is
explicit that a Tier 1 solution to a Tier 1 problem beats unnecessary WASM, and shipping a
sandboxed component to concatenate a URL would be exactly the over-engineering the craft axis
penalises.

**Consequence.** The plugin count went down. That is the intended direction when the tier
test says so, and it is easier to defend than a number.

## 3. The DePIN feed writes typed state, not a memo

**Chosen.** The device signs a reading that lands in a typed `DeviceFeed` account owned by
our oracle program, guarded by a strictly increasing sequence, and a separate consumer
program reads it and acts.

**Rejected: a memo write.** Cheaper and faster to demo, and it is what makes a DePIN entry
read as theatre. Nothing on chain can consume a memo, so the claim would stop at "we wrote
something to Solana."

**Rejected: publishing through a pull-oracle network.** When the data producer is the trust
root, a network where nodes compute the value is the wrong shape: the device physically
cannot push its own signed reading through node consensus, and routing it that way moves the
trust root off the device and adds infrastructure we would then depend on.

**Rejected: transporting this machine's device seed to the node.** That was the first plan,
so the new feed would inherit the old one's sequence history. It would have made "the device
signs its own readings" architecturally true and literally false, and anyone reading the
deploy path could see the seed had travelled. The excuse did not survive arithmetic either: at
one reading every twenty minutes a fresh feed accrues roughly 936 readings by the submission
date, which is not a thin history. The node generated its own seed instead and the copy was
shredded unused.

**Consequence.** Replay is refused by the chain rather than by our code, and a consumer
program proves the feed is consumable. The device key was generated on the node with
`openssl rand -hex 32` and has never left that box, so the claim that the device signs its own
readings is literal rather than a figure of speech.

## 4. The response path is sanitized, not just the request path

**Chosen.** On-chain data is sanitized before it reaches the model's context, treating token
names and metadata as attacker-controlled input.

**Rejected: input-side transaction safety only.** That is where the field concentrates, and
it is necessary. It is also insufficient, because a token name is attacker-controlled text
that arrives through a trusted-looking RPC response and lands directly in context. Defending
only the request path leaves the model reading whatever an attacker minted.

**Consequence.** The sanitizer became the piece worth quantifying over all inputs rather than
a few cases, including idempotence, which is the property sanitizers most often fail.

You can operate it: `microworld/sanitizer.html` runs the real function, compiled to wasm,
with no server. It deliberately includes a case the advisory flag does not catch, because a
demonstration that only shows wins teaches the wrong model of what the defense is.

## 5. The leak detector is disabled for this agent, deliberately

**Chosen.** `security.leak_detection.enabled = false` for the shop agent.

**Rejected: leaving it on.** Its entropy tier redacts public base58 addresses and its
deterministic pattern eats Solana Pay's mandatory `spl-token=` parameter, so every payment
link left the shop as unusable redacted text. Keeping it on would have meant the demo does
not work.

**Why this is not a hole.** The defense belongs at the source. This agent's jail gives it a
workspace-only shell and no path to the config, so it has no access to a secret to leak. An
output regex is the wrong layer to defend a boundary that is already closed upstream, and it
was actively breaking the correct behaviour.

**Consequence.** Stated plainly in QUICKSTART with the reasoning, because a reviewer who sees
a disabled security setting deserves the argument rather than a silent flag.

## 6. Brazilian payments are quoted in BRL and settled in USDC

**Chosen.** The shop quotes in BRL at a stated rate source and settles in USDC on chain.

**Rejected: real PIX.** PIX is the flow the brief most wants to see, and it is a fiat rail
that requires a licensed Brazilian payment provider holding funds. Adding a custodial PSP to
a submission whose entire argument is self-custody would contradict the thesis to win a
mention.

**Consequence.** The Brazil claim is narrower and true: BRL invoicing and USDC reconciliation,
with PIX named as a deliberate non-goal and the reason given, rather than a fig leaf.

## 7. Blinks and gitlana are mentioned, not built

**Chosen.** Named as options, not implemented.

**Rejected: building a Blink for the shop payment.** It is sponsor-endorsed and would have
been a cheap extra bullet. The pay page already delivers the outcome a Blink would, a tappable
link that opens the customer's wallet, and the shop's channels are WhatsApp and Telegram,
which do not render Blink cards. It would add surface without changing what a customer can do.

**Consequence.** Originality budget stays on the device-co-signed feed and the x402 earning
node, where it buys something a single-track entrant cannot copy quickly.

## 8. Deterministic simulation and proof assistants were skipped

**Chosen.** Known-answer tests against the reference implementation, then property tests, then
live devnet.

**Rejected: the Antithesis SDK.** Its macros are inert off their platform, so it would ship
dead annotations and produce no signal here.

**Rejected: a full deterministic-simulation rig.** It is the right tool for a distributed
system with real concurrency, and the wrong shape for a mostly pure library with a thin IO
edge.

**Rejected: proof assistants.** The cost is real and the surface that would benefit is one
decoder, which a single Kani harness would cover more cheaply. That harness is named as a
genuine remaining gap in TESTING.md rather than claimed.

**Consequence.** The testing argument is about which layer catches which kind of wrong, and
what each is blind to, which is recorded in TESTING.md including the failures that passed
every layer.
