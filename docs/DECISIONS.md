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
signed by the agent's own session key is rejected on chain with custom error 0x12c, which is 300,
`AmountExceedsLimit`, cited to the upstream program's source in
[`MAINNET-PROOF.md`](MAINNET-PROOF.md). The cost
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

That second sentence was an argument about a deployed program until 2026-08-05, when it became
a transaction:
`4CRapo3AEFBFLh7Y7byJR9XDYZEa95MEioUQMzUhJVxTB9HaDTRtX2X47pVgxaSu8KNfYsPyugeQ6FjN8hBzi54L`
read this node's feed and emitted `ActionTaken … crossed=true`. Worth recording why it took so
long to notice: the consumer had been deployed and exercised since 2026-07-21, so every surface
that checks whether it EXISTS and WORKS was green, and none of them asks which feed it read. It
had read the historical feed four days before this one was created. A capability that is
demonstrated once against a fixture and then cited about production is the same shape as a
control nobody wired up, which is the defect this project filed ten times upstream.

## 4. The response path is sanitized, not just the request path

**Chosen.** On-chain data is sanitized before it reaches the model's context, treating token
names and metadata as attacker-controlled input.

**Rejected: input-side transaction safety only.** That is where the field concentrates, and
it is necessary. It is also insufficient, because a token name is attacker-controlled text
that arrives through a trusted-looking RPC response and lands directly in context. Defending
only the request path leaves the model reading whatever an attacker minted.

**Consequence.** The sanitizer became the piece worth quantifying over all inputs rather than
a few cases, including idempotence, which is the property sanitizers most often fail.

You can operate it: `sanitizer-microworld/index.html` runs the real function, compiled to
wasm, with no server. It deliberately includes a case the advisory flag does not catch, the
injection-framing preset that carries no invisible characters at all, because a demonstration
that only shows wins teaches the wrong model of what the defense is.

## 5. The leak detector is disabled for this agent, deliberately

**Chosen.** `security.leak_detection.enabled = false` for the shop agent.

**Rejected: leaving it on.** Its entropy tier redacts public base58 addresses and its
deterministic pattern eats Solana Pay's mandatory `spl-token=` parameter, so every payment
link left the shop as unusable redacted text. Keeping it on would have meant the demo does
not work.

**Why this is not a hole.** The reason recorded here until 2026-07-27 was that the agent's
jail gives it a workspace-only shell and no path to the config, so it has no secret to leak.
That claim is retracted. It rested on one verified axis, the `unrestricted_filesystem = false`
flag, and generalised it into a guarantee about secrets that nothing here established. It is
also falsified by our own host audit: issue #9386 records a Gemini API key travelling in a
request URL, surviving error sanitization, and being posted into the originating chat. That
path never touches the filesystem, so a jail that closes the filesystem does not close it,
and this shop runs Gemini primary with the detector off, which is precisely where the two
compound.

The narrower claim is the one that holds, and it is the one `QUICKSTART.md` and the write-up
already make: this agent holds no key that can move funds. Signing lives outside it, the
recipient is pinned in the page that transfers, and the spend ceiling is enforced by an
audited on-chain program rather than by any jail or regex. The assets actually at risk are
customer funds, shop business data and durable agent memory, and an outbound regex is the
wrong layer for all three while demonstrably mangling public on-chain data.

**Consequence.** Stated plainly in QUICKSTART with the reasoning, because a reviewer who sees
a disabled security setting deserves the argument rather than a silent flag. An operator who
does hold secrets reachable from this agent should keep the detector on and expect broken
payment links until upstream grows an allowlist.

## 6. Brazilian payments are quoted in BRL and settled in USDC

**Chosen.** The shop quotes in BRL at a stated rate source and settles in USDC on chain.

**Rejected: real PIX.** PIX is the flow the brief most wants to see, so the reason for
refusing it has to survive being checked.

The reason recorded here until 2026-07-26 did not survive. It said PIX requires a licensed
provider holding funds, and a rival entry disproved it by shipping the thing. A static BR
Code is EMV TLV plus a CRC over the merchant's own key, generated offline, custodian
nowhere in it. Issuing a PIX charge is roughly the difficulty of the Solana Pay URL we
already build.

The real obstacle is on the settlement side, and it is not about difficulty. A bank transfer
is invisible to this software, so a PIX invoice can only be marked paid because a human said
so. Everything else here is confirmed by checking amount, mint and destination against the
chain, and that is the whole claim, not a detail of it. Shipping one leg that a human
attests to would let a reader ask why the attested one is not enough, which is the question
the submission exists to answer.

**Consequence.** The Brazil claim is narrower and true: BRL invoicing and USDC
reconciliation, with PIX named as a deliberate non-goal on the settlement argument rather
than a regulatory one.

## 7. Blinks and gitlana are mentioned, not built

**Chosen.** Named as options, not implemented.

**Rejected: building a Blink for the shop payment.** It is sponsor-endorsed and would have
been a cheap extra bullet. The pay page already delivers the outcome a Blink would, a tappable
link that opens the customer's wallet, and the shop's channels are WhatsApp and Telegram,
which do not render Blink cards. It would add surface without changing what a customer can do.

**Re-examined against the brief's own reasoning, and refused again on stronger grounds.** The
brief recommends routing through a Blink specifically "where building a transaction yourself is
the hard part," listing the protocols that hand back a ready transaction over REST as the
Tier 1 friends of anyone who does not want to construct one. That motivation does not apply
here: building the transaction is the part this submission does byte-correctly, validated
against the reference implementation, so a Blink would replace a verified path with an
outsourced one. The test that settled it is the one worth stating, because it applies to any
feature added because a rubric mentions it. Delete the feature and see what changes. Delete
Blinks and the shop behaves identically, which makes it decoration rather than a solution to a
problem this build has.

**Consequence.** Originality budget stays on the device-co-signed feed and the x402 earning
node, where it buys something a single-track entrant cannot copy quickly.

## 8. The Antithesis SDK was rejected, its technique was not

The heading here used to say proof assistants were skipped, which stopped being true the moment
the Kani harnesses landed and stayed on the page for a while afterwards. A heading that
contradicts its own body is worse than a stale note, because the heading is what gets read.

**Chosen.** Known-answer tests against the reference implementation, then property tests, then
a proof where the domain is small enough to walk, then a search for the disagreements none of
those were written to find, then live devnet.

**Rejected: the Antithesis SDK.** Its macros are inert off their platform, so it would ship
dead annotations and produce no signal here.

**Rejected: a full deterministic-simulation rig.** It is the right tool for a distributed
system with real concurrency, and the wrong shape for a mostly pure library with a thin IO
edge. That rejection stands. The conclusion drawn alongside it did not, and correcting it is
worth more than the original call. Rejecting the rig had quietly become "this whole approach is
out of reach here," which is a different and wrong claim. The search underneath it needs no
hypervisor when the target is already deterministic, and a decode path with no clock, no
threads and no IO is exactly that. So `differential-fuzz/` now mutates real transactions and
grades both decoders against the reference deserializer, which is the layer that looks for
disagreements nobody wrote a property for. The tool was correctly refused; the idea was not
theirs to keep.

**Rejected: proof assistants.** The cost is real and the surface that would benefit is one
decoder, which a single Kani harness covers more cheaply. That harness is now built and
passing, and the distinction from the Antithesis rejection above is the point: Kani's proofs
sit behind a `cfg` that cargo never sets, so nothing dead ships, and unlike inert macros they
produce an actual result. Two harnesses, both VERIFICATION SUCCESSFUL, covering all 16,777,216
three-byte inputs rather than the 1024 proptest samples.

**Reversed by measurement, not by preference.** The first version checked canonicality by
re-encoding into a `Vec` and ran 37 minutes at 3.8 GB without converging, which looked like
evidence that the property was too expensive to prove. It was the formulation. Canonicality
does not need a heap, and asserting it arithmetically proves the same thing in 4 seconds.
Recorded because the wrong lesson was available and cheap to draw.

**Consequence.** The testing argument is about which layer catches which kind of wrong, and
what each is blind to, which is recorded in TESTING.md including the failures that passed
every layer.

## 9. The attestation plugin was superseded by a lower-custody successor

**Chosen.** `oracle-publish` publishes the device's readings, and `depin-attest` runs in
neither use case. It stays in the tree with its own README, tests and devnet proof, the same
way the demoted payment plugin does.

**Rejected: keeping `depin-attest` on the live path.** It works, it has a real devnet
attestation, and it demonstrated an on-chain replay refusal, so there was every incentive to
keep shipping a component that already had proof attached. It is T2: it holds a scoped
ed25519 session key, it signs, and it broadcasts. `oracle-publish` does the same job at T1,
because the device co-signs the reading and the fee-payer slot comes back empty, so its output
cannot be broadcast by anything that does not already hold the agent's session key. The brief
puts T0 and T1 at the sweet spot, which makes a signing-and-broadcasting component worth
keeping only when nothing lower does the job. Something does.

**Rejected: deleting it.** A tier argument is checkable only when both sides of it are in the
tree. Deleting the T2 version leaves a claim that a T1 design was available with nothing to
compare it against.

**Rejected: a memo the successor also writes.** The two are not the same shape. `depin-attest`
writes an `spl-memo` a human reads back; `oracle-publish` writes a typed `DeviceFeed` account
a consumer program CPI-reads, which is why the custody went down while the capability went up.

**What would justify going back to T2.** A reading that must land on chain with no agent
session key in the loop, such as a device publishing while the host is offline. Neither use
case needs that, because the agent is the thing running the schedule.

**Consequence.** The live feed sits one tier lower than the component it replaced, and
`depin-attest` reads as an orphan in the tree unless someone says why it is there, which is
what this entry is for.

## 10. The two read-only lenses stay Tier 3, and the reason is ordering rather than the RPC call

**Chosen.** `token-risk-check` and `lending-health` are wasm plugins at T0 read-only custody.
Both predate the two use cases and run in neither; they keep their own READMEs and tests.

**Rejected: a Tier 1 skill plus the built-in `http_request` tool.** This is the option the
brief names, and refusing it needs a better reason than preference, because from outside both
look like the shape the brief rejects: one HTTP call, then shaping. The reason is ordering. A
skill's instructions are text the model reads, and `http_request` puts the response into the
model's context first, so the instructions can only ask the model to be careful about bytes it
has already read. A plugin runs before anything reaches context, so `sanitize_onchain` and
`label_untrusted` see the attacker-controlled fields (a token name, a market symbol, an RPC
error string) while there is still somewhere for them to be stripped to. That is the argument
`payment-watch` rests on, applied to the two components where it is easiest to doubt.

**Rejected: treating the third-party API as the source of truth.** `token-risk-check` does not
rest on RugCheck. It calls `getAccountInfo` and decodes the Token-2022 TLV itself through
`decode_mint`, and its report ends by saying so: on-chain extensions are authoritative,
RugCheck is corroboration only. Token-2022 TLV parsing for risk checks is the brief's own first
example of work that belongs inside the sandbox. A wrapper would inherit whichever verdict a
third party returned, including the case where it returns nothing.

**Consequence.** Both fail closed rather than downward, which is the property the tier buys.
`lending-health` turns a non-finite ratio into `Unknown` instead of letting it slide to `Safe`,
and caps every symbol at 24 characters so a minted name cannot flood the context window the
brief warns about. Both bounds are measured by a test that prints the figure: 1,355 bytes for
the risk lens under a 200-entry hostile flood, 5,810 for the positions lens under 300 hostile
positions carrying 40 symbols each. The tests assert a ceiling rather than those exact numbers,
so re-run them rather than quoting these if the shaping changes.

**What would justify Tier 1.** A lens reading only values the chain itself constrains, with no
operator-supplied text and no third-party JSON anywhere in the response. Neither of these is
that, and a lens over token metadata never will be.
