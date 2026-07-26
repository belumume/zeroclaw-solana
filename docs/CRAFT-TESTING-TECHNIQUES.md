# Testing techniques, read from the primary sources

Source talks, read in full from transcripts (not summaries):

- **[JS]** Will Wilson on Jane Street's *Signals and Threads*, 1h48m
- **[A85]** Antithesis, the Mario / deterministic-simulation talk
- **[WS]** Will Wilson, Web Summit 2025

Everything below is quoted verbatim from those transcripts. Where a technique I
expected was **not** in the sources, that is recorded as a negative result rather
than reconstructed from memory. The distinction is the point of this document.

---

## 1. Bugification: real, and NOT what we had written down

Our prior note defined bugification as "deliberately introducing bugs to measure
whether the test suite catches them." **That is mutation testing, and it is wrong.**
The word "mutation" does not appear in any of the three transcripts (the only
substring hit is inside "permutations"). Bugification is a different technique.

> "we call the technique **bugification** and the basic idea is if you have a piece
> of code that you have written well such that it 99.99% of the time does way better
> than its promise right like you know it returns an optional value but it always
> returns a value um you should when running in test sometimes just make it do the
> pathological thing with some low but real probability" (JS)

Set up two sentences earlier:

> "if your system performs better than its SLA, all everybody who depends on you
> will start to assume in code and otherwise that it will always perform better than
> SLA. And then if you ever merely meet your SLA, everything will go down and crash."
> (JS)

**Mechanism.** Contract-boundary fault injection against your own internals. Not
"is this component wrong" but "this component is *right*, and better than its
contract, and callers have silently accreted a dependency on the surplus." You force
each component to emit its full **legal** behaviour distribution during tests,
including legal-but-never-observed branches, so no caller can depend on the surplus.
**The bug it surfaces lives in the caller, not the component.**

Wilson rejects the production variant. On chaos monkey: *"I'm not such a fan of
that... I do feel like it degrades the quality of your overall service."* Test-time only.

**Why this matters here specifically.** Every fail-open defect this project has
already hit is a caller depending on an unexercised surplus:

| Incident | The surplus the caller depended on |
|---|---|
| WhatsApp `mode=business` skipping `group_policy` | policy always consulted |
| empty `allowed_groups` permitting all | list always non-empty |
| x402 empty `{}` satisfying a payee allowlist | allowlist always populated |

Candidate injection points: every WIT host import whose error variant the plugins
never see; any blockhash/RPC accessor that always returns fresh-and-valid in tests;
the sanitizer that always returns under the cap; the nonce advance path that always
succeeds.

## 2. Mined invariants: real, but the term is "speculative properties"

Present in [JS] only. Wilson credits fuzzing researchers, not himself, and hedges
on the name:

> "this is not an original idea... I think they call it speculative speculative
> properties. I forget exactly what the term it's. in a paper somewhere. But
> basically... I look at a function that I've executed a million times and if I see
> that like one of the parameters is positive every single time that function is
> executed, I just go ahead and add an assertion that that parameter will always be
> positive." (JS)

The load-bearing payoff clause:

> "if every time I execute it the thing is positive and then I get it to be negative
> one time that's going to lead to some interesting behavior later in the system
> possibly a bug because everybody else assumed it was always positive. And so the
> idea is like we can both use it to guide exploration and use it as like a kind of
> you know preemptive property creation." (JS)

Minsky supplies the triage rule, which is the operationally useful part:

> "there's the properties that are like seem to always be followed and like maybe
> those are properties and then there's the ones that are not followed at all and
> like those you discard and then there are the ones that like are **mostly followed
> and maybe those are the interesting ones**." (JS)

**Applied here.** Instrument existing proptest runs to record observed envelopes
rather than authoring new properties: shortvec byte-length per encoded value,
account-index vector cardinality, sanitized-string length and surviving codepoint
classes, nonce sequence deltas, per-instruction account counts. Promote always-true
envelopes to `debug_assert!`; route "mostly true" to a review list.

Note this technique would have caught a real defect already found by other means:
the unbounded per-instruction account-index vector that only broke past 65535 before
an `as u16` cast. An envelope-miner watching that vector's observed maximum flags the
missing bound without anyone thinking to write the property.

## 3. Exhaustive-domain audit: NOT in these transcripts

Recorded as a negative result. There is exactly one twenty-word aside:

> "or you should be using exhaustive testing, right? Like if your function takes an
> int32, you can just try all of them." (JS)

That is the entire treatment. No methodology for identifying small domains, no
procedure for proving coverage, no use of the word "audit." The only other
occurrence of "exhaustive" is Wilson describing the *"original sin of property based
testing"* (attributed to David MacIver) as the belief that you must exhaustively
enumerate all properties, a claim he argues **against**.

If we build an exhaustive-domain audit it is our own idea and must be presented as
such. (The `u16` shortvec domain is 65,536 values and genuinely exhaustible in a
round-trip test, and that observation is ours, not Wilson's.)

## 4. Stateful input distributions: the highest-value item found

Independent-per-element generation is proptest's default, and it was the wrong
distribution for our sanitizer strategy. **Found, fixed and measured the same day;
see TESTING.md.**

> "we remember the previous state of the controller. And then we use our random
> source to decide to start pressing or stop pressing a button... It's like applying
> a mask with some low probability. ... this weird trick will make all of your random
> distributions way more realistic and more lifelike" (A85)

The failure it fixes:

> "the odds of any given frame having the jump button held down, it's 50%. Great.
> it's random. Um, but the odds of having it held down for 100 frames in a row,
> that's one over 2 to the 100." (A85)

Distributed-systems restatement: per-packet coin-flip dropping is *"the most random
from the point of view of each individual packet. But from the point of view of the
system as a whole, it's actually not random at all... You're never going to get
extended periods of total blackout."*

**Applied here.** iid codepoint generation never produces a sustained run of control
characters, a long bidi-override region, or a repeated-token block near the length
cap. Same for the nonce machine: iid operation sequences never produce long
same-nonce streaks. Fix is mechanical: carry generator state, flip with low
probability.

## Honest counterarguments (the attack surface on our own testing story)

Several of these are Wilson arguing against his own position, which makes them the
strongest ones to pre-empt rather than hide.

- **Numerical and policy bugs are structurally invisible to this approach.** Minsky:
  a system *"might operate perfectly well and it never like breaks but like it's just
  like more aggressive than it should be... this kind of coarse grained well let's
  kind of look for like gross misbehavior and shake the box a lot is just like not
  going to get those things at all."* Wilson concedes: *"What I've said so far only
  covers a subset of the bugs."* Direct read: a fee calculation off by a rounding
  step survives every property we have.
- **Property inflation destroys signal.** Minsky: *"antithesis is going to say, 'Oh,
  we did your run and you have like 68 million exceptions.'"* Wilson: *"You should
  definitely not take every single thing... and turn it into a property."* This is
  the brake on technique 2: mine envelopes, promote few.
- **Coverage is a bad progress metric.** *"Consider something like a Python
  interpreter. If you hit 100% code coverage in that you have not gotten anywhere
  close to exhausting its behavior."* Do not lead with a coverage number.
- **Example-based testing is unreasonably effective.** Minsky: *"there's a kind of
  like unreasonable effectiveness of example based testing... for like modest
  complexity things, it actually like works super well."*
- **A strong validation harness plus an agent loop degrades the codebase:** *"the
  more powerful and unyielding the validation step is probably the worse this overall
  effect gets."* Relevant if we point agents at the proptest suite.
- **Recorded-trajectory tests are worthless under change.** [WS]: moving one block
  desyncs the whole replay; *"It would break every single test."* Applies to any
  golden/snapshot fixtures.

## Explicitly out of scope

Requires infrastructure we do not have and will not build: the deterministic
hypervisor; copy-on-write page dedup for branching state-space exploration;
Lyapunov-exponent measurement; FoundationDB's single-process simulated network with
deterministic scheduler (Wilson himself calls this *"totally impractical"* as a
general tool); the Antithesis product itself.

Prefix-locking / progress-coordinate search [A85] is genuinely powerful but assumes
replayability that *"totally explodes"* without determinism, and our wasm plugins are
closer to deterministic than most software, but the host boundary is not.
