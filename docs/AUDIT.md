# What an adversarial audit of this repo found

Three independent reviewers read this project cold in late July 2026, against the money path,
the blast radius of the auto-approved tool set, and the gap between what the documents assert
and what the code enforces. They found fourteen defects. This is the list, what changed, and
what is still open.

It is published for the same reason the decision record retracts its own reasoning in place
rather than deleting it. A submission that only shows its finished surface is asking to be
taken on trust, and the whole argument here is that nothing should be taken on trust.

## The headline is a negative result

The lead hypothesis was that settlement matched on the Solana Pay reference alone, so a stolen
reference plus a dust payment would mark an order paid. That is false, and it was refuted with
seven driven cases including a control that does return paid. `check_transaction` is a
conjunction over reference, amount, mint and destination. Three of four is not paid.

The finding survives as a documentation defect rather than a security one, and it is the most
instructive item in the list, so it is number twelve below.

A second hypothesis, that there is no egress filtering, was also false. Filtering, scheme
checks and a private-host block all exist and work. Only the wildcard default was wrong.

## The fourteen

| # | Defect | State |
|---|---|---|
| 1 | Merchant recipient was a prompt constant with nothing in code enforcing it | Fixed, pinned in three files with tests |
| 2 | Signature scan did not paginate, and the cursor stepped over unread history | Fixed, cursor held, three tests |
| 3 | Every money parameter in the verification path is authored by the agent | Disclosed as a boundary, not fixable at this tier |
| 4 | Egress allowlist defaulted to everything | Fixed in the documented posture, live check pending |
| 5 | A tier-demotion argument rested on a false premise | Premise replaced |
| 6 | The running proof used the feed the same document marked historical | Fixed, retraction left in place |
| 7 | A liveness claim counted immutable facts as evidence of liveness | Split into static and live |
| 8 | The documented publish cadence failed this repo's own verifier | Reconciled |
| 9 | The write-up omitted a host patch the reproduction calls mandatory | Documented |
| 10 | The testing doc cited scripts absent from a clone | Fixed, retraction left in place |
| 11 | Dependency gating covered three graphs while the docs claimed nine | Ten gated, one more than the defect asked for |
| 12 | Both judge-facing surfaces underclaimed the settlement check | Fixed |
| 13 | Documented approval list did not match the running one | Regenerated, live check pending |
| 14 | Assorted count and transcript defects | Fixed, and more found since |

## The four worth reading about

**The merchant address.** It lived in prose. Two markdown files named it and no code enforced
it, while the page that moves the money read the recipient out of a URL parameter and
transferred to whatever it found. This is not hypothetical: the build record already contains
the same failure happening by accident, when stale rows in the agent's memory produced a wrong
recipient with no attacker present. It is now a hardcoded invariant with tests, and one of
those tests carries the wallet from that incident.

The lesson is the one this project keeps relearning. A safety rule written in a prompt is a
request. The enforced version has to live somewhere the model cannot reach.

**The pagination gap.** Fail-safe in direction, since it can never produce a false paid, but it
could lose a real payment permanently. Twenty dust transfers between two polls would push a
genuine payment below the fetch window, and the cursor would then advance past it forever. The
fix refuses to advance across history it has not read, and reports a partial scan rather than a
confident not-yet. One of the three tests is named after the defect.

**The liveness number.** A script reported eleven of eleven claims verified, and ten of those
eleven were immutable: deployed programs stay deployed, account owners never change, devnet
history cannot be rewritten. Exactly one check could go red, and a feed that had been dead for
twenty-six hours still printed a pass. The count is now split, static from live, because a
green tick that cannot go red is decoration.

**The underclaim.** Both judge-facing surfaces described a four-way conjunction as a reference
lookup. That phrasing is what generated the refuted vulnerability hypothesis at the top of this
document: a reader who is told the check is a reference match will correctly observe that
references can be copied. Underclaiming your own control costs points on the axis it belongs
to, and invites an attack you are not actually open to.

## Still open, stated rather than closed

**The verification path takes its expected amount as an argument.** An agent that has been
successfully injected can call the check with a small amount and receive a truthful paid for a
small payment. This is not fixable inside a read-only lens, because the lens has no independent
view of what was owed. It is named in the threat model rather than left for a reviewer to find.

**Two live-configuration checks are unverified.** The documented posture is correct and the
drift checker is committed, but confirming the running configuration matches it needs the host
machine, which is currently unreachable. Re-run `scripts/check-config-drift.py` against a live
config to close this.

**One deliberate injection was never fired at the live agent for defect 1.** The structural gap
was proven by reading the code, and the accidental variant is on the record, but the end-to-end
deliberate exploit was assumed rather than demonstrated. The separate refund-redirect injection
transcript is a real live test; this specific one is not.

## What the audit did not find

Recorded so they are not raised again. The shell jail is real and was confirmed live. Leak
detection is correctly disabled, and re-enabling it would break payment links while fixing
nothing, because the agent has no secret to leak. The reference-only-match vulnerability is
refuted with code and driven cases. A long list of counts and claims checked out.

## One the audit did not catch, found while checking its work

Defect 11 asked for nine dependency graphs to be gated and nine were. Re-verifying it turned up
that nine was the wrong target. Eighteen manifests exist here; the matrix had been built from
the plugin surface alone, which left the x402 gate outside the check even though it ships and a
judge will read it. The harnesses and the microworlds are not shipped, and the Anchor workspace
is a separate graph scoped out on purpose, so the gate is now ten.

Adding it failed on the first run, on two licenses no plugin graph pulls: the root certificate
bundle and the TLS crates. Both are permissive and both were read rather than waved through on
the strength of the word appearing in a title. This is the whole argument for running a gate
locally before adding it to CI: the alternative was discovering it from a red badge.

## A second one, and it was in the monitoring rather than the code

The laptop feed publisher stopped running and nothing said so for six and a half hours. Three
layers reported healthy over one dead process. Its launcher was fire-and-forget, so it returned
success the instant it started something, regardless of what happened next. Task Scheduler
therefore logged about twenty consecutive successful runs with zero missed. And the proof script
called the frozen feed "quiet (allowed)", which is a real state, because that machine is allowed
to sleep.

The publish log could not settle it either. It holds no failure line for those hours, because
the script never executed far enough to write one. Absence of a complaint was being read as
absence of a problem.

The root cause is worth more than the outage. A laptop that was switched off and a publisher
that ran and failed produce an identical signature: both simply stop appending. No amount of
reading that log separates them, so the verifier could not have been fixed on its own. The
evidence it needed did not exist yet. The launcher now records an attempt before it runs and the
outcome after, so a start with no outcome reads as hung and killed, and the verifier can say
"running and not landing" instead of "allowed". Writing the marker first is the part that
matters, because a hung run gets killed and a killed process never reaches its own logging.

Two smaller things fell out. The scheduled task had no wall-clock limit at all, so hung runs
accumulated orphaned processes, one per attempt, with nothing ever waiting to reap them. And
this project reports fail-open defects upstream, where an unconfigured control should deny
rather than permit. It had one in its own monitoring the whole time.

## The pattern underneath

Every defect sat in the gap between what a document asserted and what the code enforced. That
is the gap a self-review cannot see, because a self-review reads the assertion and recognises
its own intent. It took readers who had no idea what was meant.

The monitoring defect above is the same shape one layer out: the gap between what a check
reported and what was true. A green light is an assertion too, and it earns no more trust than
a sentence in a document. The question to ask of any check is not whether it passes but what it
would have to observe in order to fail.

The same shape recurred after this audit closed. A claim that a Brazilian payment rail requires
a licensed provider had passed three independent reviews before a competitor shipped the thing
and disproved it. One on-screen test count had three different wrong values in circulation
across four documents, each copied from the last, which is what makes a stale number look
corroborated. Five files agreeing is not five witnesses when four of them are transcriptions.
