# Payment confirmation

> **DO NOT INSTALL THIS SOP. It is kept as the worked example of a defect, not as a running
> procedure, and `QUICKSTART.md` deliberately installs the other two and not this one.**
>
> Step 4 below says "never claim an order paid without a `payment_watch` confirmation". That is a
> sentence addressed to a model, and a model can satisfy it by asserting it complied. Nothing here
> carries the tool's output into the message or the ledger line: step 4 has the model COMPOSE the
> announcement and step 5 has it COMPOSE five fields including the settlement signature. On
> 2026-07-26 that is exactly what happened. With `payment_watch` unavailable the agent hunted for a
> substitute, ran a different script, and reported a settlement verdict from it.
>
> A prohibition is not a binding. The deterministic replacement reads every field out of a
> `getTransaction` response and cannot compose one:
> [`demo/confirm_settlements.py`](../../demo/confirm_settlements.py), driven by
> [`deploy/announce_settlements.sh`](../../deploy/announce_settlements.sh), which bypasses this SOP
> rather than fixing it. `deterministic` execution mode is what this job wants and the host does not
> yet reach it, which is why the replacement lives outside the SOP engine.
>
> Read the steps below for the shape of the job. Do not run them against real money.

Announces each payment to the owner's channel within about a minute of it settling on-chain.
This is the beat the listing storyboards: *"A customer wallet pays it. Forty seconds later the
agent posts 'Invoice #412 paid' in the owner's channel."*

Read-only by construction. It verifies settlement and sends a message; it holds no key, builds no
transaction, and can move no funds. The only fund-touching path in this shop is a refund, and that
lives in `evening-reconciliation` behind an explicit human checkpoint.

**This does not replace `evening-reconciliation`, and the split is deliberate.** The two answer
different questions and a single SOP cannot do both well. This one answers *"did THIS order just
land?"* the moment it happens. Reconciliation answers *"what is the state of the whole day?"* once,
in one digest, including orders that never paid. Collapsing them would either spam the owner with a
per-order message that never mentions the unpaid ones, or delay every confirmation to 21:00.

## Steps

1. **Recall open references**: Use memory_recall to list every payment reference logged for the shop
   that has not yet been confirmed (order number, amount, reference key). If none, stop here without
   sending anything. Most runs end at this step, which is what makes a per-minute cadence affordable.
   Do NOT recall the mint, and do not expect one. It is a fixed constant of this shop, stated in the
   solana-pay skill and pinned in `pay_link.py`. A reference key identifies a settlement on its own.
   The evening SOP used to recall the mint here and that made the memory store a READ path for a
   funds-critical constant while the skill's step 6 was the matching WRITE path; that pair let a
   stale mint survive a corrected skill file on 2026-08-06. Closing one side and leaving the other
   open closes nothing, so neither side recalls it now.
   - tools: memory_recall
2. **Check settlement**: For each open reference, call payment_watch to ask whether a payment
   carrying that reference key has settled. payment_watch conjoins amount, mint, destination and
   reference, so a payment that matches the reference but not the amount is NOT a settlement.
   - tools: payment_watch
3. **Filter to the newly settled**: Read `confirmed-payments.jsonl` in the workspace. Drop any
   reference already recorded there. What remains is the set that settled since the last run.
   If that set is empty, stop here without sending anything.
   This step is what stops a per-minute poll from re-announcing the same order 1,439 more times. The
   ledger file rather than memory is deliberate: it is append-only, a human can read it, and it
   survives a restart. A counter held only in process memory stops being a bound the moment the unit
   restarts, which is the same failure the x402 gate's daily cap had to solve.
   - tools: shell
4. **Announce each one**: For each newly settled reference, send ONE short message to the owner's
   channel naming the order number and the amount, in the shop's language. Never claim an order paid
   without a payment_watch confirmation from step 2. Do not summarise, do not batch, and do not
   mention orders that are still open: this message exists to mark a single moment, and the daily
   digest already covers the rest.
5. **Record the announcement**: Append one JSON line per announced reference to
   `confirmed-payments.jsonl`: the UTC timestamp, the order number, the amount, the reference key
   and the settlement signature. Append AFTER the message is sent, never before, so a failure
   between the two re-announces rather than silently swallowing a confirmation. Re-announcing is a
   visible, correctable annoyance; a swallowed confirmation is invisible and tells the owner an
   order never paid.
   - tools: shell

## What this does not do

It does not refund, and it cannot. It does not decide the amount; the amount is set when the pay
link is minted and is verified against the chain here, not re-derived. It does not touch the mint.
And it does not claim anything the chain has not already confirmed.
