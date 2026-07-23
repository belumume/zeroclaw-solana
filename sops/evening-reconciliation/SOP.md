# Evening reconciliation

Reconciles the demo shop's open payment requests against on-chain settlement daily and
reports to the owner's channel. No funds move here; the only fund-touching path (a refund)
sits behind an explicit human checkpoint.

## Steps

1. **Recall open references** — Use memory_recall to list every payment reference logged today for the demo shop (order number, amount, mint, reference key). If none, report "no open orders today" and stop.
   - tools: memory_recall
2. **Verify settlement on-chain** — For each open reference from step 1, call payment_watch to check whether a payment carrying that reference key has settled. Collect the paid set and the still-open set.
   - tools: payment_watch
3. **Report to the channel** — Compose ONE concise message: orders paid today (order #, amount) versus orders still awaiting payment, and send it as the reply. Never claim an order paid without a payment_watch confirmation from step 2.
4. **Append to the orders ledger** — Append one JSON line to `orders-ledger.jsonl` in the workspace recording today's reconciliation: the UTC date, the paid count and total, and the still-open count. This gives the shop a durable daily running-history ledger, the shop-side parallel to the DePIN feed's on-chain sequence. Read-only bookkeeping; no funds move.
   - tools: shell
5. **Refund approval** — Pause for human approval. Only a human may authorize building any refund; the agent must never originate a refund transaction on its own. Any refund the human approves is built downstream under the on-chain allowance cap.
   - kind: checkpoint
