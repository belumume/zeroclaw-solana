# Node earnings report

Reports the DePIN node's x402 earnings once a day. The node sells its device-signed feed per
request over x402; this SOP tells the owner what it sold. Read-only: no funds move.

## Steps

1. **Summarize sales** — Run the earnings summarizer over the x402 ledger and capture its one-line output.
   - tools: shell
2. **Report to the owner** — Send the summary as a channel message, framed plainly (e.g. "Your node sold N readings today and earned X USDC over x402."). If there were no sales, say so.
