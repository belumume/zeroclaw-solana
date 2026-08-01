# Node earnings report

Reports the DePIN node's x402 earnings once a day. The node sells its device-signed feed per
request over x402; this SOP tells the owner what it sold. Read-only: no funds move.

## Steps

1. **Summarize sales**: Run `python3 tools/summarize_earnings.py x402-earnings.jsonl` and capture its one-line output. The summarizer lives in your workspace `tools/` directory (channel turns run jailed to the workspace, so use exactly this relative path); the x402 gate writes `x402-earnings.jsonl` into the workspace (set `X402_EARNINGS_LOG` to the workspace path when you run the gate). If the ledger is absent the summarizer prints "No feed sales recorded yet."
   - tools: shell
2. **Report to the owner**: Send the summary as a channel message, framed plainly (e.g. "Your node sold N readings today and earned X USDC over x402."). If there were no sales, say so.
