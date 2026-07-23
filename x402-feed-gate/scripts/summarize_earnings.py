#!/usr/bin/env python3
"""Summarize the x402 earnings ledger for the agent's channel report.

Reads x402-earnings.jsonl (one settled sale per line) and prints a one-line
human summary the ZeroClaw agent relays to the owner: sales count + total
earned today and all-time. Stdlib only.

Usage: python3 tools/summarize_earnings.py [ledger_path] [utc_day]
"""
import json
import sys
import time

path = sys.argv[1] if len(sys.argv) > 1 else "x402-earnings.jsonl"
today = int(sys.argv[2]) if len(sys.argv) > 2 else int(time.time() // 86400)

rows = []
try:
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
except FileNotFoundError:
    print("No feed sales recorded yet.")
    raise SystemExit(0)

today_rows = [r for r in rows if r.get("day") == today]
tot = lambda rs: sum(int(r.get("amount", 0)) for r in rs)  # base units (6 dp)
usd = lambda a: f"{a/1_000_000:.2f}"
print(
    f"x402 feed sales: today {len(today_rows)} reads / {usd(tot(today_rows))} USDC; "
    f"all-time {len(rows)} reads / {usd(tot(rows))} USDC."
)
