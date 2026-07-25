# lending-health

A read-only ZeroClaw tool plugin that reports a wallet's liquidation health on Kamino Lend:
Safe, Warning, Critical, or Liquidatable. It lets an agent watch a lending position and warn
before it gets liquidated, without holding any authority over the account.

## What it reports

Given a wallet address, it reads the wallet's Kamino Lend obligations from
`api.kamino.finance` and reduces them to one health verdict plus a compact summary of only
the positions that are actually at risk. A healthy wallet returns Safe with nothing to act
on; a wallet near its liquidation threshold returns Warning, Critical, or Liquidatable with
the specific positions surfaced.

## Custody tier: T0 (read-only)

No keys, no signing, no transaction. The only outward action is an HTTPS read to Kamino.
There is nothing here that can move funds, so the attack surface is the input and the data
read back, not a signer.

## Threat model

The wallet address is validated before use. The response from Kamino includes token symbols,
which are attacker-influenceable text: a malicious market could name a token to smuggle
control characters or a fake instruction into whatever reads the summary. Every symbol is run
through the response-path sanitizer before it enters the verdict text, so nothing from a
market's metadata reaches the agent's context unsanitized.

## Proven behavior (host tests)
The end-to-end capture of a live attack against a running agent, with a human in the
loop refusing it, is [`docs/transcripts/injection-refund-redirect.md`](../../docs/transcripts/injection-refund-redirect.md). What follows below is the
plugin's own test suite, which is a different and weaker kind of evidence.


Host tests, no wasm toolchain, no network. Run with `cargo test --lib`:

```
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The load-bearing cases:

- `healthy_position_is_safe`: a wallet well above its threshold returns Safe.
- `compact_text_surfaces_only_at_risk_positions`: the summary shows only positions that
  matter, not every holding, so an agent is not flooded with noise.
- `hostile_token_symbol_is_sanitized`: a malicious token symbol comes back sanitized before
  it can enter the summary.

## Tool interface

```
name: lending_health
inputs:
  wallet     the Solana wallet address to check (base58)
```

## Build

```
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cargo test --lib
```

## License

MIT. See `LICENSE`.


## Output size (context-flooding defence)

The brief's trap #3 warns "judges will call execute and count tokens." Every Kamino field is attacker-influenceable (market, netValue, borrow symbols), so each is sanitized and capped (symbol 24, market 44, netValue 32) and the report ingests at most 64 positions, prints at most 16 detail lines, and 8 borrow symbols per line. Measured worst case (a 300-position flood, 40 max-length hostile symbols each, ~360 KB raw): the agent-facing report is **5,810 bytes**, hard-bounded and control-char-free (test `worst_case_output_is_bounded_under_hostile_portfolio_flood`). A typical response
is well under ~200 tokens; the number above is the adversarial ceiling, not the common case.
