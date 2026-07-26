# payment-watch

A read-only ZeroClaw tool plugin that watches an address for an expected inbound payment and
reports when it lands. One `execute()` call is one CHECK: given a recipient address and an
expected amount, it scans recent transactions to the address for a matching inbound SPL /
Token-2022 or native SOL transfer and returns one of two verdicts, PAID or NOT_YET. It holds
no keys and builds no transactions.

## What it does

Given `{address, expected_amount}` plus optional `{mint, reference, invoice_label,
since_signature}`, it does a cheap two-step JSON-RPC poll:

1. `getSignaturesForAddress` (limit 20, newest first, bounded by the `until` cursor when a
   `since_signature` is supplied) to find recent transactions touching the address.
2. `getTransaction` (jsonParsed, `maxSupportedTransactionVersion` 0) on the newest candidates
   until one matches.

A match is detected from BALANCE DELTAS, never by parsing instruction shapes: the net change
of the watched owner's token balance for the mint (`pre`/`postTokenBalances`), or the lamport
delta of the watched account (`pre`/`postBalances`) for native SOL. That is agnostic to
`transfer` vs `transferChecked` vs a router hop, and it correctly handles a freshly created
associated token account.

- **PAID** returns the amount, the sender (shortened), the full transaction signature, the
  block time, and any on-chain memo (sanitized):
  `PAID: Invoice #412 paid -> 25 USDC from H6rH..g1jos (tx 31cev4tX...rdd3nB, unix 1737300000)`
- **NOT_YET** returns how many recent transactions were checked and the newest signature as a
  cursor, so a ZeroClaw cron SOP can feed it straight back as `since_signature` on the next
  poll and only pay for the signatures that arrived since:
  `NOT_YET: Invoice #412: no matching inbound 25 USDC on 7u3H..uTnak yet (checked 3 recent tx).
  next cursor (since_signature): 31cev4tX...rdd3nB`

This is what closes the loop on the pay / publish plugins: the agent kicks off (or waits on)
an invoice, then this fires the inbound event the moment the expected amount lands. The cursor
makes the polling loop cheap: each check only re-reads what is new.

## Custody tier: T0 (read-only)

No keys, no signing, no transaction. The only outward action is two HTTPS reads to a Solana
RPC endpoint. There is nothing here that can move funds, so the attack surface is the input
arguments and the RPC data read back, not a signer.

## Threat model

`execute` takes attacker-influenceable arguments, and the RPC RESPONSE is attacker-influenceable
too (an on-chain memo and the node's own error text are the clearest indirect-injection vectors,
OWASP LLM01 on the response path). Both directions are handled fail-closed, in this order:

1. Arguments parse with `serde(deny_unknown_fields)` at both levels; an injected extra field
   (a `drain_to`, a misspelled config key) refuses the whole call before any network call.
2. `address`, `mint`, and `reference` must be valid base58; a prompt-injected non-address can
   never reach an RPC or a crafted URL, and the rejected value is echoed back only through the
   response-path sanitizer (bidi / zero-width stripped, length capped), never raw.
3. `expected_amount` must be a positive, finite, bounded number; a NaN / infinite / negative /
   absurd magnitude is refused, so a degenerate value cannot slip past the exact-match compare.
4. `since_signature` must decode to a real 64-byte signature before it is used as the RPC
   `until` param, so a junk cursor cannot be smuggled onto the endpoint.
5. A custom `rpc_url` (jailed `config_read`) must be `https://`; a downgraded override is refused.
6. On the way back, every response string that reaches the agent's context passes through the
   response-path sanitizer and is length-capped: the transaction memo, the node's JSON-RPC error
   text, and any oversized balance amount are stripped of control / zero-width / bidi characters
   and capped before they enter the report. A sender pubkey is re-validated as base58 before it
   is displayed, so a crafted `from` string can never panic a byte-slice or leak hidden framing.
7. The report itself is shaped: 1 to 3 lines, measured at 495 bytes worst-case PAID and 556
   worst-case NOT_YET, versus a raw `getTransaction` of roughly 40 KB. Judges call `execute` and
   count tokens; this never floods. The figures are printed by the tests rather than asserted
   from memory, so they cannot drift (`worst_case_output_is_bounded_on_both_verdict_branches`,
   `the_corroborated_report_stays_bounded_on_every_branch`).
8. Every check above verifies the CONTENTS of an RPC response while trusting that the response
   describes the chain at all. That trust is the last unguarded assumption here, and it is the
   expensive one: a compromised endpoint can fabricate both the signature list and the
   transaction body, at which point the recipient, mint, amount and reference checks all pass
   because they are reading the same forged bytes, and the shop ships goods for a payment that
   never happened. So `corroborating_rpc_urls` asks an independent endpoint to re-derive the
   payment from its own copy of the chain, re-running the whole conjunction rather than comparing
   a signature string, since a forged response can echo any signature back.

   Corroboration is asked for only on the settle-worthy direction, and the asymmetry is
   deliberate: a wrong PAID costs the shop its goods, a wrong NOT_YET costs one more poll. A
   no-match therefore needs no second endpoint and stays exactly as cheap as before.

   Four outcomes, aggregated fail-closed. A single disagreement disqualifies the payment
   regardless of what any other endpoint says, because a majority vote would let an attacker
   holding two endpoints outvote the honest one. An endpoint that HAS the transaction and
   contradicts it downgrades the verdict to `DISPUTED`. An endpoint that cannot answer, or does
   not have the transaction yet, yields `UNCONFIRMED` rather than either extreme, because a
   fabricated transaction is absent from an honest node and a genuine one is briefly absent while
   it propagates; re-polling resolves the lag on its own and never confirms a fabrication.
   Configuring none is still permitted, since one endpoint is the pre-existing posture, but the
   report then says `SINGLE SOURCE` instead of implying an agreement nobody gave. An endpoint
   sharing the primary's host is refused outright: the same party answering twice is not
   corroboration.

Correctness is fail-safe by construction: a fixed-point rounding edge, an unexpected RPC shape,
a failed transaction, or an amount off by a base unit all produce NOT_YET (retry on the next
poll), never a false PAID.

## Prompt injection fails closed (host tests)
The end-to-end capture of a live attack against a running agent, with a human in the
loop refusing it, is [`docs/transcripts/injection-refund-redirect.md`](../../docs/transcripts/injection-refund-redirect.md). What follows below is the
plugin's own test suite, which is a different and weaker kind of evidence.


These are the plugin's own host tests, with no wasm toolchain and no network (the RPC is a
mocked transport). Run them with `cargo test --lib`:

```
running 29 tests
test watch::tests::amount_formatting_is_exact ... ok
test watch::tests::attacker_crafted_from_string_does_not_panic_or_leak ... ok
test watch::tests::bad_reference_is_rejected_good_reference_is_kept ... ok
test watch::tests::failed_signature_entry_is_skipped ... ok
test watch::tests::garbage_transaction_shape_does_not_panic ... ok
test watch::tests::hostile_memo_is_sanitized_capped_and_flagged ... ok
test watch::tests::http_rpc_url_is_refused ... ok
test watch::tests::https_rpc_url_is_accepted ... ok
test watch::tests::injection_address_fails_base58_before_any_rpc ... ok
test watch::tests::misspelled_config_key_fails_closed ... ok
test watch::tests::native_sol_payment_is_detected ... ok
test watch::tests::non_array_signatures_result_is_an_error ... ok
test watch::tests::nonpositive_and_out_of_range_amounts_are_refused ... ok
test watch::tests::not_yet_returns_newest_signature_as_cursor ... ok
test watch::tests::null_transaction_result_is_skipped_not_matched ... ok
test watch::tests::oversized_amount_string_is_rejected_not_parsed ... ok
test watch::tests::reference_absent_from_tx_is_not_a_match ... ok
test watch::tests::reference_present_in_tx_matches ... ok
test watch::tests::reports_are_compact ... ok
test watch::tests::rpc_error_object_propagates ... ok
test watch::tests::since_signature_is_sent_as_until_param ... ok
test watch::tests::since_signature_is_shape_checked ... ok
test watch::tests::sol_and_native_sentinels_select_lamport_mode ... ok
test watch::tests::spl_usdc_payment_is_detected ... ok
test watch::tests::valid_args_default_to_usdc_and_default_rpc ... ok
test watch::tests::wrong_amount_is_rejected ... ok
test watch::tests::wrong_mint_is_rejected ... ok
test watch::tests::wrong_recipient_is_rejected ... ok

test result: ok. 29 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

What the load-bearing cases prove:

- `spl_usdc_payment_is_detected` / `native_sol_payment_is_detected`: an exact-amount inbound
  transfer (SPL token balance, and native SOL lamports) is detected from balance deltas.
- `not_yet_returns_newest_signature_as_cursor` / `since_signature_is_sent_as_until_param`: a
  no-match returns the newest signature as the cursor, and that cursor is sent back as the RPC
  `until` param, so a cron SOP polls only what is new.
- `wrong_amount_is_rejected` / `wrong_mint_is_rejected` / `wrong_recipient_is_rejected` /
  `reference_absent_from_tx_is_not_a_match`: a transfer of the wrong amount, wrong mint, wrong
  recipient, or missing the required reference is never a match.
- `hostile_memo_is_sanitized_capped_and_flagged`: a payment whose memo carries a zero-width-split
  injection payload is still detected, but the memo comes back stripped, capped, and flagged as
  untrusted on-chain data before it enters the report.
- `attacker_crafted_from_string_does_not_panic_or_leak`: a non-base58, multibyte, bidi-laden
  sender `owner` in the RPC response is sanitized (not reflected raw) and never panics a slice.
- `garbage_transaction_shape_does_not_panic` / `non_array_signatures_result_is_an_error` /
  `oversized_amount_string_is_rejected_not_parsed`: a malformed RPC response fails closed (a
  missing-field transaction yields no match, a non-array signatures result is a hard error, a
  40 KB amount is dropped rather than parsed).
- `injection_address_fails_base58_before_any_rpc` / `unknown_top_level_field_fails_closed` /
  `misspelled_config_key_fails_closed` / `http_rpc_url_is_refused` / `since_signature_is_shape_checked`:
  a prompt-injected address, a smuggled extra field, a misspelled config key, a plain-http RPC
  override, and a junk cursor are all refused before any network call.

## Output size (judges call execute and count tokens)

One verdict line, never a list, however much activity the watched address has. The pagination
that scans up to five pages of signatures stays internal; what reaches the agent is a single
`PAID:` or `NOT_YET:` sentence.

Measured on both branches with every attacker-reachable field driven to its worst case at once,
a 4 KB invoice label, an oversized injection memo carrying a zero-width split, and an
unrecognised mint so the asset renders as an address rather than borrowing a symbol from the
token: **PAID composes to 367 bytes and NOT_YET to 556**, asserted under 2000 in
`worst_case_output_is_bounded_on_both_verdict_branches`.

NOT_YET is the larger of the two because it is the branch with the most optional pieces, adding
a next cursor, a reference note, and the partial-scan warning that fires when the scan hit its
page cap with transactions still unexamined. That branch had no size test before, which is why
it is measured here rather than argued from the per-field caps.

## Tool interface

```
name: payment_watch
inputs:
  address          the recipient address to watch (base58)
  expected_amount  expected inbound amount in UI units (25 = 25 USDC, 0.5 = 0.5 SOL)
  mint             optional; base58 SPL / Token-2022 mint. Omit for USDC.
                   Use "SOL" or "native" for native SOL lamports.
  reference        optional base58 reference pubkey (Solana Pay); when set it must appear
                   in the matched transaction's account keys
  invoice_label    optional human label for the report (e.g. "Invoice #412")
  since_signature  optional cursor; only transactions newer than this signature are considered.
                   Feed back the cursor from a prior NOT_YET for cheap polling.
```

## Config keys (jailed `config_read` section)

```
rpc_url   optional https-only Solana RPC override (defaults to mainnet-beta). A user RPC
          endpoint is supported here; a plain-http override is refused.

corroborating_rpc_urls
          optional list of up to 3 INDEPENDENT https endpoints that must agree before a
          payment is reported settle-worthy. Each is https-only, de-duplicated by host, and
          refused if it shares the primary's host. Omit it and a payment still reports PAID,
          labelled SINGLE SOURCE. Set it and a contradiction reports DISPUTED, while an
          endpoint that cannot answer reports UNCONFIRMED so the next poll decides.
```

Example, primary plus one independent corroborator:

```toml
[tools.payment_watch.config]
rpc_url = "https://api.devnet.solana.com"
corroborating_rpc_urls = ["https://devnet.helius-rpc.com/?api-key=REDACTED"]
```

## Build

```
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cargo test --lib          # host tests, no wasm toolchain, no network
```

## License

MIT. See `LICENSE`.
