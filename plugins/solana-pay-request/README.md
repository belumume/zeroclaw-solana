# solana-pay-request

A ZeroClaw tool plugin that turns a payment intent ("charge table 4 for 25 USDC")
into a Solana Pay transfer-request URL and a QR-ready payload a customer's wallet
scans to pay. It holds no wallet, no key, and no config, and it makes no network
call: it is pure computation. Given a recipient and an optional amount, SPL mint,
reference key(s), label, message, and memo, it validates every field and builds a
`solana:` URL faithful to the Solana Pay spec (docs.solanapay.com/spec).

The demo: DM your agent "charge table 4 for 25 USDC", the agent resolves USDC to
its mint and calls this tool, and a scannable Solana Pay QR appears in the chat.

## What it produces (Solana Pay transfer request)

One string, always, in the spec's transfer-request grammar:

```
solana:<recipient>?amount=<amount>&spl-token=<mint>&reference=<ref>&label=<label>&message=<message>&memo=<memo>
```

- `recipient` is the base58 address of the recipient's NATIVE wallet, in the URL
  path. Per the spec the payer's wallet derives the associated token account, so
  an ATA "must not be used" as the recipient.
- `amount` is a non-negative decimal in UI units (`25` = 25 USDC, `0.5` = 0.5 SOL),
  never lamports or raw base units. Omit it to let the payer enter the amount.
- `spl-token` present makes it an SPL transfer of that mint; absent makes it SOL.
- `reference` is one or more read-only tracking keys (an order or client id).
- `label` and `message` are display-only (the wallet shows them, they are not
  written on-chain); `memo` is written ON-CHAIN with the transfer.

For the demo above the tool returns (measured: 373 bytes, roughly 120 tokens):

```
solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=25&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&memo=table%204
```

wrapped in a compact JSON envelope `{"url", "qr_payload", "summary"}`. `qr_payload`
equals `url` on purpose: a Solana Pay QR encodes the URL verbatim, so the field is
the exact string a QR encoder consumes, letting the host render it without
re-deriving anything. `summary` is a one-line human readout (amount, asset, and a
shortened recipient), with any echoed memo/label marked untrusted (see below).

## Faithful to the spec (validated against its own examples)

Two of the tests reproduce the spec's own example URLs byte-for-byte, which is the
strongest correctness check available without a wallet:

- SPL: `solana:mvines...?amount=0.01&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`
- SOL: `solana:mvines...?amount=1&label=Michael&message=Thanks%20for%20all%20the%20fish&memo=OrderId12345`

One spec nuance resolved deliberately: spaces are encoded as `%20`, never `+`. The
spec says wallets decode with `decodeURIComponent`, under which `+` would decode to
a literal plus, not a space, so `%20` is the only encoding that round-trips (and it
matches the spec's own examples).

## Custody tier: T0 (zero secrets, zero network)

This heading read `T0/T1` until a gate on the tier declaration flagged it. Two tiers is
not a declaration, and the brief asks each showcase for one. T0 is the correct answer:
the plugin reads, computes and returns, and it never builds a transaction, which is what
T1 means elsewhere in this suite.

This plugin is the safest tier in the suite:

- It holds NO wallet and NO key. There is no seed, no signer, nothing to redact.
  The whole argument and result surface is free of key material by construction.
- It makes NO network call and reads NO config. `permissions = []` in the
  manifest is the honest declaration: a compromised copy of this plugin has zero
  I/O surface. It cannot move funds, sign anything, fetch anything, or leak a key,
  because it has none of those capabilities. That last sentence used to rest on
  reading the source. It is now read out of the compiled component instead: the
  shipped `.wasm` imports no `wasi:http`, no `wasi:sockets` and no
  `wasi:filesystem`, so there is no host function through which it could reach any
  of them. Re-derive with `python3 ../../scripts/check-custody-tier.py`.
- The output is a payment REQUEST, not a signed transaction. Nothing it emits can
  authorize a transfer; the payer's own wallet builds, signs, and sends the
  transaction after scanning the QR.

## Threat model

`execute` takes attacker-influenceable arguments (an LLM agent driven by a possibly
prompt-injected chat), so everything is validated fail-closed and the URL structure
is fully controlled by this module, never by attacker free text:

1. Arguments parse with `serde(deny_unknown_fields)`; a smuggled extra field
   refuses the whole call.
2. `recipient` is validated as a 32-byte base58 pubkey and re-emitted canonically.
   It comes from its OWN typed field, so a hostile label or memo can never become
   the recipient. A recipient that is injection text ("IGNORE PREVIOUS ...") is
   simply not a valid pubkey and is rejected.
3. `spl_token` and every `reference` are validated as base58 pubkeys; `reference`
   is capped at 8 keys so an attacker cannot flood the URL (or the eventual
   transaction) with unbounded read-only accounts.
4. `amount` is validated as a canonical non-negative decimal (a digit before the
   `.`, no sign, no scientific notation, bounded integer and fractional digits) and
   preserved VERBATIM, never round-tripped through a float that would corrupt token
   precision.
5. `label`, `message`, and `memo` are run through the shared response-path
   sanitizer (control, bidi, and zero-width characters stripped, length capped),
   then PERCENT-ENCODED into the URL. This is the core defense: a memo of
   `"table 4&recipient=<attacker>&amount=999"` becomes a single percent-encoded
   memo value (`%26recipient%3D...`), so it can never break out to inject a second
   `recipient`, `amount`, or `spl-token` parameter or a different path.
6. Any echoed free text in the human summary passes through `label_untrusted`, so
   on-chain-sourced injection framing is labeled untrusted rather than re-entering
   the agent's context as if it were an instruction (OWASP LLM01, response path).

The percent-encoding uses the RFC 3986 unreserved set only (stricter than
`encodeURIComponent`), which is safe because a wallet's `decodeURIComponent`
decodes the extra escapes back to the same characters.

## Prompt injection fails closed (host tests)
The end-to-end capture of a live attack against a running agent, with a human in the
loop refusing it, is [`docs/transcripts/injection-refund-redirect.md`](../../docs/transcripts/injection-refund-redirect.md). What follows below is the
plugin's own test suite, which is a different and weaker kind of evidence.


These are the plugin's own host tests, with no wasm toolchain and no network. Run
them with `cargo test --lib`:

```
running 41 tests
test pay::tests::amount_as_json_number_is_accepted ... ok
test pay::tests::amount_exact_decimal_string_is_preserved ... ok
test pay::tests::bad_reference_is_rejected ... ok
test pay::tests::bad_spl_token_is_rejected ... ok
test pay::tests::bare_recipient_has_no_query ... ok
test pay::tests::bidi_and_zero_width_in_label_are_stripped ... ok
test pay::tests::control_chars_in_memo_become_a_single_space ... ok
test pay::tests::debug_is_available_and_holds_no_secret ... ok
test pay::tests::demo_charge_table_4_for_25_usdc ... ok
test pay::tests::demo_output_is_compact ... ok
test pay::tests::double_dot_amount_rejected ... ok
test pay::tests::every_reserved_char_in_memo_is_percent_encoded ... ok
test pay::tests::hostile_memo_cannot_inject_a_second_recipient_or_param ... ok
test pay::tests::injection_framing_in_memo_is_labeled_untrusted_in_summary ... ok
test pay::tests::leading_dot_amount_rejected ... ok
test pay::tests::leading_zeros_amount_rejected ... ok
test pay::tests::missing_recipient_fails_closed ... ok
test pay::tests::multibyte_memo_encodes_utf8_bytes_without_panic ... ok
test pay::tests::negative_amount_rejected ... ok
test pay::tests::no_amount_summary_says_payer_entered ... ok
test pay::tests::pure_hidden_payload_field_is_dropped ... ok
test pay::tests::qr_payload_equals_url ... ok
test pay::tests::recipient_injection_string_is_rejected ... ok
test pay::tests::recipient_is_re_encoded_canonically_trimming_whitespace ... ok
test pay::tests::reference_single_and_array_both_accepted ... ok
test pay::tests::scientific_notation_amount_rejected ... ok
test pay::tests::sol_transfer_has_no_spl_token_param ... ok
test pay::tests::spec_example_sol_transfer_matches_verbatim ... ok
test pay::tests::spec_example_usdc_transfer_matches_verbatim ... ok
test pay::tests::spl_token_hyphenated_key_alias_accepted ... ok
test pay::tests::the_byte_cap_leaves_an_ordinary_ascii_request_untouched ... ok
test pay::tests::the_character_cap_alone_does_not_bound_the_output_in_bytes ... ok
test pay::tests::the_published_ceiling_is_derived_from_the_prose_it_describes ... ok
test pay::tests::the_untrusted_label_is_the_length_the_output_ceiling_assumes ... ok
test pay::tests::too_many_fractional_digits_rejected ... ok
test pay::tests::too_many_references_rejected ... ok
test pay::tests::trailing_dot_amount_rejected ... ok
test pay::tests::unknown_field_fails_closed ... ok
test pay::tests::worst_case_output_is_bounded_under_multibyte_codepoints ... ok
test pay::tests::worst_case_output_is_bounded_with_every_field_at_its_cap ... ok
test pay::tests::zero_amount_is_spec_valid ... ok

test result: ok. 41 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

What the load-bearing cases prove:

- `hostile_memo_cannot_inject_a_second_recipient_or_param`: a memo that embeds
  `&recipient=<attacker>&amount=999999&spl-token=<attacker>` yields a URL with
  exactly ONE `amount`, ONE `spl-token`, and the original recipient in the path;
  the injected copies come out percent-encoded inside the memo value and are inert.
- `every_reserved_char_in_memo_is_percent_encoded`: `& = ? # / % + space` each
  encode to `%26 %3D %3F %23 %2F %25 %2B %20`.
- `bidi_and_zero_width_in_label_are_stripped` / `pure_hidden_payload_field_is_dropped`:
  RLE/RLO, zero-width, and format characters are removed; a field that is nothing
  but hidden characters sanitizes to empty and never appears in the URL.
- `recipient_injection_string_is_rejected`: an injection phrase in the recipient
  field is not a valid pubkey and is refused before any URL exists.
- `spec_example_{usdc,sol}_transfer_matches_verbatim`: the built URLs are
  byte-identical to the spec's published examples.

## Tool interface

```
name: solana_pay_request
inputs:
  recipient   base58 address of the recipient's native wallet (REQUIRED)
  amount      optional UI-unit decimal ("25", "0.5"); omit to let the payer enter it
  spl_token   optional base58 SPL mint (present = SPL transfer, absent = SOL);
              the URL-style key "spl-token" is also accepted
  reference   optional base58 tracking key(s): a single string or an array
  label       optional display source (store/brand); not written on-chain
  message     optional display note (item/order); not written on-chain
  memo        optional memo written ON-CHAIN with the transfer
output:
  a compact JSON object { url, qr_payload, summary }; url and qr_payload are the
  identical solana: URL (a Solana Pay QR encodes the URL verbatim)
```

## Config keys

None. This plugin reads no config and holds no secrets. `permissions = []`.

## Output size (judges count tokens)

The execute output is a small JSON envelope: 373 bytes for the demo above (roughly
120 tokens), and it scales only with the input URL. There is no unbounded field;
every free-text field is length-capped before it enters the output.

## What you would build next

- A `solana_pay_transaction_request` sibling for the interactive Solana Pay flow
  (`solana:<https-link>`), where a merchant server returns a base64 transaction. It
  needs an HTTPS endpoint, so it is a separate `http_client` plugin, kept distinct
  from this zero-permission one.
- Optional amount rounding to a mint's on-chain decimals, gated behind a single
  cached `getMint` call (again a separate networked plugin, so this one stays pure).

## Build

```
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cargo test --lib          # host tests, no wasm toolchain, no network
```

The pure core (`src/pay.rs`) is host-testable with no wasm toolchain; the
`#[cfg(target_family = "wasm")]` shim in `src/lib.rs` only wires the WIT tool
interface to it.

## License

MIT. See the repository `LICENSE`.
