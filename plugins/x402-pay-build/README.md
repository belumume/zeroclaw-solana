# x402-pay-build

Decide whether an x402 `402 Payment Required` challenge describes a payment the operator
authorised. If it does, hand the arguments to `allowance-spend-build`, which builds the unsigned
transaction. This plugin holds no wallet, signs nothing, and builds no transaction.

It is the buyer half of the loop whose seller half is `x402-feed-gate` in this same repo: that gate
sells a DePIN reading per request, and this decides whether to buy one.

## What it does

Given a 402 challenge, it walks the `accepts[]` menu and, for each tier, checks the seller's terms
against the operator's own configuration:

| the challenge says | checked against | refused when |
|---|---|---|
| `payTo` | `__config.receiver` | it names any other address |
| `asset` | `__config.mint` | it is denominated in another token |
| `network` | `__config.network` (CAIP-2) | a matching payee on a different chain |
| `amount` | `__config.max_amount` | over the ceiling, zero, or not plain digits |
| `scheme` | `exact` | anything else, rather than attempted |
| `extra.memo` | 1..=96 bytes of `[A-Za-z0-9._-]` | it carries something this will not echo |

With no `tier` argument it takes the **cheapest** tier that matches. A refusal names every tier it
rejected and why, because a bare "no tier matched" on a money path sends the operator to the wrong
place.

The authorised values it returns are read from **config**, not copied from the challenge, even
though the equality check above means they are identical. That is deliberate: it makes a later edit
weakening the comparison fail loudly here rather than silently adopt the seller's string.

## Why the payee check is the whole point

The spend is bounded on-chain by the Solana Foundation Subscriptions & Allowances delegation, which
enforces the cap, the period and the expiry. **It bounds the amount. It does not bound the payee.**

So a hostile or compromised seller does not need to ask for too much. It asks for the right amount
and names its own address, and every on-chain control passes. The agent reading that challenge is
also the party an injected challenge influences, so it cannot be the party that decides the payee.

This plugin is the layer where that is caught, off-chain, before anything is built. It is also why
`__config` is the only source for those five fields: a top-level `receiver` in the tool arguments is
**refused by name**, not ignored, because an ignored argument is the worst outcome: the caller
believes it took effect, the payment goes elsewhere, and nothing in the output says which value won.

## Custody tier: T1 (decides only; builds and signs nothing). Secrets held: None.

Narrower than T1 requires. The plugin's output is an argument object, not transaction bytes, so it
never touches a transaction at all. The spend is bounded three more times after it:

1. `allowance-spend-build` reads the delegation on-chain and fails closed unless the agent is the
   delegatee. It returns an **unsigned** transaction, every signature slot empty.
2. `scripts/pay_x402_certified.py` re-derives payee, mint and funding delegation from the **final
   serialized bytes** against the same operator configuration, before the host signs. An argument
   altered between the two tool calls is refused there.
3. The audited on-chain program rejects an over-cap transfer with custom error `0x12c`, so a fully
   prompt-injected agent still cannot exceed the allowance.

The declared capability set in `manifest.toml` is machine-checked against the compiled component's
import table by `scripts/check-custody-tier.py`, which runs in CI.

## Threat model

**The challenge is attacker-controlled input.** It arrives over the network from the party being
paid. Every field is treated as hostile:

- `description` is the only seller-authored text that reaches the operator. It is passed through
  `sanitize_onchain` (structural stripping, 120-character cap), then capped again at 120 **bytes**,
  then `label_untrusted`, then printed on its own line prefixed `seller says`, so nothing the seller
  wrote can be mistaken for this tool's own finding. Both caps are load-bearing: the character cap
  alone leaves 120 astral-plane codepoints at 480 bytes, which is four times what the output ceiling
  below is denominated in.
- `memo` is the one value adopted verbatim, which is why it is bounded on both axes, a byte cap and
  a character allowlist, before it is echoed into a transaction.
- `challenge_url` must be `https`. A challenge names where money goes; reading it over a channel
  anyone can rewrite makes the seller's answer whatever the network says it is.
- `challenge_body` and `challenge_url` are mutually exclusive. They are different trust stories, and
  quietly preferring one hides which bytes were actually checked.

**Decimals are read from the chain, not configured and not taken from the seller.** x402 prices in
atomic base units; `allowance-spend-build` takes UI units and refuses raw amounts by design. The
conversion needs the mint's `decimals`, so it is read from the mint account with the account's owner
checked before decoding. A configured decimals that disagreed with the mint would silently produce
the wrong amount by a factor of ten. Nothing defaults: an unreachable RPC, a missing mint, or an
implausible decimals is a refusal.

The conversion itself is integer arithmetic on the digit string, never a float, because a float
silently rounds a large `u64` and this is a money field.

**What this does not decide.** Whether the resource is worth buying. The ceiling and the payee are
the operator's judgement, expressed in config; this enforces them.

## Prompt injection fails closed (host tests)

A seller redirecting payment to its own wallet, at the correct price, in the correct token, on the
correct network, so every on-chain control would pass:

```
REFUSAL: no offered tier matches the operator's configuration (tier 0: pays
"AttackerWa11etAttackerWa11etAttackerWa11et1", and the operator configured
"C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ". A challenge is written by the party
being paid, so a redirected payee is within cap and still theft)
```

Covered by name in `src/pay.rs`:

- `a_redirected_payee_is_refused`
- `a_swapped_mint_is_refused`
- `a_different_network_is_refused_even_with_the_right_payee`
- `a_hostile_description_is_neutralised_rather_than_adopted`
- `a_hostile_memo_is_refused_rather_than_echoed`
- `the_authorised_values_come_from_config_not_the_challenge`

and in `src/args.rs`, `every_config_field_is_refused_at_the_top_level_by_name`, one case per field.

## Output size (judges call execute and count tokens)

Ceiling **1283 bytes**, derived from named parts rather than read off one fixture: `compose::OUTPUT_MAX`
sums the fixed prose and every attacker-influenced field at its cap: `amount` at `u64::MAX` against a
zero-decimal mint, 44-character addresses, a 96-byte memo, and a 120-byte description carrying the
injection label.

Measured against it, with every field at its ceiling: **1280 bytes** all-ASCII
(`the_worst_case_output_is_bounded_and_control_character_free`, which also asserts the output is free
of control characters) and **1277 bytes** when every seller-controlled field is filled with 4-byte
codepoints (`the_worst_case_output_is_bounded_under_multibyte_codepoints`).

Both numbers matter, because the caps used to count characters while this ceiling counts bytes: the
same multibyte input measured **1552 bytes** through the character-cap-only path, which
`the_character_cap_alone_does_not_bound_the_description_in_bytes` keeps as a permanent control. Run
`cargo test -- --nocapture worst_case` to re-derive all three.

### Refusal size, which is the OTHER output path

Nothing above bounds a REFUSAL, and this plugin refuses far more often than it authorises. A
refusal echoes the challenge field it rejected, that string lands in `ToolResult::error`, and it
reaches the agent's context exactly as the summary does.

Provenance INVERTS there, which is why the success path's reasoning does not carry over. "`payTo`
is an address, so it is 44 ASCII bytes" is true of a tier this tool ACCEPTS and exactly backwards
on the branch that fires BECAUSE the field did not match: nothing has validated the shape of a
value at the moment it is being rejected for its shape. Every seller-controlled echo is now capped
on both axes, measured rather than asserted:

| echoed value | measured | what was there before |
| --- | --- | --- |
| `scheme`, `payTo`, `asset`, `network`, non-digit `amount` | 61 B each | uncapped; 252 B through a character cap alone |
| all-digit `amount` that overflows `u64` | 63 B | uncapped; the charset check is not a size check, and 40,000 nines pass it |
| `challenge_url` refused as non-https | 61 B | uncapped |
| `serde` arguments error | 118 B | uncapped; 8,061 B raw |
| the 402 body refused as not-a-v2-challenge | 118 B | uncapped; 8,058 B raw |
| `RpcError` while reading the mint's decimals | 198 to 199 B | uncapped; 8,009 to 8,033 B raw |

Bounding each field is not enough on its own. `authorise` joins one refusal per offered tier and
`accepts` carries no length cap, so a bounded per-tier message times an unbounded tier count is
still unbounded: measured at **50,653 bytes** for a 200-tier challenge before the count was
bounded, and **2,118 bytes** after, with the tiers not named still counted in the message
(`a_hostile_tier_count_cannot_multiply_a_bounded_refusal`).

`x402Version`, the requested tier index, the over-ceiling amount and the rejected memo are
deliberately NOT echo-bounded, each for a reason stated at its site: the first three render
integers, and the memo branch reports its LENGTH and never its content, which is the one thing a
refusal for a bad nonce must not do.

Every figure above is printed by the test that asserts it:

```
cargo test --locked -- --nocapture --test-threads=1 2>&1 | grep MEASURED
```

## Tool interface

`x402_pay_build`

```json
{
  "challenge_body": "the 402 response body as JSON text, if you already fetched it",
  "challenge_url": "https URL to GET the challenge from; mutually exclusive with the body",
  "tier": 0
}
```

Omit `tier` to take the cheapest matching option. On success the output is an operator-readable
summary followed by the exact `allowance_spend_build` arguments:

```json
{"delegation": "...", "amount": "0.4", "receiver": "...", "memo": "x402-nonce-0001"}
```

Those four field names are `allowance-spend-build`'s own `parameters_schema`.
`scripts/check-spend-args-agreement.py` reads them out of the consumer and requires this producer to
emit what the consumer declares, so a rename there fails at the gate rather than at runtime.

## Config keys (jailed `config_read` section)

| key | required | what it is |
|---|---|---|
| `receiver` | yes | the payee wallet the operator will pay, and no other |
| `mint` | yes | the SPL mint the operator will pay in |
| `network` | yes | CAIP-2 `namespace:reference`; the friendly `solana-devnet` spelling is v1-only |
| `delegation` | yes | the funding delegation account the spend draws on |
| `max_amount` | yes | ceiling in atomic base units, as a decimal string so a JSON number cannot lose precision |
| `rpc_url` | no | https RPC override; a plain-http value is dropped rather than honoured |

No private key is ever read. Every required key has no default: a missing one is a refusal naming
the key, and a `max_amount` of `0` refuses with "authorises nothing" rather than passing as falsy.

## Build

```
cargo test --locked                                  # 70 host tests, no network
cargo clippy --all-targets --locked -- -D warnings
cargo build --target wasm32-wasip2 --release
```

Every decision lives in `args.rs`, `pay.rs`, `resolve.rs` and `compose.rs`, all host-tested with the
RPC mocked. `component.rs` is the wasm shim and owns only the two things that cannot be tested
without a runtime: one HTTPS GET and one RPC transport.

## License

MIT. See the repository root.
