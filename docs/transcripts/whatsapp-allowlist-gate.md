# The WhatsApp allowlist gate, measured both ways

Anonymised. No phone numbers, contact names, or group names appear here or in any
artifact this links to.

A deny-by-default claim is only worth the negative half. It is easy to show an agent
answering someone it likes; the question a custody reviewer actually has is whether it
stays silent for someone it does not. So we measured the same sender, in the same chat,
across a single config change, and let the two outcomes stand side by side.

## Setup

The shop runs on WhatsApp Web under `mode = "personal"` with `dm_policy = "allowlist"`,
`group_policy = "ignore"`, `mention_only = true`, and a deliberately non-matching
`allowed_groups` entry as a second layer. The allowed senders are the entries of
`peer_groups.whatsapp_shop.external_peers`.

The enforcement lives in the host, not in our code. In `whatsapp_web.rs`, a direct message
under the allowlist policy is checked against the resolved peer set, and a sender that does
not resolve is logged and dropped before the agent is ever invoked. Nothing downstream gets
a chance to be persuaded, because nothing downstream runs.

## The measurement

One real customer account, one chat, two states, on 2026-07-25 while the shop was still
hosted on the operator's laptop. The only variable changed was whether that account appeared
in the allowlist.

| time | allowlist state | message sent | outcome |
|---|---|---|---|
| 06:09 | sender **removed** | `Olá! Quero fazer um pedido de R$ 30.` | delivered, **no reply**, still silent 6 minutes later |
| 06:14 | sender **restored** | `Oi, ainda posso pedir R$ 30?` | replied in about 60 seconds |

The reply in the allowed state:

> Sim, com certeza! R$ 30 na taxa de 5,0827 (BCE, 24/07/2026) = 5,90 USDC.
> https://zeroclaw-shop-pay.pages.dev/?u=…

which is arithmetically correct (30 / 5.0827 = 5.9024), fully in Portuguese including the
rate source rendered as BCE rather than ECB, and carries a tappable pay-page link rather
than a raw `solana:` URI. Decoding that link yields the recipient constant from config,
`amount=5.90`, the Circle devnet USDC mint, a fresh reference, and `message=Pedido`.

The denied message was not rejected, bounced, or answered with an error. It was delivered
to the account and then ignored, which is the correct shape: a stranger messaging this shop
learns nothing about it, not even that a bot is present.

## The refusals, log-confirmed

The paragraph above used to close by admitting that the attribution was behavioural rather
than log-confirmed, because the host's `not in allowed list` warning could not be found on
the daemon's stdout. That was a search failure, not an absence. The warning is emitted
through the host's own structured log rather than stdout, and it lands in
`~/.zeroclaw/data/state/runtime-trace.jsonl`. Reading the right sink turns the negative half
of this claim from an inference into a record.

On 2026-07-27, on the ARM node, that trace carries thirteen refusals between 03:00:31Z and
12:00:41Z, every one of them at `whatsapp_web.rs:2096` and every one at `WARN`. Thirteen is the
count of distinct event ids: a plain grep returns sixteen lines because the live trace and its
rotated temporary files overlap, and counting those would have overstated it by three. One record
in full, unedited apart from line wrapping:

```json
{ "@timestamp": "2026-07-27T10:51:09.227Z",
  "attributes": { "_file": "crates/zeroclaw-channels/src/whatsapp_web.rs", "_line": 2096 },
  "event": { "action": "note", "category": "internal" },
  "message": "message from unrecognized sender not in allowed list (candidates_count=2)
              (sender is LID; resolved phone did not match any allowlist entry)",
  "severity_text": "WARN", "service": { "name": "zeroclaw", "version": "0.8.3" } }
```

They arrive in two shapes, and the difference between them is the interesting part:

| shape | count | what it means |
|---|---|---|
| `candidates_count=1`, no address diagnostic | 9 | a plain phone-address sender, resolved, absent from the allowlist |
| `candidates_count=2` plus `sender is LID; resolved phone did not match any allowlist entry` | 4 | a linked-identity sender whose resolution **succeeded**, still absent from the allowlist |

The second shape is worth separating out. WhatsApp increasingly addresses senders by a linked
identity rather than a phone number, and there is a known upstream defect where such a sender
cannot be matched against a phone-shaped allowlist at all. That defect produces a different
message, naming a resolution that returned nothing. These records are the other branch: the
identity resolved to a phone, and the phone was then refused on its merits. So the gate is
not accidentally denying everyone because it cannot read the sender. It is reading the sender
correctly in both address formats and refusing on the allowlist.

Thirteen refusals over eight hours, spanning a daemon restart at 10:54Z, is also the shape a
liveness claim wants: the channel was up and reachable throughout, and every message that
reached it was disposed of deliberately.

## The admit side, on the same host, the same day

The refusals above were all produced by an allowlist that named the shop's own number rather
than the customer's. A shop is never its own inbound sender, so that entry could never match
and the channel refused everyone. That is fail-safe, and it is also not the claim the docs
make, so it was corrected: the customer was added alongside the existing entry and the daemon
restarted at 12:08:58Z. The entry was re-read after the restart rather than assumed, because
this host rewrites `config.toml` at startup and has silently restored entries mid-test before.

The last refusal landed at 12:00:41Z, eight minutes before that restart. A real order was then
sent from the same account, in the same chat, with nothing changed but the allowlist:

> `Oi! Quero fazer um pedido de R$ 45, por favor.`

The reply arrived in the same minute:

> R$ 45,00 na cotação de 5.0827 BRL/USD (ECB, 2026-07-24) = 8.85 USDC
> (considerando 1 USDC = 1 USD).

which is arithmetically correct, since 45 divided by 5.0827 is 8.8534, and the pay link it
carries ends in `&lang=pt`, so the Portuguese path is the one a Brazilian customer actually
gets rather than one that merely exists in the code.

The negative half of that observation is the part worth stating: **no refusal record was
written for it.** The trace still ends at 12:00:41Z. So the admit is confirmed twice over, by
the reply and by the absence of the warning that every denied message produces.

## What this does and does not establish

The allowlist is load-bearing in both directions, on the current host, with the host's own
attribution on the deny side and a live order on the admit side, separated by one config
change and eight minutes. Same account, same chat, same policy, only the list moved.

Two honest limits remain. First, during the 2026-07-25 window the host rewrote `config.toml`
at startup and restored one of the two real entries, so that earlier allowlist was narrowed
rather than emptied; the customer still received no reply, which is consistent with the gate
working, but a fully empty allowlist was not what was under test then. Second, the deny
records were produced by an allowlist that admitted nobody, so they demonstrate that a
non-matching sender is refused and attributed, not that this specific customer would be
refused if some other entry were present. The admit measurement covers the converse and the
two together bracket the policy, but neither is a substitute for the other.

The group half of the policy was deliberately **not** exercised live. `group_policy =
"ignore"` is verified at the source level instead, because the failure it prevents already
happened once to real people, and reproducing it to generate a screenshot would repeat that
harm for no additional evidentiary value.

## Why the policy is set this way

The default posture was the opposite. Under `mode = "business"` the chat-policy block is
gated behind a personal-mode check, so `dm_policy` and `group_policy` validate and are then
never consulted; separately, an empty `allowed_groups` returns permitted rather than denied.
Both defaults are open, and they compound. That is reported upstream as
[issue #9348](https://github.com/zeroclaw-labs/zeroclaw/issues/9348) with a fix offered.

This is the same shape as two other findings in this build: a setting that validates
cleanly and is never read, and an empty collection that means permit-all rather than
deny-all. A submission that moves money should assume that shape exists somewhere in its
stack and go looking for it, rather than trusting that a configured value is an enforced
one.
