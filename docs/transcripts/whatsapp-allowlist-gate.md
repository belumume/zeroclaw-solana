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

One real customer account, one chat, two states. The only variable changed was whether that
account appeared in the allowlist.

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

## What this does and does not establish

It establishes, behaviourally, that the allowlist is load-bearing on the live channel: the
same sender with the same text gets a reply in one state and silence in the other, and the
only thing that moved between them was the allowlist.

Two honest limits. First, the attribution is behavioural rather than log-confirmed: the
host's `not in allowed list` warning did not appear on the daemon's stdout during the deny
window, so the A/B is the evidence, not a log line. Second, during the deny window the host
rewrote `config.toml` at startup and restored one of the two real entries, so the allowlist
was narrowed rather than emptied. That the customer still received no reply means the
surviving entry was not theirs, which is consistent with the gate working, but a fully
empty allowlist was not what was actually under test.

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
