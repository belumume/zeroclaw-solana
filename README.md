# zeroclaw-solana

Two self-hosted [ZeroClaw](https://github.com/zeroclaw-labs) agents doing real Solana work,
and the plugins, on-chain programs, skills and SOPs they run on.

**Watch it first:** [`.demo-assets/cut/demo-roughcut-v2.mp4`](.demo-assets/cut/demo-roughcut-v2.mp4),
2 minutes 55 seconds, five beats, no slides. Four of the five are live terminal runs rather than
recordings of a result: the injection attack refused with zero tool calls, the feed publishing on
schedule, the claim verifier at 10 of 10 static and 3 of 3 live with the over-cap rejection on
screen, and the x402 gate answering 402 with its nonce visibly incrementing between requests. The
file is committed here rather than linked off somewhere, so it does not depend on anyone else's
retention policy.

**A DePIN node that pays for itself.** An ARM box takes an ambient temperature reading for
Madinah, signs it with a key generated on that box, and lands it in a typed account owned by our
oracle program, where a separate consumer program reads it and acts. The reading comes from a
keyless public weather API on the current host rather than from a physical probe, which the
write-up says too; a Raspberry Pi with a DHT11 is the hardware path and the on-chain half is
identical either way, because what is signed is the value and the device key, not the enclosure. A `systemd` timer keeps it publishing with no
laptop involved. The same node also sells that reading per request over x402, so the machine
earns the gas it spends. You can exercise that yourself against the running node:
`curl https://x402.perfpilot.dev/price` returns an HTTP 402 challenge with two price tiers and a
single-use nonce, and the nonce changes on every request. That endpoint is a live demonstration
rather than evidence: if the node is down you get a gateway error, whereas the on-chain claims
below verify from captured bytes with no network at all.

**A shop terminal that takes payments.** A merchant agent on WhatsApp and Telegram quotes an
order, hands the customer a tappable payment link, and confirms settlement only from the
chain, never from the customer saying so. Confirmation requires the exact amount in base
units, the exact mint, and the watched destination, all read from `pre`/`postTokenBalances`;
the reference is an additional optional condition, not the check itself. A payment of the
wrong amount, or of a token the payer minted themselves, does not settle an order. Brazilian
orders are quoted in BRL at a stated rate and settled in USDC.

Both run on the same ARM node under `systemd --user`, and the two are not equally
observable from outside, so this says which is which rather than leaving you to find out.
The DePIN feed is continuously checkable: it publishes on a timer and every reading lands
on chain, so `verify-proof.py` can go red on it. The shop is a Telegram and WhatsApp client
with no inbound port, and its trace is traffic-driven, so from outside a quiet shop and a
stopped one look identical. That half is asserted here and machine-checked by a `/health`
endpoint on the x402 gate, which asks systemd on the node directly.

Live on-chain evidence, all clickable, is in
[`docs/DEVNET-PROOF.md`](docs/DEVNET-PROOF.md), and `python3 scripts/verify-proof.py`
re-checks every published claim against devnet in one command, stdlib only, nothing to
install. It reports static and live claims separately, and names what it does not cover.

## Start here

| If you want | Read |
|---|---|
| What this is and why it is built this way | [`docs/WRITEUP.md`](docs/WRITEUP.md) |
| To run it yourself | [`QUICKSTART.md`](QUICKSTART.md) |
| Proof it is real, on chain | [`docs/DEVNET-PROOF.md`](docs/DEVNET-PROOF.md) |
| Why each design call went the way it did, including what was rejected | [`docs/DECISIONS.md`](docs/DECISIONS.md) |
| How it is tested, and what each layer cannot catch | [`TESTING.md`](TESTING.md) |
| What an adversarial audit found here, including what is still open | [`docs/AUDIT.md`](docs/AUDIT.md) |
| Ten verified defects found in the HOST this runs on, all reported upstream | [`docs/HOST-SECURITY-AUDIT.md`](docs/HOST-SECURITY-AUDIT.md) |
| The agent refusing an attack, verbatim | [`docs/transcripts/`](docs/transcripts/) |
| To poke the sanitizer yourself, no build needed | [`sanitizer-microworld/index.html`](sanitizer-microworld/index.html) |

## Custody, which is the part that matters

No plugin here holds a key that can move funds. Every plugin that builds a spend emits it
**unsigned**, for a human to approve. One component signs, and naming it is more honest than
the blanket claim: `oracle-publish` holds a fund-less device seed and emits a device-**signed**
transaction with the fee-payer slot left empty, so a reading is attributable to the device
while the signature that actually pays is still the operator's. Spends are additionally
bounded on chain by the audited Solana Foundation Allowances program.

That bound is demonstrated rather than asserted, and the demonstration deliberately does the
opposite of avoiding a key, because avoiding one proves nothing about what happens when an
agent has one. A delegated session key, held by the agent, **signs** an over-cap transfer, and
the audited program rejects it with custom error `0x12c`. The chain refused the transfer; no
plugin, no prompt and no operator had to be right for that to happen. A within-cap transfer
signed by the same key settles normally, which is the control that stops the rejection being
read as the key simply not working.

Read the two sentences above together, because they are easy to mistake for a contradiction.
The **use cases** run no fund-signing key at all. The **cap demonstration** uses one on
purpose, bounded on chain, so the guarantee can be shown failing closed rather than described.

Both transactions are clickable, and one of them opens on a failed transaction on purpose. The
[within-cap transfer settled](https://explorer.solana.com/tx/5qyr7jJi8zb6SjZjnA2QT5C9nuZYgSw6raAefjmWnDDMf3JRgkQX19zssE57EpFSHVCCPfbj5qyxcYSQcfEq9W3Z?cluster=devnet);
the [over-cap transfer was refused on chain](https://explorer.solana.com/tx/3TLSrfWVYdC3hSiAWnyyd7T694bLJQDtdJYQ64EWUsBNDehGc6Kq1veR7xa8Y1BiMdpvfFm3N1dKjDrXF3BEq2ps?cluster=devnet)
with `custom program error 0x12c`. The red error page is the evidence rather than a defect: the
audited program refused a transfer the agent's own delegated key had already signed, and the
transfer that settled is the control that stops the refusal being read as a key that does not
work. Both were served by `api.devnet.solana.com` on 2026-08-01, eight days after they landed.

Retention on public devnet is set by whoever runs the endpoint and has moved before, so the
captured bytes are what this rests on rather than the links. They are in
[`docs/proof-bundle/`](docs/proof-bundle), and `python3 scripts/verify_proof_offline.py`
re-checks the ed25519 signature over the exact serialized message with no network at all. If a
link above has stopped resolving by the time you click it, that command still proves the same
thing.

Human approval is a weak boundary on its own, because the sentence the human reads is one the
model wrote. So the paths with a fixed intent never ask: `scripts/broadcast_certified.py`
re-derives the intent from the exact serialized bytes and refuses an appended transfer, a
swapped program or a spoofed feed before anything leaves the machine. Run that check as a
self-test with `python3 scripts/certify_publish_tx.py`, which puts four injection shapes
through it. Where intent is variable, a spend, the on-chain cap above is what holds, and it
holds whether or not the operator was fooled.

The two use cases run **no T2 fund-signer**. Everything they touch sits at T0 (read-only) or
T1 (builds a transaction the operator must sign), which the brief calls the sweet spot and
which is the honest place for an LLM-driven system to stop.

One T1 component departs from the ladder's "secrets held: none" wording, and it is worth
naming rather than glossing. `oracle-publish` holds a 32-byte device seed. It is fund-less by
construction, and the code asserts that rather than asking to be trusted: the device is added
as a **readonly** signer, and a hard check rejects any message whose fee payer is not signer
index zero. So the device key can attest that a reading came from that device, and it can
never pay a fee or source value. That is a narrower deviation than the ladder's wording
allows for, and a wider capability than "holds no key" would have implied.

## What the two use cases run on

| Component | Job | Tier |
|---|---|---|
| [`oracle-publish`](plugins/oracle-publish) | Device-signed reading into a typed on-chain feed, behind a durable nonce | T1 build, device co-signs |
| [`payment-watch`](plugins/payment-watch) | Confirms a payment only when amount, mint, destination and (when supplied) the Solana Pay reference all match on-chain | T0 read-only |
| [`spl-transfer-build`](plugins/spl-transfer-build) | Unsigned SPL transfers that survive an approval queue via durable nonces | T1 build |
| [`allowance-spend-build`](plugins/allowance-spend-build) | Spends bounded by the audited SF Allowances program | T1 build |
| [`solana-core`](crates/solana-core) | Shared wasm32-wasip2 core: transactions, PDAs, Token-2022, response-path sanitizer | library |
| [`onchain/`](onchain) | `zeroclaw_oracle` and `consumer_example`, Anchor, live on devnet | on-chain |
| [`x402-feed-gate`](x402-feed-gate) | Sells one signed reading per paid request | T0/T1, holds no key |
| [`skills/solana-pay`](skills/solana-pay) | Builds the payment URL. A skill, not a plugin, on purpose | skill |

`solana-pay-request` was built as a wasm plugin and then **demoted to a skill**, because
building a URL is string work and string work does not need a sandbox. The reason first given
for that call was wrong, and the correction is in [`docs/DECISIONS.md`](docs/DECISIONS.md):
the failure that matters is a well-formed URL carrying the wrong recipient, which a sandbox
would not catch, so the guard is a hardcoded invariant in `pay_link.py`. The plugin stays in
the tree as the evidence trail for that call rather than as part of the shipped path.

Three earlier plugins (`token-risk-check`, `lending-health`, `depin-attest`) predate the two
use cases and are **not part of them**. They keep their own READMEs and tests.
`depin-attest` describes a T2 posture and is not run by either use case; `oracle-publish` is
its T1 successor and is what actually publishes the live feed. The reasoning for both calls is
in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## The safety property worth knowing about

On-chain data is attacker-controlled. A token name or a memo can carry control characters,
bidi overrides, or injection framing aimed at whatever reads it next, which for an agent is
the model's own context. `solana-core` sanitizes every such value on the way back, including
the paths that are easy to forget: JSON-RPC error messages, HTTP error bodies, and serde parse
errors are attacker-influenceable too.

Run it. `cargo run --example injection_demo` in `crates/solana-core` feeds a 40 KB hostile
token name carrying a bidi override, a zero-width space and injection framing through the real
path, and shows it stripped, capped and labelled untrusted, on the data path and the error path.

The sanitizer contract is quantified over generated inputs rather than chosen ones, including
idempotence, which is the property sanitizers most often fail. See [`TESTING.md`](TESTING.md).

## Build and test

```
rustup target add wasm32-wasip2

cd crates/solana-core
cargo test --locked                                   # 120 tests, four suites
cargo test --test properties                          # 23 properties, 1024 cases each

cd plugins/<name>
cargo test --lib                                      # host tests, mocked RPC, no network
cargo build --target wasm32-wasip2 --release          # the shipped component
```

All of that runs on a clean runner on every push, plus the fail-closed certification
self-test and all eight components in a matrix, with `--locked` throughout so a green run
also proves the committed lockfiles are the ones that work. A second workflow re-verifies the
published on-chain claims twice a day. A third re-checks interface parity against upstream
HEAD, because the interface is unfrozen and drifting away from it once already came close to
making every plugin fail to register; it runs on a daily schedule that has not come around
since this repository reached its remote, so it is the one workflow here that has not yet
executed. See [`TESTING.md`](TESTING.md) for what each of those can and cannot catch.

Building the ZeroClaw host needs three feature flags, and one of them removes a channel in
silence if omitted. That is step 1 of [`QUICKSTART.md`](QUICKSTART.md), worth reading before
you build.

`depin-attest` also carries gated live-devnet tests (`ZEROCLAW_DEVNET_PROOF=1`) that broadcast
for real. They are excluded from the normal run, which is mocked and offline.

## Layout

```
crates/solana-core/       shared wasm32-wasip2 core (transactions, PDAs, sanitizer)
plugins/                  the tool plugins, one workspace each
onchain/                  zeroclaw_oracle + consumer_example (Anchor)
skills/solana-pay/        the payment-URL skill and its scripts
sops/                     the SOPs the agents run on a schedule
x402-feed-gate/           the paid-reading gate
webshop-pay/              the hosted payment page
e2e-localnet/             oracle flow against a validator
e2e-track-a/              the shop payment flow end to end
e2e-allowance/            the on-chain cap rejection
scripts/verify-proof.py   one-command live check of every on-chain claim
wit/                      the vendored tool-plugin WIT world
```

## License

MIT. See [`LICENSE`](LICENSE).
