# zeroclaw-solana

Two self-hosted [ZeroClaw](https://github.com/zeroclaw-labs) agents, both running now. One takes
shop orders on WhatsApp and Telegram and settles them in mainnet USDC. The other publishes
device-signed sensor readings into a typed on-chain account and sells them to other machines for
stablecoin, per request. This repo is those two agents plus the plugins, on-chain programs, skills
and SOPs they run on.

**Reproducing it takes three commands.** They need stdlib Python 3 and nothing else: no install,
no key, no account. Together they run in 13 to 35 seconds, and two of the three never touch the
network.
[`QUICKSTART.md`](QUICKSTART.md#fastest-path-three-checks-nothing-installed-13-to-35-seconds)
opens with them.

[![The ZeroClaw shop chat: a customer orders R$ 2, and the agent replies with a payment link and the conversion to 0.39 USDC on Solana mainnet at the quoted ECB rate](docs/assets/demo-poster.jpg)](https://youtu.be/a0jT0feuMAg)

The still above links to a 2:15 demo. The [landing page](https://belumume.github.io/zeroclaw-solana/)
covers the same ground in text and ends with three checkout links you can open yourself: one has a
single character changed in the recipient, and the page refuses it. Loading any of them sends nothing.

**A DePIN node that pays for itself.** An ARM box takes an ambient temperature reading for
Madinah, signs it with a key generated on that box, and lands it in a typed account owned by our
oracle program, where a separate consumer program reads it and acts. A `systemd` timer keeps it
publishing with no laptop involved. The same node also sells that reading per request over x402,
so the machine earns the gas it spends: `curl https://x402.perfpilot.dev/price` returns an HTTP
402 challenge with two price tiers and a single-use nonce, and the nonce changes on every request.
Three limits. That ARM box is an Ampere A1 on Oracle's free tier, measured at 0.00 EUR. Nobody
owns that board; it is rented. Ampere Altra is genuinely ARM, so the word is accurate, and naming
which kind costs nothing. The reading comes from a
keyless public weather API on the current host rather than from a physical probe; a Raspberry Pi
with a DHT11 is the hardware path, and the on-chain half is identical either way, because what is
signed is the value and the device key, not the enclosure. And that x402 endpoint is a live
demonstration rather than evidence: if the node is down you get a gateway error, whereas the
on-chain claims below verify from captured bytes with no network at all.

One thing about it is checkable rather than demonstrated, and the grader is not ours. The
challenge conforms to the x402 v2 spec as published, which you can confirm against
`@x402/core`'s own `PaymentRequiredV2Schema` in one command:
`cd scripts/x402-validator && npm ci --silent && node validate-challenge.mjs`. It carries
the pre-cutover body as a control that must be REJECTED, so a green result carries
information instead of only being green, and it reads `resource.url` separately because the
schema accepts a `localhost` value and so cannot tell you the advertised address is
reachable. Conformance is a claim about the response shape; it says nothing about uptime,
and the caveat above still stands.

**A shop terminal that takes payments.** A merchant agent on WhatsApp and Telegram quotes an
order, hands the customer a tappable payment link, and confirms settlement only from the
chain, never from the customer saying so. Confirmation requires the exact amount in base
units, the exact mint, and the watched destination, all read from `pre`/`postTokenBalances`;
the reference is an additional optional condition, not the check itself. A payment of the
wrong amount, or of a token the payer minted themselves, does not settle an order. Brazilian
orders are quoted in BRL at a stated rate and settled in USDC.

That rate is the one money-touching input a language model could otherwise invent, so it is
taken off the model: [`scripts/rate_crosscheck.py`](scripts/rate_crosscheck.py) reads the
Brazilian central bank's published USD rate and refuses unless a second source agrees within a
stated band, and it fails closed rather than guessing.
[`check-pay-link-rate-agreement.py`](scripts/check-pay-link-rate-agreement.py) holds the pay
path's copy of those constants to the original, because the deployed workspace gets exactly one
file and cannot import the rest. **The node runs this**, so the model no longer supplies the rate
on the live shop. Driven against the deployed file, a wrong figure is refused by name
(`expected: 19.14` for R$ 100 at 5.2236, BCB PTAX corroborated by ECB within 0.91%) and the
correct one settles.

What the rate work does NOT close, stated because it is the remaining hole rather than a caveat:
the order VALUE is still supplied by the caller. An implausible one is now refused in code, so
"Table 4, R$ 0.05" no longer produces a link, but a PLAUSIBLE wrong amount still does: R$ 25
for a R$ 60 order sits inside any band a shop without a catalog can justify. One free parameter
of two is gone and the second is narrowed rather than closed.

**The feed has published to devnet since 2026-07-25 and not one of its transactions has failed.**
Every 20 minutes is the median rather than a guarantee: the largest single gap is 61.5 minutes.
The account holds the `RegisterDevice` call that created it plus one
per reading, so the transaction count and the sequence number move together and both only climb.
They read at least 1,516 and 1,514, measured 2026-08-15T19:41Z, and are higher by the time you run
the commands below. The two differ by two rather than one because a consumer program has also read
this feed once on chain, which is a transaction against the account that advances no sequence. One
`getSignaturesForAddress` against `JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg` returns every
transaction the device has ever sent, which is the complete history because the oldest of them is
the account's own creation.

```bash
# the live sequence, and how long ago it last moved
FEED_PDA=JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg python3 scripts/feed_heartbeat.py

# re-checks every published claim against devnet. Stdlib only, nothing to install.
python3 scripts/verify-proof.py
```

Both use cases run on the same ARM node under `systemd --user`, and the two are not equally
observable from outside.
The DePIN feed is continuously checkable: it publishes on a timer and every reading lands
on chain, so `verify-proof.py` can go red on it. The shop is a Telegram and WhatsApp client
with no inbound port, and its trace is traffic-driven, so from outside a quiet shop and a
stopped one look identical. That half is asserted here and machine-checked by a `/health`
endpoint on the x402 gate, which asks systemd on the node directly.

A second and stronger check runs beside it, and the direction is the interesting part.
[`deploy/box_selfcheck.py`](deploy/box_selfcheck.py) runs **on** the node, compares the deployed
bytes against the manifest written at deploy time, and publishes a verdict outward through the same
tunnel at `/selfcheck`. Nothing reaches in, and the box reports on itself, which lets it see
deployed bytes and running services that an external prober cannot. Inbound is not shut so much as
impractical to automate: port 22 is blocked network-wide from the operator's location, and the one
route that does work needs a browser and a session that expires, which is a cost rather than a wall.

Both halves of that are tracked and readable here. An hourly timer
([`deploy/zc-selfcheck.timer`](deploy/zc-selfcheck.timer)) recomputes the verdict, and
[`scripts/verify-proof.py`](scripts/verify-proof.py) consumes it, distinguishing four outcomes by
status code: a build predating the route prints PENDING and does not gate, a live route with no
verdict FAILS because the timer stopped, and a stale verdict FAILS on an age derived from the file's
mtime rather than from any field the writer controls.
[`scripts/verify_proof_selfcheck_control.py`](scripts/verify_proof_selfcheck_control.py) drives all
eight branches from a loopback server, so the claim is known to be capable of going red.

**The node is still running the build that predates that route**, so today the check prints PENDING
and the live claim count stays at four rather than five. That is the designed state and not a gap:
the number is derived from what actually gated, so a pending claim can never be tallied as a
verified one, and it rises on its own when the deploy lands. Run `scripts/verify-proof.py` and the
PENDING line says so in as many words.

Live on-chain evidence, all clickable, is in
[`docs/DEVNET-PROOF.md`](docs/DEVNET-PROOF.md). The verifier above reports static and live
claims separately, and names what it does not cover.

## Start here

| If you want | Read |
|---|---|
| The whole submission on one page | [`docs/ONE-PAGER.md`](docs/ONE-PAGER.md) |
| What this is and why it is built this way | [`docs/WRITEUP.md`](docs/WRITEUP.md) |
| To run it yourself | [`QUICKSTART.md`](QUICKSTART.md) |
| Proof it is real, on chain | [`docs/DEVNET-PROOF.md`](docs/DEVNET-PROOF.md) |
| Why each design call went the way it did, including what was rejected | [`docs/DECISIONS.md`](docs/DECISIONS.md) |
| How it is tested, and what each layer cannot catch | [`TESTING.md`](TESTING.md) |
| What an adversarial audit found here, including what is still open | [`docs/AUDIT.md`](docs/AUDIT.md) |
| Eight things we believed that were wrong, and the measurement that killed each | [`docs/WHAT-WE-GOT-WRONG.md`](docs/WHAT-WE-GOT-WRONG.md) |
| Every claim the demo video makes, with the command that re-derives it | [`docs/video-claims.json`](docs/video-claims.json) |
| Ten verified defects found in the HOST this runs on, all reported upstream | [`docs/HOST-SECURITY-AUDIT.md`](docs/HOST-SECURITY-AUDIT.md) |
| The agent refusing an attack, verbatim | [`docs/transcripts/`](docs/transcripts/) |
| To poke the sanitizer yourself, no build needed | [the live microworld](https://belumume.github.io/zeroclaw-solana/sanitizer-microworld/) |

## Custody

**The use cases run no fund-signing key at all.** No plugin here holds a key that can move
funds. Every plugin that builds a spend emits it
**unsigned**, for a human to approve. One component signs, and naming it is more honest than
the blanket claim: `oracle-publish` holds a fund-less device seed and emits a device-**signed**
transaction with the fee-payer slot left empty, so a reading is attributable to the device
while the signature that actually pays is still the operator's. Spends are additionally
bounded on chain by the audited Solana Foundation Allowances program.

**The cap demonstration uses one on purpose**, bounded on chain, so the guarantee can be shown
failing closed. It deliberately does the
opposite of avoiding a key, because avoiding one proves nothing about what happens when an
agent has one. A delegated session key, held by the agent, **signs** an over-cap transfer, and
the audited program rejects it with custom error `0x12c` (300, `AmountExceedsLimit`, defined in the
upstream program's own source and IDL, cited in [`docs/MAINNET-PROOF.md`](docs/MAINNET-PROOF.md)).
The chain refused the transfer; no
plugin, no prompt and no operator had to be right for that to happen. A within-cap transfer
signed by the same key settles normally, which is the control that stops the rejection being
read as the key simply not working.

**The same refusal now holds on mainnet with real USDC**, because a rejection that costs nothing
is a weaker claim than one that does. A 0.5 USDC cap, a 0.4 USDC spend that settled and moved
value, and a 1.0 USDC spend the audited program refused with the same `0x12c`. Deliberately sized
so the over-cap amount stays inside the balance, since an attempt that also overdraws can be
refused for insufficient funds and a rejection for the wrong reason proves nothing. Transactions,
the reproduce command and the offline bundle are in [`docs/MAINNET-PROOF.md`](docs/MAINNET-PROOF.md).
The DePIN feed stays on devnet on the merits, and that page says why.

The two links below are the **devnet** pair, not the mainnet trio just described, and they are
served by an endpoint whose retention is set by whoever runs it, so they may stop resolving at any
time. Both still resolved when this line was last checked. The mainnet evidence is bytes in the
repo for the same reason:
`python3 scripts/verify_proof_offline.py` verifies both bundles offline with no network and cannot
rot.

Kept because one of them opens on a failed transaction on purpose. The
[within-cap transfer settled](https://explorer.solana.com/tx/5qyr7jJi8zb6SjZjnA2QT5C9nuZYgSw6raAefjmWnDDMf3JRgkQX19zssE57EpFSHVCCPfbj5qyxcYSQcfEq9W3Z?cluster=devnet);
the [over-cap transfer was refused on chain](https://explorer.solana.com/tx/3TLSrfWVYdC3hSiAWnyyd7T694bLJQDtdJYQ64EWUsBNDehGc6Kq1veR7xa8Y1BiMdpvfFm3N1dKjDrXF3BEq2ps?cluster=devnet)
with `custom program error 0x12c`. That code is sourced, and the trap of re-sending the captured
message at a different amount is explained, in [`docs/MAINNET-PROOF.md`](docs/MAINNET-PROOF.md).
The red error page is the evidence rather than a defect: the
audited program refused a transfer the agent's own delegated key had already signed, and the
transfer that settled is the control that stops the refusal being read as a key that does not
work. Both were served by `api.devnet.solana.com` on 2026-08-01, eight days after they landed.

Retention on public devnet is set by whoever runs the endpoint and has moved before, so this
rests on the captured bytes, not the links. They are in
[`docs/proof-bundle/`](docs/proof-bundle), and `python3 scripts/verify_proof_offline.py`
re-checks the ed25519 signature over the exact serialized message with no network at all. If a
link above has stopped resolving by the time you click it, that command still proves the same
thing.

Human approval is a weak boundary on its own, because the sentence the human reads is one the
model wrote. So the paths with a fixed intent never ask: `scripts/broadcast_certified.py`
re-derives the intent from the exact serialized bytes and refuses an appended transfer, a
swapped program or a spoofed feed. Run that check as a self-test with
`python3 scripts/certify_publish_tx.py`, which puts five injection shapes through it, and
CI runs it on every push. Stated precisely, because this project's own argument is that a
control which is claimed and enforced by no runtime path is worse than an absent one: what
this repo proves is the MECHANISM, not the wiring. The scheduler driving the live node is
operator-side configuration rather than a file in this tree, so a reader cannot confirm from
the repo alone that the running timer invokes it. The bound that does not depend on this is
the on-chain one below. Where intent is variable, a spend, the on-chain cap above is what holds, and it
holds whether or not the operator was fooled.

The two use cases run **no T2 fund-signer**. Everything they touch sits at T0 (read-only) or
T1 (builds a transaction the operator must sign), which the brief calls the sweet spot and
which is the honest place for an LLM-driven system to stop.

One T1 component departs from the ladder's "secrets held: none" wording.
`oracle-publish` holds a 32-byte device seed. It is fund-less by
construction, and the code enforces that: the device is added
as a **readonly** signer, and a hard check rejects any message whose fee payer is not signer
index zero. So the device key can attest that a reading came from that device, and it can
never pay a fee or source value. That is a narrower deviation than the ladder's wording
allows for, and a wider capability than "holds no key" would have implied.

## What the two use cases run on

| Component | Job | Tier | Network by default |
|---|---|---|---|
| [`oracle-publish`](plugins/oracle-publish) | Device-signed reading into a typed on-chain feed, behind a durable nonce | T1 build, device co-signs | devnet, because it writes to `zeroclaw_oracle` and that program is deployed there |
| [`payment-watch`](plugins/payment-watch) | Confirms a payment only when amount, mint, destination and (when supplied) the Solana Pay reference all match on-chain | T0 read-only | **mainnet** |
| [`spl-transfer-build`](plugins/spl-transfer-build) | Unsigned SPL transfers that survive an approval queue via durable nonces | T1 build | **mainnet** |
| [`allowance-spend-build`](plugins/allowance-spend-build) | Spends bounded by the audited SF Allowances program | T1 build | **mainnet**, and its three real mainnet transactions are the custody proof |
| [`solana-core`](crates/solana-core) | Shared wasm32-wasip2 core: transactions, PDAs, Token-2022, response-path sanitizer | library | none, it makes no network call |
| [`onchain/`](onchain) | `zeroclaw_oracle` and `consumer_example`, Anchor, live on devnet | on-chain | devnet |
| [`x402-feed-gate`](x402-feed-gate) | Sells one signed reading per paid request | T0/T1, holds no key | **split**: settlement is whatever `X402_SETTLE_RPC_URL` names and has settled on **mainnet** (`3gSg3mQE…`, 1.000000 USDC); the reading stays devnet, because the program owning the feed account is deployed there. The hosted endpoint runs the devnet default |
| [`skills/solana-pay`](skills/solana-pay) | Builds the payment URL. A skill, not a plugin, on purpose | skill | none, it builds a string |

Read that last column as the compiled default with no config override, which is what a
stranger gets on a fresh clone. Every row is a constant you can grep:
`grep -rn DEFAULT_RPC plugins/*/src/*.rs`. Nothing signs on a read or a build, so the four
mainnet rows cost nothing to run there, and pointing a risk check or a settlement check at
mainnet is the difference between exercising it against real tokens and exercising it
against a devnet toy.

`solana-pay-request` was built as a wasm plugin and then **demoted to a skill**, because
building a URL is string work and string work does not need a sandbox. The reason first given
for that call was wrong, and the correction is in [`docs/DECISIONS.md`](docs/DECISIONS.md):
the failure that matters is a well-formed URL carrying the wrong recipient, which a sandbox
would not catch, so the guard is a hardcoded invariant in `pay_link.py`. The plugin stays in
the tree as the evidence trail for that call rather than as part of the shipped path.

Three earlier plugins (`token-risk-check`, `lending-health`, `depin-attest`) predate the two
use cases and are **not part of them**. They keep their own READMEs and tests.
`token-risk-check` reads **mainnet** by default, and that is where the thing it looks for
actually exists: the Token-2022 mint it was written to flag carries eight live extensions
there, including a transfer hook and a permanent delegate, where the same address on devnet
is a plain system account with no token data at all. `lending-health` names no cluster
because it queries Kamino's REST API rather than an RPC, and Kamino runs on mainnet.
`depin-attest` defaults to devnet, since it writes to the same devnet program
`oracle-publish` does.
`depin-attest` describes a T2 posture and is not run by either use case; `oracle-publish` is
its T1 successor and is what actually publishes the live feed. The reasoning for both calls is
in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## The safety property

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
making every plugin fail to register; it runs daily at 05:41 UTC and has been running since
2026-07-25, so unlike the other two it reports on a moving target we do not control. Count its
runs yourself rather than believing this sentence:
`gh run list --workflow=host-drift.yml --limit 100 --json conclusion --jq 'length'`.
See [`TESTING.md`](TESTING.md) for what each of those can and cannot catch.

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
