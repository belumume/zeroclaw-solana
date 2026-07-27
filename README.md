# zeroclaw-solana

Two self-hosted [ZeroClaw](https://github.com/zeroclaw-labs) agents doing real Solana work,
and the plugins, on-chain programs, skills and SOPs they run on.

**A DePIN node that pays for itself.** An ARM box takes a sensor reading, signs it with a key
generated on that box, and lands it in a typed account owned by our oracle program, where a
separate consumer program reads it and acts. A `systemd` timer keeps it publishing with no
laptop involved. The same node also sells that reading per request over x402, so the machine
earns the gas it spends.

**A shop terminal that takes payments.** A merchant agent on WhatsApp and Telegram quotes an
order, hands the customer a tappable payment link, and confirms settlement only from the
chain, never from the customer saying so. Confirmation requires the exact amount in base
units, the exact mint, and the watched destination, all read from `pre`/`postTokenBalances`;
the reference is an additional optional condition, not the check itself. A payment of the
wrong amount, or of a token the payer minted themselves, does not settle an order. Brazilian
orders are quoted in BRL at a stated rate and settled in USDC.

Both are running. Live on-chain evidence, all clickable, is in
[`docs/DEVNET-PROOF.md`](docs/DEVNET-PROOF.md), and `python3 scripts/verify-proof.py`
re-checks every published claim against devnet in one command, stdlib only, nothing to install.

## Start here

| If you want | Read |
|---|---|
| What this is and why it is built this way | [`docs/WRITEUP-DRAFT.md`](docs/WRITEUP-DRAFT.md) |
| To run it yourself | [`QUICKSTART.md`](QUICKSTART.md) |
| Proof it is real, on chain | [`docs/DEVNET-PROOF.md`](docs/DEVNET-PROOF.md) |
| Why each design call went the way it did, including what was rejected | [`docs/DECISIONS.md`](docs/DECISIONS.md) |
| How it is tested, and what each layer cannot catch | [`TESTING.md`](TESTING.md) |
| What an adversarial audit found here, including what is still open | [`docs/AUDIT.md`](docs/AUDIT.md) |
| Ten verified defects found in the HOST this runs on, all reported upstream | [`docs/HOST-SECURITY-AUDIT.md`](docs/HOST-SECURITY-AUDIT.md) |
| The agent refusing an attack, verbatim | [`docs/transcripts/`](docs/transcripts/) |
| To poke the sanitizer yourself, no build needed | [`sanitizer-microworld/index.html`](sanitizer-microworld/index.html) |

## Custody, which is the part that matters

The agent never holds a key that can move funds. It emits an **unsigned** transaction for a
human to approve, and spends are additionally bounded on chain by the audited Solana
Foundation Allowances program. That bound is demonstrated rather than asserted: the agent's
own session key signs an over-cap transfer and the program rejects it, custom error `0x12c`,
with the failed transaction on devnet for anyone to open.

Human approval is a weak boundary on its own, because the sentence the human reads is one the
model wrote. So the paths with a fixed intent never ask: `scripts/broadcast_certified.py`
re-derives the intent from the exact serialized bytes and refuses an appended transfer, a
swapped program or a spoofed feed before anything leaves the machine. Run that check as a
self-test with `python3 scripts/certify_publish_tx.py`, which puts four injection shapes
through it. Where intent is variable, a spend, the on-chain cap above is what holds, and it
holds whether or not the operator was fooled.

The two use cases run **no T2 fund-signer**. Everything they touch sits at T0 (read-only) or
T1 (builds an unsigned transaction, holds no key), which the brief calls the sweet spot and
which is the honest place for an LLM-driven system to stop.

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
building a URL is string work with no funds at risk and does not need a sandbox. It stays in
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
also proves the committed lockfiles are the ones that work. Two more workflows re-verify the
published on-chain claims twice a day and re-check interface parity against upstream HEAD,
because the interface is unfrozen and drifting away from it once already came close to
making every plugin fail to register. See [`TESTING.md`](TESTING.md) for what each of those
can and cannot catch.

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
