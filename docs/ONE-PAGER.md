# ZeroClaw on Solana: an agent bounded by the chain, and a node that pays its own gas

**Two things run, both self-hosted, both auditable by a stranger in an evening.** A DePIN node that
signs its own sensor readings on-chain and *sells* them per request, and a merchant terminal that
takes an order in Portuguese and settles in USDC. Every claim below is checkable with one command
or one link. Nothing here is a screenshot of something that used to work.

---

## What it does, and who it is for

**A device that earns.** An ARM node publishes device-signed readings to a Solana feed on a
schedule, and gates the same feed behind x402: a machine that wants the reading pays for it,
per request, and the node covers its own gas. That is the whole loop. Nobody subsidises the
hardware.

**A shop that takes money without holding keys.** A merchant agent on Telegram and WhatsApp
quotes an order in BRL at a stated ECB rate, issues a Solana Pay link, and settles in devnet
USDC. It marks an order paid only when four things agree: the reference, the exact amount, the
exact mint, and the watched destination. A payment in a token the payer minted themselves does
not qualify.

Built for a small operator who wants an agent touching money without handing it a signing key.

**And it has been running, not demoed.** The rubric asks whether a stranger would still be running
this in a month. Read as of 2026-08-05T00:47Z, and re-derive it yourself rather than believing the
figure, because it moves every twenty minutes:

```bash
python3 scripts/verify-proof.py          # stdlib only, no install, no key
```

That checks the live claims. To count the history yourself, the underlying call is
`getSignaturesForAddress` on the feed account `JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg`, which
any devnet RPC will answer unauthenticated.

**760 transactions on the feed account. Zero failed.** First on 2026-07-25T04:12:01Z, spanning
10.86 days at a median of 20.5 minutes between publishes.

The honest part, stated here rather than left for you to find: the **largest gap is 61.5 minutes**,
so the cadence is not unbroken. Zero failures is exact, meaning no transaction has ever errored, and
"every twenty minutes" is true at the median with one hour-long interruption across eleven days.
That distinction is the sort of thing the call above would have shown you anyway, which is the only
reason it is worth stating: a number you can check is worth more than a rounder one you cannot.

---

## The custody argument, which is the part that does not depend on trusting us

An approval prompt is not a boundary. The sentence a human reads before approving was written
by the model, so influencing the model influences the description. An attacker needs no key,
only an operator who reads one plausible sentence and says yes.

Three answers, and none of them requires the operator to read correctly:

**Where intent is fixed, nothing asks.** The publish path can express exactly one intent, so the
exact serialized bytes are re-derived and anything else is refused. Its self-test *is* the attack,
run four ways, on every push.

**Where intent varies, the chain refuses.** Spends are bounded by an audited on-chain program, not
by the plugin and not by the model. Demonstrated on **mainnet**, not asserted: a delegated session
key signed an over-cap transfer and the program rejected it with custom error `0x12c` (300,
`AmountExceedsLimit`, sourced to the upstream program in [`MAINNET-PROOF.md`](MAINNET-PROOF.md)); a within-cap
transfer by the same key settled normally. Both are captured as raw bytes in the repo and verify
**offline, with no network and no dependencies**.

**Where the agent is wrong anyway, the customer's own page refuses.** Every layer above is still
something the agent composes, and an agent talked into a different recipient composes a perfectly
well-formed link to it. So the checkout page pins the one address it will ever pay, and it does not
trust the link that opened it. Change a single character of the recipient and the card is replaced
by **RECUSADO**, the pay button is gone rather than disabled, and both addresses are printed **in
full** — because a truncated `C331…iLHJ` is precisely what lets a swapped address survive a glance.

Run it yourself; it drives both directions and fails unless the page discriminates:

```bash
python demo/verify-merchant-invariant.py
```

The control is the whole point. A page that refused *everything* would produce an identical
screenshot, so the pinned address must stay payable while a one-character variant is refused. The
harness reads the pinned address out of the shipped page rather than restating it, so the two cannot
drift, and neutering its tampering makes it exit non-zero instead of passing.

That page also speaks the customer's language. It localises from `navigator.language` and renders
`pt-BR` end to end. The refusal above reads, verbatim:
*"Este link paga um endereço que não é desta loja. Nada foi enviado."*
The shop quotes in BRL; the page a Brazilian customer actually opens is in Portuguese.

Custody tier is declared per component: T0 reads run automatically, T1 emits an unsigned
transaction a human approves, and no component holds a fund-signing key.

That last sentence is table stakes and we would rather be judged on the one that follows it.
Key-free is what every careful entry in this space says, and it is a claim about what our code
*declines to do*, which is only as good as our code. **The load-bearing difference is WHERE the
limit is enforced.** Ours is not in the plugin, not in the host, and not in the prompt: it is a
deployed, audited on-chain program. The delegated key in the proof above is a real key that really
signs, and it still could not move the money, because it may move only up to a cap the program
enforces, from an account it does not own. A fund key has no such ceiling. Prompt-inject every layer
we wrote and the ceiling is still there, because it was never ours to remove.

---

## Reproduce every claim above: clone, then three commands

```bash
git clone https://github.com/belumume/zeroclaw-solana && cd zeroclaw-solana
python3 scripts/verify-proof.py           # 10 static + 4 live claims, stdlib only
python3 scripts/verify_proof_offline.py   # the custody proofs, no network at all
python3 scripts/certify_publish_tx.py     # four injection shapes, all refused
```

No install step, no venv, no credentials. The offline verifier refuses to report at all if its
own positive control stops passing, so a green result cannot come from a broken checker.

---

## What we are not claiming

The certifier's **mechanism** is proven and CI-gated; its **wiring** to the live scheduler is
operator-side configuration and is not provable from this repo. Corroborating a payment across
independent RPC endpoints moves trust to the configured set rather than removing it, and endpoints
sharing an operator or an upstream fail together. The DePIN feed runs on devnet by choice, since
duplicating an already-offline-verifiable proof on mainnet costs about 2.73 SOL in rent.

These are stated here rather than found by a reviewer, because a control that is claimed and
enforced by no runtime path is worse than an absent one: an absent control is visible, an inert
one lets you believe you are protected.

---

## Craft, briefly

Sixteen crates, formatted and clippy-clean at `-D warnings` on host and wasm. Two Kani proofs on
the shortvec decoder, one covering all 16,777,216 three-byte inputs. A differential fuzzer graded
against solana-sdk's own deserializer rather than invariants we chose. Every gate ships a control
proving it can fail, because zero findings is also what a broken detector prints.

Those four are the numbers, and this page promised each one is checkable, so here is how:

```bash
git ls-files '*Cargo.toml' | xargs grep -l '^\[package\]' | wc -l   # 16 crates
grep -rn 'kani::proof' crates/solana-core/src/ | wc -l              # 2 proofs
python3 scripts/check-all.py                                        # every gate, one command
```

Upstream, [ten host defects](HOST-SECURITY-AUDIT.md) were confirmed by one audit and reported,
one of them escalated to a private advisory. That page states its own scope in its first lines,
because the project total is larger and reported elsewhere as eighteen filed; the two count
different populations and the audit doc says which is which. Re-derive the live total rather than
trusting either number here:
`gh search issues --repo zeroclaw-labs/zeroclaw --author @me --limit 100 --json state`

## The five-second version

```bash
curl -i https://x402.perfpilot.dev/price
```

A live node answering `HTTP/1.1 402 Payment Required` with a single-use nonce that changes on every
request, which is the whole machine-commerce claim in one request. Note the verifier's LIVE claims
can legitimately go red if that node is down; the static and offline ones cannot, which is why they
are separated.

That challenge is also graded by someone other than us, which is the difference between claiming
conformance and letting you check it:

```bash
cd scripts/x402-validator && npm ci --silent && node validate-challenge.mjs
```

It runs the live body past `PaymentRequiredV2Schema` from `@x402/core`, pinned with a committed
lockfile. What makes a green result worth anything is the control shipped beside it: the body this
endpoint served before the spec-conformance fix, which the run must REJECT. It does, naming both
reasons, a missing `resource` and a `network` that is not CAIP-2. A validator never shown to reject
anything has not been shown to work. It also reads `resource.url` itself, because the schema accepts
a `localhost` value and so cannot tell you the advertised address is one a payer could reach.

If that fails on Windows with `curl: (35) schannel: ... CRYPT_E_REVOCATION_OFFLINE`, the node is
fine and the fault is on the client: Schannel could not reach a certificate-revocation responder,
which it treats as fatal for every HTTPS host, not just this one. Add one flag:

```bash
curl -i --ssl-revoke-best-effort https://x402.perfpilot.dev/price
```

That downgrades an unreachable revocation responder from fatal to non-fatal. It is not
`--ssl-no-revoke`, which switches revocation checking off altogether; certificate validation still
happens. Scripting it instead? Send a browser `User-Agent`, because Cloudflare answers a bare
`python-urllib` with a 403 that looks nothing like a payment challenge.

**Repo:** https://github.com/belumume/zeroclaw-solana
**Write-up:** [docs/WRITEUP.md](WRITEUP.md) &nbsp;&nbsp; **Run it:** [QUICKSTART.md](../QUICKSTART.md)
**Demo (2:55, plays in the browser):**
https://belumume.github.io/zeroclaw-solana/.demo-assets/cut/zeroclaw-solana-demo.mp4
(also committed at [.demo-assets/cut/zeroclaw-solana-demo.mp4](../.demo-assets/cut/zeroclaw-solana-demo.mp4), so a clone carries it)
**Injection transcript:** [docs/transcripts/injection-refund-redirect.md](transcripts/injection-refund-redirect.md)
**Mainnet custody proof:** [docs/MAINNET-PROOF.md](MAINNET-PROOF.md)
