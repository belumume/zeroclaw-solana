# ZeroClaw on Solana: an agent bounded by the chain, and a node that pays its own gas

**Two things run, both self-hosted, both auditable by a stranger in an evening.** A DePIN node that
signs its own readings on-chain and *sells* them per request, and a merchant terminal that
takes an order in Portuguese and settles in USDC. Every claim below is checkable with one command
or one link. Nothing here is a screenshot of something that used to work.

---

## What it does, and who it is for

**A device that earns.** An ARM node publishes device-signed readings to a Solana feed on a
schedule, and gates the same feed behind x402: a machine that wants the reading pays for it,
per request, and the node covers its own gas. That is the whole loop.

The node is an Ampere ARM instance on Oracle's free tier, not a board on a desk, and it is named
here because the rest of this page asks you to trust what runs where. What the arrangement buys:
its signing key was generated on that box and has never left it, and a
`systemd --user` timer with lingering publishes on a schedule no laptop is in. A Raspberry Pi with
a DHT11 is a drop-in for the reading source and the on-chain half is identical either way. Today the
reading comes from a keyless public weather API on that host rather than from a physical probe.

**A shop that takes money without holding keys.** A merchant agent on Telegram and WhatsApp
quotes an order in BRL at a rate it fetches rather than states, issues a Solana Pay link, and
settles in mainnet USDC. It marks an order paid only when four things agree: the reference, the
exact amount, the exact mint, and the watched destination. A payment in a token the payer minted
themselves does not qualify.

The rate was the one money-touching number a language model could assert with nothing checking
it, which is why it is now fetched in code. `scripts/rate_crosscheck.py` reads BRL/USD from
Brazil's central bank (BCB PTAX) and refuses unless the ECB's published figure, via Frankfurter,
agrees within a stated band. Neither source needs a credential, and neither is a fallback for the
other: there is no last-known rate, so a source that cannot be reached stops the quote rather than
ageing one. On 2026-08-14 the two sat 0.91% apart, which is the error a single source would have
carried into every order without saying so. `pay_link.py` performs that fetch itself and
re-derives the amount, so the order value in BRL is the whole contract; a rate passed on the
command line is a cross-check that can add a refusal and cannot relax one.
`scripts/check-pay-link-rate-agreement.py` holds the pay path's duplicated constants to the
original by reading them out of its source, because the deployed workspace receives a single file
and cannot import the rest.

What that leaves open, said plainly: the order *value* is still the caller's, so "table 4,
R$ 0.05" passes every check above. This removes one free parameter of two. The shop on the node
has not picked the change up yet, so the enforcement is in the repo and the deploy is what
remains.

Built for a small operator who wants an agent touching money without handing it a signing key.

**And it has been running, not demoed.** The rubric asks whether a stranger would still be running
this in a month. Read as of 2026-08-15T19:41Z, and re-derive it yourself rather than believing the
figures, because they move every twenty minutes:

```bash
python3 scripts/verify-proof.py          # stdlib only, no install, no key
```

That checks the live claims. To count the history yourself, the underlying call is
`getSignaturesForAddress` on a feed account, which any devnet RPC will answer unauthenticated.

**Two independent devices, 2,292 publishes between them, zero failed.** That is the DePIN claim
rather than a gadget claim: the same on-chain oracle program serves both, each device holds its own
key, and neither can sign for the other.

**Measured 2026-08-15T19:41Z, and the publish counts only climb.** Do not read them as current;
re-derive with one `getSignaturesForAddress` per account, which returns the complete history because
the oldest signature is the account's own creation.

| Feed account | Publishes | Failed | Span | Median gap | Largest gap |
|---|---|---|---|---|---|
| `JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg` (ARM node) | 1,514+ | 0 | 21.6 d | 20.5 min | **61.5 min** |
| `3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K` (second device, run **completed** 2026-08-06) | 778 | 0 | 12.4 d | 20.0 min | **36.0 h** |

The ARM node's 61.5 minutes is its worst run in
the span above. The second device's 36 hours is a laptop that sleeps, and disclosing it beside the
node's figure is the point: a reader who runs the command finds both, and an outlier they discover
for themselves discredits everything around it.

**The second device's run is finished, and its row is a completed result rather than a running
counter.** It stopped on 2026-08-06 and the numbers above will not grow. Its purpose was to show
the same on-chain program accepting signed readings from a second independent device holding a
second key, which 778 publishes at zero failures over 12.4 days establishes. **Only the ARM node
is still publishing**, and every continuity claim in this submission rests on that row alone. A
reader checking this a fortnight from now will find the node's count higher and the second
device's identical, which is what these two rows are each supposed to mean.

The ARM node is the one the durability claim rests on. Its key was generated on that box with
`openssl rand -hex 32` and has never left it, so this workstation cannot forge a reading for it, and
a `systemd --user` timer with lingering keeps it publishing with no laptop in the loop.

Zero failures is exact and covers
both devices: no transaction has ever errored. Continuity is where they differ. The node's largest
gap is 61.5 minutes, one interruption across the span in the table above, so "every twenty minutes"
is true at the median with one
hour-long interruption. The second device is laptop-hosted and its largest gap is 36 hours, because
a laptop sleeps. That is the reason the node exists, and the reason the headline claim is the node's
rather than the pair's. Both are the sort of thing the call above would have shown you anyway.

---

## Custody: the limit is enforced on chain, not in our code

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
full**. A truncated `C331…iLHJ` is precisely what lets a swapped address survive a glance.

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

**The selling side is capped too, which the brief makes mandatory in both directions.** The node
sells its readings behind an x402 paywall, and a per-payer per-day ceiling is enforced in the gate's
own code rather than by the protocol, so a payer who drains the cap in many small buys is refused
exactly like one who tries it in a single large one. The ledger is durable: restarting the process
does not re-open a spent allowance. An earlier version restarted the day on every boot, which is a
cap in name only. Check the fix:

```bash
curl -s https://x402.perfpilot.dev/health | jq '.ledger'
```

`restored_sales_at_startup` is non-zero because the ledger really was rebuilt from disk at boot.

**That paywall has taken real money, and the precise claim is a split one.** Reading the feed and
settling the payment are separate concerns on separate RPC endpoints, so the gate settled a genuine
mainnet payment of 1.000000 USDC while serving a reading from our devnet feed. The settlement is
`3gSg3mQE9vA5X9CmFBxGEY2EFSAMXGhaC1HrUDbH8uA3MQhuaVjCdHjb1kshyzTqWKRALa9EQPeKja2Hk2rWcF2f`,
finalized on mainnet-beta. The goods stay on devnet because a `DeviceFeed` account is owned by our
`zeroclaw_oracle` program, which is deployed on devnet only. A mainnet feed is therefore a program
deployment rather than a config flag. The hosted endpoint above runs the devnet default.

And where the cap's boundary sits *today* can be located on mainnet, with no
key and no funds. The captured refusal proves the program said no once; this reads the remaining
allowance off the delegation account and replays the captured message either side of it, requiring
at least one refusal **and** at least one acceptance, so a dead program and a broken check both fail
it instead of printing a clean result over nothing:

```bash
python3 scripts/replay_allowance_probe.py
```

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
duplicating an already-offline-verifiable proof on mainnet costs 2.87 SOL in rent.

A control that is claimed and
enforced by no runtime path is worse than an absent one: an absent control is visible, an inert
one lets you believe you are protected.

---

## Craft, briefly

Sixteen crates, formatted and clippy-clean at `-D warnings` on host and wasm. Two Kani proofs on
the shortvec decoder, one covering all 16,777,216 three-byte inputs. A differential fuzzer graded
against solana-sdk's own deserializer rather than invariants we chose. Every gate ships a control
proving it can fail, because zero findings is also what a broken detector prints.

Two more, both exercisable. **A second deployed program reads the feed on
chain**, which is the difference between an oracle and a memo: `consumer_example` CPI-reads the feed
account, checks the owner and gates on freshness, so the data is consumable by something other than
a human squinting at an explorer. Its most recent read of the live ARM feed is transaction
`4CRapo3AEFBFLh7Y7byJR9XDYZEa95MEioUQMzUhJVxTB9HaDTRtX2X47pVgxaSu8KNfYsPyugeQ6FjN8hBzi54L`. And
**the sanitizer runs in your browser, compiled from the code that ships**: `sanitizer-microworld/`
is not a JavaScript reimplementation demonstrating the idea, it compiles `solana_core::sanitize`
itself to wasm, so pasting a right-to-left override or a zero-width joiner shows what the model
would actually receive. Open `sanitizer-microworld/index.html`; there is no build step.

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
`gh search issues --repo zeroclaw-labs/zeroclaw --author belumume --limit 100 --json state`

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
**Demo:** [youtu.be/a0jT0feuMAg](https://youtu.be/a0jT0feuMAg) (2:15, 4K), or the same cut
served from this repo at
[docs/assets/zeroclaw-demo-1080p.mp4](assets/zeroclaw-demo-1080p.mp4) with
[captions](assets/zeroclaw-demo.vtt), so it plays without depending on a third party.
**Injection transcript:** [docs/transcripts/injection-refund-redirect.md](transcripts/injection-refund-redirect.md)
**Mainnet custody proof:** [docs/MAINNET-PROOF.md](MAINNET-PROOF.md)
**How it is tested, including what the tests cannot show:** [TESTING.md](../TESTING.md)
**Every on-chain claim with its transaction:** [docs/DEVNET-PROOF.md](DEVNET-PROOF.md)
**A fail-open we shipped, found, and closed:** [docs/transcripts/whatsapp-allowlist-gate.md](transcripts/whatsapp-allowlist-gate.md)
