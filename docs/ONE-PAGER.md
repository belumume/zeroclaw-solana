# ZeroClaw on Solana: an agent bounded by the chain, and a node that pays its own gas

**Two things run, both self-hosted, both auditable by a stranger in an evening.** A DePIN node that
signs its own readings on-chain and *sells* them per request, and a merchant terminal that takes an
order in Portuguese and settles in USDC. Every claim here is checkable with one command or one link.

## Five seconds, if that is all you have

```bash
curl -i https://x402.perfpilot.dev/price
```

A live node answering `HTTP/1.1 402 Payment Required` with a single-use nonce that changes on every
request. That is the machine-commerce claim in one request.

## What runs

**A device that earns.** An ARM node publishes device-signed readings to a Solana feed on a
schedule and gates that same feed behind x402, so a machine that wants the reading pays for it per
request and the node covers its own gas. The signing key was generated on that box and has never
left it, and a `systemd --user` timer with lingering publishes on a schedule no laptop is in.

**A shop that takes money without holding keys.** A merchant agent on Telegram and WhatsApp quotes
an order in BRL at a rate it *fetches* rather than states, issues a Solana Pay link, and settles in
mainnet USDC. It marks an order paid only when four things agree: the reference, the exact amount,
the exact mint, and the watched destination. A payment in a token the payer minted themselves does
not qualify.

## It has been running, not demoed

Measured 2026-08-15T19:41Z. The counts only climb, so the reproduce command below re-derives them.

| Feed account | Publishes | Failed | Span | Median gap | Largest gap |
|---|---|---|---|---|---|
| `JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg` (ARM node, still publishing) | 1,514+ | 0 | 21.6 d | 20.5 min | 61.5 min |
| `3aMsPjXuMwRNqW3Yy6aqATp1N8nDXc4ZQMpGEncTVx8K` (second device, run completed 2026-08-06) | 778 | 0 | 12.4 d | 20.0 min | 36.0 h |

Two independent devices, 2,292 publishes between them, zero failed. The same on-chain program
serves both, each holds its own key, and neither can sign for the other. The 36-hour gap is a
laptop that sleeps, printed here because a reader who runs the command finds it anyway.

## The load-bearing difference: the limit is enforced on chain

An approval prompt is not a boundary. The sentence a human reads before approving was written by
the model, so influencing the model influences the description.

Key-free is what every careful entry in this space says, and it is a claim about what our code
*declines to do*, which is only as good as our code. Ours is enforced somewhere we cannot reach: a
deployed, audited on-chain program. On **mainnet**, a real delegated key signed an over-cap
transfer and the program refused it with custom error `0x12c`; the same key's within-cap transfer
settled normally. Both are captured as raw bytes in the repo and verify **offline, with no network
and no dependencies**. Prompt-inject every layer we wrote and the ceiling is still there, because
it was never ours to remove.

## Reproduce every claim above

```bash
git clone https://github.com/belumume/zeroclaw-solana && cd zeroclaw-solana
python3 scripts/verify-proof.py           # 10 static + up to 5 live claims, stdlib only
python3 scripts/verify_proof_offline.py   # the custody proofs, no network at all
python3 scripts/certify_publish_tx.py     # seven injection shapes, all refused
```

No install step, no venv, no credentials. The offline verifier refuses to report at all if its own
positive control stops passing, so a green result cannot come from a broken checker.

## What we are not claiming

The order *value* must now be derivable from the customer's own words: `--brl` is refused unless it
equals a figure marked in reais in the quoted message, or the sum of the distinct ones. That turns a
silent numeric substitution into a fabricated customer utterance, which is echoed to the operator
and falsifiable against a channel transcript the model does not write. It is not proof, because the
agent supplies the quote. The certifier's
mechanism is proven and CI-gated; its wiring to the live scheduler is operator-side configuration
and is not provable from this repo. The DePIN feed runs on devnet by choice, since duplicating an
already-offline-verifiable proof on mainnet costs 2.87 SOL in rent.

---

**The case in full, claim by claim:** [`docs/ARGUMENT.md`](ARGUMENT.md), which carries custody in
depth, the rate cross-check, the merchant-invariant control, the x402 ledger, craft, and the
upstream audit.

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
