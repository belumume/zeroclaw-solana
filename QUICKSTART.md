# Quickstart — run both use cases in an evening

Everything below reproduces the two running use cases from a clean machine: the **DePIN
talking node** (device-signed on-chain sensor feed + consumer) and the **shop terminal**
(Solana Pay over Telegram/WhatsApp with human-gated, allowance-bounded spends). Times assume
a Linux box or WSL2 Ubuntu. No step needs a secret of ours; everywhere a key appears you
create your own.

**Fastest path to "seeing it work" (5 min, after the one-time build in step 1):** run
`cargo test` across `crates/solana-core` and `x402-feed-gate` (all green, no network), then
`zeroclaw sop validate`. To see the live chain instead of rebuilding, open any explorer link
in `docs/DEVNET-PROOF.md` — the programs, the feed sequence history, and the x402 settlement
are all public devnet. The full evening path (host + plugins + a wired bot + a live turn) is
steps 1-7 below.

## 0. Prerequisites (10 min)
- Rust stable ≥ 1.96 (`rustup update stable`), plus `rustup target add wasm32-wasip2`
- A Telegram bot token (@BotFather → `/newbot`, 2 minutes)
- A funded **devnet** keypair for the operator (`solana-keygen new`, `solana airdrop 2 --url devnet`)

## 1. Build the host with plugin support (15–20 min, one-time)
Plugins are not in release binaries, so build the host from source at the pinned release:
```
git clone https://github.com/zeroclaw-labs/zeroclaw && cd zeroclaw && git checkout v0.8.3
cargo build --release --features plugins-wasm,plugins-wasm-cranelift
```
The umbrella feature alone integrates the runtime **without a JIT backend** — every plugin
will report "failed to load code." You need both features. (Judges score Tier-3 against
exactly this build, per the brief.)

## 2. Build + install the plugins (10 min)
From this repo:
```
cargo build --target wasm32-wasip2 --release            # builds all plugin components
zeroclaw plugin install ./plugins/<name>/               # per plugin; repeat as needed
zeroclaw config set plugins.enabled true
```
Each plugin dir carries `manifest.toml` (minimal permissions) and a README with its config
keys, custody tier, threat model, and a prompt-injection transcript.

## 3. Configure the agent (10 min)
```
zeroclaw agents create demo
zeroclaw config set risk_profiles.demo.level supervised
zeroclaw config set agents.demo.risk_profile demo
zeroclaw config set agents.demo.model_provider "anthropic.default"
zeroclaw config set --no-interactive providers.models.anthropic.default.api_key <YOUR_KEY>
zeroclaw config set providers.models.anthropic.default.model claude-sonnet-5
```
Auto-approve reads and the publish tool; keep every spend builder human-gated. The shop's
payment link comes from the `solana-pay` **skill**, not a plugin (the tier demotion in the
write-up), so `solana_pay_request` is deliberately absent here:
```
zeroclaw config set --no-interactive risk_profiles.demo.auto_approve \
  '["token_risk_check","kamino_lending_health","payment_watch","oracle_publish_reading","shell","memory_recall","memory_store","cron_add","cron_list","glob_search","file_read","http_request","web_fetch","calculator"]'
```
`zeroclaw security status --agent demo` shows the whole posture.

## 4. The config posture that makes the shop work (5 min — each line has a reason)
```
zeroclaw config set channels.telegram.shop.bot_token <YOUR_BOT_TOKEN>
zeroclaw config set channels.telegram.shop.enabled true
zeroclaw config set channels.telegram.shop.stream_mode multi_message
zeroclaw config set --no-interactive security.leak_detection.enabled false
zeroclaw config set skills.allow_scripts true
zeroclaw config set skill_bundles.default.directory shared/skills/default
zeroclaw config set agents.demo.skill_bundles '["default"]'
```
- `multi_message`: in `partial` mode the final segment **replaces** the streamed draft, which
  silently ate the payment URL mid-conversation. Multi-message makes the link its own
  permanent, tap-to-copy message.
- `leak_detection.enabled false`: the outbound leak detector's entropy tier redacts public
  base58 addresses, and its deterministic `token=` pattern eats Solana Pay's mandatory
  `spl-token=` parameter — every payment link left the shop as `[REDACTED_…]` garbage. This
  agent's jail (workspace-only shell, config unreachable) already denies it access to any
  real secret, so the defense lives at the source. If you hold secrets elsewhere, keep the
  detector on and expect broken links until upstream grows an allowlist.
- `allow_scripts`: script-bearing skills are deny-by-default; our skill ships a 20-line
  stdlib reference generator you can audit at a glance.

## 5. Install the skill + SOP (5 min)
```
cp -r skills/solana-pay ~/.zeroclaw/shared/skills/default/solana-pay
mkdir -p ~/.zeroclaw/agents/demo/workspace/tools
cp skills/solana-pay/scripts/gen_reference.py ~/.zeroclaw/agents/demo/workspace/tools/
cp skills/solana-pay/scripts/pay_link.py ~/.zeroclaw/agents/demo/workspace/tools/  # wraps solana: -> tappable pay-page link
cp -r sops/evening-reconciliation ~/.zeroclaw/agents/demo/workspace/sops/
cp -r sops/evening-reconciliation ~/.zeroclaw/data/sops/        # CLI tooling reads here
zeroclaw skills test solana-pay      # 3/3
zeroclaw sop validate                # ✅
```
The generator copy into `workspace/tools/` matters: **channel turns run jailed to the agent
workspace**, so a skill referencing its own directory breaks in channels even though it
works from the CLI.

## 6. Run it (2 min)
```
zeroclaw daemon        # gateway + channels + cron scheduler
```
Send `/bind <code>` (printed at startup) to your bot, then talk to it:
> a customer wants to pay 25 USDC for order #1 — make me the payment link

WhatsApp (optional): the daemon prints a pairing QR (`channels.whatsapp.shop.session_path`
enables Web mode — no Meta account). Scan it from WhatsApp → Linked devices. If your terminal
font distorts the QR, render it to an image first; expired refs rotate every ~20s.

## 7. The DePIN node (15 min)
Deploy or reuse the devnet programs (`onchain/`; ours are live — addresses in the write-up),
register a device feed, then schedule the publisher:
- the agent turn calls `oracle_publish_reading` (device key signs inside the sandbox,
  durable nonce, range/kind/sequence gates)
- the host completes the fee-payer slot and broadcasts (`.tools` pattern in the write-up)
- schedule it 6-hourly with your OS scheduler or `zeroclaw cron`

Verify on explorer: the feed account's sequence increments with each run; the consumer
program (`act_on_feed`) proves the feed is consumable, not a memo.

## Troubleshooting the sharp edges we hit (each cost us real time)
| Symptom | Cause → fix |
|---|---|
| plugins `discovered: N, registered: 0` | missing `plugins-wasm-cranelift` feature |
| headless turn hangs forever | a tool waits on the `[Y]es/[N]o` approval prompt — auto-approve it or run attended |
| skill works in CLI, "blocked by security policy" in channels | workspace jail: put runnable files in `workspace/tools/` |
| payment link arrives as `[REDACTED_…]` | leak detector (step 4) |
| link appeared while streaming, gone in final message | `stream_mode partial` replacement — use `multi_message` |
| `sop list` says none exist, files are right there | SOP.toml needs a `[sop]` table + **root-level** `[[triggers]]`; SOP.md needs a `## Steps` heading with `1. **Title** — body` items |
| agent loops retrying an http fetch | `http_request` does not follow redirects — a 301 host move returns Cloudflare HTML; point skills at the exact current host |
| customer asks how to actually pay | the chat channels are TEXT-ONLY (no image send) and a `solana:` URI is not clickable in chat, so the shop sends a tappable **https pay-page** link (`tools/pay_link.py` wraps the `solana:` URL). The page renders a scannable QR (phone wallets) + a Connect-wallet-and-pay button (desktop extensions). Deploy your own page from `webshop-pay/` (Cloudflare Pages) and set the URL in `pay_link.py`, or reuse the reference deployment |
| bot replays an old/broken link | it memorized its own earlier output; `zeroclaw memory clear --key <id> --yes` |
| wallet shows a red "This dApp could be malicious" / "Failed to simulate the results" | NOT a domain verdict — it is a transaction-**simulation** failure. The paying wallet is unfunded or on the wrong network, so the wallet can't preview the tx and shows the red warning. Fix: switch the wallet to **Devnet** and airdrop a little devnet SOL (`solana airdrop 1 <addr> --url devnet`); it clears once the tx simulates. The separate yellow "this domain is new" notice is reputation-based and self-clears in a few days (submit the domain to the wallet's review form to speed it up) |
| the pay page auto-picks one wallet | it does not anymore — the page enumerates every installed wallet via the **Wallet Standard** (`@wallet-standard/app`) and presents a picker (same mechanism as Jupiter's Unified Wallet Kit), persisting your last choice in `localStorage` |

## 8. The earning node (x402, optional deepening)
Turn the feed into a per-request revenue stream. Build and run the gate:
```
cd x402-feed-gate && cargo build --release --example pay_client
X402_SELLER_WALLET=<your wallet> X402_MINT=<usdc mint>   X402_FEED_PDA=<your feed> cargo run --release
```
`GET /price` returns the 402 menu; a client pays with `pay_client` (builds + signs a
TransferChecked + Memo) and retries `GET /reading` with the `X-PAYMENT` header. The gate
verifies the bytes, settles on-chain, and serves the reading. No facilitator, no key custody.
See `x402-feed-gate/README.md` for the threat model and the live devnet proof.
