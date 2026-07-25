# Quickstart: run both use cases in an evening

Everything below reproduces the two running use cases from a clean machine: the **DePIN
talking node** (device-signed on-chain sensor feed + consumer) and the **shop terminal**
(Solana Pay over Telegram/WhatsApp with human-gated, allowance-bounded spends). Times assume
a Linux box or WSL2 Ubuntu. No step needs a secret of ours; everywhere a key appears you
create your own.

**Repo map (two repos):** the ZeroClaw **host** is upstream, `github.com/zeroclaw-labs/zeroclaw`
(cloned in step 1). Everything this submission adds is in **THIS repo**
(`<repo URL, filled at publish>`): the plugins, the `solana-pay` skill, the on-chain
`zeroclaw_oracle` + `consumer_example` programs (`onchain/`), the `e2e-*` reproducibility harnesses,
the `x402-feed-gate` node, and the `webshop-pay` pay page. Steps 2-7 run from a clone of this repo.

**Fastest path to "seeing it work" (5 min, after the one-time build in step 1):** run
`cargo test` across `crates/solana-core` and `x402-feed-gate` (all green, no network), then
`zeroclaw sop validate`. To confirm the live chain instead of rebuilding, run
`python3 scripts/verify-proof.py` (stdlib only, no install): it queries devnet and prints
PASS/FAIL for every on-chain claim, ending in `10/10 static claims` plus `1/1 live claims`
(the split matters: only the live one can go red). Or open any explorer link
in `docs/DEVNET-PROOF.md`; the programs, the feed sequence history, and the x402 settlement
are all public devnet. The full evening path (host + plugins + a wired bot + a live turn) is
steps 1-7 below.

## 0. Prerequisites (10 min)
- Rust stable ≥ 1.96 (`rustup update stable`), plus `rustup target add wasm32-wasip2`
- A Telegram bot token (@BotFather → `/newbot`, 2 minutes)
- A funded **devnet** keypair for the operator (`solana-keygen new`, `solana airdrop 2 --url devnet`)

## 1. Build the host with plugin support (15–20 min, one-time)
Plugins are not in release binaries, so build the host from source at the pinned release:
```
git clone https://github.com/zeroclaw-labs/zeroclaw && cd zeroclaw
git checkout bcf1f25        # the exact commit this was verified against

# REQUIRED on this commit, two lines, or no plugin will register. See the wit section
# below for why. This commit predates upstream restoring the `memory-audit` variant,
# and this repo's vendored wit/v0 carries it, so the interfaces differ until you add it.
#   wit/v0/logging.wit                              -> add `memory-audit,` after `note,`
#   crates/zeroclaw-plugins/src/component_logging.rs -> add the matching arm:
#       PluginAction::MemoryAudit => Action::Note,

cargo build --release --features plugins-wasm,plugins-wasm-cranelift,whatsapp-web
```
The umbrella feature alone integrates the runtime **without a JIT backend**, so every plugin
will report "failed to load code." You need both. (Judges score Tier-3 against exactly this
build, per the brief.)

`whatsapp-web` is the third flag and it is easy to lose. It is **not** in `default-channels`,
and `WhatsAppWebChannel::new` is `#[cfg(feature = "whatsapp-web")]`, so omitting it removes
the channel with no error anywhere: `[channels.whatsapp.<alias>]` still parses, `channel
doctor` simply does not list it, and every inbound message is dropped in silence. We lost the
channel to exactly this on 2026-07-25 during an unrelated rebuild. Telegram alone needs only
the first two flags.

The reliable confirmation is the daemon's own startup banner, which is the only place the host
states what it actually constructed:
```
zeroclaw daemon 2>&1 | grep 'Channels:'      # must list whatsapp.<alias>
```
If you want a static check before running anything, grep the binary for `wacore` (the WhatsApp
storage layer, which links only under this feature). Do **not** grep for `whatsapp`: the
cloud-API channel and the config schema compile unconditionally, so that matches on a host with
no web channel at all. And do not grep for `whatsapp_rust`, which we tried first: it is absent
even from a correct build, so it reports failure on a working host.

**Verified against host commit `bcf1f25` (v0.8.3 line) plus the two-line patch in step 1.**
`wit/v0` is explicitly experimental and unfrozen, so it moves under you, and the failure is
silent until load time. Before building the plugins, compare your host's plugin-action enum
against this repo's vendored copy:
```
diff <(sed -n '/enum plugin-action/,/}/p' <path-to-host>/wit/v0/logging.wit) \
     <(sed -n '/enum plugin-action/,/}/p' wit/v0/logging.wit)
```
Empty diff means you are in sync. The diff can be non-empty in **either** direction and they
need opposite fixes, which is worth stating plainly because getting it backwards costs a day:

- **Host has a variant this repo lacks.** Add it to `wit/v0/logging.wit` here and rebuild all
  plugins.
- **This repo has a variant the host lacks.** This is what happens on the pinned commit, which
  predates upstream restoring `memory-audit` on 2026-07-23. Patch the **host**: add the variant
  to its `wit/v0/logging.wit`, and add the one arm the compiler will then demand,
  `PluginAction::MemoryAudit => Action::Note,` in
  `crates/zeroclaw-plugins/src/component_logging.rs`. Do not delete the variant from this repo
  instead; the shipped components carry it and would all need rebuilding.

Component-model interfaces match **nominally**, so one enum variant of difference makes the
whole interface a different type and every plugin fails to REGISTER (`registered: 0`, plus a
linker error on `zeroclaw:plugin/logging`) even though `cargo build` and every test pass.

Two commands settle it rather than trusting either side:
```
strings <plugin>.wasm | grep -c memory-audit    # expect 1; a stale build gives 0
./scripts/check-host-compat.sh <path-to-host>   # compares all four wit files + all 8 components
```
`check-host-compat.sh` is the one to run if you only run one. It refuses a COMPATIBLE verdict
while any plugin is unbuilt, so it cannot pass you on partial evidence.

## 2. Build + install the plugins (10 min)
From this repo:
```
cargo build --target wasm32-wasip2 --release            # builds all plugin components
zeroclaw plugin install ./plugins/<name>/               # per plugin; repeat as needed
zeroclaw config set plugins.enabled true
```
Each plugin dir carries `manifest.toml` (minimal permissions) and a README with its config
keys, custody tier and threat model. The plugins that build a transaction or sign one also
carry a captured prompt-injection transcript; the two read-only ones (`token-risk-check`,
`lending-health`) carry the threat model without a captured attack, because there is no
action for an injection to redirect.

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
  '["token_risk_check","kamino_lending_health","payment_watch","oracle_publish_reading","shell","memory_recall","memory_store","cron_list","glob_search","file_read","http_request","web_fetch","calculator"]'
```
This is the list the running shop actually uses, regenerated from the live config rather
than written from memory. An audit found the two drifting: the documented list was missing
the two read-only risk tools that were live, which meant a reviewer auditing the documented
posture was auditing a posture nobody ran.

`cron_add` is deliberately **not** here, though it used to be. A shop agent has no reason to
create a scheduled job while taking an order, and a cron entry is persistence that outlives
the turn it was planted in. `cron_list` is a read and stays. The DePIN publisher uses an OS
scheduler rather than `zeroclaw cron`, so nothing loses a capability.

The second profile the node uses, documented here because an undocumented security profile
is not a reviewable one:
```
zeroclaw config set --no-interactive risk_profiles.depin.auto_approve \
  '["oracle_publish_reading","http_request","web_fetch","shell","memory_recall","memory_store","file_read","glob_search","calculator"]'
```
Egress for both is allowlisted rather than left open, because an unset allowlist defaults to
`["*"]` and these are the only four hosts anything here contacts:
```
zeroclaw config set --no-interactive http_request.allowed_domains \
  '["api.frankfurter.dev","api.devnet.solana.com","api.rugcheck.xyz","api.kamino.finance"]'
zeroclaw config set --no-interactive web_fetch.allowed_domains \
  '["api.frankfurter.dev","api.devnet.solana.com","api.rugcheck.xyz","api.kamino.finance"]'
```
`zeroclaw security status --agent demo` shows the whole posture. To confirm the posture above
is the one you are actually running, rather than the one this page claims:
```
python3 scripts/check-config-drift.py
```
It compares your live config against this document and exits non-zero on any difference,
naming anything running-but-undocumented. Written because the two had silently drifted here:
a reviewer auditing a document is auditing the document.

## 4. The config posture that makes the shop work (5 min; each line has a reason)
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
  `spl-token=` parameter, so every payment link left the shop as `[REDACTED_…]` garbage. This
  agent holds no key that can move funds, so an outbound regex is not what is protecting you
  here: signing lives outside the agent, the recipient is pinned in the page that transfers,
  and the spend ceiling is enforced on-chain. We deliberately do not claim the jail "denies it
  any real secret" — that is broader than what we verified (a filesystem flag), and the assets
  at risk are not secrets anyway. If you hold secrets elsewhere, keep the detector on and
  expect broken links until upstream grows an allowlist.
- `allow_scripts`: script-bearing skills are deny-by-default; our skill ships a 20-line
  stdlib reference generator you can audit at a glance.

## 5. Install the skill + SOP (5 min)
```
cp -r skills/solana-pay ~/.zeroclaw/shared/skills/default/solana-pay
mkdir -p ~/.zeroclaw/agents/demo/workspace/tools
cp skills/solana-pay/scripts/gen_reference.py ~/.zeroclaw/agents/demo/workspace/tools/
cp skills/solana-pay/scripts/pay_link.py ~/.zeroclaw/agents/demo/workspace/tools/  # wraps solana: -> tappable pay-page link
cp x402-feed-gate/scripts/summarize_earnings.py ~/.zeroclaw/agents/demo/workspace/tools/  # x402 earnings report (SOP reads it)
for s in evening-reconciliation node-earnings-report; do
  cp -r sops/$s ~/.zeroclaw/agents/demo/workspace/sops/
  cp -r sops/$s ~/.zeroclaw/data/sops/                          # CLI tooling reads here
done
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
Config is read at STARTUP. If you change any `zeroclaw config set` value after the daemon is
already running (for example the leak-detection line above), restart it (Ctrl-C, then
`zeroclaw daemon`) or the change silently will not take effect.

Send `/bind <code>` (printed at startup) to your bot, then talk to it:
> a customer wants to pay 25 USDC for order #1, make me the payment link

WhatsApp (optional): the daemon prints a pairing QR (`channels.whatsapp.shop.session_path`
enables Web mode, no Meta account). Scan it from WhatsApp → Linked devices. If your terminal
font distorts the QR, render it to an image first; expired refs rotate every ~20s.

**Fund the paying wallet before you open the link.** The shop quotes in **devnet USDC**
(mint `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`, Circle's devnet USDC), so devnet SOL
alone cannot settle a payment: SOL covers the transaction fee, the transfer itself is the
SPL token. Get free devnet USDC at `faucet.circle.com` (choose Solana Devnet) for whichever
wallet you will pay from, and fund it for at least the order amount. Without it the wallet
returns an opaque internal error; the pay page pre-checks the balance and tells you the
shortfall instead, but the fix is still the faucet.

If you paired WhatsApp, sanity-check that the channel is actually live before trusting it:
the daemon's startup banner must list `whatsapp.<alias>`. If it lists only Telegram, you
built the host without `whatsapp-web` (step 1).

## 7. The DePIN node (15 min)
The devnet programs live in `onchain/` (an isolated Anchor 0.31 workspace). Deploy your own copy:
```
cd onchain
anchor keys sync                              # generate program keypairs, sync declare_id! + Anchor.toml
anchor build
anchor deploy --provider.cluster devnet       # deploys zeroclaw_oracle + consumer_example
anchor idl init --provider.cluster devnet \
  -f target/idl/zeroclaw_oracle.json $(solana address -k target/deploy/zeroclaw_oracle-keypair.json)
```
`anchor idl init` publishes the IDL on-chain so the explorer decodes instruction names instead of
"Unknown"; it ignores the ANCHOR_* env vars, so pass `--provider.cluster devnet` and keep the payer
at the default `~/.config/solana/id.json`. Ours are already live (addresses in the write-up's Links).
Then register a device feed and schedule the publisher:
- the agent turn calls `oracle_publish_reading` (device key signs inside the sandbox, durable nonce,
  range/kind/sequence gates)
- the host completes the fee-payer slot and broadcasts (the `.tools` completion pattern)
- schedule it every 20 minutes with your OS scheduler or `zeroclaw cron`
  (`scripts/verify-proof.py` treats a feed older than 90 minutes as stale, so a slower
  cadence will report your own node as dead)

Verify on explorer: the feed account's sequence increments with each run; the consumer
program (`act_on_feed`) proves the feed is consumable, not a memo.

## Troubleshooting the sharp edges we hit (each cost us real time)
| Symptom | Cause → fix |
|---|---|
| plugins `discovered: N, registered: 0` | missing `plugins-wasm-cranelift` feature |
| headless turn hangs forever | a tool waits on the `[Y]es/[N]o` approval prompt; auto-approve it or run attended |
| skill works in CLI, "blocked by security policy" in channels | workspace jail: put runnable files in `workspace/tools/` |
| payment link arrives as `[REDACTED_…]` | leak detector (step 4) |
| link appeared while streaming, gone in final message | `stream_mode partial` replacement; use `multi_message` |
| `sop list` says none exist, files are right there | SOP.toml needs a `[sop]` table + **root-level** `[[triggers]]`; SOP.md needs a `## Steps` heading with `1. **Title** — body` items |
| agent loops retrying an http fetch | `http_request` does not follow redirects; a 301 host move returns Cloudflare HTML; point skills at the exact current host |
| customer asks how to actually pay | the chat channels are TEXT-ONLY (no image send) and a `solana:` URI is not clickable in chat, so the shop sends a tappable **https pay-page** link (`tools/pay_link.py` wraps the `solana:` URL). The page renders a scannable QR (phone wallets) + a Connect-wallet-and-pay button (desktop extensions). Deploy your own page from `webshop-pay/` (`npx wrangler pages deploy webshop-pay`) and set its URL in `pay_link.py`, or reuse the reference deployment `pay_link.py` already defaults to: `https://zeroclaw-shop-pay.pages.dev/` (the page is static and stateless, safe to share) |
| bot replays an old/broken link | it memorized its own earlier output; `zeroclaw memory clear --key <id> --yes` |
| wallet shows "This dApp could be malicious" / "Failed to simulate" | Phantom-specific wording (each wallet's engine differs: Phantom uses Blowfish, Solflare/Backpack/Jupiter use Blockaid, Glow its own; severity ranges from an overridable warn to Solflare hard-blocking). Two independent causes stack, both overridable, neither a permanent block: (a) the paying wallet is unfunded or on the wrong network so the tx can't simulate, cleared by funding it on **Devnet** (`solana airdrop 1 <addr> --url devnet`); (b) the domain is brand-new, so reputation shows a soft "new domain" notice that self-clears in days. Our reference domain is verified NOT on Phantom's static blocklist, so it is never a hard block. Warning-free demo path: a phone **QR-scan** (a transfer-request skips the dApp-connect reputation flow), or a custom apex domain |
| the pay page auto-picks one wallet | it does not; the page enumerates every installed wallet via the **Wallet Standard** (`@wallet-standard/app` `getWallets()`) and presents a picker (the mechanism Jupiter's Unified Wallet Kit uses), persisting your last choice in `localStorage`. The only hardcoded wallet list is a legacy fallback that fires solely when no Wallet-Standard wallet is present |

## 8. The earning node (x402, optional deepening)
Turn the feed into a per-request revenue stream. Build and run the gate:
```
cd x402-feed-gate && cargo build --release --example pay_client
X402_SELLER_WALLET=<your wallet> X402_MINT=<usdc mint> X402_FEED_PDA=<your feed> \
  X402_EARNINGS_LOG=~/.zeroclaw/agents/demo/workspace/x402-earnings.jsonl cargo run --release
```
`GET /price` returns the 402 menu; a client pays with `pay_client` (builds + signs a
TransferChecked + Memo) and retries `GET /reading` with the `X-PAYMENT` header. The gate
verifies the bytes, settles on-chain, and serves the reading. No facilitator, no key custody.
See `x402-feed-gate/README.md` for the threat model and the live devnet proof.
`X402_EARNINGS_LOG` points the gate's per-sale ledger at the agent workspace, so the
`node-earnings-report` SOP (installed in step 5) can read it and announce the node's daily
x402 revenue to the owner's channel ("the node that pays for itself"). Runs on a 20:00 cron.
