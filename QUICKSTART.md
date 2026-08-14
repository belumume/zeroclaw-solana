# Quickstart: run both use cases in an evening

Everything below reproduces the two running use cases from a clean machine: the **DePIN
talking node** (device-signed on-chain sensor feed + consumer) and the **shop terminal**
(Solana Pay over Telegram/WhatsApp with human-gated, allowance-bounded spends). Times assume
a Linux box or WSL2 Ubuntu. No step needs a secret of ours; everywhere a key appears you
create your own.

**Repo map (two repos):** the ZeroClaw **host** is upstream, `github.com/zeroclaw-labs/zeroclaw`
(cloned in step 1). Everything this submission adds is in **THIS repo**
(`github.com/belumume/zeroclaw-solana`): the plugins, the `solana-pay` skill, the on-chain
`zeroclaw_oracle` + `consumer_example` programs (`onchain/`), the `e2e-*` reproducibility harnesses,
the `x402-feed-gate` node, and the `webshop-pay` pay page. Steps 2-7 run from a clone of this repo.

## Fastest path: three checks, nothing installed, 13 to 35 seconds

Start here. These three need **stdlib Python 3 and nothing else**: no `pip install`, no
virtualenv, no Rust, no Solana CLI, no API key, no config file, no account anywhere. Clone
this repo and run them. Two of the three never touch the network.

```
python3 scripts/verify_proof_offline.py     # 0.8s, no network at all
python3 scripts/certify_publish_tx.py       # 0.2s, no network at all
python3 scripts/verify-proof.py             # about 10s, queries public devnet
```

All three together take between 13 and 35 seconds, exit 0. That spread is real and measured,
not a hedge: four independent runs gave 13.1s, 22.8s, 24.1s and 34.1s on two machines. Re-derive
with
`time bash -c 'python3 scripts/verify_proof_offline.py && python3 scripts/certify_publish_tx.py && python3 scripts/verify-proof.py'`.

Nearly all of that variance is the third command, which waits on a public RPC you do not
control. The two offline figures are stable: an independent run from a clean clone measured
0.63s and 0.58s against the 0.8s and 0.2s quoted above. Those two import no network library at
all, which is checkable without running them:
`grep -c urllib scripts/verify_proof_offline.py scripts/certify_publish_tx.py` prints a count
of zero for each file.

**`verify_proof_offline.py` re-verifies the on-chain record from bytes committed in this
repo.** For every captured transaction it checks the ed25519 signature against the exact
serialized message and decodes the instructions, so you read what was actually signed rather
than what a document says was signed. It runs five self-tests first, one positive control and
four negative, and refuses to report if any of them stops behaving, so a broken verifier
cannot print a pass. Last line:

```
PASS  all 2 bundles verified offline: devnet-transactions.json, mainnet-transactions.json
```

That covers 29 devnet and 3 mainnet transactions, and it holds whether or not any RPC still
serves them. Among them you can read the durable-nonce replay guard on every publish, and the
over-cap transfer the on-chain allowance program refused, on both chains.

**`certify_publish_tx.py` drives the fail-closed action certifier** over one good publish
transaction and four injected shapes, and prints `5/5 cases correct`. The four refusals are
an injected third-instruction SOL transfer, a token-program instruction swapped in for the
publish, a plain System transfer where the nonce advance belongs, and a publish aimed at a
spoofed feed account.

**`verify-proof.py` is the only one that needs the network,** and it needs no credential for
it. It queries public devnet and prints PASS or FAIL per claim, ending in `10/10 static
claims` plus every live claim it could gate. The split matters: only the live ones can go red.
The live count is derived from what actually gated rather than pinned, so it reads 4 once the
node serves the x402 ledger block and 3 until then, and a claim reporting PENDING is never
tallied as verified.

Or open any explorer link in `docs/DEVNET-PROOF.md`; the programs, the feed sequence history,
and the devnet x402 settlements are all public devnet. The gate has also settled once on
**mainnet-beta**, for 1.000000 USDC, while serving a reading from that same devnet feed. The
settlement is
`3gSg3mQE9vA5X9CmFBxGEY2EFSAMXGhaC1HrUDbH8uA3MQhuaVjCdHjb1kshyzTqWKRALa9EQPeKja2Hk2rWcF2f`.
Settlement and feed-read now take separate RPC endpoints, which is what makes that split possible
(see the run block below).

That settlement came from a locally-run gate with the split configured. **The hosted endpoint at
`x402.perfpilot.dev` still runs the devnet default on both endpoints**, so the challenge you get
from the `curl` below quotes the devnet mint and a payment against it settles on devnet. Both
statements are true at once and the distinction is the point: the capability is real and proven on
mainnet, and the box you can poke is not currently pointed there.

## Three more demos, each under a minute

Still no host build, and none of these needs a key.

| Demo | Runtime | What it proves |
|---|---|---|
| `cd crates/solana-core && cargo run --example injection_demo` | 51-105s cold, 2s warm (needs Rust; the cold figure is dominated by your machine, and both ends of that range are measured) | Feeds a 40,077-byte hostile token name carrying a bidi override, a zero-width space and injection framing through the real sanitizer. Prints it capped to 96 chars with 4 control characters cut, `any bidi/zero-width residual: false`, and the same neutralization on the error path. |
| Open `sanitizer-microworld/index.html` in a browser | instant, no build | The same sanitizer, compiled to wasm and embedded in the page as base64, running on whatever you type. Six presets, or paste your own. A bidi override plus a zero-width space reports `invisible characters removed: 2` and renders the result under `WHAT REACHES THE MODEL` carrying the untrusted label. The page requests nothing over the network; the only fetch a browser makes on it is its own automatic `favicon.ico` lookup. `python3 sanitizer-microworld/check_page.py` confirms the blob is present and the script parses. |
| `curl -s https://x402.perfpilot.dev/price` | under 2s (on Windows see the note below this table) | The earning node answering live. Returns HTTP 402 with two price tiers, the devnet USDC mint, the pay-to address, and a single-use memo nonce that changes on every request (`x402-18c8ab1db58445d3-6e` then `x402-18c8ab1e3b3e35a2-6f` on two consecutive calls). This one is a live demonstration rather than evidence: if the node is down you get a gateway error, whereas the two offline checks above verify from committed bytes. Its SHAPE is checkable though, by a grader that is not ours: `cd scripts/x402-validator && npm ci --silent && node validate-challenge.mjs` runs it past `@x402/core`'s own `PaymentRequiredV2Schema`, with the pre-cutover body as a control that must be rejected. |

On Windows, that last `curl` can hang for about a minute and exit 35 without printing anything.
That is schannel refusing the handshake because it cannot reach the CA's revocation responder,
not the node being down. Add `--ssl-revoke-best-effort`, or read the endpoint with Python, which
ships its own TLS stack:

```bash
U=https://x402.perfpilot.dev/price
curl -s --ssl-revoke-best-effort "$U"
python3 -c "import urllib.request as u,sys
r=u.Request(sys.argv[1],headers={'User-Agent':'Mozilla/5.0'})
try: x=u.urlopen(r); print(x.status); print(x.read().decode())
except u.HTTPError as e: print(e.code); print(e.read().decode())" "$U"
```

The `try/except` is load-bearing rather than defensive: `urlopen` raises on any 4xx, and 402 is
the whole point of this endpoint, so the obvious one-liner tracebacks on a perfectly healthy
response. Catching `HTTPError` and reading `e.code` / `e.read()` is how you see the challenge.

Do not reach for `--ssl-no-revoke`, which disables revocation checking globally to work around
one host.

**The two test suites also need no host build**, which is worth saying plainly because the
build section below reads as though they do:

```
(cd crates/solana-core && cargo test)     # 120 tests, ~30s, no network
(cd x402-feed-gate && cargo test)         # 26 tests, ~100s, no network
```

146 green, from a clean clone, with Rust and nothing else. Re-derive the counts by summing the
`test result:` lines rather than trusting these figures. The `cd` is required rather than
stylistic: there is no cargo manifest at the repo root, for the reason given in step 2.

## Building from source is a separate, optional path

Everything below this line needs a toolchain, and step 0 lists what. After step 1 you can also
run `zeroclaw sop validate`. The full evening path (host + plugins + a wired bot + a live turn)
is steps 1-7 below.

## 0. Prerequisites (10 min)

**For verification: none of the below.** The three checks at the top of this page and the
three demos under them need stdlib Python 3, plus Rust for the one that says so and a browser
for the one that says so. Everything listed here is for steps 1-7, which build and run the
agents.

Needed for steps 1-6, the full evening path:

- **Rust stable >= 1.96** (`rustup update stable`), plus `rustup target add wasm32-wasip2`
- **The Solana CLI** (`solana`, `solana-keygen`). The reference environment runs
  `solana-cli 2.1.19` from the Agave client. Used from step 0 onward for keys and airdrops.
- **A funded devnet keypair for the operator**: `solana-keygen new`, then
  `solana airdrop 2 --url devnet`
- **A Telegram bot token** (@BotFather then `/newbot`, 2 minutes)
- **An Anthropic API key with credit on it.** Step 3 wires it as the agent's model provider,
  and without it the agent parses config and answers nothing. Only the live agent turns need
  it; none of the verification above does.
- **`zeroclaw` resolvable on your PATH.** Step 1 builds the host inside its own clone, so the
  binary lands at `<host-clone>/target/release/zeroclaw` and steps 2 onward call a bare
  `zeroclaw`. Symlink it, copy it into `~/.local/bin`, or add that directory to PATH before
  step 2, or every command from step 2 down fails with "command not found" and the cause is
  one directory away from where you are reading.

Needed **only for step 7**, which is optional because our programs are already deployed:

- **Anchor CLI 0.31.0**, the version `onchain/Anchor.toml` pins. Check with `anchor --version`;
  a different minor version changes the generated IDL and the deploy flow.
- **Several more devnet SOL than the 2 above.** Measured on chain: the two deployed programs
  hold 1.4983 and 1.3649 SOL of rent-exempt reserve, so deploying your own pair costs about
  2.87 SOL against a 2 SOL airdrop. Step 7 says why you almost certainly do not want to.

## 1. Build the host with plugin support (15–20 min, one-time)
Plugins are not in release binaries, so build the host from source at the pinned release:
```
git clone https://github.com/zeroclaw-labs/zeroclaw && cd zeroclaw
git checkout b119cc09        # verified against this commit, 2026-08-01

# Check the interface BEFORE patching anything, because the answer changed upstream
# and a patch applied blindly now ADDS A DUPLICATE VARIANT and breaks the build:
grep -c memory-audit wit/v0/logging.wit
#   1  -> upstream already carries it. Patch NOTHING. This is the case at b119cc09.
#   0  -> you are on an older commit that predates it. Add it in two places, or no
#         plugin will register (the component model matches interfaces nominally, so
#         a missing variant fails at instantiation, not at compile):
#           wit/v0/logging.wit                               -> add `memory-audit,` after `note,`
#           crates/zeroclaw-plugins/src/component_logging.rs -> add the matching arm:
#               PluginAction::MemoryAudit => Action::Note,

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

**Verified against host commit `b119cc09` (2026-08-01), which needs NO patch because upstream
now carries `memory-audit` itself. The earlier pin `bcf1f25` was the head of one of this
project's own PR branches, so it resolved through the GitHub API from here and was
unreachable in anyone else's clone; that is why step 1 now checks the interface instead of
prescribing a patch.**
`wit/v0` is explicitly experimental and unfrozen, so it moves under you, and the failure is
silent until load time. Before building the plugins, compare your host's plugin-action enum
against this repo's vendored copy:
```
diff <(sed -n '/enum plugin-action/,/}/p' <path-to-host>/wit/v0/logging.wit) \
     <(sed -n '/enum plugin-action/,/}/p' wit/v0/logging.wit)
```
Empty diff means you are in sync. The diff can be non-empty in **either** direction and they
need opposite fixes, and getting it backwards costs a day:

- **Host has a variant this repo lacks.** Add it to `wit/v0/logging.wit` here and rebuild all
  plugins.
- **This repo has a variant the host lacks.** This happens on any host commit predating
  upstream restoring `memory-audit` on 2026-07-23, which the current pin postdates. Patch
  the **host**: add the variant to its `wit/v0/logging.wit`, and add the one arm the
  compiler will then demand,
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
There is deliberately no cargo manifest at the repo root, so `cargo` has to run inside a
crate directory and a bare `cargo build` here fails with "could not find `Cargo.toml`".
Every plugin is its own workspace on purpose: `solana-sdk` does not compile for
`wasm32-wasip2` inside a WIT component, and the devnet harnesses depend on it, so a root
workspace would drag it into every component's graph. The isolation is the reason the wire
format is hand-decoded at all.

From this repo:
```
for d in plugins/*/; do (cd "$d" && cargo build --target wasm32-wasip2 --release) || break; done
zeroclaw plugin install ./plugins/<name>/               # per plugin; repeat as needed
zeroclaw config set plugins.enabled true
```
Each component lands at `plugins/<name>/target/wasm32-wasip2/release/<name>.wasm` with the
hyphens in its name turned to underscores, so `payment-watch` produces `payment_watch.wasm`.
That is the path the `strings <plugin>.wasm` check in step 1 wants.

Each plugin dir carries `manifest.toml` (minimal permissions) and a README with its config
keys, custody tier and threat model. Six of the eight carry a captured prompt-injection
transcript. The two that do not, `token-risk-check` and `lending-health`, carry the threat
model without a captured attack, because an injection reaching them has nothing to redirect.

Being read-only is not what decides that. Three plugins are T0 read-only:
`token-risk-check`, `lending-health` and `payment-watch`.
`payment-watch` holds no key and signs nothing, and it carries a transcript anyway, because
the verdict it returns is what a shop acts on when it hands over goods, and the on-chain
memo it reads back is attacker-controlled. What predicts a transcript is whether an
injection has something to redirect: a transaction for four of them, the recipient inside
the payment URL for `solana-pay-request`, and a settle-or-not verdict for `payment-watch`.

## 3. Configure the agent (10 min)
```
zeroclaw agents create demo
zeroclaw config set risk_profiles.demo.level supervised
zeroclaw config set agents.demo.risk_profile demo
zeroclaw config set agents.demo.model_provider "anthropic.default"
zeroclaw config set --no-interactive providers.models.anthropic.default.api_key <YOUR_KEY>
zeroclaw config set providers.models.anthropic.default.model claude-sonnet-5
```
Every spend builder stays human-gated. The auto-approved set is wider than "reads", and
saying so here rather than leaving a reviewer to diff it against the block: it also carries
`shell`, `memory_store`, `http_request` and `web_fetch`. What bounds those is not the
model's judgement. Channel turns run jailed to the agent workspace, egress for both fetch
tools is allowlisted to four hosts a few lines down, and `cron_add` was deliberately
removed. The shop's payment link comes from the `solana-pay` **skill**, not a plugin (the
tier demotion in the write-up), so `solana_pay_request` is deliberately absent here:
```
zeroclaw config set --no-interactive risk_profiles.demo.auto_approve \
  '["token_risk_check","kamino_lending_health","payment_watch","oracle_publish_reading","shell","memory_recall","memory_store","cron_list","glob_search","file_read","http_request","web_fetch","calculator"]'
```
This is the list the running shop actually uses, regenerated from the live config rather
than written from memory. The two drift: the documented list omitted two read-only risk
tools that were live, so a reviewer auditing the documented posture would be auditing a
posture nobody ran. Regenerating it from the live config is what keeps them equal.

`cron_add` is deliberately **not** here, though it used to be. A shop agent has no reason to
create a scheduled job while taking an order, and a cron entry is persistence that outlives
the turn it was planted in. `cron_list` is a read and stays. The DePIN publisher uses an OS
scheduler rather than `zeroclaw cron`, so nothing loses a capability.

### The payment watcher needs no network override

**Read this if you followed an earlier copy of this page.** Until 2026-08-05 this section
told you to point `payment_watch` at devnet and to pass a devnet mint on every call. Both
instructions are now wrong, and following them is the exact failure the old text warned
about, with the chain the other way round: the watcher would poll devnet for a payment that
settled on mainnet, the order would sit at NOT_YET forever, and nothing would error.

The shop moved to mainnet, so the two sides now agree by default. `payment_watch` compiles
with `DEFAULT_RPC = https://api.mainnet-beta.solana.com` and defaults its mint to mainnet
USDC (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`); the pay page settles on mainnet in
that same real USDC. **No `rpc_url` override and no explicit `mint` argument are needed.**

Re-derive both halves rather than trusting this paragraph:

```
grep -n DEFAULT_RPC plugins/payment-watch/src/watch.rs     # api.mainnet-beta.solana.com
grep -c "api.devnet" webshop-pay/src/app.js                # 0
grep -n "api.mainnet-beta" webshop-pay/src/app.js          # the page's own RPC
```

Optional and recommended, since the plugin asks a second independent endpoint to re-derive
a settle-worthy payment from its own copy of the chain (a corroborator sharing the primary's
host is refused, because the same party answering twice is not corroboration):

```
zeroclaw config set --no-interactive tools.payment_watch.config.corroborating_rpc_urls \
  '["https://mainnet.helius-rpc.com/?api-key=YOUR_KEY"]'
```

If you point the shop at your own devnet deployment instead, the override still exists and
it is now two settings rather than one: set `tools.payment_watch.config.rpc_url` to
`https://api.devnet.solana.com` and pass the devnet USDC mint
(`4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`) on every call, because omitting `mint`
falls back to the mainnet one.

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
  any real secret", which is broader than what we verified (a filesystem flag), and the assets
  at risk are not secrets anyway. If you hold secrets elsewhere, keep the detector on and
  expect broken links until upstream grows an allowlist.
- `shell` is auto-approved, which is the line in this posture a reviewer should push on
  hardest. It is what lets the
  agent run the pay-link generator and the earnings summarizer without a human in the loop
  on every order, and it is bounded by the workspace jail, which is a filesystem flag and
  not a sandbox. The reason that trade is acceptable HERE is the same reason stated above:
  this agent holds no key that can move funds, so the worst a redirected `shell` reaches is
  a jailed working directory holding two stdlib scripts and a copy of the SOPs. It is not
  acceptable by default. If you point this profile at an agent that does hold a signing key,
  take `shell` out first, because nothing else in this configuration is standing between it
  and that key.
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
enables Web mode, no Meta account). Scan it from WhatsApp under Linked devices. The code
rotates about every 20 seconds and the daemon stops emitting after roughly two minutes, so
any route that copies an image to a phone is slower than the rotation and hands over a code
that is already dead. Serving the live one is what works:
```
python3 scripts/qr_live_server.py        # serves on 127.0.0.1 port 8899, self-refreshing
```
It reads the daemon log, reconstructs the modules from the half-block art (each text row
carries two module rows, so this is lossless), and emits SVG, which needs no imaging library.
It self-tests before serving and prints the grid size, because a page that renders nothing
looks exactly like the pairing window having closed. The log path and port are constants at
the top of the file; the default is the reference node's, so edit it if yours differs. A
terminal font that distorts the QR is a rendering problem in your terminal rather than in the
code, and this sidesteps it by never asking the terminal to draw it.

**Keep this bound to localhost. Do not tunnel it.** The page serves a live pairing QR, and a
pairing QR is a bearer credential: whoever scans it links their device to your shop's WhatsApp
session. The obvious move when the daemon runs on a remote box is to expose port 8899 through
something like `cloudflared tunnel --url http://127.0.0.1:8899` so you can scan it from your
phone. That publishes the credential to the whole internet with no authentication in front of
it. We did exactly that on the reference node and left it up for five days before catching it.
Use SSH port-forwarding instead, which reaches the same page from your phone's network without
publishing anything:

```
ssh -L 8899:127.0.0.1:8899 <your-node>   # then open http://127.0.0.1:8899 locally
```

Stop the server once the session is linked. It has no reason to keep running afterwards.

**Fund the paying wallet before you open the link.** The hosted pay page at
`zeroclaw-shop-pay.pages.dev` settles in **mainnet USDC**
(mint `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`). SOL alone cannot settle a payment
whichever network you are on: SOL covers the transaction fee, the transfer itself is the
SPL token, so the paying wallet needs both.

Two ways to run it, and the second costs nothing:

1. **Against the hosted page, on mainnet.** Real USDC, and the demo order is 0.25 USDC plus a
   fee under a tenth of a cent. Fund the wallet you will pay from with at least the order
   amount.
2. **Against your own devnet deployment, free.** Apply the two-setting devnet override
   documented above (`tools.payment_watch.config.rpc_url` to `https://api.devnet.solana.com`,
   and pass the devnet USDC mint `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU` on every call),
   serve `webshop-pay/` yourself, and take free devnet USDC from `faucet.circle.com`
   (choose Solana Devnet). Every claim in this document is checkable this way without spending.

Get the network wrong and the wallet returns an opaque internal error. The pay page pre-checks
the balance and names the shortfall instead, which is the faster signal, but the underlying fix
is funding the wallet on the network the page is actually using.

If you paired WhatsApp, sanity-check that the channel is actually live before trusting it:
the daemon's startup banner must list `whatsapp.<alias>`. If it lists only Telegram, you
built the host without `whatsapp-web` (step 1).

## 7. The DePIN node (15 min, and the deploy half is optional)

**Ours are already live on devnet, and you do not need to deploy anything to check any claim
on this page.** `zeroclaw_oracle` is `EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn` and
`consumer_example` is `B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt`, both public devnet, both
verified as executable by `verify-proof.py` in the first section of this page. Every reading
the node has published is readable from the chain by anyone, and the offline verifier checks
the signatures on 20 captured publishes without a network connection at all. Re-derive that
count with `python3 scripts/verify_proof_offline.py | grep -c publish_reading`.

Deploying your own copy is worth doing if you want to change the programs, and it costs real
devnet SOL: the two deployed programs hold 1.4983 and 1.3649 SOL of rent-exempt reserve, so a
fresh pair runs about 2.87 SOL against the 2 SOL that step 0 airdrops. Budget more airdrops,
or skip this block and read from ours.

The programs live in `onchain/`, an isolated Anchor 0.31 workspace:
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
at the default `~/.config/solana/id.json`.
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
| Symptom | Cause and fix |
|---|---|
| plugins `discovered: N, registered: 0` | missing `plugins-wasm-cranelift` feature |
| headless turn hangs forever | a tool waits on the `[Y]es/[N]o` approval prompt; auto-approve it or run attended |
| skill works in CLI, "blocked by security policy" in channels | workspace jail: put runnable files in `workspace/tools/` |
| payment link arrives as `[REDACTED_…]` | leak detector (step 4) |
| link appeared while streaming, gone in final message | `stream_mode partial` replacement; use `multi_message` |
| `sop list` says none exist, files are right there | SOP.toml needs a `[sop]` table + **root-level** `[[triggers]]`; SOP.md needs a `## Steps` heading with `1. **Title**: body` items, which is the form both shipped SOPs use |
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
  X402_EARNINGS_LOG=~/.zeroclaw/agents/demo/workspace/x402-earnings.jsonl \
  X402_NETWORK=solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 \
  X402_RESOURCE_URL=https://<your public host>/reading cargo run --release
```
**To settle in real money while selling a devnet feed**, add the two split RPC variables. Both
default to `X402_RPC_URL`, so a run that omits them is unchanged:
```
  X402_READ_RPC_URL=https://api.devnet.solana.com \
  X402_SETTLE_RPC_URL=https://api.mainnet-beta.solana.com \
  X402_NETWORK=solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp \
  X402_MINT=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
```
The gate prints both endpoints at startup, labelling which one moves money, so a half-applied
split is visible rather than silent. Reading and settling were one client until 2026-08-05; they
are separate because they are separate concerns and can honestly live on different clusters. The
mint must match the settle cluster: the devnet USDC mint does not exist on mainnet-beta.

Those last two are not optional decoration, and the recipe omitted them until 2026-08-05.
Without `X402_NETWORK` the gate advertises `solana-devnet`, the v1 friendly form, which the
published v2 schema rejects. Without `X402_RESOURCE_URL` it falls back to
`http://localhost:{port}/reading`, and that is the trap: the schema **accepts** a localhost
resource url, so the challenge validates while advertising an address no payer can reach.
Check both rather than assuming, with the pinned reference grader:
```
cd scripts/x402-validator && npm ci --silent
node validate-challenge.mjs                 # the live reference node
node validate-challenge.mjs ../../body.json # or a challenge you captured from your own
```
It ships the pre-cutover body as a control that must be REJECTED, so a pass carries
information rather than just printing green, and it reads `resource.url` separately
because the schema alone cannot tell you that value is public.
`GET /price` returns the 402 menu; a client pays with `pay_client` (builds + signs a
TransferChecked + Memo) and retries `GET /reading` with the `X-PAYMENT` header. The gate
verifies the bytes, settles on-chain, and serves the reading. No facilitator, no key custody.
See `x402-feed-gate/README.md` for the threat model and the live devnet proof.
`X402_EARNINGS_LOG` points the gate's per-sale ledger at the agent workspace, so the
`node-earnings-report` SOP (installed in step 5) can read it and announce the node's daily
x402 revenue to the owner's channel ("the node that pays for itself"). Runs on a 20:00 cron.
