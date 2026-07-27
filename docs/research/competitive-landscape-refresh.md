# Competitive landscape refresh

Checked 2026-07-26 late evening. Supersedes the 2026-07-23 registry recon (task #23) and the
2026-07-25 Discord sweep where they overlap. Every claim names where it was read. Where a source
could not be reached it says so instead of guessing. Bounty published 2026-07-16T21:42:01Z (the
publishedAt field of the listing object), which is the reference point for "since the bounty
opened" below.

## 1. The listing has not moved. Verified by byte comparison, not by eyeball.

Fetched https://superteam.fun/earn/listing/zeroclaw and parsed the server-rendered __NEXT_DATA__
(the same route .tools/fetch-listing.py uses; a plain body fetch of the rendered DOM returns a JS
shell, which is why that route exists). The read was live: NEXT_DATA_FOUND True.

Compared field by field against the captured docs/listing-verbatim.json:

| Field | Live value | Captured value |
|---|---|---|
| updatedAt | 2026-07-22T18:00:59.486Z | identical |
| deadline | 2026-08-07T02:59:59.000Z | identical |
| commitmentDate (winners) | 2026-08-21T02:59:59.999Z | identical |
| rewards | 1: 1800, 2: 1200, 3: 1000, 99: 250 | identical |
| rewardAmount / maxBonusSpots | 5000 USDG / 4 | identical |
| status / region / isWinnersAnnounced | OPEN / Global / false | identical |
| description sha256 | eddd658f8c88f3cdc884ec196200e1ac7c588c839c20277da505973d6c57500e | identical |
| description length | 23707 chars | identical |

The diff over the whole listing object returned CHANGED_KEYS = []. Zero fields differ, so the
scored criteria, the prize split, the deadline and the custody ladder are exactly what
docs/LISTING-VERBATIM.md records. No re-audit of the compliance ledger is owed against the listing.

Two notes on the object shape. It carries no submission counter at all (no _count, no
submissionCount), so the number the UI shows is not available from this route, and it was never the
instrument here. And isFeatured is true, so the listing still has front-page placement.

## 2. The largest change is not an entrant. The maintainer opened a second official surface.

zeroclaw-labs/zeroclaw-community-plugins-list was created 2026-07-25T05:33Z by JordanTheJet and
last pushed 2026-07-25T06:30Z. Read its README and CONTRIBUTING in full. It is an official org repo
that indexes community plugins hosted in their authors own repositories, and it already carries a
dedicated "Solana and blockchain" section that names this bounty by URL and by sponsor.

Its five commit subjects, in order, are the story:

1. Seed the community plugin index
2. Seed three verified community entries
3. Reposition as the intake path for community plugins
4. Stop telling bounty entrants to close their submission
5. Rule out hosting a registry index, and point authors at their own

That fourth commit is a same-day self-correction by the maintainer, and the resulting text in
CONTRIBUTING.md is worth quoting because it cuts against a posture this project holds:

> Do not close your zeroclaw-plugins pull request. "Build Solana-native plugins for ZeroClaw",
> sponsored by Superteam Brasil, runs until 21 August 2026, and your pull request is part of how
> that work gets read. Closing it early can only cost you.

And, separately:

> Listing here is available to you today and it is additive. It does not replace your submission,
> does not affect judging, and is not a withdrawal.

Read carefully, this is addressed to entrants who already have a registry PR open. It does not
invite new ones, so it does not contradict the sponsor line "Do not open registry PRs during the
bounty", and the sponsor brief governs. What it does establish is that the maintainer reads those
PRs and considers them part of how the work is read, which downgrades the pure moat-hold argument
for the registry surface and upgrades this new index, which the maintainer says plainly does not
affect judging and is therefore free of that tension.

The acceptance bar for the index, verbatim from CONTRIBUTING: a maintainer merges the row if the
repository is a real ZeroClaw plugin, the link resolves to a public repo with a README, the
description is one plain sentence under 140 characters, and it is in the right section. One row,
one PR, titled "add: <plugin-name>".

Three observations that matter more than the mechanism:

- The Solana section already lists sixteen entrants. We are not among them. Neither is any of the
  strongest field (no ProofPay, no Palinurus, no Cupel, no proof-carrying cashier), so the list
  currently indexes the easier half of the field.
- The Channels section reads "Nothing listed yet". Corroborating evidence for section 4 below.
- The README itself warns that many listed entries carry no license file, so default copyright
  applies. Our MIT posture is a differentiator on a surface where it is visibly rare.

Gating reality: a row here needs a public repo, so it is downstream of the repo push (task #67,
user-gated), not an independent action.

## 3. The field is no longer the registry PR list

Entrants are closing registry PRs and moving to standalone repos. Read verbatim from PR #93
(AntonsBB), closed 2026-07-23T02:56:

> Closing this registry PR to align with the showcase-first rules of the bounty, which ask entrants
> to publish a real use case and defer registry submissions until maintainers invite the strongest
> implementation after judging. The reproducible use-case package is now at
> https://github.com/AntonsBB/token-risk-check-demo

Four more closed in the last four days (#124 Lusitaniae, #125 fengyangxxx, #133 Adarsh-Dhar, #143
sclee980528-prog) and #76 closed as superseded by #138. Note the maintainer text in section 2 is a
direct response to exactly this behaviour.

Measured on 2026-07-26: 63 open PRs on zeroclaw-plugins, highest number #144, 121 forks, and zero
community PRs merged in the history of that repo (every merge is infrastructure work by
JordanTheJet). A GitHub repository search for zeroclaw plus solana returns 44 repositories; a
broader search for zeroclaw pushed after 2026-07-23 returns the same order of magnitude with the
non-Solana ecosystem mixed in. Method stated so the negative is checkable: this is a name,
description and topic search, so a rival repo named without either word (Cupel, for instance) does
not appear and I did not enumerate those. Treat 44 as a floor.

Standalone rivals with fresh pushes worth naming, all read from repo metadata:

| Repo | Pushed | What it asserts |
|---|---|---|
| Dipraise1/rende | 2026-07-23 | Self-hosted agent selling idle GPU compute behind an x402 paywall. T1, earns and never spends. Direct overlap with our x402 earning-node originality claim. |
| zkasuran/solana-core-wasi | 2026-07-26 | Track E rival to solana-core. No solana crates, no borsh, five deps, every byte layout in-repo, pinned to spec vectors, proven by three payment plugins. |
| capitv/pixzclaw-pi | 2026-07-25 | PIX and USDC plugins plus an aarch64 plugin-host build for Raspberry Pi. Overlaps our ARM node claim and our Brazil angle at once. |
| shivamSspirit/safespend | 2026-07-26 | Runway-locked Solana treasury autopilot. New, 695 KB, created same day. |
| Chengyuann/zeroclaw-solana-pay-cashier | 2026-07-25 | Proof-carrying non-custodial cashier plus reconciliation. The dual-RPC entrant already credited in our ledger. |
| ertanyeni/zeroclaw-solana-plugins | 2026-07-26 | Kasa, a zero-custody collections desk: Solana Pay invoices plus on-chain reconciliation. |
| shud26/kamino-sentinel | 2026-07-26 | Kamino lending-health sentinel. Overlaps lending-health. |
| lucaboy/proofpay-eurc, RECTOR-LABS/palinurus | 2026-07-24, 2026-07-23 | Previously known from Discord; both now have standalone repos. |

## 4. New registry PRs since the last check, and what each asserts that we do not

### PR #144, Sushant6095, ProofKiosk (opened 2026-07-26T20:33, 50 files, +8302)

The most directly threatening new entry, and it is hours old. Track C with Track A rails inside.
Read from the PR body:

- A Raspberry Pi kiosk where a verified payment fires a GPIO relay. Money in, physical actuation
  out. That closes a loop ours does not: our DePIN feed publishes readings, theirs acts on payment.
- Merkle-batched hash-chained attestation of readings and receipts, seq and prev recovered from the
  chain in one call.
- kiosk-charge declares permissions = [config_read] only and ships scripts/verify-no-network.sh to
  prove permissions equal imports (the component imports no wasi:http at all). We have no
  equivalent artifact: we argue capability minimality in prose, they assert it with a script a
  judge can run in seconds.
- 107 host tests, clippy -D warnings clean on host and wasm, three components building to
  wasm32-wasip2, layout mirrored on plugins/redact-text.
- Frames the SOP as gating the relay on the structured verdict of the plugin rather than on model
  text, which is our own argument stated by someone else.

What theirs asserts that ours does not: physical actuation as the consequence of settlement, a
runnable permissions-equal-imports proof, Merkle batching. What ours asserts that theirs does not,
judged from their own body: no on-chain program of their own, no externally-graded oracle for their
decoder, no proofs, and no on-chain spend bound, since they avoid custody rather than bounding it.

### PR #140, Zartaj0, solana-inbox (opened 2026-07-25, 22 files, +5286)

This one falsifies a premise this project has carried since 2026-07-21. Our handoff records the
non-tool WIT worlds as INELIGIBLE, not open ground. Zartaj0 shipped a channel-plugin that makes
Solana an inbound channel: it polls an address, extracts SPL Memo instructions and transfers that
credit it, and delivers each as an InboundMessage shaped identically to a Telegram DM. Their body
claims, and the registry PR list agrees, that channel-plugin had zero Solana submissions across all
open PRs. The empty Channels section of the new official community index is a second, independent
confirmation of the same emptiness.

They pre-empt the nearest-neighbour question by naming PR #121 wallet-narrate and arguing
pull-versus-push rather than pretending no neighbour exists. That is the same honesty move our
write-up makes, made by a rival.

The corroborating signal is host-side: JordanTheJet merged three channel-plugin fixes in the 36
hours to 2026-07-26 (#9123 host-stamp channel plugin routes, #9124 channel component fixture, #9125
keep channel listener under supervision). The host is hardening the channel-plugin path right now.
Our ineligible read looks stale; at minimum it was never re-derived against the 2026-07-22 rewrite.

### PR #143, sclee980528-prog, Realms governance (opened and closed 2026-07-26)

Governance watch plus a policy-gated unsigned vote builder. Two things worth carrying. The
fail-closed detail is good: the builder forces createTokenOwnerRecord false so the path cannot
trigger a first-time 0.1 SOL deposit, and it rejects any transaction arriving with a nonzero
serialized signature. And they ran a live Wasmtime end-to-end test against
https://v2.realms.today/api/v1 and said so in the body. Demo is 34 seconds over the Gateway WSS web
channel. Opened and closed the same day, matching section 3. This is the entrant the Discord recon
flagged for opening a registry PR mid-bounty; they have withdrawn it.

### PR #142 BigGbotex, PR #141 taharfi

Both token-risk-check family, the most saturated area in the field. #141 marks its token-risk-check
registry = false because live HTTP imports are host-gated, and says its Telegram results and
injection evidence were captured locally, which is weaker evidence than ours. Neither asserts
anything we lack. Low threat, listed for completeness.

## 5. Automated gates, corrected

A gate WAS added after the bounty opened, and it is the one that matters most to us.

Commit f0d8a6e4, "ci: add deterministic plugin quality gate", landed 2026-07-17T22:51:06Z, about
25 hours after the listing published. It rewrote both workflows (+380 lines in validate.yml, +142
in publish.yml) and added tools/ci/validate_components.sh, plan_matrix.py, report_schema.py,
manifest_field.py, summary.py, test_counts.py, a CI test suite, docs/ci.md, and wit/UPSTREAM_REF.

Reading validate.yml directly, the job list is: Format, Plan component matrix, Registry contract,
WIT drift, and sharded Components. The WIT drift job runs the step "Compare vendored WIT with
pinned ZeroClaw source". That is an automated control for the exact failure that nearly killed this
submission on 2026-07-25, and it has existed in the registry repo since 2026-07-17. It only guards
plugins inside that repo, so it never protected our vendored copy, but the ecosystem answer to that
class already shipped, which is context our upstream issue #9380 should be read against.

On the host repo, gates added since the bounty opened, read from the workflow commit history:
Semgrep as a PR gate plus CodeQL on master and schedule (#8157, 2026-07-17), the comment hygiene
gate (#8901, 2026-07-17, made language-aware by #9131 on 2026-07-20), a firmware shared-protocol
host gate (#9108, 2026-07-20), Code Analysis aligned to workspace MSRV (#9118, 2026-07-18), and a
workflow_dispatch shell-injection fix (#9165, 2026-07-20). The comment hygiene gate is the one this
project already collided with on PR #9382, so that collision was with a control younger than the
bounty rather than with an old repo convention.

## 6. The acceptance bar lives on the host repo, not the registry

The registry has zero community merges. The host merges community work constantly. From the
merged-PR API, the 2026-07-22 to 2026-07-26 window alone carries merges from IftekharUddin (five),
Audacity88 (seven), perillamint, yijunyu, mazhuima, yanchenko, perlowja, Darren2030, NiuBlibing,
AngryPacifist, Alix-007, alexandme, Rhoahndur.

The shape of what merges: small, single-defect, test-carrying fixes with a fix(scope) subject. Read
from the list: "fix(runtime): isolate model switches per turn", "fix(config): propagate nested
set_prop value errors instead of masking as unknown property", "fix(runtime): serialize RPC config
writes so a flush cannot erase concurrent updates", "fix(vi): fail closed when a constraint subject
is absent from the fulfillment".

That last one is AngryPacifist, merged 2026-07-25T19:06. It is the x402 verifiable-intent fail-open
our own compliance ledger credits to OUTIS, and it merged. A fail-closed fix by a bounty-adjacent
contributor is in the host; ours are not yet.

Our own upstream footprint, read from the open-issue list rather than recalled: #9386, #9387, #9389
through #9395 and RFC #9397 are all open under belumume with status:accepted, most at priority:p1
and risk:high, and five of them carry help wanted. Nothing on the newest-issue page suggests anyone
else has claimed them.

## 7. Ranked by what would change our plan

1. Re-derive the channel-plugin premise from the brief text. We recorded non-tool worlds as
   ineligible on 2026-07-21, five days before the brief was rewritten, and never re-tested it. A
   rival shipped one, the host merged three channel-plugin fixes this week, and the official
   community index shows the Channels section empty. The arbiter is the brief on disk, so this is
   minutes of work with a large swing either way.
2. Ship a runnable permissions-equal-imports proof. ProofKiosk converted a prose claim into a
   script a judge can run. We hold the stronger underlying position across eight components and the
   weaker artifact, which is the same shape as most defects the 2026-07-25 adversarial audit found.
3. Get one host PR merged. A bounty-adjacent fail-closed fix merged this week while our three sit
   open. The merge cadence shows the bar is small scoped fixes, which is what the five help wanted
   issues invite by name.
4. Decide on a row in zeroclaw-labs/zeroclaw-community-plugins-list. The maintainer states plainly
   that it does not affect judging, which cuts both ways: one PR of cost, and not a scored surface.
   It is downstream of the repo push regardless, so the decision rides with that one.
5. Stop treating the registry PR list as the field. Serious entrants are withdrawing from it and
   the standalone-repo layer is where the work now lives. 44 repos is a floor, not a count.

## What this refresh did not cover

- Discord. The bounty channel was not read this pass, so any showcase posted there since
  2026-07-26 is unseen. The Discord recon of 2026-07-25 remains the newest read of that surface.
- Rival repos whose name and description carry neither the word zeroclaw nor solana are invisible
  to the search method used here. Cupel is the known example.
- I did not read the source of any rival repository. Every rival claim above is quoted from a PR
  body, a README, or repository metadata, and is their assertion rather than a verified fact.
- The 121 forks were enumerated by push time only. Fork contents were not diffed, so a fork
  carrying strong work with no PR behind it would not show up here except by its push date.
