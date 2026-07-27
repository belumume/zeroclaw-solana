# Running Claude Security on this project: what it would find, and where to point it

Written 2026-07-26. Sources are named inline. Where a claim comes from reading the installed
plugin rather than from a published page, it says so, because the two disagree in places and the
installed copy is what will actually run.

The installed copy is `claude-security` **v0.10.0**, at
`~\.claude\plugins\cache\claude-plugins-official\claude-security\0.10.0`.
Every file cited below was read from that directory.

## Verdict first

**GO**, once, at `medium` effort, whole repository, on `zeroclaw-solana`.
**NO-GO** on re-scanning `zeroclaw-host`.

The reasoning is in section 4. The short version: the plugin's finding taxonomy and our host
audit's finding taxonomy barely intersect, our own shipped code has never been read for the
classes the plugin is built for, and this repo is small enough (169 tracked files) that the run
is cheap and its coverage ledger can return the strongest available result.

---

## 1. What the plugin actually is

### 1.1 The pipeline

Read verbatim out of the phase list in `workflows/scan.js` (minified, 31,932 bytes):

| Phase | What it does |
|---|---|
| Inventory | partition the repository into components; every top-level directory scanned or explicitly skipped |
| Threat model | one modeler per component |
| Research | one researcher per component x category cell |
| Sweep | gap-fill over what the matrix did not cover |
| Panel | three-lens adversarial verification, one voter per lens |
| Adversarial | max effort only: repanel marginal keeps, red-team every survivor |

The three lenses are fixed and named in `agents/scan-verifier.md`: **REACHABILITY** (can an
attacker get there), **IMPACT** (does it matter if they do), **DEFENSES** (is something already
stopping it). Each is one voter. The panel arithmetic happens outside every model.

### 1.2 Effort tiers

From `skills/claude-security/jobs/scan-codebase.md`, which is the recipe the Security Lead follows:

- `low`: one researcher over the whole repository, then the three-lens panel. No inventory, no
  threat model, no breadth sweep.
- `medium` (default): the full six-phase workflow, one researcher per component x category cell,
  one breadth sweep, three-lens panel at 2-of-3.
- `high`: as medium, but a wider inventory (24 components), **two** researchers per cell, **two**
  breadth sweeps.
- `max`: as high, plus the adversarial phase.

The panel is fixed at three voters at every tier. The recipe states why: "that is what the
report's confidence figures are calibrated against, so a lower tier does less research and a
higher tier adds work, but neither thins the panel."

A scope resolving to five files or fewer collapses at `medium` to a single-researcher shape.
`high` and `max` run their full shape regardless.

### 1.3 What it costs

There is no published token or dollar figure. Three things are stated:

- code.claude.com/docs/en/claude-security: "each scan counts against your plan's usage limits"
  and the plugin runs locally in the session.
- The recipe forces a fixed confirmation before anything runs, worded: "This scan may take a
  while and may use a significant number of tokens." An unanswered confirmation is a scan that
  never starts. That gate is deliberate and cannot be skipped except by a request that already
  accepted the cost in words.
- `agents/scan-researcher.md` and `agents/scan-verifier.md` both carry `effort: xhigh` and
  `model: inherit` in frontmatter. So every researcher and every voter runs at the top thinking
  tier on whatever model the session is on.

The only calibration we own is our own host audit, which ran a comparable shape by hand: six
hunters at `effort: high` over 1,064 Rust files, each burning 650k to 720k tokens, roughly 4.2M
tokens for the hunt phase alone, plus 21 verifier agents. That was a 31-crate tree. This repo is
17,472 tracked Rust lines across 169 tracked files, which is between one and two orders of
magnitude smaller, so a `medium` run here is not in that range. Stating this as an anchor rather
than a prediction: nobody has published a per-file cost curve and I did not find one.

Prerequisites, from the docs page: Claude Code v2.1.154 or later on a paid plan (the scan uses
dynamic workflows), Python 3.9.6+ on PATH as `python3`, git for change scans and patches. A full
scan works without version control.

### 1.4 The shape of a finding

From `skills/claude-security/specs/report-spec.md`, which is the contract the report is written
against. Each finding is:

```
### F1 - <title> (HIGH, confidence medium)
**Impact.**            what an attacker gets, leading, because it decides priority
**Where.**             path/to/file.rs:123 in function_name
**What.**              two or three sentences naming the untrusted source, the dangerous
                       operation, and why nothing between them stops it
**Exploit scenario.**  a concrete walkthrough, not "an attacker could inject SQL"
**Preconditions.**     bullets. An empty list means none, which the spec says is worth saying
**Fix.**               outcome terms, root cause at the sink, not a patch at one caller
**Verification.**      n/3 lens verifiers confirmed
```

Three products land in `CLAUDE-SECURITY-<UTC timestamp>/`:
`CLAUDE-SECURITY-RESULTS.md`, `CLAUDE-SECURITY-RESULTS.jsonl` (one JSON object per line), and
`CLAUDE-SECURITY-REVISION-<sha12>.json`. The stamp filename carries `-dirty` when uncommitted
changes were part of the scanned tree.

Two properties matter for using this as a judge-facing artifact:

- **The verification status is computed in code, not asserted by a model.** `render_report.py`
  derives `verification.status` from the vote record. The recipe says: "never claim a
  verification status the renderer did not print." Confidence is clamped the same way: a finding
  two of three voters confirmed cannot claim `high` confidence, and the renderer lowers it if the
  report tries.
- **The report directory ships its own `.gitignore` containing `*`.** Nothing in it reaches a
  commit unless that one file is deleted first. That is a deliberate design choice documented on
  the docs page, and it is the step to remember if we want the report in history.

### 1.5 The category vocabulary, which is the load-bearing detail

`agents/scan-researcher.md` gives researchers a fixed slug list and warns that the dedupe key is
`(file, line, category)`, so an off-list slug "silently fails to merge" with the same finding
from another researcher. The list:

- **injection**: sql-injection, command-injection, code-injection, xss, xxe, redos,
  insecure-deserialization, template-injection, header-injection, log-injection, format-string,
  improper-input-validation, prompt-injection
- **authorization**: auth-bypass, improper-authorization, idor, privilege-escalation, csrf, ssrf,
  open-redirect, path-traversal, race-condition
- **memory**: buffer-overflow, out-of-bounds-read, out-of-bounds-write, use-after-free,
  double-free, integer-overflow, null-dereference, uninitialized-memory, type-confusion,
  unsafe-ffi
- **crypto**: timing-side-channel, weak-crypto, weak-randomness, key-nonce-reuse, hardcoded-secret
- **exposure**: info-disclosure, insecure-file-permissions, dos, prototype-pollution

Note what is not there. No slug for a config key that validates and is never read. No slug for an
empty collection satisfying an allowlist. No Solana or Anchor slugs: no missing-signer-check, no
missing-owner-check, no account-confusion, no arbitrary-CPI.

### 1.6 The patch flow

`patch-generator` drafts in a scratch clone; our working tree and index are never touched.
`patch-verifier` then has to vouch for three things before a patch is written at all: the change
addresses that one finding, it introduces no new vulnerability, and it leaves behavior otherwise
unchanged. `skills/claude-security/role.md` adds a definition that is stricter than it looks:
"a change to which inputs the software accepts, beyond the exploit itself, counts as a change in
behavior." When the verifier cannot vouch for all three, we get a note explaining why instead of
a patch. Nothing is ever applied, committed, or pushed.

### 1.7 Trust model, stated plainly by the plugin itself

From `README.md` and `SKILL.md`: the scan runs in our session, under our permissions, with our
settings, hooks, `CLAUDE.md`, and MCP servers in effect. There is no isolation layer. The
repository's contents, including any `CLAUDE.md` and any text addressed to the scan, are treated
as data under review rather than instructions. That is the right model for our own code. It is
not a defense against a hostile repository, and the plugin says so.

---

## 2. Would it find a different class than our host audit did?

### 2.1 What our workflow was actually built to find

`scripts/audit/host-security-audit.workflow.js` is 357 lines and its taxonomy is two values:

```js
category: { type: 'string', enum: ['absent-control', 'inert-control'] }
```

Six dimensions: fail-open-policy, untrusted-to-llm, approval-bypass, capability-sandbox,
secret-handling, blast-radius. The prompt names the vein explicitly: "a security control that
silently does nothing under some configuration, mode, or empty-value. Hunt that class hard,
everywhere." It carried a 20-issue dedupe list so a duplicate would be dropped.

That is a hypothesis-driven audit of **control state**, seeded by three already-accepted findings
of one shape. It is not a general vulnerability sweep and was never trying to be.

### 2.2 The overlap, named finding by finding

Mapping our ten confirmed upstream issues onto the plugin's slug list:

| Our finding | Plugin slug it would carry | In vocabulary? |
|---|---|---|
| #9387 approval responses accepted from any chat member | `improper-authorization` | yes |
| #9386 Gemini key in URL survives sanitization, posted to chat | `info-disclosure` | yes |
| #9389 pairing lockout keyed on attacker-supplied header | `auth-bypass` | yes |
| #9396 approval prompt renders control characters | closest is `log-injection` or off-list | partial |
| #9392 LINE group messages skip allowlist and pairing | `improper-authorization` | yes |
| #9393 Bluesky and Reddit have no sender authorization | `improper-authorization` | yes |
| #9390 emergency stop writes a state file nothing reads | none | **no** |
| #9391 audit logging defaults enabled, writes nothing | none | **no** |
| #9394 pairing_dashboard accepted and entirely unread | none | **no** |
| #9395 plugin wasi:http egress has no destination policy | none | **no** |

So five of ten sit in the plugin's native vocabulary and would plausibly be found by it. Four do
not, and the fourth of those (#9395) is the closest to a normal finding while still having no
slug, because "there is no knob at all" is not a code path.

### 2.3 Why the inert-control class specifically would die in the panel

This is mechanical, not speculative. `agents/scan-researcher.md` defines a finding as:

> "a complete path from an attacker-controlled source to a dangerous operation with no effective
> check in between; anything less is a note, not a finding."

`agents/scan-verifier.md` sets the bar for surviving:

> "Default to FALSE_POSITIVE. Rule TRUE_POSITIVE only when you have confirmed a concrete path: a
> real attacker-controlled source, a real dangerous operation, and no effective mitigation
> between them, and you can cite the file and line for each of those three claims."

An inert control has no attacker-controlled source and no dangerous operation. `[security.audit]`
defaulting to enabled and constructing no logger is a struct field with a serde derive and an
absence elsewhere. There is no line to cite for "the dangerous operation", because the defect is
that nothing happens. A REACHABILITY voter asked "can an attacker get there" has no there. The
finding is real, it is high severity in context, and it would be voted down correctly under the
plugin's own stated standard.

This is a taxonomy boundary, not a defect in the plugin. Our workflow found that class because it
was pointed at it. The plugin will not find it, and that is worth stating in our own write-up as
a claim about what each instrument is for.

### 2.4 The direction that inverts, and this is the reason to run it

Our host audit had six dimensions and every one of them is about **policy, authorization, and
information flow**. Not one is about memory safety, integer behavior, or decoder correctness on
adversarial bytes. The word "overflow" does not appear in the workflow. Neither does
"out-of-bounds", "buffer", or "traversal".

That is exactly the plugin's strongest documented territory. Anthropic's own
https://www.anthropic.com/research/zero-days reports over 500 high-severity vulnerabilities found
and validated in open-source software with Claude Opus 4.6, and all three case studies it details
are this class:

- GhostScript: a bounds-checking flaw in an unpatched code path, found by reading commit history
- OpenSC: buffer overflow risk across successive `strcat` calls, in code fuzzers "infrequently
  studied"
- CGIF: an overflow reachable through understanding the LZW algorithm, which the page says would
  be missed "even if CGIF had 100% line- and branch-coverage"

The page's framing is that Claude "reads and reasons about code the way a human researcher would"
rather than generating randomized input, and that some of these had survived decades of fuzzing.

Now look at what we ship. `crates/solana-core` is 18 files and 4,217 lines of **hand-rolled
binary decoding**: shortvec varint decode, Token-2022 TLV walks, legacy and v0 message parsing,
80-byte nonce account decode, instruction and account-index vectors. We hand-rolled it precisely
because `solana-sdk` does not compile for `wasm32-wasip2`. Every one of the eight plugins links
it. That is the same shape of surface as the three case studies above, and it has never been read
by anything looking for that class.

We have real coverage there, and it is worth being precise about what kind. Kani proves
canonicality over all 16,777,216 three-byte shortvec inputs. The exhaustive suite walks all 65,535
Token-2022 extension discriminants. The differential fuzzer ran 220,000 iterations across five
seeds against solana-sdk's own deserializer. Twenty-three property tests. Those are strong, and
they are all **oracle-shaped**: they compare our output against a property we chose or against a
reference decoder on inputs we generated. A reading-based researcher looking for an
out-of-bounds read on an attacker-shaped TLV length is a different instrument with a different
failure mode, and the zero-days page argues exactly that point about coverage-complete fuzzing.

Two further classes we have no coverage for at all:

- **The pay page and the scripts.** `webshop-pay/index.html` decodes a base64 URL parameter and
  renders it. Twenty tracked `.py`/`.js`/`.html` files. The plugin's vocabulary has `xss`,
  `open-redirect`, `prototype-pollution`, `path-traversal`. We hardened the pay page by hand
  against XSS using DOM/textContent, and we have never had an independent read of it.
- **Committed secrets.** This repo has already had two private-identifier leaks purged from
  history, both found by grepping content rather than paths, and one of them (`webshop-pay/build.py`)
  was invisible because the incident it belonged to had been closed. The plugin runs a dedicated
  secrets pass whenever `focus` is set, and it still checks fixtures for real committed keys.
  That is an independent control over exactly the failure we have already committed twice.

### 2.5 Honest answer to the question as asked

**Different class, in both directions.** The plugin will not find the accepted-and-inert-control
family that produced half our upstream issues, because that family has no slug and does not
satisfy the panel's source-to-sink standard. Our workflow could not have found a bounds error in
a TLV walk, because none of its six dimensions asks about one. The two are close to disjoint,
which is the strongest possible argument for running both, and it is a defensible sentence to put
in the write-up.

---

## 3. Where to point it

### 3.1 The size gauge decides the shape, and we are on the good side of it

The recipe's rule: "Under a few hundred files the tree is small enough to read whole; above that
it is large." `git ls-files` in `zeroclaw-solana` returns **169**. That puts us firmly in the
small-tree regime, which has three consequences worth having:

1. **Whole repository is the recommended pick**, not a scoped scan. The recipe marks the
   size-appropriate option " (Recommended)" and puts it first.
2. **`focus` should be `null`.** The recipe sets `focus: "attack-surface"` only for a large tree.
   With focus null, tests and fixtures are read as targets rather than as background. Given that
   our test suites are where a lot of the decoder logic is exercised, that is the read we want.
   The tradeoff: the dedicated secrets pass runs "whenever focus is set". If we want the secrets
   pass specifically, that argues for setting focus. Decide this explicitly rather than by
   default. My recommendation is `focus: null` for the main run, since 169 files is cheap to read
   whole and we already have two purge sweeps plus `deploy-leak-guard.py` on the secrets side.
3. **The completeness ledger can return `checked`.** On an unscoped whole-repository scan the
   workflow requires the inventory to account for every top-level directory, scanned or
   explicitly skipped, and that check runs in code before the search begins.
   `coverage.completenessCheckOutcome` comes back `checked`, `partial`, `not-checkable`, or
   `not-applicable`. A scoped scan returns `not-applicable`. **Only the whole-repository shape
   can produce `checked`**, and `checked` is what turns a zero-finding report from "not examined"
   into "covered and clean". That distinction is the whole reason to run this on a small repo
   rather than a scoped slice.

Our seventeen top-level directories, all of which the inventory must account for:
`.github crates differential-fuzz docs e2e-allowance e2e-localnet e2e-track-a microworld onchain
plugins sanitizer-microworld scripts skills sops webshop-pay wit x402-feed-gate`.

### 3.2 Ranked by expected yield, if we ever want a second scoped run

1. **`crates/solana-core`** (18 files, 4,217 lines). Hand-rolled binary decoders. Every plugin
   links it, so one finding here is a finding in all eight. Highest density of the class the
   plugin is best at.
2. **`x402-feed-gate`** (3 files). The only component with a genuine unauthenticated remote
   attacker: an HTTP server that accepts a base64 `X-PAYMENT` header, decodes JSON, introspects a
   transaction, and sends it. The plugin's severity rubric explicitly raises severity for
   "unauthenticated with no interaction on a default deployment", so this is where a HIGH would
   come from if one exists.
3. **`webshop-pay` and `scripts`** (20 tracked py/js/html files). Browser-facing parameter
   decoding, plus the certifier and the broadcaster. Different language, different vocabulary,
   zero prior independent read.
4. **`plugins/`** (8 plugins, roughly 20 `.rs` files). The shipped surface. Well covered by our
   own tests, which lowers expected yield but raises the value of a clean result.
5. **`onchain/programs`** (2 files). Run it, but calibrate expectations down. The category
   vocabulary has no Solana or Anchor slugs. Do not present a clean result here as a Solana
   program audit, because the instrument does not have the words for the findings a Solana
   auditor looks for.

### 3.3 Why not the host

`zeroclaw-host` is the wrong target for four independent reasons:

- We already audited it, and the audit discriminated: 213 candidates, 176 dropped at the hunt
  stage, 21 verified, 10 confirmed, 11 partial. That is a completed pass.
- The class the plugin adds is authorization and injection and memory. The tracker already
  carries 20 or more issues from other parties across those shapes, including `#9247` shell
  workspace boundary bypass and `#9255` unbounded plugin calls. Our own workflow's dedupe list
  documents this. A duplicate filed upstream is worse than nothing for us.
- It is 1,064 `.rs` files across 31 crates, which is a large tree. That forces a scoped scan,
  which forces `completenessCheckOutcome: not-applicable`, which is the weakest result shape. It
  is the most expensive option and the one that produces the least defensible artifact.
- Nothing on the scored axes rewards it. The rubric scores our use case, our custody, and our
  craft. A report on someone else's code is evidence about someone else's code. We already
  extracted the submission value from the host by publishing `docs/HOST-SECURITY-AUDIT.md` and
  filing the ten issues.

---

## 4. Go / no-go, with the reasoning

**GO.** One run, `medium`, whole repository, on `zeroclaw-solana`.

Four reasons, in order of weight:

1. **It reads a class nobody has read on our code.** Section 2.4. Our six audit dimensions
   contain no memory, decoder, or traversal lens. Our correctness layers are oracle-shaped. The
   plugin is a reading-based researcher, and Anthropic's own zero-days work argues specifically
   that this finds bounds errors that coverage-complete fuzzing does not.
2. **The artifact is judge-legible and independently produced.** A revision stamp tied to a
   commit, a `verification.status` computed in code rather than asserted by the model that wrote
   the findings, and per-finding vote counts. This project's existing evidence is almost entirely
   self-produced, the host audit included. An external instrument over our own code is a
   different kind of evidence, and it lands on both the safety axis (25) and the craft axis (20).
3. **It is cheap here and only here.** 169 files is the regime where the whole-repository shape
   is both affordable and able to return `completenessCheckOutcome: checked`.
4. **A zero-finding result is still a result.** The docs and the report spec both say so:
   "An empty report is a real and common result", and "No findings is a complete report, and
   writing it well, what you covered, what you did not, is more valuable than a page of maybes."
   Zero findings over a `checked` ledger on the code we ship is publishable. That is the downside
   case, and it is not a loss.

**NO-GO on `zeroclaw-host`.** Section 3.3.

**Where this plan says no to manufactured work.** The honest limit is that our existing audit
does cover the host, and re-running any instrument there is busywork dressed as diligence. It is
also true that our eight plugins and `solana-core` have had three cold code reviews, a 14-defect
adversarial audit, and six correctness layers. If the plugin returns nothing, the correct
write-up sentence is that an independent multi-agent scan over the shipped tree found nothing,
with the coverage ledger quoted, and not a paragraph of hedging.

### 4.1 Preconditions to clear before running

Four, and each is checkable now.

1. **Commit first.** The stamp filename carries `-dirty` when uncommitted changes are in the
   scanned tree. A `-dirty` stamp on a submission artifact is weaker evidence than a clean one.
   As of this writing the uncommitted work on `#9382` and `#9385` lives in `zeroclaw-host`, not
   here. Verify `git status` in `zeroclaw-solana` is clean before starting.
2. **The schema-cap guard will not fire.** Our own `workflow-schema-cap-guard.py` denies any
   workflow putting `maxLength` or `maxItems` on an agent-filled field. It was built after that
   exact defect ate six completed audit agents. **Checked: `workflows/scan.js` contains zero
   occurrences of `maxLength` and zero of `maxItems`.** So the guard will not block the scan.
   Worth having checked rather than discovering it twenty minutes in.
3. **Sixty other hooks are in effect and the plugin says so.** The scan runs "with your session's
   configuration (settings, hooks, `CLAUDE.md`, MCP servers) in effect as usual". This machine
   has about 60 registered hooks. The ones most likely to interact: `workflow-pacing-guard`,
   `workflow-silent-drop-guard`, `subagent-validator`, `subagent-audit`, `task-completion-gate`.
   None is known to deny a vendored workflow, but the scan runs unattended for tens of minutes
   and a hook denial mid-run is the expensive failure. Consider a `low` effort dry run first,
   purely as a harness test, since `low` is one researcher plus the panel and completes fast.
4. **Auto mode.** The plugin states it works best in auto mode and prints a fixed line saying so.
   Without it, every subagent step can hit a permission prompt, and the whole value of the run is
   that we walk away from it.

### 4.2 The run, concretely

Menu path: `/claude-security`, then Scan codebase, then Whole repository at medium, then Yes.

One-line path, which skips the sub-menu because it names both shape and effort, and skips the
confirmation because it accepts the cost in words:

    /claude-security scan the whole repository at medium effort, and I understand it
    will take a while and use a significant number of tokens

The recipe is explicit that only words accepting the scan's time or token cost count as the
"Yes". Naming the job or the effort is not enough, and neither is "just run it".

Afterward the report lands in `CLAUDE-SECURITY-<timestamp>/`. To publish it, delete that
directory's own `.gitignore` and commit the directory, then link it from the README table and
from the write-up's testing section, beside `docs/HOST-SECURITY-AUDIT.md`. This project has
parked real work where a reader could not reach it five times. The report is worth nothing if it
sits behind its own `.gitignore`.

### 4.3 What to do with findings

Do not run Suggest patches blind on the whole set. Read each finding first, because both audits
this project has already run produced findings whose severity was wrong or whose exploit path
was falsified: 11 of 21 came back PARTIAL on the host audit. Then, per finding:

- **A confirmed finding in `solana-core`** is the highest-value outcome and should be fixed by
  hand with a regression test that fails before the fix, matching how every other defect in this
  repo was closed. The patch flow is a fallback, not the default.
- **A confirmed finding anywhere** gets a line in `docs/AUDIT.md`, which already publishes our
  own defects and their reasoning. Consistency matters: we publish defects found in someone
  else's code, so hiding our own would be the inconsistent option, and that call was already made.
- **A false positive we disagree with** is worth recording too. The panel's reasoning cites a
  decisive `file:line`, so a disagreement is checkable rather than a matter of taste.

---

## 5. What belongs in the owner's global config

Three items, ordered by value. All are outside this repo.

### 5.1 Install `security-guidance`, user scope

This is the item with the best ratio and it is not the same plugin. From
https://code.claude.com/docs/en/security-guidance, read today:

- Three layers: a per-edit deterministic pattern match with **no model call and no usage cost**;
  an end-of-turn background review of the turn's git diff; and a deeper agentic review on each
  `git commit` or `git push` Claude runs through Bash.
- The end-of-turn review catches authorization bypass, IDOR, injection, SSRF, weak crypto. It
  covers up to 30 changed files per turn and fires at most three times in a row.
- The commit review is capped at 20 per rolling hour and reads surrounding code before reporting.
- Both model-backed layers use Claude Opus 4.7 by default, overridable via
  `SECURITY_REVIEW_MODEL` and `SG_AGENTIC_MODEL`.
- **It only reviews commits Claude makes through its Bash tool.** Commits run from the user's own
  shell, including the `!` escape inside a session, are not reviewed.
- Available on all plans.

Install with `/plugin install security-guidance@claude-plugins-official` at **user scope**, then
`/reload-plugins`.

Why it belongs globally rather than in this project: it is a hooks plugin firing on every edit
and commit in every repo, and this machine's agent writes code across many repos. It is also
architecturally the same thing this project already built by hand, sixty times over, in
`~/.claude/hooks/`. Its source is worth reading as a reference implementation of running a
separate model call from a hook and feeding the result back into the session; the docs point at
`anthropics/claude-plugins-official/tree/main/plugins/security-guidance` for exactly that.

One caveat before installing: on first run it creates a virtualenv under `~/.claude/security/`
and pip-installs the Claude Agent SDK into it, which needs pip and network access. Disk is fine
now (15.28 GB free), but the install is a real side effect and it is worth knowing it happens.

### 5.2 A user-scope `~/.claude/claude-security-guidance.md`

The security-guidance plugin loads a plain-language threat model and review checklist from three
locations and concatenates them, capped at 8 KB combined:

| Scope | Path |
|---|---|
| User | `~/.claude/claude-security-guidance.md` |
| Project | `.claude/claude-security-guidance.md` |
| Project local | `.claude/claude-security-guidance.local.md` |

The user-scope file is where this machine's recurring, cross-project security lessons belong. The
candidates are already written down and already proven, which is what makes this cheap:

- The accepted-and-inert control pattern, stated as a review question rather than a prohibition:
  for any config key added, is there a runtime read of it, and does a test assert behavior rather
  than parsing. Five of ten upstream findings were this. `~/.claude/rules/verify-before-acting.md`
  rule 24 already carries the sweep direction; this is the reviewer-facing half.
- An empty collection must not satisfy an allowlist. Three independent instances found in one
  codebase, plus a rival's merged fix on the same shape in the x402 payee allowlist.
- Credentials must never enter a URL query string, and error text must have the query string
  stripped rather than a vendor prefix added to a scrubber list. That is the exact recommendation
  filed as `#9386`. The property is the fix; the list is not.
- A control that runs after the decision it is meant to bind is not a control. Two instances in
  our own upstream PRs: the `#9382` ordering bug and `#9385`'s revocation bypass.

The docs are explicit that these are guidance for the reviewer, not deterministic guardrails, and
that a rule saying to ignore a vulnerability class does not suppress those findings. For hard
enforcement the docs point at hooks, which this machine already prefers under the standing
hooks-primary directive.

### 5.3 A user-scope `~/.claude/security-patterns.yaml`

Deterministic, zero model cost, fires on every edit in every project. Schema fields are
`rule_name`, `reminder` (capped at 1 KB), `regex` or `substrings`, optional `paths` and
`exclude_paths` globs, up to 50 rules loaded. Globs match the full path, so project-relative
patterns need a `**/` prefix. YAML needs PyYAML importable; `security-patterns.json` works on any
Python install.

The two rules this machine has already paid for:

- The private-identifier leak. Two separate git-history purges this project needed, both found by
  grepping content rather than paths. A substring rule on the account name and on the home path
  would have warned at the write.
- The credential prefixes: `AIza`, `sk-ant-`, `sk-proj-`, `enc2:`. Partly covered by
  `deploy-leak-guard.py` and `pass-output-redaction.py` already, so check for overlap before
  adding. A duplicate rule in an always-loaded surface is its own cost.

Note the overlap risk generally. This machine has 59 hook files and 60 registered hooks. Before
adding anything here, grep the existing corpus twice, once on literal phrasing and once on
concept terms. Every one of the ten duplicates caught during the arc-mine audit returned zero
hits on literal phrasing and was caught only on concept terms.

### 5.4 Deliberately not recommended

- **The managed Claude Security product.** https://claude.com/product/claude-security states it
  is "Available in public beta for Claude Enterprise", with Team and Max coming later per the
  public beta post. It is a hosted service monitoring connected repositories, with webhooks for
  Slack and Jira, scheduled scanning, scoped scans, and CSV and Markdown export. Not applicable
  to this account and not needed: the docs note the plugin reaches code the managed product
  cannot, including repositories on networks that do not allow inbound connections, which
  describes this one.
- **`/security-review` as a substitute.** It is a single pass over the current branch. The
  layering table on the docs page places it below the plugin. Given we are running the plugin
  once over the whole tree, the single pass adds little.

---

## 6. Sources, and what each one settled

| Source | Read | What it settled |
|---|---|---|
| Installed plugin v0.10.0, 29 files | in full for every file cited | pipeline phases, effort tiers, category vocabulary, verifier standard, report shape, trust model |
| `workflows/scan.js` (minified, 31,932 B) | phase list, tier branches, coverage object, cap grep | phase titles verbatim; zero `maxLength` and zero `maxItems` |
| code.claude.com/docs/en/claude-security | yes | prerequisites, products, layering table, scoping guidance, patch flow |
| code.claude.com/docs/en/security-guidance | yes | the three layers, costs, extension points, lookup paths, env toggles |
| claude.com/blog/claude-security-public-beta | yes | Enterprise public beta, Opus 4.7, five named customers, no published detection rates |
| claude.com/product/claude-security | yes | beta feature list, plan availability, no pricing and no benchmarks published |
| anthropic.com/research/zero-days | yes | 500+ high-severity vulnerabilities, three case studies all memory and bounds class, reading over fuzzing |
| `docs/HOST-SECURITY-AUDIT.md` | yes, 139 lines | the ten findings, the 213 to 10 ratio, the inert-control pattern |
| `scripts/audit/host-security-audit.workflow.js` | yes, 357 lines | the two-value taxonomy, six dimensions, rules of evidence, dedupe list |

Neither the blog post nor the product page publishes a detection rate, a false-positive rate, or
a price. The customer quotes from DoorDash, Snowflake, Column, Yuno and Hebbia are qualitative.
Anyone citing a number for this tool's accuracy is citing something that is not on either page.

---

## 7. The rest of the stack, and what it costs

The docs page carries a layering table. Repeating it with the cost facts attached, because the
prices differ by an order of magnitude and only one of them is published as a dollar figure.

| Stage | Tool | Cost | Available to us |
|---|---|---|---|
| In session, per edit | security-guidance pattern match | no model call, no cost | yes, all plans |
| In session, per turn and per commit | security-guidance model reviews | counts as normal usage, Opus 4.7 default, commit reviews capped at 20 per rolling hour | yes, all plans |
| On demand, single pass | `/security-review` | normal usage | yes |
| On demand, deep scan | claude-security plugin | counts against plan usage limits, no published figure | yes, paid plan, v2.1.154+ |
| On demand, local diff | `/code-review` | normal usage; runs as a background subagent with its own context window | yes |
| On pull request | Code Review, managed | **$15 to $25 per review on average**, billed via usage credits separately from plan usage | no, Team and Enterprise only |
| Managed, hosted | Claude Security product | consumption billing, "costs scale with the size and number of scans" | no, Enterprise only |

Two things worth carrying out of that table:

- **Code Review is the only one with a published price**, and it is not cheap: $15 to $25 per
  review, scaling with PR size and complexity, completing in 20 minutes on average. It is Team
  and Enterprise only and is not available to this account. The local `/code-review` command is,
  and it needs no GitHub App.
- **The managed Claude Security product has real prerequisites** beyond the plan, per
  claude.com/resources/tutorials/getting-started-with-claude-security: an active Enterprise
  account, Claude Code on the Web enabled, Extra Usage turned on for consumption billing, a
  GitHub App installed with repository access, and premium user seats. Its own guidance for large
  repositories matches what section 3.1 argues here: "we highly recommend picking a directory to
  increase the success rate." Scans "may take several minutes or hours."

The managed product's triage workflow is worth knowing about even though we cannot use it,
because it names the discipline the plugin leaves to us: export findings, open a remediation
session, dismiss false positives **with a documented reason**, work highest severity first, run
on a cadence, assign a named owner. The plugin gives no dismissal record. If we run it more than
once we should keep our own, which is what `docs/AUDIT.md` already is.

### One more piece of context on the direction of travel

https://www.anthropic.com/research/critical-infrastructure-defense is the adversary-emulation
half of the same research line: Anthropic and Pacific Northwest National Laboratory ran Claude
Sonnet 4 against a cyber-physical water treatment simulation, and an attack reconstruction the
page says would have taken a human expert multiple weeks took three hours. It is not directly
usable here, but it is the same claim as the zero-days page pointed at offense instead of
defense, and it is the reason the plugin's researchers are told to reason rather than to
pattern-match. Worth citing in the write-up only if we want one sentence on why a reading-based
scanner is a different instrument from a linter, and not otherwise.
