---
audience: internal
---

# Standing-paste compliance ledger

What in the re-pasted mega-prompt is satisfied and droppable, what must stay, and what is now wrong.
Built 2026-07-27 by reading the six ask files in full and checking every claim against artifacts on
disk rather than against the docs that assert them.

Scope note: `ambition.txt` is not a task file. It is a pasted X thread (Franz Bruckhoff, 2026-07-21)
already folded into the always-loaded standing bar as "EXTERNAL ANCHOR". It is treated as one row.

---

## 1. CUT LIST — safe to delete from the paste

These are DONE-VERIFIED: the ask is satisfied AND the artifact proving it was opened this session.

1. **A2** "put it down somewhere so nothing is lost" — the post-compact context artifact exists.
2. **A3** "the resumption post-compact should be airgapped/lossless" — it is, and it auto-loads.
3. **A4** "all valuable lessons this session compounded so new claudes anywhere don't repeat them".
4. **C1** "compound this session fully, at the right level/scopes/locations".
5. **C3** "ensure failure modes that could easily be avoided are reduced or eliminated" — hooks.
6. **P2** "follow the files listed below" — every listed path resolves except one (see STALE §3).
7. **AMB** the Bruckhoff ambition anchor — already verbatim in the always-loaded bar.

Everything else stays. Seven of roughly twenty-four asks are droppable, which is the honest number:
most of this paste is not a task list, it is a standing disposition, and disposition never completes.

---

## 2. KEEP LIST

### (a) Still-outstanding work — the paste is doing real tracking here

| Ask | Why it stays |
|---|---|
| **C2** full-jsonl compound "including the jsonl from the last export/compound checkpoints" | The arc mine is complete only through 2026-07-26. Four session JSONLs dated 2026-07-27 (158,078 bytes) are outside the coverage map. |
| **A1-open** "we still have many open tasks as well as the primary one" | The ranked queue in `HANDOFF-POST-COMPACT.md` still carries #87, #88, #86, #19, #67, #27, #15. |
| **B1** "redo/launch any failed/incomplete agents" | Recurring, not a one-time act. Fires on every fan-out. |

### (b) TIMELESS instructions NOT yet wired into an always-loaded surface

**This is the highest-value section. Anything here dies the moment you stop pasting.**

The audit found **one** genuinely unwired item, plus one wired-but-broken pointer:

| Item | Status |
|---|---|
| **P2-list** `load-execute-skills-commands.txt` ("use these proactively/situation-wise") | The FILE is never referenced by any always-loaded surface, and it is STALE (§3). `~/DEV/CLAUDE.md` carries a fresher overlapping table, so the capability survives; the file does not. Either drop the reference or regenerate the file. |
| **B-src** the standing bar's provenance pointer to `continue-after-hitting-limit.txt` | That path does **not exist**. The live file is `continue-after-hitting-limit-or-interruption.txt`. The bar's *content* is fine; only its source citation dangles. |

Everything else in the paste's timeless half is already wired and survives without you:

- `permissions.txt` delegation -> `~/.claude/CLAUDE.md` operating-default paragraph, `operate-at-the-frontier-by-default.md` rule 1, and this project's `.claude/GOAL.md` ("Full agency is delegated... not a warden").
- `research.txt` (data/experts/exhaustive research decide) -> quoted verbatim as §"RESEARCH / DATA / DOMAIN-EXPERTS DECIDE, EXHAUSTIVELY" in `standing-excellence-bar.md`, which `~/.claude/CLAUDE.md:202` `@`-imports.
- `prompts.txt` -> same file, §"VERIFIED / EMPIRICAL / MULTI-CORROBORATIVE"; its signature line greps 1 hit in the bar.
- `continue-after-hitting-limit-or-interruption.txt` -> §"CONTINUE UNLESS GENUINELY BLOCKED / NO MINIMIZATION" in the bar, plus `workflow-pacing-mode.md` (limit-type table, scope invariant) and `deadline-does-not-modulate-quality.md`.
- `pre-compact-prompt.txt` + `full-compound-instructions.txt` -> `CLAUDE.local.md` standing duty #5 cites both by path; `session-completion-checklist.md` item 8 carries the mine procedure.

---

## 3. STALE / CONTRADICTED

1. **`load-execute-skills-commands.txt` names six dead commands.** It lists `/ce:brainstorm`,
   `/ce:plan`, `/ce:work`, `/ce:review`, `/ce:compound`, `/ce:compound-refresh` — the colon form.
   `verify-volatile-data.md` records that CE renamed every skill to the `ce-` prefix and that the
   colon forms last dispatched 2026-04-14, dead ~3 months. It also lists `/ce-sessions`, which
   `~/DEV/CLAUDE.md` marks NOT INSTALLED.
2. **The standing bar cites a filename that does not exist** (`continue-after-hitting-limit.txt`).
3. **`permissions.txt` line 4 is a retirement note**, not an instruction — `claude-code-workflow-addendum.md`
   was retired 2026-07-17. Correct, but it is inert text in a re-pasted prompt.
4. **B4's "the limit has reset now, relaunch the subagent"** is a point-in-time instruction from a
   past incident. The durable half is already a rule; the incident half is spent.

---

## 4. The ledger

| # | Ask (operator's words) | Source | Status | Evidence | Safe to cut? |
|---|---|---|---|---|---|
| A1 | "what would you write as context for the post-compact?" | pre-compact | **DONE-VERIFIED** | `HANDOFF-POST-COMPACT.md`, read in full; newest block "SESSION 2026-07-27 ~14:00-15:00". Per-session blocks back to 2026-07-20. | YES |
| A2 | "put it down somewhere so nothing is lost" | pre-compact | **DONE-VERIFIED** | Same file, plus `docs/BUILD-JOURNAL.md` (438,370 B, entries dated 2026-07-27). | YES |
| A3 | "the resumption should be airgapped/fully-lossless/gapless" | pre-compact | **DONE-VERIFIED** | `CLAUDE.local.md` `@`-imports `HANDOFF-POST-COMPACT.md` and `docs/COMPLIANCE-AUDIT.md` (47,888 B), so both re-inject after compaction without a paste. | YES |
| A4 | "all valuable lessons this session... for each level/scope" | pre-compact | **DONE-VERIFIED** | `.compound-tmp/arc-audit-progress.json`: `clusters 28, placed 20, verified_already_covered 8, rule_additions 31, status COMPLETE`. Spot-checked four placements live in the loaded corpus: `verify-before-acting.md` r28/r33, `walkback...md` step 5, `auth-verification...md` browser-enumeration, `claude-code-windows.md` grep -c. | YES |
| A5 | "we still have many open tasks as well as the original/main/primary task" | pre-compact | **PARTIAL** | Primary task is durable (`.claude/GOAL.md`, win condition + deadline 2026-08-07T02:59:59Z). Open queue is real: #87 streaming/fallback A-B, #88 C+D, #86 group runtime path, #19 synthetic liveness, #67 repo public, #27 mainnet, #15 demo capture. | NO — queue live |
| A6 | "after everything objectively best and compounded — with no issues/noise" | pre-compact | **TIMELESS** | Standing quality bar. Wired: `standing-excellence-bar.md` (@-imported), `no-shortcuts.md`, `anti-slop.md`. | NO — standing instruction (wired) |
| P1 | "dynamic permission always/auto granted/denied by me on everything, only gated by ceiling/objectively-best" | permissions | **TIMELESS** | Wired three places: `~/.claude/CLAUDE.md` operating-default; `operate-at-the-frontier-by-default.md` r1; `.claude/GOAL.md` mandate. | NO — standing instruction (wired) |
| P2 | "gated by longterm-thinking, durable/timeless/gapless/non-degrading-nor-step-down" | permissions | **TIMELESS** | Wired: `execute-dont-ask-when-workflow-is-obvious.md` r6 states the delegation gate verbatim, including that it can resolve to "do nothing and say why". | NO — standing instruction (wired) |
| P3 | "following research.txt and every other file listed below" | permissions | **DONE-VERIFIED** | 4 of 5 listed paths exist: `standing-excellence-bar.md` (14,244 B), `continue-after-hitting-limit-or-interruption.txt`, `prompts.txt` (12,657 B), `load-execute-skills-commands.txt` (21,143 B). Line 4 is a retirement note, not a path. | YES (but see STALE 1) |
| C1 | "compound this session fully, at the right level/scopes/locations" | full-compound | **DONE-VERIFIED** | `arc-coverage-map.json`: `windows_defined 37, windows_covered 37, findings_files 39, files_under_1kb 0, complete: true`, generated 2026-07-26. Integrity verified by payload, not completion status. | YES |
| C2 | "...including the post-compact export and/or the jsonl from the last export/compound checkpoints... and/or the full jsonl?" | full-compound | **PARTIAL** | Complete through 2026-07-26. **Four JSONLs dated 2026-07-27 are outside the map**: `a2131210` 34,631 B, `95c600bd` 35,426 B, `5f658129` 50,409 B, `d8709a6e` 37,612 B = 158,078 B unmined. Per-turn capture did happen (handoff blocks + rule placements), so this is a missing formal mine, not lost content. | NO — 158 KB unmined |
| C3 | "update/strengthen whatever needs hardening/strengthening" | full-compound | **TIMELESS** | Continuous. Wired: `walkback-requires-structural-enforcement.md`, `redecision-doc-sweep.md`. | NO — standing instruction (wired) |
| C4 | "ensure failure modes that could easily be avoided are reduced so they occur less and less or eliminated" | full-compound | **DONE-VERIFIED** | All ten hooks named in the handoff exist on disk: `unread-review-guard`, `workflow-schema-cap-guard`, `unreachable-artifact-guard`, `instance-vs-class-guard`, `local-creds-first`, `git-trailer-guard`, `detector-goodhart-guard`, `prior-decision-guard`, `sync-clash-guard`, `workflow-pacing-guard`. | YES |
| C5 | "in a universal/intelligent/timeless/generalizable/non-[hardcoded/bloat]" way | full-compound | **TIMELESS** | Scope-discipline gate. Wired: `context-management.md` "Config Quality Gates" + the PostToolUse scope-check on writes to rules/memory/CLAUDE.md. | NO — standing instruction (wired) |
| B1 | "continue. full/complete/gapless. redo-do/launch any failed/incomplete agents" | continue-limit | **TIMELESS** | Wired: `agent-prompt-discipline.md` r5/r11/r12 (relaunch at full scope, never approximate). | NO — standing instruction (wired) |
| B2 | "don't let the limit/classifier affect your behaviour" | continue-limit | **TIMELESS** | Wired: `workflow-pacing-mode.md` limit-type table ("NOT a behavior signal"). | NO — standing instruction (wired) |
| B3 | "nothing subpar/below objective best. make sure no continuation gaps" | continue-limit | **TIMELESS** | Wired: `no-shortcuts.md`, `session-discipline.md`. | NO — standing instruction (wired) |
| B4 | "never mind the subscription-limit/glitch, it has reset now... relaunch the subagent (full scope)" | continue-limit | **STALE** | Point-in-time. The durable half is B1/B2. No live agent is parked on a limit: last workflow `wf_a3014de6-6f6` completed 3/3, 0 errors. | NO — but reword to the durable half |
| B5 | "if the limit is server/traffic-side, adapt strategy/pace/sequence/batch while still achieving full scope" | continue-limit | **DONE-VERIFIED** | Structurally enforced. `~/.claude/.pacing-mode` reads `paced`; `workflow-pacing-guard.py` denies unpaced fans and named built-in launches. Scope invariant is explicit in the rule. | NO — standing, but wired |
| R1 | "whatever objectively best/complete/diligent/empirical/gapless... data, domain experts, deep research, root-cause be the ultimate judges" | research | **TIMELESS** | Quoted verbatim in `standing-excellence-bar.md`; `research-default.md` + `verify-before-acting.md` (35 rules) operationalize it. | NO — standing instruction (wired) |
| R2 | "always researching/confirming comprehensively/exhaustively... never leaving to chance/gut feel/bias/polluted context" | research | **TIMELESS** | Wired: `verify-before-acting.md` r16 (open the primary artifact), `claim-verification.md`. | NO — standing instruction (wired) |
| AMB | Bruckhoff: aim at complexity x excellence, floor-level output is negative-value, the lunatic heuristic | ambition | **DONE-VERIFIED** | Folded verbatim into `standing-excellence-bar.md` §"EXTERNAL ANCHOR — the AI-era ambition math", which is `@`-imported at `~/.claude/CLAUDE.md:202`. | YES |
| L1 | "use all that helpful/useful/relevant in `load-execute-skills-commands.txt` proactively" | permissions -> prompts | **STALE** | File lists 6 dead `/ce:` colon-form commands and `/ce-sessions` (NOT INSTALLED). `~/DEV/CLAUDE.md` carries a current overlapping table. | NO — regenerate or drop the pointer |

---

## 5. Two contradictions found, reported rather than resolved

**Contradiction A — the demo-video blocker.** `docs/COMPLIANCE-AUDIT.md` S3 says the remaining gap
is "ONE thing: Beat 1's phone half (a handset on camera plus the agent replying, which needs the
WSL-bound shop daemon)". The 2026-07-27 handoff block says that blocker "is STALE twice over" (the
shop is off the laptop and on the ARM node since 00:0x, and the WhatsApp half was driven from the
connected browser with no handset). Both documents are always-loaded. The audit row is the stale
one, but I did not edit it. The open question the handoff names is *capture*, not the handset.

**Contradiction B — what a compound checkpoint covers.** `arc-coverage-map.json` reports
`complete: true`, and `arc-audit-progress.json` reports `status: COMPLETE`. Both are true **as of
2026-07-26** and neither carries an expiry, so a future session reading either one will conclude
the arc is mined while 158 KB of 2026-07-27 sessions sit outside it. This is the exact
"a count in a plan is not a count of what ran" trap the handoff records twice.

---

## 6. Suggested replacement paste

Delete asks A1-A4, C1, C3(hooks half), P3, AMB. Keep, in about six lines:

- the standing bar reference (one path, `~/DEV/standing-excellence-bar.md` — it is already
  auto-loaded, so this is belt-and-braces, not load-bearing);
- "compound the windows since the last coverage map, not the whole arc";
- the open queue pointer (`HANDOFF-POST-COMPACT.md` -> OPEN, RANKED);
- B4 reworded to its durable half.

Everything else in the paste is either already in context before you type, or now wrong.
