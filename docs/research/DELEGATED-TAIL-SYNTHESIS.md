# Delegated tail: one ranked action list

Written 2026-07-26 from the three research files in this directory. Deadline 2026-08-07.

**Read this first.** The submission is at or near ceiling on the two axes that carry 45 percent
between them, and the remaining work is narrow. Nothing below is a rescue. Four of the five ranked
actions are packaging, framing, or independent verification of work that already exists, and the
fifth is finishing two upstream pull requests that are already open. Section 2 is longer than
section 1 on purpose. More than half of what the four agents recommended should not be done.

## What I verified myself, and what I am relaying

Verified in this session, with the command run:

| Claim | Check | Result |
|---|---|---|
| `.tools/` is gitignored | `git check-ignore -v` | `.gitignore:28:.tools/`, confirmed |
| Both explain-diff artifacts exist | `ls -la .tools/explain-*.html` | 18,782 B and 20,123 B, both present, both unreachable from a clone |
| Two microworld directories are tracked | `git ls-files` | 6 paths under `microworld/`, 4 under `sanitizer-microworld/` |
| Which microworld a reader is pointed at | grep of README, write-up, QUICKSTART | **They disagree. See action 1.** |
| Channel-plugin eligibility | grep of `docs/LISTING-VERBATIM.md` lines 24 to 118 | **Resolved. See section 2, item 1.** |
| Working tree state | `git status --short` | Clean except untracked `docs/research/` and `notes/` |

Relayed without independent verification: every rival repository claim in the competitive file
(the agent states these are quoted from PR bodies and repo metadata, not from reading rival source),
the installed claude-security plugin's internals, and every external source summary in the corpus
file. Each of those files names its own gaps in its method section.

---

## 1. The five highest-value actions, ranked

### 1. Make the unreachable artifacts reachable, and fix the microworld contradiction

**Axis: craft 20, showcase 10. Effort: 45 minutes.**

Two separate defects, one fix session.

The explain-diff artifacts sit at `.tools/explain-2026-07-25.html` and
`.tools/explain-2026-07-25-evening.html` inside a gitignored directory. A markdown-wide grep finds
five references, four of them in private files. A judge's clone contains neither the artifacts nor
any pointer to them, so the whole cognitive-debt cluster currently scores zero while the work sits
finished on disk. This repo has now committed that same failure six times by its own count.

The microworld defect is worse than the corpus agent reported, and I found it by checking which
file a reader is actually sent to rather than by diffing the two directories:

- `README.md:36` points at `microworld/sanitizer.html`
- `docs/WRITEUP-DRAFT.md:245` points at `sanitizer-microworld/index.html`

Both files carry the title `Sanitizer microworld`. So the problem is not that a cloner finds two
directories and cannot tell which is canonical. It is that our two judge-facing documents send a
reader to two different files, and a judge who opens both learns that we do not know which artifact
we shipped. Pick one, delete or clearly subordinate the other, and make both documents agree.

Do this first because it is cheap, because it is entirely in our control, and because action 3
depends on part of it (`.tools/slop_check.py` has the same reachability problem).

### 2. One write-up framing pass, four edits

**Axis: craft 20, and originality counts double. Effort: 90 minutes, single editing session.**

Four changes to `docs/WRITEUP-DRAFT.md`, all pure writing, no engineering:

**Move the originality weight off comprehension artifacts.** Litt gave the source talk at AI
Engineer on 2026-07-10 and his skill gist carries 651 stars. Comprehension artifacts are a known
public practice as of two weeks ago. Any sentence positioning them as original reads as late to a
judge who watched that talk. Cite Litt, keep the artifacts, and let the doubled originality score
rest on what is genuinely ours: the on-chain over-cap rejection, the device-co-signed feed, the
x402 earning node, and the differential fuzzer graded against solana-sdk's own deserializer.

**Add the back-pressure reading of the six correctness layers, with its objection.** Banay's
framing is that every automatic feedback source you build is human attention you never spend. That
gives a second reading of the existing artifacts: they are the reason an agent-built custody system
can be trusted, because they are the oracle the agent was forced to satisfy. No rival is likely to
be answering that question. Ship Wilson's counter with it, since he is already quoted in
`docs/CRAFT-TESTING-TECHNIQUES.md` saying "the more powerful and unyielding the validation step is
probably the worse this overall effect gets." The corpus contains both positions. Presenting only
the flattering one when the objection is already in our own repo is the weaker move.

**Present the Kani harnesses as specifications with stated coverage, not as effort.** Kleppmann's
argument is that the proof checker is a free oracle, so proof volume is becoming cheap and the
bottleneck moves to the specification. The repo already half does this: the shortvec canonicality
harness is stated over all 16,777,216 three-byte inputs, which is a specification sentence. Finish
the framing, and state what each harness does not cover.

**Name intent debt in the decisions section.** One sentence citing Storey 2026 (alphaxiv
2603.22106) explaining why a rejected-alternatives document belongs in a plugin submission.
`docs/DECISIONS.md` already records eight decisions with their rejected alternatives, including
killing a novel on-chain custody program after finding Swig already ships program allowlisting.
That is precisely the artifact her third category names. Do not imply comprehension was measured;
she states twice that measurement frameworks do not exist, so a measurement claim would contradict
its own citation.

### 3. A runnable permissions-equal-imports proof across all eight components

**Axis: safety 25, craft 20. Effort: 2 to 4 hours.**

PR #144 (ProofKiosk, opened 2026-07-26) ships `scripts/verify-no-network.sh`, which asserts that a
component whose manifest declares no network permission imports no `wasi:http`. They converted a
prose claim into something a judge runs in seconds. We make the same capability-minimality argument
across more components and hold the weaker artifact.

This is the same shape as most defects this project's own adversarial audits keep finding: the gap
between what a document asserts and what something enforces. We have the mechanism already, since
the wit-drift incident was diagnosed by reading embedded component-type strings out of the wasm with
`strings <plugin>.wasm | grep -c <case>`. The proof script is that technique pointed at imports
instead of at enum cases, run across all eight manifests, with a control that fails loudly.

Relayed, not verified: I did not read PR #144's script or confirm its behavior. The competitive
agent quotes it from the PR body.

### 4. Run claude-security once, medium effort, whole repository, on this repo

**Axis: safety 25, craft 20. Effort: one command, then a review pass. Start it first, it runs unattended.**

The security file's reasoning holds up. Our own host audit had six dimensions and every one is about
policy, authorization, and information flow. None asks about memory safety, integer behavior, or
decoder correctness on adversarial bytes. Meanwhile `crates/solana-core` is 4,217 lines of
hand-rolled binary decoding that every one of the eight plugins links, written by hand precisely
because solana-sdk does not compile for wasm32-wasip2. That surface has never been read by anything
looking for a bounds error.

Our existing coverage there is real and is all oracle-shaped: Kani over all three-byte shortvec
inputs, the exhaustive walk over all 65,535 Token-2022 discriminants, 220,000 differential-fuzz
iterations, 23 property tests. Each compares our output against a property we chose or a reference
decoder on inputs we generated. A reading-based researcher is a different instrument.

Three preconditions the security agent already checked: `workflows/scan.js` contains zero
`maxLength` and zero `maxItems`, so our own schema-cap guard will not block the run; 169 tracked
files puts us in the small-tree regime where the whole-repository shape can return
`completenessCheckOutcome: checked`; and a clean `git status` avoids a `-dirty` stamp. The tree is
clean today apart from two untracked directories.

Zero findings is still a result worth publishing, provided the coverage ledger says `checked`. That
is the downside case and it is not a loss. Sequencing note: this is the only item that runs
unattended for tens of minutes, so start it before doing actions 1 and 2.

One thing to remember afterward: the report directory ships its own `.gitignore` containing `*`.
Delete that file before committing, or the report becomes the seventh instance of the pattern
action 1 exists to fix.

### 5. Finish the two open upstream pull requests to merge

**Axis: safety 25. Effort: already in flight, tasks #74 and #75.**

A bounty-adjacent contributor got a fail-closed fix merged into the host on 2026-07-25. We have 16
items open upstream and zero merged. The merge is the evidence, and filing more issues does not
produce it.

This ranks fifth rather than first because it is the work already underway rather than a new
recommendation, and because the outcome depends on a maintainer. It appears here to say one thing
clearly: finish #9382 and #9385 before starting action 3. #9385 has four blocking findings, two of
them still open and both genuine correctness work rather than doc fixes.

---

## 2. Recommended against, with reasons

This section carries as much weight as the one above. A plan that only adds work is not a plan.

**1. Do not spend 15 minutes re-deriving channel-plugin eligibility. I resolved it here, and the
question was mis-framed.** The competitive agent ranked this first on the grounds that a rival
shipped a channel-plugin, the official community index shows its Channels section empty, and our
"non-tool WIT worlds are ineligible" note predates the 2026-07-22 brief rewrite. The arbiter is
`docs/LISTING-VERBATIM.md`, which is on disk, so I read it:

- Line 26: "We are judging use cases, not components. A plugin nobody uses is not a submission."
- Line 29: "A submission is a showcase post. There is no other submission format."
- Line 67, inside the Tier 3 section: "A plugin is a WebAssembly component (wasm32-wasip2)
  implementing the tool-plugin world from wit/v0."
- Line 118, under what fails: "A plugin with no use case around it. Components are not submissions
  here."

Neither reading was right. The 2026-07-21 note called other worlds ineligible, which overstates what
line 67 says, since line 67 defines what the brief means by "plugin" in its Tier 3 build guidance
rather than banning anything. And treating the rival's channel-plugin as open ground overstates the
opportunity, because a channel-plugin is not a submission any more than a tool-plugin is. The
scoring unit is the use case. The only question worth asking is whether building one would improve
ours, and `docs/COMPLIANCE-AUDIT.md` already answers that on merits: two channels are live, the
rubric scores use cases rather than channel count, and each additional channel is a new failure
surface with zero scored value. The empty Channels section in the community index is not an opening.
It is a section for a thing that is not scored.

**2. Do not build a third Kani harness.** Kleppmann's own argument is the reason. If the proof
checker is a free oracle and proof volume is becoming cheap, then harness count is the wrong axis
and specification precision is the right one. Take the free half of that finding, which is the
reframe in action 2, and skip the 2 to 4 hours. The account-index bound is a defensible target if
this were a research project. It is not the marginal hour that moves a judge.

**3. Do not add the cap-sweep overview to the sanitizer page.** Litt's own warning is that
interactivity "can just be a crutch, and it can be kind of slop." The page already lets a reader set
the cap, already carries a preset showing a case the sanitizer deliberately does not catch, and
already passes Papert's safety and discovery-density criteria. The corpus agent explicitly did not
read the page body, so the premise that the overview is missing is unverified. Two to three hours
for a marginal teaching gain on an artifact that is already the strongest showcase piece.

**4. Do not ship the prek pre-commit hooks.** Reproducibility at 15 percent is already the
best-evidenced axis in the submission: three CI workflows, `scripts/verify-proof.py` at 10 static
plus 2 live checks, a passing fresh-clone reproduction, and all ten Cargo.locks tracked. A fourth
mechanism there has the lowest marginal return of anything the four agents proposed. It also asks a
reader to install another binary, which cuts against the "set this up in an evening" promise the
axis is scored on. The one genuinely useful half of that finding is that `.tools/slop_check.py` is
unreachable from a clone, and action 1 fixes that without adopting a new tool.

**5. Do not re-scan `zeroclaw-host` with claude-security.** The security agent's NO-GO holds on all
four of its reasons, and the strongest is that the tree is 1,064 Rust files, which forces a scoped
scan, which forces `completenessCheckOutcome: not-applicable`, the weakest result shape, at the
highest cost. Adding to that: the host tracker already carries findings from other parties across
the injection and authorization shapes, so a duplicate filed upstream is worse for us than nothing.

**6. Do not build an exploration heatmap.** Wilson rules it out in our own corpus: "Consider
something like a Python interpreter. If you hit 100% code coverage in that you have not gotten
anywhere close to exhausting its behavior." A heatmap is a coverage picture. Building one would put
a number in the write-up that the same corpus tells us not to lead with.

**7. Do not adopt Hegel, the Antithesis SDK, or bombadil.** Already correctly rejected in
`docs/DECISIONS.md` entry 8 on the ground that the SDK's macros are inert off-platform. The corpus
walk of the Antithesis org turned up no component that works without the hypervisor. Switching from
proptest to a cross-language protocol in a single-language crate is a downgrade.

**8. Do not describe the quiz in Matuschak's terms, and do not claim comprehension was measured.**
His efficacy claim rests on spaced review over months. A bounty submission is read once. Keeping the
gate and dropping the spacing was the right call; describing it in his vocabulary would be an
overclaim against the source being cited. Same for Storey: the quiz is a gate, not a metric.

**9. Do not install the global config items before 2026-08-07.** The security file recommends
installing `security-guidance` at user scope, plus a user-scope guidance markdown and a patterns
YAML. Each is defensible on its own merits and none of them touches a scored axis. The install
creates a virtualenv under `~/.claude/security/` and pip-installs the Agent SDK, which introduces a
new variable into a hook harness that currently works, eleven days before a deadline. Do it after.

**10. Do not file more upstream issues.** Sixteen open and zero merged. The gap is closed by a merge,
not by volume.

**11. Do not chase the community-plugins-list row as an independent action.** The maintainer states
plainly that it is additive and does not affect judging, and it needs a public repo, so it is
downstream of the push. It rides along with that decision rather than competing for an hour.

**12. Do not "correct" upstream issue #9380 because the registry has a WIT-drift gate.** The
competitive agent found that a 2026-07-17 commit added a "Compare vendored WIT with pinned ZeroClaw
source" job to the registry, about 25 hours after the listing published. That is real context and
worth knowing, but the same
agent notes the gate guards plugins inside that repo, so it never protected a downstream vendored
copy, which is exactly what #9380 reports. The issue stands. The only thing to adjust is how the
war story is told in the write-up, so that a judge who knows about the registry gate does not read
our account as unaware of it.

---

## 3. Genuinely blocked on the human

Five items, and only five. Everything else in this document is agent-doable.

| Item | Why only the user | Blocks |
|---|---|---|
| Push the repo public (task #67) | A moat-timing judgement the user is deliberately holding | Every `<repo URL, filled at publish>` placeholder, X draft G, the community-list row, and part of the reproducibility axis |
| Beat 1's phone half of the demo video | A handset on camera, and it needs the shop daemon reachable | The one remaining gap in an otherwise complete five-beat cut |
| The Discord showcase post (S2) | Standing directive: anything going out as them is gated, except GitHub | The required submission artifact |
| X build-in-public posts | Same directive, plus the back-to-back-losses timing constraint is theirs | The tiebreak axis, where six of seven drafts already measure Human |
| One elevated shell for WSL, or the Bastion route | `Restart-Service vmcompute` needs Administrator | The shop daemon, and therefore the phone half above |

Two things that look user-gated and are not. Deleting the `CLAUDE-SECURITY-*/.gitignore` before
committing the scan report is ours. So is everything in actions 1 through 4.

One note on the WSL item. The project handoff file at the repo root records that hosting the shop off
this laptop via the Cloud Shell plus Bastion route is the better fix than restarting the VM, and that
route has already produced `NODE_SHELL_OK` once. That is task #77 and it is agent-doable. The
elevated command is the fallback rather than the plan.

---

## 4. Where the agents disagreed

Named as disagreements rather than resolved silently. Two are between agents, two are between
sources inside the corpus, and one is a gap rather than a conflict.

**A. Corpus agent and competitive agent point opposite directions on the marginal hour.** The corpus
list is ten items, eight of which are writing and framing on the craft axis. The competitive list is
six items, three of which are upstream and rival-response work on the safety axis. Neither
references the other and neither is wrong. The tension is real: is the next hour better spent on how
the submission reads or on what it contains? My call is framing first, and only because the contents
are already strong and the framing items are an order of magnitude cheaper on a doubled-weight axis.
If action 4 returns a confirmed finding in `solana-core`, that inverts immediately and the finding
becomes the top of the list.

**B. The security agent says stay off the host; the competitive agent says spend half a day on it.**
These are reconcilable and it is worth stating how, because a careless read drops one of them. The
security agent argues against re-auditing the host, on the grounds that a completed pass already
exists and a report on someone else's code is evidence about someone else's code. The competitive
agent argues for landing a host pull request, on the grounds that a rival has a merged fix and we
have none. Auditing and contributing are different acts. Contribute, do not re-audit.

**C. Wilson against Huntley and Banay, inside our own corpus.** Huntley and Banay say build the most
unyielding validation harness you can and loop the agent against it. Wilson says the more unyielding
the validation step, the worse the overall effect. Both are in this project's source corpus and they
disagree. This is not an agent error and it should not be smoothed. Action 2 ships the objection
alongside the thesis, because the objection is the more interesting half and it is already written
down in `docs/CRAFT-TESTING-TECHNIQUES.md`.

**D. The corpus agent both promotes and demotes explain-diff, and the two are consistent.** Its item
1 says move the artifacts somewhere a cloner can reach. Its item 4 says move the originality weight
off them. Read carelessly those look contradictory and a reader might drop the artifacts entirely.
They are not: ship the artifacts because they are real work that currently scores zero, and stop
claiming they are novel because a 651-star gist and a two-week-old conference talk say otherwise.

**E. The fourth agent's output is missing, and I could not synthesize it.** Only three files exist in
`docs/research/`. I received the condensed returns of two agents, the second truncated mid-sentence.
Whatever the fourth investigated is absent from this synthesis. See the note below.

---

## 5. What this synthesis does not cover

- **The fourth research file does not exist.** `docs/research/` contains exactly three files, all
  read in full. I searched the directory and `.compound-tmp/`. A full-tree search for markdown
  modified after 20:00 timed out at 120 seconds and was not retried. If the fourth agent wrote
  somewhere else, its findings are not represented here, and the ranking above may be missing a
  candidate that would have placed.
- **I did not read the bodies of the two explain-diff HTML files or the two sanitizer pages.** Action
  1 rests on their paths, their tracked status, and which document points at which, all of which I
  verified. It does not rest on their contents. The corpus agent's items about literate diff
  ordering and the cap sweep depend on those bodies and remain unverified in both directions.
- **Every rival claim is their assertion.** The competitive agent states plainly that it read PR
  bodies, READMEs, and repository metadata, and did not read rival source. Action 3 responds to what
  ProofKiosk's PR body claims, which is the right response either way, since the artifact is worth
  having regardless of whether theirs works.
- **No cost figure exists for the claude-security run.** The plugin's docs say it counts against plan
  usage limits and publish no per-file curve. The security file's anchor is our own host audit, which
  ran a comparable shape by hand at roughly 4.2 million tokens for the hunt phase over a tree between
  one and two orders of magnitude larger. That is an anchor, not a prediction.
- **I did not re-run the listing tripwire.** The competitive agent reports a byte-identical listing
  with `CHANGED_KEYS = []`, including a matching sha256 over the 23,707-character description. I am
  relaying that rather than confirming it.
