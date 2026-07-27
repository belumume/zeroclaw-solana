# Research corpus extraction, read 2026-07-26

Twenty-three sources the project owner surfaced and nobody had read end to end. Each entry
records what the source argues, then whether it changes this submission. Most do not. The ones
that do are collected in the action list in Part 4.

Two findings came out of checking the corpus against the repo rather than out of the corpus
itself, and both outrank most of the reading. They are items 1 and 2 in Part 4.

Method and honesty notes are in Part 6. Read them before citing anything here.

---

## Part 1: testing, verification, correctness

### antithesis.com/blog/sdtalk/ (the Super Mario talk)

Two claims worth separating. The first is that determinism is not only a reproducibility
property but a *search* property: "our deterministic hypervisor isn't just about getting perfect
reproducibility of the bugs we find, it also helps us find the bugs in the first place."
Branching from a saved state is only possible if replay is exact, and branching is what makes
state-space search cheap. The second is a generality claim: the same system beat a Kaizo ROM
hack with "zero tweaking, zero hyperparameter tuning, and zero iteration," offered as evidence
that the search strategy is not tuned per target.

**Changes anything?** No, and this is already correctly dispositioned. `docs/CRAFT-TESTING-TECHNIQUES.md`
records prefix-locking and progress-coordinate search as out of scope because they assume
replayability the host boundary does not give us. The post adds one thing not in that doc: the
exploration *heatmap*, showing where the explorer spends its time. Do not build one. Wilson in
the Jane Street interview says directly that coverage is a bad progress metric, and a heatmap is
a coverage picture wearing better clothes. Building it would put a number in the write-up that
the same corpus tells us not to lead with.

### github.com/antithesishq (the org, walked for repos)

Public repos include `bombadil` (Rust, "Property-based testing for web and terminal UIs"),
`snouty` (Rust CLI for the platform), `antithesis-trigger-action` (GitHub Action), `valthree`,
`madness`, `aardvark-arena`, `anta`. SDKs are published for Rust, Go, Java, C++, Python, with
.NET and JS/TS in beta. The SDK surface is assertion and property declaration, so the platform
knows what to look for.

**Changes anything?** No. `docs/DECISIONS.md` entry 8 already rejects the SDK on the correct
ground, which is that its macros are inert off-platform, so shipping them would put dead code in
a wasm component for a signalling benefit. Walking the org did not turn up a component that works
without the hypervisor. `bombadil` is the only near miss and it targets web and terminal UIs,
which is the pay page rather than the custody path, so it would buy signal on the least
load-bearing surface.

### hegel.dev

A property-based testing protocol built on Hypothesis, with libraries for Rust, Go, C++,
TypeScript, Java and OCaml, sharing one wire protocol so the same property harness shape works
across languages. The landing example is an LRU cache with a capacity invariant.

**Changes anything?** No, and switching would be a downgrade. `proptest` is already a
dev-dependency that never enters the wasm component, the suite is 23 properties plus 5
mined-invariant checks, and a cross-language protocol buys nothing in a single-language crate.
The one idea worth stealing is upstream of Hegel, in Hypothesis itself: see the next entry.

### github.com/hypothesisworks/hypothesis

The GitHub landing page is thin. It documents shrinking ("it reports the simplest possible one")
and not much else; the features I went looking for (targeted PBT, stateful rule-based machines,
the failing-example database, ghostwriter) are in the docs site, not the README, and I did not
read the docs site. Recording that as a gap rather than asserting the features from memory.

**Changes anything?** Possibly one thing, and it is already half-built. Hypothesis's *targeted*
property-based testing hill-climbs on a caller-supplied numeric score rather than sampling blind.
`differential-fuzz/` already does exactly this, using agreement-depth as its fitness signal
rather than coverage. So the technique is present. What is missing is that the write-up never
names it as a search strategy with a name and a lineage, which is a framing gap rather than an
engineering one.

### martin.kleppmann.com/2025/12/08/ai-formal-verification.html

The argument is economic, not technical. Verification has always been possible and always been
unaffordable: seL4 cost "23 lines of proof and half a person-day for every single line of
implementation," and only a few hundred people worldwide can do it. LLMs collapse the proof half
of that cost, and Kleppmann's reason is mechanical rather than optimistic: "the proof checker
will reject any invalid proof and force the AI agent to retry," so proof writing is a task with a
free, exact, unbounded oracle. He names Rocq, Isabelle, Lean, F*, Agda, and seL4, CompCert,
Project Everest as the existing verified systems. The conclusion that matters is the shift: once
proofs are cheap, **the bottleneck moves to the specification**, and specifications carry the risk
of "subtleties lost in translation" between the formal and the natural-language statement.

**Changes anything? Yes, in two directions, and one of them is a warning.**

The warning first. If proofs are now cheap, then two Kani harnesses is not by itself a craft flex,
and presenting it as heroic effort invites the reader to notice the same thing Kleppmann noticed.
The defensible presentation is not "we did formal verification" but "here is the exact property,
here is the domain it is proved over, and here is what it does not cover." The repo already half
does this: the shortvec canonicality harness is stated over all 16,777,216 three-byte inputs,
which is a specification sentence, not a badge.

The opportunity second. The proof checker is a free oracle, so adding a third harness is cheap in
the way Kleppmann describes. The best target is not another shortvec property but the
**per-instruction account-index vector bound**, because that is where this project already hit a
real defect (an unbounded vector that only broke past 65535 before an `as u16` cast). A harness
asserting that any accepted instruction has an account-index count representable in the on-wire
width would prove the class rather than the instance.

### blog.exe.dev/how-antithesis-turned-exe-into-a-sandbox-for-agentic-software-tests

The title is misleading. The post is not about deterministic testing. It is a customer story about
Carl Sverre of Antithesis using exe.dev virtual machines for his own workflow: root access, no
hibernation delay, persistent machines for remote agent sessions, 25 dollars per user per month
pooled across up to 50 VMs. There is no hypervisor content, no snapshotting content, no benchmark,
no reproducibility mechanism.

**Changes anything?** No. Recording this explicitly so nobody spends another read on it. The URL
reads like a technical case study and is a pricing testimonial.

### github.com/j178/prek

A git hook manager written in Rust, drop-in compatible with `pre-commit` configuration files,
shipped as a single binary with no Python or other runtime. v0.4.11. Claims parallel repository
fetching, concurrent hook environment preparation, concurrent execution by priority, native Rust
reimplementations of the common hooks, workspace mode for monorepos, and checksum verification on
downloaded hooks. The README lists CPython, FastAPI and Godot as users.

**Changes anything? Yes, and it lands on the reproducibility axis, which is 15 percent.**

This repo has a documented failure that prek is the direct fix for. Four deterministic
pre-publish gates existed and were documented, and none of them ran anywhere except when someone
remembered to type the command; two were later put on a CI runner and two were deliberately left
off with the reasons written into the workflow. A cloner who wants to reproduce the claims has no
local path to run the gates at all. A `.pre-commit-config.yaml` running `check-repo-paths.py`,
`check-shadowed-scripts.py` and `.tools/slop_check.py` as local hooks, invoked by a single static
binary the reader downloads, turns "four gates we remember to run" into "clone, install one
binary, the gates run on commit."

The specific reason to prefer prek over `pre-commit` here is that the repo's reproducibility
promise is "another operator in an evening," and `pre-commit` requires a Python environment before
it can manage anything, while prek is one binary. That is a smaller ask on a reader who is already
installing a Rust toolchain and a Solana CLI.

Two caveats. I read prek's claims on the repository page and did not benchmark it or verify the
adoption list. And `.tools/slop_check.py` is inside the gitignored `.tools/` directory, so it
would have to move before a cloner could run it, which is the same defect as item 1 in Part 4.

### ghuntley.com/pressure/

Short and conceptual. The claim is that agent-built software needs "structure around the agent
itself, to provide it with automated feedback on quality and correctness," and that "software
engineering is now about preventing failure scenarios and preventing the wheel from turning over
through back pressure to the generative function." No mechanisms, no evals, no test harness
shapes, no CI configuration. It points at a linked essay for the practice.

### banay.me/dont-waste-your-backpressure/

The essay the above points at, and the one with content. It reframes back pressure as a *budget
belonging to the human*: "you spend **your** back pressure (the time you spend giving feedback to
agents) on typing a message telling the agent it missed an import." Every automatic feedback source
you build is human attention you never have to spend. The named sources are build systems with
readable error output, expressive type systems (Rust named specifically) whose errors feed back
into the model, browser tooling so the agent can see what it rendered, proof assistants and fuzzing
so the agent can iterate until results are trustworthy, and generated API documentation so the
agent can check its own schema against intent.

**Changes anything? Not the code. Possibly the write-up, and this is the highest-value
non-engineering item in the corpus.**

The submission currently presents its six correctness layers as evidence for a judge. Banay's
framing gives a second, more original reading of the same artifacts: the layers are the reason an
agent-built custody system can be trusted at all, because they are the oracle the agent was forced
to satisfy. That is a claim about *why this project's provenance is not a liability*, which no
rival is likely to be making, and it costs one paragraph. It also composes with Kleppmann: the
proof checker is the strongest back-pressure source available, which is why the Kani harnesses are
worth more than their line count suggests.

**And it contains a contradiction the corpus itself surfaces, which must not be hidden.** Wilson,
in the Jane Street interview already quoted in `docs/CRAFT-TESTING-TECHNIQUES.md`, says "the more
powerful and unyielding the validation step is probably the worse this overall effect gets" when
an agent loops against a validation harness. Huntley and Banay say build the unyielding harness.
Both are in this corpus and they disagree. If the write-up adopts the back-pressure framing it
should name the objection rather than only the thesis, because the objection is the more
interesting half and it is already written down in this repo.

### YouTube F_LvzcdNH3Q, "Why Testing Is Hard and How to Fix It with Will Wilson" (Jane Street, 1h48m, 2026-03-17)

Already mined in full. `docs/CRAFT-TESTING-TECHNIQUES.md` is built from this transcript plus two
others and quotes it verbatim throughout, including the bugification definition, the speculative
properties technique, Minsky's triage rule for mined invariants, and six counterarguments.

**Changes anything?** No.

### YouTube 1Vz3_VR-L04, "Why software keeps breaking and why AI isn't the shortcut" (Antithesis, Web Summit 2025, 18m)

Already mined, cited as [WS] in the craft doc, source of the recorded-trajectory finding ("It
would break every single test") that applies to golden and snapshot fixtures.

**Changes anything?** No.

### YouTube zc4cqtibTzs, "Testing a single-node, single threaded, distributed system written in 1985" (Antithesis, 42m, 2025-12-01)

The talk version of the sdtalk blog post: Super Mario Brothers framed as a distributed system.
The setup is a joke with a real argument inside it. Testing distributed systems is hard because of
dropped messages, reordering and clock drift; testing single-node systems is also hard because of
threads, concurrency and an embedded JIT; so the only tractable target is software old enough to
predate all of that, and even then the state space defeats conventional testing.

**Changes anything?** No, it is the same material as the blog post and as [A85] in the craft doc,
which is where the stateful-input-distribution technique came from (the one that produced the
measured iid=18 versus stateful=89 longest-forbidden-run improvement in the sanitizer generator).

---

## Part 2: cognitive debt

### margaretstorey.com 2026-02-09, "cognitive debt"

The definition is locational and that is the whole point: "technical debt lives in the code;
cognitive debt lives in developers' minds." It is grounded in Naur's claim that a program is a
theory held in the minds of the people who built it, so when the shared theory fragments the debt
accrues even if the code is clean. Her illustrating case is a student team that could not make
simple changes without breaking things, not because the code was messy but because nobody could
explain why the design decisions had been made. Proposed mitigations: require a human to
understand each AI-generated change before it ships, document the why rather than the what,
checkpoint through reviews and retrospectives. Detection signs: hesitation to change, reliance on
one knowledge holder, treating the system as a black box. She states explicitly that measurement
frameworks do not exist and calls for research into them.

### margaretstorey.com 2026-02-18, "cognitive debt revisited"

Synthesis of the response rather than new theory. Three additions worth keeping. Cognitive debt
manifests experientially, as loss of confidence, review burden and stress, not just as slower
delivery. Restoring the shared theory requires attention across "people, documentation, tests,
conversations, tooling, and increasingly, AI agents," which puts tests and tooling inside the
comprehension surface rather than beside it. And the incentive analysis: AI lowers the cost of
producing structure, so systems evolve faster than teams can collectively understand them even
under disciplined practice.

### simonwillison.net 2026-02-15

Willison quoting Storey and confirming from his own experience: on "vibe-code-adjacent projects"
he stopped reviewing the implementations and "lost the ability to make confident decisions." No
prescription of his own. Its value is as the popularization vector, which is why the term shows up
in Litt's talk.

### alphaxiv.org/abs/2603.22106, Storey, "From Technical Debt to Cognitive and Intent Debt" (2026-04-06)

The paper adds a third category. **Intent debt** is missing externalized goals and rationale: not
"we no longer understand the system" but "the reasons were never written down anywhere outside
someone's head." The Triple Debt Model is technical, cognitive and intent debt interacting. It is
a position paper: the evidence is the same student-team anecdote plus a literature synthesis, with
no experiment, no measurements and no controlled methodology. It offers diagnostic indicators
(resistance to change, unexpected results, slow onboarding) and mitigations drawn from existing
practice.

**Do these change anything? One of them does, modestly, and one of them is a trap.**

The trap first. Storey says twice that measurement frameworks for cognitive debt do not exist. Any
sentence in the submission implying we measured comprehension would be an overclaim against the
source it cites. The explain-diff quiz is a *gate*, not a measurement, and it should be described
as one.

The useful part is the intent-debt vocabulary. `docs/DECISIONS.md` records eight decisions
including rejected alternatives, and the strongest of them (killing a novel on-chain custody
program after finding Swig already ships program allowlisting) is exactly the artifact Storey's
third category names. The submission presents that file as ADRs. Naming it as intent-debt
repayment, with the citation, costs one sentence and gives a judge a frame for why a
rejected-alternatives document belongs in a plugin submission at all. Small, real, cheap.

What does *not* change: none of these sources describes a technique the project is not already
running. Requiring understanding before shipping, documenting the why, checkpointing through
review, and using AI to make cognitive work visible are all present as explain-diff artifacts,
ADRs, and the published audit. The problem is not that the artifacts are missing. It is where two
of them are stored, which is item 1 in Part 4.

### geoffreylitt.com 2026-07-02, "Understanding is the new bottleneck"

The essay's real argument is a correction of a common one. Most people assume humans must
understand agent output in order to *verify* it, and Litt agrees that role is shrinking because
agents are getting good at correctness checking given the right verification loop. His claim is
that the reason to understand is to *participate*: "You need a rich set of concepts in your mind
to think creatively and fluently about how to move something forward." Three techniques follow:
code explainer documents with an embedded quiz, microworlds a human can step through, and shared
spaces where humans and agents build a common model.

### gist.github.com/geoffreylitt/a29df1b5f9865506e8952488eac3d524

The actual skill definitions, two of them: `explain-diff-html.md` and `explain-diff-notion.md`.
The HTML one specifies Background, then Intuition with toy examples and diagrams, then Code, then
a five-question multiple-choice quiz, output as a single self-contained HTML file with inline CSS
and JS, filed outside the code repo with a `YYYY-MM-DD-explanation-` filename. 651 stars. The
comment thread contains a community fix for quiz answers clustering in predictable positions and a
security note about prompt injection when running this over an untrusted codebase.

Note the "outside the code repo" instruction. It is right for Litt's use, a personal comprehension
aid, and wrong for ours, an artifact a judge should be able to reach. See item 1 in Part 4.

### YouTube WkBPX-oDMnA, "Understanding is the new bottleneck", Litt at AI Engineer, 2026-07-10, 19m

The talk carries material the essay does not.

The explainer structure is stated as pedagogy with reasons attached. Background first, "it makes
sure that I'm sort of being led up to the point where I can even begin to understand." Then
intuition before details, which he calls what good math teachers do. Then interactive figures
"where it makes sense." Then what he calls **literate code diffs**: "we don't just throw a list of
files in order," each file is introduced with prose that says what is coming and why, in a chosen
order rather than the diff's order. Then the quiz.

The quiz has a stated personal rule attached: "I don't send code to others on my team to review
unless I can pass the quiz about what my agents wrote," and a stated function: "I think of it as
sort of a speed regulator... How do we make sure we're not just moving at the speed of
correctness, but also of understanding?" The originating anecdote is that he sent a PR believing
he had understood it, and a coworker asked the most basic question and he could not answer.

The microworlds section credits Papert's Mathland directly: kids learn French by living in France,
so where is the country where you learn math by living in it.

And one line cuts against enthusiasm: interactivity "can just be a crutch, and it can be kind of
slop, to be honest."

**Do these change anything? Two things, and the second is strategic rather than technical.**

First, the *literate diff* ordering. The distinction is precise and testable: does the explainer
walk files in diff order, or in an order chosen for teaching with prose transitions? Check the two
artifacts before acting; I located them but did not read their bodies.

Second, and more decision-relevant for the bounty: **explain-diff is now public, popular and
easy.** The gist has 651 stars, the talk was given about two weeks ago at a large conference, and
the skill is a copy-paste. Any claim in the write-up that positions comprehension artifacts as
*original* will read as late rather than early to a judge who has seen the talk. The defensible
position is the opposite one: cite Litt, treat the artifact as a known good practice adopted
deliberately, and put the originality weight on the things that are actually ours (the on-chain
over-cap rejection, the device-co-signed feed, the x402 earning node, the differential fuzzer
graded against solana-sdk). Originality counting double is a reason to *move* the claim, not to
inflate it.

---

## Part 3: microworlds and explorable explanation

### dailypapert.com, "Microworlds: Transforming Education", Papert 1984

Read in full on the second attempt (see Part 6). It is more useful than expected, because it
contains a definition, design criteria, and one distinction that names something this project
built without having a word for it.

The definition is by contrast with the two other ways computers get used in education, as
tutorials and as tools: "thirdly, a different concept altogether: as microworlds." A microworld is
"a little world, a little slice of reality. It's strictly limited, completely defined by the
turtle and the ways it can be made to move and draw. But it is rich."

Two design criteria are stated outright. Safety: "created and designed as a safe place for
exploring. You can try all sorts of things. You will never get into trouble. You will never feel
'stupid'." And discovery density: "designed to be discovery-rich in the sense that little nuggets
of knowledge have been scattered around in it for you to find."

A third criterion is continuity across levels of expertise: "you can explore one when you're five,
and then again when you're six or fifteen, or continually at all ages, doing more complex
operations and projects as you go along, yet with a single, continuous entity." His story of the
younger children learning motion by watching the older ones' screens works only because both
groups were operating the same system.

The concept that names our artifact is the **transitional object**: a microworld "gives you an
entirely new kind of object, a transitional object between the ones that you can touch and push
(like tables and wooden blocks) and the kind of objects that you know in science, in philosophy,
and in mathematics... This ability to create transitional objects gives us a way of closing the
gap between intuitive and formal learning."

And the distinction that is the sharpest thing in the chapter: **microworld versus simulation**. A
dynaturtle obeying Newton's laws is "a special kind of microworld, one that tries to copy a certain
part of reality thought to be important in science." Papert argues the more fundamental approach is
a world with *simpler* laws than the real ones, because "the problem with learning dynamics in
physics is not so much the particular laws of physics that we're teaching these children. It's that
they're not really used to thinking about motion at all."

**Changes anything? It changes what to call what we shipped, and it supplies one honest test.**

By Papert's line, `sanitizer-microworld` is a *simulation* rather than a microworld in his sense:
it runs the shipped `sanitize_onchain` compiled to wasm, so it copies the real system exactly. That
is the correct choice here and the README already gives the reason, which is that a JS
reimplementation would be a claim about the sanitizer rather than the sanitizer. Papert's
distinction is not an argument to change it. It is a vocabulary for defending it, and a warning
that fidelity and teachability pull in opposite directions.

The criteria give a real test, and the artifact already passes more of it than I expected. It is
safe by construction, since nothing can be broken by typing into it and there is no server. It is
discovery-rich in exactly Papert's sense: the README documents a preset called "Framing the flag
misses" that shows a case the sanitizer deliberately does not catch, with the reasoning for why
that is correct rather than a gap. That is a nugget scattered for the reader to find, and it
doubles as a negative control, which is unusual and good.

Where it is thinner is Papert's continuity criterion, which is the same gap Victor names below.

### worrydream.com (Bret Victor)

The index lists Learnable Programming (connect code to its visual effect immediately so cause and
effect is directly observable), Up and Down the Ladder of Abstraction (understanding requires
moving between the concrete instance and the abstract family, seeing both at once), Inventing on
Principle, Media for Thinking the Unthinkable, Explorable Explanations, Dynamic Pictures, Kill
Math, Magic Ink, and Dynamicland as the current work.

**Changes anything? One small thing, stated more carefully than my first pass had it.**

The sanitizer page already lets a reader set the cap (the README invites "set the cap to zero"), so
the concrete rung and the parameter control both exist. What does not exist, as far as I can tell
without reading the page source, is the *overview*: a view where the cap sweeps its whole range at
once and the reader sees the family of outcomes rather than one member of it. That is Victor's
ladder in one sentence, and it maps onto Papert's continuity criterion, because an overview is what
lets a five-minute reader and a careful reader use the same artifact at different depths.

Weigh it against Litt's warning that interactivity can be slop. The test is whether the sweep
teaches something the presets cannot, and for a cap it does, because the interesting behaviour is
at the boundary and the presets are chosen points. Verify the page does not already have this
before building it.

### notes.andymatuschak.org/zKPv6qkSErdRGqyryvgS2wS, "Mnemonic Medium"

Not the microworld note. It argues that spaced repetition "makes memory a choice," that the
mnemonic medium embeds review prompts inside narrative prose, that it supplies expert-authored
prompts so the reader is not burdened with writing them, and that it keeps readers in contact with
material over time. The variable he flags as critical is emotional: "the critical thing to optimize
in spaced repetition memory systems is emotional connection to the review session."

### andymatuschak.org/books/, "Why books don't work"

The claim is that books rest on a false theory of learning, transmissionism, the idea that "people
absorb knowledge by reading sentences," and that the failure is invisible: readers feel they
understood while reading and discover later that they did not. Understanding requires metacognition
(self-monitoring, planning, feedback) and books leave all of that work to the reader. His proposal
is not to fix books but to design media where "normal engagement naturally produces understanding,"
his example being Quantum Country, where prose alternates with brief interactive review sessions
that continue over days and weeks.

**Do these change anything?** No, and the reason is worth writing down. The mechanism that makes
the mnemonic medium work for Matuschak is repeated review over months. A bounty submission is read
once. Adopting the quiz keeps the part that transfers, a comprehension gate you cannot pass by
skimming, and drops the part that does not, the spacing. The project already made that call
correctly, but the write-up should not describe the quiz in Matuschak's terms, because his claim is
about long-term retention and ours is about a gate.

### microworlds.com/company/philosophy.pdf

**Could not reach.** HTTP 403. Recorded as a gap; nothing here rests on it.

---

## Part 4: what to actually do, ranked

The first two came out of checking the corpus against the repo, not out of the reading.

1. **Move the explain-diff artifacts somewhere a cloner can reach them.** They are at
   `.tools/explain-2026-07-25.html` and `.tools/explain-2026-07-25-evening.html`, and `.tools/` is
   gitignored at `.gitignore:28`. Confirmed with `git check-ignore -v`. A grep of all markdown for
   `explain-diff`, `explain-2026` or `explainer` returns five files, four of which are private
   (`HANDOFF-POST-COMPACT.md`, `docs/BUILD-JOURNAL.md`, `docs/X-BUILDLOG-DRAFTS.md`,
   `docs/USER-DIRECTIVE-2026-07-26-VERBATIM.md`) and the fifth is this document. **Zero tracked,
   judge-facing document references them and a clone does not contain them.** This is the same
   pattern this repo has already written up five times (the mutation harness, the certifier call
   site, the negative control, the 14-defect audit list, the host security audit), and it is now
   the sixth. It is also why the entire cognitive-debt cluster currently scores zero for a judge
   despite the work being done. Fix is mechanical: move to a tracked path, link from the README and
   from the write-up's craft section. Note that Litt's skill deliberately writes these outside the
   repo, which is right for his use and wrong for ours, so this is a case where the source should be
   departed from on purpose and the reason stated.
2. **Resolve the two microworld directories.** Both `microworld/` (README, `build.py`,
   `sanitizer.html` at 74,416 bytes, `sanitizer-wasm/`) and `sanitizer-microworld/` (`Cargo.toml`,
   `index.html` at 76,411 bytes, `src/`) are tracked, and both embed a compiled wasm build of the
   sanitizer. The two HTML files differ by about 2 KB and 13 hours of mtime. I did not diff their
   contents, so this is a flag rather than a verdict: either one supersedes the other and the loser
   should go, or they are genuinely different artifacts and nothing tells a reader which to open. A
   judge cloning this repo currently finds two.
3. **Ship the pre-publish gates as prek hooks.** Reproducibility, 15 percent, and it closes the
   documented failure of gates that only run when someone remembers them. One config file plus a
   QUICKSTART line, and one static binary for the reader. Blocked on `.tools/slop_check.py` moving
   to a tracked path, which is the same fix as item 1.
4. **Move the originality weight off explain-diff.** Litt's talk and a 651-star gist make
   comprehension artifacts a known practice as of two weeks ago. Cite him, keep the artifacts, and
   let the on-chain over-cap rejection, the device-co-signed feed and the externally-graded
   differential fuzzer carry the doubled originality score.
5. **Reframe the six correctness layers as the agent's back-pressure**, with Wilson's objection
   stated rather than hidden. One paragraph. It answers the question a judge is entitled to ask
   about an agent-built custody system, and no rival is likely to be answering it.
6. **Add one Kani harness on the account-index bound.** The proof checker is a free oracle, so the
   marginal harness is cheap; the target is chosen because this project already hit that defect
   once. Present all three harnesses as specifications with stated coverage limits, not as effort.
7. **Name the microworld a transitional object, and name the microworld-versus-simulation
   distinction**, citing Papert 1984. It gives the artifact a defensible category and states why
   running the shipped function rather than a reimplementation was the right trade.
8. **Add the cap-sweep overview to the sanitizer page**, after verifying it is not already there.
   Victor's ladder and Papert's continuity criterion point at the same missing view.
9. **Name intent debt in the write-up's decisions section**, citing Storey 2026. One sentence
   explaining why a rejected-alternatives document belongs in a plugin submission.
10. **Check the explainer artifacts for literate ordering.** If they walk files in diff order,
    reorder for teaching with prose transitions. Only if the check shows it is needed.

---

## Part 5: sources that argue against something we currently do

- **Wilson versus Huntley and Banay, inside this corpus.** Huntley and Banay say build the most
  unyielding validation harness you can and loop the agent against it. Wilson says "the more
  powerful and unyielding the validation step is probably the worse this overall effect gets."
  Both are in the corpus and they disagree. If the back-pressure framing is adopted, the objection
  ships with it.
- **Wilson on coverage.** "Consider something like a Python interpreter. If you hit 100% code
  coverage in that you have not gotten anywhere close to exhausting its behavior." Rules out the
  Antithesis heatmap idea and rules out leading with any coverage number.
- **Litt on interactivity.** It "can just be a crutch, and it can be kind of slop." Applies to the
  sanitizer microworld and to any sweep added to it. The justification has to be that the
  interaction shows something static presentation cannot.
- **Litt's skill, on where to file explainers.** It says to put the output "outside the code repo."
  Following that instruction is how the artifacts ended up unreachable from a clone. Depart from it
  deliberately and say why.
- **Litt's talk, against the originality of explain-diff.** Public, popular, two weeks old,
  copy-pasteable. Presenting it as novel is now a liability rather than an asset.
- **Kleppmann, against presenting Kani as heroic.** If proofs are becoming cheap because the checker
  is a free oracle, then effort is the wrong axis and specification precision is the right one.
- **Papert, against calling our page a microworld without qualification.** By his own distinction it
  is a simulation, because it copies the real system exactly rather than simplifying its laws. The
  right move is to name the trade, not to change the artifact.
- **Storey, against claiming measurement.** She states that measurement frameworks for cognitive
  debt do not exist. The quiz is a gate, not a metric.
- **Matuschak, against the quiz as adopted.** The mnemonic medium's efficacy claim rests on spaced
  review over time. A one-shot quiz keeps the gate and drops the memory mechanism, which is right
  here but should not be described in his terms.

---

## Part 6: method, and what I could not reach

**Read in full or near-full:** antithesis.com/blog/sdtalk/, github.com/antithesishq (org repo
list), hegel.dev, github.com/hypothesisworks/hypothesis (landing page only), Kleppmann's post,
blog.exe.dev, github.com/j178/prek, ghuntley.com/pressure/, banay.me/dont-waste-your-backpressure/,
simonwillison.net cognitive-debt, both margaretstorey.com posts, alphaxiv 2603.22106,
geoffreylitt.com understanding-is-the-new-bottleneck, the explain-diff gist, worrydream.com index,
notes.andymatuschak.org zKPv6qkSErdRGqyryvgS2wS, andymatuschak.org/books/, and the full Papert
chapter.

**The Papert chapter took two attempts and the failure is worth recording.** WebFetch returned it
as undecoded binary and reported it as unreadable, which is what my first pass wrote down. A second
attempt through firecrawl with the `pdf` parser returned all 16 pages of clean text. A PDF that one
fetcher cannot decode is not an unreachable source, and the first verdict would have dropped the
most useful item in the microworlds cluster.

**YouTube:** all four IDs resolved and auto-captions downloaded with yt-dlp. Metadata confirmed:
F_LvzcdNH3Q Jane Street 6501s 2026-03-17; 1Vz3_VR-L04 Antithesis 1077s 2025-07-01; zc4cqtibTzs
Antithesis 2526s 2025-12-01; WkBPX-oDMnA AI Engineer 1173s 2026-07-10. WkBPX-oDMnA and zc4cqtibTzs
were read from transcript for this document. F_LvzcdNH3Q and 1Vz3_VR-L04 were previously mined into
`docs/CRAFT-TESTING-TECHNIQUES.md` and were not re-read line by line here; their entries rest on
that document plus the metadata check.

**Repo checks actually run, so items 1 and 2 are not inferences.** `git check-ignore -v` on
`.tools/explain-2026-07-25.html` returned `.gitignore:28:.tools/`. `git ls-files` filtered for
`explain` returned nothing and for `microworld` returned nine paths across the two directories. A
markdown-wide grep for `explain-diff|explain-2026|explainer` returned five files, four private and
one this document. Sizes and mtimes for the two sanitizer HTML pages were read with `ls -la`.

**Could not reach:**
- `microworlds.com/company/philosophy.pdf` returned HTTP 403.
- `andymatuschak.org` top level not fetched; the two linked pages were.
- Hypothesis's documentation site not read, so targeted PBT, stateful machines, the example
  database and ghostwriter are named from prior knowledge and marked as such rather than verified.

**Located but not read to the bottom:** the bodies of the two explain-diff HTML files and the two
sanitizer HTML pages. Items 2, 8 and 10 in Part 4 are therefore stated as things to verify, not as
established defects.

**Not verified independently:** prek's speed claims and adoption list, Hegel's per-language library
maturity, and the Antithesis generality claim about the Kaizo ROM hack. Each is reported as what
the source says.
