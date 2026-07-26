export const meta = {
  name: 'zeroclaw-upstream-security-audit',
  description: 'Adversarial security audit of ZeroClaw upstream to surface reportable, non-duplicate defects',
  phases: [
    { title: 'Recon' },
    { title: 'Hunt' },
    { title: 'Verify' },
    { title: 'Report' },
  ],
}

// paced-ok: waves of 3, awaited sequentially, retry-once per agent, dead agents logged not dropped

const ROOT = '../zeroclaw-host'

const KNOWN = `ALREADY REPORTED BY US — do NOT re-report these, but DO look for SIBLINGS of the same shape elsewhere:
- zeroclaw-labs/zeroclaw#9348: WhatsApp Web answers every DM and every group under mode="business"; chat policies were personal-mode only, and an empty allowed_groups permitted ALL groups (fail-open on empty collection).
- #9366: WhatsApp Web accepts approval_timeout_secs and never reads it (accepted-but-inert config key).
- #9380: a vendored wit/v0 that drifts fails only at plugin registration; nothing before that can see it.
A rival independently found the same "empty set satisfies the allowlist" shape in the x402 payee
allowlist and got the fail-closed fix MERGED as PR #9327.
The PRODUCTIVE VEIN is therefore: a security control that silently does nothing under some
configuration, mode, or empty-value. Hunt that class hard, everywhere.

ALREADY FILED BY OTHERS — this codebase is heavily audited already. A finding that duplicates any
of these is WORSE THAN NOTHING for us, because filing a known issue signals we did not read the
tracker. Check every candidate against this list and DROP duplicates. A near-miss that is
genuinely a DIFFERENT site or a DIFFERENT mechanism is still valuable, but say how it differs.
- #9247 Shell Tool Workspace Boundary Bypass
- #9255 WASM plugin calls have no wall-clock timeout; a dripping HTTP response runs unbounded
- #9191 Cron agent jobs have no wall-clock timeout; in-flight locks only cleared at process start
- #9340 CLI-created cron jobs cannot deliver output; delivery hardcoded to None (output discarded, run records ok)
- #9328 verifiable-intent evaluates constraints without verifying the credential chain
- #9192 shared_budget TOCTOU can wrap AtomicUsize; SopEngine::finish_run unwrap panics under mutex
- #9206 agent cron runs intermittently resolve workspace_dir to /
- #9278 context_compression.enabled defaults true while runtime ignores it (accepted-but-inert)
- #9373 peer-agent delivery runs recipient turn with no cost-tracking context, so budgets are unenforced
- #9374 CLI run() leaks unbalanced AgentStart on 12 exit paths
- #9316 unauthorized Telegram senders of media messages receive no unauthorized notice
- #9284 config flush can overwrite concurrent writes
- #9237 failed config updates leave phantom map aliases
- #9186 MCP stdio: response id not matched, 30s hard timeout vs 180-600s tool budget, Mutex held for whole call
- #9188 Telegram long-poll advances update offset before successful inbound delivery
- #9187 WeChat sync cursor persisted before message enqueue; crash loses inbound messages
- #9189 Discord gateway listen loop runs attachment download/transcribe inline; heartbeats starve
- #9190 Reliable provider API key rotation selects but cannot apply alternate keys
- #9231 Docker runtime commands nested inside a second Docker sandbox
- #9207 web_fetch returns garbage for compressed responses
So: the cron-timeout, cron-delivery, shell-boundary, plugin-timeout, VI-chain, budget-TOCTOU and
context-compression shapes are TAKEN. Go find what nobody has looked at yet.`

const RULES = `RULES OF EVIDENCE — a finding is worthless to us unless it survives these:
1. Cite exact file:line and quote the deciding lines. No finding without a source quote.
2. State a CONCRETE exploit or failure path: what an attacker or a misconfiguring operator does,
   and what they get. "Could be unsafe" is not a finding.
3. Distinguish (a) the control is ABSENT, (b) the control EXISTS but is inert under some
   mode/empty-value/branch, (c) the control exists and works. Only (a) and (b) are findings.
4. If a guard exists that already defends it, say so and DROP the finding. We would rather
   report three real defects than thirty theoretical ones; a false report costs us credibility
   with maintainers who have already reviewed our work.
5. Do NOT report style, missing docs, dependency advisories, or unwrap()-in-tests.
6. Read the actual code. Never infer a mechanism from a filename or a function name.`

phase('Recon')

const RECON_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['policy_sites', 'llm_context_sinks', 'approval_gates', 'capability_grants', 'notes'],
  properties: {
    policy_sites: { type: 'array', items: { type: 'string' },
      description: 'file:line of each place a policy/allowlist/permission decision is made' },
    llm_context_sinks: { type: 'array', items: { type: 'string' },
      description: 'file:line where external/untrusted text can reach the model context' },
    approval_gates: { type: 'array', items: { type: 'string' },
      description: 'file:line of human-approval / confirmation checkpoints' },
    capability_grants: { type: 'array', items: { type: 'string' },
      description: 'file:line where tool/plugin capabilities or auto-approve are granted' },
    notes: { type: 'string' },
  },
}

const recon = await agent(
  `You are mapping the security-relevant surface of the ZeroClaw agent framework at ${ROOT}.
It is a Rust workspace: 1064 .rs files, 31 crates. Do NOT read target/.

Your ONLY job is to LOCATE decision points, not to judge them. Find where the code:
(a) makes a policy / allowlist / permission / filter decision (DM policy, group policy, payee
    allowlists, tool allowlists, channel gating, rate limits, leak detection),
(b) puts externally-controlled text into anything that reaches the LLM (tool results, channel
    messages, RPC/HTTP error bodies, parse-error Display impls, memory recall, file reads),
(c) gates an action on human approval/confirmation,
(d) grants capabilities to plugins or auto-approves tools.

Use grep/glob aggressively: search for policy, allow, deny, permit, approve, confirm, capability,
sanitiz, redact, filter, gate, trust. Then OPEN the files to confirm each hit is a real decision
point and record file:line.

Return ONLY the structured map. Be precise about line numbers; downstream agents depend on them.`,
  { label: 'recon:surface', phase: 'Recon', schema: RECON_SCHEMA, effort: 'high' }
)

log(`Recon: ${recon ? `${recon.policy_sites.length} policy sites, ${recon.llm_context_sinks.length} context sinks, ${recon.approval_gates.length} approval gates, ${recon.capability_grants.length} capability grants` : 'RECON FAILED — hunters will self-locate'}`)

const MAP = recon
  ? `RECON MAP (verify each before trusting it; the recon agent located but did not judge):
POLICY SITES: ${recon.policy_sites.join(' | ')}
LLM CONTEXT SINKS: ${recon.llm_context_sinks.join(' | ')}
APPROVAL GATES: ${recon.approval_gates.join(' | ')}
CAPABILITY GRANTS: ${recon.capability_grants.join(' | ')}
RECON NOTES: ${recon.notes}`
  : 'RECON FAILED — locate the surface yourself with grep before hunting.'

// NO maxLength ANYWHERE ON THIS PATH, and the omission is the fix rather than an oversight.
//
// The 2026-07-26 run of this exact workflow lost SIX completed hunt agents here. Each ran 15 to 21
// minutes, burned 650k to 720k tokens, found real defects, and was then refused at the return
// boundary by the caps that used to live on these fields:
//
//   Output does not match required schema: /findings/0/source_quote: must NOT have more than 700
//   characters, /findings/0/exploit_path: must NOT have more than 900 characters
//
// Each retried, trimmed, was refused again, burned the five-retry cap and threw. The top finding's
// exploit_path was 905 characters. It died for five characters. They were NOT out of context:
// 723k of a 1M window, roughly 280k still spare.
//
// A security finding has to carry quoted source across several files AND a full exploit
// walkthrough, so any per-field cap that feels generous while writing the schema is a wall in
// practice. The caps are gone rather than raised, because a raised cap is the same trap with a
// bigger number. `agent-prompt-discipline.md` rule 8b is the general form: when an agent's output
// is inherently large, take the constraint off the return path.
//
// If a future version needs bounded returns, do NOT reintroduce caps here. Have each agent WRITE
// its findings to a file and return only {written_to, finding_count, dropped_count}, the way
// `.tools/hunt-missing-three.js` does.
const FINDINGS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['findings', 'dropped_count', 'coverage'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['title', 'file_line', 'source_quote', 'exploit_path', 'category', 'severity'],
        properties: {
          title: { type: 'string' },
          file_line: { type: 'string' },
          source_quote: { type: 'string' },
          exploit_path: { type: 'string' },
          category: { type: 'string', enum: ['absent-control', 'inert-control'] },
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
      },
    },
    dropped_count: { type: 'number', description: 'candidates you investigated and dropped as defended' },
    coverage: { type: 'string', description: 'what you actually read, and what you could not reach' },
  },
}

const DIMENSIONS = [
  {
    key: 'fail-open-policy',
    prompt: `Hunt FAIL-OPEN POLICY CONTROLS: a security control that silently permits everything under
some mode, some branch, or an empty collection. This is the vein that already produced three
accepted upstream issues, so look for its siblings across EVERY channel and subsystem, not just
WhatsApp. Specifically: does an empty allowlist/denylist mean "permit all"? Is a policy read in
one mode and ignored in another? Is a config key accepted by the schema and never consulted at
the enforcement site? Does a filter default to permissive when parsing fails?`,
  },
  {
    key: 'untrusted-to-llm',
    prompt: `Hunt UNTRUSTED TEXT REACHING THE MODEL CONTEXT without sanitization or length bound.
The happy-path data fields are usually handled; the ERROR and DIAGNOSTIC paths usually are not.
Check: serde/parse error Display impls that embed the offending value verbatim, HTTP/RPC error
bodies, server-controlled error.message, validation echoes that reflect rejected input, memory
recall, and file/tool output. Look for missing control-char/bidi/zero-width stripping and missing
length caps. Also check collection SIZES (unbounded vectors, TLV walks) that could flood context.`,
  },
  {
    key: 'approval-bypass',
    prompt: `Hunt HUMAN-APPROVAL AND CONFIRMATION BYPASS. Where an action is supposed to require a
human, can it proceed without one? Look for: approval that is checked in one code path and not a
sibling path, timeouts that default to approve, auto-approve lists that are broader than they
look, approval state that can be replayed or reused, and any place a tool executes before its
gate is evaluated. Also check whether the thing approved is the same thing executed (a
confirm-then-substitute gap).`,
  },
  {
    key: 'capability-sandbox',
    prompt: `Hunt CAPABILITY AND SANDBOX ESCAPE in the wasm plugin host. Which capabilities are
granted by default? Can a plugin reach the network, filesystem, or shell it was not granted? Is
the host's capability check performed before or after the plugin acts? Look at wit/ world
definitions versus what the host actually links, and at any host function that takes a
plugin-supplied path, URL, or command. Check whether a plugin can influence another plugin's
state or the host's config.`,
  },
  {
    key: 'secret-handling',
    prompt: `Hunt SECRET AND CREDENTIAL EXPOSURE. Trace keys, tokens, seeds and passwords: are any
written to logs, error messages, memory stores, telemetry, or the model context? Is redaction
applied at every sink or only the obvious one? Check Debug/Display derives on structs holding
secrets, error types that wrap credentials, and any serialization of config. Also check whether a
secret survives in a file with permissive modes or in a process argv.`,
  },
  {
    key: 'blast-radius',
    prompt: `Hunt BLAST RADIUS of the dangerous built-in tools: shell/exec, cron/scheduled tasks,
http_request, and file write. For each: what bounds it? Can a prompt-injected instruction reach
it? Is there an allowlist of commands or hosts, and is that allowlist fail-open (see the empty-set
shape)? Can a scheduled task be added that outlives the session or escalates later? Does a
disabled leak-detector change what these tools may emit?`,
  },
]

phase('Hunt')

// Paced fan: waves of 3, awaited sequentially. Retry once, then log the death rather than
// letting a throttled agent silently resolve to a dropped dimension.
async function pacedMap(items, fn, waveSize) {
  const out = []
  for (let i = 0; i < items.length; i += waveSize) {
    const wave = items.slice(i, i + waveSize)
    const settled = await parallel(wave.map((it, j) => async () => {
      try {
        return await fn(it, i + j)
      } catch (e) {
        try {
          return await fn(it, i + j)
        } catch (e2) {
          log(`DEAD after retry: ${it.key || it.title || `item ${i + j}`}`)
          return null
        }
      }
    }))
    out.push(...settled)
  }
  return out
}

const hunted = await pacedMap(DIMENSIONS, (d) => agent(
  `You are a security engineer auditing the ZeroClaw agent framework at ${ROOT}.
Rust workspace, 1064 .rs files, 31 crates. NEVER read target/.

${d.prompt}

${MAP}

${KNOWN}

${RULES}

Investigate thoroughly, then report at most 5 findings that survive the rules of evidence.
Report FEWER if fewer survive — an empty findings array is a perfectly good answer and is much
better than padding. Also report how many candidates you dropped as already-defended, because
that number tells us the control coverage is real.`,
  { label: `hunt:${d.key}`, phase: 'Hunt', schema: FINDINGS_SCHEMA, effort: 'high' }
), 3)

const candidates = hunted
  .filter(Boolean)
  .flatMap((r, i) => r.findings.map((f) => ({ ...f, dimension: DIMENSIONS[i] ? DIMENSIONS[i].key : 'unknown' })))

const droppedTotal = hunted.filter(Boolean).reduce((a, r) => a + (r.dropped_count || 0), 0)
const deadDimensions = DIMENSIONS.length - hunted.filter(Boolean).length

log(`Hunt: ${candidates.length} candidates from ${hunted.filter(Boolean).length}/${DIMENSIONS.length} dimensions; ${droppedTotal} candidates self-dropped as defended; ${deadDimensions} dimensions DEAD`)

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['verdict', 'reasoning', 'corrected_severity'],
  properties: {
    verdict: { type: 'string', enum: ['CONFIRMED', 'REFUTED', 'PARTIAL'] },
    reasoning: { type: 'string' },
    corrected_severity: { type: 'string', enum: ['high', 'medium', 'low', 'none'] },
  },
}

phase('Verify')

const verified = candidates.length === 0 ? [] : await pacedMap(candidates, (c) => agent(
  `You are an ADVERSARIAL VERIFIER. Your job is to REFUTE the finding below, not to confirm it.
Default to REFUTED unless the code forces you to agree. A false report to these maintainers
costs us real credibility, and they have already reviewed our earlier work closely.

Repository: ${ROOT}

CLAIMED FINDING
title: ${c.title}
location: ${c.file_line}
category: ${c.category}
claimed severity: ${c.severity}
quoted source: ${c.source_quote}
claimed exploit path: ${c.exploit_path}

Do this:
1. OPEN the cited file and verify the quote is real and current. If the quote is fabricated or
   paraphrased into something the file does not say, that alone is REFUTED.
2. Search for a guard elsewhere that already defends this — a caller-side check, a type
   invariant, a validation layer upstream, a config-schema constraint. Follow the call graph to
   the real entry point. Most claimed fail-open bugs die here.
3. Try to actually walk the exploit path. If any step does not work, say which one.
4. Only if it survives all three, answer CONFIRMED.

Answer PARTIAL only when the defect is real but the claimed severity or exploit path is wrong.`,
  { label: `verify:${c.file_line.slice(0, 42)}`, phase: 'Verify', schema: VERDICT_SCHEMA, effort: 'high' }
).then((v) => ({ ...c, verdict: v })), 3)

const survivors = verified.filter(Boolean).filter((c) => c.verdict && c.verdict.verdict !== 'REFUTED')
const refuted = verified.filter(Boolean).filter((c) => c.verdict && c.verdict.verdict === 'REFUTED').length
const unverified = verified.filter((c) => c && !c.verdict).length + verified.filter((c) => c === null).length

log(`Verify: ${survivors.length} survived, ${refuted} refuted, ${unverified} UNVERIFIED (must be labelled as such)`)

phase('Report')

const report = await agent(
  `Write the audit report to ${ROOT}/../zeroclaw-solana/docs/UPSTREAM-SECURITY-AUDIT.md.

Repository audited: ${ROOT} at git 63f432da (v0.8.3-182).
Dimensions run: ${DIMENSIONS.map((d) => d.key).join(', ')}${deadDimensions > 0 ? ` — WARNING: ${deadDimensions} dimension(s) DIED and their coverage is MISSING` : ''}
Candidates raised: ${candidates.length}. Self-dropped as already-defended: ${droppedTotal}.
Adversarially refuted: ${refuted}. Survived: ${survivors.length}. Unverified: ${unverified}.

SURVIVORS (each already survived an adversarial refutation attempt):
${JSON.stringify(survivors, null, 1).slice(0, 22000)}

Write a report that a ZeroClaw maintainer would find useful and would not resent. Structure:
1. Scope and method, including what was NOT covered. State the refuted and self-dropped counts
   plainly — they are evidence the audit discriminates rather than pads.
2. One section per surviving finding: location, the real quoted code, the concrete failure path,
   the adversarial verifier's reasoning, and a suggested fix. Rank by corrected_severity.
3. A short section listing controls found to be WORKING, since that is genuinely useful to them
   and shows the audit read the defenses too.
4. If any finding is UNVERIFIED, label it "[unverified]" explicitly. Never present an unverified
   finding as confirmed.

House style, non-negotiable: no em dashes. No bullet-point padding. No "comprehensive",
"robust", "leverage", "streamline", "actionable". No self-congratulation. Plain declarative
sentences. Do not restate the same point in a summary and then again in a section.

Return ONLY a one-paragraph summary of what you wrote plus the count of findings by severity.
Do not return the report body.`,
  { label: 'report:write', phase: 'Report', effort: 'high' }
)

return {
  candidates: candidates.length,
  survivors: survivors.length,
  refuted,
  unverified,
  selfDropped: droppedTotal,
  deadDimensions,
  summary: report,
}
