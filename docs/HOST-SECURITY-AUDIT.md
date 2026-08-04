# Security audit of the host this project runs on

This project is a set of Solana plugins for ZeroClaw, and every custody claim it makes rests on
the host enforcing what it says it enforces. So the host got audited rather than assumed.

Ten defects were found, verified, and reported upstream. All ten are public issues, linked below.
This document is a summary and a pattern analysis; the issues carry the code, the exploit paths and
the suggested fixes.

**Ten is this audit's count, not the project's total, and the two are easy to read as a
contradiction.** This was ONE structured pass over one commit, and its ten confirmed findings are
the number quoted here and in the README. The project's total upstream contribution is larger and
counts different things: issues filed while BUILDING against the host, which is how the WhatsApp
policy bug, the inert approval timeout, the vendored-WIT drift and the Cloud approval-token leak
were all found, plus the pull requests that followed. Read live from the API rather than restated
here, since both figures move as maintainers triage:

```
gh search issues --repo zeroclaw-labs/zeroclaw --author @me --limit 100 --json labels,state
gh search prs    --repo zeroclaw-labs/zeroclaw --author @me --limit 50  --json state,title
```

At the last read that returned eighteen issues, fourteen carrying `status:accepted`, sixteen rated
`priority:p1`, and five pull requests of which one is merged. If a figure elsewhere disagrees with
what those commands print, the commands are right.

Audited at `zeroclaw-labs/zeroclaw` commit `63f432da` (v0.8.3-182), a Rust workspace of 1064 source
files across 31 crates.

## Why this belongs in a plugin submission

Two reasons, and the second is the one that matters.

The plugins here are deny-by-default and push the real spending bound onto an audited on-chain
program, precisely so that a host-side or model-side compromise cannot move funds. That argument is
only honest if someone has actually looked at the host-side controls rather than trusting them. Six
of the ten findings are host-side authorization or audit gaps, which is the layer the custody design
deliberately does not rely on.

And one finding is a live risk to any operator running this stack, including this one. See the
credential-exposure entry below.

## The findings

| Issue | Finding | Severity |
|---|---|---|
| [#9387](https://github.com/zeroclaw-labs/zeroclaw/issues/9387) | Interactive approval responses are accepted from any chat member on Telegram, Slack, Lark and Matrix | high |
| [#9386](https://github.com/zeroclaw-labs/zeroclaw/issues/9386) | A Gemini API key in the request URL survives error sanitization and is posted into the originating chat | high |
| [#9389](https://github.com/zeroclaw-labs/zeroclaw/issues/9389) | Unauthenticated `POST /api/pair` keys its lockout on an attacker-supplied header | high |
| [#9390](https://github.com/zeroclaw-labs/zeroclaw/issues/9390) | Emergency stop is a CLI-only state file that no runtime path reads | high |
| [#9391](https://github.com/zeroclaw-labs/zeroclaw/issues/9391) | Command audit logging defaults to enabled and writes nothing | high |
| [#9392](https://github.com/zeroclaw-labs/zeroclaw/issues/9392) | LINE group messages skip the allowlist and the pairing handshake | high |
| [#9393](https://github.com/zeroclaw-labs/zeroclaw/issues/9393) | Bluesky and Reddit have no sender authorization and no central gate covers them | medium |
| [#9394](https://github.com/zeroclaw-labs/zeroclaw/issues/9394) | `[gateway.pairing_dashboard]` is accepted and entirely unread; pairing codes never expire | medium |
| [#9395](https://github.com/zeroclaw-labs/zeroclaw/issues/9395) | Plugin `wasi:http` egress has no destination policy and no configuration knob | medium |
| [#9396](https://github.com/zeroclaw-labs/zeroclaw/issues/9396) | The CLI approval prompt renders tool arguments without stripping control characters | medium |

Two further issues predate this audit and come from the same work:
[#9348](https://github.com/zeroclaw-labs/zeroclaw/issues/9348) (WhatsApp Web ignores its chat
policies under `mode = "business"`, and an empty `allowed_groups` admits every group) and
[#9366](https://github.com/zeroclaw-labs/zeroclaw/issues/9366) (`approval_timeout_secs` accepted and
never read). Both have PRs:
[#9382](https://github.com/zeroclaw-labs/zeroclaw/pull/9382) and
[#9385](https://github.com/zeroclaw-labs/zeroclaw/pull/9385).

## The pattern: accepted-and-inert controls

Five of these are the same defect wearing different clothes. An operator writes a safety setting,
the config schema validates it, the value is stored and serialized, and no runtime path ever reads
it:

- emergency stop (#9390) writes a state file nothing consults
- `[security.audit]` (#9391) defaults to enabled and constructs no logger
- `[gateway.pairing_dashboard]` (#9394) is parsed and never consulted
- plugin `wasi:http` egress (#9395) has no knob at all, while the built-in HTTP tool has one
- `approval_timeout_secs` (#9366) is read on other transports and not on WhatsApp Web

**An accepted-and-inert control is worse than an absent one.** An absent control is visible: the
operator knows they have no emergency stop. An inert one is invisible, and the operator makes
decisions believing they are protected. This is a design-review finding rather than five bugs, and
it predicts where the sixth will be: any setting whose only test asserts that it parses.

The custody model in this project is built on the opposite principle. The spending bound is a
Solana Foundation Allowances delegation, so the rejection of an over-cap transfer is produced by an
audited on-chain program and is visible as a failed transaction with `custom program error 0x12c`.
It cannot be inert, because the chain either rejected the transfer or it did not.

## How the findings were verified

The interesting part of this audit is not the count, it is the ratio.

| stage | candidates |
|---|---|
| investigated across six dimensions | 128 |
| dropped at the hunt stage as already-defended, out of scope, or duplicate | 107 (84%) |
| raised to adversarial verification | 21 |
| confirmed | 10 (7.8% of all candidates) |
| partial: real defect, original claim corrected | 11 |
| refuted outright | 0 |

The counts are the hunt agents' own returned `dropped_count` and finding totals summed across the
six dimensions, so the stages close: 107 dropped plus 21 raised is the 128 investigated, and the 21
raised split into 10 confirmed plus 11 partial.

The six dimensions were fail-open policy, untrusted-input-to-model, approval bypass, capability and
sandbox escape, secret handling, and blast radius of the dangerous built-in tools. Each hunter was
required to look for an existing guard and to DROP the candidate on finding one, which is where 107
candidates died.

Each survivor then went to a verifier told to **refute** it, and to treat a paraphrased quote as a
refutation on its own. Nothing was refuted outright, which is expected downstream of an 84%
pre-screen, but eleven came back partial, and one finding could be corrected in more than one of
these ways: six had their severity lowered, eight had at least one named exploit step falsified,
and two were reclassified as documented-by-design. The three counts therefore overlap rather than
partitioning the eleven. Those eleven are not reported here, because a corrected finding still
needs its correction verified before it is worth a maintainer's time.

Concretely, verification killed claims like these:

- a chain in which one message permanently unsupervises `shell`, falsified because the channel path
  builds its approval manager with `non_interactive_shell_requires_approval: false`, so `shell`
  short-circuits to NotRequired and never prompts at all
- a plugin-egress bug, shown to be documented behaviour by the project's own book, which states that
  a tool holding the `http_client` grant may reach whatever its code decides
- a privilege bypass via a forged `<tool_result>` envelope, shown to be context poisoning plus a host
  misparse rather than an approval bypass, because approval is a pre-execution hook over a live
  operator answer and is never read back from history text

## The credential exposure

[#9386](https://github.com/zeroclaw-labs/zeroclaw/issues/9386) is the one that affects anyone
running this stack with a Google-keyed provider. The chain, with each link either read from source
or tested:

1. the API key is sent as a `?key=` query parameter
2. reqwest's error `Display` carries the full URL including that query string, which was tested
   against a closed port rather than assumed
3. `sanitize_api_error` does not strip it: the scrubber matches seven token prefixes and `AIza` is
   not among them. Reproduced, alongside a positive control proving the same call does redact an
   `sk-` prefixed key, so the failure is the sanitizer and not the test
4. the sanitized-but-not-really text is formatted into a user-facing message and sent to the
   originating chat, which may be a group
5. the outbound leak detector has an `AIza` pattern but is not on that code path

No attacker is required. A DNS blip does it.

The obvious rebuttal is that the leak detector would have caught it if it were wired onto that
path. It would not, and this is the part worth reading twice. The detector's only Google pattern
is `AIza[a-zA-Z0-9_-]{35}`, while keys issued by AI Studio today carry an `AQ.` prefix. That
character class excludes `.`, so the pattern fails at the third character and cannot match a
current key at all. Enabling the mitigation everyone assumes exists would have changed nothing
here, which is why the fix below targets the property rather than the pattern list.

The recommended fix upstream is the property rather than the list: strip the query string from any
URL appearing in error text, instead of adding one more vendor prefix, because the next provider to
put a credential in a URL will not be caught by an `AIza` entry.

## Reproducing the audit

The dimension prompts, the rules of evidence, and the dedup list are in
`scripts/audit/host-security-audit.workflow.js`, committed here so a clone gets them. It is not a
black box: the hunters are told what counts as a finding, what to drop, and that three real defects
beat thirty theoretical ones. The script is a Claude Code dynamic workflow, so running it as-is needs
that harness; reading it needs nothing.

Each issue is independently checkable without running any of it. Every one cites exact `file:line`
locations and quotes the deciding code, so a reader can open the same lines at the same commit and
judge for themselves.
