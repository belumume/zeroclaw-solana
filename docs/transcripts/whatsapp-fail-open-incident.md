---
audience: internal
---

# The WhatsApp fail-open incident (2026-07-23/24)

A real deny-by-default failure, caught in the wild, root-caused from host source, fixed, and
reported upstream as zeroclaw-labs/zeroclaw#9348. This file is the anonymised record. Phone
numbers and the group identity are deliberately omitted from anything public.

## What happened, in order

The shop agent (display name "Learner") was linked to a WhatsApp account that also belonged to a
university student group. It had no gating, so it answered the group.

1. **It answered a question that was not addressed to it.** Students were discussing a delayed
   stipend. The agent replied asking which reward they meant, since it had no context. Students
   apologised for the confusion, thinking they had messaged the wrong person.
2. **It kept answering.** A question about whether allocations are released each semester got an
   answer. A student asked why the university site would not open and whether the reader had tried
   Nafath, the Saudi national identity SSO.
3. **It outed itself.** It replied that it is an AI assistant with no ability to use Nafath
   directly, and offered help. A student quoted that message back and asked simply: "AI?"
4. **It confirmed.** "Yes! How can I help you?"
5. **The group started playing with it.** One asked whether he should walk or drive to a car wash
   50 metres away. The agent joked back correctly (walking would wash him, not the car). Another
   asked for a shakshuka recipe without eggs and got a full recipe with headings and quantities.
6. **The owner took over, apologised publicly, and left**, then killed the daemon.

Every agent message was posted two or more times, which is a second defect and is what made the
intrusion read as spam rather than as one stray reply.

## Root cause, read from host source rather than inferred

Two gates, both defaulting open, compounding:

1. **The chat-policy block is gated on personal mode.** `dm_policy`, `group_policy`, and
   `self_chat_mode` are parsed and validated, then only consulted inside a branch conditioned on
   `wa_mode == Personal`. The shop ran `mode = "business"`, so all three were dead config: present,
   valid, never read.
2. **An empty allowlist means allow-all.** `is_group_chat_allowed` returns `true` when
   `allowed_groups` is empty, and empty is the default.

So the configuration looked restrictive and enforced nothing. This is the same
validates-but-never-consulted shape as the `approval_timeout_secs` key being inert on the
whatsapp-web backend, and as OCI reporting a Run Command plugin `ENABLED` that its agent never
instantiated. Three instances, one pattern: **a setting's presence is not its enforcement.**

## The fix

`mode = "personal"` so the policy block is actually reached, plus `group_policy = "ignore"`
(drops every group at the message boundary), `dm_policy = "allowlist"`, `mention_only = true`, and
a non-empty dummy `allowed_groups` as a mode-independent second layer. Daemon restarted onto the
safe config and verified reading it at startup.

Independently corroborated: OUTIS found the identical empty-means-permissive fail-open in
ZeroClaw's x402 verifiable-intent checker (#9327 / #9328). It is a platform-wide pattern, not a
one-off.

## Why this belongs in the submission

It is the strongest custody material available, because it is real rather than hypothetical. A
deny-by-default claim backed by a story where the default was NOT deny, we found it, root-caused
it from source, fixed it, and upstreamed it, is worth more than an assertion that the design is
safe. It also demonstrates the discipline the rubric scores: reading the source instead of
trusting the config surface.

Anonymisation rules for any public use: no phone numbers, no group name, no institution, no
message text that could identify a participant. Describe the shape (a live group, an agent with
no gating, students who realised and played with it), never the people.

## Still open

Empirical confirmation that the allowlist now gates, which needs a DM from the allowlisted
customer number to the shop. Tracked as #45. The source-level fix is verified; the live-channel
behaviour is not yet.
