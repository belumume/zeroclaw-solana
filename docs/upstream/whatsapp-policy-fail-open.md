# Upstream contribution: WhatsApp Web policy fail-open

Status: FILED 2026-07-25 as https://github.com/zeroclaw-labs/zeroclaw/issues/9348

Body as filed is reproduced in full below, between the horizontal rules, from
`## Title` to the end of `## Notes` (audited before posting: 0 em dashes, 0
flagged vocabulary, 0 operator identifiers, no local paths, no phone numbers, no
group names). This line pointed at a gitignored staging copy until 2026-07-27,
which resolved to nothing in a clone while the text it named was already on the
page. Maintainers active on this area: JordanTheJet, tidux, Audacity88, Nillth.
Offered a PR for whichever of the three fixes they prefer, so the follow-up is a
genuine merge opportunity rather than a drive-by report.

Prior art checked (none cover this): 4110 (policy keys rejected as unknown
config keys, closed), 6371 (per-JID allowed_groups feature, closed), 6413
(is_from_me leak, closed), 5260 (self_chat_mode replies, closed). A search for
whatsapp policy, dm_policy, group_policy, allowed_groups and fail open returned
no open or closed issue describing the behavior below.

---

## Title

[Bug]: WhatsApp Web answers every DM and every group in business mode (chat
policies are personal-mode only, and an empty allowed_groups permits all groups)

## Affected component

channels (whatsapp-web)

## Severity

S1, security risk. An operator who believes they configured an allowlist gets an
agent that replies to every inbound message, including unrelated group chats.

## Current behavior

Two independent gates both default open, and they compound.

1. The chat-type policy block is gated on personal mode. In
   `crates/zeroclaw-channels/src/whatsapp_web.rs` the inbound handler reads:

   ```rust
   // ── Personal-mode chat-type policy filtering ──
   if wa_mode == zeroclaw_config::schema::WhatsAppWebMode::Personal {
       ... self_chat_mode / group_policy / dm_policy enforcement ...
   }
   ```

   With `mode = "business"` the entire block is skipped, so `dm_policy`,
   `group_policy` and `self_chat_mode` are parsed and accepted from config but
   never consulted. There is no warning at startup and no log line at message
   time. A config that reads as locked down behaves as fully open.

2. The group allowlist treats empty as permit-all:

   ```rust
   fn is_group_chat_allowed(chat_jid: &str, allowed_groups: &[String]) -> bool {
       if allowed_groups.is_empty() {
           return true;
       }
       ...
   }
   ```

   `allowed_groups` defaults to empty, so by default every group the linked
   account belongs to is permitted. This gate does run in both modes, which
   makes it the only group protection in business mode, and it is open.

Net effect for `mode = "business"` with default `allowed_groups`: the agent
replies to every DM from any sender and to every message in every group the
linked WhatsApp account is a member of.

## Expected behavior

Any of the following would close it, in rough order of preference:

1. Enforce `dm_policy` and `group_policy` in both modes, or state explicitly in
   config validation that they are personal-mode only and warn at startup when
   they are set under `mode = "business"`.
2. Make an empty `allowed_groups` mean permit none rather than permit all, so
   the group gate fails closed. If the current default must be preserved for
   compatibility, gate it behind an explicit `group_policy = "all"` so the
   permissive case is chosen rather than inherited.
3. At minimum, emit a startup warning when a policy key is set but unreachable
   on the active mode, in the same spirit as the existing
   `memory_semantic_search_without_embedder` warning.

## Steps to reproduce

1. Configure a WhatsApp Web channel with:

   ```toml
   [channels.whatsapp.<alias>]
   enabled = true
   mode = "business"
   dm_policy = "allowlist"
   group_policy = "ignore"
   mention_only = true
   # allowed_groups omitted, so it defaults to empty
   ```

2. Link the account and start the daemon. Config validation accepts every key.
3. Send a DM from a number that is not in any peer group. The agent replies.
4. Send a message in any group the linked account belongs to, without
   mentioning the bot. The agent replies.

Expected: both are ignored. Actual: both are answered.

## Notes

This is the same shape as the fail-open reported for the verifiable-intent
constraint checker, where an empty fulfillment satisfies a payee allowlist. Two
independent instances of "an empty collection is treated as permit-all" suggest
the codebase would benefit from a shared convention: an unset allowlist is an
unconfigured allowlist, and an unconfigured security control should deny rather
than permit. Happy to open a PR for whichever of the three options above the
maintainers prefer.

---

## Why this matters to our own submission (internal note, not part of the issue)

Found while hardening our own deny-by-default posture. It is the strongest real
custody evidence we have: a configuration that reads as locked down and was not.
The anonymized before, fix, and deny-by-default arc belongs in the write-up and
the demo, and this issue is the good-citizen half of it.
