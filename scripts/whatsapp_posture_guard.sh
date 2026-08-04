#!/bin/bash
# Refuse to start the shop when the WhatsApp group posture is fail-open.
#
# Why this exists as a START GATE rather than a comment: on the host build this node
# runs, an EMPTY `allowed_groups` means permit-ALL, not permit-none. The live config
# neutralises that with a dummy JID that matches no real group. That dummy looks like
# junk, so the realistic failure is someone tidying it into `allowed_groups = []` and
# silently re-opening every group the account belongs to. A group-spam incident is
# exactly what this project already had once.
#
# Fails CLOSED: any doubt refuses the start. A shop that will not boot is recoverable;
# a shop that answers a school group is not.
#
# Positive control lives in the suite next to it: a guard that has never refused a
# known-bad config has not been shown to work.
set -u

CFG="${ZC_CONFIG:-$HOME/.zeroclaw/config.toml}"

fail() {
    echo "REFUSING TO START: $1" >&2
    exit 1
}

[ -r "$CFG" ] || fail "config unreadable at $CFG"

# Gate 1: allowed_groups must exist AND carry at least one entry. Empty is permit-all here.
if ! grep -qE '^[[:space:]]*allowed_groups[[:space:]]*=' "$CFG"; then
    fail "allowed_groups is absent; on this build an absent/empty list permits every group"
fi
if grep -qE '^[[:space:]]*allowed_groups[[:space:]]*=[[:space:]]*\[[[:space:]]*\]' "$CFG"; then
    fail "allowed_groups is EMPTY; on this build that means permit-ALL groups, not permit-none"
fi

# Gate 2: group_policy must never be the open value.
if grep -qE '^[[:space:]]*group_policy[[:space:]]*=[[:space:]]*"all"' "$CFG"; then
    fail 'group_policy = "all" admits every group regardless of the allowlist'
fi

# Gate 3: the policy block is only consulted in personal mode on this build, so business
# mode would skip group_policy entirely. Refuse the combination that reintroduces #9348.
if grep -qE '^[[:space:]]*mode[[:space:]]*=[[:space:]]*"business"' "$CFG" \
    && ! grep -qE '^[[:space:]]*group_policy[[:space:]]*=[[:space:]]*"ignore"' "$CFG"; then
    fail 'mode = "business" does not consult group_policy on this build (upstream #9348)'
fi

echo "whatsapp group posture OK (allowed_groups non-empty, group_policy not open)"
