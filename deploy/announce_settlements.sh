#!/usr/bin/env bash
# Deterministic settlement receipts: chain -> message, with no model anywhere in the path.
#
# WHY THIS EXISTS. The payment-confirmation SOP is prose-authored, so the host hands its final
# wording to the model. Measured 2026-08-06: the model invented settlements -- placeholder
# signatures, one signature shared across two orders, timestamps in the future, and an order
# literally named "another_customer". Nothing it wrote matched any of the merchant's real
# signatures. Piping a correct script through that layer reintroduces exactly the surface the
# script removes, so this wrapper bypasses the SOP entirely.
#
# Every field in the outgoing message is derived by confirm_settlements.py from the chain.
# `zeroclaw channel send` delivers the bytes verbatim. Neither step consults a model.
#
# ORDER OF OPERATIONS, and it is the whole safety argument: SEND FIRST, COMMIT AFTER. If a send
# fails, the ledger is not written, so the next run announces that payment again. A visible
# duplicate is recoverable; a swallowed confirmation is not, and the customer has already paid.
#
# The recipient is read from the channel's OWN allowlist rather than hardcoded, so this file
# carries no phone number and cannot drift away from the channel it sends to.
#
# ------------------------------------------------------------------------------------------
# TWO VALUES, ONE VARIABLE. `$ZC_CHANNEL` used to feed both the config lookup and `--channel-id`,
# and those two want DIFFERENT strings:
#
#   the config lookup wants the INSTANCE  `whatsapp.shop`, because `[channels.whatsapp.shop]`
#                                         is the literal section header the recipient lives in
#   `--channel-id`      wants a channel   `whatsapp`, because the flag is documented as "Channel
#                       the binary knows  config name (e.g. telegram, discord, slack)" and the
#                                         binary matches it against a fixed list of families
#
# So one of the two was always wrong. Measured on the box 2026-08-16, every tick since 2026-08-06:
#
#   Error: Unknown channel 'whatsapp.shop'. Supported: telegram, discord, slack, ...
#   SEND FAILED, will retry next run: payment received: ...
#   announced 0 of 4; ledger NOT committed so the rest re-announce
#
# Four genuine mainnet settlements re-queued and none was ever announced. The ledger discipline
# held perfectly, which is why nothing was lost, and it is also why this stayed invisible.
#
# THE FIX IS TO SEPARATE THEM, NOT TO RENAME ONE. `$ZC_CHANNEL` keeps its meaning and its value
# (the instance) because that is what the deployed unit sets and what the config lookup needs;
# the channel-id is DERIVED from it below and is a distinct variable from here on.
#
# WHICH FORM THE BINARY WANTS DEPENDS ON ITS VINTAGE, so this tries the precise one first:
#
#   newer hosts   `send_channel_message` falls through to the announcement dispatcher for any
#                 dotted id its channel builder does not claim, and that dispatcher resolves
#                 `<type>.<alias>` properly. `whatsapp.shop` is exact and reaches the shop.
#   older hosts   no such fallback. Only a bare family name resolves, and the builder pins it
#                 to the `default` alias -- so a bare `whatsapp` is the SAME destination only
#                 when the instance IS the default alias.
#
# The bare-type retry is therefore gated on `alias = default`, and on the specific
# `Unknown channel '<id>'` error, which is raised while BUILDING the channel and so guarantees
# nothing was delivered. Retrying any other failure could double-send a receipt.
#
# When neither form is usable the run FAILS LOUD with both remedies named. It does not fall
# back to some other family, some other alias, or an unverified id: a receipt delivered to the
# wrong account is worse than a receipt delayed, and this path touches money.

set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    *) echo "usage: $0 [--dry-run]" >&2; exit 1 ;;
  esac
done

Z="${ZC_BIN:-$HOME/zeroclaw/target/release/zeroclaw}"
CFG="${ZC_CONFIG:-$HOME/.zeroclaw/config.toml}"
TOOLS="${ZC_TOOLS:-$HOME/.zeroclaw/agents/demo/workspace/tools}"
LEDGER="${ZC_LEDGER:-$HOME/.zeroclaw/agents/demo/workspace/confirmed-payments-v2.jsonl}"
# The channel INSTANCE: `<type>.<alias>`, and the name of its config section.
CHANNEL="${ZC_CHANNEL:-whatsapp.shop}"
CONFIRM="$TOOLS/confirm_settlements.py"

[ -x "$Z" ]        || { echo "no zeroclaw binary at $Z" >&2; exit 2; }
[ -f "$CONFIRM" ]  || { echo "no confirmer at $CONFIRM" >&2; exit 2; }
[ -f "$CFG" ]      || { echo "no config at $CFG" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Resolution. Kept in one function with no side effects so it can be driven
# against a fixture config off the box -- see deploy/test_announce_settlements.py.
# ---------------------------------------------------------------------------

case "$CHANNEL" in
  *.*) ;;
  *) echo "ZC_CHANNEL must be a <type>.<alias> instance (e.g. whatsapp.shop), got '$CHANNEL'" >&2
     exit 2 ;;
esac
CHANNEL_TYPE="${CHANNEL%%.*}"
CHANNEL_ALIAS="${CHANNEL#*.}"

# The id handed to --channel-id. Explicit beats derived: an operator who knows their host takes
# a form this script did not predict says so, and gets no silent retry behind their back.
if [ -n "${ZC_CHANNEL_ID:-}" ]; then
  CHANNEL_ID="$ZC_CHANNEL_ID"
  CHANNEL_ID_RETRY=""
else
  CHANNEL_ID="$CHANNEL"
  if [ "$CHANNEL_ALIAS" = "default" ]; then
    CHANNEL_ID_RETRY="$CHANNEL_TYPE"
  else
    CHANNEL_ID_RETRY=""
  fi
fi

# Resolve the recipient from the channel section that will actually carry the message. An empty
# result is exit 2 (could not run), never exit 0 -- a receipt sent nowhere must not read as success.
#
# The pattern is a WhatsApp JID because that is the family this ships against; any other family
# must set ZC_RECIPIENT, and the error below says so rather than guessing at another id shape.
# Matches are collected whole and the first taken by expansion rather than piped through `head`,
# which under `pipefail` can turn a healthy read into a SIGPIPE failure.
SECTION_RE="$(printf '%s' "$CHANNEL" | sed 's/[].[^$*\/]/\\&/g')"
if [ -n "${ZC_RECIPIENT:-}" ]; then
  RECIPIENT="$ZC_RECIPIENT"
else
  MATCHES="$(sed -n "/^\[channels\.${SECTION_RE}\]/,/^\[/p" "$CFG" \
    | grep -oE '[0-9]+@(g\.us|s\.whatsapp\.net)' || true)"
  RECIPIENT="${MATCHES%%$'\n'*}"
fi
[ -n "$RECIPIENT" ] || {
  echo "no recipient resolved from [channels.${CHANNEL}] in $CFG" >&2
  echo "  the section must carry a WhatsApp JID, or set ZC_RECIPIENT explicitly" >&2
  exit 2
}

if [ "$DRY_RUN" -eq 1 ]; then
  echo "instance      ZC_CHANNEL=$CHANNEL"
  echo "  type        $CHANNEL_TYPE"
  echo "  alias       $CHANNEL_ALIAS"
  echo "config lookup [channels.${CHANNEL}] in $CFG"
  echo "  recipient   $RECIPIENT"
  echo "channel-id    $CHANNEL_ID"
  if [ -n "$CHANNEL_ID_RETRY" ]; then
    echo "  retry-as    $CHANNEL_ID_RETRY   (only on Unknown channel '$CHANNEL_ID')"
  else
    echo "  retry-as    none; alias '$CHANNEL_ALIAS' is not reachable by a bare type"
  fi
fi

# 1. Ask the chain what is unannounced. Appends no ledger records.
#
# The confirmer keeps a cache of signatures already proven NOT to be incoming settlements,
# under ~/.zeroclaw/state/ by default. That is what stops this step re-reading the same
# dozen unrelated transactions from the chain on every tick; see the confirmer's own header
# for why only negative verdicts are ever cached. ZC_SCAN_CACHE relocates it; setting it to
# the empty string disables it and forces every verdict to be re-derived.
CACHE_ARGS=()
if [ -n "${ZC_SCAN_CACHE+x}" ]; then
  if [ -n "$ZC_SCAN_CACHE" ]; then
    CACHE_ARGS=(--cache "$ZC_SCAN_CACHE")
  else
    CACHE_ARGS=(--no-cache)
  fi
fi

PENDING="$(python3 "$CONFIRM" --ledger "$LEDGER" \
  ${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"} --dry-run | grep '^SEND: ' || true)"

if [ -z "$PENDING" ]; then
  echo "nothing to announce"
  exit 0
fi

# The host's own error and the remedies, emitted ONCE for the whole run rather than once per
# message. Every pending receipt fails identically here, because the cause is the id and not the
# payment, so on the incident's four stuck settlements this block would otherwise repeat four
# times and bury the run's actual outcome. Which payments are affected is NOT lost to this: the
# loop below still prints its own "will retry next run" line once per message.
#
# The flag survives the loop because a `while ... done <<< "$PENDING"` herestring runs in the
# current shell rather than a subshell. A pipe there would silently give each iteration its own
# copy and restore the repetition, which is why the loop must stay a herestring.
UNSUPPORTED_TOLD=0
unsupported_id() {
  [ "$UNSUPPORTED_TOLD" -eq 0 ] || return 0
  UNSUPPORTED_TOLD=1
  printf '%s\n' "$1" >&2
  echo "this host's \`channel send\` does not accept '$CHANNEL_ID', and alias" >&2
  echo "'$CHANNEL_ALIAS' is not reachable by the bare type '$CHANNEL_TYPE' (the builder" >&2
  echo "pins a bare type to the 'default' alias). Nothing was sent and the ledger is" >&2
  echo "unchanged, so every pending receipt re-announces on the next run. Either:" >&2
  echo "  - update the host binary to one whose channel send resolves <type>.<alias>, or" >&2
  echo "  - set ZC_CHANNEL_ID to an id this host does resolve to the same account" >&2
}

# Send one message. Prints the command under --dry-run and sends nothing.
send_one() {
  local msg="$1" out
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'would run: %s channel send --channel-id %s --recipient %s %q\n' \
      "$Z" "$CHANNEL_ID" "$RECIPIENT" "$msg"
    return 0
  fi
  if out="$("$Z" channel send --channel-id "$CHANNEL_ID" --recipient "$RECIPIENT" "$msg" 2>&1)"; then
    return 0
  fi
  # Only an id the binary does not KNOW is safe to retry: that error is raised while building
  # the channel, before any delivery. Every other failure may have partially delivered.
  case "$out" in
    *"Unknown channel '$CHANNEL_ID'"*) ;;
    *) printf '%s\n' "$out" >&2; return 1 ;;
  esac
  if [ -z "$CHANNEL_ID_RETRY" ]; then
    unsupported_id "$out"
    return 1
  fi
  echo "channel-id '$CHANNEL_ID' unknown to this host; using '$CHANNEL_ID_RETRY'" >&2
  CHANNEL_ID="$CHANNEL_ID_RETRY"
  CHANNEL_ID_RETRY=""
  if out="$("$Z" channel send --channel-id "$CHANNEL_ID" --recipient "$RECIPIENT" "$msg" 2>&1)"; then
    return 0
  fi
  printf '%s\n' "$out" >&2
  return 1
}

# 2. Send each line verbatim. Count failures rather than aborting, so one bad send does not
#    strand the others -- they are independent payments.
#
# The signature of each ANNOUNCED payment is collected as we go, and step 3 commits exactly
# those. See the note there for why re-deriving instead would swallow a receipt.
FAILED=0
COUNT=0
ONLY=()
while IFS= read -r line; do
  [ -n "$line" ] || continue
  COUNT=$((COUNT + 1))
  MSG="${line#SEND: }"
  # `...(signature <sig>)` is the confirmer's own trailing field. Strip to the last
  # occurrence so a payer or amount could never be mistaken for it.
  SIG="${MSG##*(signature }"
  SIG="${SIG%)}"
  if send_one "$MSG"; then
    [ "$DRY_RUN" -eq 1 ] || echo "sent: $MSG"
    case "$SIG" in
      "$MSG"|*[!0-9A-Za-z]*|"") ;;   # unparsed, or not bare base58: leave it out
      *) ONLY+=(--only "$SIG") ;;
    esac
  else
    echo "SEND FAILED, will retry next run: $MSG" >&2
    FAILED=$((FAILED + 1))
  fi
done <<< "$PENDING"

if [ "$DRY_RUN" -eq 1 ]; then
  # Not "wrote nothing": step 1 ran a real scan, and a scan updates the confirmer's cache.
  # Nothing was SENT and no ledger record was written, which is what a dry run promises.
  echo "dry run: sent nothing, wrote no ledger record ($COUNT message(s) withheld)"
  exit 0
fi

# 3. Commit ONLY if every send landed. A partial commit is the one outcome that loses a receipt.
#
# THE COMMIT IS NARROWED TO WHAT WAS ACTUALLY ANNOUNCED, and the un-narrowed version had a
# hole. This step re-derives from chain, and it used to append EVERYTHING it found. Between
# the scan in step 1 and this call sit N `channel send` round trips, so a payment settling in
# that window -- seconds, not milliseconds -- was written to the ledger having never been
# sent. The next run then read it as already recorded and never announced it. That is a
# swallowed confirmation, the single outcome the send-first/commit-after ordering exists to
# prevent, arriving through the commit rather than through a failed send.
#
# Passing --only for each announced signature closes it: a payment that lands mid-run is
# simply not appended, so the next tick announces it normally. Every field written is still
# read from the chain on THIS call; --only restricts which records are kept, never their
# contents. A signature that failed to parse above is left out of the list, so the narrowing
# can only ever be tighter than reality, and a too-tight commit costs a duplicate receipt --
# which the header of this file calls recoverable, unlike the swallow it replaces.
if [ "$FAILED" -eq 0 ]; then
  if [ "${#ONLY[@]}" -ne $((COUNT * 2)) ]; then
    echo "refusing to commit: parsed $(( ${#ONLY[@]} / 2 )) signature(s) from $COUNT announced" >&2
    echo "message(s). Committing an unnarrowed pass here can swallow a payment that settled" >&2
    echo "mid-run, so nothing is written and all $COUNT re-announce on the next tick." >&2
    exit 1
  fi
  # DEPLOY ORDERING. --only is newer than this script's first deployed version, so a box that
  # received this file without the matching confirmer would have argparse reject the flag. That
  # is a real shape here: the pair is synced together from deploy/deploy-targets.json, and the
  # last incident on this path was precisely a component whose deployed vintage did not match
  # what called it. `set -e` would abort on the failure and say nothing about the cause, so it
  # is caught and named instead. Nothing is committed either way, so the receipts re-announce.
  if ! python3 "$CONFIRM" --ledger "$LEDGER" "${ONLY[@]}" >/dev/null; then
    echo "the confirmer rejected the commit; ledger NOT written, so all $COUNT re-announce." >&2
    echo "If it reported an unrecognized --only, this script is newer than the deployed" >&2
    echo "$CONFIRM. Sync both from deploy/deploy-targets.json; they are one pair." >&2
    exit 1
  fi
  echo "announced $COUNT, ledger committed"
  exit 0
fi

echo "announced $((COUNT - FAILED)) of $COUNT; ledger NOT committed so the rest re-announce" >&2
exit 1
