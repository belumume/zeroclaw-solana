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

set -euo pipefail

Z="${ZC_BIN:-$HOME/zeroclaw/target/release/zeroclaw}"
CFG="${ZC_CONFIG:-$HOME/.zeroclaw/config.toml}"
TOOLS="${ZC_TOOLS:-$HOME/.zeroclaw/agents/demo/workspace/tools}"
LEDGER="${ZC_LEDGER:-$HOME/.zeroclaw/agents/demo/workspace/confirmed-payments-v2.jsonl}"
CHANNEL="${ZC_CHANNEL:-whatsapp.shop}"
CONFIRM="$TOOLS/confirm_settlements.py"

[ -x "$Z" ]        || { echo "no zeroclaw binary at $Z" >&2; exit 2; }
[ -f "$CONFIRM" ]  || { echo "no confirmer at $CONFIRM" >&2; exit 2; }
[ -f "$CFG" ]      || { echo "no config at $CFG" >&2; exit 2; }

# Resolve the recipient from the channel section that will actually carry the message. An empty
# result is exit 2 (could not run), never exit 0 -- a receipt sent nowhere must not read as success.
RECIPIENT="${ZC_RECIPIENT:-$(
  sed -n "/^\[channels.${CHANNEL}\]/,/^\[/p" "$CFG" \
    | grep -oE '[0-9]+@(g\.us|s\.whatsapp\.net)' | head -1
)}"
[ -n "$RECIPIENT" ] || { echo "no recipient resolved for channel ${CHANNEL} in $CFG" >&2; exit 2; }

# 1. Ask the chain what is unannounced. Writes nothing.
PENDING="$(python3 "$CONFIRM" --ledger "$LEDGER" --dry-run | grep '^SEND: ' || true)"

if [ -z "$PENDING" ]; then
  echo "nothing to announce"
  exit 0
fi

# 2. Send each line verbatim. Count failures rather than aborting, so one bad send does not
#    strand the others -- they are independent payments.
FAILED=0
COUNT=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  COUNT=$((COUNT + 1))
  MSG="${line#SEND: }"
  if "$Z" channel send --channel-id "$CHANNEL" --recipient "$RECIPIENT" "$MSG"; then
    echo "sent: $MSG"
  else
    echo "SEND FAILED, will retry next run: $MSG" >&2
    FAILED=$((FAILED + 1))
  fi
done <<< "$PENDING"

# 3. Commit ONLY if every send landed. A partial commit is the one outcome that loses a receipt.
if [ "$FAILED" -eq 0 ]; then
  python3 "$CONFIRM" --ledger "$LEDGER" >/dev/null
  echo "announced $COUNT, ledger committed"
  exit 0
fi

echo "announced $((COUNT - FAILED)) of $COUNT; ledger NOT committed so the rest re-announce" >&2
exit 1
