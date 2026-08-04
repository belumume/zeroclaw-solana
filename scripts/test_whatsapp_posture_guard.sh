#!/bin/bash
# Controls for whatsapp_posture_guard.sh, in BOTH directions.
#
# One direction alone is worthless here. Only-must-refuse passes for a guard that
# refuses everything, which would just wedge the shop. Only-must-pass passes for a
# guard that refuses nothing, which is the fail-open it exists to prevent.
#
# Case 1 is the real incident shape: an empty allowed_groups, which on this host build
# means permit-ALL. If that case ever stops refusing, this guard is dead.
set -u
G="${1:-$(dirname "$0")/whatsapp_posture_guard.sh}"
pass=0
fail=0
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

run() {
    local name="$1" want="$2" body="$3"
    local cfg="$tmpdir/cfg.toml"
    printf '%s\n' "$body" >"$cfg"
    ZC_CONFIG="$cfg" bash "$G" >/dev/null 2>&1
    local rc=$?
    if [ "$rc" = "$want" ]; then
        echo "  ok   $name (rc=$rc)"
        pass=$((pass + 1))
    else
        echo "  FAIL $name (rc=$rc want=$want)"
        fail=$((fail + 1))
    fi
}

echo "MUST REFUSE (rc=1):"
run "empty allowed_groups (THE INCIDENT SHAPE)" 1 'allowed_groups = []
group_policy = "ignore"
mode = "personal"'
run "absent allowed_groups" 1 'group_policy = "ignore"
mode = "personal"'
run "group_policy = all" 1 'allowed_groups = ["000000000000000000@g.us"]
group_policy = "all"
mode = "personal"'
run "business mode without ignore (#9348)" 1 'allowed_groups = ["000000000000000000@g.us"]
group_policy = "allowlist"
mode = "business"'
run "empty list with whitespace" 1 'allowed_groups = [   ]
group_policy = "ignore"
mode = "personal"'

echo "MUST PASS (rc=0):"
run "the live node posture" 0 'allowed_groups = ["000000000000000000@g.us"]
group_policy = "ignore"
mode = "personal"'
run "business but group_policy ignore" 0 'allowed_groups = ["000000000000000000@g.us"]
group_policy = "ignore"
mode = "business"'
run "a genuinely allowlisted group" 0 'allowed_groups = ["120363111@g.us"]
group_policy = "allowlist"
mode = "personal"'

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
