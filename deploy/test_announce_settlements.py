#!/usr/bin/env python3
"""Controls for deploy/announce_settlements.sh -- proves what id it hands the binary.

WHY THIS EXISTS. `$ZC_CHANNEL` fed two different consumers that want two different strings:
the config lookup wants the INSTANCE (`whatsapp.shop`, the literal `[channels.whatsapp.shop]`
section header), and `--channel-id` wants an id the binary resolves. One of the two was always
wrong. Measured on the box 2026-08-16, on every tick since 2026-08-06:

    Error: Unknown channel 'whatsapp.shop'. Supported: telegram, discord, slack, ...
    announced 0 of 4; ledger NOT committed so the rest re-announce

Four genuine mainnet settlements had re-queued and none was ever announced. Nothing was lost,
because the send-first/commit-after discipline held, and that is also why it stayed invisible.

The box is not reachable from here, so every claim below is driven against a FIXTURE config and
a FAKE binary that records its own argv. What that buys is the thing a green suite usually does
not: the exact command the next box contact should expect, established before the contact.

FIVE LAYERS, because a control on one proves nothing about the others.

  1. RESOLUTION, through --dry-run: which instance, which type, which alias, which recipient,
     which channel-id, and whether a retry id exists at all.
  1b. RECIPIENT KIND -- which DOMAIN the resolved jid belongs to. The section scoping in 1
     proves the resolver stays out of a neighbouring alias; it says nothing about picking the
     wrong kind of address INSIDE the right one. Measured on the box 2026-08-16, the resolver
     took the section's `allowed_groups` placeholder and reported `recipient resolved: ...@g.us`.
     Every fixture in 1 carries exactly one jid and it is always a dm, so a resolver that takes
     the first jid of any domain passed all of them. A group jid must refuse, never send.
  2. SEND, end to end with a fake binary, asserting on the ACTUAL argv it received and on
     whether the ledger was committed.
  3. REFUSAL. The incident's own stderr, verbatim, must fail loud and commit nothing -- and
     must NOT broaden to a bare type that reaches a different account.
  4. MUTATION CONTROLS. The retry gate, the once-only flag and the section anchor are each
     disabled in a
     copy of the script and the matching case is REQUIRED to flip. Each asserts its target
     string is present in the source FIRST, so a control gone stale fails loudly instead of
     certifying an unmodified script.

  5. WHAT IT HANDS THE CONFIRMER. Two things the argv on that side has to get right: the
     scan cache flags, and the --only narrowing on the commit. The narrowing is the one
     that matters -- an unnarrowed commit re-derives from chain and appends everything it
     finds, so a payment settling during the sends is recorded having never been sent, and
     is then never announced. The RPC-cost half of the cache claim is not provable here,
     because the confirmer is faked; it is proved in demo/test_confirm_settlements.py
     against the real code with a counting RPC.

No network, no python3 dependency in the child: the "python3" the script invokes is a shim in
the test's own PATH that runs the fake confirmer.

    python3 deploy/test_announce_settlements.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "announce_settlements.sh"

# The reserved synthetic JID for fixtures in this repo. It has to be this exact value: the
# identifier gate allows it by exact match and flags any realistic-looking phone JID, rightly.
# The decoy is a GROUP jid, which the same recipient pattern matches and which the identifier
# gate clears by domain: a room id is not a phone number. A second synthetic phone JID would be
# flagged, correctly, because only the all-zero one is reserved.
FIXTURE_JID = "00000000000@s.whatsapp.net"
DECOY_JID = "000000000000000000@g.us"

# The box's own error, verbatim from the journal on 2026-08-16. Kept byte-faithful: a paraphrase
# here cannot tell you that a change still handles the real thing.
BOX_UNKNOWN_CHANNEL = (
    "Error: Unknown channel 'whatsapp.shop'. Supported: telegram, discord, slack, "
    "mattermost, signal, matrix, whatsapp, qq, lark, feishu, dingtalk, wecom, wecom_ws, "
    "nextcloud_talk, wati, linq, email, gmail_push, git, irc, twitter, mochat, imessage, "
    "line, voice-call"
)

SEND_LINE_A = (
    "SEND: payment received: 0.39 USDC from EpzuUPXwMR2oWqL3MCUTjvvpfdrZXforkMt85ZCSowo3 "
    "at 2026-08-06T23:01:43Z (signature "
    "4WG7HYF6As2AeDnJzQjuwEjEYXQK9WQKzqipqafZAirJf164Y8MEmJUsVGCkhk5bRTG5KpnixHFVAcfBkAKkuMsD)"
)
SEND_LINE_B = (
    "SEND: payment received: 1.5 USDC from EpzuUPXwMR2oWqL3MCUTjvvpfdrZXforkMt85ZCSowo3 "
    "at 2026-08-07T09:12:04Z (signature "
    "4VUbLWcE2dPPYAXQVtH2WhvgP33KrbUiX2ruA9PeyfKMU4k5iPgFSL3xkg8wLtjk8GumPYdyNR92haxgEasDstUh)"
)

SEND_LINE_C = (
    "SEND: payment received: 12 USDC from EpzuUPXwMR2oWqL3MCUTjvvpfdrZXforkMt85ZCSowo3 "
    "at 2026-08-07T15:44:20Z (signature "
    "5Zk9RPAffYmo9zzgXZuGrHJ8bV9Y2rnbE3ZdsPiMqzjEDWVQN2dWieiPu1VpGUMX2d4SNBt4Quqs9ewHdk3eAvbm)"
)

# A SEND line with no `(signature ...)` field. Not a shape the real confirmer emits, which
# is the point: it stands for the confirmer's format drifting away from the script's parse.
# The script must refuse to commit rather than fall back to an unnarrowed pass.
SEND_LINE_NOSIG = "SEND: payment received: 0.39 USDC from EpzuUPXwMR2oWqL3MCUTjvvpfdrZXforkMt85ZCSowo3"

# A line unique to the remedy block, used to COUNT it. Kept as a fragment of the real sentence
# rather than a paraphrase, so rewording the remedy breaks the count rather than silently
# measuring nothing.
REMEDY_MARKER = "does not accept"
RETRY_MARKER = "will retry next run"

CHECKS = 0
FAILS = 0


def check(label: str, ok: bool, detail: object = "") -> None:
    global CHECKS, FAILS
    CHECKS += 1
    if ok:
        print(f"  PASS  {label}")
    else:
        FAILS += 1
        print(f"  FAIL  {label}")
        if detail:
            print(f"        {detail}")


# A config whose SHOP section is preceded by a decoy alias carrying a different JID. The
# section lookup has to land on the right one; a loose pattern takes the decoy and the receipt
# goes to a stranger.
CONFIG_SHOP = f"""\
[channels.whatsapp.other]
allowed_groups = ["{DECOY_JID}"]

[channels.whatsapp.shop]
mode = "personal"
session_path = "/tmp/wa"
allowed_peers = ["{FIXTURE_JID}"]

[channels.telegram.shop]
enabled = true
"""

CONFIG_DEFAULT_ALIAS = f"""\
[channels.whatsapp.default]
mode = "personal"
allowed_peers = ["{FIXTURE_JID}"]
"""

CONFIG_NO_PEER = """\
[channels.whatsapp.shop]
mode = "personal"
"""

# THE LIVE BOX SHAPE, and the defect. Byte-faithful to the "live node posture" case in
# scripts/test_whatsapp_posture_guard.sh: personal mode, group_policy ignore, and a single
# non-matching `allowed_groups` placeholder that whatsapp_posture_guard.sh REQUIRES to be
# present and non-empty. There is no direct-chat jid in the section at all -- the dm allowlist
# lives in `peer_groups.<name>.external_peers`, another table -- so the only jid here is the
# group placeholder. A resolver that takes the first jid of any domain resolves a GROUP, and
# measured on the box it did exactly that.
CONFIG_GROUP_ONLY = f"""\
[channels.whatsapp.shop]
mode = "personal"
dm_policy = "allowlist"
group_policy = "ignore"
allowed_groups = ["{DECOY_JID}"]
"""

# Both domains present, GROUP FIRST. Written in this order deliberately: with the group last,
# a resolver that simply takes the last match would pass for the wrong reason.
CONFIG_GROUP_BEFORE_DM = f"""\
[channels.whatsapp.shop]
mode = "personal"
group_policy = "ignore"
allowed_groups = ["{DECOY_JID}"]
allowed_peers = ["{FIXTURE_JID}"]
"""

# The same two, DM first. The pair is what proves order is not the discriminator.
CONFIG_DM_BEFORE_GROUP = f"""\
[channels.whatsapp.shop]
mode = "personal"
allowed_peers = ["{FIXTURE_JID}"]
group_policy = "ignore"
allowed_groups = ["{DECOY_JID}"]
"""

# The shop section is group-only and the reserved DM sits in a NEIGHBOURING alias. Unmutated
# this must refuse: there is no direct-chat jid in the right section. It is the fixture for the
# section-anchor mutation below -- see the comment there for why the anchor control needs a
# fixture of this shape rather than the plain decoy one.
CONFIG_GROUP_ONLY_NEIGHBOUR_DM = f"""\
[channels.whatsapp.other]
allowed_peers = ["{FIXTURE_JID}"]

[channels.whatsapp.shop]
mode = "personal"
group_policy = "ignore"
allowed_groups = ["{DECOY_JID}"]
"""

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

FAKE_ACCEPT = """\
#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$ZCLOG"
echo "Message sent."
exit 0
"""

# An OLD host: the channel builder is the only resolver, so any dotted id is unknown and the
# failure happens while BUILDING, before any delivery.
FAKE_OLD_HOST = """\
#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$ZCLOG"
id=""
while [ $# -gt 0 ]; do
  case "$1" in
    --channel-id) id="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "$id" in
  *.*) echo "Error: Unknown channel '$id'. Supported: telegram, discord, slack, mattermost, \
signal, matrix, whatsapp, qq, lark, feishu, dingtalk, wecom, wecom_ws, nextcloud_talk, wati, \
linq, email, gmail_push, git, irc, twitter, mochat, imessage, line, voice-call" >&2
       exit 1 ;;
esac
echo "Message sent."
exit 0
"""

# A DELIVERY failure. Shaped nothing like an unknown id, because it is not one: the channel was
# built and the send attempt may have partially landed. Retrying this is how a receipt doubles.
FAKE_DELIVERY_FAIL = """\
#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$ZCLOG"
echo "Error: Failed to send message via whatsapp.shop: connection reset by peer" >&2
exit 1
"""

# The first send lands, the second does not. Proves the ledger stays uncommitted on a partial.
FAKE_SECOND_FAILS = """\
#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$ZCLOG"
n=$(wc -l < "$ZCLOG")
if [ "$n" -ge 2 ]; then
  echo "Error: Failed to send message via whatsapp.shop: connection reset by peer" >&2
  exit 1
fi
exit 0
"""

FAKE_CONFIRMER = """\
#!/usr/bin/env bash
dry=0
for a in "$@"; do [ "$a" = "--dry-run" ] && dry=1; done
if [ "$dry" -eq 1 ]; then
  printf '%s\\n' "$*" >> "$SCANLOG"
  printf '%s\\n' "$SEND_LINES"
  exit 0
fi
printf '%s\\n' "$*" >> "$COMMITLOG"
exit 0
"""

# A confirmer of the PREVIOUS deployed vintage: it scans fine and rejects --only the way
# argparse does. This is the split-deploy shape -- the script synced, its confirmer did not --
# and it is the same class of failure as the incident this whole path was written for, where a
# component's deployed vintage did not match what called it.
FAKE_CONFIRMER_NO_ONLY = """\
#!/usr/bin/env bash
dry=0
for a in "$@"; do [ "$a" = "--dry-run" ] && dry=1; done
if [ "$dry" -eq 1 ]; then
  printf '%s\\n' "$*" >> "$SCANLOG"
  printf '%s\\n' "$SEND_LINES"
  exit 0
fi
for a in "$@"; do
  if [ "$a" = "--only" ]; then
    echo "error: unrecognized arguments: --only" >&2
    exit 2
  fi
done
printf '%s\\n' "$*" >> "$COMMITLOG"
exit 0
"""

# The shim standing in for python3: the script invokes `python3 <confirmer> ...`, and the
# confirmer here is a bash script, so this runs it with bash.
PY_SHIM = """\
#!/usr/bin/env bash
script="$1"; shift
exec bash "$script" "$@"
"""


def bash() -> str | None:
    found = shutil.which("bash")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\Git\bin\bash.exe",
        "/bin/bash",
        "/usr/bin/bash",
    ):
        if Path(candidate).exists():
            return candidate
    return None


BASH = bash()


class Box:
    """A throwaway fixture box: fake binary, fake confirmer, fixture config."""

    def __init__(
        self,
        config: str,
        fake: str,
        send_lines: list[str],
        script: Path = SCRIPT,
        confirmer: str | None = None,
    ):
        self.dir = Path(tempfile.mkdtemp(prefix="announce-test-"))
        self.script = script
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.zclog = self.dir / "zc-argv.log"
        self.commitlog = self.dir / "committed.log"
        self.scanlog = self.dir / "scanned.log"
        self.config = self.dir / "config.toml"
        self.config.write_text(config, encoding="utf-8")
        self.zbin = self.dir / "zeroclaw"
        self._write_exec(self.zbin, fake)
        self.confirmer = self.dir / "tools" / "confirm_settlements.py"
        self.confirmer.parent.mkdir()
        self._write_exec(self.confirmer, confirmer or FAKE_CONFIRMER)
        self._write_exec(self.bin / "python3", PY_SHIM)
        self.send_lines = "\n".join(send_lines)

    @staticmethod
    def _write_exec(path: Path, body: str) -> None:
        path.write_text(body, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def run(self, *args: str, **overrides: str) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PATH"] = str(self.bin) + os.pathsep + env.get("PATH", "")
        env.update(
            {
                "ZC_BIN": str(self.zbin),
                "ZC_CONFIG": str(self.config),
                "ZC_TOOLS": str(self.confirmer.parent),
                "ZC_LEDGER": str(self.dir / "ledger.jsonl"),
                "ZC_CHANNEL": "whatsapp.shop",
                "ZCLOG": str(self.zclog),
                "COMMITLOG": str(self.commitlog),
                "SCANLOG": str(self.scanlog),
                "SEND_LINES": self.send_lines,
            }
        )
        env.pop("ZC_RECIPIENT", None)
        env.pop("ZC_CHANNEL_ID", None)
        env.pop("ZC_SCAN_CACHE", None)
        for key, value in overrides.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        return subprocess.run(
            [BASH, str(self.script), *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )

    def sends(self) -> list[str]:
        if not self.zclog.exists():
            return []
        return [
            ln
            for ln in self.zclog.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]

    def committed(self) -> bool:
        return self.commitlog.exists()

    def _argv(self, log: Path) -> str:
        """The argv of the last confirmer invocation of that kind, or ''."""
        if not log.exists():
            return ""
        lines = [
            ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()
        ]
        return lines[-1] if lines else ""

    def commit_args(self) -> str:
        return self._argv(self.commitlog)

    def scan_args(self) -> str:
        return self._argv(self.scanlog)

    def cleanup(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def mutated_script(anchor: str, replacement: str) -> Path:
    """A copy of the script with one line replaced, asserting the anchor was really there."""
    src = SCRIPT.read_text(encoding="utf-8")
    if anchor not in src:
        raise AssertionError(
            f"mutation anchor is stale, not found in source: {anchor!r}"
        )
    path = Path(tempfile.mkdtemp(prefix="announce-mutant-")) / "announce_settlements.sh"
    path.write_text(src.replace(anchor, replacement, 1), encoding="utf-8", newline="\n")
    path.chmod(0o755)
    # A mutant that does not PARSE tests nothing while looking like a result. Which way it lies
    # depends on the case: a must-fire check reads the crash as "did not fire" and goes red,
    # which is loud, but a must-not-fire check reads the very same crash as the silence it
    # wanted and goes GREEN. Asserting the anchor was present cannot catch this -- the
    # substitution applies and the file is then broken, most often on indentation or a quote.
    # So every mutant is parsed here, once, before any case can be built on it.
    syntax = subprocess.run(
        [BASH, "-n", str(path)], capture_output=True, text=True, timeout=60
    )
    if syntax.returncode != 0:
        raise AssertionError(
            f"mutant does not parse, so it would test nothing: {syntax.stderr.strip()}"
        )
    return path


# ---------------------------------------------------------------------------
# 1. RESOLUTION
# ---------------------------------------------------------------------------


def test_resolution() -> None:
    print(
        "\n1. RESOLUTION -- the two values are separated and each gets the right string"
    )
    box = Box(CONFIG_SHOP, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        r = box.run("--dry-run")
        out = r.stdout
        check("dry run exits 0", r.returncode == 0, r.stderr)
        check("instance is the config section", "ZC_CHANNEL=whatsapp.shop" in out, out)
        check("type is derived as whatsapp", "type        whatsapp" in out, out)
        check("alias is derived as shop", "alias       shop" in out, out)
        check(
            "recipient comes from the SHOP section",
            f"recipient   {FIXTURE_JID}" in out,
            out,
        )
        check(
            "the decoy alias's JID is NOT taken",
            DECOY_JID not in out,
            out,
        )
        check(
            "channel-id is the instance, tried first",
            "channel-id    whatsapp.shop" in out,
            out,
        )
        check(
            "alias 'shop' has NO bare-type retry",
            "retry-as    none" in out,
            out,
        )
        check("dry run sent nothing", box.sends() == [], box.sends())
        check("dry run committed nothing", not box.committed())
        check(
            "dry run prints the exact command the box will run",
            "would run:" in out
            and "channel send --channel-id whatsapp.shop --recipient" in out,
            out,
        )
    finally:
        box.cleanup()

    box = Box(CONFIG_DEFAULT_ALIAS, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        r = box.run("--dry-run", ZC_CHANNEL="whatsapp.default")
        check(
            "alias 'default' DOES get a bare-type retry",
            "retry-as    whatsapp" in r.stdout,
            r.stdout,
        )
    finally:
        box.cleanup()

    box = Box(CONFIG_SHOP, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        r = box.run("--dry-run", ZC_CHANNEL="whatsapp")
        check("a ZC_CHANNEL with no alias exits 2", r.returncode == 2, r.stderr)
        check(
            "and says what shape it wanted",
            "<type>.<alias>" in r.stderr,
            r.stderr,
        )
    finally:
        box.cleanup()

    box = Box(CONFIG_NO_PEER, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        r = box.run("--dry-run")
        check("an unresolvable recipient exits 2, never 0", r.returncode == 2, r.stderr)
        check(
            "and names the section it looked in",
            "[channels.whatsapp.shop]" in r.stderr,
            r.stderr,
        )
    finally:
        box.cleanup()


# ---------------------------------------------------------------------------
# 1b. RECIPIENT KIND -- a group jid is not a recipient
# ---------------------------------------------------------------------------


def test_recipient_kind() -> None:
    print("\n1b. RECIPIENT KIND -- a group jid refuses; a dm wins at any position")

    # THE DEFECT, at the live box's own config shape. Not a dry run: the whole point is that
    # the real send path must never reach the binary with a group as its --recipient.
    box = Box(CONFIG_GROUP_ONLY, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        r = box.run()
        check("a group-only section exits 2, never 0", r.returncode == 2, r.stdout)
        check("and sends NOTHING", box.sends() == [], box.sends())
        check("and commits nothing", not box.committed())
        check(
            "the group jid is never handed to the binary as a recipient",
            all(DECOY_JID not in s for s in box.sends()),
            box.sends(),
        )
        check(
            "the message says the section carries a GROUP jid",
            "GROUP jid" in r.stderr,
            r.stderr,
        )
        check(
            "and names ZC_RECIPIENT as the remedy",
            "ZC_RECIPIENT" in r.stderr,
            r.stderr,
        )
        check(
            "and names the section it looked in",
            "[channels.whatsapp.shop]" in r.stderr,
            r.stderr,
        )
        # The refusal must not ECHO the jid it rejected. box_selfcheck.py's redactor states as
        # an invariant that this script carries no jid, and printing the rejected value directly
        # above "set ZC_RECIPIENT" would hand an operator the wrong string to paste -- into the
        # one override that is deliberately not domain-checked. Two reasons, same direction.
        check(
            "the refusal does not echo the rejected jid anywhere in its output",
            DECOY_JID not in r.stderr and DECOY_JID not in r.stdout,
            r.stderr + r.stdout,
        )
    finally:
        box.cleanup()

    # ORDER IS NOT THE DISCRIMINATOR. The group is written FIRST here on purpose: with it last,
    # a resolver that took the last match would pass this and still be wrong.
    box = Box(CONFIG_GROUP_BEFORE_DM, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        r = box.run("--dry-run")
        check("group-first: exits 0", r.returncode == 0, r.stderr)
        check(
            "group-first: the DM wins",
            f"recipient   {FIXTURE_JID}" in r.stdout,
            r.stdout,
        )
        check(
            "group-first: the group is not taken", DECOY_JID not in r.stdout, r.stdout
        )
    finally:
        box.cleanup()

    box = Box(CONFIG_DM_BEFORE_GROUP, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        r = box.run("--dry-run")
        check("dm-first: exits 0", r.returncode == 0, r.stderr)
        check(
            "dm-first: the DM wins",
            f"recipient   {FIXTURE_JID}" in r.stdout,
            r.stdout,
        )
        check("dm-first: the group is not taken", DECOY_JID not in r.stdout, r.stdout)
    finally:
        box.cleanup()

    # An explicit ZC_RECIPIENT is the documented way out of the refusal, so it has to actually
    # work from the shape that refuses -- an escape hatch nobody tested is not one.
    box = Box(CONFIG_GROUP_ONLY, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        r = box.run(ZC_RECIPIENT=FIXTURE_JID)
        check("ZC_RECIPIENT clears the refusal", r.returncode == 0, r.stderr)
        check(
            "and is the recipient actually sent to",
            len(box.sends()) == 1 and f"--recipient {FIXTURE_JID}" in box.sends()[0],
            box.sends(),
        )
    finally:
        box.cleanup()


# ---------------------------------------------------------------------------
# 2. SEND
# ---------------------------------------------------------------------------


def test_send() -> None:
    print("\n2. SEND -- the argv the binary actually receives")
    box = Box(CONFIG_SHOP, FAKE_ACCEPT, [SEND_LINE_A, SEND_LINE_B])
    try:
        r = box.run()
        check("exits 0 when every send lands", r.returncode == 0, r.stderr)
        check("one invocation per pending payment", len(box.sends()) == 2, box.sends())
        check(
            "channel send carries --channel-id whatsapp.shop",
            all("--channel-id whatsapp.shop" in s for s in box.sends()),
            box.sends(),
        )
        check(
            "and --recipient from the shop allowlist",
            all(f"--recipient {FIXTURE_JID}" in s for s in box.sends()),
            box.sends(),
        )
        check(
            "the message is the confirmer's line with SEND: stripped",
            "payment received: 0.39 USDC" in box.sends()[0]
            and "SEND: payment" not in box.sends()[0],
            box.sends()[0],
        )
        check("the ledger is committed", box.committed())
    finally:
        box.cleanup()

    box = Box(CONFIG_SHOP, FAKE_SECOND_FAILS, [SEND_LINE_A, SEND_LINE_B])
    try:
        r = box.run()
        check("a partial run exits 1", r.returncode == 1, r.stdout)
        check("a partial run does NOT commit the ledger", not box.committed())
        check(
            "and says the rest re-announce",
            "ledger NOT committed" in r.stderr,
            r.stderr,
        )
    finally:
        box.cleanup()


# ---------------------------------------------------------------------------
# 3. REFUSAL -- the incident, and the boundary of the retry
# ---------------------------------------------------------------------------


def test_refusal() -> None:
    print("\n3. REFUSAL -- the box's own failure, and what must NOT be broadened")

    # THE INCIDENT. An old host, alias 'shop'. The dotted id is refused, the bare type would
    # reach `[channels.whatsapp.default]` which is a DIFFERENT account, so nothing is sent.
    box = Box(CONFIG_SHOP, FAKE_OLD_HOST, [SEND_LINE_A])
    try:
        r = box.run()
        check("an old host fails loud rather than 0", r.returncode == 1, r.stdout)
        check("nothing is committed", not box.committed())
        check(
            "exactly ONE invocation: no bare-type broadening for alias 'shop'",
            len(box.sends()) == 1,
            box.sends(),
        )
        check(
            "the one invocation used the instance id",
            "--channel-id whatsapp.shop" in box.sends()[0],
            box.sends(),
        )
        check(
            "the host's own error is surfaced, not swallowed",
            "Unknown channel 'whatsapp.shop'" in r.stderr,
            r.stderr,
        )
        check(
            "the diagnosis names the upgrade remedy",
            "resolves <type>.<alias>" in r.stderr,
            r.stderr,
        )
        check(
            "the diagnosis names the ZC_CHANNEL_ID remedy",
            "ZC_CHANNEL_ID" in r.stderr,
            r.stderr,
        )
        check(
            "and says the receipts re-announce",
            "re-announce" in r.stderr,
            r.stderr,
        )
    finally:
        box.cleanup()

    # THE INCIDENT AT ITS REAL WIDTH. Four settlements were stuck, not one, and every refusal
    # case above uses a single message, so multi-message refusal went unexercised and a remedy
    # block emitted once PER MESSAGE read as correct. The run-level diagnosis must appear once
    # while the per-payment record must appear once per payment: the first says why the run
    # failed, the second says which money is still owed, and collapsing either loses something.
    box = Box(CONFIG_SHOP, FAKE_OLD_HOST, [SEND_LINE_A, SEND_LINE_B, SEND_LINE_C])
    try:
        r = box.run()
        remedies = r.stderr.count(REMEDY_MARKER)
        host_errors = r.stderr.count("Unknown channel 'whatsapp.shop'")
        retries = r.stderr.count(RETRY_MARKER)
        check("three pending, still exits 1", r.returncode == 1, r.stdout)
        check("three pending, still commits nothing", not box.committed())
        check(
            "one invocation per payment, none broadened",
            len(box.sends()) == 3
            and all("--channel-id whatsapp.shop" in s for s in box.sends()),
            box.sends(),
        )
        check(
            f"the remedy block appears EXACTLY ONCE across 3 messages (got {remedies})",
            remedies == 1,
            r.stderr,
        )
        check(
            f"the host's error is quoted once, not per message (got {host_errors})",
            host_errors == 1,
            r.stderr,
        )
        check(
            f"the per-payment retry line appears ONCE PER MESSAGE (got {retries} of 3)",
            retries == 3,
            r.stderr,
        )
        check(
            "and each payment is named in its own retry line",
            all(
                f"{RETRY_MARKER}: {line[len('SEND: ') :]}" in r.stderr
                for line in (SEND_LINE_A, SEND_LINE_B, SEND_LINE_C)
            ),
            r.stderr,
        )
    finally:
        box.cleanup()

    # OVER-CORRECTION CONTROL. The same old host with alias 'default': the bare type IS the same
    # destination there, so the retry must fire and the run must succeed.
    box = Box(CONFIG_DEFAULT_ALIAS, FAKE_OLD_HOST, [SEND_LINE_A])
    try:
        r = box.run(ZC_CHANNEL="whatsapp.default")
        check("alias 'default' on an old host succeeds", r.returncode == 0, r.stderr)
        check("it took two invocations", len(box.sends()) == 2, box.sends())
        check(
            "the retry used the bare type",
            "--channel-id whatsapp " in box.sends()[1] + " ",
            box.sends(),
        )
        check("the ledger is committed", box.committed())
    finally:
        box.cleanup()

    # A DELIVERY failure is NOT retried. This is the control that keeps the retry from becoming
    # a general retry, which would double-send a receipt the customer already got.
    box = Box(CONFIG_DEFAULT_ALIAS, FAKE_DELIVERY_FAIL, [SEND_LINE_A])
    try:
        r = box.run(ZC_CHANNEL="whatsapp.default")
        check("a delivery failure exits 1", r.returncode == 1, r.stdout)
        check(
            "a delivery failure is sent ONCE, never retried",
            len(box.sends()) == 1,
            box.sends(),
        )
        check("and commits nothing", not box.committed())
    finally:
        box.cleanup()

    # An explicit id is honoured and gets no retry behind the operator's back.
    box = Box(CONFIG_SHOP, FAKE_OLD_HOST, [SEND_LINE_A])
    try:
        r = box.run(ZC_CHANNEL_ID="whatsapp")
        check("ZC_CHANNEL_ID overrides the derived id", r.returncode == 0, r.stderr)
        check(
            "and is the id actually sent",
            len(box.sends()) == 1 and "--channel-id whatsapp " in box.sends()[0] + " ",
            box.sends(),
        )
        check(
            "while the recipient still comes from the shop section",
            f"--recipient {FIXTURE_JID}" in box.sends()[0],
            box.sends(),
        )
    finally:
        box.cleanup()


# ---------------------------------------------------------------------------
# 4. MUTATION CONTROLS
# ---------------------------------------------------------------------------


def test_mutations() -> None:
    print("\n4. MUTATION CONTROLS -- each guard is load-bearing")

    # Disable the Unknown-channel gate so ANY failure retries. The delivery-failure case must
    # then double-send, which is exactly the harm the gate prevents.
    mutant = mutated_script(
        """    *"Unknown channel '$CHANNEL_ID'"*) ;;""",
        """    *) ;;""",
    )
    box = Box(CONFIG_DEFAULT_ALIAS, FAKE_DELIVERY_FAIL, [SEND_LINE_A], script=mutant)
    try:
        box.run(ZC_CHANNEL="whatsapp.default")
        check(
            "removing the Unknown-channel gate DOES double-send (gate is real)",
            len(box.sends()) == 2,
            box.sends(),
        )
    finally:
        box.cleanup()
        shutil.rmtree(mutant.parent, ignore_errors=True)

    # Disable the alias=default condition so any alias retries as a bare type. The incident case
    # must then broaden to `whatsapp`, which is the wrong-account send this refuses to make.
    mutant = mutated_script(
        """  if [ "$CHANNEL_ALIAS" = "default" ]; then""",
        """  if true; then""",
    )
    box = Box(CONFIG_SHOP, FAKE_OLD_HOST, [SEND_LINE_A], script=mutant)
    try:
        box.run()
        sends = box.sends()
        check(
            "removing the alias gate DOES broaden to the bare type (gate is real)",
            len(sends) == 2 and "--channel-id whatsapp " in sends[1] + " ",
            sends,
        )
    finally:
        box.cleanup()
        shutil.rmtree(mutant.parent, ignore_errors=True)

    # Disable the once-only flag so the remedy is emitted per message again. Three pending
    # messages must then produce three remedy blocks. This is the control for the drift the
    # review caught: the comment claimed once while the code emitted per message, and every
    # refusal case used a single message, so nothing could tell the two apart.
    mutant = mutated_script(
        """  [ "$UNSUPPORTED_TOLD" -eq 0 ] || return 0""",
        """  : """,
    )
    box = Box(
        CONFIG_SHOP,
        FAKE_OLD_HOST,
        [SEND_LINE_A, SEND_LINE_B, SEND_LINE_C],
        script=mutant,
    )
    try:
        r = box.run()
        remedies = r.stderr.count(REMEDY_MARKER)
        check(
            f"removing the once-only flag DOES repeat the remedy (got {remedies} of 3)",
            remedies == 3,
            r.stderr,
        )
        check(
            "while the per-payment line was already once per message",
            r.stderr.count(RETRY_MARKER) == 3,
            r.stderr,
        )
    finally:
        box.cleanup()
        shutil.rmtree(mutant.parent, ignore_errors=True)

    # Loosen the section pattern back to unescaped dots AND drop the anchor, so a neighbouring
    # alias can be matched. The anchor is still exactly the guard under test and the decision it
    # pins is unchanged; only the FIXTURE moved, and it had to.
    #
    # This control used to run against CONFIG_SHOP and assert the decoy GROUP jid was taken.
    # Once the resolver started preferring the direct-chat domain, that observable stopped being
    # produced -- the loosened range still reaches the neighbour, but the shop's own dm outranks
    # the neighbour's group, so the control would have gone green on a mutant while proving
    # nothing. Two guards masking each other, not a reversed decision. CONFIG_GROUP_ONLY_NEIGHBOUR_DM
    # removes the confound by putting the only dm in the NEIGHBOUR: the domain preference cannot
    # rescue the section anchor there, so the flip is attributable to the anchor alone.
    mutant = mutated_script(
        """/^\\[channels\\.${SECTION_RE}\\]/,/^\\[/p""",
        """/channels/,/^\\[zzz/p""",
    )
    box = Box(CONFIG_GROUP_ONLY_NEIGHBOUR_DM, FAKE_ACCEPT, [SEND_LINE_A], script=SCRIPT)
    try:
        r = box.run("--dry-run")
        check(
            "anchored, a neighbour's dm is out of reach so the run refuses",
            r.returncode == 2,
            r.stdout + r.stderr,
        )
    finally:
        box.cleanup()

    box = Box(CONFIG_GROUP_ONLY_NEIGHBOUR_DM, FAKE_ACCEPT, [SEND_LINE_A], script=mutant)
    try:
        r = box.run("--dry-run")
        check(
            "loosening the section pattern DOES reach the neighbour's dm (anchor is real)",
            r.returncode == 0 and f"recipient   {FIXTURE_JID}" in r.stdout,
            r.stdout + r.stderr,
        )
    finally:
        box.cleanup()
        shutil.rmtree(mutant.parent, ignore_errors=True)

    # THE DOMAIN PREFERENCE ITSELF. Restore the old any-domain match and the live box's own
    # config shape must resolve a GROUP again -- the defect, reproduced on demand. Without this
    # the preference is a line of code nothing proves is load-bearing.
    # The anchor is the match EXPRESSION rather than the whole assignment: it is the code path
    # under test, it is unique in the source, and it carries no leading whitespace, so the
    # substitution cannot break indentation the way a whole-line anchor can.
    mutant = mutated_script(
        r"""grep -oE '[0-9]+@s\.whatsapp\.net'""",
        r"""grep -oE '[0-9]+@(g\.us|s\.whatsapp\.net)'""",
    )
    box = Box(CONFIG_GROUP_ONLY, FAKE_ACCEPT, [SEND_LINE_A], script=mutant)
    try:
        r = box.run()
        check(
            "removing the dm-domain match DOES send the receipt to a group (preference is real)",
            len(box.sends()) == 1 and f"--recipient {DECOY_JID}" in box.sends()[0],
            (r.returncode, box.sends(), r.stderr),
        )
    finally:
        box.cleanup()
        shutil.rmtree(mutant.parent, ignore_errors=True)


# ---------------------------------------------------------------------------
# 5. WHAT IT HANDS THE CONFIRMER -- cache flags, and the commit narrowing
# ---------------------------------------------------------------------------


def sig_of(send_line: str) -> str:
    return send_line.rsplit("(signature ", 1)[1].rstrip(")")


def test_confirmer_argv() -> None:
    print("\n5. CONFIRMER ARGV -- scan cache flags and the --only commit narrowing")

    # THE NARROWING. Both settlements land, so the commit runs -- and it must name exactly
    # the two signatures that were announced. An unnarrowed commit re-derives the window and
    # appends whatever settled during the sends, which is a receipt nobody was ever sent.
    box = Box(CONFIG_SHOP, FAKE_ACCEPT, [SEND_LINE_A, SEND_LINE_B])
    try:
        r = box.run()
        args = box.commit_args()
        check("both sends land, so the run exits 0", r.returncode == 0, r.stderr)
        check(
            "the commit names --only once per announced payment",
            args.count("--only") == 2,
            args,
        )
        check(
            "and names the exact signatures from the SEND lines",
            all(
                f"--only {sig_of(line)}" in args for line in (SEND_LINE_A, SEND_LINE_B)
            ),
            args,
        )
        check(
            "the commit still targets the same ledger",
            "--ledger" in args,
            args,
        )
    finally:
        box.cleanup()

    # A run that announced NOTHING never reaches the commit, so there is nothing to narrow.
    box = Box(CONFIG_SHOP, FAKE_OLD_HOST, [SEND_LINE_A])
    try:
        box.run()
        check("a failed run commits nothing at all", not box.committed())
    finally:
        box.cleanup()

    # A SEND line the script cannot parse a signature out of must not be committed blind.
    # Committing unnarrowed there would restore the swallow on exactly the run where the
    # script has already shown it does not understand its own input.
    box = Box(CONFIG_SHOP, FAKE_ACCEPT, [SEND_LINE_A, SEND_LINE_NOSIG])
    try:
        r = box.run()
        check("an unparseable SEND line refuses to commit", r.returncode == 1, r.stdout)
        check("and writes no ledger record", not box.committed())
        check(
            "and says why, naming the mismatch",
            "refusing to commit" in r.stderr
            and "parsed 1 signature(s) from 2" in r.stderr,
            r.stderr,
        )
        check(
            "while both messages were still DELIVERED (the send half is unaffected)",
            len(box.sends()) == 2,
            box.sends(),
        )
    finally:
        box.cleanup()

    # SPLIT DEPLOY. An older confirmer rejects --only. The run must name that specifically
    # rather than dying on `set -e` with no explanation, and must not commit -- so the
    # receipts re-announce, which is the recoverable direction.
    box = Box(
        CONFIG_SHOP,
        FAKE_ACCEPT,
        [SEND_LINE_A],
        confirmer=FAKE_CONFIRMER_NO_ONLY,
    )
    try:
        r = box.run()
        check(
            "a confirmer that rejects --only fails the run", r.returncode == 1, r.stdout
        )
        check("and commits nothing", not box.committed())
        check(
            "and never claims the ledger was committed",
            "ledger committed" not in r.stdout,
            r.stdout,
        )
        check(
            "and names the deploy pair as the remedy",
            "unrecognized --only" in r.stderr and "deploy-targets.json" in r.stderr,
            r.stderr,
        )
    finally:
        box.cleanup()

    # THE CACHE FLAGS. Unset means the confirmer's own default path applies, which is the
    # deployed posture -- the script must not invent a --cache of its own.
    box = Box(CONFIG_SHOP, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        box.run()
        check(
            "with ZC_SCAN_CACHE unset the scan passes no cache flag",
            "--cache" not in box.scan_args() and "--no-cache" not in box.scan_args(),
            box.scan_args(),
        )
    finally:
        box.cleanup()

    box = Box(CONFIG_SHOP, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        box.run(ZC_SCAN_CACHE="/tmp/zc-scan-cache.json")
        check(
            "a set ZC_SCAN_CACHE becomes --cache <path>",
            "--cache /tmp/zc-scan-cache.json" in box.scan_args(),
            box.scan_args(),
        )
    finally:
        box.cleanup()

    box = Box(CONFIG_SHOP, FAKE_ACCEPT, [SEND_LINE_A])
    try:
        box.run(ZC_SCAN_CACHE="")
        check(
            "an EMPTY ZC_SCAN_CACHE becomes --no-cache, not an empty --cache",
            "--no-cache" in box.scan_args() and "--cache " not in box.scan_args(),
            box.scan_args(),
        )
    finally:
        box.cleanup()

    # OVER-CORRECTION CONTROL for the narrowing. Removing --only must restore the
    # unnarrowed commit, or "the commit is narrowed" is a claim about a flag nobody reads.
    mutant = mutated_script(
        """  if ! python3 "$CONFIRM" --ledger "$LEDGER" "${ONLY[@]}" >/dev/null; then""",
        """  if ! python3 "$CONFIRM" --ledger "$LEDGER" >/dev/null; then""",
    )
    box = Box(CONFIG_SHOP, FAKE_ACCEPT, [SEND_LINE_A, SEND_LINE_B], script=mutant)
    try:
        box.run()
        check(
            "removing --only DOES restore the unnarrowed commit (the narrowing is real)",
            box.committed() and "--only" not in box.commit_args(),
            box.commit_args(),
        )
    finally:
        box.cleanup()
        shutil.rmtree(mutant.parent, ignore_errors=True)

    # And the count guard must be what refuses, not something incidental: disable it and
    # the unparseable case commits a narrowing that is missing a payment.
    mutant = mutated_script(
        """  if [ "${#ONLY[@]}" -ne $((COUNT * 2)) ]; then""",
        """  if false; then""",
    )
    box = Box(CONFIG_SHOP, FAKE_ACCEPT, [SEND_LINE_A, SEND_LINE_NOSIG], script=mutant)
    try:
        r = box.run()
        check(
            "removing the count guard DOES let a short narrowing commit (guard is real)",
            r.returncode == 0 and box.commit_args().count("--only") == 1,
            box.commit_args(),
        )
    finally:
        box.cleanup()
        shutil.rmtree(mutant.parent, ignore_errors=True)


def main() -> int:
    if BASH is None:
        print("FAIL  no bash on PATH; this suite drives a shell script and cannot run")
        return 1
    if not SCRIPT.exists():
        print(f"FAIL  {SCRIPT} is missing")
        return 1
    print(f"bash: {BASH}")
    test_resolution()
    test_recipient_kind()
    test_send()
    test_refusal()
    test_mutations()
    test_confirmer_argv()
    print(f"\n{CHECKS - FAILS}/{CHECKS} checks passed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
