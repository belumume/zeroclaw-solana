#!/usr/bin/env python3
"""Runs ON the box. Asserts the shop's invariants and publishes a verdict the world can fetch.

WHY THE DIRECTION IS INVERTED, because this is the design decision worth defending.

The obvious shape is a CI job that reaches into the box and inspects it. That shape is impractical
here, and the reasons are measured rather than assumed: port 22 is blocked network-wide from the
operator's location (control: `github.com:22` times out while `:443` opens in about a second), and
Compute Instance Run Command reports `desired-state: ENABLED` while being absent from the live
plugin list, so the agent never instantiated it.

NOT every inbound route is shut, and that distinction matters because the opposite claim sends a
reader away from the one that works. OCI Bastion plus Cloud Shell REACHES the node: Bastion runs,
it accepts the ed25519 key the node authorises (the RSA-only constraint belongs to Cloud Shell's
FIPS OpenSSH, not to Bastion), and sessions have been created and used through it. What that route
is not is CHEAP or unattended: it needs a browser, a session that expires, and a human-ish hop.

So the box checks ITSELF and pushes the verdict outward through the Cloudflare tunnel it already
runs for the x402 gate. Nothing needs to reach in, and a checker anywhere fetches one JSON
document over plain HTTPS.

THAT FETCHER DOES NOT EXIST YET. `deploy/make_invariants.py` writes the manifest this file
consumes, and this file computes a verdict, but nothing schedules the run and nothing retrieves
the result: `box_selfcheck` appears in zero of the six workflows and in no unit here. Until both
halves exist the inversion is a design that works when invoked by hand rather than a gate, and
describing it otherwise is the failure it was written to prevent.

That inversion is strictly better than the inbound design, not merely a workaround for a blocked
port: a verdict computed on the box can see the deployed bytes, the live memory and the running
services, which an external prober cannot see at all.

THE THREE TIERS, because they need genuinely different mechanisms and conflating them is what
produced tonight's drift.

  CODE AND SKILLS   must be byte-identical to a named commit. Compared by sha256 against the
                    manifest written at deploy time. A hand-edit is drift by definition.
  CONFIG            is SUPPOSED to differ, because the box holds real endpoints and real keys.
                    Diffing it produces noise that trains people to ignore the checker. Only the
                    network-bearing fields are asserted.
  STATE             cannot be synced at all. brain.db is supposed to diverge. What it must never
                    do is carry a funds-critical constant, so the assertion is a PROHIBITION on
                    content rather than a comparison against anything.

FAILS CLOSED, deliberately, and this is the one place that choice is not obvious. A missing
invariants file, an unreadable skill or an absent manifest all return NOT OK rather than being
skipped. A checker that cannot see its subject and reports green is worse than no checker, because
the green is then quoted as evidence. Every check that cannot run says so in its own detail line.

SELF-TEST. `--self-test` builds a synthetic tree where every invariant is violated and requires
each check to FAIL, then a clean tree and requires each to PASS. A checker never shown to fail has
not been shown to work, and this one exists precisely because three green checkers missed an
eleven-day skill drift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ZC = Path(os.environ.get("ZEROCLAW_HOME", str(Path.home() / ".zeroclaw")))

# Written by `deploy/make_invariants.py` from the repo, then copied here at deploy time. Absent
# means we cannot know what SHOULD be here, which is a failure rather than a skip -- and it was
# absent for this file's whole life until that generator existed, so every check below was
# unrunnable on the box whatever its logic said.
INVARIANTS = ZC / "SHOP-INVARIANTS.json"
DEPLOYED_SHA = ZC / "DEPLOYED_SHA"

VERDICT_DEFAULT = ZC / "state" / "box-selfcheck.json"

# A base58 Solana address, used to find any mint-shaped token in a file. Deliberately broad: the
# check is "is there an address here that is not the configured one", so over-matching is safe and
# under-matching is not.
B58 = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")

# How many mint-scan findings the detail line SAMPLES. The line is served publicly and read in a
# terminal, so it cannot carry an unbounded list. The cap is a sample size, never the count: the
# total is always reported alongside, because a bounded list without its total is unmeasurable and
# reads as complete.
MINT_FINDINGS_SHOWN = 8

# A line that FORBIDS a network necessarily names it, so the network-prose check has to tell a
# prohibition apart from an assertion to the customer. Deliberately a small, boring marker set:
# this is a semantic distinction and regex does those badly, so the honest posture is a narrow
# list plus a stated ceiling rather than a clever pattern.
#
# CEILING, so nobody reads a green as stronger than it is: a prohibition phrased with none of these
# markers still reads as an assertion and FALSE-POSITIVES, and an assertion that happens to carry
# one of them elsewhere in the same line FALSE-NEGATIVES. The strong instrument is the emitted
# message, not the template; this check is the cheap file-side backstop for the case where the
# value is right and the sentence under it is wrong.
PROHIBITION_RE = re.compile(
    r"\b(never|not|no longer|don'?t|do NOT|must not|cannot|can'?t|avoid|forbid\w*|"
    r"prohibit\w*|refus\w*|reject\w*|wrong|stale|incorrect|instead of|rather than|"
    r"no longer accurate|used to)\b",
    re.IGNORECASE,
)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_invariants() -> dict | None:
    try:
        return json.loads(INVARIANTS.read_text(encoding="utf-8"))
    except Exception:
        return None


class Result:
    def __init__(self) -> None:
        self.checks: list[dict] = []
        # Structured payload a check wants PUBLISHED alongside its verdict, keyed by name.
        # A detail line is one string read in a terminal; a unit's definition is a nested
        # document a reviewer greps. Carrying it here rather than stuffing it into `detail`
        # keeps `ok` computed from checks alone and keeps redaction in one place
        # (`build_verdict` walks this too, so nothing reaches disk unredacted).
        self.data: dict = {}

    def add(self, name: str, ok: bool, detail: str) -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})

    def attach(self, name: str, payload: object) -> None:
        self.data[name] = payload

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c["ok"] for c in self.checks)


def is_commit_sha(value: object) -> bool:
    """A full 40-character hex commit id, and nothing that merely resembles one.

    A LENGTH TEST IS NOT ENOUGH HERE, and the counterexample is already in this repo:
    `make_invariants.py` writes the literal string `"unknown"` into `repo_commit` when
    `git rev-parse HEAD` fails, and `"unknown"` is exactly seven characters. A `len >= 7` guard
    therefore accepts the one value that means "no commit at all" and republishes it as a
    corroborated vintage, which is the exact failure this whole check exists to remove, wearing
    a different disguise. Requiring 40 hex digits rejects it on both counts.
    """
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(c in "0123456789abcdef" for c in value.lower())
    )


def check_vintage_agreement(inv: dict, r: Result) -> None:
    """TWO RECORDS OF THE DEPLOY VINTAGE EXIST. Assert they still agree.

    `SHOP-INVARIANTS.json` carries `repo_commit`, written by `make_invariants.py` from
    `git rev-parse HEAD` in the SAME run that computed every hash in `files`. It is therefore
    the authoritative vintage by construction: it names the commit the manifest actually
    verifies against. `DEPLOYED_SHA` is a separate file that nothing in this repo writes, so it
    is maintained by hand at deploy time.

    A hand-maintained label beside a generated one drifts, and this one did. On 2026-08-16 the
    box served `deployed_sha` from 2026-08-06 while the files it was running had been deployed
    on 2026-08-15: the manifest was green, correctly, because the hashes had been regenerated,
    and the published label was nine days stale. Every reader of that endpoint, human or gate,
    was handed the wrong baseline, and the correct one was sitting unread in the same directory.

    Reported rather than silently preferred, because the two disagreeing is itself the finding:
    it means a deploy updated one record and not the other, and whatever did that will do it
    again. `repo_commit` is what `deployed_sha` now carries, so a consumer gets the value the
    hashes belong to.
    """
    generated = inv.get("repo_commit")
    label = None
    try:
        label = DEPLOYED_SHA.read_text(encoding="utf-8").strip() or None
    except OSError:
        label = None

    if not is_commit_sha(generated):
        r.add(
            "deploy-vintage",
            False,
            f"the invariants file carries no usable repo_commit ({generated!r}), so the "
            f"commit its hashes belong to cannot be named",
        )
        return

    # A DIRTY TREE AT GENERATION MEANS THE COMMIT DOES NOT IDENTIFY THE CONTENT, which
    # `make_invariants.py` already warns about at generation time and nothing carried onto the
    # box. The hashes are still right, because they were taken from the files themselves; what is
    # wrong is the NAME attached to them, which is this check's whole subject.
    if inv.get("repo_dirty") is True:
        r.add(
            "deploy-vintage",
            False,
            f"repo_commit {generated[:12]} was generated from a DIRTY tree, so it names a "
            f"commit whose content is not what was deployed. The hashes are still authoritative; "
            f"the commit is not. Redeploy from a clean checkout.",
        )
        return
    if label is None:
        # Not a failure. The generated record is the authoritative one and it is present; the
        # hand file is the redundant copy, and its absence removes the thing that can drift.
        r.add(
            "deploy-vintage",
            True,
            f"repo_commit {generated[:12]}; no hand-written DEPLOYED_SHA to disagree with it",
        )
        return
    agree = label.startswith(generated[:12]) or generated.startswith(label[:12])
    r.add(
        "deploy-vintage",
        agree,
        f"repo_commit {generated[:12]} and DEPLOYED_SHA {label[:12]} agree"
        if agree
        else (
            f"repo_commit {generated[:12]} but DEPLOYED_SHA says {label[:12]}. The hashes "
            f"below belong to the FIRST; the second is a hand-written label that a deploy "
            f"updated the files without updating. Trust repo_commit and correct the file."
        ),
    )


def check_manifest(inv: dict, r: Result) -> None:
    """CODE AND SKILLS: every tracked file byte-identical to the commit it was deployed from."""
    files = inv.get("files") or {}
    if not files:
        r.add(
            "manifest", False, "invariants file lists no files, so nothing was compared"
        )
        return
    bad = []
    for rel, want in sorted(files.items()):
        p = ZC / rel
        if not p.is_file():
            bad.append(f"{rel}: MISSING")
            continue
        got = sha256_file(p)
        if got != want:
            bad.append(f"{rel}: {got[:12]} != {want[:12]}")
    r.add(
        "manifest",
        not bad,
        f"{len(files)} file(s) compared; "
        + ("all match" if not bad else "; ".join(bad)),
    )


def _read_target(rel: str, p: Path, findings: list[str]) -> str | None:
    """Bytes of one scan target as text, or None with the reason recorded as a finding.

    Binary-safe by design: decoding with replacement makes brain.db scannable the same way
    strings(1) would scan it, which also reaches freelist pages and deleted rows that a SQL
    query over the live tables cannot see. That reach is the reason this stays a byte scan
    rather than becoming a set of sqlite queries.
    """
    if not p.is_file():
        findings.append(f"{rel}: MISSING")
        return None
    try:
        return p.read_bytes().decode("utf-8", "replace")
    except Exception as exc:
        findings.append(f"{rel}: unreadable ({exc})")
        return None


def check_mint_prohibition(inv: dict, r: Result) -> None:
    """No wrong mint may reach a customer, asserted with a DIFFERENT POLARITY PER TIER.

    THE TWO TIERS ARE NOT THE SAME PROBLEM, and running one mechanism across both is what made
    this the only permanently-red check on the box.

      DEPLOYED FILES (`mint_scan`)   skills, SOPs and scripts. We write them, we hash them, and
                                     measurement across every tracked file under skills/ and
                                     sops/ found ZERO foreign base58 tokens outside test
                                     fixtures. So "any address that is not the configured one"
                                     is affordable here and it is the strong form: it catches a
                                     mint nobody has ever seen, including a typo and a
                                     substituted merchant. Unchanged.

      AGENT STATE (`state_scan`)     brain.db. Conversational memory legitimately accumulates
                                     arbitrary addresses, because a Solana Pay reference key is
                                     a FRESH RANDOM ADDRESS PER ORDER and the agent records it.
                                     An allowlist here is unbounded BY CONSTRUCTION: the set of
                                     legitimate tokens grows with every sale, so the check can
                                     only ever go redder. Measured 2026-08-16 on the live box:
                                     27 distinct unexpected tokens, each appearing exactly ONCE
                                     in real content (the 54 occurrences are the memories_fts
                                     index mirroring memories, and this scanner already dedupes
                                     per file with set(), so the mirror was never the noise).
                                     Every one was a one-off reference key.

    So state is asserted as a PROHIBITION ON KNOWN-BAD VALUES, which is what this check has been
    named all along. The list is `retired_mints`: finite, auditable, derived by the generator
    from the same mint-to-network table that refuses to guess a network, so a mint cannot be
    retired in one place and live in the other.

    WHAT THIS GIVES UP, stated rather than hidden: an UNKNOWN wrong mint sitting only in agent
    memory is no longer caught. That is a real reduction and it is the price of the check being
    able to pass at all. It is bounded by what stayed strong: the deployed files keep the
    allowlist, `code-pins` still requires both constants in the script that builds every link,
    and `network-prose` still reads the sentence under the value. A mint the agent invents has
    to survive pay_link.py's pin before it reaches a customer.

    THE CONTROL THAT DECIDED THE DESIGN: the 2026-08-06 incident must still be caught. That
    incident's mint is the devnet USDC mint, it is retired, and a brain.db row carrying it is
    flagged by the denylist exactly as it was by the allowlist. Both directions are driven in
    --self-test against a synthetic sqlite database with the live table shape.

    FAILS CLOSED on an empty denylist while state targets exist: a prohibition with nothing to
    prohibit reads every database as clean, which is the silent green this whole file exists to
    refuse.
    """
    mint = inv.get("mint")
    merchant = inv.get("merchant")
    if not mint:
        r.add(
            "mint-prohibition",
            False,
            "no mint configured, so nothing could be asserted",
        )
        return

    allowed = {mint, merchant} | set(inv.get("allowed_addresses") or [])
    allowed.discard(None)
    known_other = set(inv.get("known_other") or [])

    # Retired values are compared case-sensitively and exactly; base58 is case-significant.
    retired = {t for t in (inv.get("retired_mints") or []) if t}
    retired.discard(mint)

    file_targets = list(inv.get("mint_scan") or [])
    state_targets = list(inv.get("state_scan") or [])
    if not file_targets and not state_targets:
        r.add("mint-prohibition", False, "no scan targets configured")
        return
    if state_targets and not retired:
        r.add(
            "mint-prohibition",
            False,
            f"{len(state_targets)} state target(s) configured with an EMPTY retired_mints "
            "list, so the prohibition would read every database as clean",
        )
        return

    findings: list[str] = []
    scanned = 0

    for rel in file_targets:
        text = _read_target(rel, ZC / rel, findings)
        if text is None:
            continue
        scanned += 1
        for tok in set(B58.findall(text)):
            if tok in allowed or tok in known_other:
                continue
            findings.append(f"{rel}: unexpected address {tok[:10]}..")

    for rel in state_targets:
        text = _read_target(rel, ZC / rel, findings)
        if text is None:
            continue
        scanned += 1
        present = set(B58.findall(text))
        for tok in sorted(retired & present):
            findings.append(f"{rel}: RETIRED mint {tok[:10]}.. present in agent state")

    # THE CAP MUST NAME WHAT IT DROPPED. This listed the first 8 findings and never the total, so
    # a reader could not tell 8 from 8,000 and the check was permanently unmeasurable: the question
    # "is this scan noisy in steady state" had no answer available from its own output, and the
    # verdict file carries the same string, so reading it on the box gave the same 8. A silent
    # truncation reads as completeness. The count goes first, before the sample, because the count
    # is the part a decision is made on.
    uniq = sorted(set(findings))
    if not uniq:
        detail = (
            f"{scanned} target(s) scanned "
            f"({len(file_targets)} file allowlist, {len(state_targets)} state denylist over "
            f"{len(retired)} retired mint(s)); nothing prohibited found"
        )
    else:
        shown = uniq[:MINT_FINDINGS_SHOWN]
        more = len(uniq) - len(shown)
        detail = (
            f"{scanned} target(s) scanned; {len(uniq)} finding(s): "
            + "; ".join(shown)
            + (f"; ... and {more} more not shown" if more else "")
        )
    r.add("mint-prohibition", not findings, detail)


def check_network_prose(inv: dict, r: Result) -> None:
    """STATE-adjacent: the skill must not tell a customer the wrong network.

    Separate from the mint check on purpose. On 2026-08-06 the mint was right and the sentence
    under it said devnet, so a value-only check reported clean while the customer was misinformed.
    """
    want = (inv.get("network") or "").lower()
    forbid = {"devnet", "testnet", "localnet"} - {want}
    if not want:
        r.add("network-prose", False, "no network configured")
        return
    bad = []
    checked = 0
    for rel in inv.get("prose_scan") or []:
        p = ZC / rel
        if not p.is_file():
            bad.append(f"{rel}: MISSING")
            continue
        checked += 1
        text = p.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            hits = [w for w in sorted(forbid) if w in low]
            if not hits:
                continue
            # A PROHIBITION HAS TO NAME WHAT IT FORBIDS, so a whole-file count of the forbidden
            # word scores the CORRECTED file worse than one that never mentioned the hazard. That
            # is not a strict check, it is an inverted one: this gate was red before the fix, red
            # after, red forever, and `Result.ok` is all-of so it pinned the entire verdict to
            # DRIFTED. Skipping prohibition lines is what makes the check able to pass at all.
            if PROHIBITION_RE.search(line):
                continue
            bad.append(f"{rel}:{lineno}: {', '.join(repr(w) for w in hits)}")
    r.add(
        "network-prose",
        not bad,
        f"{checked} file(s) checked against network={want}; "
        + ("clean" if not bad else "; ".join(bad)),
    )


def check_pins(inv: dict, r: Result) -> None:
    """CODE: the last script before a customer sees an address must carry both pins."""
    bad = []
    checked = 0
    for rel in inv.get("pinned_scripts") or []:
        p = ZC / rel
        if not p.is_file():
            bad.append(f"{rel}: MISSING")
            continue
        checked += 1
        src = p.read_text(encoding="utf-8", errors="replace")
        for field, value in (
            ("merchant", inv.get("merchant")),
            ("mint", inv.get("mint")),
        ):
            if not value or value not in src:
                bad.append(f"{rel}: {field} pin absent")
    r.add(
        "code-pins",
        not bad and checked > 0,
        f"{checked} script(s) checked; "
        + ("both pins present" if not bad else "; ".join(bad)),
    )


# --------------------------------------------------------------------------------------------
# UNIT DEFINITIONS. Published so reviewing a unit never requires a shell on the box.
# --------------------------------------------------------------------------------------------
#
# THE GAP THIS CLOSES. `deploy/deploy-targets.json` names six units. Two of them,
# `zc-announce` and `zc-selfcheck`, are committed here and reviewable by anyone with the repo.
# The other four are not, and one of those four is `x402-feed-gate.service` -- the unit for the
# component that takes money. Its ExecStart, the account it runs as, and the environment it
# loads exist only on the box, so nobody can review them and no gate here can see them drift.
#
# THE DIRECTION IS THE SAME INVERSION THIS FILE ALREADY ARGUES FOR. Reading those units means a
# shell, and every remote-hands route into the node is currently shut: Cloud Shell is over its
# monthly tenancy limit, outbound 22 is blocked from the operator's network, Bastion rides SSH
# and lands back on that block, and Run Command is absent from the node's agent plugins. So the
# box PUBLISHES its own unit definitions through the tunnel it already runs, and review becomes
# one HTTPS fetch rather than an interactive session nobody can currently open.
#
# STRUCTURE IS PUBLISHED AND VALUES ARE NOT, because the verdict is served publicly at
# `/selfcheck` and a unit file can carry a credential in an `Environment=` line. The split:
#
#   published    ExecStart and the other Exec* lines, User, Group, WorkingDirectory, Type,
#                Restart, the hardening directives, the timer schedule, the ordering deps.
#   names only   `Environment=` contributes VARIABLE NAMES and never a value.
#   path only    `EnvironmentFile=` contributes the PATH. Its contents are never read; this
#                file does not open it, which is stronger than reading and filtering it.
#   dropped      everything else, counted but not emitted.
#
# AN ALLOWLIST RATHER THAN A DENYLIST, and the concrete reason is `SetCredential=name:value`.
# It carries a secret separated by a COLON, so every value-stripping rule keyed on `=` misses it
# entirely and a denylist that nobody thought to extend would ship it to a public URL. Under an
# allowlist an unrecognised directive is invisible by default and the failure is a reviewer
# asking for one more field, which is recoverable. `LoadCredential=` is left out for the same
# reason even though it is path-shaped. The cost of this choice is real and stated: a directive
# worth publishing stays dark until someone adds it here, and the dropped COUNT is what makes
# that visible rather than silent.
UNIT_DIRECTIVES_PUBLISHED = frozenset(
    {
        # [Unit]
        "Description",
        "Documentation",
        "After",
        "Before",
        "Requires",
        "Wants",
        "PartOf",
        "BindsTo",
        "ConditionPathExists",
        # [Service] identity and execution -- the custody-relevant half.
        "Type",
        "User",
        "Group",
        "WorkingDirectory",
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
        "Restart",
        "RestartSec",
        "TimeoutStartSec",
        "TimeoutStopSec",
        "RuntimeMaxSec",
        "StandardOutput",
        "StandardError",
        "SyslogIdentifier",
        "PassEnvironment",
        # [Service] hardening. None of these can hold a secret and all of them are exactly
        # what a security reviewer opens the unit to find out.
        "NoNewPrivileges",
        "PrivateTmp",
        "PrivateDevices",
        "ProtectSystem",
        "ProtectHome",
        "ProtectKernelTunables",
        "ProtectControlGroups",
        "ReadWritePaths",
        "ReadOnlyPaths",
        "InaccessiblePaths",
        "CapabilityBoundingSet",
        "AmbientCapabilities",
        "RestrictAddressFamilies",
        "SystemCallFilter",
        "MemoryMax",
        "LimitNOFILE",
        # [Timer]
        "OnCalendar",
        "OnBootSec",
        "OnStartupSec",
        "OnUnitActiveSec",
        "OnActiveSec",
        "AccuracySec",
        "RandomizedDelaySec",
        "Persistent",
        "Unit",
        # [Install]
        "WantedBy",
        "RequiredBy",
        "Also",
    }
)

UNIT_DIRECTIVES_NAMES_ONLY = frozenset({"Environment"})
UNIT_DIRECTIVES_PATH_ONLY = frozenset({"EnvironmentFile"})

# systemd's own rule for an environment variable name. A token that does not match is not a
# name, so it is DROPPED rather than published: the alternative is emitting a fragment of a
# value under the label "name", which is the leak this whole split exists to prevent.
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Caps, following this file's existing rule for the mint scan: a bounded list ALWAYS reports its
# true total, because a sample without its denominator reads as complete and is unmeasurable.
UNIT_DIRECTIVES_SHOWN = 40
UNIT_ENV_NAMES_SHOWN = 24

# A `key=value` token anywhere inside a published directive value. Deliberately keyed on the
# `=` alone rather than on a key that looks secret-shaped: a denylist of secret-looking keys
# fails open on the first name nobody predicted, and `ExecStart` is the one published directive
# whose value is attacker-shaped in the sense that matters -- it can carry an inline environment
# assignment (`/usr/bin/env API_TOKEN=... prog`) or a credential flag (`--token=...`).
#
# THE COST IS STATED RATHER THAN HIDDEN: a benign `--port=8402` publishes as `--port=<redacted>`,
# so a reviewer sees which flags exist and not what they are set to. That is a question they can
# ask; a leaked key is not a question anyone gets to ask afterwards. A value worth reviewing
# belongs in the write-up or in a positional argument, both of which survive this untouched.
ASSIGNMENT_TOKEN_RE = re.compile(r"^([^\s=]+)=(.+)$")


def scrub_assignment_values(value: str) -> str:
    """Replace the value half of every `key=value` token, keeping the key.

    Whitespace-split rather than shlex-split on purpose. shlex raises on unbalanced quotes and
    would need a fallback, and it MERGES quoted tokens -- so `"A=x y"` becomes one token whose
    interior this would then have to reason about. Splitting on whitespace can only ever produce
    MORE tokens, and more tokens means more redaction, so the conservative direction is the
    default. The original spacing is not preserved; nothing downstream re-executes this string.
    """
    out = []
    for tok in value.split():
        m = ASSIGNMENT_TOKEN_RE.match(tok)
        out.append(f"{m.group(1)}=<redacted>" if m else tok)
    return " ".join(out)


def environment_names(value: str) -> tuple[list[str], int]:
    """Variable NAMES from an `Environment=` value. Returns (names, dropped).

    shlex IS the right splitter here and whitespace is not, which is the exact inverse of
    `scrub_assignment_values` above and worth stating so neither gets "made consistent" with the
    other. `Environment="GREETING=hello there" MODE=fast` is two assignments, and a whitespace
    split would read `there` as a third token whose name half is `there` -- a fragment of a VALUE
    published under the label "name". shlex keeps the quoted assignment whole.

    Unbalanced quoting makes shlex raise, and the answer to that is to publish NOTHING from the
    line and count it, never to guess at where the values end.
    """
    try:
        tokens = shlex.split(value)
    except ValueError:
        return [], 1
    names: list[str] = []
    dropped = 0
    for tok in tokens:
        name = tok.split("=", 1)[0]
        if ENV_NAME_RE.fullmatch(name):
            names.append(name)
        else:
            dropped += 1
    return names, dropped


def parse_unit_definition(text: str) -> dict:
    """Parse `systemctl cat` output into the publishable shape. PURE, so the self-test drives it.

    Split out for the same reason `unit_verdict` is: the systemd call cannot run in a synthetic
    tree, and a redaction rule that is only ever exercised through a subprocess is a rule nobody
    can prove fails. Every control below drives this function on planted text.

    `systemctl cat` emits `# <absolute path>` before each fragment and before every drop-in, and
    the drop-ins are exactly where an override hides, so the paths are collected as `sources`.
    Every other comment line is discarded, which is not incidental: the units in this repo carry
    long rationale comments, and an allowlist over directives drops all of them for free.
    """
    sources: list[str] = []
    directives: list[str] = []
    env_names: list[str] = []
    env_files: list[str] = []
    dropped = 0
    section = ""
    pending = ""

    for raw in text.splitlines():
        line = raw.strip()
        if pending:
            line = f"{pending} {line}"
            pending = ""
        # A directive may continue onto the next physical line. Joining FIRST means a
        # continuation of an `Environment=` line is classified as one assignment rather than
        # arriving as an orphan token whose key half is part of a value.
        if line.endswith("\\"):
            pending = line[:-1].rstrip()
            continue
        if not line:
            continue
        if line.startswith("#") or line.startswith(";"):
            body = line[1:].strip()
            if body.startswith("/") and " " not in body:
                sources.append(body)
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" not in line:
            dropped += 1
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key in UNIT_DIRECTIVES_NAMES_ONLY:
            names, bad = environment_names(value)
            env_names.extend(names)
            dropped += bad
        elif key in UNIT_DIRECTIVES_PATH_ONLY:
            env_files.append(value)
        elif key in UNIT_DIRECTIVES_PUBLISHED:
            prefix = f"[{section}] " if section else ""
            directives.append(f"{prefix}{key}={scrub_assignment_values(value)}")
        else:
            dropped += 1
    if pending:
        # A trailing continuation with nothing after it. Counted rather than parsed.
        dropped += 1

    unique_names = sorted(set(env_names))
    return {
        "sources": sources,
        "directives": directives[:UNIT_DIRECTIVES_SHOWN],
        "directives_total": len(directives),
        "environment_names": unique_names[:UNIT_ENV_NAMES_SHOWN],
        "environment_names_total": len(unique_names),
        "environment_files": env_files,
        "dropped_directives": dropped,
    }


def systemctl_cat(unit: str) -> tuple[bool, str]:
    """(ok, text-or-reason). Isolated so `collect_unit_definitions` can be driven without systemd."""
    try:
        out = subprocess.run(
            ["systemctl", "--user", "cat", unit],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except Exception as exc:
        return False, f"error:{exc}"
    if out.returncode != 0:
        first = (out.stderr or "").strip().splitlines()
        return False, first[0] if first else f"rc={out.returncode}"
    return True, out.stdout or ""


def check_unit_definitions(inv: dict, r: Result, reader=None) -> None:
    """Publish each configured unit's DEFINITION, and report the count with its denominator.

    THE DIVISION OF LABOUR WITH `check_services` IS DELIBERATE, so nobody merges them later.
    `check_services` owns LIVENESS and fails closed on a unit it cannot read, which is correct:
    a unit that is missing or dead is already red there. This check owns PUBLICATION, and an
    individual unreadable unit does not turn it red -- doing so would report the same defect
    twice under two names while adding nothing a reader can act on. What DOES turn it red is
    reading none of them, because that is the instrument failing rather than the subject: no
    systemctl on PATH, the wrong `--user` scope, a container with no session bus. Zero readable
    out of six and zero configured are different failures and both say so in their own line.

    NOT VERIFIED AGAINST THE REAL BOX. Deploys are frozen until after the live demo on
    2026-08-20 20:00 EST, so every case below runs against planted `systemctl cat` text and
    nothing here has met a live unit. On the first deploy after the freeze lifts, check three
    things against `/selfcheck` before trusting the output:
      1. the count reads `6 of 6` -- anything less names a unit that is not installed under the
         `--user` scope, which is a real finding rather than a checker bug;
      2. `environment_files` lists a path per secret-bearing unit and `environment_names` lists
         the `X402_*` names, which together are the evidence that the split worked on real input;
      3. no value appears anywhere in the published payload. Fetch it and grep it for a value you
         know is set on the box. That grep is the only check that matters, and it cannot be run
         from here.
      4. THE PUBLISHED INVARIANT COUNT MOVES, and two surfaces quote it. This adds one row, so
         `verify-proof.py` starts printing "on all 8 invariants" where it prints 7 today, and
         `notes/DEMO-RUNBOOK.md` pins the 7 in two places. Neither is wrong now -- 7 is the truth
         until this reaches the box -- so they are swept AT DEPLOY, not before. The runbook is
         gitignored, so no gate in this repo can see that drift and nothing but this line will
         raise it.

    AND ONE THING NOT TO MISREAD ON THAT FIRST FETCH: no unit here will publish a `User=` line,
    and its absence is the truth rather than a redaction. `User=` is a system-manager directive
    that the service manager REFUSES inside a user unit, and every unit in this list is a
    `--user` unit -- `grep -rn 'User=' deploy/*.service` finds none for that reason. The account
    these run as is fixed by whose session owns the manager, so "what does it run as" is answered
    by the scope plus the lingering account, never by a directive. `User` stays in the allowlist
    anyway, because a unit that ever moves to the system manager should publish it immediately.
    """
    units = inv.get("units") or []
    read = reader or systemctl_cat
    defs: dict = {}
    unreadable: list[str] = []
    for unit in units:
        ok, payload = read(unit)
        if ok:
            defs[unit] = parse_unit_definition(payload)
        else:
            unreadable.append(f"{unit}: {payload}")
    r.attach("unit_definitions", defs)

    total = len(units)
    if total == 0:
        r.add(
            "service-definitions",
            False,
            "0 of 0 unit(s) readable; no units configured, so nothing was published and "
            "this is NOT a pass",
        )
        return
    detail = f"{len(defs)} of {total} unit(s) readable"
    if unreadable:
        detail += "; not published: " + "; ".join(unreadable)
    else:
        detail += "; every definition published"
    r.add("service-definitions", bool(defs), detail)


def unit_verdict(
    unit: str, active_state: str, result: str, utype: str
) -> tuple[bool, str]:
    """Pure decision, split out from the systemd call SO THE SELF-TEST CAN DRIVE IT.

    THIS WAS INVERTED UNTIL 2026-08-06 AND THE INVERSION WAS INVISIBLE, because the self-test set
    `units = []` and skipped the only check that had it. The old expression allowed `inactive` for
    a `.timer` and forbade it for everything else, which is backwards in both directions:

        stopped zc-feed.timer  -> PASSED     the feed is the submission's lead claim, and its
                                             death was the exact thing this gate existed to catch
        finished oneshot       -> FAILED     the healthy steady state of zc-feed.service

    The correct model needs the unit's TYPE, which `is-active` alone cannot supply:

      .timer      a loaded timer waiting to fire reports ACTIVE. So `inactive` means stopped and
                  whatever it drives is dead. Nothing else is acceptable.
      oneshot     finishes and reports inactive; healthy only when Result=success. A crashed one
                  reports inactive too, which is why Result rather than ActiveState decides it.
      anything    a daemon (simple/notify/forking) must be running. `inactive` is dead even when
      else        it was stopped cleanly, so Result=success must NOT rescue it here.
    """
    if unit.endswith(".timer"):
        ok = active_state == "active"
        return ok, "" if ok else f"{unit}={active_state} (timer not scheduled)"
    if active_state in ("active", "activating"):
        return True, ""
    if utype == "oneshot" and active_state == "inactive" and result == "success":
        return True, ""
    return (
        False,
        f"{unit}={active_state}/{result or 'unknown'} type={utype or 'unknown'}",
    )


def check_services(inv: dict, r: Result) -> None:
    """Liveness. A correct configuration on a dead service is not a working shop."""
    units = inv.get("units") or []
    if not units:
        r.add("services", False, "no units configured")
        return
    bad = []
    for unit in units:
        try:
            out = subprocess.run(
                [
                    "systemctl",
                    "--user",
                    "show",
                    unit,
                    "-p",
                    "ActiveState",
                    "-p",
                    "Result",
                    "-p",
                    "Type",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            kv = dict(
                line.split("=", 1)
                for line in (out.stdout or "").splitlines()
                if "=" in line
            )
        except Exception as exc:
            # Fail CLOSED: an unreadable unit is not a passing unit.
            bad.append(f"{unit}=error:{exc}")
            continue
        ok, why = unit_verdict(
            unit,
            kv.get("ActiveState", ""),
            kv.get("Result", ""),
            kv.get("Type", ""),
        )
        if not ok:
            bad.append(why)
    r.add("services", not bad, "all healthy" if not bad else "; ".join(bad))


def run_checks() -> Result:
    r = Result()
    inv = load_invariants()
    if inv is None:
        r.add(
            "invariants",
            False,
            f"cannot read {INVARIANTS}; nothing was checked, and this is NOT a pass",
        )
        return r
    r.add("invariants", True, f"loaded {INVARIANTS.name}")
    check_vintage_agreement(inv, r)
    check_manifest(inv, r)
    check_mint_prohibition(inv, r)
    check_network_prose(inv, r)
    check_pins(inv, r)
    check_services(inv, r)
    check_unit_definitions(inv, r)
    return r


def redact(text: str) -> str:
    """Strip the two things a PUBLICLY SERVED detail line must never carry.

    The verdict is fetched over plain HTTPS by anyone, so a detail line is public copy rather than
    a local log line. Two classes have to go, and only two:

      the home directory   an absolute path carries the account name on any box that is not this
                           one. `$HOME/.zeroclaw/x` becomes `~/.zeroclaw/x`, which is the form the
                           reproduction doc uses anyway, so nothing legible is lost.
      a chat recipient     a WhatsApp JID is a phone number. Nothing here needs to name it, and
                           `announce_settlements.sh` already avoids carrying one for the same reason.

    DELIBERATELY NARROW, because the obvious wider version would gut the checker. Base58 tokens are
    NOT redacted: the merchant address and the USDC mint are exactly what the mint and manifest
    checks assert, they are public constants published in the write-up, and a verdict that hides
    them cannot state which mint it found. Over-redaction here would leave a green checker saying
    nothing, which is the failure mode this file's docstring already warns about.
    """
    home = str(Path.home())
    for form in (home, home.replace("\\", "/")):
        if form and form != "/":
            text = text.replace(form, "~")
    return re.sub(r"\b\d+@(?:g\.us|s\.whatsapp\.net)", "<recipient>", text)


def redact_tree(obj: object) -> object:
    """`redact` over a nested payload, so an attached document gets the same treatment as a line.

    Unit definitions arrive as nested lists of strings full of absolute paths -- `systemctl cat`
    names every fragment by its full path and a `WorkingDirectory` is one by definition. Walking
    the structure rather than redacting at each producer keeps ONE redaction site, so a future
    attachment inherits it instead of needing to remember it.
    """
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_tree(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_tree(v) for v in obj]
    return obj


def build_verdict(r: Result) -> dict:
    # `deployed_sha` NOW CARRIES THE GENERATED VINTAGE, not the hand-written label. It used to
    # publish DEPLOYED_SHA alone, and on 2026-08-16 that served a commit nine days older than
    # the files the same payload was certifying. The name is kept because it is already read by
    # `scripts/verify-proof.py` and by anyone who has opened the endpoint; what changes is that
    # it now names the commit the hashes in this verdict actually belong to. The hand file is
    # still published beside it so a disagreement stays visible rather than being papered over,
    # and `check_vintage_agreement` turns that disagreement red.
    label = "unknown"
    try:
        label = DEPLOYED_SHA.read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        pass
    inv = load_invariants() or {}
    generated = inv.get("repo_commit")
    # Same strictness as check_vintage_agreement, deliberately sharing one predicate: publishing
    # the "unknown" sentinel under `deployed_sha_source: repo_commit` would label a non-commit as
    # the corroborated baseline, which is worse than publishing the hand label it replaced.
    have_generated = is_commit_sha(generated)
    sha = generated if have_generated else label
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_at_epoch": int(time.time()),
        "deployed_sha": sha,
        "deployed_sha_source": (
            "repo_commit"
            if have_generated
            else "DEPLOYED_SHA (no repo_commit available)"
        ),
        "deployed_sha_label": label,
        "ok": r.ok,
        # Redacted HERE rather than at the serving layer, so what lands on disk is already safe.
        # The gate that serves this is a dumb file reader; putting the defense in the writer means
        # a second consumer (a copy, an operator paste, a future endpoint) inherits it too.
        "checks": [dict(c, detail=redact(c["detail"])) for c in r.checks],
        # WHAT each unit is, beside whether it is running. Structure only: `check_unit_definitions`
        # publishes variable NAMES and EnvironmentFile PATHS and never a value, and this walk adds
        # the same home-directory redaction the detail lines get.
        "unit_definitions": redact_tree(r.data.get("unit_definitions") or {}),
    }


# --------------------------------------------------------------------------------------------
# Self-test. Every check driven in BOTH directions against a synthetic tree.
# --------------------------------------------------------------------------------------------

GOOD_MERCHANT = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
GOOD_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
BAD_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"


def _plant(root: Path, *, clean: bool) -> None:
    (root / "skills").mkdir(parents=True, exist_ok=True)
    (root / "tools").mkdir(parents=True, exist_ok=True)
    (root / "memory").mkdir(parents=True, exist_ok=True)

    mint = GOOD_MINT if clean else BAD_MINT
    net = "mainnet" if clean else "devnet"

    (root / "skills" / "SKILL.md").write_text(
        f"Pay to {GOOD_MERCHANT} using {mint}.\nEsta loja funciona na {net}.\n",
        encoding="utf-8",
    )
    (root / "tools" / "pay_link.py").write_text(
        f'MERCHANT = "{GOOD_MERCHANT}"\n'
        + (f'MINT = "{GOOD_MINT}"\n' if clean else "# mint is a pass-through\n"),
        encoding="utf-8",
    )
    (root / "memory" / "brain.db").write_bytes(
        b"\x00rows\x00" + (GOOD_MINT if clean else BAD_MINT).encode() + b"\x00"
    )


B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _reference_addresses(n: int) -> list[str]:
    """n distinct 44-char base58 tokens shaped like Solana Pay reference keys.

    Deterministic rather than random so a failure is reproducible. The alphabet EXCLUDES 0, O, I
    and l, and a previous fixture here used a decimal counter, produced tokens carrying a zero,
    and the scanner correctly ignored them -- which made three cases fail for a reason that had
    nothing to do with the code under test.
    """
    out = []
    for i in range(n):
        a = B58_ALPHABET[i % len(B58_ALPHABET)]
        b = B58_ALPHABET[(i * 7 + 3) % len(B58_ALPHABET)]
        out.append(("Ref" + a + b).ljust(44, "k"))
    return out


def _plant_brain_db(path: Path, refs: list[str], *, retired: str | None = None) -> None:
    """A synthetic brain.db with the table shape measured on the box on 2026-08-16.

    memories_fts is a MIRROR of memories, which is why the live probe counted every token twice.
    It is reproduced here rather than simplified away, so the fixture exercises the duplication
    the real database has and the dedupe this scanner relies on.
    """
    import sqlite3

    path.unlink(missing_ok=True)
    con = sqlite3.connect(path)
    try:
        con.execute("CREATE TABLE schema_version (version INTEGER)")
        con.execute("INSERT INTO schema_version VALUES (1)")
        con.execute("CREATE TABLE agents (id TEXT PRIMARY KEY, name TEXT)")
        con.execute("INSERT INTO agents VALUES ('demo', 'demo')")
        con.execute("CREATE TABLE memory_meta (k TEXT, v TEXT)")
        con.execute("CREATE TABLE embedding_cache (k TEXT, v BLOB)")
        con.execute("CREATE TABLE memories (id INTEGER PRIMARY KEY, content TEXT)")
        try:
            con.execute("CREATE VIRTUAL TABLE memories_fts USING fts5(content)")
        except sqlite3.OperationalError:
            # fts5 absent from this build. The scan reads bytes, so a plain mirror table
            # reproduces the duplication faithfully enough for what is being tested.
            con.execute("CREATE TABLE memories_fts (content TEXT)")
        rows = [f"order {i}: reference {ref} recorded" for i, ref in enumerate(refs)]
        if retired:
            rows.append(f"pay with mint {retired} as recalled from memory")
        for row in rows:
            con.execute("INSERT INTO memories (content) VALUES (?)", (row,))
            con.execute("INSERT INTO memories_fts (content) VALUES (?)", (row,))
        con.commit()
    finally:
        con.close()


def _invariants_for(root: Path, *, honest_manifest: bool) -> dict:
    skill = root / "skills" / "SKILL.md"
    return {
        "merchant": GOOD_MERCHANT,
        "mint": GOOD_MINT,
        "network": "mainnet",
        "files": {
            "skills/SKILL.md": sha256_file(skill) if honest_manifest else "0" * 64
        },
        "mint_scan": ["skills/SKILL.md"],
        "state_scan": ["memory/brain.db"],
        "retired_mints": [BAD_MINT],
        "prose_scan": ["skills/SKILL.md"],
        "pinned_scripts": ["tools/pay_link.py"],
        "units": [],
    }


def self_test() -> int:
    global ZC, INVARIANTS
    passed = failed = 0

    def report(label: str, cond: bool) -> None:
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS  {label}")
        else:
            failed += 1
            print(f"  FAIL  {label}")

    for clean in (True, False):
        tmp = Path(tempfile.mkdtemp(prefix="boxcheck-"))
        try:
            _plant(tmp, clean=clean)
            ZC = tmp
            INVARIANTS = tmp / "SHOP-INVARIANTS.json"
            inv = _invariants_for(tmp, honest_manifest=clean)
            # Drop the units check in the synthetic tree; systemd is not the subject here.
            inv["units"] = []
            INVARIANTS.write_text(json.dumps(inv), encoding="utf-8")

            r = Result()
            check_manifest(inv, r)
            check_mint_prohibition(inv, r)
            check_network_prose(inv, r)
            check_pins(inv, r)
            by = {c["name"]: c["ok"] for c in r.checks}

            word = "clean" if clean else "drifted"
            for name in ("manifest", "mint-prohibition", "network-prose", "code-pins"):
                report(
                    f"{word} tree: {name} {'passes' if clean else 'FAILS'}",
                    by[name] is clean,
                )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # THE MINT SCAN'S CAP MUST NAME WHAT IT DROPPED. It listed the first 8 findings and never the
    # total, so the check was permanently unmeasurable: 8 and 8,000 produced the same line, and the
    # verdict file carried the same string, so reading it on the box did not help either. Driven
    # with MORE findings than the cap, which is the only way this can fail.
    tmp = Path(tempfile.mkdtemp(prefix="zc-mintcap-"))
    try:
        planted = 12  # deliberately above MINT_FINDINGS_SHOWN
        (tmp / "skills").mkdir(parents=True)
        # Distinct 44-char base58 addresses, none of them the configured mint or merchant.
        # The alphabet EXCLUDES 0, O, I and l, which is why a naive f"{i:02d}" counter produced
        # tokens the scanner correctly ignored and made all three cases fail on the first run.
        d = "123456789"
        addrs = [("Z" + d[i // 9] + d[i % 9]).ljust(44, "k") for i in range(planted)]
        (tmp / "skills" / "SKILL.md").write_text(" ".join(addrs), encoding="utf-8")
        inv = {
            "mint": GOOD_MINT,
            "merchant": GOOD_MERCHANT,
            "mint_scan": ["skills/SKILL.md"],
            "allowed_addresses": [],
            "known_other": [],
        }
        r = Result()
        # `global ZC` is declared at the top of this function, so the plain assignment is the
        # file's own idiom. The RESTORE is deliberate and deviates from the blocks above, which
        # leave ZC pointing at a deleted temp dir: this block is not last, so leaking the path
        # would silently change what every later block scans. Do not "simplify" it away.
        prev_zc = ZC
        try:
            ZC = tmp
            check_mint_prohibition(inv, r)
        finally:
            ZC = prev_zc
        detail = r.checks[0]["detail"]
        report(
            f"mint cap: the TRUE total is reported, not the sample size ({planted})",
            f"{planted} finding(s)" in detail,
        )
        report(
            "mint cap: the dropped remainder is named rather than silently cut",
            f"and {planted - MINT_FINDINGS_SHOWN} more not shown" in detail,
        )
        report(
            "mint cap: the sample really is capped (over-correction control)",
            detail.count("unexpected address") == MINT_FINDINGS_SHOWN,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # THE STATE SCAN'S POLARITY, driven both directions against a synthetic brain.db carrying the
    # table shape measured on the live box. These two cases DECIDED the design rather than
    # documenting it: a narrowing that could not keep the incident caught would have been the
    # wrong narrowing, and one that stayed noisy on 27 reference keys would have kept the box red.
    tmp = Path(tempfile.mkdtemp(prefix="zc-state-"))
    try:
        prev_zc = ZC
        (tmp / "memory").mkdir(parents=True)
        db = tmp / "memory" / "brain.db"

        refs = _reference_addresses(27)
        _plant_brain_db(db, refs)
        inv = {
            "mint": GOOD_MINT,
            "merchant": GOOD_MERCHANT,
            "mint_scan": [],
            "state_scan": ["memory/brain.db"],
            "retired_mints": [BAD_MINT],
            "allowed_addresses": [],
            "known_other": [],
        }
        r = Result()
        try:
            ZC = tmp
            check_mint_prohibition(inv, r)
        finally:
            ZC = prev_zc
        clean_detail = r.checks[0]["detail"]
        report(
            f"state scan: {len(refs)} one-off reference keys produce ZERO findings",
            r.checks[0]["ok"] is True and "finding(s)" not in clean_detail,
        )
        # Proves the scanner READ the database rather than skipping it. A zero from a target that
        # was never opened is byte-identical to a zero from a clean one.
        report(
            "state scan: the clean verdict is a READ, not a skip",
            "1 target(s) scanned" in clean_detail and "MISSING" not in clean_detail,
        )

        # THE NON-NEGOTIABLE CONTROL: 2026-08-06 verbatim in shape. The devnet mint in a brain.db
        # row while the skill on disk is already correct. If this ever goes green the narrowing is
        # wrong and must be reverted, not adjusted.
        _plant_brain_db(db, refs, retired=BAD_MINT)
        r = Result()
        try:
            ZC = tmp
            check_mint_prohibition(inv, r)
        finally:
            ZC = prev_zc
        detail = r.checks[0]["detail"]
        report(
            "state scan: a RETIRED mint in a brain.db row is FLAGGED (the 2026-08-06 incident)",
            r.checks[0]["ok"] is False and "RETIRED mint" in detail,
        )
        report(
            "state scan: it flags the retired mint ALONE, not the reference keys beside it",
            detail.count("RETIRED mint") == 1 and "1 finding(s)" in detail,
        )

        # MUTATION CONTROL: the intersection above is what catches the incident, and nothing
        # else in the file is. Without this, the incident case could be passing because some
        # neighbouring check happens to complain, and the suite would never say so. The
        # substitution is asserted to have APPLIED, because a stale anchor produces a mutant
        # byte-identical to the original that then passes while testing nothing.
        src = Path(__file__).read_text(encoding="utf-8")
        anchor = "        for tok in sorted(retired & present):"
        report("mutation: the anchor the control keys on still exists", anchor in src)
        ns: dict = {"__name__": "bsc_mutant", "__file__": __file__}
        exec(
            compile(
                src.replace(anchor, "        for tok in sorted(set()):", 1),
                "bsc_mutant",
                "exec",
            ),
            ns,
        )
        ns["ZC"] = tmp
        mr = ns["Result"]()
        ns["check_mint_prohibition"](inv, mr)
        report(
            "mutation: with the denylist gutted the incident STOPS firing",
            mr.checks[0]["ok"] is True,
        )

        # An empty denylist over a live state target must FAIL rather than report clean. Without
        # this the narrowing has an off switch that looks exactly like a pass.
        r = Result()
        try:
            ZC = tmp
            check_mint_prohibition({**inv, "retired_mints": []}, r)
        finally:
            ZC = prev_zc
        report(
            "state scan: an EMPTY retired list fails closed rather than reading clean",
            r.checks[0]["ok"] is False
            and "EMPTY retired_mints" in r.checks[0]["detail"],
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # SERVICES. Driven through the pure verdict rather than systemd, because the whole reason the
    # inversion survived is that the self-test set units=[] and this check was never exercised.
    # Case 1 is the incident verbatim: a stopped feed timer used to PASS, which made the death of
    # the submission's lead claim invisible.
    for unit, state, res, utype, want, label in (
        (
            "zc-feed.timer",
            "inactive",
            "success",
            "",
            False,
            "STOPPED timer FAILS (the incident)",
        ),
        ("zc-feed.timer", "active", "success", "", True, "scheduled timer passes"),
        (
            "zc-feed.service",
            "inactive",
            "success",
            "oneshot",
            True,
            "finished oneshot passes",
        ),
        (
            "zc-feed.service",
            "inactive",
            "exit-code",
            "oneshot",
            False,
            "crashed oneshot FAILS",
        ),
        (
            "zc-shop.service",
            "active",
            "success",
            "simple",
            True,
            "running daemon passes",
        ),
        (
            "zc-shop.service",
            "inactive",
            "success",
            "simple",
            False,
            "stopped daemon FAILS",
        ),
        (
            "zc-shop.service",
            "failed",
            "exit-code",
            "simple",
            False,
            "failed daemon FAILS",
        ),
    ):
        got, _why = unit_verdict(unit, state, res, utype)
        report(f"services: {label}", got is want)

    # UNIT DEFINITIONS. The load-bearing case is the FIRST one: this payload is served publicly,
    # so a unit carrying a credential must publish the variable's NAME and never its value. The
    # rest of the block exists because that case alone cannot tell a working redactor from a
    # publisher that emits nothing -- the over-correction control is what separates them.
    #
    # Driven on planted `systemctl cat` text rather than through systemd, for the same reason
    # `unit_verdict` is a pure function: the box is frozen until after the demo, so nothing here
    # has met a live unit and every case must run in a synthetic tree.
    tmp = Path(tempfile.mkdtemp(prefix="zc-unitdefs-"))
    try:
        # Unmistakably synthetic, and deliberately not shaped like any vendor's real prefix: the
        # repo's identifier gate scans this tree, and a realistic-looking fixture is a finding
        # there and rightly so.
        secret = "SYNTHETIC-NOT-A-REAL-SECRET-0000000000"
        file_secret = "SYNTHETIC-INSIDE-THE-ENV-FILE-0000000000"

        # A REAL, READABLE file with secrets in it, planted on disk on purpose. A payload that
        # omits its contents because the path did not resolve proves nothing; this way the
        # absence is evidence that the file is never opened.
        envfile = tmp / "gate.env"
        envfile.write_text(
            f"X402_SELLER_KEY={file_secret}\nX402_DAILY_CAP=25\n", encoding="utf-8"
        )

        secretive = (
            "# /etc/systemd/user/zc-demo-gate.service\n"
            "# A rationale comment that must not be published.\n"
            "[Unit]\n"
            "Description=Demo gate\n"
            "[Service]\n"
            "Type=simple\n"
            "User=svc-demo\n"
            "WorkingDirectory=/opt/zc-demo\n"
            f"Environment=X402_SELLER_KEY={secret}\n"
            'Environment="X402_GREETING=hello there" X402_NETWORK=devnet\n'
            f"EnvironmentFile={envfile}\n"
            f"SetCredential=seller:{secret}\n"
            f"ExecStart=/usr/bin/env X402_INLINE={secret} /opt/zc-demo/gate --port=8402\n"
        )
        d = parse_unit_definition(secretive)
        blob = json.dumps(d)

        report(
            "unit defs: the Environment variable NAME is published",
            "X402_SELLER_KEY" in d["environment_names"],
        )
        report(
            "unit defs: the EnvironmentFile PATH is published",
            any(str(envfile) in p for p in d["environment_files"]),
        )
        # THE LOAD-BEARING ASSERTION. Anywhere in the payload, not just in the field the value
        # came from: a leak that lands in `directives` instead of `environment_names` is the
        # same leak, and a per-field assertion would miss it.
        report(
            "unit defs: the Environment VALUE appears nowhere in the payload",
            secret not in blob,
        )
        report(
            "unit defs: the EnvironmentFile's CONTENTS appear nowhere (it is never opened)",
            file_secret not in blob and "X402_DAILY_CAP" not in blob,
        )
        report(
            "unit defs: a quoted assignment yields its NAME, not a fragment of its value",
            "X402_GREETING" in d["environment_names"] and "there" not in blob,
        )
        report(
            "unit defs: an inline assignment inside ExecStart is scrubbed too",
            any("X402_INLINE=<redacted>" in x for x in d["directives"]),
        )
        report(
            "unit defs: SetCredential (colon-separated, so no `=` rule can see it) is DROPPED",
            "seller" not in blob and d["dropped_directives"] >= 1,
        )
        report(
            "unit defs: a rationale comment is not published",
            "rationale comment" not in blob,
        )
        report(
            "unit defs: the fragment path is published as a source",
            "/etc/systemd/user/zc-demo-gate.service" in d["sources"],
        )
        # A STRUCTURAL invariant rather than a behavioural one, because the behavioural cases
        # above are protected only by branch ORDER: names-only is tested before the allowlist, so
        # adding "Environment" to the allowlist leaks nothing TODAY and leaks everything the day
        # someone reorders the branches. That is a silent regression a fixture cannot see.
        report(
            "unit defs: Environment is not in the published allowlist (structural)",
            "Environment" not in UNIT_DIRECTIVES_PUBLISHED
            and "EnvironmentFile" not in UNIT_DIRECTIVES_PUBLISHED,
        )
        report(
            "unit defs: the value-bearing directive sets stay disjoint (structural)",
            not (UNIT_DIRECTIVES_PUBLISHED & UNIT_DIRECTIVES_NAMES_ONLY)
            and not (UNIT_DIRECTIVES_PUBLISHED & UNIT_DIRECTIVES_PATH_ONLY),
        )
        report(
            "unit defs: SetCredential/LoadCredential stay OUT of the allowlist (structural)",
            not ({"SetCredential", "LoadCredential"} & UNIT_DIRECTIVES_PUBLISHED),
        )

        # OVER-CORRECTION CONTROLS. "No secret in the output" is trivially satisfied by an empty
        # output, so the same fixture must still carry the two fields a custody reviewer opens
        # the unit for. Without these the redaction could be a `return {}` and every case above
        # would still pass.
        report(
            "unit defs: ExecStart still publishes its binary (over-correction control)",
            any("/opt/zc-demo/gate" in x for x in d["directives"]),
        )
        report(
            "unit defs: User still publishes (over-correction control)",
            any(x.endswith("User=svc-demo") for x in d["directives"]),
        )
        report(
            "unit defs: WorkingDirectory still publishes (over-correction control)",
            any("/opt/zc-demo" in x for x in d["directives"]),
        )
        report(
            "unit defs: the section each directive came from is kept",
            any(x.startswith("[Service] ") for x in d["directives"]),
        )

        # A continuation line is joined before classification. Split naively, `MODE=fast` would
        # arrive as an orphan and the value half of the first assignment could be read as a name.
        cont = f"[Service]\nEnvironment=X402_A={secret} \\\n    X402_B=fast\n"
        dc = parse_unit_definition(cont)
        report(
            "unit defs: a continued Environment line yields both names and no value",
            dc["environment_names"] == ["X402_A", "X402_B"]
            and secret not in json.dumps(dc),
        )

        # MUTATION CONTROL. With the name-only rule gutted, the load-bearing case must go RED --
        # that is what proves the green above comes from this rule and not from the fixture
        # happening to be harmless. The substitution is asserted to have APPLIED first, because a
        # stale anchor produces a mutant byte-identical to the original that passes while testing
        # nothing; and the replacement is deliberately a DIFFERENT LENGTH from its anchor, since
        # CPython keys its bytecode cache on source size and mtime and a same-length edit inside
        # one clock tick can run the ORIGINAL bytecode.
        src = Path(__file__).read_text(encoding="utf-8")
        anchor = (
            "        if ENV_NAME_RE.fullmatch(name):\n            names.append(name)"
        )
        mutant = "        if True:\n            names.append(tok)"
        report("unit defs mutation: the anchor still exists", anchor in src)
        report(
            "unit defs mutation: the mutant differs in LENGTH (bytecode-cache safety)",
            len(mutant) != len(anchor),
        )
        ns: dict = {"__name__": "bsc_unit_mutant", "__file__": __file__}
        exec(
            compile(src.replace(anchor, mutant, 1), "bsc_unit_mutant", "exec"),
            ns,
        )
        md = ns["parse_unit_definition"](secretive)
        report(
            "unit defs mutation: with the name-only rule gutted the secret LEAKS",
            secret in json.dumps(md),
        )

        # THE DENOMINATOR, driven through the check with an injected reader. A bare count cannot
        # tell "every unit published" from "the reader never reached systemd", which is the whole
        # reason this file states a total beside every number it prints.
        inv3 = {"units": ["a.service", "b.service", "c.timer"]}

        def _reader_all(unit: str) -> tuple[bool, str]:
            return True, f"[Service]\nType=simple\nExecStart=/opt/{unit}\n"

        def _reader_partial(unit: str) -> tuple[bool, str]:
            if unit == "b.service":
                return False, "No files found for b.service."
            return _reader_all(unit)

        def _reader_none(unit: str) -> tuple[bool, str]:
            return False, "error:[Errno 2] systemctl not found"

        r = Result()
        check_unit_definitions(inv3, r, reader=_reader_all)
        report(
            "unit defs: the count carries its denominator",
            "3 of 3 unit(s) readable" in r.checks[0]["detail"],
        )
        report(
            "unit defs: all-readable is OK and every definition is attached",
            r.checks[0]["ok"] is True and len(r.data["unit_definitions"]) == 3,
        )

        r = Result()
        check_unit_definitions(inv3, r, reader=_reader_partial)
        report(
            "unit defs: a partial read reports N of M and NAMES what it missed",
            "2 of 3 unit(s) readable" in r.checks[0]["detail"]
            and "b.service" in r.checks[0]["detail"],
        )
        report(
            "unit defs: a partial read stays OK (liveness is check_services' job, not this one)",
            r.checks[0]["ok"] is True,
        )

        r = Result()
        check_unit_definitions(inv3, r, reader=_reader_none)
        report(
            "unit defs: reading NONE of them is the instrument failing, and FAILS",
            r.checks[0]["ok"] is False
            and "0 of 3 unit(s) readable" in r.checks[0]["detail"],
        )

        r = Result()
        check_unit_definitions({"units": []}, r, reader=_reader_all)
        report(
            "unit defs: no units configured FAILS and says nothing was published",
            r.checks[0]["ok"] is False and "0 of 0" in r.checks[0]["detail"],
        )

        # THE PUBLISHED PAYLOAD, which is what a remote reviewer actually fetches. The redaction
        # walk has to reach a nested attachment; a home path surviving inside `unit_definitions`
        # is the same leak as one in a detail line, and only this case would see it.
        home = str(Path.home())
        r = Result()
        r.attach(
            "unit_definitions",
            {
                "z.service": {
                    "directives": [f"[Service] WorkingDirectory={home}/.zeroclaw"],
                    "environment_names": ["X402_NETWORK"],
                }
            },
        )
        r.add("probe", True, "ok")
        v = build_verdict(r)
        published = json.dumps(v["unit_definitions"])
        report(
            "unit defs: the attachment reaches the verdict",
            "X402_NETWORK" in published,
        )
        report(
            "unit defs: redaction reaches INSIDE the attachment",
            home not in published and "~/.zeroclaw" in published,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # NETWORK PROSE. The over-correction control matters more than the fix here: "the false
    # positive stopped" is equally consistent with having disabled the detector, so a real
    # customer-facing sentence must still fire.
    tmp = Path(tempfile.mkdtemp(prefix="boxcheck-prose-"))
    try:
        ZC = tmp
        (tmp / "skill.md").write_text(
            "Never tell the customer this shop settles on devnet.\n"
            "Do NOT emit a devnet mint under any circumstances.\n"
            "This shop receives USDC on Solana mainnet.\n",
            encoding="utf-8",
        )
        r = Result()
        check_network_prose({"network": "mainnet", "prose_scan": ["skill.md"]}, r)
        report(
            "prose: a prohibition NAMING devnet passes (was red forever)",
            r.checks[0]["ok"] is True,
        )

        (tmp / "skill.md").write_text(
            "This shop receives USDC on Solana mainnet.\n"
            "Esta loja funciona na devnet.\n",
            encoding="utf-8",
        )
        r = Result()
        check_network_prose({"network": "mainnet", "prose_scan": ["skill.md"]}, r)
        report(
            "prose: an ASSERTION of devnet still FAILS (over-correction control)",
            r.checks[0]["ok"] is False,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # The fail-closed case, which is the one a broken deploy actually produces.
    tmp = Path(tempfile.mkdtemp(prefix="boxcheck-"))
    try:
        ZC = tmp
        INVARIANTS = tmp / "does-not-exist.json"
        r = run_checks()
        report("absent invariants file is NOT OK", r.ok is False)
        report(
            "absent invariants file says so in its detail",
            "NOT a pass" in r.checks[0]["detail"],
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # THE DEPLOY VINTAGE, driven both directions plus the incident. The failure this guards was
    # invisible precisely because both records looked healthy on their own: the manifest was
    # green against regenerated hashes while the published label was nine days stale, so the
    # only observable was the two disagreeing and nothing compared them.
    global DEPLOYED_SHA
    tmp = Path(tempfile.mkdtemp(prefix="boxcheck-"))
    try:
        ZC = tmp
        DEPLOYED_SHA = tmp / "DEPLOYED_SHA"
        agreeing = "a" * 40
        stale = "b" * 40

        DEPLOYED_SHA.write_text(agreeing, encoding="utf-8")
        r = Result()
        check_vintage_agreement({"repo_commit": agreeing}, r)
        report("vintage: matching records pass", r.checks[0]["ok"] is True)

        # THE INCIDENT, 2026-08-16: files deployed at one commit, label left at an older one.
        DEPLOYED_SHA.write_text(stale, encoding="utf-8")
        r = Result()
        check_vintage_agreement({"repo_commit": agreeing}, r)
        report(
            "vintage: disagreeing records FAIL (the incident)",
            r.checks[0]["ok"] is False,
        )
        report(
            "vintage: the failure names repo_commit as the one to trust",
            "Trust repo_commit" in r.checks[0]["detail"],
        )

        # An ABSENT hand file is not a failure: the generated record is authoritative and the
        # thing that can drift is simply not there. Over-correction control for the case above.
        DEPLOYED_SHA.unlink()
        r = Result()
        check_vintage_agreement({"repo_commit": agreeing}, r)
        report(
            "vintage: absent label passes (over-correction control)",
            r.checks[0]["ok"] is True,
        )

        # A missing GENERATED record is a failure, because then nothing names the commit the
        # hashes belong to and the manifest below it is verifying against an unnamed baseline.
        r = Result()
        check_vintage_agreement({}, r)
        report("vintage: absent repo_commit FAILS", r.checks[0]["ok"] is False)

        # THE "unknown" SENTINEL, which `make_invariants.py` writes when `rev-parse HEAD` fails
        # and which is exactly seven characters long. A length-based guard accepts it and labels
        # a non-commit as the corroborated baseline.
        DEPLOYED_SHA.write_text(agreeing, encoding="utf-8")
        r = Result()
        check_vintage_agreement({"repo_commit": "unknown"}, r)
        report("vintage: the 'unknown' sentinel FAILS", r.checks[0]["ok"] is False)
        report(
            "vintage: a real 40-hex sha is still accepted",
            is_commit_sha(agreeing) is True,
        )
        report(
            "vintage: a short sha is rejected", is_commit_sha(agreeing[:12]) is False
        )
        report(
            "vintage: a 40-char non-hex string is rejected",
            is_commit_sha("z" * 40) is False,
        )

        # A DIRTY tree at generation time: the hashes are right and the commit does not name the
        # content they came from, which is the same class of wrong baseline.
        r = Result()
        check_vintage_agreement({"repo_commit": agreeing, "repo_dirty": True}, r)
        report("vintage: a dirty-tree generation FAILS", r.checks[0]["ok"] is False)
        r = Result()
        check_vintage_agreement({"repo_commit": agreeing, "repo_dirty": False}, r)
        report(
            "vintage: a clean-tree generation passes (over-correction control)",
            r.checks[0]["ok"] is True,
        )

        # THE PUBLISHED FIELD, which is what a remote reader and every gate actually consume.
        # Before this change it carried the hand label, so it served the stale commit.
        DEPLOYED_SHA.write_text(stale, encoding="utf-8")
        INVARIANTS = tmp / "SHOP-INVARIANTS.json"
        INVARIANTS.write_text(json.dumps({"repo_commit": agreeing}), encoding="utf-8")
        v = build_verdict(Result())
        report(
            "vintage: deployed_sha publishes repo_commit, not the label",
            v["deployed_sha"] == agreeing,
        )
        report(
            "vintage: the stale label is still published beside it",
            v["deployed_sha_label"] == stale,
        )
        report(
            "vintage: the source of the value is named",
            v["deployed_sha_source"] == "repo_commit",
        )

        # MUTATION CONTROL. With the comparison neutered the incident must stop firing, which is
        # what proves the red above came from the comparison rather than from anywhere else.
        real = check_vintage_agreement.__code__
        try:
            check_vintage_agreement.__code__ = (
                lambda inv, r: r.add("deploy-vintage", True, "muted")
            ).__code__
            r = Result()
            check_vintage_agreement({"repo_commit": agreeing}, r)
            report(
                "vintage: mutation, the incident STOPS firing",
                r.checks[0]["ok"] is True,
            )
        finally:
            check_vintage_agreement.__code__ = real
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # REDACTION, driven both directions. This verdict is served publicly, so a detail line is
    # public copy; and the over-redaction control matters more than the redaction one, because a
    # checker that hides the values it asserts reports green while saying nothing.
    home = str(Path.home())
    r = Result()
    r.add("probe", False, f"cannot read {home}/.zeroclaw/SHOP-INVARIANTS.json")
    # All zeros rather than a plausible number: it matches the JID shape the redactor keys on, so
    # it exercises the same path, while being unmistakably synthetic to the identifier gate that
    # scans this tree. A realistic-looking fixture is flagged by that gate and rightly so.
    r.add("probe2", False, "would send to 00000000000@s.whatsapp.net")
    r.add(
        "probe3",
        True,
        f"mint {GOOD_MINT} and merchant {GOOD_MERCHANT} both match the manifest",
    )
    details = [c["detail"] for c in build_verdict(r)["checks"]]

    report("redaction: the home path is gone", home not in details[0])
    report("redaction: it leaves a legible ~ path", "~/.zeroclaw/" in details[0])
    report("redaction: a chat recipient is gone", "5511987654321" not in details[1])
    report("redaction: the JID is replaced, not deleted", "<recipient>" in details[1])
    # The over-correction controls. A wider redactor would pass the two above and destroy these.
    report(
        "redaction: the USDC mint SURVIVES (over-correction control)",
        GOOD_MINT in details[2],
    )
    report(
        "redaction: the merchant address SURVIVES (over-correction control)",
        GOOD_MERCHANT in details[2],
    )
    # And the writer is what carries it, not the caller: an unredacted Result must not reach disk.
    report(
        "redaction: build_verdict applies it rather than the caller",
        home not in json.dumps(build_verdict(r)),
    )

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument(
        "--self-test", action="store_true", help="drive every check both directions"
    )
    ap.add_argument(
        "--out", default=str(VERDICT_DEFAULT), help="where to write the verdict JSON"
    )
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    r = run_checks()
    verdict = build_verdict(r)

    out = Path(args.out)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(verdict, indent=2) + "\n", encoding="utf-8")
    except Exception as exc:
        print(f"WARN could not write {out}: {exc}", file=sys.stderr)

    if not args.quiet:
        for c in verdict["checks"]:
            print(f"{'ok  ' if c['ok'] else 'FAIL'}  {c['name']:<18} {c['detail']}")
        print(f"\ndeployed_sha {verdict['deployed_sha']}")
        print(f"verdict      {'OK' if verdict['ok'] else 'DRIFTED'}  -> {out}")

    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
