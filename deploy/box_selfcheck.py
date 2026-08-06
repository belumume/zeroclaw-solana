#!/usr/bin/env python3
"""Runs ON the box. Asserts the shop's invariants and publishes a verdict the world can fetch.

WHY THE DIRECTION IS INVERTED, because this is the design decision worth defending.

The obvious shape is a CI job that reaches into the box and inspects it. That shape is dead here
and the reason is measured rather than assumed: port 22 is blocked network-wide from the operator's
location, direct HTTPS to the instance IP is blocked, the OCI Bastion endpoint is blocked on both
22 and 443, and Compute Instance Run Command reports `desired-state: ENABLED` while being absent
from the live plugin list, so the agent never instantiated it. Every inbound route is shut.

So the box checks ITSELF and pushes the verdict outward through the Cloudflare tunnel it already
runs for the x402 gate. Nothing needs to reach in. A checker anywhere fetches one JSON document
over plain HTTPS, and `check_box_drift.py` is that checker.

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
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ZC = Path(os.environ.get("ZEROCLAW_HOME", str(Path.home() / ".zeroclaw")))

# Written at deploy time from the repo. Absent means we cannot know what SHOULD be here, which is
# a failure rather than a skip.
INVARIANTS = ZC / "SHOP-INVARIANTS.json"
DEPLOYED_SHA = ZC / "DEPLOYED_SHA"

VERDICT_DEFAULT = ZC / "state" / "box-selfcheck.json"

# A base58 Solana address, used to find any mint-shaped token in a file. Deliberately broad: the
# check is "is there an address here that is not the configured one", so over-matching is safe and
# under-matching is not.
B58 = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")

# A line that FORBIDS a network necessarily names it, so the network-prose check has to tell a
# prohibition apart from an assertion to the customer. Deliberately a small, boring marker set:
# this is a semantic distinction and regex does those badly (measured F1 ~0.22-0.33 for the class),
# so the honest posture is a narrow list plus a stated ceiling rather than a clever pattern.
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

    def add(self, name: str, ok: bool, detail: str) -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c["ok"] for c in self.checks)


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


def check_mint_prohibition(inv: dict, r: Result) -> None:
    """STATE: no address other than the configured mint may appear in skill or memory.

    This is the check that would have caught the 2026-08-06 incident in seconds. The agent held a
    stale mint in three brain.db rows while the skill on disk was already correct, so a
    file-to-file comparison could never have seen it.
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

    targets: list[tuple[str, Path]] = []
    for rel in inv.get("mint_scan") or []:
        targets.append((rel, ZC / rel))
    if not targets:
        r.add("mint-prohibition", False, "no scan targets configured")
        return

    findings = []
    scanned = 0
    for rel, p in targets:
        if not p.is_file():
            findings.append(f"{rel}: MISSING")
            continue
        scanned += 1
        try:
            blob = p.read_bytes()
        except Exception as exc:
            findings.append(f"{rel}: unreadable ({exc})")
            continue
        # Binary-safe: decode with replacement so brain.db is scannable the same way strings(1)
        # would scan it.
        text = blob.decode("utf-8", "replace")
        for tok in set(B58.findall(text)):
            if tok not in allowed:
                # Only report tokens that look like a mint or a wallet rather than every base58
                # blob; a reference key is a fresh random address per order and is legitimate.
                if tok in (inv.get("known_other") or []):
                    continue
                findings.append(f"{rel}: unexpected address {tok[:10]}..")

    r.add(
        "mint-prohibition",
        not findings,
        f"{scanned} target(s) scanned; "
        + (
            "only configured addresses present"
            if not findings
            else "; ".join(sorted(set(findings))[:8])
        ),
    )


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
    check_manifest(inv, r)
    check_mint_prohibition(inv, r)
    check_network_prose(inv, r)
    check_pins(inv, r)
    check_services(inv, r)
    return r


def build_verdict(r: Result) -> dict:
    sha = "unknown"
    try:
        sha = DEPLOYED_SHA.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_at_epoch": int(time.time()),
        "deployed_sha": sha,
        "ok": r.ok,
        "checks": r.checks,
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


def _invariants_for(root: Path, *, honest_manifest: bool) -> dict:
    skill = root / "skills" / "SKILL.md"
    return {
        "merchant": GOOD_MERCHANT,
        "mint": GOOD_MINT,
        "network": "mainnet",
        "files": {
            "skills/SKILL.md": sha256_file(skill) if honest_manifest else "0" * 64
        },
        "mint_scan": ["skills/SKILL.md", "memory/brain.db"],
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
