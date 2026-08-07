#!/usr/bin/env python3
"""Find capability that ONCE EXISTED in this repo and silently vanished.

WHY THIS EXISTS. On 2026-07-23 a Wallet Standard wallet picker was added to the pay
page and tested by the operator. On 2026-07-24, nine hours after being refined, it was
destroyed by a commit whose subject is about payer preflight, an idempotent token
account and cache headers -- it does not mention wallets at all. Nobody noticed for two
weeks, and the operator rediscovered it by clicking his own pay page. Git had the whole
story; nothing ever asked git the question.

THE QUESTION THIS ASKS, which no test suite asks: what named thing did this repo once
contain that it no longer contains, where the commit that removed it never said so?

A test suite protects what someone thought to write a test for. This protects everything
that was ever NAMED, which is a much larger set and needs no foresight.

METHOD
  1. Walk every commit's added lines and collect DECLARED identifiers -- functions,
     consts, classes, CSS classes, element ids. A declaration is the cheapest available
     proxy for "a capability someone built".
  2. Diff that historical set against what HEAD contains.
  3. For each vanished identifier, find the commit that removed it and ask whether that
     commit's own message mentions it.

     Mentioned     -> a deliberate removal. Silent.
     NOT mentioned -> a SILENT REGRESSION candidate. Reported.

POSITIVE CONTROL, and the tool refuses to report without it. `--control <token>` names an
identifier known to have vanished silently; if the walk does not rediscover it, the walk
is broken and any empty result would be meaningless rather than clean. Default control is
`walletsCache`, the picker's own state variable.

LIMITS, stated rather than discovered later:
  - A renamed identifier reads as vanished. That is a FEATURE for this purpose (a rename
    that loses behaviour is the same defect) and noise otherwise, so read the report.
  - It sees declarations, not behaviour. A function that still exists and stopped working
    is invisible here.
  - It is bounded by --max-commits so it cannot hang; a truncated walk SAYS so.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Declarations worth treating as "a thing someone built". Deliberately narrow: a loose
# pattern floods the report and a flooded report gets ignored, which is the same as no report.
DECL = re.compile(
    r"^\+.*?\b(?:"
    r"function\s+([A-Za-z_$][\w$]{3,})"  # js function foo()
    # Any js binding, not just one assigned a function. The first version required
    # `= function` or `= (`, which silently missed `var walletsCache=[]` -- the picker's
    # own state, i.e. the exact identifier this tool exists to rediscover. The positive
    # control caught that before any result was reported.
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]{5,})\s*="
    r"|def\s+([a-z_][\w]{4,})"  # python def foo
    r"|fn\s+([a-z_][\w]{4,})"  # rust fn foo
    r"|class=[\"']([a-z][\w-]{4,})[\"']"  # css class in markup
    r"|id=[\"']([a-z][\w-]{3,})[\"']"  # element id
    r")"
)

SKIP = (
    "vendor/",
    "target/",
    "node_modules/",
    "/dist/",
    ".min.",
    "Cargo.lock",
    "package-lock",
)


def sh(args: list[str], timeout: int = 240) -> str:
    r = subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return r.stdout or ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--paths", nargs="*", default=["webshop-pay/", "index.html"])
    ap.add_argument("--max-commits", type=int, default=400)
    ap.add_argument("--control", default="walletsCache")
    args = ap.parse_args()

    print(f"scope: {' '.join(args.paths)}   max-commits: {args.max_commits}")

    # 1. every identifier ever DECLARED, with the commit that introduced it
    log = sh(
        [
            "git",
            "log",
            "--all",
            f"-n{args.max_commits}",
            "-p",
            "--unified=0",
            "--format=@@%H|%s",
            "--",
        ]
        + args.paths
    )

    born: dict[str, tuple[str, str]] = {}
    cur_sha = cur_subj = ""
    for line in log.splitlines():
        if line.startswith("@@") and "|" in line:
            cur_sha, _, cur_subj = line[2:].partition("|")
            continue
        if not line.startswith("+") or any(s in line for s in SKIP):
            continue
        m = DECL.match(line)
        if m:
            name = next(g for g in m.groups() if g)
            born.setdefault(name, (cur_sha, cur_subj))

    print(f"identifiers ever declared in scope: {len(born)}")
    if not born:
        print("FAIL: the walk found nothing. The scope or the patterns are wrong.")
        return 2

    # 2. which are absent from the working tree now
    head = sh(
        # WORKING TREE, not HEAD. Reading HEAD made the gate report a restoration as still missing
        # until it was committed, which is backwards: the whole point is to catch a loss BEFORE it
        # lands. In CI the working tree is the commit, so this is identical there and honest here.
        ["git", "grep", "-h", "-o", "-E", r"[A-Za-z_$][A-Za-z0-9_$-]{3,}", "--"]
        + args.paths
    )
    present = set(head.split())
    # POSIX ERE, NOT pcre: `\w` is not portable inside git grep -E and matched NOTHING,
    # which left `present` empty and reported 163 of 163 identifiers as vanished. An
    # all-vanished verdict is the uniformity signature of a parser that never matched,
    # never a finding about the repo. This floor makes that failure loud.
    if len(present) < 50:
        print(f"FAIL: only {len(present)} identifiers readable at HEAD, so every one")
        print("      would read as vanished. The extraction is broken. Not reporting.")
        return 2
    vanished = {n: v for n, v in born.items() if n not in present}

    # 3. POSITIVE CONTROL before believing any verdict
    ctl = args.control
    ctl_ok = ctl in born and ctl not in present
    print(
        f"positive control {ctl!r}: ever-declared={ctl in born}  absent-now={ctl not in present}  -> {'OK' if ctl_ok else 'BROKEN'}"
    )
    if not ctl_ok:
        print("REFUSING to report: the control did not reproduce, so an empty or short")
        print("result would be a fact about this tool rather than about the repo.")
        return 2

    print(f"\nvanished identifiers: {len(vanished)}\n")

    # 4. silent vs deliberate: did the removing commit say so?
    silent: list[tuple[str, str, str, str]] = []
    for name, (bsha, bsubj) in sorted(vanished.items()):
        out = sh(
            ["git", "log", "--all", "-n1", "--format=%h|%s", "-S", name, "--"]
            + args.paths,
            timeout=60,
        ).strip()
        if not out:
            continue
        rsha, _, rsubj = out.partition("|")
        if name.lower() not in rsubj.lower():
            silent.append((name, bsha[:7], bsubj, f"{rsha} {rsubj}"))

    by_removal: dict[str, list[str]] = defaultdict(list)
    for name, _b, _bs, removal in silent:
        by_removal[removal].append(name)

    print(
        f"SILENT REGRESSION CANDIDATES: {len(silent)} identifier(s) in {len(by_removal)} commit(s)\n"
    )
    for removal, names in sorted(by_removal.items(), key=lambda kv: -len(kv[1])):
        print(f"  removed by: {removal[:96]}")
        print(
            f"    lost {len(names)}: {', '.join(sorted(names)[:8])}{' ...' if len(names) > 8 else ''}"
        )
        print()

    # BASELINE. Everything already lost is recorded once, with a reason, so this gate
    # reports only what is NEW. Without it the gate is red from birth, and a gate that is
    # red on a healthy tree gets learned around, which is worse than no gate at all.
    base_path = ROOT / "scripts" / "silent-regressions-baseline.json"
    accepted: dict[str, str] = {}
    if base_path.exists():
        accepted = json.loads(base_path.read_text(encoding="utf-8")).get("accepted", {})

    new = [s for s in silent if s[0] not in accepted]
    print(f"baseline accepts {len(accepted)}; NEW since baseline: {len(new)}")
    if not new:
        print("\nPASS  nothing that once existed has vanished without being recorded.")
        return 0

    print(
        "\nFAIL  these were declared once, are gone now, and no commit message says so:"
    )
    for name, bsha, bsubj, removal in new:
        print(f"    {name}")
        print(f"      born  {bsha}  {bsubj[:76]}")
        print(f"      lost  {removal[:82]}")
    print(
        "\n  Restore it, or record it in scripts/silent-regressions-baseline.json with"
    )
    print("  a reason. Recording is cheap; the point is that it stops being SILENT.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
