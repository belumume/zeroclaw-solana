"""Shoot every terminal beat as a keepable take, warming the live ones first.

take.py shoots ONE beat and gates the frame. This drives the whole set in the
order the shoot notes ask for: offline beats first, because they are
byte-identical across runs and cannot fail mid-take, then the network beats
each warmed immediately before rolling.

The warm-up is not a courtesy. Four of these hit the network and three of them
have been measured failing on a cold first call while passing on the retry
seconds later, so a cold take films a hang rather than a defect. --dry-run runs
the command in this shell without a window, which is exactly a warm-up.

A beat that fails is RE-SHOT ONCE and then reported red rather than retried
forever: the documented transient clears on the second attempt, and anything
surviving two attempts is a real finding that belongs in the report instead of
being buried under a third roll.

Usage:
    python demo/shoot_all.py              # every beat
    python demo/shoot_all.py --only a,b   # a subset, same ordering rules
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAKE = ROOT / "demo" / "take.py"
TAKES_DIR = ROOT / ".demo-assets" / "takes"

# Offline beats are byte-identical across runs, so they anchor the session: if
# one of these fails the rig is broken rather than the network.
OFFLINE = ["mainnet-refusal", "injection-certify", "coherence-gate"]

# Live beats, each warmed immediately before its take.
NETWORK = [
    "feed-heartbeat",
    "x402-challenge",
    "x402-nonce",
    "replay-probe",
    "chain-history",
    "x402-earnings",
    "reproducibility",
    "clean-clone",
]


def run(args: list[str], timeout: int) -> tuple[int, str]:
    try:
        p = subprocess.run(
            [sys.executable, str(TAKE), *args],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s"


def shoot(beat: str, warm: bool) -> tuple[bool, str, float]:
    if warm:
        rc, _ = run(["--beat", beat, "--dry-run"], timeout=180)
        # A cold dry-run failure is information, not a stop: the take itself is
        # the measurement and a warmed retry is what the notes prescribe.
        if rc != 0:
            time.sleep(2)
            run(["--beat", beat, "--dry-run"], timeout=180)
        time.sleep(1)

    t0 = time.time()
    rc, out = run(["--beat", beat], timeout=300)
    if rc != 0:
        time.sleep(3)
        rc, out = run(["--beat", beat], timeout=300)
    return (
        rc == 0,
        out.strip().splitlines()[-1] if out.strip() else "(no output)",
        time.time() - t0,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated beat names")
    args = ap.parse_args()

    plan = [(b, False) for b in OFFLINE] + [(b, True) for b in NETWORK]
    if args.only:
        want = {s.strip() for s in args.only.split(",")}
        plan = [(b, w) for b, w in plan if b in want]
        missing = want - {b for b, _ in plan}
        if missing:
            print(f"unknown beat(s): {', '.join(sorted(missing))}", flush=True)
            return 2

    results = []
    for i, (beat, warm) in enumerate(plan, 1):
        print(f"[{i}/{len(plan)}] {beat}{' (warming)' if warm else ''} ...", flush=True)
        ok, last, secs = shoot(beat, warm)
        mp4 = TAKES_DIR / f"{beat}.mp4"
        size = mp4.stat().st_size if mp4.exists() else 0
        results.append((beat, ok, size, secs))
        print(
            f"    {'PASS' if ok else 'FAIL'}  {secs:5.1f}s  {size:>9,} B  {last[:100]}",
            flush=True,
        )

    print("\n=== SHOOT SUMMARY ===", flush=True)
    passed = [r for r in results if r[1]]
    for beat, ok, size, secs in results:
        print(
            f"{'PASS' if ok else 'FAIL'}  {beat:20s} {size:>9,} B  {secs:5.1f}s",
            flush=True,
        )
    print(f"\n{len(passed)}/{len(results)} beats shot", flush=True)
    return 0 if len(passed) == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
