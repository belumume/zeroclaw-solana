#!/usr/bin/env python3
"""Controls for check-root-divergence.py.

Run from the repository root:  python3 scripts/test_check_root_divergence.py

Every case builds a synthetic PAIR of git roots, plants exactly one condition, and requires the
verdict it should produce. Synthetic because the real pair's state changes with every merge, so a
suite pinned to it would report the repo's mood rather than the checker's behaviour.

THE TWO CASES THAT MATTER MOST are the ones the real pair produced:
  - a must-match path differing must FAIL, because that is one root enforcing something the other
    does not, and it is the whole reason this exists
  - a JSON file differing only in SERIALISATION must NOT be reported, because the real proof bundle
    differs by 42 bytes across the roots while carrying identical data, and calling that a divergent
    proof bundle would be the most alarming thing this checker could say and would be false

Stdlib only. Touches no network and nothing outside a temp directory.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "check-root-divergence.py"

AGREE, DIVERGED, CANNOT = 0, 1, 2

# The gate needs the intersection above its floor before it will judge anything, so every case
# plants filler. Named so the floor itself is visibly satisfied rather than accidentally.
FILLER = 200

# Named rather than written inline, because a backslash escape in a bytes literal is what a
# shell heredoc mangles, and this file has already been rewritten once for that reason.
NL = bytes([10])
CRNL = bytes([13, 10])


def _force_rw(func, path, exc):
    """rmtree onexc handler: drop the read-only attribute git sets, then retry once."""
    try:
        os.chmod(path, 0o700)
        func(path)
    except Exception:
        pass


def build_pair(tmp: pathlib.Path, mutate) -> tuple[pathlib.Path, pathlib.Path]:
    """Two git roots with identical content, then `mutate(a, b)` plants the case's condition."""
    a, b = tmp / "trunk", tmp / "other"
    for r in (a, b):
        (r / "scripts").mkdir(parents=True)
        (r / "docs" / "proof-bundle").mkdir(parents=True)
        (r / ".github" / "workflows").mkdir(parents=True)
        for i in range(FILLER):
            (r / f"f{i:03d}.txt").write_text(f"shared {i}\n", encoding="utf-8")
        (r / "scripts" / "check-example.py").write_text(
            "print('gate')\n", encoding="utf-8"
        )
        (r / ".github" / "workflows" / "ci.yml").write_text(
            "on: push\n", encoding="utf-8"
        )
        (r / "docs" / "proof-bundle" / "b.json").write_text(
            json.dumps({"tx": [1, 2, 3]}), encoding="utf-8"
        )
        subprocess.run(["git", "-C", str(r), "init", "-q"], check=True)
        subprocess.run(
            ["git", "-C", str(r), "add", "-A"], check=True, capture_output=True
        )
    shutil.copy2(GATE, a / "scripts" / GATE.name)
    subprocess.run(["git", "-C", str(a), "add", "-A"], check=True, capture_output=True)
    mutate(a, b)
    return a, b


def run(a: pathlib.Path, b: pathlib.Path) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(a / "scripts" / GATE.name)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "ZC_OTHER_ROOT": str(b)},
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def nothing(a, b):
    pass


def divergent_gate(a, b):
    (b / "scripts" / "check-example.py").write_text(
        "print('OLD gate')\n", encoding="utf-8"
    )


def divergent_workflow(a, b):
    (b / ".github" / "workflows" / "ci.yml").write_text(
        "on: pull_request\n", encoding="utf-8"
    )


def divergent_ordinary(a, b):
    (b / "f001.txt").write_text("in flight\n", encoding="utf-8")


def json_reserialised(a, b):
    # Same data, different bytes: the real proof bundle's exact situation.
    (b / "docs" / "proof-bundle" / "b.json").write_text(
        json.dumps({"tx": [1, 2, 3]}, indent=2) + "\n", encoding="utf-8"
    )


def json_data_changed(a, b):
    (b / "docs" / "proof-bundle" / "b.json").write_text(
        json.dumps({"tx": [1, 2, 4]}), encoding="utf-8"
    )


def other_root_absent(a, b):
    # Renamed rather than deleted. Git marks its object files READ-ONLY, so `shutil.rmtree` fails
    # on Windows with WinError 5, and the gate's own test for a second root is whether `.git`
    # exists, so a rename exercises exactly the branch a delete would.
    (b / ".git").rename(b / ".notgit")


def crlf_only(a, b):
    """The real defect: a must-match path identical apart from checkout line endings."""
    src = (a / "scripts" / "check-example.py").read_bytes()
    # Normalised FIRST. `write_text` in build_pair already applied the platform ending on
    # Windows, so a bare NL->CRNL replace produces CR CR LF and plants a real difference
    # rather than an ending-only one. The fixture hit the exact trap the gate now handles.
    (b / "scripts" / "check-example.py").write_bytes(src.replace(CRNL, NL).replace(NL, CRNL))


def crlf_plus_real_change(a, b):
    """Over-correction control: normalising endings must not swallow a real change."""
    src = (a / "scripts" / "check-example.py").read_bytes()
    (b / "scripts" / "check-example.py").write_bytes(
        src.replace(CRNL, NL).replace(NL, CRNL).replace(b"gate", b"OLD gate")
    )


def floor_broken(a, b):
    for i in range(FILLER):
        (b / f"f{i:03d}.txt").unlink()
    subprocess.run(["git", "-C", str(b), "add", "-A"], check=True, capture_output=True)


CASES = [
    ("identical roots agree", nothing, AGREE, None),
    # The two the real pair produced.
    ("a divergent GATE fails", divergent_gate, DIVERGED, "check-example.py"),
    ("a divergent CI WORKFLOW fails", divergent_workflow, DIVERGED, "ci.yml"),
    (
        "a proof bundle differing only in SERIALISATION is not reported",
        json_reserialised,
        AGREE,
        None,
    ),
    # The over-correction control for the case above: parsed comparison must not swallow real
    # data drift, which would be the worst possible false clean.
    (
        "a proof bundle whose DATA changed still fails",
        json_data_changed,
        DIVERGED,
        "b.json",
    ),
    # In-flight difference on an ordinary path is reported and does NOT gate, because two live
    # branches should diverge and a permanently red gate gets ignored.
    (
        "an ordinary in-flight difference does not gate",
        divergent_ordinary,
        AGREE,
        "INFO",
    ),
    (
        "a must-match path differing ONLY in line endings is not reported",
        crlf_only,
        AGREE,
        None,
    ),
    (
        "normalising endings does NOT swallow a real change (over-correction control)",
        crlf_plus_real_change,
        DIVERGED,
        "check-example.py",
    ),
    # Not-applicable and could-not-check, kept distinct from both agree and diverged.
    (
        "an absent second root SKIPS rather than passing silently",
        other_root_absent,
        AGREE,
        "SKIP",
    ),
    (
        "too small an intersection is CANNOT-CHECK, not a pass",
        floor_broken,
        CANNOT,
        "too small",
    ),
]


def main() -> int:
    names = {AGREE: "agree", DIVERGED: "diverged", CANNOT: "cannot-check"}
    passed = failed = 0
    for desc, mutate, want, must_say in CASES:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="rootdiv-"))
        try:
            a, b = build_pair(tmp, mutate)
            rc, out = run(a, b)
            ok = rc == want and (must_say is None or must_say in out)
            print(f"{'PASS' if ok else 'FAIL'}  [{names[want]:12s}] {desc}")
            if not ok:
                failed += 1
                print(
                    f"        wanted rc={want}"
                    + (f" and {must_say!r}" if must_say else "")
                )
                print(f"        got rc={rc}: {out.strip()[:200]}")
            else:
                passed += 1
        finally:
            # Git object files carry the READ-ONLY attribute on Windows, so a plain
            # rmtree raises WinError 5. Clear the bit and retry rather than passing
            # ignore_errors, which would silently leave a git tree per case behind.
            shutil.rmtree(tmp, onexc=_force_rw)
    print(f"\nRESULT: {passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
