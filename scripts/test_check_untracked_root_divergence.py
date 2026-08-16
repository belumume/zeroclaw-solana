#!/usr/bin/env python3
"""Controls for check-untracked-root-divergence.py.

Run from the repository root:  python3 scripts/test_check_untracked_root_divergence.py

Every case builds a synthetic PAIR of git roots, plants exactly one condition among their
UNTRACKED internal documents, and requires the verdict it should produce. Synthetic because the
real pair's internal documents change every session, so a suite pinned to them would report the
repo's mood rather than the checker's behaviour.

THE TWO CASES THAT MATTER MOST are the pair the brief for this gate demanded, because without
both an allowlist is indistinguishable from a gate that never fires:
  - an UNDECLARED internal document differing must FAIL and must NAME the file
  - a DECLARED one differing must be silent, because some of these are supposed to differ

MUTATION CONTROLS AT THE BOTTOM prove both halves are load-bearing rather than agreeable: one
removes the undeclared branch and requires the must-fire case to go green, the other empties the
allowlist and requires the must-be-silent case to go red. Each asserts its anchor is present
before substituting, so a stale anchor fails loudly instead of certifying an unmodified file.

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
GATE = ROOT / "scripts" / "check-untracked-root-divergence.py"
SIBLING = ROOT / "scripts" / "check-root-divergence.py"

AGREE, DIVERGED, CANNOT = 0, 1, 2

# The gate needs at least MIN_SHARED shared untracked documents before it will judge anything, so
# every case plants more than that. Named so the floor is visibly satisfied rather than by luck.
DOCS = 8

# Named rather than written inline, because a backslash escape in a bytes literal is what a shell
# heredoc mangles, and this repo has already had a fixture rewritten for that reason.
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
    """Two roots with identical internal documents, then `mutate(a, b)` plants the condition."""
    a, b = tmp / "trunk", tmp / "other"
    for r in (a, b):
        (r / "scripts").mkdir(parents=True)
        (r / ".claude").mkdir(parents=True)
        (r / "docs").mkdir(parents=True)
        # Tracked filler, so the roots look like real checkouts and `git ls-files` is non-empty.
        (r / "README.md").write_text("tracked\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(r), "init", "-q"], check=True)
        subprocess.run(
            ["git", "-C", str(r), "add", "-A"], check=True, capture_output=True
        )
        # UNTRACKED internal documents, written AFTER the add so git never indexes them. This is
        # what the gate exists to compare and what its sibling structurally cannot see.
        for i in range(DOCS):
            (r / ".claude" / f"hookify.rule{i}.local.md").write_text(
                f"rule {i}\n", encoding="utf-8"
            )
        # A real DECLARED key, so the allowlist cases exercise the shipped allowlist rather than
        # a fixture-only path that could pass while the real entry was wrong.
        (r / "CLAUDE.local.md").write_text("root state\n", encoding="utf-8")
        # The hardlinked mandate. Written as BYTES so the two roots are byte-identical whatever
        # the platform does to newlines, which is the property the real hardlink guarantees.
        (r / ".claude" / "MANDATE.md").write_bytes(b"the operator's own words\n")
        (r / "docs" / "listing-verbatim.json").write_text(
            json.dumps({"deadline": "2026-08-07", "title": "zeroclaw"}),
            encoding="utf-8",
        )
    shutil.copy2(GATE, a / "scripts" / GATE.name)
    shutil.copy2(SIBLING, a / "scripts" / SIBLING.name)
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


def undeclared_differs(a, b):
    """The whole reason this gate exists: an agent-config rule tightened in one root only."""
    (b / ".claude" / "hookify.rule3.local.md").write_text(
        "rule 3 TIGHTENED\n", encoding="utf-8"
    )


def declared_differs(a, b):
    """A path the allowlist declares. Must be silent, or the gate is red on day one."""
    (b / "CLAUDE.local.md").write_text("the other root's own state\n", encoding="utf-8")


def declared_json_differs(a, b):
    """The listing capture: parsed-unequal because a schema change dropped a key."""
    (b / "docs" / "listing-verbatim.json").write_text(
        json.dumps(
            {"deadline": "2026-08-07", "title": "zeroclaw", "updatedAt": "2026-07-22"}
        ),
        encoding="utf-8",
    )


def json_reserialised(a, b):
    """Same data, different bytes. Must not be reported, declared or not."""
    (b / "docs" / "listing-verbatim.json").write_text(
        json.dumps({"title": "zeroclaw", "deadline": "2026-08-07"}, indent=2) + "\n",
        encoding="utf-8",
    )


def hardlink_broke(a, b):
    """The measured signature of a broken hardlink: SAME byte count, different content.

    `.claude/MANDATE.md` is one inode shared by both roots, so it is identical by construction and
    deliberately absent from DECLARED: while the link holds this gate says nothing, and if it
    breaks the gate becomes a second detector for free. An in-place append keeps the link; an
    atomic write-then-rename breaks it, which is what the Edit tool does. The break that was
    actually observed left both paths the SAME SIZE, so this case exists to keep anyone from
    adding a size or mtime pre-filter as an optimisation. Byte counts are asserted equal here so
    the fixture cannot silently stop testing that.
    """
    p, q = a / ".claude" / "MANDATE.md", b / ".claude" / "MANDATE.md"
    q.write_bytes(b"the operator's OWN words\n")
    assert len(p.read_bytes()) == len(q.read_bytes()), "fixture must be size-identical"


def crlf_only(a, b):
    """An undeclared document identical apart from checkout line endings."""
    src = (a / ".claude" / "hookify.rule3.local.md").read_bytes()
    (b / ".claude" / "hookify.rule3.local.md").write_bytes(
        src.replace(CRNL, NL).replace(NL, CRNL)
    )


def crlf_plus_real_change(a, b):
    """Over-correction control: normalising endings must not swallow a real change."""
    src = (a / ".claude" / "hookify.rule3.local.md").read_bytes()
    (b / ".claude" / "hookify.rule3.local.md").write_bytes(
        src.replace(CRNL, NL).replace(NL, CRNL).replace(b"rule 3", b"rule 3 TIGHTENED")
    )


def became_tracked(a, b):
    """A shared document committed in one root only. Reported, not gating."""
    subprocess.run(
        ["git", "-C", str(b), "add", "-f", ".claude/hookify.rule5.local.md"],
        check=True,
        capture_output=True,
    )


def only_in_one_root(a, b):
    """A document the trunk has and the other does not. Scope, not drift: must be silent."""
    (a / "docs" / "TRUNK-ONLY.md").write_text("mine alone\n", encoding="utf-8")


def worktree_ignored(a, b):
    """An agent worktree under .claude/ must not be walked as internal documents."""
    wt = b / ".claude" / "worktrees" / "agent-x"
    wt.mkdir(parents=True)
    (wt / "CLAUDE.local.md").write_text("a whole other checkout\n", encoding="utf-8")


def other_root_absent(a, b):
    # Renamed rather than deleted: git marks its object files READ-ONLY, so rmtree fails on
    # Windows with WinError 5, and the gate's test for a second root is whether `.git` exists.
    (b / ".git").rename(b / ".notgit")


def floor_broken(a, b):
    for i in range(DOCS):
        (b / ".claude" / f"hookify.rule{i}.local.md").unlink()


def sibling_missing(a, b):
    """The comparison lives in the sibling gate. Losing it must be cannot-check, not a pass."""
    (a / "scripts" / SIBLING.name).unlink()


CASES = [
    ("identical internal documents agree", nothing, AGREE, None),
    # The pair that makes the allowlist meaningful. Neither alone proves anything.
    (
        "an UNDECLARED internal document differing FAILS and names the file",
        undeclared_differs,
        DIVERGED,
        "hookify.rule3.local.md",
    ),
    (
        "a DECLARED divergence is silent",
        declared_differs,
        AGREE,
        "CLAUDE.local.md",
    ),
    (
        "a DECLARED capture whose parsed data differs is still silent",
        declared_json_differs,
        AGREE,
        "listing-verbatim.json",
    ),
    (
        "a broken hardlink is caught even though both copies are the SAME SIZE",
        hardlink_broke,
        DIVERGED,
        "MANDATE.md",
    ),
    (
        "a JSON document differing only in SERIALISATION is not reported",
        json_reserialised,
        AGREE,
        None,
    ),
    (
        "a document differing ONLY in line endings is not reported",
        crlf_only,
        AGREE,
        None,
    ),
    (
        "normalising endings does NOT swallow a real change (over-correction control)",
        crlf_plus_real_change,
        DIVERGED,
        "hookify.rule3.local.md",
    ),
    (
        "a document tracked in one root only is reported and does not gate",
        became_tracked,
        AGREE,
        "TRACKED in the",
    ),
    (
        "a document present in one root only is scope, not drift",
        only_in_one_root,
        AGREE,
        None,
    ),
    (
        "an agent worktree under .claude/ is not walked",
        worktree_ignored,
        AGREE,
        None,
    ),
    # Not-applicable and could-not-check, kept distinct from both agree and diverged.
    (
        "an absent second root is CANNOT-CHECK, not a pass",
        other_root_absent,
        CANNOT,
        "nothing to compare",
    ),
    (
        "too few shared documents is CANNOT-CHECK, not a pass",
        floor_broken,
        CANNOT,
        "too little",
    ),
    (
        "losing the borrowed comparison is CANNOT-CHECK, not a pass",
        sibling_missing,
        CANNOT,
        "could not load the comparison",
    ),
]


# --- mutation controls -------------------------------------------------------------------
# Each replaces one line of the gate with an equally-indented substitute, so a mutant that fails
# to compile cannot masquerade as the silence a must-not-fire case wants. The anchor is asserted
# present first: a stale anchor would leave the gate byte-identical and the control would pass
# while testing nothing.

MUTATIONS = [
    (
        "removing the undeclared branch makes the must-fire case go green",
        "            (declared_diff if rel in DECLARED else undeclared).append(rel)",
        # Keeps `declared_diff` correctly populated and only removes the undeclared append. An
        # earlier form sent EVERY divergence to `declared_diff`, which then raised a KeyError
        # printing a reason that does not exist -- rc=1 from a crash, indistinguishable from the
        # gate's own rc=1, and the control reported a false failure until it was read.
        "            declared_diff.append(rel) if rel in DECLARED else None",
        undeclared_differs,
        DIVERGED,
    ),
    (
        "emptying the allowlist makes the must-be-silent case go red",
        "DECLARED = {",
        "DECLARED = {} and {",
        declared_differs,
        AGREE,
    ),
]


def run_mutation(desc, anchor, replacement, mutate, was) -> bool:
    src = GATE.read_text(encoding="utf-8")
    if anchor not in src:
        print(f"FAIL  [mutation   ] {desc}")
        print(f"        anchor not found in the gate: {anchor!r}")
        print("        The control is stale and is testing an unmodified file.")
        return False
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="untrackdiv-mut-"))
    try:
        a, b = build_pair(tmp, mutate)
        (a / "scripts" / GATE.name).write_text(
            src.replace(anchor, replacement, 1), encoding="utf-8"
        )
        rc, out = run(a, b)
        # The unmutated gate returns `was` on this case. The control passes only when the mutant
        # stops doing that -- and a crashing mutant returns neither, so it is a failure too.
        ok = rc != was and rc in (AGREE, DIVERGED)
        print(f"{'PASS' if ok else 'FAIL'}  [mutation   ] {desc}")
        if not ok:
            print(f"        wanted a verdict other than rc={was}, got rc={rc}")
            print(f"        {out.strip()[:200]}")
        return ok
    finally:
        shutil.rmtree(tmp, onexc=_force_rw)


def main() -> int:
    names = {AGREE: "agree", DIVERGED: "diverged", CANNOT: "cannot-check"}
    passed = failed = 0
    for desc, mutate, want, must_say in CASES:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="untrackdiv-"))
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
                print(f"        got rc={rc}: {out.strip()[:300]}")
            else:
                passed += 1
        finally:
            # Git object files carry the READ-ONLY attribute on Windows, so a plain rmtree raises
            # WinError 5. Clear the bit and retry rather than passing ignore_errors, which would
            # silently leave a git tree per case behind.
            shutil.rmtree(tmp, onexc=_force_rw)

    for desc, anchor, replacement, mutate, was in MUTATIONS:
        if run_mutation(desc, anchor, replacement, mutate, was):
            passed += 1
        else:
            failed += 1

    print(f"\nRESULT: {passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
