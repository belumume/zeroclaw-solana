#!/usr/bin/env python3
"""Prove the always-loaded half of `check-plugin-count-agreement.py` is load-bearing. (stdlib only)

    python3 scripts/mutation-check-plugin-count-agreement.py

Exit 0 = every control behaved. 1 = at least one did not. 2 = the controls could not run.

WHY THE SELFTEST IS NOT ENOUGH HERE. That suite proves the gate returns the right verdict on
inputs it was handed. It cannot prove the verdict came from the code the widening added: a gate
that reddened on everything, and a marker that exempted everything, both pass a suite of positive
cases. Each control below disables ONE of the two new pieces and requires the verdict to flip.

WHY IT IS HERMETIC. The always-loaded tier is gitignored, so it exists in the trunk root and in no
clone, no runner and no agent worktree. A control that could only run in one directory on one
machine would report not-applicable on every CI run, and a step that can only skip is a green
check asserting nothing. So this builds its own fixture root in a temp directory -- one tracked
plugin, the declared tracked surfaces, and a CLAUDE.local.md importing a gitignored-shaped file --
and drives the real gate against it through `--root`.

THREE PROPERTIES EACH CONTROL HOLDS, because each has cost this repo a false green before:
  - the mutation ANCHOR is asserted present before substituting. An anchor that has drifted out
    of the source produces a byte-identical copy, and the control then certifies the real gate.
  - the anchor's INDENTATION is preserved. A replacement dedented against its block is an
    IndentationError, and a mutant that cannot start looks exactly like a mutant that did not
    fire -- silently green for any must-not-fire case.
  - an exit code OUTSIDE the gate's own vocabulary (0, 1, 2) is FAILURE for every control, not
    silence. That is what separates "did not detect" from "could not start".
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "check-plugin-count-agreement.py"
CANNOT_CHECK = 2
VOCABULARY = (0, 1, 2)  # anything else means the mutant never ran

# AN EXIT CODE ALONE CANNOT TELL A CRASH FROM A VERDICT, and the collision is exactly on the code
# a control wants: a mutant with a syntax or indentation error exits 1, which is also the gate's
# own "a claim disagrees". Control C expects 1, so on the exit code alone it would go green
# against a mutant that never parsed. This line is the gate's first output, so a mutant that
# prints it reached the check; a mutant that could not start cannot forge it.
STARTED_MARKER = "plugin directories tracked"


def run(script: pathlib.Path, root: pathlib.Path) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, str(script), "--root", str(root)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(ROOT),
    )
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def report(name: str, ok: bool, detail: str) -> bool:
    print(f"  {'ok  ' if ok else 'FAIL'} {name:<52} {detail}")
    return ok


def fixture(
    tmp: pathlib.Path, surfaces: tuple[str, ...], always_loaded_body: str
) -> None:
    """One tracked plugin, correct tracked prose, and an always-loaded tier carrying the body."""
    (tmp / "plugins" / "p0" / "src").mkdir(parents=True)
    (tmp / "plugins" / "p0" / "src" / "lib.rs").write_text("", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp), "init", "-q"], capture_output=True)
    subprocess.run(["git", "-C", str(tmp), "add", "-A"], capture_output=True)
    for rel in surfaces:
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("`plugins/` holds all one components.\n", encoding="utf-8")
    (tmp / "CLAUDE.local.md").write_text("@NOTES.md\n", encoding="utf-8")
    (tmp / "NOTES.md").write_text(always_loaded_body, encoding="utf-8")


def mutate(src: str, anchor: str, replacement: str) -> str | None:
    """Substitute once, or None if the anchor is gone. Indentation is the caller's to preserve."""
    if anchor not in src:
        return None
    out = src.replace(anchor, replacement, 1)
    return None if out == src else out


def main() -> int:
    if not GATE.is_file():
        print(f"CANNOT VERIFY  no gate at {GATE.name}")
        return CANNOT_CHECK
    src = GATE.read_text(encoding="utf-8")
    sys.path.insert(0, str(GATE.parent))
    import importlib.util

    spec = importlib.util.spec_from_file_location("_pca", GATE)
    if spec is None or spec.loader is None:
        print("CANNOT VERIFY  the gate could not be loaded")
        return CANNOT_CHECK
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    print("controls for check-plugin-count-agreement.py (always-loaded scope)\n")
    ok = True

    with tempfile.TemporaryDirectory() as td:
        base = pathlib.Path(td)

        # ---- A: the real gate, both verdicts, on a tree where ONLY the gitignored file is wrong.
        good = base / "good"
        good.mkdir()
        fixture(good, mod.SURFACES, "The suite covers all one components.\n")
        rc, out = run(GATE, good)
        ok &= report("A1 always-loaded prose correct -> PASS", rc == 0, f"rc={rc}")

        bad = base / "bad"
        bad.mkdir()
        fixture(bad, mod.SURFACES, "The suite covers all 8 components.\n")
        rc_bad, out_bad = run(GATE, bad)
        ok &= report(
            "A2 wrong count in the gitignored file -> FAIL",
            rc_bad == 1 and "NOTES.md:1" in out_bad,
            f"rc={rc_bad}",
        )

        marked = base / "marked"
        marked.mkdir()
        fixture(marked, mod.SURFACES, "HISTORICAL: it covered all 8 components.\n")
        rc_mk, out_mk = run(GATE, marked)
        ok &= report(
            "A3 the same wrong count, marked as a record -> PASS and REPORTED",
            rc_mk == 0 and "exempt" in out_mk and "NOTES.md:1" in out_mk,
            f"rc={rc_mk}",
        )

        # ---- B: THE SCOPE IS LOAD-BEARING. Neuter the always-loaded walk and A2 must stop
        # failing. Without this, A2 is equally true of a gate that reddens on the tracked
        # surfaces for some unrelated reason.
        anchor_b = "    entry = root / ALWAYS_LOADED_ENTRY\n    if not entry.is_file():"
        mutant_b = mutate(
            src, anchor_b, "    entry = root / ALWAYS_LOADED_ENTRY\n    if True:"
        )
        if mutant_b is None:
            ok &= report(
                "B  scope mutant",
                False,
                "the anchor is gone; this control tests nothing",
            )
        else:
            p = GATE.parent / "_mutant_pca_scope.py"
            try:
                p.write_text(mutant_b, encoding="utf-8")
                rc_m, out_m = run(p, bad)
            finally:
                p.unlink(missing_ok=True)
            started = rc_m in VOCABULARY and STARTED_MARKER in out_m
            ok &= report(
                "B  scope disabled -> the same tree stops failing",
                started and rc_m == 0 and "NOT CHECKED" in out_m,
                f"rc={rc_m}" + ("" if started else "  MUTANT DID NOT START"),
            )

        # ---- C: THE EXEMPTION IS LOAD-BEARING, and this is the control that stops the marker
        # from being a blanket. Neuter it and A3's marked record must be reported as a failure,
        # which proves the exemption is what kept it quiet rather than the claim being invisible.
        anchor_c = "            if marker is not None:"
        mutant_c = mutate(src, anchor_c, "            if False:")
        if mutant_c is None:
            ok &= report(
                "C  exemption mutant",
                False,
                "the anchor is gone; this control tests nothing",
            )
        else:
            p = GATE.parent / "_mutant_pca_exempt.py"
            try:
                p.write_text(mutant_c, encoding="utf-8")
                rc_m, out_m = run(p, marked)
            finally:
                p.unlink(missing_ok=True)
            started = rc_m in VOCABULARY and STARTED_MARKER in out_m
            ok &= report(
                "C  exemption disabled -> the marked record now FAILS",
                started and rc_m == 1 and "NOTES.md:1" in out_m,
                f"rc={rc_m}" + ("" if started else "  MUTANT DID NOT START"),
            )

        # ---- D: A COLLAPSED DERIVATION IS NOT A PASS. An entry point that yields no imports is
        # the shape a renamed import or a changed syntax leaves, and it must be cannot-check.
        collapsed = base / "collapsed"
        collapsed.mkdir()
        fixture(collapsed, mod.SURFACES, "nothing\n")
        (collapsed / "CLAUDE.local.md").write_text("no imports\n", encoding="utf-8")
        rc, out = run(GATE, collapsed)
        ok &= report(
            "D  entry point yielding zero imports -> CANNOT CHECK",
            rc == CANNOT_CHECK and "ZERO @-imports" in out,
            f"rc={rc}",
        )

        # ---- E: ABSENT IS NOT BROKEN. Every clone and runner is in this shape, so a gate that
        # failed here would be red on arrival and would be routed around by the second day.
        absent = base / "absent"
        absent.mkdir()
        fixture(absent, mod.SURFACES, "unused\n")
        (absent / "CLAUDE.local.md").unlink()
        rc, out = run(GATE, absent)
        ok &= report(
            "E  no entry point -> PASS, and says the tier was NOT CHECKED",
            rc == 0 and "NOT CHECKED" in out,
            f"rc={rc}",
        )

    print()
    if ok:
        print(
            "all controls behaved; the always-loaded scope and its exemption both do work"
        )
        return 0
    print(
        "a control did not behave, so this gate's always-loaded verdict is not yet evidence"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
