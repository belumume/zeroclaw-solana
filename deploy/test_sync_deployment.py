#!/usr/bin/env python3
"""Drive deploy/sync_workspace.py's REAL main() against an isolated fake box. (stdlib only)

    python3 deploy/test_sync_deployment.py

WHY THIS EXISTS SEPARATELY FROM `--selftest`. That suite exercises the helper functions, which is
where the copy and compare logic lives. It cannot reach main(), and main() is where the ORDER of the
refusals is decided and where a guard can be perfectly correct and never reached. The
not-a-live-deployment guard fires before everything else by design, so on any developer machine the
whole deploy path below it is unexercised unless something builds a box to point at.

THE CLAIM THIS FILE EXISTS TO PROVE, and it is the reason `box_selfcheck.py` was added to the deploy
map: THE DEPLOYED CHECKER NOW VERIFIES ITSELF. Until 2026-08-16 it was absent from
deploy-targets.json, which made it the single artifact on the box that could drift with nothing able
to report it. Both halves failed for one reason: the deployer does not copy what the map does not
list, and the manifest check compares only what is in `files`, so the drift detector was exempt from
drift detection. The evidence was on the live endpoint the whole time, in the checker's own output:
it reported `unexpected address` for a state target and printed no finding count, both of which
belong to a box_selfcheck that predates the denylist rewrite, while the 19 files it compared all
matched.

So the load-bearing case here corrupts the DEPLOYED checker and requires its own manifest check to
name it, then restores it and requires green again. Neither direction was reachable before.

EVERY POSITIVE HAS ITS CONTROL, because a deployer that copied indiscriminately and a comparison
that always said SAME would pass every "the file is there" assertion in this file. Each artifact is
perturbed on the box after a clean sync and required to be detected BY NAME.

`services` is expected to fail on a machine with no systemd, so assertions read the `manifest` check
by name rather than the overall verdict.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SYNC = HERE / "sync_workspace.py"
GEN = HERE / "make_invariants.py"
INV = HERE / "SHOP-INVARIANTS.json"

failures: list[str] = []
cases = 0


def expect(name: str, cond: bool, detail: object = "") -> None:
    global cases
    cases += 1
    if cond:
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name}")
        failures.append(f"{name} :: {str(detail)[:400]}")


def _run(argv: list[str], env: dict | None = None) -> tuple[int, str]:
    p = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(ROOT),
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout.strip()


def named(verdict: dict, name: str) -> dict:
    for c in verdict.get("checks", []):
        if c.get("name") == name:
            return c
    return {}


def main() -> int:
    if _git("rev-parse", "--git-dir") == "":
        print("NOT CHECKED  not a git repo, so a deploy cannot be anchored to a commit")
        return 2

    rc, out = _run([sys.executable, str(GEN)])
    if rc != 0:
        print(
            f"NOT CHECKED  the generator refused, so there is no manifest to deploy:\n{out}"
        )
        return 2

    head = _git("rev-parse", "HEAD")
    dirty = bool(_git("status", "--porcelain"))
    print(f"repo {head[:12]} dirty={dirty}")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        box, sysd = tmp / "box", tmp / "sysd"
        box.mkdir()
        sysd.mkdir()
        # A real deployment carries the daemon's config. The deployer refuses without it rather
        # than populating a directory that merely looks like a box, so the fixture needs one.
        (box / "config.toml").write_text("# fixture\n", encoding="utf-8")
        env = dict(os.environ, ZEROCLAW_HOME=str(box), ZC_SYSTEMD_DIR=str(sysd))

        def sync(*args: str) -> tuple[int, str]:
            return _run([sys.executable, str(SYNC), *args], env)

        # THE DIRTY-TREE GUARD, driven in whichever direction this checkout allows, so the case
        # is meaningful on a developer machine AND on a clean runner. The clean branch is the
        # over-correction control: a guard that refused every tree would also "pass" the dirty
        # branch, and only the clean run distinguishes the two.
        if dirty:
            rc, out = sync()
            expect(
                "a dirty tree is refused",
                rc == 1 and "working tree is dirty" in out,
                out,
            )
            expect("the refusal wrote nothing", not (box / "bin").exists())
            flags = ["--allow-dirty"]
        else:
            rc, out = sync()
            expect(
                "a CLEAN tree is not refused by the dirty guard",
                "working tree is dirty" not in out,
                out,
            )
            flags = []

        # COHERENCE. Placing files from one commit beside a manifest generated from another
        # leaves the box comparing fresh bytes against stale hashes, and the resulting verdict
        # cannot distinguish "the box is behind" from "the manifest is behind".
        original = INV.read_bytes()
        try:
            tampered = json.loads(original.decode("utf-8"))
            tampered["repo_commit"] = "0" * 40
            INV.write_text(json.dumps(tampered), encoding="utf-8")
            rc, out = sync(*flags)
            expect(
                "a manifest from another commit is refused",
                rc == 1 and "was generated from" in out,
                out,
            )
            expect("that refusal happened before any copy", not (box / "bin").exists())
        finally:
            INV.write_bytes(original)

        held = tmp / "held.json"
        shutil.move(str(INV), str(held))
        try:
            rc, out = sync(*flags)
            expect(
                "an ungenerated manifest is refused rather than skipped",
                rc == 1 and "make_invariants" in out,
                out,
            )
        finally:
            shutil.move(str(held), str(INV))

        # DRY RUN.
        rc, out = sync(*flags)
        expect("the coherent dry run succeeds", rc == 0, out)
        expect("it announces itself as a dry run", "DRY RUN" in out, out)
        expect("it wrote nothing", not (box / "bin").exists())
        expect(
            "it names the checker as absent on the box",
            "bin/box_selfcheck.py" in out,
            out,
        )
        expect(
            "it names the unit files against the systemd dir",
            "zc-announce.service" in out and str(sysd) in out,
            out,
        )
        expect("it names the missing version marker", "DEPLOYED_SHA" in out, out)

        # APPLY.
        rc, out = sync("--apply", *flags)
        expect("apply succeeds", rc == 0, out)
        checker = box / "bin" / "box_selfcheck.py"
        expect("the checker itself landed", checker.is_file())
        expect(
            "the checker's bytes match the repo",
            checker.is_file()
            and checker.read_bytes() == (HERE / "box_selfcheck.py").read_bytes(),
        )
        expect(
            "the manifest landed where box_selfcheck reads it",
            (box / "SHOP-INVARIANTS.json").is_file(),
        )
        expect(
            "unit files landed in the systemd dir and NOT under the box root",
            (sysd / "zc-announce.service").is_file()
            and not (box / "zc-announce.service").exists(),
        )
        want = f"{head}-dirty" if dirty else head
        got = (box / "DEPLOYED_SHA").read_text(encoding="utf-8").strip()
        expect(
            "DEPLOYED_SHA records the commit deployed",
            got == want,
            f"{got!r} != {want!r}",
        )
        expect(
            "the reload is printed rather than claimed to have run",
            "systemctl --user daemon-reload" in out and "INERT until" in out,
            out,
        )

        rc, out = sync(*flags)
        expect(
            "a second run reports nothing to do",
            rc == 0 and "nothing to do" in out,
            out,
        )

        # THE LOOP: run the DEPLOYED checker against the box it was deployed to.
        verdict = tmp / "verdict.json"

        def gate() -> dict:
            _run([sys.executable, str(checker), "--out", str(verdict), "--quiet"], env)
            return json.loads(verdict.read_text(encoding="utf-8"))

        man = named(gate(), "manifest")
        expect(
            "the manifest check passes on a freshly synced box",
            man.get("ok") is True,
            man,
        )

        # THE LOAD-BEARING CONTROL. Impossible before the checker entered the map.
        pristine = checker.read_bytes()
        checker.write_bytes(b"# DRIFT CONTROL\n" + pristine)
        man2 = named(gate(), "manifest")
        expect(
            "a drifted CHECKER is caught by its own manifest check, by name",
            man2.get("ok") is False and "box_selfcheck.py" in str(man2.get("detail")),
            man2,
        )
        checker.write_bytes(pristine)
        expect(
            "restoring it returns the manifest check to green",
            named(gate(), "manifest").get("ok") is True,
        )

        # The same control for the two surfaces the deployer newly covers.
        (sysd / "zc-announce.service").write_text("tampered\n", encoding="utf-8")
        rc, out = sync(*flags)
        expect(
            "a tampered UNIT FILE is detected",
            "DIFFERS" in out and "zc-announce.service" in out,
            out,
        )
        (box / "DEPLOYED_SHA").write_text("deadbeef\n", encoding="utf-8")
        rc, out = sync(*flags)
        expect("a stale DEPLOYED_SHA is detected", "STALE" in out, out)

    for f in failures:
        print(f"  ---   {f}")
    print(f"\n{cases - len(failures)} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
