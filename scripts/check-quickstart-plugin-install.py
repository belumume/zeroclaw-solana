#!/usr/bin/env python3
"""Run QUICKSTART's own build loop and assert `plugin install` could then find the component.

WHY THIS EXISTS. Followed verbatim on a real host, QUICKSTART section 2 failed on the first
plugin:

    Error: plugin not found: WASM file not found:
      /mnt/c/.../plugins/x402-pay-build/x402_pay_build.wasm

The documented loop built each component into `target/wasm32-wasip2/release/`, and every
`manifest.toml` declares a BARE FILENAME, so the host looked beside the manifest and found
nothing. A copy step was missing from the loop and no automation anywhere performed it: there is
no `plugins/build*.sh`, no Makefile, and no workflow runs `plugin install` at all. CI builds each
component and then inspects the TARGET-DIR artifact, so the path we actually tell strangers to
walk had never been exercised by any runtime path.

WHY IT SURVIVED FOR MONTHS. Eight of the nine plugin directories already had a `.wasm` sitting
beside the manifest from a hand copy months earlier. `*.wasm` is gitignored, so those existed only
on one machine, and a fresh clone had none. The defect was invisible from the tree where the work
happened and total everywhere else. That is why this check builds its own tree from the real
manifests rather than looking at `plugins/` on disk: a check that asks "is the file there" passes
on the one machine where it must not.

WHAT IT ASSERTS. The loop is EXTRACTED from QUICKSTART and EXECUTED, not restated here, so the doc
and the check cannot drift apart -- the pattern `host-drift.yml` uses to read the host pin out of
the same file. `cargo` is stubbed by a shim that writes the artifact the real build would write, at
the path the real build writes it, derived from each crate's own `Cargo.toml` package name. That
keeps the check offline and sub-second while leaving the assertion intact, because the defect is
file CHOREOGRAPHY and not compilation. The final assertion reproduces the host's own precondition:
after the documented sequence, does `<manifest dir>/<wasm_path>` resolve?

THE CEILING, stated so nobody reads this as more than it is. The stub means a component that FAILS
TO COMPILE still passes here; `ci.yml`'s plugin matrix and `host-drift.yml` both do the real build,
and this is deliberately not a third copy of that. It does not run the real `zeroclaw plugin
install` either, because no runner has the host binary. It asserts the condition whose absence
produced the error above, which is the whole of the reported defect and none of its neighbours.

Exit 0 the documented sequence works, 1 it does not, 2 could not check. A could-not-check is NOT a
pass. The distinction is load-bearing here: if the stub never ran, every plugin is missing its
artifact for a reason that has nothing to do with the copy step, and reporting that as the defect
would be a false red pointing at correct prose.

  --selftest   drives both directions, including the control that strips the copy step out of the
               REAL loop and requires this gate to go red
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QUICKSTART = "QUICKSTART.md"

# Discovery floor, matching `host-drift.yml`. A walk that finds nothing would report a clean sweep
# over an empty set, which is this repo's most-repeated instrument failure. Nine exist today; more
# is fine, fewer means the walk broke.
FLOOR = 9

# The loop opens with this. Anchored on `plugins/*/` rather than on a whole sentence: the gate
# should survive the loop being reworded and must not survive it being pointed somewhere else.
LOOP_START = re.compile(r"^\s*for\s+d\s+in\s+plugins/\*/")

# Executing text out of a document is only reasonable with a floor under what may be executed.
# This is not a security boundary -- the file is in the repo and anyone editing it can already run
# anything in CI. It is a tripwire for a rewrite that turns a build loop into something else, and
# it fails LOUD (cannot-check, with the offending text) rather than skipping.
FORBIDDEN = ("$(", "`", "rm ", "curl", "wget", "sudo", "eval", "chmod", ">")

STUB_CARGO = """#!/bin/sh
# Stands in for `cargo build`. Writes the artifact the real build writes, where the real build
# writes it, named from THIS crate's own package name -- never from the manifest's wasm_path,
# which is the very thing under test.
[ "$1" = "build" ] || exit 0
name=$(sed -n 's/^name[[:space:]]*=[[:space:]]*"\\(.*\\)".*/\\1/p' Cargo.toml | head -1)
if [ -z "$name" ]; then
  echo "stub cargo: no package name in $PWD/Cargo.toml" >&2
  exit 1
fi
out="target/wasm32-wasip2/release/$(echo "$name" | tr '-' '_').wasm"
mkdir -p "target/wasm32-wasip2/release"
printf '\\000asm\\001\\000\\000\\000' > "$out"
"""


def read_quickstart(root: Path) -> str | None:
    p = root / QUICKSTART
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return None


def extract_loop(text: str) -> str | None:
    """The build loop, verbatim, continuations joined.

    Returns None rather than guessing. A parser that stopped matching must be FIXED, not deleted:
    silently checking nothing is the failure this file exists to prevent one layer up.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not LOOP_START.match(line):
            continue
        chunk = [line]
        while chunk[-1].rstrip().endswith("\\") and i + len(chunk) < len(lines):
            chunk.append(lines[i + len(chunk)])
        return "\n".join(chunk)
    return None


def loop_is_safe(loop: str) -> str | None:
    """None if the loop may be executed, else the reason it may not."""
    for tok in FORBIDDEN:
        if tok in loop:
            return (
                f"the extracted loop contains {tok!r}, which this gate refuses to execute. "
                "If QUICKSTART legitimately needs it, widen FORBIDDEN deliberately rather than "
                "removing the step."
            )
    if "cargo build" not in loop:
        return (
            "the extracted loop never runs `cargo build`, so it is not the build loop"
        )
    return None


def plugin_dirs(root: Path) -> list[str] | None:
    """Plugin directory names from git's index, sorted. None if git cannot answer.

    From the INDEX, like `check-plugin-count-agreement.py`, so an untracked scratch directory
    cannot enter the fixture and fail a check about tracked plugins.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "plugins"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    names = {
        p.split("/")[1]
        for p in out.stdout.split("\n")
        if p.startswith("plugins/") and p.count("/") >= 2
    }
    return sorted(names) or None


def manifest_wasm_path(text: str) -> str | None:
    m = re.search(r'^\s*wasm_path\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else None


def artifact_name(text: str) -> str | None:
    """The crate name cargo would build the artifact under, or None.

    SECTION-AWARE ON PURPOSE, and both halves of that were reviewer-caught. A bare first-match
    for `name = "..."` reads whichever table comes first, so a `[workspace.package]` or a
    dependency table sitting above `[package]` would be picked up and silently mis-name the
    artifact -- and a wrong name here reads as the copy step failing, which is a confident red
    pointing at correct prose.

    `[lib].name` WINS over `[package].name` because that is what cargo does, and it is one line
    from mattering: every plugin already carries a `[lib]` table, none of them names itself
    today, and adding a name to one would move the artifact out from under this check.

    Not a TOML parser. It reads top-level table headers and the first `name` inside each, which
    is the whole of what is needed and cannot be confused by an inline table or an array of
    tables the way the flat regex could.
    """
    section, names = None, {}
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s.strip("[]").strip()
            continue
        m = re.match(r'name\s*=\s*"([^"]+)"', s)
        if m and section is not None and section not in names:
            names[section] = m.group(1)
    return names.get("lib") or names.get("package")


def build_fixture(root: Path, names: list[str], dest: Path) -> list[str]:
    """Mirror each plugin's manifest.toml and Cargo.toml name into `dest`. Returns problems.

    Only those two files. The fixture must carry the real declarations under test and nothing
    else, so a stray file in a real plugin directory cannot change the verdict.
    """
    problems: list[str] = []
    for n in names:
        src = root / "plugins" / n
        man, cargo = src / "manifest.toml", src / "Cargo.toml"
        if not man.is_file():
            problems.append(f"plugins/{n} has no manifest.toml")
            continue
        if not cargo.is_file():
            problems.append(f"plugins/{n} has no Cargo.toml")
            continue
        try:
            man_text = man.read_text(encoding="utf-8")
            pkg = artifact_name(cargo.read_text(encoding="utf-8"))
        except Exception as exc:
            problems.append(f"plugins/{n} is unreadable ({exc})")
            continue
        if pkg is None:
            problems.append(f"plugins/{n}/Cargo.toml declares no package name")
            continue
        d = dest / "plugins" / n
        d.mkdir(parents=True, exist_ok=True)
        (d / "manifest.toml").write_text(man_text, encoding="utf-8")
        (d / "Cargo.toml").write_text(f'[package]\nname = "{pkg}"\n', encoding="utf-8")
    return problems


def run_loop(tmp: Path, loop: str) -> tuple[bool, str]:
    """Execute the loop in `tmp` with the stub ahead of PATH. (ran, combined output).

    PATH is extended from inside bash with `$PWD`, which is already POSIX there. Composing a
    POSIX PATH from a Windows path in Python is the MSYS trap that would make this look like a
    missing stub on one platform and work on the other.
    """
    bash = shutil.which("bash")
    if bash is None:
        return False, "no bash on PATH"
    stub_dir = tmp / ".zc-stub"
    stub_dir.mkdir(parents=True, exist_ok=True)
    stub = stub_dir / "cargo"
    stub.write_text(STUB_CARGO, encoding="utf-8", newline="\n")
    stub.chmod(0o755)
    script = f'set -u\nexport PATH="$PWD/.zc-stub:$PATH"\n{loop}\n'
    try:
        out = subprocess.run(
            [bash, "-c", script],
            cwd=str(tmp),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except Exception as exc:
        return False, f"could not run the loop ({exc})"
    return True, (out.stdout or "") + (out.stderr or "")


def check(root: Path, loop_override: str | None = None, floor: int = FLOOR):
    """(exit code, lines to print)."""
    text = read_quickstart(root)
    if text is None:
        return 2, [f"cannot check: {QUICKSTART} is missing or unreadable"]

    loop = loop_override if loop_override is not None else extract_loop(text)
    if loop is None:
        return 2, [
            f"cannot check: could not find the build loop in {QUICKSTART}. It is matched on "
            "`for d in plugins/*/`. If the loop was reworded, fix this parser rather than "
            "deleting the step: a gate that cannot find its subject must not report success."
        ]

    why = loop_is_safe(loop)
    if why is not None:
        return 2, [f"cannot check: {why}", f"  extracted: {loop}"]

    names = plugin_dirs(root)
    if names is None:
        return 2, ["cannot check: could not list plugins from git ls-files plugins"]
    if len(names) < floor:
        return 2, [
            f"cannot check: discovery found {len(names)} plugin(s), fewer than the {floor} that "
            "exist today. The walk is broken, so a clean result here would mean nothing."
        ]

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        problems = build_fixture(root, names, tmp)
        if problems:
            return 2, ["cannot check:"] + [f"  - {p}" for p in problems]

        ran, output = run_loop(tmp, loop)
        if not ran:
            return 2, [f"cannot check: {output}"]

        built, resolved, missing = 0, 0, []
        for n in names:
            d = tmp / "plugins" / n
            if list((d / "target" / "wasm32-wasip2" / "release").glob("*.wasm")):
                built += 1
            declared = manifest_wasm_path(
                (d / "manifest.toml").read_text(encoding="utf-8")
            )
            if declared is None:
                return 2, [
                    f"cannot check: plugins/{n}/manifest.toml declares no wasm_path"
                ]
            if (d / declared).is_file():
                resolved += 1
            else:
                missing.append(
                    f"  plugins/{n}: manifest wants {declared!r}, not there afterwards"
                )

        # THE INSTRUMENT CHECK, and it must come before the verdict. If the stub never produced a
        # single artifact then nothing was built, every plugin is missing its component for a
        # reason unrelated to the copy step, and calling that a documentation defect would be a
        # confident red pointing at correct prose.
        if built == 0:
            return 2, [
                f"cannot check: the loop ran but produced no artifact for any of the {len(names)} "
                "plugin(s), so the stubbed build never fired and the copy step was never reached.",
                f"  loop output: {output.strip()[:400] or '(none)'}",
            ]

        lines = [
            f"plugins discovered: {len(names)} (floor {floor})",
            f"built by the documented loop: {built}/{len(names)}",
            f"manifests that resolve afterwards: {resolved}/{len(names)}",
        ]
        if missing:
            lines.append(
                f"{len(missing)} plugin(s) would fail `zeroclaw plugin install` after following "
                f"{QUICKSTART} exactly:"
            )
            lines.extend(missing)
            lines.append(
                "  The manifests declare a bare filename, so the component has to end up beside "
                "the manifest. Restore the copy step in the loop. Do NOT repoint wasm_path into "
                "the target directory: that couples the distributable unit to a build layout."
            )
            return 1, lines
        lines.append(
            "every manifest resolves; the documented sequence works from a clean tree"
        )
        return 0, lines


def selftest() -> int:
    cases, failures = 0, []

    def report(label: str, cond: bool) -> None:
        nonlocal cases
        cases += 1
        if not cond:
            failures.append(label)

    # ---- extraction ---------------------------------------------------------------------------
    doc = read_quickstart(ROOT)
    report("QUICKSTART is readable", doc is not None)
    if doc is None:
        print("selftest: cannot run without QUICKSTART.md")
        return 3

    real = extract_loop(doc)
    report("the loop is found in the real QUICKSTART", real is not None)
    if real is None:
        print("selftest: cannot run without the loop")
        return 3

    report("the extracted loop builds", "cargo build" in real)
    report("the extracted loop joins its continuation", "\n" in real or "cp " in real)
    report("the real loop is safe to execute", loop_is_safe(real) is None)

    report(
        "a document with no loop yields None, not a guess",
        extract_loop("## 2. Build\nnothing here\n") is None,
    )
    report(
        "a loop pointed somewhere other than plugins/ is not matched",
        extract_loop("for d in crates/*/; do cargo build; done") is None,
    )

    # The safety tripwire, and its opposite so it is not just refusing everything.
    report(
        "a substituted command is refused",
        loop_is_safe("for d in plugins/*/; do cargo build $(id); done") is not None,
    )
    report(
        "a loop with no build is refused",
        loop_is_safe("for d in plugins/*/; do echo hi; done") is not None,
    )

    # ---- artifact naming ----------------------------------------------------------------------
    # Getting this wrong does not look like a naming bug. The stub emits one filename, the
    # manifest names another, and the gate reports the copy step as broken -- a confident red
    # against correct prose, which is the failure direction that gets a gate deleted.
    report(
        "the package name is read",
        artifact_name('[package]\nname = "oracle-publish"\n') == "oracle-publish",
    )
    report(
        "a [lib] name WINS, because that is the artifact cargo writes",
        artifact_name('[package]\nname = "pkg"\n\n[lib]\nname = "lib_override"\n')
        == "lib_override",
    )
    report(
        "a [lib] with no name of its own leaves the package name standing",
        artifact_name('[package]\nname = "pkg"\n\n[lib]\ncrate-type = ["cdylib"]\n')
        == "pkg",
    )
    # THE REVIEWER'S CASE. A flat first-match regex returns "shared" here and mis-names every
    # artifact in the tree.
    report(
        "a name in an earlier unrelated table does NOT win",
        artifact_name(
            '[workspace.package]\nname = "shared"\n\n[package]\nname = "real"\n'
        )
        == "real",
    )
    report(
        "a dependency's name key is not mistaken for the crate's",
        artifact_name(
            '[dependencies.serde]\nname = "serde"\n\n[package]\nname = "real"\n'
        )
        == "real",
    )
    report(
        "a manifest with no name at all yields None",
        artifact_name("[package]\n") is None,
    )
    # Every real plugin resolves, so the parser is exercised against the tree it guards rather
    # than against fixtures alone.
    real_names = [
        artifact_name((ROOT / "plugins" / n / "Cargo.toml").read_text(encoding="utf-8"))
        for n in (plugin_dirs(ROOT) or [])
    ]
    report(
        "every real plugin resolves to a name",
        len(real_names) >= FLOOR and all(real_names),
    )

    # ---- the verdict, both directions, against the REAL tree ----------------------------------
    rc, out = check(ROOT)
    report("the documented sequence PASSES as written", rc == 0)
    report(
        "and it reports the denominator, not a bare ok",
        any("manifests that resolve" in ln for ln in out),
    )

    # THE CONTROL THIS GATE EXISTS FOR. Strip the copy step out of the REAL loop and the same
    # machinery must go red. Without it, "passes as written" is equally true of a gate that
    # passes on anything -- which is precisely how the defect survived: eight artifacts sat
    # beside their manifests and every check that looked was satisfied.
    #
    # The anchor is asserted before substituting. A mutation control whose anchor has rotted
    # applies nothing, leaves the mutant byte-identical to the original, and then certifies the
    # unmutated code while printing a pass.
    anchor = "&& cp "
    report("CONTROL anchor is present in the real loop", anchor in real)
    if anchor in real:
        stripped = re.sub(r"\s*\\?\s*&&\s*cp\s+[^\n)]*", "", real)
        report("the mutation actually changed the loop", stripped != real)
        report("and it removed the copy", anchor not in stripped)
        rc_c, out_c = check(ROOT, loop_override=stripped)
        report("CONTROL: dropping the copy step turns this gate RED", rc_c == 1)
        report(
            "CONTROL: it goes red as a FAILURE, not as cannot-check",
            rc_c == 1
            and any("would fail `zeroclaw plugin install`" in ln for ln in out_c),
        )
        report(
            "CONTROL: and it names every plugin, not just the one that surfaced",
            sum(1 for ln in out_c if ln.startswith("  plugins/")) >= FLOOR,
        )

    # A loop that never reaches the compiler must be cannot-check rather than a failure, so the
    # two reds stay distinguishable: "the copy step is missing" and "nothing ran at all" have
    # opposite remedies and identical symptoms at the manifest.
    #
    # This fixture says `cargo build` on purpose. The first version said `cargo x`, which tripped
    # the safety tripwire instead and returned 2 from a completely different branch -- the rc
    # assertion passed while testing nothing, and only the message assertion beside it noticed.
    # A case that reaches the right verdict by the wrong path is worse than a missing case.
    rc_n, out_n = check(
        ROOT,
        loop_override='for d in plugins/*/; do (cd "$d/absent" && cargo build); done',
    )
    report("a loop that builds nothing is cannot-check, not a failure", rc_n == 2)
    report(
        "and it says the stub never fired",
        any("never fired" in ln for ln in out_n),
    )

    # ---- fixture-level cases, isolated from the real tree -------------------------------------
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        (tmp / "plugins").mkdir(parents=True)
        for i in range(FLOOR):
            d = tmp / "plugins" / f"p{i}"
            d.mkdir()
            (d / "Cargo.toml").write_text(
                f'[package]\nname = "p{i}"\n', encoding="utf-8"
            )
            (d / "manifest.toml").write_text(
                'wasm_path = "p{}.wasm"\n'.format(i), encoding="utf-8"
            )
        (tmp / QUICKSTART).write_text(f"```\n{real}\n```\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp), "init", "-q"], capture_output=True)
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], capture_output=True)

        report("a synthetic tree at the floor passes", check(tmp)[0] == 0)

        # A manifest naming a file the build does not produce. This is the OTHER way install
        # breaks, and the copy step cannot save it: `cp *.wasm .` lands the real artifact under
        # the real name, so a manifest pointing at a different name still resolves to nothing.
        (tmp / "plugins" / "p0" / "manifest.toml").write_text(
            'wasm_path = "not_what_cargo_builds.wasm"\n', encoding="utf-8"
        )
        rc_m, out_m = check(tmp)
        report("a manifest naming a file the build never produces FAILS", rc_m == 1)
        report(
            "and it quotes what the manifest wanted",
            any("not_what_cargo_builds.wasm" in ln for ln in out_m),
        )
        (tmp / "plugins" / "p0" / "manifest.toml").write_text(
            'wasm_path = "p0.wasm"\n', encoding="utf-8"
        )
        report("restoring the manifest passes again", check(tmp)[0] == 0)

        # Below the floor is cannot-check. A discovery walk that lost most of the set must not
        # report a clean sweep of the few it kept.
        shutil.rmtree(tmp / "plugins" / f"p{FLOOR - 1}")
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], capture_output=True)
        rc_f, out_f = check(tmp)
        report("below the discovery floor is cannot-check", rc_f == 2)
        report(
            "and it says the walk is broken",
            any("walk is broken" in ln for ln in out_f),
        )

    for f in failures:
        print(f"  FAIL  {f}")
    print(f"selftest: {cases - len(failures)}/{cases}")
    return 0 if not failures else 3


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    rc, lines = check(ROOT)
    for ln in lines:
        print(ln)
    return rc


if __name__ == "__main__":
    sys.exit(main())
