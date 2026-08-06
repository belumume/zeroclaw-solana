#!/usr/bin/env python3
"""Diff this repo's vendored `wit/` against the host you actually build against.

WHY THIS EXISTS, and it is the most expensive defect this project hit.

Every WASM tool plugin here failed to instantiate for the whole life of the project:

    failed to instantiate tool plugin: component imports instance
    `zeroclaw:plugin/logging@0.1.0`, but a matching implementation was not found in the linker

That sentence reads as "the host never registered the import", and it sent us to the host's
source hunting a missing `add_to_linker`. The host registers it correctly. `wasmtime` emits the
SAME message for "import absent" and "import present but the wrong TYPE", and the discriminating
detail lives in the `Caused by:` chain underneath, which a truncated log drops.

The type was wrong by ONE ENUM VARIANT. Our vendored `plugin-action` had 38 cases; the host we run
has 37. Component-model interfaces match NOMINALLY, so 37 and 38 are different types, the whole
`logging` instance fails typecheck, and every plugin importing it dies regardless of what else is
right.

THE PART THAT MAKES A CHECKER NECESSARY RATHER THAN A HABIT: the repo's own compatibility script
verified each component carried ALL the host's variants. That passes when ours is a strict
SUPERSET, which is the direction this failure takes. It was green throughout. **So this asserts set
EQUALITY, never containment.**

Usage
-----
    python demo/check_wit_parity.py --host-wit ~/zeroclaw/wit
    python demo/check_wit_parity.py --self-test

Exit codes: 0 parity, 1 drift found, 2 could not check (never a silent pass), 3 self-test failed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

REPO_WIT = Path(__file__).resolve().parent.parent / "wit"

# A named type declaration: `enum foo {`, `variant bar {`, `record baz {`, `flags qux {`.
_DECL = re.compile(r"^\s*(enum|variant|record|flags)\s+([a-z0-9-]+)\s*\{", re.M)


def parse_types(text: str) -> dict[str, set[str]]:
    """Return {"<kind> <name>": {case, ...}} for every named type in one .wit file.

    Deliberately a small brace-counting parser rather than a regex over the whole block: a nested
    brace inside a variant payload would end the match early and silently under-count cases, which
    is the exact class of error this checker exists to catch.
    """
    out: dict[str, set[str]] = {}
    for m in _DECL.finditer(text):
        kind, name = m.group(1), m.group(2)
        i = text.index("{", m.start())
        depth, j = 0, i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = text[i + 1 : j]
        cases: set[str] = set()
        for line in body.splitlines():
            line = line.split("//")[0].strip().rstrip(",")
            if not line:
                continue
            # `case-name` or `case-name(payload)` or `field: type`
            cm = re.match(r"^([a-z0-9-]+)", line)
            if cm:
                cases.add(cm.group(1))
        out[f"{kind} {name}"] = cases
    return out


def load_dir(root: Path) -> dict[str, dict[str, set[str]]]:
    """{filename: {type: cases}} across every .wit under root, recursively."""
    found: dict[str, dict[str, set[str]]] = {}
    for p in sorted(root.rglob("*.wit")):
        found[p.name] = parse_types(p.read_text(encoding="utf-8"))
    return found


def compare(ours: dict, theirs: dict) -> list[str]:
    """Every asymmetry, in both directions. Returns human-readable findings."""
    findings: list[str] = []

    only_ours = sorted(set(ours) - set(theirs))
    only_theirs = sorted(set(theirs) - set(ours))
    for f in only_ours:
        findings.append(f"FILE only in repo: {f}")
    for f in only_theirs:
        findings.append(
            f"FILE only in host: {f}  (a plugin importing it cannot instantiate)"
        )

    for fname in sorted(set(ours) & set(theirs)):
        o, t = ours[fname], theirs[fname]
        for ty in sorted(set(o) - set(t)):
            findings.append(f"{fname}: TYPE only in repo: {ty}")
        for ty in sorted(set(t) - set(o)):
            findings.append(f"{fname}: TYPE only in host: {ty}")
        for ty in sorted(set(o) & set(t)):
            extra_ours = sorted(o[ty] - t[ty])
            extra_theirs = sorted(t[ty] - o[ty])
            if extra_ours:
                findings.append(
                    f"{fname}: {ty} has {len(o[ty])} cases in repo vs {len(t[ty])} in host; "
                    f"repo-only: {', '.join(extra_ours)}  "
                    f"<-- SUPERSET. A containment check passes here and instantiation still fails."
                )
            if extra_theirs:
                findings.append(
                    f"{fname}: {ty} has {len(o[ty])} cases in repo vs {len(t[ty])} in host; "
                    f"host-only: {', '.join(extra_theirs)}"
                )
    return findings


def self_test() -> int:
    """Positive control: the checker must FAIL on the real incident and PASS on parity.

    A checker never shown to fail on a known-bad input has not been shown to work.
    """
    checks: list[tuple[str, bool]] = []

    base = """
package zeroclaw:plugin@0.1.0;
interface logging {
  enum plugin-action {
    read-file,
    write-file,
    list-action,
  }
}
"""
    drifted = base.replace("    list-action,", "    list-action,\n    memory-audit,")

    with tempfile.TemporaryDirectory() as td:
        host = Path(td) / "host"
        repo = Path(td) / "repo"
        host.mkdir()
        repo.mkdir()

        # 1. THE INCIDENT: repo is a strict superset by one variant. Must be caught.
        (host / "logging.wit").write_text(base, encoding="utf-8")
        (repo / "logging.wit").write_text(drifted, encoding="utf-8")
        f = compare(load_dir(repo), load_dir(host))
        checks.append(
            (
                "incident: one extra repo variant is detected",
                any("memory-audit" in x for x in f),
            )
        )
        checks.append(
            ("incident: names it as a SUPERSET", any("SUPERSET" in x for x in f))
        )

        # 2. Parity must be silent, or the checker cries wolf and gets ignored.
        (repo / "logging.wit").write_text(base, encoding="utf-8")
        checks.append(
            ("parity is silent", compare(load_dir(repo), load_dir(host)) == [])
        )

        # 3. The OTHER direction: host has a variant we lack. Also drift.
        (repo / "logging.wit").write_text(
            base.replace("    list-action,\n", ""), encoding="utf-8"
        )
        f = compare(load_dir(repo), load_dir(host))
        checks.append(
            ("host-only variant is detected", any("host-only" in x for x in f))
        )

        # 4. A missing FILE on either side is drift, not a pass.
        (repo / "logging.wit").write_text(base, encoding="utf-8")
        (host / "extra.wit").write_text(
            "interface x { record r { a: u8 } }", encoding="utf-8"
        )
        f = compare(load_dir(repo), load_dir(host))
        checks.append(
            ("file only in host is detected", any("only in host" in x for x in f))
        )
        (host / "extra.wit").unlink()

        # 5. MUTATION CONTROL: break the case-extraction and the incident must go undetected.
        #    Proves the parse is load-bearing rather than the comparison passing by accident.
        saved = globals()["parse_types"]
        globals()["parse_types"] = lambda _t: {}
        (repo / "logging.wit").write_text(drifted, encoding="utf-8")
        blind = compare(load_dir(repo), load_dir(host))
        globals()["parse_types"] = saved
        checks.append(
            ("mutation control: gutted parser misses the incident", blind == [])
        )

        # 6. A nested brace must not truncate the case list (the parser's own failure mode).
        nested = """
interface x {
  variant payload {
    plain,
    complex(list<tuple<u8, u8>>),
    last-one,
  }
}
"""
        (repo / "n.wit").write_text(nested, encoding="utf-8")
        got = load_dir(repo)["n.wit"]["variant payload"]
        checks.append(
            ("nested braces do not truncate", got == {"plain", "complex", "last-one"})
        )
        (repo / "n.wit").unlink()

    width = max(len(n) for n, _ in checks)
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name.ljust(width)}")
    bad = sum(1 for _, ok in checks if not ok)
    print(f"\nself-test: {len(checks) - bad}/{len(checks)} passed")
    return 0 if bad == 0 else 3


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--host-wit", help="path to the host's wit/ directory (the host you RUN)"
    )
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    host_wit = args.host_wit or os.environ.get("ZEROCLAW_WIT")
    if not host_wit:
        print(
            "NOT CHECKED: no host wit/ supplied.\n"
            "  Pass --host-wit <path> or set ZEROCLAW_WIT. On a source-built host this is\n"
            "  <zeroclaw-checkout>/wit. This exits 2 rather than 0 on purpose: a parity check\n"
            "  that cannot find the host has not established parity.",
            file=sys.stderr,
        )
        return 2

    hp = Path(host_wit).expanduser()
    if not hp.is_dir():
        print(f"NOT CHECKED: {hp} is not a directory.", file=sys.stderr)
        return 2
    if not REPO_WIT.is_dir():
        print(f"NOT CHECKED: {REPO_WIT} is not a directory.", file=sys.stderr)
        return 2

    ours, theirs = load_dir(REPO_WIT), load_dir(hp)
    if not ours or not theirs:
        print(
            f"NOT CHECKED: parsed {len(ours)} repo file(s) and {len(theirs)} host file(s); "
            "one side is empty so a clean result would be meaningless.",
            file=sys.stderr,
        )
        return 2

    findings = compare(ours, theirs)
    print(f"repo: {REPO_WIT}  ({len(ours)} .wit)")
    print(f"host: {hp}  ({len(theirs)} .wit)\n")
    if not findings:
        print("PARITY. Every named type matches by SET EQUALITY, both directions.")
        return 0
    for f in findings:
        print(f"DRIFT  {f}")
    print(
        f"\n{len(findings)} drift finding(s). Any one of these makes every plugin importing the\n"
        "affected interface fail at instantiation with a linker message that names the import\n"
        "rather than the type. Copy the host's file over the repo's and rebuild."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
