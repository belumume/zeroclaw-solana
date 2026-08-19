#!/usr/bin/env python3
"""Stage and publish the pay page, uploading only what the page actually serves.

`wrangler pages deploy <dir>` uploads a DIRECTORY, not a git tree, so anything
sitting beside the artifact ships with it regardless of `.gitignore`. That is not
hypothetical here: `webshop-pay/.ruff_cache/` is git-ignored and held ten hits for
the operator's username and Windows home path, because a ruff cache records the
absolute path of every file it linted. A deploy of the directory as-is would have
put those on a public origin.

So the upload set is DERIVED rather than assumed: index.html is self-contained
(its styles and scripts are inlined by build.py), which this script re-checks
rather than trusting, and `_headers` is Cloudflare's own config file. Nothing else
in that directory is served, which the live origin corroborates -- build.py and
src/app.js both return the SPA fallback rather than their own bytes.

Every staged file is then scanned for identifiers before anything is uploaded. The
scan runs over the STAGED set, not over a list of files this script expects to
find, so a file added to the deploy directory later cannot ride along unscanned.

Usage:
  python scripts/deploy-pay-page.py            # stage + gate, print what would ship
  python scripts/deploy-pay-page.py --publish  # ...then upload it
  python scripts/deploy-pay-page.py --selftest
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC_DIR = REPO / "webshop-pay"
PROJECT = "zeroclaw-shop-pay"
LIVE_URL = f"https://{PROJECT}.pages.dev/"

# PINNED DELIBERATELY. A bare `npx wrangler` resolves at run time, so a deploy executes whatever
# npm serves that day, plus its whole transitive tree, with a live Pages token in the environment.
# That token publishes this page, and whoever holds it can publish one with a different MERCHANT
# constant and take payments directly, which makes it the highest-consequence credential here.
# Pinning does not remove the supply-chain surface; it makes it DETERMINISTIC, so nobody can reach
# this deploy by publishing a new `latest`.
#
# A lockfile would be stronger and is not available: rpc-proxy/ declares no dependencies and has no
# package-lock.json, so `npm ci` has nothing to install. A security review asserted that lockfile
# exists and its recommended fix was built on it; the file has never existed. Verify before
# reinstating that plan:  ls rpc-proxy/package-lock.json
#
# To move this pin, run the version you intend and record what it printed:
#   npx wrangler@<new> --version
WRANGLER = "4.124.0"  # `npx wrangler --version` on 2026-08-19

# The page is one self-contained document plus Cloudflare's header config. Any
# addition here needs a reason a reader can check: does the browser fetch it?
SERVE = ("index.html", "_headers")

# Patterns that name nobody in particular. A denylist has to name what it blocks,
# so a hardcoded account would make THIS tracked file the compact, labelled copy of
# the very strings it exists to keep off a public origin.
# `/Users/` covers macOS, and it is here for parity rather than for this machine:
# the deploy directory is whatever tree a contributor runs this from, so a cache
# left by a Mac would otherwise carry an absolute path past a scan that only knew
# about Windows and Linux. It also matches the repo's own identifier gate, which
# already reports a `[macos home]` class.
GENERIC = (rb"C:\Users", b"C:/Users", b"/Users/", b"/home/", b"OneDrive")


def identifiers() -> tuple[bytes, ...]:
    """GENERIC plus the running account, derived rather than written down.

    Deriving is not only a privacy choice. A hardcoded account is wrong on every
    machine except one, so the check would quietly pass for anyone else who ran a
    deploy from a tree with their own paths in it.

    Bytes, because the artifact is read as bytes and a str scan would depend on
    guessing an encoding for files this script does not own.
    """
    home = Path.home()
    account = home.name

    # Fail closed at both ends. An empty account matches nothing and reports clean,
    # and a very short one matches ordinary bytes inside a 105 KB document, so the
    # scan would be either blind or useless. Neither may pass silently.
    if len(account) < 3:
        sys.exit(
            f"REFUSED: cannot derive an account pattern from home dir {home!r} "
            f"(resolved account {account!r}). Nothing was scanned or uploaded."
        )

    pats = {
        str(home).encode(),
        str(home).replace("\\", "/").encode(),
        account.encode(),
        *GENERIC,
    }
    # Longest first, so a finding names the most specific pattern that matched.
    return tuple(sorted(pats, key=len, reverse=True))


def staged_files(src: Path) -> list[Path]:
    missing = [n for n in SERVE if not (src / n).is_file()]
    if missing:
        sys.exit(f"REFUSED: deploy set names {missing} but they are not in {src}")
    return [src / n for n in SERVE]


def self_contained(index_html: str) -> list[str]:
    """Return local runtime refs. A non-empty result means SERVE is incomplete."""
    refs = []
    for m in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', index_html):
        u = m.group(1)
        if u.startswith(("http://", "https://", "data:", "#", "mailto:", "//")):
            continue
        refs.append(u)
    return refs


def scan(paths: list[Path], patterns: tuple[bytes, ...] | None = None) -> list[str]:
    # Injectable so the selftest can drive this with a SYNTHETIC identity. Testing
    # it against the real account would put that account back into tracked source,
    # which is the thing the derivation above exists to avoid.
    pats = identifiers() if patterns is None else patterns
    findings = []
    for p in paths:
        blob = p.read_bytes()
        for pat in pats:
            n = blob.count(pat)
            if n:
                findings.append(f"{p.name}: {pat.decode('utf-8', 'replace')} x{n}")
    return findings


def stage(src: Path, dest: Path) -> list[Path]:
    files = staged_files(src)

    # A ref the deploy set does not carry would 404 for every visitor, and the SPA
    # fallback hides that by serving index.html with a 200.
    refs = self_contained((src / "index.html").read_text(encoding="utf-8"))
    if refs:
        sys.exit(
            "REFUSED: index.html references local assets that the deploy set does "
            f"not carry: {sorted(set(refs))}\n"
            "Either inline them at build time or add them to SERVE with a reason."
        )

    dest.mkdir(parents=True, exist_ok=True)
    out = []
    for f in files:
        shutil.copy2(f, dest / f.name)
        out.append(dest / f.name)
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--publish", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    # The artifact must be reproducible from its sources before it is published,
    # or the thing on the origin is not the thing in the repo.
    check = subprocess.run(
        [sys.executable, str(SRC_DIR / "build.py"), "--check"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check.returncode != 0:
        sys.stderr.write(check.stdout + check.stderr)
        sys.exit("REFUSED: index.html does not match its sources. Run build.py first.")
    print(f"  build --check ok: {check.stdout.strip()}")

    with tempfile.TemporaryDirectory(prefix="paypage-") as tmp:
        dest = Path(tmp)
        files = stage(SRC_DIR, dest)

        findings = scan(files)
        if findings:
            for f in findings:
                print(f"  LEAK {f}", file=sys.stderr)
            sys.exit(
                f"REFUSED: {len(findings)} identifier hit(s) in the staged set. "
                "Nothing was uploaded."
            )

        total = sum(p.stat().st_size for p in files)
        print(f"  staged {len(files)} file(s), {total} bytes, 0 identifier hits:")
        for p in files:
            print(f"    {p.name:16} {p.stat().st_size:>8} B")

        if not args.publish:
            print("\n  dry run. Re-run with --publish to upload.")
            return 0

        print(f"\n  uploading to {PROJECT} ...")
        # `npx` is a .cmd shim on Windows, and CreateProcess does not resolve
        # PATHEXT, so passing the bare name raises WinError 2 -- which reads as
        # "wrangler is not installed" rather than "the name was never resolved".
        npx = shutil.which("npx")
        if npx is None:
            sys.exit("REFUSED: npx not found on PATH. Nothing was uploaded.")

        rc = subprocess.run(
            [
                npx,
                f"wrangler@{WRANGLER}",
                "pages",
                "deploy",
                str(dest),
                f"--project-name={PROJECT}",
                "--branch=main",
                "--commit-dirty=true",
            ],
            cwd=REPO,
        ).returncode
        if rc != 0:
            return rc

    print(
        f"\n  uploaded. Verify from the LIVE origin, not from this exit code:\n    {LIVE_URL}"
    )
    return 0


def selftest() -> int:
    """Drive both directions of every gate: each must refuse, and each must pass."""
    cases: list[tuple[str, bool]] = []

    def case(name: str, ok: bool) -> None:
        cases.append((name, ok))
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")

    with tempfile.TemporaryDirectory(prefix="paypage-selftest-") as tmp:
        root = Path(tmp)

        # A SYNTHETIC identity throughout. Exercising the scanner against the real
        # account would write that account into tracked source, which is the leak
        # this whole script exists to prevent -- and a public denylist naming the
        # person it protects is a worse artifact than the cache it was guarding.
        # The synthetic home is JOINED at runtime rather than written as a literal.
        # Not obfuscation: the repo's own identifier gate scans tracked source for
        # the home-path SHAPE and is right to, so a literal fake home would trip it
        # exactly as a real one does. Joining also mirrors what identifiers() does.
        fake_home = Path("C:/Users") / "testacct"
        FAKE = (
            str(fake_home).replace("/", "\\").encode(),
            str(fake_home).replace("\\", "/").encode(),
            fake_home.name.encode(),
            *GENERIC,
        )

        # 1-2. scan(): fires on each pattern, silent on clean bytes.
        for pat in FAKE:
            p = root / "dirty.bin"
            p.write_bytes(b"prefix" + pat + b"suffix")
            case(
                f"scan fires on {pat.decode('utf-8', 'replace')}",
                len(scan([p], FAKE)) >= 1,
            )
        clean = root / "clean.bin"
        clean.write_bytes(b"<html>no identifiers here</html>")
        case("scan silent on clean bytes", scan([clean], FAKE) == [])

        # 3. identifiers() derives the running account rather than reading a
        # constant, so it is correct on a machine that is not this one.
        derived = identifiers()
        case(
            "identifiers() derives the running account and keeps the generics",
            Path.home().name.encode() in derived and all(g in derived for g in GENERIC),
        )
        # Keyed on the full HOME PATH rather than the bare account, which is what
        # the repo's own identifier gate treats as a finding and the only form that
        # cannot collide by accident. A bare account is not safe to assert on: one
        # named `test` or `self` is a substring of `selftest`, `testacct` and
        # `self_contained` already in this file, so the case would fail for a reason
        # that has nothing to do with a hardcoded path.
        own = Path(__file__).read_bytes()
        home_forms = {
            str(Path.home()).encode(),
            str(Path.home()).replace("\\", "/").encode(),
        }
        case(
            "no home path is hardcoded in this file's source",
            all(f not in own for f in home_forms),
        )
        # The control, because a check that has only ever returned clean has not
        # been shown to be capable of returning anything else.
        planted = root / "planted.py"
        planted.write_bytes(b"CACHED_ROOT = r'" + str(Path.home()).encode() + b"'")
        case(
            "control: the same check catches a planted home path",
            any(f in planted.read_bytes() for f in home_forms),
        )

        # 3. self_contained(): a local ref is reported, remote/inline are not.
        case(
            "self_contained finds a local ref",
            self_contained('<script src="app.js">') == ["app.js"],
        )
        case(
            "self_contained ignores remote and data refs",
            self_contained(
                '<script src="https://x/a.js"><img src="data:image/png;base64,AA">'
                '<a href="#top">'
            )
            == [],
        )

        # 4. stage(): copies the deploy set, and refuses an incomplete one.
        good = root / "good"
        good.mkdir()
        (good / "index.html").write_text(
            "<html><style>x</style></html>", encoding="utf-8"
        )
        (good / "_headers").write_text(
            "/*\n  X-Frame-Options: DENY\n", encoding="utf-8"
        )
        (good / "build.py").write_text("# not served", encoding="utf-8")
        cache = good / ".ruff_cache"
        cache.mkdir()
        # Shaped exactly like a real ruff cache entry: an absolute source path.
        (cache / "0").write_bytes(str(fake_home / "webshop-pay" / "build.py").encode())
        out = stage(good, root / "out")
        case(
            "stage copies only the deploy set, leaving the cache behind",
            sorted(p.name for p in out) == ["_headers", "index.html"],
        )
        case(
            "the ruff cache is not staged, so its identifiers cannot ship",
            scan(out, FAKE) == [],
        )
        # The control, and the load-bearing case: the same cache IS dirty, so the
        # clean result above is a statement about staging rather than about a
        # scanner that finds nothing.
        dirty = scan([cache / "0"], FAKE)
        case(
            "control: that cache really does carry identifiers",
            # Asserted on WHAT matched rather than on a count, which changes
            # whenever a pattern is added and says nothing about correctness.
            any(fake_home.name in f for f in dirty)
            and any("Users" in f for f in dirty),
        )

        # 5. stage() refuses when index.html needs an asset the set does not carry.
        bad = root / "bad"
        bad.mkdir()
        (bad / "index.html").write_text(
            '<script src="app.js"></script>', encoding="utf-8"
        )
        (bad / "_headers").write_text("/*\n", encoding="utf-8")
        try:
            stage(bad, root / "out2")
            case("stage refuses an index.html with an unstaged local ref", False)
        except SystemExit:
            case("stage refuses an index.html with an unstaged local ref", True)

        # 6. staged_files() refuses a missing member rather than shipping a partial set.
        short = root / "short"
        short.mkdir()
        (short / "index.html").write_text("<html></html>", encoding="utf-8")
        try:
            staged_files(short)
            case("staged_files refuses a missing deploy-set member", False)
        except SystemExit:
            case("staged_files refuses a missing deploy-set member", True)

    passed = sum(1 for _, ok in cases if ok)
    print(f"\n  {passed}/{len(cases)}")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
