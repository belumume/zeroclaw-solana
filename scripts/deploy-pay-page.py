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

# What the browser actually fetches: the document, Cloudflare's header config, and the
# same-origin module the pay path imports at click time. Any addition here needs a
# reason a reader can check: does the browser fetch it?
#
# The module is NAMED AS A FILE rather than reached by copying `vendor/` whole, which is
# the same discipline the docstring above argues for. A directory copy ships whatever
# lands in that directory next, unreviewed and unexplained, and that is precisely the
# shape that put a ruff cache on a public origin. Naming the file means a second module
# cannot ride along silently: it has to be added here, and unserved_refs() below refuses
# the deploy until it is.
#
# It is REQUIRED rather than optional. index.html imports it twice at click time, so a
# deploy without it leaves the desktop wallet path dead while the page still answers 200
# through the SPA fallback, which is why the browser reports nothing a deploy could see.
SERVE = ("index.html", "_headers", "vendor/solana-bundle.js")

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


# Every shape in which this page reaches for another file at run time. Attributes are the
# shape a reader thinks of; the module graph is the one that broke the checkout, because
# `import('/vendor/...')` is a run-time fetch that appears in no attribute at all and so
# was invisible to a check that read only src= and href=. A page missing its own module
# therefore passed as self-contained.
#
# NARROWED BY MEASUREMENT against the 114,630-character page this ships, because a checker
# that fires on correct content gets routed around rather than followed. A bare
# `from "..."` was tried and REFUSED: it matches English prose inside a code comment
# ("...tell 'never paid' apart from 'aged out of a rolling retention window'"), one hit on
# the live page, so the module form is anchored on the import or export keyword instead.
# Every pattern here returns zero refs on the live page beyond the two real module imports,
# and every one has its own case in the selftest, because one live pattern says nothing
# about its siblings.
REF_PATTERNS = (
    r'(?:src|href)\s*=\s*["\']([^"\']+)["\']',
    r'\bimport\s*\(\s*["\']([^"\']+)["\']',
    r'\b(?:import|export)\b[^;\n]{0,200}?\bfrom\s*["\']([^"\']+)["\']',
    r'\bnew\s+(?:Shared)?Worker\s*\(\s*["\']([^"\']+)["\']',
    r'\bimportScripts\s*\(\s*["\']([^"\']+)["\']',
    r'\bserviceWorker\s*\.\s*register\s*\(\s*["\']([^"\']+)["\']',
    r'\burl\(\s*["\']?\s*([^"\')\s]+)',
)

# Prefixes that name something this origin does not have to carry.
REMOTE = ("http://", "https://", "data:", "blob:", "#", "mailto:", "//")


def self_contained(index_html: str) -> list[str]:
    """Return every local run-time ref the page makes, in any shape REF_PATTERNS knows."""
    refs = []
    for pat in REF_PATTERNS:
        for m in re.finditer(pat, index_html):
            u = m.group(1).strip()
            if not u or u.startswith(REMOTE):
                continue
            refs.append(u)
    return refs


def _as_served(ref: str) -> str:
    """Reduce a ref and a SERVE member to the one form they can be compared in."""
    return ref.split("#", 1)[0].split("?", 1)[0].lstrip("/").removeprefix("./")


def unserved_refs(index_html: str, serve: tuple[str, ...] = SERVE) -> list[str]:
    """Local refs the deploy set does not carry. Non-empty means SERVE is incomplete.

    Compared AGAINST the deploy set rather than asserted empty. Asserting emptiness
    forces the fix for a legitimate same-origin module to be "stop referencing it"
    rather than "ship it", which is backwards: the page is allowed to have parts, and
    what must hold is that every part it names is one this deploy uploads.
    """
    served = {_as_served(n) for n in serve}
    return sorted(
        {r for r in self_contained(index_html) if _as_served(r) not in served}
    )


def scan(
    paths: list[Path],
    patterns: tuple[bytes, ...] | None = None,
    root: Path | None = None,
) -> list[str]:
    # Injectable so the selftest can drive this with a SYNTHETIC identity. Testing
    # it against the real account would put that account back into tracked source,
    # which is the thing the derivation above exists to avoid.
    pats = identifiers() if patterns is None else patterns
    findings = []
    for p in paths:
        # Relative to the staging root once one is given, because the deploy set now
        # has subdirectories and two members can share a basename. A finding that
        # names only the basename would not say which file to open.
        label = str(p.relative_to(root)).replace("\\", "/") if root else p.name
        blob = p.read_bytes()
        for pat in pats:
            n = blob.count(pat)
            if n:
                findings.append(f"{label}: {pat.decode('utf-8', 'replace')} x{n}")
    return findings


def stage(src: Path, dest: Path) -> list[Path]:
    files = staged_files(src)

    # A ref the deploy set does not carry would 404 for every visitor, and the SPA
    # fallback hides that by answering index.html with a 200, so the failure reaches
    # the customer as a dead button and never reaches a deploy as an error.
    refs = unserved_refs((src / "index.html").read_text(encoding="utf-8"))
    if refs:
        sys.exit(
            "REFUSED: index.html references local assets that the deploy set does "
            f"not carry: {refs}\n"
            "Either inline them at build time or add them to SERVE with a reason."
        )

    out = []
    for name, f in zip(SERVE, files, strict=True):
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, target)
        out.append(target)
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

        findings = scan(files, root=dest)
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
            rel = str(p.relative_to(dest)).replace("\\", "/")
            print(f"    {rel:26} {p.stat().st_size:>8} B")

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

        # A fixture that is the DEPLOY SET, derived from SERVE rather than listing its
        # members. A hand-listed fixture drifts the moment SERVE gains one, and it drifts
        # silently in the reassuring direction: staged_files() would refuse for a MISSING
        # MEMBER, every case below would still go green, and none of them would be
        # exercising the thing it names.
        def serve_set(dirpath: Path) -> Path:
            dirpath.mkdir(parents=True, exist_ok=True)
            for name in SERVE:
                f = dirpath / name
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(f"/* {name} */\n", encoding="utf-8")
            (dirpath / "index.html").write_text(
                "<html><style>x</style></html>", encoding="utf-8"
            )
            return dirpath

        # 3. self_contained(): every shape it must see, and the shapes it must not.
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
        # THE CASE THIS CHECKER WAS MISSING, and the reason the checkout broke: a module
        # fetched at click time names itself in no attribute at all.
        module_only = (
            "<script>var w=(await import('/vendor/solana-bundle.js')).web3;</script>"
        )
        case(
            "self_contained sees a dynamic import()",
            self_contained(module_only) == ["/vendor/solana-bundle.js"],
        )
        # The control that makes the case above evidence rather than an assertion: the
        # attribute-only pattern, alone, is blind to that identical page. If this ever
        # stops holding, the widening below has stopped being load-bearing.
        case(
            "control: an attribute-only scan is blind to that same module",
            re.findall(REF_PATTERNS[0], module_only) == [],
        )
        # One case per remaining pattern. A single live pattern says nothing about its
        # siblings, and these fire on nothing in today's page, so without a case each they
        # would be untested by construction.
        case(
            "self_contained sees a static import ... from",
            self_contained('<script type="module">import x from "/m.js"</script>')
            == ["/m.js"],
        )
        case(
            "self_contained sees a Worker",
            self_contained('<script>new Worker("/w.js")</script>') == ["/w.js"],
        )
        case(
            "self_contained sees importScripts",
            self_contained('<script>importScripts("/i.js")</script>') == ["/i.js"],
        )
        case(
            "self_contained sees a service-worker registration",
            self_contained(
                '<script>navigator.serviceWorker.register("/sw.js")</script>'
            )
            == ["/sw.js"],
        )
        case(
            "self_contained sees a CSS url()",
            self_contained("<style>b{background:url(/bg.png)}</style>") == ["/bg.png"],
        )
        # THE OVER-CORRECTION CONTROL, and it pins a measurement rather than a taste. A
        # bare from-pattern was tried first and matched this sentence, which is English
        # prose in a code comment on the live page. A checker that reddens a correct page
        # gets routed around, so the anchored form has to stay silent here.
        case(
            "self_contained ignores prose a bare from-pattern would have matched",
            self_contained(
                '// tell "never paid" apart from "aged out of a rolling window".'
            )
            == [],
        )

        # 4. unserved_refs(): a ref is measured against the deploy set, not against zero.
        case(
            "unserved_refs: the deploy set carries the module the page imports",
            unserved_refs(module_only) == [],
        )
        # THE CONTROL FOR THE DEFECT ITSELF. Drop the module from the deploy set and the
        # page's own import becomes a finding. The clean result above is only meaningful
        # because this one goes the other way on the same page.
        without_module = tuple(n for n in SERVE if n != "vendor/solana-bundle.js")
        case(
            "control: dropping that module from the deploy set is a finding",
            unserved_refs(module_only, without_module) == ["/vendor/solana-bundle.js"],
        )
        case(
            "unserved_refs matches a rooted ref to its deploy-set member",
            unserved_refs('<script src="/vendor/solana-bundle.js?v=2"></script>') == [],
        )

        # 5. stage(): copies the whole deploy set, and refuses an incomplete one.
        good = serve_set(root / "good")
        (good / "build.py").write_text("# not served", encoding="utf-8")
        cache = good / ".ruff_cache"
        cache.mkdir()
        # Shaped exactly like a real ruff cache entry: an absolute source path.
        (cache / "0").write_bytes(str(fake_home / "webshop-pay" / "build.py").encode())
        out = stage(good, root / "out")
        staged_rel = sorted(
            str(p.relative_to(root / "out")).replace("\\", "/") for p in out
        )
        case(
            "stage copies the whole deploy set, subdirectories included",
            staged_rel == sorted(SERVE),
        )
        case(
            "stage leaves everything else behind, the cache included",
            sorted(
                str(p.relative_to(root / "out")).replace("\\", "/")
                for p in (root / "out").rglob("*")
                if p.is_file()
            )
            == sorted(SERVE),
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
        # Its OWN nested fixture rather than a staged member. Reaching into the staged
        # output for a file named in SERVE couples a case about LABELLING to whatever the
        # deploy set currently holds, and a case that reaches for a member SERVE no longer
        # names raises rather than failing -- which aborts the run, so every case after it
        # is silently never reached. That is worse than a red: it hides the reds behind it.
        nested = root / "labels" / "sub"
        nested.mkdir(parents=True)
        (nested / "thing.js").write_bytes(b"needle")
        case(
            "a finding names the path, not just the basename",
            scan([nested / "thing.js"], (b"needle",), root=root / "labels")
            == ["sub/thing.js: needle x1"],
        )

        # 6. stage() refuses when index.html needs an asset the set does not carry.
        # Both fixtures carry the FULL deploy set, so the refusal is the ref check and
        # not staged_files() rejecting a short set, which would pass these cases for a
        # reason that has nothing to do with what they claim to test.
        bad = serve_set(root / "bad")
        (bad / "index.html").write_text(
            '<script src="app.js"></script>', encoding="utf-8"
        )
        try:
            stage(bad, root / "out2")
            case("stage refuses an index.html with an unstaged local ref", False)
        except SystemExit:
            case("stage refuses an index.html with an unstaged local ref", True)

        badmod = serve_set(root / "badmod")
        (badmod / "index.html").write_text(
            "<script>import('/vendor/other.js')</script>", encoding="utf-8"
        )
        try:
            stage(badmod, root / "out3")
            case("stage refuses an index.html importing an unstaged module", False)
        except SystemExit:
            case("stage refuses an index.html importing an unstaged module", True)

        # 7. staged_files() refuses a missing member rather than shipping a partial set.
        short = root / "short"
        short.mkdir()
        (short / "index.html").write_text("<html></html>", encoding="utf-8")
        try:
            staged_files(short)
            case("staged_files refuses a missing deploy-set member", False)
        except SystemExit:
            case("staged_files refuses a missing deploy-set member", True)

        # 8. THE PAGE THAT ACTUALLY SHIPS. Every case above is a fixture, and a fixture
        # cannot tell you whether the thing on the origin is served. The control is what
        # makes the clean verdict mean something: an unreadable or empty page would also
        # report zero unserved refs, and only the third case separates those.
        live = SRC_DIR / "index.html"
        case("the shipped index.html is present to be checked", live.is_file())
        html = live.read_text(encoding="utf-8") if live.is_file() else ""
        case(
            "every local ref the shipped page makes is in the deploy set",
            unserved_refs(html) == [],
        )
        case(
            "control: that page really does reach for the same-origin module",
            "/vendor/solana-bundle.js" in self_contained(html),
        )

    passed = sum(1 for _, ok in cases if ok)
    print(f"\n  {passed}/{len(cases)}")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
