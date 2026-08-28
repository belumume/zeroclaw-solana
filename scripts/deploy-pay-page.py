#!/usr/bin/env python3
"""Stage and publish the pay page, uploading only what the page actually serves.

`wrangler pages deploy <dir>` uploads a DIRECTORY, not a git tree, so anything
sitting beside the artifact ships with it regardless of `.gitignore`. That is not
hypothetical here: `webshop-pay/.ruff_cache/` is git-ignored and held ten hits for
the operator's username and Windows home path, because a ruff cache records the
absolute path of every file it linted. A deploy of the directory as-is would have
put those on a public origin.

The bytes themselves come from a GIT REF (`--ref`, default `origin/main`), never
from the working tree, because a tree is not a version: it can sit behind the branch,
carry another session's half-finished edit, or hold CRLF where the commit holds LF.
Measured here -- a tree two commits behind was missing 7 lines of the pay page's
click-time settlement re-check, and deploying from it in place would have reverted a
money-path control on a live page while the origin still answered 200.

So the upload set is DERIVED rather than assumed: index.html is self-contained
(its styles and scripts are inlined by build.py), which this script re-checks
rather than trusting, and `_headers` is Cloudflare's own config file. Nothing else
in that directory is served, which the live origin corroborates -- build.py and
src/app.js both return the SPA fallback rather than their own bytes.

Every staged file is then scanned for identifiers before anything is uploaded. The
scan runs over the STAGED set, not over a list of files this script expects to
find, so a file added to the deploy directory later cannot ride along unscanned.

Usage:
  python scripts/deploy-pay-page.py                    # stage + gate origin/main, dry run
  python scripts/deploy-pay-page.py --ref HEAD         # ...from a local commit instead
  python scripts/deploy-pay-page.py --publish          # ...then upload it
  python scripts/deploy-pay-page.py --selftest
"""

from __future__ import annotations

import argparse
import os
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


# The bytes this script publishes come from a GIT REF, never from the working tree.
#
# `wrangler pages deploy` reads a directory, so the obvious source is `webshop-pay/`
# as it sits on disk -- and that is whatever state the tree happens to hold. A tree is
# not a version. It can sit behind the branch, carry another session's half-finished
# edit, or hold a file checked out with the platform's line endings, and none of those
# announce themselves at deploy time. Measured on this repo: a tree two commits behind
# was missing exactly 7 lines of the pay page's click-time settlement re-check, 607
# bytes, on a page that takes mainnet payments. Deploying from it in place would have
# reverted a money-path control, silently, and the origin would still have answered 200.
#
# So the source is named and resolved: `--ref`, defaulting to the branch the origin is
# supposed to be serving. The subtree is materialised out of git's object store and the
# deploy set is staged from THAT. Two properties follow that the tree cannot offer.
#
# BYTES, not text. Blobs are handed over exactly as git stores them, which is what a
# clone receives and what `.gitattributes` (`* text=auto eol=lf`) says this repo means.
# A tree checked out on Windows is CRLF, so an in-place deploy publishes a file that
# differs from the committed one on every line while every diff-free check agrees.
#
# TRACKED CONTENT ONLY. A ref carries no ignored files, so the ruff cache the docstring
# above describes cannot be in the materialised tree at all. That does NOT retire the
# identifier scan or the explicit payload: an ignored cache is one way a stray file
# arrives and a committed one is another, and the scan runs over the STAGED set either
# way. It removes a class; it is not a reason to start copying directories.
#
# There is deliberately NO working-tree escape hatch. A local commit is a ref, so
# `--ref HEAD` covers iterating without pushing, and uncommitted bytes have no business
# on a live payment page. Adding the hatch back is how the defect returns.
DEFAULT_REF = "origin/main"
SRC_SUBTREE = "webshop-pay"


def _git(
    args: list[str], repo: Path | None = None, exe: str = "git"
) -> subprocess.CompletedProcess:
    """Run git in `repo`, returning stdout as BYTES.

    Never `text=True`. Blob content is the thing being published, and text mode would
    apply universal-newline translation on the way in -- handing the origin CRLF for a
    repository whose `.gitattributes` says `eol=lf`. It would also decode with the
    locale codec, which is cp1252 on this machine and cannot round-trip a UTF-8 page.

    `repo` is injectable so the selftest can drive these against a throwaway repository
    it builds itself. Asserting against this checkout would make the cases depend on
    what someone last fetched, which is the class of thing they exist to rule out.
    """
    try:
        return subprocess.run(
            [exe, "-C", str(repo or REPO), *args], capture_output=True
        )
    except (FileNotFoundError, NotADirectoryError) as e:
        # An unresolvable executable RAISES rather than returning non-zero, so without
        # this the one case where git is absent escapes both refusal paths below and
        # arrives as a stack trace naming `git`, which reads as a defect in this script
        # rather than as a missing tool. Funnelled into the failed result the callers
        # already refuse on, so there is one refusal path and not two.
        #
        # `exe` exists so that branch can be DRIVEN. Without it the guard is unreachable
        # from any fixture -- `git -C <a file>` makes git itself exit non-zero, so the
        # obvious case never gets here, and a first attempt shipped exactly that: a case
        # named for this guard that stayed green with the guard deleted.
        return subprocess.CompletedProcess(
            args=args, returncode=127, stdout=b"", stderr=str(e).encode()
        )


def resolve_ref(ref: str, repo: Path | None = None) -> str:
    """The commit `ref` names, or REFUSE. Never a fallback to anything else."""
    p = _git(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], repo)
    if p.returncode != 0 or not p.stdout.strip():
        sys.exit(
            f"REFUSED: {ref!r} does not resolve to a commit in {repo or REPO}. "
            "Nothing was staged or uploaded.\n"
            "  A remote-tracking ref goes stale until you fetch:  git fetch origin\n"
            "  To publish a commit that is only local, name it:   --ref HEAD"
        )
    return p.stdout.decode().strip()


def materialise(ref: str, dest: Path, repo: Path | None = None) -> Path:
    """Write the ref's SRC_SUBTREE into `dest`, as the blob bytes git holds.

    Addressed by OBJECT ID rather than through the `<ref>:<path>` form. Two reasons,
    and only the first is portability: MSYS rewrites that colon form when the ref
    contains a slash and the path begins with a dot, and it fails as a stopped clock --
    zero bytes, exit 0 -- which would read here as an empty page rather than an error.
    The second is that a sha names one object and cannot be re-resolved into a
    different one halfway through by anything else touching the repository.
    """
    p = _git(["ls-tree", "-r", "-z", ref, "--", f"{SRC_SUBTREE}/"], repo)
    if p.returncode != 0:
        sys.exit(
            f"REFUSED: could not list {SRC_SUBTREE}/ at {ref}: "
            f"{p.stderr.decode('utf-8', 'replace').strip()}\n"
            "Nothing was staged or uploaded."
        )

    entries: list[tuple[str, str]] = []
    for rec in p.stdout.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        parts = meta.split()
        # Only blobs carry bytes. A gitlink (a submodule commit) is listed here and has
        # nothing to serve, and skipping it silently is right -- but it must be skipped
        # by TYPE rather than by hoping the tree has none.
        if len(parts) < 3 or parts[1] != b"blob":
            continue
        # MODE as well as type, because a SYMLINK is also type blob: its content is the
        # link target, so filtering on type alone would write the string "../secrets"
        # into a served file and call it the asset. Refusing rather than skipping, since
        # a symlink appearing under a deploy root is a question for a human and a skip
        # would answer it by shipping an incomplete set.
        if parts[0] not in (b"100644", b"100755"):
            sys.exit(
                f"REFUSED: {ref} carries {path.decode('utf-8', 'replace')} with mode "
                f"{parts[0].decode()}, which is not a regular file. A symlink's content "
                "is its target, not the asset. Nothing was staged or uploaded."
            )
        entries.append((parts[2].decode(), path.decode("utf-8", "surrogateescape")))

    if not entries:
        sys.exit(
            f"REFUSED: {ref} carries no files under {SRC_SUBTREE}/. Nothing was "
            "staged or uploaded."
        )

    prefix = f"{SRC_SUBTREE}/"
    for sha, path in entries:
        blob = _git(["cat-file", "blob", sha], repo)
        if blob.returncode != 0:
            # A shallow or partial clone lists a tree whose objects it does not hold,
            # so this is reachable on a perfectly healthy-looking checkout. Refusing is
            # the whole point: a deploy that quietly skipped the object it could not
            # fetch is exactly the missing-module failure this deploy set exists to stop.
            sys.exit(
                f"REFUSED: {ref} names {path} as blob {sha[:12]} and git cannot produce "
                f"it: {blob.stderr.decode('utf-8', 'replace').strip()}\n"
                "A shallow or partial clone carries the tree without the objects. "
                "Nothing was staged or uploaded."
            )
        target = dest / path[len(prefix) :]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob.stdout)
    return dest


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
    ap.add_argument(
        "--ref",
        default=DEFAULT_REF,
        help=(
            "the commit-ish whose bytes get published (default: %(default)s). "
            "The working tree is never a source; use --ref HEAD for a local commit."
        ),
    )
    ap.add_argument("--publish", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    # Resolve the source BEFORE anything else, so a stale or misspelled ref fails
    # here rather than after a reassuring wall of staging output.
    sha = resolve_ref(args.ref)
    print(f"  source: {args.ref} = {sha[:12]}  (working tree is not read)")
    # Everything below is addressed by the RESOLVED COMMIT rather than by the name.
    # A branch is a moving target -- origin/main most of all -- so re-resolving it a
    # second time inside materialise() could stage a tree that is not the commit this
    # line just printed, and the result would be internally consistent and pass every
    # gate while contradicting the only thing telling the operator what shipped.

    with tempfile.TemporaryDirectory(prefix="paypage-") as tmp:
        tmpd = Path(tmp)
        src = materialise(sha, tmpd / "src")
        dest = tmpd / "out"

        # The artifact must be reproducible from its sources before it is published,
        # or the thing on the origin is not the thing in the repo. Run against the
        # MATERIALISED tree, so what is checked is the ref's index.html against the
        # ref's own sources -- the working tree's build.py could be a different one.
        builder = src / "build.py"
        if not builder.is_file():
            sys.exit(
                f"REFUSED: {args.ref} carries no {SRC_SUBTREE}/build.py, so the page "
                "cannot be checked against its sources. Nothing was uploaded."
            )
        check = subprocess.run(
            [sys.executable, str(builder), "--check"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if check.returncode != 0:
            sys.stderr.write(check.stdout + check.stderr)
            sys.exit(
                f"REFUSED: index.html at {args.ref} does not match its sources there. "
                "Nothing was uploaded."
            )
        print(f"  build --check ok: {check.stdout.strip()}")

        files = stage(src, dest)

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

        # 9. WHERE THE BYTES COME FROM. Every case above is about WHAT gets staged;
        # these are about WHICH VERSION of it, which is the half that nearly reverted a
        # money-path control on a live page.
        #
        # A REAL repository, not a stub. The claim under test is "the script asks git
        # and uses git's answer", and a fake that returns whatever it was handed would
        # pass whether or not the script asks git at all -- so the fixture has to be
        # something git actually reads. Hermetic all the same: `git init` under the temp
        # directory, no network, no remote, nothing outside `root`.
        def _g(
            *args: str, cwd: Path, env: dict[str, str] | None = None
        ) -> subprocess.CompletedProcess:
            r = subprocess.run(
                ["git", *args],
                cwd=str(cwd),
                capture_output=True,
                env=({**os.environ, **env} if env else None),
            )
            if r.returncode != 0:
                raise RuntimeError(
                    f"fixture setup: git {args[0]} -> {r.returncode}: "
                    f"{r.stderr.decode('utf-8', 'replace').strip()}"
                )
            return r

        fixture = root / "fixture"
        (fixture / SRC_SUBTREE).mkdir(parents=True)
        _g("init", "-q", "-b", "main", ".", cwd=fixture)
        # Local config only. A committer identity is required or `commit` refuses, and
        # writing it globally would edit the machine running the suite.
        _g("config", "user.email", "selftest@invalid", cwd=fixture)
        _g("config", "user.name", "selftest", cwd=fixture)
        # An explicit .gitattributes, so the fixture pins the LF claim rather than
        # inheriting whatever autocrlf the running machine happens to have set.
        (fixture / ".gitattributes").write_bytes(b"* text=auto eol=lf\n")

        def _fixture_commit(marker: bytes, msg: str) -> str:
            for name in SERVE:
                f = fixture / SRC_SUBTREE / name
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(b"/* " + name.encode() + b" */\n")
            # LF in the committed blob, deliberately. The whole point of reading git is
            # that what ships is this, and not a checkout translated on the way to disk.
            (fixture / SRC_SUBTREE / "index.html").write_bytes(
                b"<html>\n<!-- " + marker + b" -->\n</html>\n"
            )
            _g("add", "-A", cwd=fixture)
            _g("commit", "-q", "-m", msg, cwd=fixture)
            return _g("rev-parse", "HEAD", cwd=fixture).stdout.decode().strip()

        old_sha = _fixture_commit(b"OLDCONTENT", "old")
        _fixture_commit(b"NEWCONTENT", "new")

        # THE STATE THAT CAUSED THIS. The working tree is put BEHIND the branch, then
        # dirtied on top -- two commits behind with an uncommitted edit, which is what a
        # shared checkout looks like on an ordinary afternoon. `main` still names the tip.
        _g("checkout", "-q", "--detach", old_sha, cwd=fixture)
        (fixture / SRC_SUBTREE / "index.html").write_bytes(b"<html>DIRTYCONTENT</html>")

        # THE HEADLINE CONTROL. Three markers exist and only one may ship. Asserting the
        # tip's presence alone would pass for a script that read the tree and happened to
        # find the same string, so the two that must be ABSENT are the load-bearing half.
        got = materialise("main", root / "mat", repo=fixture)
        staged = (got / "index.html").read_bytes()
        case(
            "the deploy set is the REF's bytes, not the working tree's",
            b"NEWCONTENT" in staged
            and b"OLDCONTENT" not in staged
            and b"DIRTYCONTENT" not in staged,
        )
        # And the tree really is the other thing, so the case above is a statement about
        # the script rather than about a fixture where every version happens to match.
        case(
            "control: that working tree really does hold different bytes",
            b"DIRTYCONTENT" in (fixture / SRC_SUBTREE / "index.html").read_bytes(),
        )
        # The line-ending half, which no diff-shaped check can see: a tree checked out on
        # Windows is CRLF and the committed blob is LF, so an in-place deploy publishes a
        # file differing from the commit on every line while every text comparison agrees.
        case(
            "materialised bytes carry the blob's LF, not the platform's CRLF",
            b"\r\n" not in staged and b"\n" in staged,
        )
        # End to end through the real staging path, against the ref rather than a
        # directory someone assembled. Anything short of this leaves the join between
        # materialise() and stage() untested.
        out9 = stage(got, root / "out9")
        case(
            "stage runs on the materialised ref and carries the whole deploy set",
            sorted(str(p.relative_to(root / "out9")).replace("\\", "/") for p in out9)
            == sorted(SERVE)
            and b"NEWCONTENT" in (root / "out9" / "index.html").read_bytes(),
        )

        # REFUSE, three ways, because "cannot produce the ref's bytes" must never
        # degrade into publishing something else. Each is driven, not asserted.
        try:
            resolve_ref("no/such/ref/anywhere", repo=fixture)
            case("resolve_ref refuses a ref that does not resolve", False)
        except SystemExit:
            case("resolve_ref refuses a ref that does not resolve", True)
        # The over-correction control: a resolvable ref must still resolve. A refusal
        # path that fires on everything is not a gate, it is an outage.
        case(
            "control: resolve_ref still returns the commit for a ref that exists",
            resolve_ref("main", repo=fixture) != old_sha
            and len(resolve_ref("main", repo=fixture)) == 40,
        )

        # A ref whose subtree is absent entirely. Reached here through the FIRST commit
        # of a second fixture, because an empty result and a failed command are different
        # refusals and only one of them is this one.
        bare = root / "bare"
        bare.mkdir()
        _g("init", "-q", "-b", "main", ".", cwd=bare)
        _g("config", "user.email", "selftest@invalid", cwd=bare)
        _g("config", "user.name", "selftest", cwd=bare)
        (bare / "readme.md").write_bytes(b"no pay page here\n")
        _g("add", "-A", cwd=bare)
        _g("commit", "-q", "-m", "no subtree", cwd=bare)
        try:
            materialise("main", root / "mat2", repo=bare)
            case("materialise refuses a ref carrying no pay page", False)
        except SystemExit:
            case("materialise refuses a ref carrying no pay page", True)

        # A ref whose tree LISTS a blob the object store does not hold. That is what a
        # shallow or partial clone looks like from inside, and it is the refusal most
        # likely to matter on someone else's machine, so it is driven rather than
        # asserted: one loose object is deleted, which no fixture can fake by other means
        # offline. Without this the branch is unreachable from the suite -- a mutant that
        # deleted the refusal outright left every case green.
        gone = root / "gone"
        (gone / SRC_SUBTREE).mkdir(parents=True)
        _g("init", "-q", "-b", "main", ".", cwd=gone)
        _g("config", "user.email", "selftest@invalid", cwd=gone)
        _g("config", "user.name", "selftest", cwd=gone)
        (gone / ".gitattributes").write_bytes(b"* text=auto eol=lf\n")
        for name in SERVE:
            f = gone / SRC_SUBTREE / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(b"/* " + name.encode() + b" */\n")
        _g("add", "-A", cwd=gone)
        _g("commit", "-q", "-m", "complete", cwd=gone)
        blob_sha = (
            _g("rev-parse", f"main:{SRC_SUBTREE}/index.html", cwd=gone)
            .stdout.decode()
            .strip()
        )
        loose = gone / ".git" / "objects" / blob_sha[:2] / blob_sha[2:]
        # Loose objects are written read-only, and unlink() on a read-only file raises
        # on Windows rather than removing it.
        loose.chmod(0o600)
        loose.unlink()
        # THE CONTROL, and it is what makes the refusal below attributable: the tree still
        # lists the entry, so this is a missing OBJECT and not a missing entry. Those are
        # different refusals and only one of them is under test here.
        listed = _g("ls-tree", "-r", "-z", "main", "--", f"{SRC_SUBTREE}/", cwd=gone)
        case(
            "control: the tree still lists the blob whose object was removed",
            listed.returncode == 0 and b"index.html" in listed.stdout,
        )
        try:
            materialise("main", root / "mat4", repo=gone)
            case("materialise refuses a blob git cannot produce", False)
        except SystemExit:
            case("materialise refuses a blob git cannot produce", True)

        # A RESOLVED COMMIT PINS THE CONTENT while the name it came from moves. This is
        # the production path's invariant: resolve_ref() prints a commit and everything
        # after is addressed by that id, so what ships is what was printed.
        pinned = resolve_ref("main", repo=fixture)
        # -f because the fixture tree was deliberately dirtied above; this is a
        # throwaway repository and the dirt has already served its case.
        _g("checkout", "-q", "-f", "main", cwd=fixture)
        (fixture / SRC_SUBTREE / "index.html").write_bytes(
            b"<html>\n<!-- MOVEDCONTENT -->\n</html>\n"
        )
        _g("add", "-A", cwd=fixture)
        _g("commit", "-q", "-m", "moved", cwd=fixture)
        by_id = (
            materialise(pinned, root / "mat5", repo=fixture) / "index.html"
        ).read_bytes()
        case(
            "a resolved commit pins the content even after the branch moves",
            b"NEWCONTENT" in by_id and b"MOVEDCONTENT" not in by_id,
        )
        # THE CONTROL, and it is what makes the case above mean anything: the NAME really
        # did move, so the pinned read is a statement about addressing and not about a
        # fixture where both happen to be the same commit.
        by_name = (
            materialise("main", root / "mat6", repo=fixture) / "index.html"
        ).read_bytes()
        case(
            "control: the branch name really does now resolve to the newer commit",
            b"MOVEDCONTENT" in by_name,
        )

        # A SYMLINK is type blob with mode 120000, so a type-only filter would have
        # written its target string as the asset. Built with plumbing rather than with a
        # real symlink, because Windows checkouts do not create them by default and the
        # case must run everywhere the suite does.
        link_blob = (
            subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                cwd=str(fixture),
                input=b"../../../etc/passwd",
                capture_output=True,
            )
            .stdout.decode()
            .strip()
        )
        idx = root / "linkindex"
        env_idx = {"GIT_INDEX_FILE": str(idx)}
        _g("read-tree", "main", cwd=fixture, env=env_idx)
        _g(
            "update-index",
            "--add",
            "--cacheinfo",
            f"120000,{link_blob},{SRC_SUBTREE}/evil.js",
            cwd=fixture,
            env=env_idx,
        )
        link_tree = _g("write-tree", cwd=fixture, env=env_idx).stdout.decode().strip()
        link_commit = (
            subprocess.run(
                ["git", "commit-tree", link_tree, "-p", "main", "-m", "link"],
                cwd=str(fixture),
                capture_output=True,
                env={
                    **os.environ,
                    "GIT_AUTHOR_NAME": "selftest",
                    "GIT_AUTHOR_EMAIL": "selftest@invalid",
                    "GIT_COMMITTER_NAME": "selftest",
                    "GIT_COMMITTER_EMAIL": "selftest@invalid",
                },
            )
            .stdout.decode()
            .strip()
        )
        # The control first: the entry really is in that tree with mode 120000, so the
        # refusal below is about the mode and not about a tree that never got it.
        planted = _g("ls-tree", "-r", link_commit, "--", f"{SRC_SUBTREE}/", cwd=fixture)
        case(
            "control: the planted tree really carries a mode-120000 entry",
            b"120000" in planted.stdout and b"evil.js" in planted.stdout,
        )
        try:
            materialise(link_commit, root / "mat7", repo=fixture)
            case("materialise refuses a tree entry that is not a regular file", False)
        except SystemExit:
            case("materialise refuses a tree entry that is not a regular file", True)

        # THE CALL SITE, pinned at the source level and labelled as such. The case above
        # proves materialise() pins content when handed a commit id; it cannot prove
        # main() hands it one, and main() has no seam a fixture can drive -- it shells
        # out to build.py and wants a real deploy set. Reverting the wiring is exactly
        # the defect a review caught here, and a property with no test on its call site
        # is a property that regresses quietly.
        own_src = Path(__file__).read_text(encoding="utf-8")
        # The forbidden form is BUILT rather than written, because a literal copy of it
        # in this file would be found by the very scan below and the case would fail on
        # its own control text. Same reason the fake home above is joined at runtime.
        good = "materialise(" + "sha,"
        bad = "materialise(" + "args.ref"
        wiring = [
            ln.strip()
            for ln in own_src.splitlines()
            if "materialise(" in ln and "def materialise" not in ln and "tmpd" in ln
        ]
        case(
            "main() materialises the RESOLVED COMMIT, not the ref name",
            len(wiring) == 1 and good in wiring[0] and bad not in wiring[0],
        )
        # The control, because a check that can only ever pass has not been shown to be
        # capable of anything else: the same predicate rejects the shape it forbids.
        planted_call = "        src = " + bad + ', tmpd / "src")'
        case(
            "control: that same predicate rejects the ref-name form",
            good not in planted_call and bad in planted_call,
        )

        # A repo path git cannot read. Named for what it proves -- resolve_ref refuses on
        # git's own non-zero exit -- and NOT for the raise-guard below, which it does not
        # reach: git exits non-zero here rather than Python raising.
        notrepo = root / "notrepo.txt"
        notrepo.write_bytes(b"not a directory\n")
        try:
            resolve_ref("main", repo=notrepo)
            case("a repo path git cannot read is refused, not part-shipped", False)
        except SystemExit:
            case("a repo path git cannot read is refused, not part-shipped", True)

        # THE RAISE-GUARD, driven. An unresolvable executable is the one case that raises
        # out of subprocess instead of returning, and a fixture cannot uninstall git, so
        # the name is injected. Asserted on the RESULT rather than on "did not raise",
        # because a guard that swallowed the failure into a zero exit would also not raise.
        try:
            probe = _git(["rev-parse", "HEAD"], repo=root, exe="git-not-installed-zzz")
            case(
                "an unresolvable git refuses through the normal path, it does not raise",
                probe.returncode != 0 and not probe.stdout,
            )
        except OSError:
            case(
                "an unresolvable git refuses through the normal path, it does not raise",
                False,
            )

        # A ref that carries the subtree but not every deploy-set member. Distinct from
        # the case above and from case 7: this one goes through git, so it proves the
        # missing-member refusal survives the new source rather than only holding for a
        # directory the caller assembled by hand.
        partial = root / "partial"
        (partial / SRC_SUBTREE).mkdir(parents=True)
        _g("init", "-q", "-b", "main", ".", cwd=partial)
        _g("config", "user.email", "selftest@invalid", cwd=partial)
        _g("config", "user.name", "selftest", cwd=partial)
        (partial / SRC_SUBTREE / "index.html").write_bytes(b"<html></html>\n")
        _g("add", "-A", cwd=partial)
        _g("commit", "-q", "-m", "index only", cwd=partial)
        mat3 = materialise("main", root / "mat3", repo=partial)
        try:
            staged_files(mat3)
            case(
                "a ref missing a deploy-set member is refused, not part-shipped", False
            )
        except SystemExit:
            case("a ref missing a deploy-set member is refused, not part-shipped", True)

    passed = sum(1 for _, ok in cases if ok)
    print(f"\n  {passed}/{len(cases)}")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
